"""Offline regression for exact staged harmless-file intake and execution."""

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

from src.models.execution import ExecutionResourceLimits
from src.registered_actions import get_registered_action
from src.staged_fixture_process import (_StagedHarmlessPlan, inspect_staged_fixture,
    run_staged_fixture)
from src.tools.process import canonical_target_environment, measure_tool_identity


LINUX = os.name == "posix" and sys.platform.startswith("linux")


class TestStagedBootstrap(unittest.TestCase):
    def test_bootstrap_contains_no_registry_source_and_only_reads_inherited_fd(self):
        limits = ExecutionResourceLimits(wall_time_seconds=2.0, cpu_seconds=1,
            memory_bytes=268435456, max_output_bytes=4096)
        action = get_registered_action("p2b-normal-v1")
        plan = _StagedHarmlessPlan(47, {"source_path": "/private/received/candidate.py",
            "source_sha256": action.sha256})
        script = plan.bootstrap(control_fd=48, limits=limits, request_id="1" * 32,
            run_id="2" * 32, nonce="3" * 32)
        compile(script, "<trusted-staged-bootstrap>", "exec")
        self.assertNotIn(action.source.decode("utf-8"), script)
        self.assertIn("os.pread(fd, 1048577, 0)", script)
        self.assertLess(script.index("PR_SET_PDEATHSIG"), script.index("os.pread(fd, 1048577, 0)"))
        self.assertIn('os.getppid() != cfg["parent_pid"]', script)
        self.assertIn('exec(compile(raw, expected["source_path"], "exec"), namespace)', script)
        self.assertIn("STAGED_SOURCE_READY", script)
        self.assertNotIn("get_registered_action", script)

    def test_proof_cannot_be_rebound_to_other_run_or_nonce(self):
        plan = _StagedHarmlessPlan(7, {"source_path": "/private/candidate.py"})
        proof = plan.expected_proof(request_id="1" * 32, run_id="2" * 32, nonce="3" * 32, pid=91)
        for field, replacement in (("run_id", "4" * 32), ("nonce", "5" * 32),
                                   ("source_fd", 8), ("pid", 92)):
            altered = {**proof, field: replacement}
            with patch("src.staged_fixture_process.os.stat") as observed:
                with self.assertRaises(ValueError):
                    plan.verify_proof(altered, request_id="1" * 32, run_id="2" * 32,
                        nonce="3" * 32, pid=91)
                observed.assert_not_called()

    @unittest.skipIf(LINUX, "Linux tests exercise descriptor intake")
    def test_non_linux_intake_does_not_launch(self):
        with patch("src.lifecycle_process.subprocess.Popen") as launched:
            with self.assertRaises(ValueError):
                inspect_staged_fixture({}, "a" * 64)
            launched.assert_not_called()


@unittest.skipUnless(LINUX, "requires Linux openat/O_NOFOLLOW/pread descriptor semantics")
class TestStagedFileIdentity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "transfers"
        self.root.mkdir(mode=0o700)
        self.transfer_id = uuid.uuid4().hex
        self.folder = self.root / self.transfer_id
        self.folder.mkdir(mode=0o700)
        self.source = self.folder / "candidate.py"
        self.action = get_registered_action("p2b-normal-v1")
        self.source.write_bytes(self.action.source)
        self.source.chmod(0o600)
        self.receipt = {"schema_version": "1.0", "status": "STAGED_AND_VERIFIED",
            "request_id": uuid.uuid4().hex, "transfer_id": self.transfer_id,
            "action_id": "p2b-normal-v1", "source_sha256": self.action.sha256,
            "source_bytes": len(self.action.source), "target_environment": canonical_target_environment(),
            "receiver_pid": os.getpid(), "receiver_ppid": os.getppid(),
            "receiver_uid": os.getuid(), "receiver_gid": os.getgid(), "receiver_start_ticks": 1,
            "staged_relative_path": "candidate.py", "staged_path": str(self.source),
            "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
        self.receipt_path = self.folder / "transfer_receipt.json"
        self.persist_receipt()
        self.root_patch = patch("src.staged_fixture_process._transfer_root", return_value=self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.limits = ExecutionResourceLimits(wall_time_seconds=2.0, cpu_seconds=1,
            memory_bytes=268435456, max_output_bytes=4096)
        self.ids = {name: uuid.uuid4().hex for name in ("request_id", "run_id", "nonce")}
        self.expected = measure_tool_identity(sys.executable)

    def persist_receipt(self):
        self.receipt_raw = (json.dumps(self.receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        self.receipt_path.write_bytes(self.receipt_raw)
        self.receipt_path.chmod(0o600)
        self.receipt_sha = hashlib.sha256(self.receipt_raw).hexdigest()

    def inspect(self):
        return inspect_staged_fixture(self.receipt, self.receipt_sha)

    def run_fixture(self, identity, **kwargs):
        return run_staged_fixture(self.receipt, self.receipt_sha, self.limits,
            expected_source_identity=identity, expected_tool=self.expected,
            cwd=kwargs.pop("cwd", self.folder), target_environment=canonical_target_environment(),
            **self.ids, **kwargs)

    def test_intake_matches_actual_file_and_does_not_launch(self):
        with patch("src.lifecycle_process.subprocess.Popen") as launched:
            identity = self.inspect()
        self.assertEqual(identity["inode"], self.source.stat().st_ino)
        self.assertEqual(identity["device"], self.source.stat().st_dev)
        self.assertEqual(identity["source_path"], str(self.source))
        self.assertEqual(identity["source_sha256"], self.action.sha256)
        self.assertEqual(identity["receipt_sha256"], self.receipt_sha)
        launched.assert_not_called()

    def test_wrong_receipt_hash_is_rejected(self):
        with self.assertRaises(ValueError):
            inspect_staged_fixture(self.receipt, "a" * 64)

    def test_receipt_cross_run_or_target_is_rejected(self):
        for field, replacement in (("request_id", uuid.uuid4().hex),
                                   ("transfer_id", uuid.uuid4().hex),
                                   ("target_environment", "wsl:other")):
            changed = {**self.receipt, field: replacement}
            with self.assertRaises((ValueError, OSError)):
                inspect_staged_fixture(changed, self.receipt_sha)

    def test_registry_action_must_remain_exact_normal_fixture(self):
        changed = {**self.receipt, "action_id": "p2b-timeout-v1"}
        with self.assertRaises(ValueError):
            inspect_staged_fixture(changed, self.receipt_sha)

    def test_path_traversal_or_alternate_path_is_rejected(self):
        for path in (str(self.folder / ".." / "candidate.py"), "/tmp/another.py", "C:\\candidate.py"):
            with self.assertRaises(ValueError):
                inspect_staged_fixture({**self.receipt, "staged_path": path}, self.receipt_sha)

    def test_tampered_received_bytes_are_rejected(self):
        self.source.write_bytes(b'print("unregistered")\n')
        with self.assertRaises(ValueError):
            self.inspect()

    def test_unregistered_bytes_with_self_consistent_receipt_are_rejected(self):
        raw = b'print("not the fixed fixture")\n'
        self.source.write_bytes(raw)
        self.receipt.update(source_sha256=hashlib.sha256(raw).hexdigest(), source_bytes=len(raw))
        self.persist_receipt()
        with self.assertRaises(ValueError):
            self.inspect()

    def test_same_bytes_replaced_inode_is_rejected_before_launch(self):
        identity = self.inspect()
        replacement = self.folder / "replacement.py"
        replacement.write_bytes(self.action.source)
        replacement.chmod(0o600)
        replacement.replace(self.source)
        with patch("src.lifecycle_process.subprocess.Popen") as launched:
            with self.assertRaises(ValueError):
                self.run_fixture(identity)
            launched.assert_not_called()

    def test_same_inode_change_is_rejected_before_launch(self):
        identity = self.inspect()
        self.source.write_bytes(self.action.source + b"\n")
        with patch("src.lifecycle_process.subprocess.Popen") as launched:
            with self.assertRaises(ValueError):
                self.run_fixture(identity)
            launched.assert_not_called()

    def test_symlinked_source_and_receipt_are_rejected(self):
        for path in (self.source, self.receipt_path):
            saved = path.with_suffix(".saved")
            path.rename(saved)
            path.symlink_to(saved)
            try:
                with self.assertRaises((ValueError, OSError)):
                    self.inspect()
            finally:
                path.unlink()
                saved.rename(path)

    def test_symlinked_directory_is_rejected(self):
        other = self.root / "real-folder"
        self.folder.rename(other)
        self.folder.symlink_to(other, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.inspect()

    def test_hard_link_or_relaxed_file_mode_is_rejected(self):
        linked = self.folder / "linked.py"
        os.link(self.source, linked)
        with self.assertRaises(ValueError):
            self.inspect()
        linked.unlink()
        self.source.chmod(0o644)
        with self.assertRaises(ValueError):
            self.inspect()

    def test_non_private_directory_and_wrong_cwd_are_rejected(self):
        identity = self.inspect()
        with patch("src.lifecycle_process.subprocess.Popen") as launched:
            with self.assertRaises(ValueError):
                self.run_fixture(identity, cwd=self.root)
            launched.assert_not_called()
        self.folder.chmod(0o755)
        with self.assertRaises(ValueError):
            self.inspect()

    def test_fixed_staged_source_is_the_only_code_executed(self):
        identity = self.inspect()
        events = []
        result = self.run_fixture(identity, on_event=lambda kind, detail: events.append((kind, detail)))
        self.assertEqual(result.state, "COMPLETED", result.process.diagnostics)
        self.assertEqual(result.stdout, b"P2-B harmless normal exit\n")
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.process.returncode, 0)
        self.assertEqual(result.process.cleanup.status, "CONFIRMED")
        names = [kind for kind, _ in events]
        self.assertLess(names.index("STAGED_SOURCE_READY"), names.index("RESOURCE_READY"))
        self.assertLess(names.index("RESOURCE_READY"), names.index("RUNNING"))
        proof = next(detail for kind, detail in events if kind == "STAGED_SOURCE_READY")
        self.assertEqual(proof["pid"], result.process.pid)
        self.assertEqual(proof["inode"], identity["inode"])
        self.assertEqual(proof["source_sha256"], self.action.sha256)
        self.assertEqual(proof["source_path"], str(self.source))
        self.assertNotIn(self.action.source.decode("utf-8"), result.process.argv[3])
        self.assertIn("exec(compile(raw", result.process.argv[3])
        self.assertTrue(result.observation["events"])

    def test_child_reread_rejects_content_changed_after_parent_intake(self):
        identity = self.inspect()
        def changed_after_parent_gate(kind, detail):
            if kind == "STARTING":
                self.source.write_bytes(b'print("changed before child read")\n')
        result = self.run_fixture(identity, on_event=changed_after_parent_gate)
        self.assertFalse(result.process.action_started)
        self.assertEqual(result.stdout, b"")
        self.assertNotEqual(result.state, "COMPLETED")
        self.assertEqual(result.process.cleanup.status, "CONFIRMED")

    def test_resource_proof_without_staged_proof_never_releases_go(self):
        identity = self.inspect()
        # Returning the frozen registry source here simulates an implementation
        # accidentally reverting to the historical -c branch. The missing staged
        # proof must stop it before the fixed action prints anything.
        with patch.object(_StagedHarmlessPlan, "bootstrap", return_value=self.action.source.decode("utf-8")):
            result = self.run_fixture(identity)
        self.assertFalse(result.process.action_started)
        self.assertEqual(result.stdout, b"")
        self.assertNotEqual(result.state, "COMPLETED")
        self.assertEqual(result.process.cleanup.status, "CONFIRMED")
