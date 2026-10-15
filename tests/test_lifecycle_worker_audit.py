"""Independent worker/control audit; only mocked observations, no child launch."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path, PurePosixPath
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src import lifecycle_worker as worker
from src.models.platform import PlatformSnapshot
from src.models.execution import PreflightResult
from src.models.lifecycle import ProcessObservation
from src.registered_actions import get_registered_action
from tests.test_lifecycle_models import synthetic_context


class SyntheticTargetRoot:
    """Separate target path spelling from the real local private test store."""

    def resolve(self, *, strict):
        return self

    def __str__(self):
        return "/workspace"

    def __truediv__(self, relative):
        return PurePosixPath("/workspace") / relative


class TestWorkerAudit(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / "tasks"
        req, auth, policy, snapshot, tool = synthetic_context()
        self.request, self.authorization, self.policy = req, auth, policy
        self.snapshot = PlatformSnapshot.model_validate(snapshot)
        self.tool = tool
        self.identity = {"pid": os.getpid(), "ppid": 1, "pgid": os.getpid(),
                         "session_id": os.getpid(), "start_ticks": 1000,
                         "uid": 1000, "gid": 1000, "state": "S"}
        self.payload = {"operation": "EXECUTE", "nonce": "e" * 32, "request_id": req.request_id,
                        "run_id": "f" * 32, "control_token": "a" * 64,
                        "request": req.model_dump(mode="json"),
                        "authorization": auth.model_dump(mode="json"),
                        "policy": policy.model_dump(mode="json"),
                        "snapshot": snapshot, "tool_record": tool.model_dump(mode="json")}
        real_path = Path
        patches = [patch.object(worker, "task_root", return_value=self.folder),
                   patch.object(worker, "current_platform_type", return_value="wsl"),
                   patch.object(worker, "canonical_target_environment", return_value="wsl:Ubuntu-22.04"),
                   patch.object(worker, "_identity", return_value=self.identity),
                   patch.object(worker, "_boot_id", return_value="synthetic-boot-id"),
                   patch.object(worker, "Path", side_effect=lambda value: SyntheticTargetRoot()
                                if value == "synthetic-project-root" else real_path(value)),
                   patch.object(worker.os, "getuid", return_value=1000, create=True),
                   patch.object(worker, "_snapshot", return_value=self.snapshot),
                   patch.object(worker, "measure_tool_identity", return_value=req.tool_identity),
                   patch.object(worker, "resource_capabilities", return_value={
                       "status": "OBSERVED", "mechanisms": list(policy.resource_support.mechanisms),
                       "source": "synthetic audit capabilities"})]
        for selected in patches:
            selected.start()
            self.addCleanup(selected.stop)
        selected = patch("src.lifecycle_process.run_registered_action")
        self.launch = selected.start()
        self.addCleanup(selected.stop)

    def execute(self, payload=None):
        return worker.handle_worker(self.payload if payload is None else payload,
                                    project_root="synthetic-project-root")

    def lease(self, *, spawn_intent=False, process=None):
        folder = self.folder / self.payload["run_id"]
        folder.mkdir(parents=True)
        worker._write_json(folder / "lease.json", {
            "request_id": self.payload["request_id"], "run_id": self.payload["run_id"],
            "nonce": self.payload["nonce"], "spawn_intent": spawn_intent,
            "control_token_sha256": hashlib.sha256(self.payload["control_token"].encode("ascii")).hexdigest(),
            "target_environment": "wsl:Ubuntu-22.04", "worker": self.identity,
            "boot_id": "synthetic-boot-id", "process": process})
        return folder

    def control(self, operation="STATUS"):
        payload = deepcopy(self.payload)
        payload["operation"] = operation
        for name in ("request", "authorization", "policy", "snapshot", "tool_record"):
            payload[name] = None
        return payload

    def assert_not_started(self, packet, expected):
        self.assertEqual(packet["record"]["status"], expected)
        self.assertIsNone(packet["record"]["process"])
        self.assertEqual(packet["record"]["candidate_execution_status"], "NOT_EXECUTED")
        self.assertEqual(packet["record"]["verification_status"], "NOT_VERIFIED")
        self.launch.assert_not_called()

    def test_missing_authorization_rejected_without_runner(self):
        payload = deepcopy(self.payload)
        payload["authorization"] = None
        packet = self.execute(payload)
        self.assert_not_started(packet, "REJECTED")
        self.assertIn("AUTHORIZATION_MISSING", packet["record"]["diagnostics"])

    def test_authorization_expired_during_probe_is_rechecked_before_start(self):
        payload = deepcopy(self.payload)
        payload["authorization"].update(not_before="2000-01-01T00:00:00+00:00",
                                         expires_at="2001-01-01T00:00:00+00:00")
        packet = self.execute(payload)
        self.assert_not_started(packet, "REJECTED")
        self.assertIn("AUTHORIZATION_EXPIRED", packet["record"]["diagnostics"])

    def test_unknown_registry_action_is_unsupported_without_runner(self):
        payload = deepcopy(self.payload)
        payload["request"]["fixture_id"] = "unreviewed-action"
        packet = self.execute(payload)
        self.assert_not_started(packet, "UNSUPPORTED")
        self.assertIn("ACTION_NOT_REGISTERED", packet["record"]["diagnostics"])

    def test_generic_candidate_execution_remains_unsupported(self):
        payload = deepcopy(self.payload)
        payload["request"]["authorized_action"] = "EXECUTE_CANDIDATE"
        packet = self.execute(payload)
        self.assert_not_started(packet, "UNSUPPORTED")

    def test_same_request_id_cannot_overwrite_prior_history(self):
        self.payload["authorization"] = None
        self.execute()
        original = (self.folder / self.payload["run_id"] / "execution_record.json").read_bytes()
        payload = deepcopy(self.payload)
        payload["run_id"] = "d" * 32
        packet = self.execute(payload)
        self.assert_not_started(packet, "REJECTED")
        self.assertEqual(packet["record"]["diagnostics"], ["TASK_ID_CONFLICT"])
        self.assertEqual((self.folder / self.payload["run_id"] / "execution_record.json").read_bytes(), original)

    def test_same_run_id_cannot_overwrite_existing_lease(self):
        folder = self.lease()
        original = (folder / "lease.json").read_bytes()
        packet = self.execute()
        self.assert_not_started(packet, "REJECTED")
        self.assertEqual((folder / "lease.json").read_bytes(), original)

    def test_wrong_control_token_never_writes_cancellation(self):
        folder = self.lease()
        payload = self.control("CANCEL")
        payload["control_token"] = "b" * 64
        record, recovery, diagnostics = worker._control(payload)
        self.assertIsNone(record)
        self.assertIsNone(recovery)
        self.assertEqual(diagnostics, ["CONTROL_IDENTITY_OR_RECOVERY_UNKNOWN"])
        self.assertFalse((folder / "cancel.json").exists())
        self.launch.assert_not_called()

    def test_spawn_intent_without_native_identity_cannot_claim_cleanup(self):
        self.lease(spawn_intent=True)
        with patch.object(worker, "_identity", side_effect=ProcessLookupError), \
                patch.object(worker, "_group_members") as inspect:
            record, recovery, diagnostics = worker._control(self.control())
        self.assertIsNone(record)
        self.assertEqual(recovery["status"], "UNKNOWN")
        self.assertIsNone(recovery["group_empty"])
        self.assertFalse(recovery["worker_alive"])
        self.assertEqual(recovery["diagnostics"], ["SPAWN_IDENTITY_UNKNOWN"])
        self.assertEqual(diagnostics, [])
        inspect.assert_not_called()

    def test_remaining_group_member_is_cleanup_failed(self):
        self.lease(spawn_intent=True, process={"pgid": 10001, "session_id": 10001})
        with patch.object(worker, "_identity", side_effect=ProcessLookupError), \
                patch.object(worker, "_group_members", return_value=[10002]):
            _, recovery, _ = worker._control(self.control())
        self.assertEqual(recovery["status"], "FAILED")
        self.assertFalse(recovery["group_empty"])

    def test_still_running_worker_is_not_cleaned_up(self):
        self.lease()
        _, recovery, _ = worker._control(self.control())
        self.assertEqual(recovery["status"], "UNKNOWN")
        self.assertTrue(recovery["worker_alive"])

    def test_cancellation_record_binds_original_nonce_request_and_run(self):
        folder = self.lease()
        payload = self.control("CANCEL")
        payload["nonce"] = "b" * 32
        worker._control(payload)
        self.assertEqual(worker._read_json(folder / "cancel.json"),
                         {"request_id": self.payload["request_id"], "run_id": self.payload["run_id"],
                          "nonce": self.payload["nonce"], "action": "CANCEL"})
        self.launch.assert_not_called()

    def test_control_envelope_cannot_carry_execution_inputs(self):
        payload = self.control()
        payload["request"] = self.payload["request"]
        packet = self.execute(payload)
        self.assertEqual(packet["diagnostics"], ["CONTROL_HAS_EXECUTION_INPUTS"])
        self.launch.assert_not_called()

    def test_invalid_task_identifiers_and_unknown_operation_are_rejected(self):
        for field, value in (("run_id", "../../escape"), ("control_token", ""),
                             ("operation", "SHELL"), ("nonce", True)):
            payload = deepcopy(self.payload)
            payload[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.execute(payload)
        self.launch.assert_not_called()

    def expired_at_gate(self, gate):
        """Trusted observations are mocks; the stub never launches a process."""
        moment = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)

        class Clock:
            current = moment

            @classmethod
            def now(cls, timezone):
                return cls.current

        payload = deepcopy(self.payload)
        payload["authorization"].update(not_before=(moment - timedelta(seconds=1)).isoformat(),
                                         expires_at=(moment + timedelta(seconds=5)).isoformat())
        ready = PreflightResult(request_id=self.request.request_id, status="READY", diagnostics=[],
                                checked_at=moment.isoformat(),
                                measured_candidate_sha256=self.request.candidate_sha256,
                                measured_tool_sha256=self.request.tool_identity.file_sha256)

        def safe_stub(action_id, limits, **kwargs):
            callback = kwargs["on_event"]
            guard_started = gate == "RESOURCE_READY"
            if guard_started:
                callback("STARTING", {"fixture_id": action_id})
                Clock.current = moment + timedelta(seconds=1)
                callback("WORKER_CHILD_STARTED", {"pid": 10001, "pgid": 10001, "session_id": 10001,
                                                   "start_ticks": 5000, "uid": 1000, "gid": 1000})
            Clock.current = moment + timedelta(seconds=6)
            with self.assertRaisesRegex(PermissionError, "AUTHORIZATION_EXPIRED_AT_GATE"):
                callback(gate, {"fixture_id": action_id})
            empty_sha = hashlib.sha256(b"").hexdigest()
            resources = {"status": "ENFORCED" if guard_started else "NOT_STARTED",
                         "wall_watchdog": guard_started, "output_cap": guard_started,
                         "process_group": guard_started,
                         "cpu_seconds": limits.cpu_seconds if guard_started else None,
                         "memory_bytes": limits.memory_bytes if guard_started else None,
                         "verification_source": "SYNTHETIC gate-only audit observations"}
            cleanup = {"status": "CONFIRMED" if guard_started else "NOT_STARTED",
                       "termination_method": "SIGKILL" if guard_started else "NONE",
                       "parent_reaped": guard_started, "group_absent": guard_started,
                       "descendants_absent": guard_started, "checked_at": Clock.current.isoformat(),
                       "source": "SYNTHETIC cleanup audit"}
            action = get_registered_action(action_id)
            process = ProcessObservation(
                started=guard_started, action_started=False,
                argv=[self.request.tool_identity.resolved_path, "-I", "-c", action.source.decode("utf-8")],
                cwd=self.request.cwd, target_environment=self.request.binding.target_environment,
                tool_identity=self.request.tool_identity,
                pid=10001 if guard_started else None, pgid=10001 if guard_started else None,
                session_id=10001 if guard_started else None, start_ticks=5000 if guard_started else None,
                uid=1000 if guard_started else None, gid=1000 if guard_started else None,
                worker_pid=os.getpid(), started_at=(moment + timedelta(seconds=1)).isoformat() if guard_started else None,
                finished_at=Clock.current.isoformat(), duration_seconds=6.0,
                returncode=-9 if guard_started else None, linux_signal=9 if guard_started else None,
                timed_out=False, cancelled=False, truncated=False, capture_failed=True,
                stdout_b64="", stderr_b64="", stdout_sha256=empty_sha, stderr_sha256=empty_sha,
                stdout_size_bytes=0, stderr_size_bytes=0, resource_limits=limits, resources=resources,
                cleanup=cleanup, diagnostics=["SYNTHETIC event sink denied the expired authorization gate"])
            return SimpleNamespace(state="START_FAILED", process=process)

        self.launch.side_effect = safe_stub
        with patch.object(worker, "datetime", Clock), patch.object(worker, "preflight_execution", return_value=ready):
            packet = self.execute(payload)
        record = packet["record"]
        self.assertEqual(record["status"], "REJECTED")
        self.assertIn("AUTHORIZATION_EXPIRED_AT_GATE", record["diagnostics"])
        self.assertFalse(record["process"]["action_started"])
        self.assertEqual(record["fixture_execution_status"], "NOT_STARTED")
        self.assertNotIn("RUNNING", [item["state"] for item in record["events"]])
        self.assertEqual(record["verification_status"], "NOT_VERIFIED")
        self.launch.assert_called_once()
        return packet

    def test_grant_expired_after_preflight_is_blocked_at_starting_gate(self):
        packet = self.expired_at_gate("STARTING")
        self.assertFalse(packet["record"]["process"]["started"])

    def test_grant_expired_after_guard_start_is_blocked_before_action_go(self):
        packet = self.expired_at_gate("RESOURCE_READY")
        self.assertTrue(packet["record"]["process"]["started"])
        self.assertEqual(packet["record"]["process"]["cleanup"]["status"], "CONFIRMED")


if __name__ == "__main__":
    unittest.main()
