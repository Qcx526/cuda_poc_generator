"""Entirely synthetic lifecycle evidence; no Windows/WSL process is dispatched."""

import base64
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.lifecycle_artifacts import (EvidenceWriteError, read_execution_evidence,
                                     rebuild_execution_report, write_execution_evidence)
from src.models.execution import ExecutionRequest, request_sha256, snapshot_sha256
from src.models.lifecycle import ExecutionRecord, canonical_sha256
from src.models.tool_result import digest_bytes, seal_tool_result
from src.registered_actions import get_registered_action
from tests.test_lifecycle_models import synthetic_context
from tests.test_p1c_integration import synthetic_tool_record


STAMP = "2026-10-14T00:00:02+00:00"
RUN_ID = "3" * 32


def replace_packet_bytes(result, packet_key, transport_key):
    """Reseal a deliberately synthetic observation after changing its packet."""
    raw = json.dumps(result[packet_key], separators=(",", ":")).encode("utf-8")
    observed = result[transport_key].model_dump(mode="python")
    observed.update(stdout_b64=base64.b64encode(raw).decode("ascii"), stdout_sha256=digest_bytes(raw))
    result[transport_key] = seal_tool_result(observed)


def synthetic_lifecycle_context(*, status="COMPLETED", authorized=True, truncated=False):
    """Construct synthetic observations, never claiming an actual execution."""
    request, authorization, policy, snapshot, binding_tool = synthetic_context()
    action = get_registered_action(request.fixture_id)
    raw = b"synthetic harmless action output\n"
    process = {
        "started": True, "action_started": True,
        "argv": [request.tool_identity.resolved_path, "-I", "-c", action.source.decode("utf-8")],
        "cwd": request.cwd, "target_environment": request.binding.target_environment,
        "tool_identity": request.tool_identity.model_dump(mode="json"), "pid": 110, "pgid": 110,
        "session_id": 110, "start_ticks": 900, "worker_pid": 100,
        "uid": 1000, "gid": 1000,
        "started_at": STAMP, "finished_at": STAMP, "duration_seconds": 0.0,
        "returncode": 0, "linux_signal": None, "timed_out": False, "cancelled": False,
        "truncated": truncated, "capture_failed": False, "resource_limit_reason": None,
        "stdout_b64": base64.b64encode(raw).decode("ascii"), "stderr_b64": "",
        "stdout_sha256": digest_bytes(raw), "stderr_sha256": digest_bytes(b""),
        "stdout_size_bytes": len(raw), "stderr_size_bytes": 0,
        "resource_limits": request.resource_limits.model_dump(mode="json"),
        "resources": {"status": "ENFORCED", "wall_watchdog": True, "output_cap": True,
                      "process_group": True, "cpu_seconds": request.resource_limits.cpu_seconds,
                      "memory_bytes": request.resource_limits.memory_bytes,
                      "verification_source": "synthetic offline resource observation"},
        "cleanup": {"status": "CONFIRMED", "termination_method": "NONE", "parent_reaped": True,
                    "group_absent": True, "descendants_absent": True, "checked_at": STAMP,
                    "source": "synthetic offline cleanup observation"}, "diagnostics": [],
    }
    states = ["CREATED", "AUTHORIZED", "PREFLIGHT_READY", "STARTING", "RUNNING", status]
    if status in {"REJECTED", "UNKNOWN", "UNSUPPORTED", "START_FAILED"}:
        process = None
        states = ["CREATED", status] if status != "START_FAILED" else ["CREATED", "AUTHORIZED", "PREFLIGHT_READY", status]
    if status == "NONZERO_EXIT":
        process["returncode"] = 7
    if status == "RESOURCE_LIMIT":
        process["resource_limit_reason"] = "OUTPUT_CAP"
    if status == "TIMED_OUT":
        process.update(timed_out=True, returncode=-9, linux_signal=9)
        process["cleanup"]["termination_method"] = "SIGKILL"
    record = ExecutionRecord.model_validate({
        "request_id": request.request_id, "run_id": RUN_ID, "request_sha256": request_sha256(request),
        "authorization_sha256": canonical_sha256(authorization) if authorized else None,
        "policy_sha256": canonical_sha256(policy), "snapshot_sha256": snapshot_sha256(snapshot),
        "candidate_sha256": request.candidate_sha256, "platform_environment_id": request.platform_environment_id,
        "platform_probe_id": request.platform_probe_id, "target_environment": request.binding.target_environment,
        "tool_record_id": binding_tool.record_id, "tool_identity": request.tool_identity.model_dump(mode="json"),
        "authorization_reference": authorization.authorization_reference if authorized else None,
        "operator_id": authorization.operator_id if authorized else None, "action_id": request.fixture_id,
        "status": status, "events": [{"sequence": index, "state": state, "observed_at": STAMP,
            "source": "synthetic offline test", "reason": "synthetic " + state} for index, state in enumerate(states)],
        "process": process, "worker_pid": 100,
        "started_at": STAMP, "finished_at": STAMP, "diagnostics": ["Synthetic observations only"],
        "evidence_files": ["stdout.bin", "stderr.bin", "lifecycle.json"],
        "fixture_execution_status": "STARTED" if process else "NOT_STARTED",
    })
    packet = {"schema_version": "1.0", "operation": "EXECUTE", "nonce": "e" * 32,
              "request_id": request.request_id, "run_id": RUN_ID,
              "worker_exit_code": 0, "target_environment": request.binding.target_environment,
              "worker_identity": {"pid": 100, "ppid": 90, "pgid": 90, "session_id": 90,
                  "start_ticks": 900, "uid": 1000, "gid": 1000, "state": "R"}, "worker_events": [],
              "record": record.model_dump(mode="json"), "recovery": None, "diagnostics": [],
              "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    recovery = {"recovery_schema_version": "1.0", "request_id": request.request_id, "run_id": RUN_ID,
                "status": "CONFIRMED", "worker_alive": False, "group_empty": True, "identity_match": True,
                "checked_at": "2026-10-14T00:00:03+00:00", "observer_pid": 200,
                "observer_uid": 1000, "diagnostics": []}
    recovery_packet = dict(packet, operation="STATUS", nonce="f" * 32, recovery=recovery,
        worker_identity={"pid": 200, "ppid": 90, "pgid": 90, "session_id": 90,
            "start_ticks": 1000, "uid": 1000, "gid": 1000, "state": "R"})

    def transport_for(value, run_id):
        original = synthetic_tool_record().model_dump(mode="json")
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        original.update(run_id=run_id, stdout_b64=base64.b64encode(raw).decode("ascii"), stdout_sha256=digest_bytes(raw))
        original["resource_limits"]["max_output_bytes"] = 1048576
        return seal_tool_result(original)

    result = {"record": record, "transport": transport_for(packet, "1" * 32), "worker_packet": packet,
              "recovery_transport": transport_for(recovery_packet, "2" * 32), "recovery_packet": recovery_packet}
    return result, {"request": request, "authorization": authorization if authorized else None, "policy": policy,
                    "snapshot": snapshot, "binding_tool_result": binding_tool}


class TestLifecycleArtifacts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def save(self, **options):
        result, context = synthetic_lifecycle_context(**options)
        return write_execution_evidence(self.root, result, **context), result, context

    def test_roundtrip_preserves_process_packet_authority_and_raw_bytes(self):
        folder, result, context = self.save()
        loaded = read_execution_evidence(folder, expected_request_id=context["request"].request_id,
                                          expected_run_id=result["record"].run_id)
        self.assertEqual(loaded["record"], result["record"])
        self.assertEqual(loaded["request"], context["request"])
        self.assertEqual(loaded["manifest"].effective_status, "COMPLETED")
        self.assertEqual(loaded["manifest"].cleanup_confirmation, "CONFIRMED")
        self.assertEqual((folder / "stdout.bin").read_bytes(), result["record"].process.stdout_bytes())
        self.assertEqual((folder / "worker_packet.json").read_bytes(), result["transport"].stdout_bytes())
        self.assertEqual(loaded["manifest"].verification_status, "NOT_VERIFIED")

    def test_report_rebuild_is_byte_identical_and_does_not_require_old_report(self):
        folder, _, _ = self.save()
        original = (folder / "report.md").read_text(encoding="utf-8")
        self.assertEqual(rebuild_execution_report(folder), original)
        (folder / "report.md").unlink()
        self.assertEqual(rebuild_execution_report(folder), original)
        with self.assertRaises(ValueError):
            read_execution_evidence(folder)

    def test_duplicate_run_does_not_overwrite_history(self):
        folder, result, context = self.save()
        old = (folder / "manifest.json").read_bytes()
        with self.assertRaises(EvidenceWriteError) as caught:
            write_execution_evidence(self.root, result, **context)
        self.assertEqual(caught.exception.record, result["record"])
        self.assertEqual((folder / "manifest.json").read_bytes(), old)

    def test_no_independent_recovery_remains_unknown_despite_remote_zero_exit(self):
        result, context = synthetic_lifecycle_context()
        result.update(recovery_transport=None, recovery_packet=None, effective_state="COMPLETED")
        folder = write_execution_evidence(self.root, result, **context)
        manifest = read_execution_evidence(folder)["manifest"]
        self.assertEqual(manifest.remote_status, "COMPLETED")
        self.assertEqual(manifest.effective_status, "UNKNOWN")
        self.assertEqual(manifest.cleanup_confirmation, "UNKNOWN")

    def test_rejected_and_unknown_have_deterministic_reports(self):
        for status in ("REJECTED", "UNKNOWN", "UNSUPPORTED", "START_FAILED"):
            with self.subTest(status=status):
                result, context = synthetic_lifecycle_context(status=status, authorized=status == "START_FAILED")
                folder = write_execution_evidence(self.root / status, result, **context)
                loaded = read_execution_evidence(folder)
                self.assertEqual(loaded["manifest"].effective_status, status)
                self.assertIn("No target process was confirmed started", rebuild_execution_report(folder))

    def test_nonzero_timeout_and_output_limit_never_claim_cve_success(self):
        for status, truncated in (("NONZERO_EXIT", False), ("TIMED_OUT", False), ("RESOURCE_LIMIT", True)):
            with self.subTest(status=status):
                folder, _, _ = self.save_at(status, status=status, truncated=truncated)
                loaded = read_execution_evidence(folder)
                self.assertEqual(loaded["manifest"].effective_status, status)
                self.assertEqual(loaded["manifest"].capture_complete, not truncated)
                self.assertEqual(loaded["manifest"].verification_status, "NOT_VERIFIED")

    def save_at(self, name, **options):
        result, context = synthetic_lifecycle_context(**options)
        return write_execution_evidence(self.root / name, result, **context), result, context

    def test_disk_write_failure_retains_observed_record_without_committed_manifest(self):
        result, context = synthetic_lifecycle_context()
        original_open = Path.open

        def fail_stdout(path, *args, **kwargs):
            if path.name == "stdout.bin" and args and args[0] == "xb":
                raise OSError("synthetic disk failure")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", fail_stdout), self.assertRaises(EvidenceWriteError) as caught:
            write_execution_evidence(self.root, result, **context)
        self.assertEqual(caught.exception.record, result["record"])
        self.assertEqual(caught.exception.storage_status, "INCOMPLETE")
        folder = Path(caught.exception.evidence_directory)
        self.assertFalse((folder / "manifest.json").exists())
        with self.assertRaises((OSError, ValueError)):
            read_execution_evidence(folder)

    def test_failed_launcher_has_report_without_invented_worker_or_cleanup(self):
        result, context = synthetic_lifecycle_context(status="UNKNOWN")
        changed = result["record"].model_dump(mode="python")
        changed.update(worker_pid=None, fixture_execution_status="UNKNOWN")
        result["record"] = ExecutionRecord.model_validate(changed)
        transport = synthetic_tool_record().model_dump(mode="python")
        transport.update(start_status="START_FAILED", end_status="START_FAILED", returncode=None,
                         stdout_b64="", stdout_sha256=digest_bytes(b""))
        transport["tool_identity"].update(status="UNKNOWN", resolved_path=None, file_sha256=None)
        result.update(transport=seal_tool_result(transport), worker_packet=None,
                      recovery_transport=None, recovery_packet=None)
        folder = write_execution_evidence(self.root, result, **context)
        loaded = read_execution_evidence(folder)
        self.assertIsNone(loaded["worker_packet"])
        self.assertEqual(loaded["manifest"].effective_status, "UNKNOWN")
        self.assertFalse(loaded["manifest"].capture_complete)
        report = rebuild_execution_report(folder)
        self.assertIn("Initial dispatch: START_FAILED", report)
        self.assertIn("Independent cleanup confirmation: UNKNOWN", report)

    def test_cancellation_request_retains_its_separate_transport_and_packet(self):
        result, context = synthetic_lifecycle_context()
        packet = deepcopy(result["recovery_packet"])
        packet.update(operation="CANCEL", recovery=None, record=None, nonce="8" * 32)
        raw = json.dumps(packet).encode("utf-8")
        transport = result["recovery_transport"].model_dump(mode="python")
        transport.update(run_id="9" * 32, stdout_b64=base64.b64encode(raw).decode("ascii"), stdout_sha256=digest_bytes(raw))
        result.update(cancellation_transport=seal_tool_result(transport), cancellation_packet=packet)
        folder = write_execution_evidence(self.root, result, **context)
        loaded = read_execution_evidence(folder)
        self.assertEqual(loaded["cancellation_packet"], packet)
        self.assertEqual((folder / "cancellation_packet.json").read_bytes(), raw)
        self.assertIn("Scoped cancellation: NORMAL_EXIT", rebuild_execution_report(folder))

    def test_invalid_primary_protocol_can_recover_exact_record_from_independent_status(self):
        result, context = synthetic_lifecycle_context()
        primary = result["transport"].model_dump(mode="python")
        raw = b"unparseable original primary protocol bytes"
        primary.update(stdout_b64=base64.b64encode(raw).decode("ascii"), stdout_sha256=digest_bytes(raw))
        result.update(transport=seal_tool_result(primary), worker_packet=None)
        folder = write_execution_evidence(self.root, result, **context)
        loaded = read_execution_evidence(folder)
        self.assertEqual(loaded["manifest"].effective_status, "COMPLETED")
        self.assertEqual(loaded["record"], result["record"])
        self.assertFalse(loaded["manifest"].capture_complete)
        self.assertEqual((folder / "transport_stdout.bin").read_bytes(), raw)

    def test_windows_fallback_time_cannot_override_unknown_remote_end_time(self):
        result, context = synthetic_lifecycle_context(status="UNKNOWN")
        record = result["record"].model_dump(mode="python")
        record.update(worker_pid=None, fixture_execution_status="UNKNOWN")
        result["record"] = ExecutionRecord.model_validate(record)
        raw = b"invalid primary protocol"
        primary = result["transport"].model_dump(mode="python")
        primary.update(stdout_b64=base64.b64encode(raw).decode("ascii"), stdout_sha256=digest_bytes(raw))
        result.update(transport=seal_tool_result(primary), worker_packet=None)
        result["recovery_packet"].update(record=None)
        result["recovery_packet"]["recovery"]["checked_at"] = "2020-01-01T00:00:00+00:00"
        replace_packet_bytes(result, "recovery_packet", "recovery_transport")
        folder = write_execution_evidence(self.root, result, **context)
        loaded = read_execution_evidence(folder)
        self.assertEqual(loaded["manifest"].effective_status, "UNKNOWN")
        self.assertEqual(loaded["manifest"].cleanup_confirmation, "UNKNOWN")
        self.assertIsNone(loaded["record"].worker_pid)
        self.assertIn("Effective status after independent cleanup check: UNKNOWN", rebuild_execution_report(folder))

    def test_remote_rejection_still_requires_independent_worker_recovery(self):
        for failed in (False, True):
            result, context = synthetic_lifecycle_context(status="REJECTED", authorized=False)
            if failed:
                result["recovery_packet"]["recovery"].update(status="FAILED", group_empty=False)
                replace_packet_bytes(result, "recovery_packet", "recovery_transport")
            else:
                result.update(recovery_transport=None, recovery_packet=None)
            folder = write_execution_evidence(self.root / str(failed), result, **context)
            manifest = read_execution_evidence(folder)["manifest"]
            self.assertEqual(manifest.remote_status, "REJECTED")
            self.assertEqual(manifest.effective_status, "CLEANUP_FAILED" if failed else "UNKNOWN")
            self.assertNotEqual(manifest.cleanup_confirmation, "NOT_STARTED")

    def test_request_cannot_declare_an_uncollected_legacy_tool_result(self):
        result, context = synthetic_lifecycle_context()
        request = context["request"].model_dump(mode="python")
        request.update(request_schema_version="1.0", expected_artifacts=["stdout.bin", "stderr.bin", "tool_result.json"])
        context["request"] = ExecutionRequest.model_validate(request)
        record = result["record"].model_dump(mode="python")
        record["request_sha256"] = request_sha256(context["request"])
        result["record"] = ExecutionRecord.model_validate(record)
        for packet_key, transport_key in (("worker_packet", "transport"), ("recovery_packet", "recovery_transport")):
            result[packet_key]["record"] = result["record"].model_dump(mode="json")
            replace_packet_bytes(result, packet_key, transport_key)
        with self.assertRaisesRegex(ValueError, "expected artifact"):
            write_execution_evidence(self.root, result, **context)

    def test_control_transport_zero_exit_does_not_hide_failed_worker_acknowledgement(self):
        result, context = synthetic_lifecycle_context()
        packet = deepcopy(result["recovery_packet"])
        packet.update(operation="CANCEL", recovery=None, record=None, nonce="8" * 32,
                      diagnostics=["CONTROL_IDENTITY_OR_RECOVERY_UNKNOWN"])
        result.update(cancellation_packet=packet, cancellation_transport=result["recovery_transport"])
        replace_packet_bytes(result, "cancellation_packet", "cancellation_transport")
        observed = result["cancellation_transport"].model_dump(mode="python")
        observed["run_id"] = "9" * 32
        result["cancellation_transport"] = seal_tool_result(observed)
        folder = write_execution_evidence(self.root, result, **context)
        report = rebuild_execution_report(folder)
        self.assertIn("Scoped cancellation: NORMAL_EXIT", report)
        self.assertIn("CONTROL_IDENTITY_OR_RECOVERY_UNKNOWN", report)

    @unittest.skipIf(os.name == "nt", "POSIX mode observation requires Linux")
    def test_private_directory_and_file_permissions(self):
        folder, _, _ = self.save()
        self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(file.stat().st_mode & 0o777 == 0o600 for file in folder.iterdir()))


class TestLifecycleEvidenceAssociation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def save(self):
        result, context = synthetic_lifecycle_context()
        return write_execution_evidence(self.root, result, **context), result, context

    @staticmethod
    def rehash(folder, name, value):
        raw = json.dumps(value).encode("utf-8") if not isinstance(value, bytes) else value
        (folder / name).write_bytes(raw)
        manifest = json.loads((folder / "manifest.json").read_bytes())
        manifest["artifacts"][name].update(size_bytes=len(raw), sha256=digest_bytes(raw))
        (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    def test_original_stdout_tamper_is_rejected(self):
        folder, _, _ = self.save()
        (folder / "stdout.bin").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "digest or length"):
            read_execution_evidence(folder)

    def test_rehashed_log_cannot_disagree_with_process_observation(self):
        folder, _, _ = self.save()
        self.rehash(folder, "stdout.bin", b"tampered and rehashed")
        with self.assertRaisesRegex(ValueError, "raw bytes association"):
            read_execution_evidence(folder)

    def test_rehashed_authorization_cannot_replace_original_issuer(self):
        folder, _, context = self.save()
        auth = context["authorization"].model_dump(mode="json")
        auth["issuer_kind"] = "trusted_policy"
        self.rehash(folder, "operator_authorization.json", auth)
        with self.assertRaisesRegex(ValueError, "authorization differs"):
            read_execution_evidence(folder)

    def test_rehashed_policy_cannot_replace_original_input(self):
        folder, _, context = self.save()
        policy = context["policy"].model_dump(mode="json")
        policy["max_snapshot_age_seconds"] += 1
        self.rehash(folder, "preflight_policy.json", policy)
        with self.assertRaisesRegex(ValueError, "policy differs"):
            read_execution_evidence(folder)

    def test_other_expected_run_or_request_is_rejected(self):
        folder, _, _ = self.save()
        for expected in ({"expected_request_id": "9" * 32}, {"expected_run_id": "9" * 32},
                         {"expected_record_sha256": "9" * 64}):
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, "identity mismatch"):
                read_execution_evidence(folder, **expected)

    def test_missing_raw_log_and_removed_manifest_entry_are_rejected(self):
        folder, _, _ = self.save()
        (folder / "stdout.bin").unlink()
        with self.assertRaises(ValueError):
            read_execution_evidence(folder)
        manifest = json.loads((folder / "manifest.json").read_bytes())
        del manifest["artifacts"]["stdout.bin"]
        (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "required"):
            read_execution_evidence(folder)

    def test_valid_transport_cannot_omit_worker_packet(self):
        result, context = synthetic_lifecycle_context()
        result["worker_packet"] = None
        with self.assertRaisesRegex(ValueError, "suppress its worker packet"):
            write_execution_evidence(self.root, result, **context)

    def test_worker_packet_cannot_be_added_after_receipt(self):
        result, context = synthetic_lifecycle_context()
        result["worker_packet"] = deepcopy(result["worker_packet"])
        result["worker_packet"]["diagnostics"].append("invented after receipt")
        with self.assertRaisesRegex(ValueError, "raw transport"):
            write_execution_evidence(self.root, result, **context)

    def test_unknown_manifest_path_or_missing_process_record_is_rejected(self):
        folder, _, _ = self.save()
        manifest = json.loads((folder / "manifest.json").read_bytes())
        manifest["artifacts"]["outside.json"] = {"file": "outside.json", "size_bytes": 0, "sha256": digest_bytes(b"")}
        (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unsupported"):
            read_execution_evidence(folder)

    def test_report_modification_is_rejected_but_rebuild_uses_originals(self):
        folder, _, _ = self.save()
        original = rebuild_execution_report(folder)
        (folder / "report.md").write_text("forged conclusion: CVE validated", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "report mismatch"):
            read_execution_evidence(folder)
        self.assertEqual(rebuild_execution_report(folder), original)

    def test_missing_original_authority_tool_or_snapshot_is_rejected(self):
        for field in ("authorization", "snapshot", "binding_tool_result"):
            result, context = synthetic_lifecycle_context()
            context[field] = None
            with self.subTest(field=field), self.assertRaises(ValueError):
                write_execution_evidence(self.root, result, **context)

    def test_removed_worker_or_process_artifact_cannot_be_hidden_in_manifest(self):
        for name in ("worker_packet.json", "process_result.json", "operator_authorization.json"):
            result, context = synthetic_lifecycle_context()
            folder = write_execution_evidence(self.root / name, result, **context)
            manifest = json.loads((folder / "manifest.json").read_bytes())
            del manifest["artifacts"][name]
            (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.subTest(name=name), self.assertRaises(ValueError):
                read_execution_evidence(folder)

    def test_changed_manifest_outcome_cannot_claim_completion_without_cleanup(self):
        result, context = synthetic_lifecycle_context()
        result.update(recovery_transport=None, recovery_packet=None)
        folder = write_execution_evidence(self.root, result, **context)
        manifest = json.loads((folder / "manifest.json").read_bytes())
        manifest.update(effective_status="COMPLETED", cleanup_confirmation="CONFIRMED")
        (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "outcome differs"):
            read_execution_evidence(folder)

    def test_cleanup_packet_from_another_run_cannot_supply_confirmation(self):
        result, context = synthetic_lifecycle_context()
        changed = deepcopy(result["recovery_packet"])
        changed["recovery"]["run_id"] = "8" * 32
        raw = json.dumps(changed).encode("utf-8")
        transport = result["recovery_transport"].model_dump(mode="python")
        transport.update(stdout_b64=base64.b64encode(raw).decode("ascii"), stdout_sha256=digest_bytes(raw))
        result.update(recovery_transport=seal_tool_result(transport), recovery_packet=changed)
        with self.assertRaisesRegex(ValueError, "another"):
            write_execution_evidence(self.root, result, **context)

    def test_duplicate_json_keys_and_nonfinite_json_are_rejected(self):
        folder, _, _ = self.save()
        for raw in (b'{"request_id":"one","request_id":"two"}', b'{"number":NaN}'):
            (folder / "manifest.json").write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                read_execution_evidence(folder)

    @unittest.skipIf(os.name == "nt", "POSIX symlink fixture requires Linux")
    def test_evidence_file_symlink_is_rejected(self):
        folder, _, _ = self.save()
        raw = (folder / "stdout.bin").read_bytes()
        outside = self.root / "outside.bin"
        outside.write_bytes(raw)
        (folder / "stdout.bin").unlink()
        (folder / "stdout.bin").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            read_execution_evidence(folder)
