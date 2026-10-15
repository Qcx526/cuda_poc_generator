"""Independent bridge/identity regressions; all launcher results are synthetic."""

import base64
from copy import deepcopy
import json
import threading
import unittest
from unittest.mock import patch

from src import lifecycle_bridge as bridge
from src.models.lifecycle import ExecutionRecord
from src.models.tool_result import digest_argv, digest_bytes, seal_tool_result
from src.tool_artifacts import ToolEvidenceError
from tests.test_lifecycle_artifacts import RUN_ID, synthetic_lifecycle_context
from tests.test_p1c_integration import synthetic_tool_record


def worker_identity(pid):
    return {"pid": pid, "ppid": 90, "pgid": 90, "session_id": 90, "start_ticks": 900,
            "uid": 1000, "gid": 1000, "state": "R"}


def observed_packets():
    result, context = synthetic_lifecycle_context()
    result["worker_packet"]["worker_identity"] = worker_identity(100)
    result["recovery_packet"]["worker_identity"] = worker_identity(200)
    return result, context


def launcher_record(raw, *, run_id="1" * 32, status="NORMAL_EXIT"):
    """Fabricated Windows launcher observation; no subprocess is created."""
    value = synthetic_tool_record().model_dump(mode="python")
    executable = "C:\\Windows\\System32\\wsl.exe"
    value.update(run_id=run_id, argv=[executable, "--distribution", "Ubuntu-22.04", "--exec", "/tools/python", "-I", "-"],
                 cwd="C:\\workspace", evidence_directory="C:\\private-evidence\\" + run_id,
                 target_environment="windows", platform_type="windows", stdout_b64=base64.b64encode(raw).decode("ascii"),
                 stdout_sha256=digest_bytes(raw))
    value["command_identity"]["argv_sha256"] = digest_argv(value["argv"])
    value["tool_identity"].update(requested_executable=executable, resolved_path=executable)
    value["resource_limits"].update(termination_scope="WINDOWS_DIRECT_CHILD", max_output_bytes=16777216)
    if status == "START_FAILED":
        value.update(start_status="START_FAILED", end_status="START_FAILED", returncode=None)
        value["tool_identity"].update(status="UNKNOWN", resolved_path=None, file_sha256=None)
    elif status == "NONZERO_EXIT":
        value.update(end_status="NONZERO_EXIT", returncode=5)
    return seal_tool_result(value)


class TestLifecyclePacketIndependentAudit(unittest.TestCase):
    def setUp(self):
        self.result, self.context = observed_packets()
        self.packet = self.result["worker_packet"]
        self.request = self.context["request"]

    def parse(self, packet, *, operation="EXECUTE"):
        raw = packet if isinstance(packet, bytes) else json.dumps(packet).encode("utf-8")
        return bridge.parse_lifecycle_packet(raw, operation=operation, nonce="e" * 32,
            request_id=self.request.request_id, run_id=RUN_ID,
            target_environment=self.request.binding.target_environment, expected_request=self.request)

    def test_exact_observed_process_packet_preserves_request(self):
        result = self.parse(self.packet)
        self.assertEqual(result["record"]["status"], "COMPLETED")
        self.assertEqual(result["record"]["process"]["pid"], 110)
        self.assertEqual(result["verification_status"], "NOT_VERIFIED")

    def test_request_run_nonce_target_and_unknown_field_confusion_rejected(self):
        for field, value in (("request_id", "9" * 32), ("run_id", "9" * 32), ("nonce", "9" * 32),
                             ("target_environment", "wsl:Other"), ("arbitrary_field", True)):
            changed = deepcopy(self.packet)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.parse(changed)

    def test_zero_boolean_worker_code_and_nonfinite_or_duplicate_json_rejected(self):
        changed = deepcopy(self.packet)
        changed["worker_exit_code"] = False
        with self.assertRaises(ValueError):
            self.parse(changed)
        for raw in (b'{"nonce":"one","nonce":"two"}', b'{"float":NaN}', b"not JSON", b"\xff"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.parse(raw)

    def test_record_cannot_change_request_hash_or_observed_worker_pid(self):
        for change in ("request_sha256", "worker_pid", "tool_identity", "cwd"):
            packet = deepcopy(self.packet)
            if change == "request_sha256":
                packet["record"][change] = "d" * 64
            elif change == "worker_pid":
                packet["worker_identity"]["pid"] += 1
            elif change == "tool_identity":
                packet["record"]["tool_identity"]["file_sha256"] = "d" * 64
                packet["record"]["process"]["tool_identity"]["file_sha256"] = "d" * 64
            else:
                packet["record"]["process"]["cwd"] = "/another-directory"
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.parse(packet)

    def test_status_recovery_cannot_be_relabelled_as_execute_response(self):
        packet = deepcopy(self.result["recovery_packet"])
        packet["nonce"] = "e" * 32
        with self.assertRaises(ValueError):
            self.parse(packet)

    def test_remote_record_requires_actual_worker_identity(self):
        packet = deepcopy(self.packet)
        packet["worker_identity"] = None
        with self.assertRaisesRegex(ValueError, "worker identity"):
            self.parse(packet)

    def test_recovery_observer_pid_or_uid_must_match_actual_control_worker(self):
        for field in ("observer_pid", "observer_uid"):
            packet = deepcopy(self.result["recovery_packet"])
            packet["nonce"] = "e" * 32
            packet["recovery"][field] += 1
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "observer"):
                self.parse(packet, operation="STATUS")


class TestFixedLauncherTransport(unittest.TestCase):
    def setUp(self):
        self.result, self.context = observed_packets()
        self.handle = bridge.TaskHandle(request_id=self.context["request"].request_id, run_id=RUN_ID,
            control_token="d" * 64, distro="Ubuntu-22.04", user="pocdev", linux_python="/tools/python",
            linux_project_root="/workspace")
        self.payload = {"operation": "EXECUTE", "nonce": "e" * 32}

    def dispatch(self, observed, error=None):
        with patch.object(bridge.os, "name", "nt"), patch.object(bridge, "measure_tool_identity", return_value=observed.tool_identity), \
                patch.object(bridge, "build_execution_worker_source", return_value=b"fixed trusted worker source"), \
                patch.object(bridge, "run_tool", return_value=observed, side_effect=error) as run:
            result = bridge._transport(self.payload, self.handle, expected_request=self.context["request"])
        return result, run

    def test_fixed_argv_uses_no_shell_and_pins_measured_launcher_file(self):
        raw = json.dumps(self.result["worker_packet"]).encode("utf-8")
        observed = launcher_record(raw)
        (actual, packet, diagnostics), run = self.dispatch(observed)
        self.assertEqual(actual, observed)
        self.assertEqual(packet["record"]["status"], "COMPLETED")
        self.assertEqual(diagnostics, [])
        argv = run.call_args.args[0]
        self.assertEqual(argv[-4:], ["--exec", "/tools/python", "-I", "-"])
        self.assertNotIn("--shell", argv)
        self.assertEqual(run.call_args.kwargs["allowed_tool_identities"],
                         {observed.tool_identity.resolved_path: observed.tool_identity.file_sha256})

    def test_invalid_protocol_preserves_original_raw_launcher_record(self):
        observed = launcher_record(b"invalid harmless protocol bytes")
        (actual, packet, diagnostics), _ = self.dispatch(observed)
        self.assertEqual(actual.stdout_bytes(), b"invalid harmless protocol bytes")
        self.assertIsNone(packet)
        self.assertEqual(diagnostics, ["WSL_LIFECYCLE_PROTOCOL_INVALID"])

    def test_start_failure_or_nonzero_cannot_create_a_worker_packet(self):
        for status in ("START_FAILED", "NONZERO_EXIT"):
            with self.subTest(status=status):
                observed = launcher_record(b"", status=status)
                (actual, packet, diagnostics), run = self.dispatch(observed)
                self.assertEqual(actual.end_status, status)
                self.assertIsNone(packet)
                self.assertEqual(diagnostics, ["WSL_LAUNCHER_" + status])
                if status == "START_FAILED":
                    self.assertEqual(run.call_args.kwargs["allowed_tool_identities"], {})

    def test_arbitrary_control_operation_is_rejected_before_transport(self):
        with patch.object(bridge, "_transport") as launch, self.assertRaises(ValueError):
            bridge.control_task_wsl(self.handle, operation="EXECUTE_CANDIDATE")
        launch.assert_not_called()

    def test_log_storage_failure_preserves_actual_observed_bytes_if_available(self):
        raw = json.dumps(self.result["worker_packet"]).encode("utf-8")
        observed = launcher_record(raw)
        error = ToolEvidenceError("synthetic disk failure", tool_result=observed)
        (actual, packet, diagnostics), _ = self.dispatch(observed, error)
        self.assertEqual(actual, observed)
        self.assertEqual(actual.stdout_bytes(), raw)
        self.assertEqual(packet["record"]["status"], "COMPLETED")
        self.assertIn("LAUNCHER_EVIDENCE_WRITE_FAILED_RAW_OBSERVATION_RECOVERED", diagnostics)

    def test_storage_failure_without_observation_cannot_fabricate_tool_result(self):
        observed = launcher_record(b"")
        with self.assertRaises(ToolEvidenceError):
            self.dispatch(observed, ToolEvidenceError("synthetic early disk failure"))


class TestWholeBridgeSafeMocks(unittest.TestCase):
    def setUp(self):
        self.result, self.context = observed_packets()
        self.calls = []

    def dispatch(self, *, primary_lost=False, recovery_status="CONFIRMED", recovery_missing=False):
        def fake_transport(payload, handle, **kwargs):
            operation = payload["operation"]
            self.calls.append(operation)
            if operation == "EXECUTE" and primary_lost:
                return launcher_record(b"", status="NONZERO_EXIT"), None, ["WSL_LAUNCHER_NONZERO_EXIT"]
            packet = deepcopy(self.result["worker_packet"] if operation == "EXECUTE" else self.result["recovery_packet"])
            packet.update(nonce=payload["nonce"], operation=operation)
            if operation == "CANCEL":
                packet.update(record=None, recovery=None)
            elif operation == "STATUS":
                if recovery_missing:
                    return launcher_record(b"", run_id="2" * 32, status="NONZERO_EXIT"), None, ["WSL_LAUNCHER_NONZERO_EXIT"]
                packet["recovery"].update(status=recovery_status, worker_alive=recovery_status == "UNKNOWN",
                                         group_empty=recovery_status != "FAILED")
            raw = json.dumps(packet).encode("utf-8")
            return launcher_record(raw, run_id={"EXECUTE": "1", "STATUS": "2", "CANCEL": "4"}[operation] * 32), packet, []

        with patch.object(bridge, "_transport", side_effect=fake_transport):
            return bridge.run_task_wsl(self.context["request"], self.context["authorization"], self.context["policy"],
                self.context["snapshot"], self.context["binding_tool_result"], linux_project_root="/workspace", run_id=RUN_ID)

    def test_completion_requires_independent_worker_exit_and_group_absence(self):
        result = self.dispatch()
        self.assertEqual(result["effective_state"], "COMPLETED")
        self.assertEqual(self.calls, ["EXECUTE", "STATUS"])

    def test_live_worker_or_missing_recovery_keeps_unknown(self):
        for options in ({"recovery_status": "UNKNOWN"}, {"recovery_missing": True}):
            with self.subTest(options=options):
                result = self.dispatch(**options)
                self.assertEqual(result["effective_state"], "UNKNOWN")
                self.assertEqual(result["record"]["status"], "COMPLETED")

    def test_remaining_remote_processes_require_cleanup_failed(self):
        result = self.dispatch(recovery_status="FAILED")
        self.assertEqual(result["effective_state"], "CLEANUP_FAILED")

    def test_lost_primary_launcher_uses_scoped_cancel_and_independent_record_recovery(self):
        result = self.dispatch(primary_lost=True)
        self.assertEqual(self.calls, ["EXECUTE", "CANCEL", "STATUS"])
        self.assertIsNone(result["worker_packet"])
        self.assertEqual(result["effective_state"], "COMPLETED")
        self.assertEqual(result["record"]["run_id"], RUN_ID)
        self.assertIn("cancellation_transport", result)

    def test_both_lost_transports_do_not_fabricate_native_pid_or_fixture_status(self):
        result = self.dispatch(primary_lost=True, recovery_missing=True)
        record = ExecutionRecord.model_validate(result["record"])
        self.assertEqual(result["effective_state"], "UNKNOWN")
        self.assertIsNone(record.process)
        self.assertIsNone(record.worker_pid)
        self.assertEqual(record.fixture_execution_status, "UNKNOWN")

    def test_dispatch_observer_exception_still_attempts_scoped_cancel_and_status(self):
        def fake(payload, handle, **kwargs):
            self.calls.append(payload["operation"])
            if payload["operation"] == "EXECUTE":
                raise ToolEvidenceError("synthetic disk full; no actual ToolResult")
            packet = deepcopy(self.result["recovery_packet"])
            packet.update(operation=payload["operation"], nonce=payload["nonce"])
            if payload["operation"] == "CANCEL":
                packet.update(record=None, recovery=None)
            return launcher_record(json.dumps(packet).encode("utf-8"), run_id="2" * 32), packet, []

        with patch.object(bridge, "_transport", side_effect=fake), self.assertRaises(bridge.LifecycleDispatchError) as caught:
            bridge.run_task_wsl(self.context["request"], self.context["authorization"], self.context["policy"],
                self.context["snapshot"], self.context["binding_tool_result"], linux_project_root="/workspace", run_id=RUN_ID)
        self.assertEqual(self.calls, ["EXECUTE", "CANCEL", "STATUS"])
        self.assertIsNone(caught.exception.result["transport"])
        self.assertEqual(caught.exception.storage_status, "INCOMPLETE")
        self.assertIn("Status: UNKNOWN", caught.exception.report)
        self.assertIn("NOT_VERIFIED", caught.exception.report)

    def test_control_observer_exceptions_are_reported_without_false_cleanup(self):
        def fake(payload, handle, **kwargs):
            self.calls.append(payload["operation"])
            if payload["operation"] != "EXECUTE":
                raise OSError("synthetic unavailable observer")
            packet = deepcopy(self.result["worker_packet"])
            packet["nonce"] = payload["nonce"]
            return launcher_record(json.dumps(packet).encode("utf-8")), packet, []

        with patch.object(bridge, "_transport", side_effect=fake), self.assertRaises(bridge.LifecycleDispatchError) as caught:
            bridge.run_task_wsl(self.context["request"], self.context["authorization"], self.context["policy"],
                self.context["snapshot"], self.context["binding_tool_result"], linux_project_root="/workspace", run_id=RUN_ID)
        self.assertEqual(self.calls, ["EXECUTE", "STATUS"])
        self.assertIsNone(caught.exception.result["recovery_transport"])
        self.assertEqual(caught.exception.result["effective_state"], "UNKNOWN")

    def test_cancel_retries_only_same_task_until_durable_lease_available(self):
        allow_finish = threading.Event()
        seen_handles = []
        cancel_count = 0

        def fake(payload, handle, **kwargs):
            nonlocal cancel_count
            operation = payload["operation"]
            seen_handles.append(handle)
            if operation == "EXECUTE":
                if not allow_finish.wait(5):
                    raise OSError("synthetic test cancellation did not arrive")
                packet = deepcopy(self.result["worker_packet"])
            else:
                packet = deepcopy(self.result["recovery_packet"])
            packet.update(operation=operation, nonce=payload["nonce"])
            if operation == "CANCEL":
                cancel_count += 1
                packet["record"] = None
                if cancel_count < 3:
                    packet.update(recovery=None, diagnostics=["CONTROL_IDENTITY_OR_RECOVERY_UNKNOWN"])
                else:
                    packet["recovery"].update(status="UNKNOWN", worker_alive=True)
                    allow_finish.set()
            return launcher_record(json.dumps(packet).encode("utf-8"), run_id="2" * 32), packet, []

        with patch.object(bridge, "_transport", side_effect=fake):
            result = bridge.run_task_wsl(self.context["request"], self.context["authorization"], self.context["policy"],
                self.context["snapshot"], self.context["binding_tool_result"], linux_project_root="/workspace",
                run_id=RUN_ID, cancel_after_seconds=0)
        self.assertEqual(cancel_count, 3)
        self.assertTrue(all(handle == seen_handles[0] for handle in seen_handles))
        self.assertEqual(result["effective_state"], "COMPLETED")

    def test_task_created_observer_is_trusted_callable_and_runs_before_dispatch(self):
        for invalid in ("LLM observer", True, 1, {}):
            with self.subTest(invalid=invalid), patch.object(bridge, "_transport") as launch, self.assertRaises(ValueError):
                bridge.run_task_wsl(self.context["request"], self.context["authorization"], self.context["policy"],
                    self.context["snapshot"], self.context["binding_tool_result"], linux_project_root="/workspace",
                    run_id=RUN_ID, on_task_created=invalid)
            launch.assert_not_called()
        with patch.object(bridge, "_transport") as launch:
            def refuse_handle(_):
                raise OSError("synthetic operator handle could not be persisted")
            with self.assertRaises(OSError):
                bridge.run_task_wsl(self.context["request"], self.context["authorization"], self.context["policy"],
                    self.context["snapshot"], self.context["binding_tool_result"], linux_project_root="/workspace",
                    run_id=RUN_ID, on_task_created=refuse_handle)
            launch.assert_not_called()
