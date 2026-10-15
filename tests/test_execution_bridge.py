"""Offline P2-A transport/registry tests; no WSL or GPU process is launched."""

import base64
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src import execution_bridge as bridge
from src import execution_worker as worker
from src.models.execution import (ExecutionRequest, OperatorAuthorization, PreflightPolicy,
                                  PreflightResult, request_sha256, snapshot_sha256)
from src.models.execution_binding import bind_candidate_to_tool
from src.models.platform import PlatformSnapshot
from src.models.tool_result import digest_argv, digest_bytes, seal_tool_result
from tests import test_execution_preflight as preflight_fixture
from tests.test_platform_probe import packet


NONCE = "e" * 32


def fixed_request():
    """Synthetic contract helper; none of its file/tool observations are real."""
    base = preflight_fixture.TestExecutionPreflight("test_complete_strict_request_ready_without_launching")
    base.setUp()
    try:
        req = deepcopy(base.request)
        snapshot = deepcopy(base.snapshot)
        record = base.record
        req.update(candidate_sha256=worker.FIXTURE_SHA256,
                   candidate_path="/workspace/" + worker.FIXTURE_RELATIVE_PATH, cwd="/workspace")
        req["binding"] = bind_candidate_to_tool(worker.FIXTURE_SOURCE, snapshot, record,
                                               expected_probe_id=req["platform_probe_id"],
                                               expected_tool_record_id=record.record_id).model_dump(mode="json")
        return ExecutionRequest.model_validate(req), snapshot, record
    finally:
        base.doCleanups()


def fixture_authority(request, snapshot):
    """Entirely synthetic authority records for offline evidence regressions."""
    authorization = OperatorAuthorization(
        request_id=request.request_id, authorization_reference=request.authorization_reference,
        operator_id="test-operator", issuer_kind="operator", candidate_sha256=request.candidate_sha256,
        platform_environment_id=request.platform_environment_id, platform_probe_id=request.platform_probe_id,
        authorized_action=request.authorized_action, fixture_id=request.fixture_id,
        tool_resolved_path=request.tool_identity.resolved_path, tool_file_sha256=request.tool_identity.file_sha256,
        resource_limits=request.resource_limits,
        not_before=(preflight_fixture.NOW - timedelta(seconds=30)).isoformat(),
        expires_at=(preflight_fixture.NOW + timedelta(seconds=30)).isoformat())
    policy = PreflightPolicy(
        expected_environment_id=request.platform_environment_id, expected_probe_id=request.platform_probe_id,
        expected_snapshot_sha256=snapshot_sha256(snapshot), expected_target_environment=request.binding.target_environment,
        execution_backend="wsl", allowed_operator_ids=[authorization.operator_id],
        allowed_authorization_references=[request.authorization_reference], scope_root=request.cwd,
        allowed_tools={request.tool_identity.resolved_path: request.tool_identity.file_sha256},
        fixture_hashes={worker.FIXTURE_ID: worker.FIXTURE_SHA256},
        resource_support={"status": "OBSERVED", "mechanisms": ["WALL_WATCHDOG", "OUTPUT_CAP", "POSIX_PROCESS_GROUP", "RLIMIT_CPU", "RLIMIT_AS"],
                          "source": "synthetic offline resource capability observation"},
        max_resource_limits=request.resource_limits)
    return authorization, policy


def execution_packet(*, operation="FIXED_FIXTURE"):
    request, snapshot, original = fixed_request()
    authorization, policy = fixture_authority(request, snapshot)
    proof = worker.expected_resource_proof(request, NONCE)
    raw = worker.proof_bytes(proof)
    record = original.model_dump(mode="json")
    record["argv"] = [request.tool_identity.resolved_path, "-I", "-c", worker.FIXTURE_SOURCE.decode("utf-8")]
    record["command_identity"]["argv_sha256"] = digest_argv(record["argv"])
    config = {"request_id": request.request_id, "nonce": NONCE,
              "cpu_seconds": request.resource_limits.cpu_seconds,
              "memory_bytes": request.resource_limits.memory_bytes}
    stdin = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
    record.update(cwd=request.cwd, stdin_sha256=digest_bytes(stdin), stdin_size_bytes=len(stdin))
    record.update(stdout_b64=base64.b64encode(raw).decode("ascii"), stdout_sha256=digest_bytes(raw))
    record = seal_tool_result(record)
    preflight = PreflightResult(request_id=request.request_id, status="READY", diagnostics=[],
                                checked_at="2026-10-14T00:00:02+00:00",
                                measured_candidate_sha256=worker.FIXTURE_SHA256,
                                measured_tool_sha256=request.tool_identity.file_sha256)
    value = {"schema_version": "1.0", "operation": operation, "nonce": NONCE,
             "request_id": request.request_id, "worker_exit_code": 0, "status": "FIXTURE_COMPLETED",
             "request_sha256": request_sha256(request),
             "authorization_sha256": worker.contract_digest(OperatorAuthorization, authorization),
             "policy_sha256": worker.contract_digest(PreflightPolicy, policy),
             "target_snapshot": snapshot, "current_snapshot": deepcopy(snapshot),
             "target_environment": "wsl:Ubuntu-22.04", "tool_result": record.model_dump(mode="json"),
             "fixture_id": worker.FIXTURE_ID, "fixture_sha256": worker.FIXTURE_SHA256,
             "fixture_path": request.candidate_path, "cwd": request.cwd,
             "preflight": preflight.model_dump(mode="json"), "resource_proof": proof,
             "resource_support": {"status": "OBSERVED", "mechanisms": ["WALL_WATCHDOG", "OUTPUT_CAP", "POSIX_PROCESS_GROUP", "RLIMIT_CPU", "RLIMIT_AS"],
                                  "source": "synthetic offline resource capability observation"},
             "diagnostics": [], "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    return value, request


class TestExecutionPacket(unittest.TestCase):
    def parse(self, payload, request):
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        return bridge.parse_execution_packet(raw, operation="FIXED_FIXTURE", nonce=NONCE,
                                             request_id=request.request_id, target_environment="wsl:Ubuntu-22.04",
                                             expected_request=request)

    def test_exact_fixed_fixture_evidence_and_request_match(self):
        payload, request = execution_packet()
        parsed = self.parse(payload, request)
        self.assertEqual(parsed["status"], "FIXTURE_COMPLETED")
        self.assertEqual(parsed["candidate_execution_status"], "NOT_EXECUTED")
        self.assertEqual(parsed["verification_status"], "NOT_VERIFIED")

    def test_nonce_request_target_or_unknown_field_rejected(self):
        payload, request = execution_packet()
        for field, value in (("nonce", "f" * 32), ("request_id", "d" * 32),
                             ("target_environment", "wsl:Other"), ("extra", True)):
            changed = deepcopy(payload)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.parse(changed, request)

    def test_exact_request_content_hash_cannot_be_replaced_with_same_id(self):
        payload, request = execution_packet()
        changed = request.model_dump(mode="python")
        changed["authorization_reference"] = "another-reference-with-same-request-id"
        with self.assertRaises(ValueError):
            self.parse(payload, ExecutionRequest.model_validate(changed))
        payload["request_sha256"] = None
        with self.assertRaises(ValueError):
            self.parse(payload, request)

    def test_boolean_worker_exit_code_is_not_an_integer_observation(self):
        payload, request = execution_packet()
        payload["worker_exit_code"] = False
        with self.assertRaises(ValueError):
            self.parse(payload, request)

    def test_rejected_preflight_cannot_contain_a_launched_fixture(self):
        payload, request = execution_packet()
        payload.update(status="REJECTED", resource_proof=None)
        with self.assertRaises(ValueError):
            self.parse(payload, request)

    def test_changed_resource_proof_or_stdout_cannot_claim_completion(self):
        payload, request = execution_packet()
        payload["resource_proof"]["cpu_seconds"] += 1
        with self.assertRaises(ValueError):
            self.parse(payload, request)
        payload, request = execution_packet()
        payload["resource_proof"]["cpu_seconds"] = True
        with self.assertRaises(ValueError):
            self.parse(payload, request)
        payload, request = execution_packet()
        record = payload["tool_result"]
        record.update(stdout_b64="", stdout_sha256=digest_bytes(b""))
        payload["tool_result"] = seal_tool_result(record).model_dump(mode="json")
        with self.assertRaises(ValueError):
            self.parse(payload, request)

    def test_modified_argv_or_executable_or_preflight_rejected(self):
        for mode in ("argv", "identity", "preflight"):
            payload, request = execution_packet()
            if mode == "preflight":
                payload["preflight"].update(status="REJECTED", diagnostics=[{"code": "DENIED", "message": "denied"}])
            else:
                record = payload["tool_result"]
                if mode == "argv":
                    record["argv"][-1] = "print('arbitrary code is forbidden')"
                    record["command_identity"]["argv_sha256"] = digest_argv(record["argv"])
                else:
                    record["tool_identity"]["file_sha256"] = "f" * 64
                payload["tool_result"] = seal_tool_result(record).model_dump(mode="json")
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.parse(payload, request)

    def test_weaker_observed_limits_or_wrong_stdin_are_rejected(self):
        for mode in ("timeout", "output", "stdin", "cwd"):
            payload, request = execution_packet()
            record = payload["tool_result"]
            if mode == "timeout":
                record["resource_limits"]["timeout_seconds"] = 4.0
            elif mode == "output":
                record["resource_limits"]["max_output_bytes"] = 8192
            elif mode == "stdin":
                record["stdin_sha256"] = "f" * 64
            else:
                record["cwd"] = "/foreign"
            payload["tool_result"] = seal_tool_result(record).model_dump(mode="json")
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.parse(payload, request)

    def test_duplicate_nonfinite_truncated_and_nonjson_rejected(self):
        payload, request = execution_packet()
        for raw in (b"{}", b"not json", b'{"nonce":"a","nonce":"b"}', b'{"number":NaN}', b'{"nonce":'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.parse(raw, request)

    def test_completed_packet_requires_expected_request(self):
        payload, request = execution_packet()
        with self.assertRaises(ValueError):
            bridge.parse_execution_packet(json.dumps(payload).encode(), operation="FIXED_FIXTURE", nonce=NONCE,
                                           request_id=request.request_id, target_environment="wsl:Ubuntu-22.04")


class TestFixedWorker(unittest.TestCase):
    def payload(self):
        return {"operation": "DESCRIBE", "nonce": NONCE, "request": None,
                "authorization": None, "snapshot": None, "tool_record": None, "policy": None}

    def test_tracked_fixture_exactly_matches_immutable_registry_bytes(self):
        root = Path(__file__).resolve().parent.parent
        self.assertEqual((root / worker.FIXTURE_RELATIVE_PATH).read_bytes(), worker.FIXTURE_SOURCE)
        self.assertEqual(digest_bytes(worker.FIXTURE_SOURCE), worker.FIXTURE_SHA256)

    def test_non_wsl_worker_rejected_without_launch(self):
        with patch.object(worker, "current_platform_type", return_value="windows"), patch.object(worker, "run_tool") as runner:
            value = worker.handle_worker(self.payload())
        self.assertEqual(value["status"], "REJECTED")
        self.assertIn("WORKER_NOT_WSL", value["diagnostics"])
        runner.assert_not_called()

    def test_replaced_fixture_rejected_without_any_probe_or_launch(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / worker.FIXTURE_RELATIVE_PATH
            source.parent.mkdir(parents=True)
            source.write_bytes(b"print('different bytes')\n")
            with patch.object(worker, "current_platform_type", return_value="wsl"), \
                    patch.object(worker, "canonical_target_environment", return_value="wsl:Ubuntu-22.04"), \
                    patch.object(worker, "_snapshot") as probe, patch.object(worker, "run_tool") as runner:
                value = worker.handle_worker(self.payload(), project_root=folder)
        self.assertEqual(value["status"], "REJECTED")
        probe.assert_not_called()
        runner.assert_not_called()

    def test_describe_cannot_smuggle_execution_parameters(self):
        payload = self.payload()
        payload["authorization"] = {"issuer_kind": "llm"}
        snapshot = PlatformSnapshot.model_validate(packet()["snapshot"])
        with patch.object(worker, "current_platform_type", return_value="wsl"), \
                patch.object(worker, "canonical_target_environment", return_value="wsl:Ubuntu-22.04"), \
                patch.object(worker, "_snapshot", return_value=snapshot), patch.object(worker, "run_tool") as runner:
            value = worker.handle_worker(payload)
        self.assertEqual(value["status"], "REJECTED")
        runner.assert_not_called()

    def test_bootstrap_pins_source_and_never_builds_shell_command(self):
        source = bridge.build_execution_worker_source(self.payload(), linux_project_root="/mnt/f/qcx/code/cuda_poc_generator")
        self.assertIn(b"trusted worker source identity mismatch", source)
        self.assertIn(worker.FIXTURE_SHA256.encode(), source)
        self.assertIn(b"compile(SOURCES[self.relative]", source)
        self.assertIn(b"sys.meta_path.insert(0,VerifiedFinder())", source)
        self.assertNotIn(b"sys.path.insert", source)
        self.assertNotIn(b"shell=True", source)
        compile(source, "<fixed-bootstrap>", "exec")

    def test_windows_path_and_traversal_are_not_linux_roots(self):
        for root in ("F:\\source", "/home/user/../other", "relative", "//server/share", "/tmp/line\nnext"):
            with self.subTest(root=root), self.assertRaises(ValueError):
                bridge.build_execution_worker_source(self.payload(), linux_project_root=root)

    def test_unknown_operation_never_enters_a_dispatcher(self):
        payload = self.payload()
        payload["operation"] = "EXECUTE_CANDIDATE"
        with patch.object(worker, "run_tool") as runner, self.assertRaises(ValueError):
            worker.handle_worker(payload)
        runner.assert_not_called()

    def test_fixed_python_role_cannot_select_another_allowlisted_executable(self):
        request, snapshot, record = fixed_request()
        payload = {**self.payload(), "operation": "FIXED_FIXTURE", "request": request.model_dump(mode="json"),
                   "snapshot": snapshot, "tool_record": record.model_dump(mode="json"),
                   "authorization": None, "policy": None}
        # A syntactically valid policy is enough for this early identity check;
        # it still does not grant the missing operator authorization.
        helper = preflight_fixture.TestExecutionPreflight("test_complete_strict_request_ready_without_launching")
        helper.setUp()
        self.addCleanup(helper.doCleanups)
        payload["policy"] = helper.policy
        actual = record.tool_identity.model_copy(update={"resolved_path": "/usr/bin/python3.10"})
        with patch.object(worker, "current_platform_type", return_value="wsl"), \
                patch.object(worker, "canonical_target_environment", return_value="wsl:Ubuntu-22.04"), \
                patch.object(worker, "_snapshot", return_value=PlatformSnapshot.model_validate(snapshot)), \
                patch.object(worker, "measure_tool_identity", return_value=actual), \
                patch.object(worker, "run_tool") as runner:
            value = worker.handle_worker(payload)
        self.assertEqual(value["status"], "REJECTED")
        self.assertIn("WORKER_PYTHON_IDENTITY_MISMATCH", value["diagnostics"])
        runner.assert_not_called()

    def test_known_hard_resource_caps_reject_infeasible_limits_before_launch(self):
        fake_resource = SimpleNamespace(setrlimit=lambda *args: None, getrlimit=lambda _: (1, 1),
                                        RLIMIT_CPU=0, RLIMIT_AS=9, RLIM_INFINITY=-1)
        limits = SimpleNamespace(cpu_seconds=2, memory_bytes=134217728)
        with patch.dict("sys.modules", {"resource": fake_resource}), \
                patch.object(worker.os, "name", "posix"), patch.object(worker.os, "killpg", create=True):
            observed = worker.resource_capabilities(limits)
        self.assertEqual(observed["status"], "UNSUPPORTED")
        self.assertEqual(observed["mechanisms"], [])

    def test_resource_observation_failure_is_unknown(self):
        def failure(_):
            raise OSError("synthetic capability query failure")
        fake_resource = SimpleNamespace(setrlimit=lambda *args: None, getrlimit=failure,
                                        RLIMIT_CPU=0, RLIMIT_AS=9, RLIM_INFINITY=-1)
        limits = SimpleNamespace(cpu_seconds=2, memory_bytes=134217728)
        with patch.dict("sys.modules", {"resource": fake_resource}), \
                patch.object(worker.os, "name", "posix"), patch.object(worker.os, "killpg", create=True):
            observed = worker.resource_capabilities(limits)
        self.assertEqual(observed["status"], "UNKNOWN")
        self.assertEqual(observed["mechanisms"], [])
