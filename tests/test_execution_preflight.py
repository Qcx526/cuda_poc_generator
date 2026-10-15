"""Offline preflight regressions; fixture/tool files are never executed.

Portable tests explicitly map synthetic POSIX paths onto a temporary directory.
That mapping is test-only and does not make Windows a WSL filesystem observer.
"""

from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path, PurePosixPath
import tempfile
import unittest
from unittest.mock import patch

from src.execution_preflight import preflight_execution
from src.models.execution import (ExecutionRequest, OperatorAuthorization,
                                  PreflightPolicy, request_sha256, snapshot_sha256)
from src.models.execution_binding import bind_candidate_to_tool
from src.models.platform import seal_snapshot
from src.models.tool_result import ToolIdentity, digest_argv, seal_tool_result
from tests.test_p1c_integration import synthetic_tool_record
from tests.test_platform_probe import packet


NOW = datetime(2026, 10, 14, 0, 0, 2, tzinfo=timezone.utc)
FIXTURE = b"print('fixed harmless offline fixture; never executed by preflight')\n"
TOOL = b"synthetic tool bytes, deliberately not an executable\n"
ROOT = "/p2-fixture"
TOOL_PATH = "/tools/python3.10"


def digest(data):
    return hashlib.sha256(data).hexdigest()


class TestExecutionPreflight(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.local_root = Path(self.temp.name) / "scope"
        self.local_root.mkdir()
        (self.local_root / "fixture.py").write_bytes(FIXTURE)
        self.tool_path = Path(self.temp.name) / "python3.10"
        self.tool_path.write_bytes(TOOL)
        self.snapshot = packet()["snapshot"]
        self.snapshot["metadata"]["started_at"] = (NOW - timedelta(seconds=1)).isoformat()
        tool = synthetic_tool_record().model_dump(mode="json")
        tool["argv"] = [TOOL_PATH, "--version"]
        tool["command_identity"]["argv_sha256"] = digest_argv(tool["argv"])
        tool["tool_identity"].update(requested_executable=TOOL_PATH,
                                     resolved_path=TOOL_PATH, file_sha256=digest(TOOL))
        self.record = seal_tool_result(tool)
        binding = bind_candidate_to_tool(FIXTURE, self.snapshot, self.record,
                                         expected_probe_id="fixture-id",
                                         expected_tool_record_id=self.record.record_id)
        self.limits = {"wall_time_seconds": 3.0, "cpu_seconds": 1,
                       "memory_bytes": 134217728, "max_output_bytes": 4096,
                       "process_scope": "POSIX_PROCESS_GROUP"}
        self.request = {
            "request_id": "c" * 32, "candidate_sha256": digest(FIXTURE),
            "platform_environment_id": self.snapshot["environment_id"],
            "platform_probe_id": "fixture-id", "execution_backend": "wsl",
            "authorized_action": "FIXED_FIXTURE_CHECK", "authorization_reference": "operator-test-approval",
            "tool_role": "fixture_python", "tool_identity": self.record.tool_identity.model_dump(mode="json"),
            "binding": binding.model_dump(mode="json"), "resource_limits": deepcopy(self.limits),
            "expected_artifacts": ["stdout.bin", "stderr.bin", "tool_result.json"],
            "candidate_path": ROOT + "/fixture.py", "cwd": ROOT, "input_files": [],
            "fixture_id": "p2-fixed-print-v1",
        }
        self.authorization = {
            **{name: self.request[name] for name in ("request_id", "candidate_sha256", "platform_environment_id",
                                                     "platform_probe_id", "authorized_action", "fixture_id")},
            "authorization_reference": "operator-test-approval", "operator_id": "test-operator",
            "issuer_kind": "operator", "tool_resolved_path": TOOL_PATH,
            "tool_file_sha256": digest(TOOL), "resource_limits": deepcopy(self.limits),
            "not_before": (NOW - timedelta(seconds=30)).isoformat(),
            "expires_at": (NOW + timedelta(seconds=30)).isoformat(),
        }
        self.policy = {
            "expected_environment_id": self.snapshot["environment_id"], "expected_probe_id": "fixture-id",
            "expected_snapshot_sha256": snapshot_sha256(self.snapshot),
            "expected_target_environment": "wsl:Ubuntu-22.04", "execution_backend": "wsl",
            "allowed_operator_ids": ["test-operator"],
            "allowed_authorization_references": ["operator-test-approval"],
            "scope_root": ROOT, "allowed_tools": {TOOL_PATH: digest(TOOL)},
            "fixture_hashes": {"p2-fixed-print-v1": digest(FIXTURE)},
            "resource_support": {"status": "OBSERVED", "mechanisms": ["WALL_WATCHDOG", "OUTPUT_CAP",
                "POSIX_PROCESS_GROUP", "RLIMIT_CPU", "RLIMIT_AS"], "source": "synthetic offline worker capability fixture"},
            "max_resource_limits": deepcopy(self.limits),
        }

    def mapped_path(self, raw):
        text = str(raw)
        if text == ROOT:
            return self.local_root
        if text.startswith(ROOT + "/"):
            return self.local_root.joinpath(*PurePosixPath(text).relative_to(ROOT).parts)
        if text.startswith("/"):
            return Path(self.temp.name) / "outside" / text[1:]
        return Path(raw)

    def measured_identity(self, executable, **kwargs):
        try:
            raw = self.tool_path.read_bytes()
            return ToolIdentity(requested_executable=executable, resolved_path=executable,
                                status="OBSERVED", file_sha256=digest(raw), source="synthetic file byte measurement")
        except OSError:
            return ToolIdentity(requested_executable=executable, resolved_path=executable,
                                status="UNKNOWN", file_sha256=None, source="synthetic missing tool fixture")

    def check(self, *, request=None, snapshot=None, record=None, authorization="default", policy=None, **options):
        with ExitStack() as stack:
            stack.enter_context(patch("src.execution_preflight.Path", side_effect=self.mapped_path))
            stack.enter_context(patch("src.tools.process.measure_tool_identity", side_effect=self.measured_identity))
            stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("preflight must never launch")))
            return preflight_execution(request if request is not None else self.request,
                                       snapshot if snapshot is not None else self.snapshot,
                                       record if record is not None else self.record,
                                       self.authorization if authorization == "default" else authorization,
                                       policy if policy is not None else self.policy, now=NOW,
                                       observed_platform_type=options.pop("observed_platform_type", "wsl"),
                                       observed_target_environment=options.pop("observed_target_environment", "wsl:Ubuntu-22.04"),
                                       **options)

    def assert_outcome(self, result, status, code):
        self.assertEqual(result.status, status)
        self.assertEqual(result.diagnostics[0].code, code)
        self.assertEqual(result.candidate_execution_status, "NOT_EXECUTED")
        self.assertEqual(result.verification_status, "NOT_VERIFIED")

    def test_complete_strict_request_ready_without_launching(self):
        result = self.check()
        self.assertEqual(result.status, "READY")
        self.assertEqual(result.measured_candidate_sha256, digest(FIXTURE))
        self.assertEqual(result.measured_tool_sha256, digest(TOOL))
        self.assertEqual(result.candidate_execution_status, "NOT_EXECUTED")
        self.assertEqual(result.verification_status, "NOT_VERIFIED")

    def test_request_reference_cannot_supply_authorization(self):
        self.assert_outcome(self.check(authorization=None), "REJECTED", "AUTHORIZATION_MISSING")

    def test_llm_cannot_claim_to_be_an_authorization_issuer(self):
        self.authorization["issuer_kind"] = "llm"
        self.assert_outcome(self.check(), "REJECTED", "AUTHORIZATION_INVALID")

    def test_untrusted_operator_or_reference_is_rejected(self):
        for field, value in (("operator_id", "unknown-operator"), ("authorization_reference", "invented-reference")):
            auth = deepcopy(self.authorization)
            auth[field] = value
            with self.subTest(field=field):
                self.assert_outcome(self.check(authorization=auth), "REJECTED", "AUTHORIZATION_UNTRUSTED")

    def test_authorization_binds_exact_request_and_resource_limits(self):
        for field, value in (("request_id", "d" * 32), ("candidate_sha256", "d" * 64),
                             ("platform_probe_id", "other"), ("fixture_id", "other"),
                             ("tool_file_sha256", "d" * 64), ("authorized_action", "COMPILE")):
            auth = deepcopy(self.authorization)
            auth[field] = value
            with self.subTest(field=field):
                self.assert_outcome(self.check(authorization=auth), "REJECTED", "AUTHORIZATION_SCOPE_MISMATCH")
        auth = deepcopy(self.authorization)
        auth["resource_limits"]["cpu_seconds"] = 2
        self.assert_outcome(self.check(authorization=auth), "REJECTED", "AUTHORIZATION_SCOPE_MISMATCH")

    def test_expired_and_future_authorization_are_rejected(self):
        for bounds in ((NOW - timedelta(minutes=2), NOW - timedelta(seconds=1)),
                       (NOW + timedelta(seconds=1), NOW + timedelta(minutes=2))):
            auth = deepcopy(self.authorization)
            auth.update(not_before=bounds[0].isoformat(), expires_at=bounds[1].isoformat())
            self.assert_outcome(self.check(authorization=auth), "REJECTED", "AUTHORIZATION_EXPIRED")

    def test_arbitrary_candidate_execution_compile_inspect_unsupported(self):
        for action in ("EXECUTE_CANDIDATE", "COMPILE", "INSPECT"):
            request = deepcopy(self.request)
            request["authorized_action"] = action
            self.assert_outcome(self.check(request=request), "UNSUPPORTED", "ACTION_UNSUPPORTED")

    def test_actual_target_or_platform_confusion_is_rejected(self):
        for options in ({"observed_target_environment": "wsl:other"}, {"observed_platform_type": "windows"}):
            self.assert_outcome(self.check(**options), "REJECTED", "ACTUAL_TARGET_MISMATCH")

    def test_trusted_target_environment_or_probe_mismatch_is_rejected(self):
        for field, value in (("expected_environment_id", "sha256:" + "0" * 64),
                             ("expected_probe_id", "other-probe"), ("expected_target_environment", "wsl:other")):
            policy = deepcopy(self.policy)
            policy[field] = value
            self.assert_outcome(self.check(policy=policy), "REJECTED", "TARGET_IDENTITY_MISMATCH")

    def test_stale_future_missing_and_naive_snapshot_times_are_blocked(self):
        for timestamp, status, code in (
            ((NOW - timedelta(minutes=6)).isoformat(), "REJECTED", "PLATFORM_SNAPSHOT_STALE"),
            ((NOW + timedelta(seconds=6)).isoformat(), "REJECTED", "PLATFORM_SNAPSHOT_STALE"),
            ("2026-10-14T00:00:00", "UNKNOWN", "PLATFORM_TIME_UNKNOWN"),
            ("not-a-time", "UNKNOWN", "PLATFORM_TIME_UNKNOWN"),
        ):
            snapshot = deepcopy(self.snapshot)
            snapshot["metadata"]["started_at"] = timestamp
            policy = deepcopy(self.policy)
            policy["expected_snapshot_sha256"] = snapshot_sha256(snapshot)
            self.assert_outcome(self.check(snapshot=snapshot, policy=policy), status, code)
        snapshot = deepcopy(self.snapshot)
        del snapshot["metadata"]["started_at"]
        policy = deepcopy(self.policy)
        policy["expected_snapshot_sha256"] = snapshot_sha256(snapshot)
        self.assert_outcome(self.check(snapshot=snapshot, policy=policy), "UNKNOWN", "PLATFORM_TIME_UNKNOWN")

    def test_snapshot_timestamp_edit_cannot_freshen_an_old_observation(self):
        snapshot = deepcopy(self.snapshot)
        snapshot["metadata"]["started_at"] = (NOW - timedelta(minutes=6)).isoformat()
        policy = deepcopy(self.policy)
        policy["expected_snapshot_sha256"] = snapshot_sha256(snapshot)
        self.assert_outcome(self.check(snapshot=snapshot, policy=policy), "REJECTED", "PLATFORM_SNAPSHOT_STALE")
        # Environment identity is intentionally unchanged by volatile metadata.
        original_environment_id = snapshot["environment_id"]
        snapshot["metadata"]["started_at"] = NOW.isoformat()
        self.assertEqual(snapshot["environment_id"], original_environment_id)
        self.assert_outcome(self.check(snapshot=snapshot, policy=policy), "REJECTED", "SNAPSHOT_CONTENT_MISMATCH")

    def test_failed_probe_does_not_claim_ready(self):
        snapshot = deepcopy(self.snapshot)
        snapshot["probe_status"] = "FAILED"
        # probe_status is part of scientific identity: update both target refs.
        snapshot = seal_snapshot(snapshot).model_dump(mode="json")
        request = deepcopy(self.request)
        auth = deepcopy(self.authorization)
        policy = deepcopy(self.policy)
        for payload in (request, auth):
            payload["platform_environment_id"] = snapshot["environment_id"]
        request["binding"]["platform_environment_id"] = snapshot["environment_id"]
        policy["expected_environment_id"] = snapshot["environment_id"]
        policy["expected_snapshot_sha256"] = snapshot_sha256(snapshot)
        self.assert_outcome(self.check(request=request, snapshot=snapshot, authorization=auth, policy=policy),
                            "UNKNOWN", "PLATFORM_PROBE_FAILED")

    def test_candidate_byte_replacement_is_rejected(self):
        (self.local_root / "fixture.py").write_bytes(b"changed fixture bytes\n")
        self.assert_outcome(self.check(), "REJECTED", "CANDIDATE_HASH_MISMATCH")

    def test_missing_empty_oversized_candidate_are_rejected(self):
        candidate = self.local_root / "fixture.py"
        for raw in (b"", b"x" * (1048576 + 1)):
            candidate.write_bytes(raw)
            self.assert_outcome(self.check(), "REJECTED", "CANDIDATE_SIZE_INVALID")
        candidate.unlink()
        self.assert_outcome(self.check(), "REJECTED", "INPUT_MISSING")

    def test_non_allowlisted_fixture_is_rejected(self):
        policy = deepcopy(self.policy)
        policy["fixture_hashes"]["p2-fixed-print-v1"] = "d" * 64
        self.assert_outcome(self.check(policy=policy), "REJECTED", "FIXTURE_NOT_ALLOWLISTED")

    def test_outside_scope_and_non_directory_cwd_are_rejected(self):
        outside = self.mapped_path("/outside.py")
        outside.parent.mkdir(parents=True)
        outside.write_bytes(FIXTURE)
        request = deepcopy(self.request)
        request["candidate_path"] = "/outside.py"
        self.assert_outcome(self.check(request=request), "REJECTED", "INPUT_SCOPE_INVALID")
        request = deepcopy(self.request)
        request["cwd"] = ROOT + "/fixture.py"
        self.assert_outcome(self.check(request=request), "REJECTED", "INPUT_SCOPE_INVALID")

    @unittest.skipIf(os.name == "nt", "native POSIX symlink fixture requires Linux")
    def test_symlink_candidate_rejected_without_following(self):
        candidate = self.local_root / "fixture.py"
        candidate.unlink()
        candidate.symlink_to(self.tool_path)
        self.assert_outcome(self.check(), "REJECTED", "INPUT_SCOPE_INVALID")

    def test_tool_replacement_missing_hash_failure_and_allowlist_mismatch(self):
        self.tool_path.write_bytes(b"tool replaced after binding\n")
        self.assert_outcome(self.check(), "REJECTED", "TOOL_IDENTITY_MISMATCH")
        self.tool_path.unlink()
        self.assert_outcome(self.check(), "UNKNOWN", "TOOL_IDENTITY_UNKNOWN")
        self.tool_path.write_bytes(TOOL)
        policy = deepcopy(self.policy)
        policy["allowed_tools"][TOOL_PATH] = "d" * 64
        self.assert_outcome(self.check(policy=policy), "REJECTED", "TOOL_NOT_ALLOWLISTED")
        with patch.object(Path, "read_bytes", side_effect=PermissionError("synthetic hash permission error")):
            self.assert_outcome(self.check(), "UNKNOWN", "TOOL_IDENTITY_UNKNOWN")

    def test_foreign_record_and_changed_record_identity_are_blocked(self):
        for field, value in (("target_environment", "wsl:other"), ("run_id", "d" * 32)):
            record = self.record.model_dump(mode="json")
            record[field] = value
            self.assert_outcome(self.check(record=seal_tool_result(record)), "REJECTED", "TOOL_BINDING_MISMATCH")

    def test_nonzero_tool_observation_rejected(self):
        record = self.record.model_dump(mode="json")
        record.update(returncode=2, end_status="NONZERO_EXIT")
        self.assert_outcome(self.check(record=seal_tool_result(record)), "REJECTED", "TOOL_RECORD_UNUSABLE")

    def test_unknown_unsupported_and_missing_resource_mechanisms_are_blocked(self):
        for status, expected in (("UNKNOWN", "UNKNOWN"), ("UNSUPPORTED", "UNSUPPORTED")):
            policy = deepcopy(self.policy)
            policy["resource_support"].update(status=status, mechanisms=[])
            self.assert_outcome(self.check(policy=policy), expected,
                                "RESOURCE_SUPPORT_UNKNOWN" if status == "UNKNOWN" else "RESOURCE_POLICY_UNSUPPORTED")
        for mechanism in self.policy["resource_support"]["mechanisms"]:
            policy = deepcopy(self.policy)
            policy["resource_support"]["mechanisms"].remove(mechanism)
            self.assert_outcome(self.check(policy=policy), "UNSUPPORTED", "RESOURCE_POLICY_UNSUPPORTED")

    def test_resource_limits_above_trusted_policy_rejected(self):
        for field, value in (("wall_time_seconds", 4.0), ("cpu_seconds", 2),
                             ("memory_bytes", 268435456), ("max_output_bytes", 8192)):
            request = deepcopy(self.request)
            auth = deepcopy(self.authorization)
            request["resource_limits"][field] = value
            auth["resource_limits"][field] = value
            self.assert_outcome(self.check(request=request, authorization=auth), "REJECTED", "RESOURCE_LIMIT_EXCEEDS_POLICY")

    def test_extra_inputs_and_shell_argv_not_supported(self):
        request = deepcopy(self.request)
        request["input_files"] = [ROOT + "/fixture.py"]
        self.assert_outcome(self.check(request=request), "UNSUPPORTED", "EXTRA_INPUT_UNSUPPORTED")
        request = deepcopy(self.request)
        request["argv"] = ["sh", "-c", "echo arbitrary"]
        self.assert_outcome(self.check(request=request), "REJECTED", "INVALID_CONTRACT")

    def test_strict_types_ranges_required_fields_and_windows_path_rejected(self):
        for mutate in (
            lambda request: request.pop("candidate_sha256"),
            lambda request: request.update(candidate_path="C:\\candidate.py"),
            lambda request: request.update(candidate_path=ROOT + "/../outside.py"),
            lambda request: request["resource_limits"].update(cpu_seconds=True),
            lambda request: request["resource_limits"].update(memory_bytes="134217728"),
            lambda request: request["resource_limits"].update(wall_time_seconds=float("inf")),
            lambda request: request["resource_limits"].update(max_output_bytes=0),
            lambda request: request.update(expected_artifacts=["stdout.bin"] * 3),
            lambda request: request.update(authorization_reference=" "),
        ):
            request = deepcopy(self.request)
            mutate(request)
            self.assert_outcome(self.check(request=request), "REJECTED", "INVALID_CONTRACT")

    def test_model_copy_mutation_revalidated_at_boundary(self):
        model = ExecutionRequest.model_validate(self.request)
        model = model.model_copy(update={"candidate_sha256": "d" * 64})
        self.assert_outcome(self.check(request=model), "REJECTED", "INVALID_CONTRACT")
        model = OperatorAuthorization.model_validate(self.authorization).model_copy(update={"issuer_kind": "llm"})
        self.assert_outcome(self.check(authorization=model), "REJECTED", "AUTHORIZATION_INVALID")
        policy = PreflightPolicy.model_validate(self.policy).model_copy(update={"max_snapshot_age_seconds": True})
        self.assert_outcome(self.check(policy=policy), "REJECTED", "INVALID_CONTRACT")

    def test_request_content_hash_is_canonical_and_changes_with_identity(self):
        self.assertEqual(request_sha256(self.request), request_sha256(ExecutionRequest.model_validate(self.request)))
        changed = deepcopy(self.request)
        changed["request_id"] = "d" * 32
        self.assertNotEqual(request_sha256(self.request), request_sha256(changed))

    def test_naive_caller_clock_is_not_guessed(self):
        with self.assertRaisesRegex(ValueError, "timezone aware"):
            preflight_execution(self.request, self.snapshot, self.record, self.authorization,
                                self.policy, now=datetime(2026, 10, 14))
