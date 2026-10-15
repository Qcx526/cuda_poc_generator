"""Versioned CUDA contracts using fabricated observations, never native tools."""

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import unittest
import time

from pydantic import ValidationError

from src.cuda_registry import CUDA_SMOKE_ID, CUDA_SMOKE_SOURCE, CUDA_SMOKE_SHA256
from src.models.execution import (CudaResourceLimits, CudaToolchainScope, ExecutionRequest,
                                  ExecutionResourceLimits, OperatorAuthorization, PreflightPolicy,
                                  request_sha256, snapshot_sha256)
from src.models.execution_binding import bind_candidate_to_tool
from src.models.platform import PlatformSnapshot
from src.models.tool_result import digest_argv, seal_tool_result
from tests.test_cuda_registry import synthetic_tools
from tests.test_execution_bridge import fixed_request, fixture_authority
from tests.test_lifecycle_models import synthetic_context
from tests.test_p1c_integration import synthetic_tool_record
from tests.test_platform_probe import packet


def synthetic_version_record(role, *, tools=None, version="12.8", returncode=0, truncated=False, timed_out=False):
    tools = synthetic_tools() if tools is None else tools
    identity = tools[role]
    data = synthetic_tool_record().model_dump(mode="python")
    raw = ("Synthetic " + role + " release " + version + ", V" + version + ".93\n").encode("ascii")
    argv = [identity.resolved_path, "--version"]
    data.update(argv=argv, stdout_b64=base64.b64encode(raw).decode("ascii"),
                stdout_sha256=hashlib.sha256(raw).hexdigest(), tool_identity=identity.model_dump(mode="python"),
                returncode=returncode, truncated=truncated, timed_out=timed_out,
                end_status="TIMED_OUT" if timed_out else "OUTPUT_LIMIT" if truncated else
                "NORMAL_EXIT" if returncode == 0 else "NONZERO_EXIT")
    data["command_identity"]["argv_sha256"] = digest_argv(argv)
    return seal_tool_result(data)


def synthetic_cuda_scope():
    tools = synthetic_tools()
    return CudaToolchainScope(arch="sm_75", tools=tools,
        target_boot_id="00000000-0000-0000-0000-000000000001",
        snapshot_started_monotonic_ns=time.monotonic_ns(), observed_monotonic_ns=time.monotonic_ns(),
                               version_records={role: synthetic_version_record(role, tools=tools)
                                                for role in ("nvcc", "cuobjdump", "nvdisasm")})


def synthetic_cuda_context():
    """Syntactically valid fabricated authority, not permission for real runs."""
    old, _, _ = fixed_request()
    snapshot = PlatformSnapshot.model_validate(packet(gpu=b"0, Fixture GPU A, 7.5, 555.42\n")["snapshot"])
    scope = synthetic_cuda_scope()
    observation = scope.version_records["nvcc"]
    limits = CudaResourceLimits(wall_time_seconds=90.0, cpu_seconds=45,
                                memory_bytes=4294967296, max_output_bytes=32768)
    request = old.model_dump(mode="python")
    request.update(request_schema_version="1.2", candidate_sha256=CUDA_SMOKE_SHA256,
                   fixture_id=CUDA_SMOKE_ID, authorized_action="SAFE_CUDA_SMOKE", tool_role="nvcc",
                   tool_identity=scope.tools["nvcc"], resource_limits=limits, cuda_toolchain=scope,
                   expected_artifacts=["stdout.bin", "stderr.bin", "process_result.json"],
                   candidate_path="/workspace/safe_smoke.cu", cwd="/workspace",
                   platform_environment_id=snapshot.environment_id,
                   platform_probe_id=snapshot.metadata["probe_id"],
                   binding=bind_candidate_to_tool(CUDA_SMOKE_SOURCE, snapshot, observation,
                                                   expected_probe_id=snapshot.metadata["probe_id"],
                                                   expected_tool_record_id=observation.record_id))
    request = ExecutionRequest.model_validate(request)
    now = datetime.now(timezone.utc)
    authorization = OperatorAuthorization(
        authorization_schema_version="1.1", request_id=request.request_id,
        authorization_reference=request.authorization_reference, operator_id="synthetic-cuda-operator",
        issuer_kind="operator", candidate_sha256=request.candidate_sha256,
        platform_environment_id=request.platform_environment_id, platform_probe_id=request.platform_probe_id,
        authorized_action=request.authorized_action, tool_resolved_path=request.tool_identity.resolved_path,
        tool_file_sha256=request.tool_identity.file_sha256, resource_limits=limits, cuda_toolchain=scope,
        authorization_clock="TARGET_BOOT_MONOTONIC", not_before_monotonic_ns=scope.observed_monotonic_ns,
        expires_monotonic_ns=scope.observed_monotonic_ns + 120000000000,
        fixture_id=request.fixture_id, not_before=(now - timedelta(seconds=5)).isoformat(),
        expires_at=(now + timedelta(minutes=2)).isoformat())
    policy = PreflightPolicy(
        policy_schema_version="1.1", expected_environment_id=snapshot.environment_id,
        expected_probe_id=request.platform_probe_id, expected_snapshot_sha256=snapshot_sha256(snapshot),
        expected_target_environment=request.binding.target_environment, execution_backend="wsl",
        allowed_operator_ids=[authorization.operator_id], allowed_authorization_references=[request.authorization_reference],
        scope_root=request.cwd, allowed_tools={tool.resolved_path: tool.file_sha256 for tool in scope.tools.values()},
        fixture_hashes={CUDA_SMOKE_ID: CUDA_SMOKE_SHA256}, max_resource_limits=limits, cuda_toolchain=scope,
        resource_support={"status": "OBSERVED", "mechanisms": ["WALL_WATCHDOG", "OUTPUT_CAP", "POSIX_PROCESS_GROUP", "RLIMIT_CPU", "RLIMIT_AS"],
                          "source": "SYNTHETIC capabilities only; not actual isolation"})
    return request, authorization, policy, snapshot, observation


class TestCudaContractVersions(unittest.TestCase):
    def test_cuda_versions_and_resource_profile_are_explicit_and_independent(self):
        request, auth, policy, _, _ = synthetic_cuda_context()
        self.assertEqual(request.request_schema_version, "1.2")
        self.assertEqual(auth.authorization_schema_version, "1.1")
        self.assertEqual(policy.policy_schema_version, "1.1")
        self.assertIsInstance(request.resource_limits, CudaResourceLimits)
        self.assertGreater(request.resource_limits.memory_bytes, 1073741824)
        self.assertEqual(ExecutionRequest.model_validate_json(request.model_dump_json()), request)

    def test_legacy_profile_keeps_its_original_limits(self):
        for key, value in (("memory_bytes", 4294967296), ("cpu_seconds", 45), ("wall_time_seconds", 90.0)):
            profile = ExecutionResourceLimits(wall_time_seconds=10.0, cpu_seconds=2,
                                               memory_bytes=268435456, max_output_bytes=4096).model_dump(mode="python")
            profile[key] = value
            with self.subTest(key=key), self.assertRaises(ValidationError):
                ExecutionResourceLimits.model_validate(profile)

    def test_cuda_profile_requires_integer_finite_bounded_limits(self):
        profile = synthetic_cuda_context()[0].resource_limits.model_dump(mode="python")
        for key, value in (("memory_bytes", 268435456), ("memory_bytes", 8589934593),
                           ("cpu_seconds", True), ("cpu_seconds", 61), ("wall_time_seconds", float("nan"))):
            data = {**profile, key: value}
            with self.subTest(key=key, value=value), self.assertRaises(ValidationError):
                CudaResourceLimits.model_validate(data)

    def test_legacy_request_dump_and_hash_match_committed_p2a_example(self):
        raw = json.loads((Path(__file__).resolve().parent.parent / "docs/examples/P2_A_EXECUTION_REQUEST.json").read_text(encoding="utf-8"))["execution_request"]
        request = ExecutionRequest.model_validate(raw)
        self.assertEqual(request.model_dump(mode="json"), raw)
        expected = hashlib.sha256(json.dumps(raw, sort_keys=True, ensure_ascii=False,
                                              separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
        self.assertEqual(request_sha256(request), expected)

    def test_legacy_authority_and_policy_dumps_do_not_add_cuda_fields(self):
        old, snapshot, _ = fixed_request()
        auth, policy = fixture_authority(old, snapshot)
        for contract in (old, auth, policy, synthetic_context()[0]):
            dumped = contract.model_dump(mode="json")
            self.assertNotIn("cuda_toolchain", dumped)
            profile = dumped.get("resource_limits", dumped.get("max_resource_limits"))
            self.assertNotIn("resource_profile", profile)

    def test_cuda_request_cannot_route_through_any_legacy_request_version(self):
        request = synthetic_cuda_context()[0]
        for version in ("1.0", "1.1"):
            data = request.model_dump(mode="python")
            data["request_schema_version"] = version
            data["expected_artifacts"] = ["stdout.bin", "stderr.bin", "tool_result.json" if version == "1.0" else "process_result.json"]
            with self.subTest(version=version), self.assertRaises(ValidationError):
                ExecutionRequest.model_validate(data)

    def test_new_request_version_cannot_accept_fixture_profile_or_action(self):
        request = synthetic_cuda_context()[0]
        for change in ({"authorized_action": "EXECUTE_CANDIDATE"}, {"cuda_toolchain": None},
                       {"fixture_id": "p2b-normal-v1"}, {"tool_role": "fixture_python"},
                       {"resource_limits": ExecutionResourceLimits(wall_time_seconds=10.0, cpu_seconds=2,
                                                                    memory_bytes=268435456, max_output_bytes=4096)}):
            data = {**request.model_dump(mode="python"), **change}
            with self.subTest(change=change), self.assertRaises(ValidationError):
                ExecutionRequest.model_validate(data)

    def test_legacy_authorization_cannot_grant_cuda_action_even_without_scope(self):
        old, snapshot, _ = fixed_request()
        auth, _ = fixture_authority(old, snapshot)
        data = auth.model_dump(mode="python")
        data["authorized_action"] = "SAFE_CUDA_SMOKE"
        with self.assertRaises(ValidationError):
            OperatorAuthorization.model_validate(data)

    def test_legacy_authority_or_policy_cannot_enable_larger_cuda_profile(self):
        _, auth, policy, _, _ = synthetic_cuda_context()
        for model, contract, version_key in ((OperatorAuthorization, auth, "authorization_schema_version"),
                                             (PreflightPolicy, policy, "policy_schema_version")):
            raw = contract.model_dump(mode="python")
            raw[version_key] = "1.0"
            with self.subTest(model=model), self.assertRaises(ValidationError):
                model.model_validate(raw)


class TestCudaToolScope(unittest.TestCase):
    def test_all_five_tools_and_three_version_observations_are_required(self):
        for group, key in (("tools", "host_compiler"), ("tools", "guard_python"),
                           ("version_records", "nvdisasm")):
            data = synthetic_cuda_scope().model_dump(mode="python")
            del data[group][key]
            with self.subTest(group=group, key=key), self.assertRaises(ValidationError):
                CudaToolchainScope.model_validate(data)

    def test_unknown_tool_hash_cannot_be_an_observed_scope(self):
        data = synthetic_cuda_scope().model_dump(mode="python")
        data["tools"]["cuobjdump"].update(status="UNKNOWN", file_sha256=None)
        with self.assertRaises(ValidationError):
            CudaToolchainScope.model_validate(data)

    def test_version_tool_identity_and_argv_must_match_exact_bound_tool(self):
        for mode in ("identity", "argv"):
            data = synthetic_cuda_scope().model_dump(mode="python")
            record = data["version_records"]["nvcc"]
            if mode == "identity":
                record["tool_identity"]["file_sha256"] = "b" * 64
            else:
                record["argv"] = [record["argv"][0], "--help"]
                record["command_identity"]["argv_sha256"] = digest_argv(record["argv"])
            data["version_records"]["nvcc"] = seal_tool_result(record)
            with self.subTest(mode=mode), self.assertRaises(ValidationError):
                CudaToolchainScope.model_validate(data)

    def test_nonzero_timeout_and_truncated_versions_are_unusable(self):
        for kwargs in ({"returncode": 7}, {"timed_out": True}, {"truncated": True}):
            scope = synthetic_cuda_scope().model_dump(mode="python")
            scope["version_records"]["nvcc"] = synthetic_version_record("nvcc", **kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(ValidationError):
                CudaToolchainScope.model_validate(scope)


if __name__ == "__main__":
    unittest.main()
