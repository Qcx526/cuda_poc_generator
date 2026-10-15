"""Narrow P2-A worker: read-only describe or one immutable harmless fixture.

This module has no candidate dispatcher and never accepts a command line from a
request. The only child body is the constant below, supplied through ``-c`` so
that replacement of a workspace file cannot change the executed source.
"""

import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

from .execution_preflight import preflight_execution
from .models.execution import ExecutionRequest, OperatorAuthorization, PreflightPolicy, request_sha256
from .models.platform import PlatformSnapshot
from .platform_worker import probe_platform
from .probe_artifacts import write_probe_artifacts
from .tools.process import (canonical_target_environment, current_platform_type,
                            measure_tool_identity, run_tool)


FIXTURE_ID = "p2-fixed-print-v1"
FIXTURE_SOURCE = b'''"""Fixed harmless P2-A fixture; no CUDA, filesystem writes or networking."""
import json
import resource
import sys

config = json.loads(sys.stdin.buffer.read(4097))
if set(config) != {"request_id", "nonce", "cpu_seconds", "memory_bytes"}:
    raise ValueError("invalid fixed fixture configuration")
if (type(config["cpu_seconds"]) is not int or not 1 <= config["cpu_seconds"] <= 30
        or type(config["memory_bytes"]) is not int
        or not 67108864 <= config["memory_bytes"] <= 1073741824):
    raise ValueError("invalid fixed fixture resource bounds")
for name in ("request_id", "nonce"):
    if (not isinstance(config[name], str) or len(config[name]) != 32
            or any(char not in "0123456789abcdef" for char in config[name])):
        raise ValueError("invalid fixed fixture identity")
resource.setrlimit(resource.RLIMIT_CPU, (config["cpu_seconds"], config["cpu_seconds"]))
resource.setrlimit(resource.RLIMIT_AS, (config["memory_bytes"], config["memory_bytes"]))
if (resource.getrlimit(resource.RLIMIT_CPU) != (config["cpu_seconds"],) * 2
        or resource.getrlimit(resource.RLIMIT_AS) != (config["memory_bytes"],) * 2):
    raise RuntimeError("resource bounds were not applied")
proof = {"fixture_id": "p2-fixed-print-v1", "request_id": config["request_id"],
         "nonce": config["nonce"], "cpu_seconds": config["cpu_seconds"],
         "memory_bytes": config["memory_bytes"], "message": "harmless fixture completed"}
sys.stdout.write(json.dumps(proof, sort_keys=True, separators=(",", ":")) + "\\n")
sys.stdout.flush()
'''
FIXTURE_SHA256 = hashlib.sha256(FIXTURE_SOURCE).hexdigest()
FIXTURE_RELATIVE_PATH = "tests/fixtures/execution/p2_fixed_print.py"


def contract_digest(model, value):
    """Hash a strict, fully defaulted contract without coercing model mutations."""
    checked = model.model_validate(value.model_dump(mode="python") if isinstance(value, model) else value)
    canonical = json.dumps(checked.model_dump(mode="json"), ensure_ascii=False,
                           sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def expected_resource_proof(request, nonce):
    return {"fixture_id": FIXTURE_ID, "request_id": request.request_id,
            "nonce": nonce, "cpu_seconds": request.resource_limits.cpu_seconds,
            "memory_bytes": request.resource_limits.memory_bytes,
            "message": "harmless fixture completed"}


def proof_bytes(proof):
    return (json.dumps(proof, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def resource_capabilities(limits=None):
    """Observe available mechanisms; successful child proof confirms application."""
    try:
        import resource
        available = (os.name == "posix" and callable(resource.setrlimit)
                     and callable(resource.getrlimit) and hasattr(resource, "RLIMIT_CPU")
                     and hasattr(resource, "RLIMIT_AS") and callable(os.killpg))
        if available and limits is not None:
            for kind, value in ((resource.RLIMIT_CPU, limits.cpu_seconds),
                                (resource.RLIMIT_AS, limits.memory_bytes)):
                hard = resource.getrlimit(kind)[1]
                if hard != resource.RLIM_INFINITY and hard < value:
                    available = False
    except ImportError:
        available = False
    except (OSError, ValueError):
        return {"status": "UNKNOWN", "mechanisms": [],
                "source": "native resource limit observation failed; fixed fixture remains blocked"}
    return {"status": "OBSERVED" if available else "UNSUPPORTED",
            "mechanisms": ["WALL_WATCHDOG", "OUTPUT_CAP", "POSIX_PROCESS_GROUP", "RLIMIT_CPU", "RLIMIT_AS"] if available else [],
            "source": "fixed P2-A worker inspected POSIX resource APIs; child must confirm actual rlimits"}


def _snapshot(target):
    probe_id, nonce = uuid.uuid4().hex, uuid.uuid4().hex
    packet = probe_platform({"probe_id": probe_id, "nonce": nonce,
                             "execution_backend": "wsl", "environment_label": target,
                             "command_timeout_seconds": 3, "total_budget_seconds": 30,
                             "max_output_bytes": 32768})
    snapshot = PlatformSnapshot.model_validate(packet["snapshot"])
    from .platform_probe import default_probe_output_root
    result = {"probe_id": probe_id, "backend": "wsl", "status": snapshot.probe_status,
              "snapshot": snapshot.model_dump(mode="json"), "host_snapshot": None,
              "commands": packet["commands"], "diagnostics": packet["snapshot"]["diagnostics"],
              "stdout_b64": "", "stderr_b64": "",
              "transport": {"launcher_returncode": None, "worker_reported_exit_code": 0},
              "execution": "NOT_EXECUTED", "verification": "NOT_VERIFIED"}
    folder = write_probe_artifacts(default_probe_output_root(), result)
    snapshot.metadata["record_directory"] = str(folder)
    return PlatformSnapshot.model_validate(snapshot.model_dump(mode="python"))


def handle_worker(payload, *, project_root=None):
    """Trusted transport entry point. Policy/authorization are separate arguments."""
    if set(payload) != {"operation", "nonce", "request", "authorization", "snapshot", "tool_record", "policy"}:
        raise ValueError("invalid fixed worker envelope")
    operation, nonce = payload["operation"], payload["nonce"]
    if operation not in {"DESCRIBE", "FIXED_FIXTURE"}:
        raise ValueError("unsupported worker operation")
    if not isinstance(nonce, str) or len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
        raise ValueError("invalid worker nonce")
    root = Path(project_root or Path(__file__).resolve().parent.parent).resolve(strict=True)
    fixture = root / FIXTURE_RELATIVE_PATH
    result = {"schema_version": "1.0", "operation": operation, "nonce": nonce,
              "request_id": payload["request"].get("request_id") if isinstance(payload["request"], dict) else None,
              "request_sha256": None, "authorization_sha256": None, "policy_sha256": None,
              "worker_exit_code": 0, "status": "UNKNOWN", "target_snapshot": None,
              "current_snapshot": None, "target_environment": None, "tool_result": None,
              "fixture_id": FIXTURE_ID, "fixture_sha256": FIXTURE_SHA256,
              "fixture_path": str(fixture), "cwd": str(root), "preflight": None,
              "resource_proof": None, "diagnostics": [],
              "resource_support": {"status": "UNKNOWN", "mechanisms": [], "source": "target resource APIs have not been observed"},
              "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    if operation == "FIXED_FIXTURE":
        try:
            result["target_snapshot"] = PlatformSnapshot.model_validate(payload["snapshot"]).model_dump(mode="json")
        except (ValueError, TypeError):
            pass

    def fail(status, code):
        result.update(status=status)
        result["diagnostics"].append(code)
        return result

    if current_platform_type() != "wsl":
        return fail("REJECTED", "WORKER_NOT_WSL")
    try:
        target = canonical_target_environment()
        result["target_environment"] = target
        result["resource_support"] = resource_capabilities()
        if not fixture.is_file() or fixture.is_symlink() or fixture.read_bytes() != FIXTURE_SOURCE:
            return fail("REJECTED", "FIXED_FIXTURE_IDENTITY_MISMATCH")
        current = _snapshot(target)
        result["current_snapshot"] = current.model_dump(mode="json")
    except (OSError, ValueError):
        return fail("UNKNOWN", "TARGET_OBSERVATION_FAILED")
    if current.probe_status == "FAILED":
        return fail("UNKNOWN", "CURRENT_PROBE_FAILED")
    if operation == "DESCRIBE":
        if any(payload[name] is not None for name in ("request", "authorization", "snapshot", "tool_record", "policy")):
            return fail("REJECTED", "DESCRIBE_HAS_EXECUTION_INPUTS")
        result["target_snapshot"] = current.model_dump(mode="json")
        identity = measure_tool_identity(sys.executable, cwd=root, source="fixed worker Python interpreter file bytes")
        if identity.status != "OBSERVED":
            return fail("UNKNOWN", "PYTHON_IDENTITY_UNKNOWN")
        record = run_tool([sys.executable, "--version"], cwd=root, target_environment=target,
                          timeout_seconds=5, max_output_bytes=4096,
                          allowed_tool_identities={identity.resolved_path: identity.file_sha256},
                          command_source="registered read-only Python version observation")
        result["tool_result"] = record.model_dump(mode="json")
        if not record.ok:
            return fail("UNKNOWN", "PYTHON_OBSERVATION_FAILED")
        result["status"] = "DESCRIBED"
        return result
    try:
        req = ExecutionRequest.model_validate(payload["request"])
        snapshot = PlatformSnapshot.model_validate(payload["snapshot"])
        policy = PreflightPolicy.model_validate(payload["policy"])
        authorization = (None if payload["authorization"] is None
                         else OperatorAuthorization.model_validate(payload["authorization"]))
        digests = {"request_sha256": request_sha256(req),
                   "authorization_sha256": None if authorization is None else contract_digest(OperatorAuthorization, authorization),
                   "policy_sha256": contract_digest(PreflightPolicy, policy)}
    except (ValueError, TypeError):
        return fail("REJECTED", "INVALID_EXECUTION_CONTRACT")
    result.update(digests)
    result["target_snapshot"] = snapshot.model_dump(mode="json")
    if (current.environment_id != req.platform_environment_id
            or current.metadata["environment_label"] != req.binding.target_environment):
        return fail("REJECTED", "CURRENT_TARGET_IDENTITY_MISMATCH")
    try:
        actual_python = measure_tool_identity(sys.executable, cwd=root,
                                             source="fresh actual fixed worker interpreter identity")
    except (OSError, ValueError):
        return fail("UNKNOWN", "WORKER_PYTHON_IDENTITY_UNKNOWN")
    if actual_python.status != "OBSERVED":
        return fail("UNKNOWN", "WORKER_PYTHON_IDENTITY_UNKNOWN")
    if (req.tool_identity.resolved_path != actual_python.resolved_path
            or req.tool_identity.file_sha256 != actual_python.file_sha256):
        return fail("REJECTED", "WORKER_PYTHON_IDENTITY_MISMATCH")
    if (req.request_schema_version != "1.0" or req.fixture_id != FIXTURE_ID or req.candidate_sha256 != FIXTURE_SHA256
            or req.candidate_path != str(fixture) or req.cwd != str(root)
            or policy.scope_root != str(root) or policy.fixture_hashes != {FIXTURE_ID: FIXTURE_SHA256}):
        return fail("REJECTED", "FIXED_REGISTRY_SCOPE_MISMATCH")
    # Caller data cannot assert worker capabilities. Replace it with actual APIs.
    actual_policy = policy.model_dump(mode="json")
    actual_support = resource_capabilities(req.resource_limits)
    result["resource_support"] = actual_support
    if actual_support["status"] != "OBSERVED" or policy.resource_support.status == "OBSERVED":
        # A configured UNKNOWN/UNSUPPORTED remains a refusal. An OBSERVED claim
        # cannot add mechanisms the actual fixed worker does not implement.
        if policy.resource_support.status == "OBSERVED":
            actual_support["mechanisms"] = [item for item in actual_support["mechanisms"]
                                            if item in policy.resource_support.mechanisms]
        actual_policy["resource_support"] = actual_support
    checked = preflight_execution(req, snapshot, payload["tool_record"], payload["authorization"], actual_policy,
                                  observed_platform_type="wsl", observed_target_environment=target)
    result["preflight"] = checked.model_dump(mode="json")
    if checked.status != "READY":
        result["status"] = checked.status
        return result
    # Registry bytes, never an LLM string or caller argv. Source is passed inline
    # to close the workspace-file replacement gap after preflight hashing.
    config = {"request_id": req.request_id, "nonce": nonce,
              "cpu_seconds": req.resource_limits.cpu_seconds,
              "memory_bytes": req.resource_limits.memory_bytes}
    record = run_tool([req.tool_identity.resolved_path, "-I", "-c", FIXTURE_SOURCE.decode("utf-8")],
                      cwd=req.cwd, target_environment=target,
                      timeout_seconds=req.resource_limits.wall_time_seconds,
                      max_output_bytes=req.resource_limits.max_output_bytes,
                      input_bytes=json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                      allowed_tool_identities=policy.allowed_tools,
                      command_source="registered immutable harmless P2-A fixture only")
    result["tool_result"] = record.model_dump(mode="json")
    expected = expected_resource_proof(req, nonce)
    if not record.ok or record.stdout_bytes() != proof_bytes(expected) or record.stderr_bytes():
        return fail("FIXTURE_FAILED", "FIXTURE_EXIT_OR_RESOURCE_PROOF_FAILED")
    result["resource_proof"] = expected
    result["status"] = "FIXTURE_COMPLETED"
    return result


def main(payload=None, *, project_root=None):
    if payload is None:
        raise ValueError("worker requires the fixed trusted transport envelope")
    packet = handle_worker(payload, project_root=project_root)
    sys.stdout.buffer.write((json.dumps(packet, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0
