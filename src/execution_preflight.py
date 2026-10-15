"""Read-only P2-A checks. READY never dispatches a process or proves a CVE."""

from datetime import datetime, timezone
import hashlib
from pathlib import Path

from pydantic import ValidationError

from .models.execution import (ExecutionRequest, OperatorAuthorization, PreflightPolicy,
                               PreflightResult, REQUIRED_MECHANISMS, aware_time, snapshot_sha256)
from .models.execution_binding import CandidateToolBinding, bind_candidate_to_tool
from .models.platform import PlatformSnapshot
from .models.tool_result import ToolResult
from .tools.process import current_platform_type


def _validate(model, value):
    # JSON serialization can turn a model_copy-injected True in an int field
    # into 1. Revalidate original Python types before any JSON normalization.
    return model.model_validate(value.model_dump(mode="python") if isinstance(value, model) else value)


def _scoped_path(raw: str, root: Path, *, directory: bool = False) -> Path:
    path = Path(raw)
    # Avoid accepting paths whose spelling hides a link or escapes the root.
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("path is not a canonical absolute target path")
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError("symlink paths are unsupported for fixed fixture inputs")
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError("path is outside trusted workspace scope")
    if directory and not resolved.is_dir():
        raise ValueError("working directory is not a directory")
    if not directory and not resolved.is_file():
        raise ValueError("input is not a regular file")
    return resolved


def preflight_execution(request, snapshot, tool_record, authorization, policy, *, now=None,
                        observed_platform_type=None, observed_target_environment=None) -> PreflightResult:
    """Compare independent trusted policy/authorization to real local file bytes.

    Run this function in the target environment. A Windows process cannot check a
    WSL request's POSIX files. Optional observed identity arguments are for a
    trusted observer/worker, never fields accepted from untrusted request JSON.
    The caller must keep the trusted policy and operator record out of LLM input.
    """
    moment = now if now is not None else datetime.now(timezone.utc)
    if not isinstance(moment, datetime) or moment.tzinfo is None:
        raise ValueError("preflight now must be timezone aware")
    checked_at = moment.isoformat()
    request_id = None
    measured_candidate = None
    measured_tool = None

    def result(status, code=None, message=None):
        return PreflightResult(request_id=request_id, status=status, checked_at=checked_at,
                               diagnostics=[] if code is None else [{"code": code, "message": message}],
                               measured_candidate_sha256=measured_candidate, measured_tool_sha256=measured_tool)

    try:
        req = _validate(ExecutionRequest, request)
        request_id = req.request_id
        trusted = _validate(PreflightPolicy, policy)
        platform = _validate(PlatformSnapshot, snapshot)
        record = _validate(ToolResult, tool_record)
    except (ValidationError, ValueError, TypeError, KeyError):
        return result("REJECTED", "INVALID_CONTRACT", "Request, policy, snapshot or tool record failed strict validation.")

    if req.authorized_action != "FIXED_FIXTURE_CHECK" or req.tool_role != "fixture_python":
        return result("UNSUPPORTED", "ACTION_UNSUPPORTED", "P2-A supports only the registered harmless fixed fixture check.")
    if req.execution_backend != "wsl" or trusted.execution_backend != "wsl":
        return result("UNSUPPORTED", "BACKEND_UNSUPPORTED", "P2-A fixture resource policy supports only the WSL target backend.")
    if authorization is None:
        return result("REJECTED", "AUTHORIZATION_MISSING", "A separately supplied trusted operator authorization is required.")
    try:
        auth = _validate(OperatorAuthorization, authorization)
    except (ValidationError, ValueError, TypeError):
        return result("REJECTED", "AUTHORIZATION_INVALID", "Operator authorization failed strict validation.")
    if (auth.operator_id not in trusted.allowed_operator_ids
            or auth.authorization_reference not in trusted.allowed_authorization_references
            or req.authorization_reference != auth.authorization_reference):
        return result("REJECTED", "AUTHORIZATION_UNTRUSTED", "Operator identity or authorization reference is outside trusted policy.")
    auth_fields = ("request_id", "candidate_sha256", "platform_environment_id", "platform_probe_id",
                   "authorized_action", "fixture_id", "resource_limits")
    if (any(getattr(req, name) != getattr(auth, name) for name in auth_fields)
            or auth.tool_resolved_path != req.tool_identity.resolved_path
            or auth.tool_file_sha256 != req.tool_identity.file_sha256):
        return result("REJECTED", "AUTHORIZATION_SCOPE_MISMATCH", "Authorization does not bind this exact request, action, target, tool and limits.")
    if not aware_time(auth.not_before) <= moment < aware_time(auth.expires_at):
        return result("REJECTED", "AUTHORIZATION_EXPIRED", "Authorization is expired or is not yet effective.")

    if (req.platform_environment_id != trusted.expected_environment_id
            or platform.environment_id != trusted.expected_environment_id
            or req.platform_probe_id != trusted.expected_probe_id
            or platform.metadata["probe_id"] != trusted.expected_probe_id
            or platform.execution_backend != req.execution_backend
            or platform.platform_type != "wsl"
            or platform.metadata["environment_label"] != trusted.expected_target_environment
            or req.binding.target_environment != trusted.expected_target_environment):
        return result("REJECTED", "TARGET_IDENTITY_MISMATCH", "Snapshot, request, binding and trusted target identity do not agree.")
    if snapshot_sha256(platform) != trusted.expected_snapshot_sha256:
        return result("REJECTED", "SNAPSHOT_CONTENT_MISMATCH", "Stored snapshot bytes differ from the independently trusted observation, including its time.")
    try:
        actual_platform = observed_platform_type or current_platform_type()
        if observed_target_environment is None:
            from .tools.process import canonical_target_environment
            actual_target = canonical_target_environment(actual_platform)
        else:
            actual_target = observed_target_environment
    except (OSError, ValueError):
        return result("UNKNOWN", "TARGET_OBSERVATION_FAILED", "Actual target environment could not be established.")
    if actual_platform != platform.platform_type or actual_target != trusted.expected_target_environment:
        return result("REJECTED", "ACTUAL_TARGET_MISMATCH", "The actual worker environment differs from the authorized target.")
    if platform.probe_status == "FAILED":
        return result("UNKNOWN", "PLATFORM_PROBE_FAILED", "Failed platform probing cannot establish execution readiness.")
    try:
        age = (moment - aware_time(platform.metadata["started_at"])).total_seconds()
    except (ValueError, TypeError, KeyError, AttributeError):
        return result("UNKNOWN", "PLATFORM_TIME_UNKNOWN", "Snapshot has no valid timezone-aware observation time.")
    if age < -5 or age > trusted.max_snapshot_age_seconds:
        return result("REJECTED", "PLATFORM_SNAPSHOT_STALE", "Platform snapshot is too old or is dated in the future.")
    if record.start_status != "STARTED" or not record.ok or record.capture_failed or record.truncated:
        return result("REJECTED", "TOOL_RECORD_UNUSABLE", "Tool binding requires a complete normally exiting tool observation.")

    if req.input_files:
        return result("UNSUPPORTED", "EXTRA_INPUT_UNSUPPORTED", "The fixed fixture accepts no caller-supplied extra input files.")
    try:
        root = Path(trusted.scope_root)
        for component in (root, *root.parents):
            if component.is_symlink():
                raise ValueError("trusted scope root must not use symlink components")
        root = root.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("trusted scope root is not a directory")
        candidate = _scoped_path(req.candidate_path, root)
        _scoped_path(req.cwd, root, directory=True)
        with candidate.open("rb") as stream:
            data = stream.read(trusted.max_candidate_bytes + 1)
        if not data or len(data) > trusted.max_candidate_bytes:
            return result("REJECTED", "CANDIDATE_SIZE_INVALID", "Candidate is empty or exceeds the trusted byte-size limit.")
        measured_candidate = hashlib.sha256(data).hexdigest()
    except FileNotFoundError:
        return result("REJECTED", "INPUT_MISSING", "Candidate or working directory does not exist.")
    except (OSError, ValueError):
        return result("REJECTED", "INPUT_SCOPE_INVALID", "Candidate or working directory is unreadable, linked, nonregular or outside trusted scope.")
    if measured_candidate != req.candidate_sha256:
        return result("REJECTED", "CANDIDATE_HASH_MISMATCH", "Current candidate bytes do not match the authorized SHA-256.")
    if trusted.fixture_hashes.get(req.fixture_id) != measured_candidate:
        return result("REJECTED", "FIXTURE_NOT_ALLOWLISTED", "Candidate bytes are not the exact registered harmless fixture.")

    tool_path = req.tool_identity.resolved_path
    allowed_digest = trusted.allowed_tools.get(tool_path)
    if allowed_digest is None or allowed_digest != req.tool_identity.file_sha256:
        return result("REJECTED", "TOOL_NOT_ALLOWLISTED", "Executable path and identity are outside the trusted allowlist.")
    try:
        from .tools.process import measure_tool_identity
        measured = measure_tool_identity(tool_path, cwd=req.cwd, source="P2-A preflight real executable bytes")
    except (OSError, ValueError):
        return result("UNKNOWN", "TOOL_IDENTITY_UNKNOWN", "Executable identity measurement failed; no process may start.")
    if measured.status != "OBSERVED":
        return result("UNKNOWN", "TOOL_IDENTITY_UNKNOWN", "Executable identity is unknown; no process may start.")
    measured_tool = measured.file_sha256
    if measured.resolved_path != tool_path or measured_tool != allowed_digest:
        return result("REJECTED", "TOOL_IDENTITY_MISMATCH", "Current executable file differs from its authorized path or SHA-256.")
    try:
        actual_binding = bind_candidate_to_tool(data, platform, record,
                                               expected_probe_id=trusted.expected_probe_id,
                                               expected_tool_record_id=req.binding.tool_record_id)
        expected_binding = _validate(CandidateToolBinding, req.binding)
        if actual_binding != expected_binding:
            raise ValueError("binding differs from measured inputs")
    except (ValidationError, ValueError, TypeError):
        return result("REJECTED", "TOOL_BINDING_MISMATCH", "Tool record and candidate binding differ or describe a foreign environment.")

    support = trusted.resource_support
    if support.status == "UNKNOWN":
        return result("UNKNOWN", "RESOURCE_SUPPORT_UNKNOWN", "Actual resource enforcement capabilities have not been established.")
    if support.status != "OBSERVED" or not REQUIRED_MECHANISMS.issubset(support.mechanisms):
        return result("UNSUPPORTED", "RESOURCE_POLICY_UNSUPPORTED", "Worker cannot implement every required resource boundary.")
    for name in ("wall_time_seconds", "cpu_seconds", "memory_bytes", "max_output_bytes"):
        if getattr(req.resource_limits, name) > getattr(trusted.max_resource_limits, name):
            return result("REJECTED", "RESOURCE_LIMIT_EXCEEDS_POLICY", "Requested resource limits exceed trusted policy.")
    return result("READY")
