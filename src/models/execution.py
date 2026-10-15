"""P2-A request and preflight contracts; these models never grant execution."""

from datetime import datetime
import hashlib
import json
from pathlib import PurePosixPath, PureWindowsPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_serializer, model_validator

from .execution_binding import CandidateToolBinding
from .platform import PlatformSnapshot
from .tool_result import ToolIdentity, ToolResult


Action = Literal["FIXED_FIXTURE_CHECK", "SAFE_CUDA_SMOKE", "COMPILE", "INSPECT", "EXECUTE_CANDIDATE"]
ResourceMechanism = Literal["WALL_WATCHDOG", "OUTPUT_CAP", "POSIX_PROCESS_GROUP", "RLIMIT_CPU", "RLIMIT_AS"]
REQUIRED_MECHANISMS = frozenset({"WALL_WATCHDOG", "OUTPUT_CAP", "POSIX_PROCESS_GROUP", "RLIMIT_CPU", "RLIMIT_AS"})


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)


def aware_time(value: str) -> datetime:
    """Reject ambiguous naive timestamps instead of guessing the host timezone."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed


def absolute_target_path(value: str, backend: str) -> bool:
    if backend == "wsl":
        return (PurePosixPath(value).is_absolute() and "\\" not in value
                and not PureWindowsPath(value).drive and ".." not in PurePosixPath(value).parts)
    return (PureWindowsPath(value).is_absolute() or PurePosixPath(value).is_absolute())


class ExecutionResourceLimits(StrictContract):
    wall_time_seconds: float = Field(ge=0.1, le=60)
    cpu_seconds: int = Field(ge=1, le=30)
    memory_bytes: int = Field(ge=67108864, le=1073741824)
    max_output_bytes: int = Field(ge=1, le=1048576)
    process_scope: Literal["POSIX_PROCESS_GROUP"] = "POSIX_PROCESS_GROUP"


class CudaResourceLimits(ExecutionResourceLimits):
    """Separately authorized compiler profile; old fixture bounds stay unchanged."""

    resource_profile: Literal["SAFE_CUDA_TOOLCHAIN"] = "SAFE_CUDA_TOOLCHAIN"
    wall_clock_scope: Literal["PER_TOOL_STEP"] = "PER_TOOL_STEP"
    maximum_tool_steps: Literal[6] = 6
    wall_time_seconds: float = Field(ge=0.1, le=120)
    cpu_seconds: int = Field(ge=1, le=60)
    memory_bytes: int = Field(ge=1073741824, le=8589934592)


class CudaToolchainScope(StrictContract):
    action_id: Literal["p2c-cuda-smoke-v1"] = "p2c-cuda-smoke-v1"
    arch: str = Field(pattern=r"^sm_[0-9]{2,3}$")
    tools: dict[str, ToolIdentity]
    version_records: dict[str, ToolResult]
    target_boot_id: str = Field(pattern=r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
    snapshot_started_monotonic_ns: int = Field(ge=0)
    observed_monotonic_ns: int = Field(ge=0)

    @model_validator(mode="after")
    def measured_tools(self):
        if self.observed_monotonic_ns < self.snapshot_started_monotonic_ns:
            raise ValueError("CUDA target clock observations must be ordered within the same boot")
        if set(self.tools) != {"nvcc", "cuobjdump", "nvdisasm", "host_compiler", "guard_python"}:
            raise ValueError("safe CUDA scope requires all five measured executables")
        if set(self.version_records) != {"nvcc", "cuobjdump", "nvdisasm"}:
            raise ValueError("safe CUDA scope requires three original version observations")
        if any(tool.status != "OBSERVED" for tool in self.tools.values()):
            raise ValueError("all safe CUDA executables must have measured identities")
        for role, record in self.version_records.items():
            if (not record.ok or record.truncated or record.capture_failed
                    or record.tool_identity != self.tools[role]
                    or record.argv != [self.tools[role].resolved_path, "--version"]):
                raise ValueError("CUDA tool version must be a complete bound --version observation")
        return self


class ExecutionRequest(StrictContract):
    request_schema_version: Literal["1.0", "1.1", "1.2"] = "1.0"
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    platform_environment_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    platform_probe_id: str = Field(min_length=1, max_length=128)
    execution_backend: Literal["local", "wsl"]
    authorized_action: Action
    authorization_reference: str = Field(min_length=1, max_length=256)
    tool_role: Literal["fixture_python", "nvcc", "cuobjdump", "nvdisasm"]
    tool_identity: ToolIdentity
    binding: CandidateToolBinding
    resource_limits: ExecutionResourceLimits | CudaResourceLimits
    cuda_toolchain: CudaToolchainScope | None = None
    expected_artifacts: list[Literal["stdout.bin", "stderr.bin", "tool_result.json", "process_result.json"]] = Field(min_length=3, max_length=3)
    candidate_path: str = Field(min_length=1, max_length=4096)
    cwd: str = Field(min_length=1, max_length=4096)
    input_files: list[str] = Field(default_factory=list, max_length=16)
    fixture_id: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def internally_consistent(self):
        if self.request_schema_version == "1.2":
            if (self.authorized_action != "SAFE_CUDA_SMOKE" or self.tool_role != "nvcc"
                    or self.fixture_id != "p2c-cuda-smoke-v1" or self.cuda_toolchain is None
                    or not isinstance(self.resource_limits, CudaResourceLimits)
                    or self.tool_identity != self.cuda_toolchain.tools["nvcc"]):
                raise ValueError("request 1.2 is reserved for the exact registered safe CUDA scope")
        elif self.cuda_toolchain is not None or isinstance(self.resource_limits, CudaResourceLimits) or self.authorized_action == "SAFE_CUDA_SMOKE":
            raise ValueError("legacy requests cannot use the CUDA resource profile or scope")
        for name in ("platform_probe_id", "authorization_reference", "fixture_id", "candidate_path", "cwd"):
            value = getattr(self, name)
            if not value.strip() or "\0" in value:
                raise ValueError(name + " must be nonblank and contain no NUL")
        process_artifact = "tool_result.json" if self.request_schema_version == "1.0" else "process_result.json"
        if set(self.expected_artifacts) != {"stdout.bin", "stderr.bin", process_artifact}:
            raise ValueError("expected artifacts must include stdout.bin, stderr.bin and " + process_artifact
                             + " exactly once for request schema " + self.request_schema_version)
        if len(set(self.input_files)) != len(self.input_files):
            raise ValueError("duplicate input files")
        for path in (self.candidate_path, self.cwd, *self.input_files):
            if "\0" in path or not absolute_target_path(path, self.execution_backend):
                raise ValueError("request paths must be absolute paths in the target environment")
        if self.tool_identity.status != "OBSERVED":
            raise ValueError("execution request requires a measured executable identity")
        for name in ("candidate_sha256", "platform_environment_id", "platform_probe_id", "execution_backend"):
            if getattr(self, name) != getattr(self.binding, name):
                raise ValueError("request and binding disagree on " + name)
        if (self.tool_identity.resolved_path != self.binding.tool_resolved_path
                or self.tool_identity.file_sha256 != self.binding.tool_file_sha256):
            raise ValueError("request executable identity disagrees with candidate/tool binding")
        return self

    @model_serializer(mode="wrap")
    def preserve_legacy(self, handler):
        data = handler(self)
        if self.request_schema_version != "1.2":
            data.pop("cuda_toolchain", None)
        return data


class OperatorAuthorization(StrictContract):
    """A separately supplied operator record, accepted only against trusted policy.

    Merely putting this JSON alongside an LLM response does not make it trusted.
    The entry point must load operator records and policy from its trusted source.
    """

    authorization_schema_version: Literal["1.0", "1.1"] = "1.0"
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    authorization_reference: str = Field(min_length=1, max_length=256)
    operator_id: str = Field(min_length=1, max_length=128)
    issuer_kind: Literal["operator", "trusted_policy"]
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    platform_environment_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    platform_probe_id: str = Field(min_length=1, max_length=128)
    authorized_action: Action
    tool_resolved_path: str = Field(min_length=1, max_length=4096)
    tool_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    resource_limits: ExecutionResourceLimits | CudaResourceLimits
    cuda_toolchain: CudaToolchainScope | None = None
    fixture_id: str = Field(min_length=1, max_length=128)
    not_before: str
    expires_at: str
    authorization_clock: Literal["WALL", "TARGET_BOOT_MONOTONIC"] = "WALL"
    not_before_monotonic_ns: int | None = Field(default=None, ge=0)
    expires_monotonic_ns: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def valid_authorization(self):
        cuda = self.authorization_schema_version == "1.1"
        if cuda != (self.authorized_action == "SAFE_CUDA_SMOKE" and self.fixture_id == "p2c-cuda-smoke-v1"
                    and isinstance(self.resource_limits, CudaResourceLimits) and self.cuda_toolchain is not None):
            raise ValueError("authorization version and exact safe CUDA scope/profile disagree")
        if not cuda and (self.cuda_toolchain is not None or isinstance(self.resource_limits, CudaResourceLimits)
                         or self.authorized_action == "SAFE_CUDA_SMOKE"):
            raise ValueError("legacy authorization cannot grant CUDA resource profile")
        if cuda:
            if (self.authorization_clock != "TARGET_BOOT_MONOTONIC" or self.not_before_monotonic_ns is None
                    or self.expires_monotonic_ns is None
                    or self.not_before_monotonic_ns != self.cuda_toolchain.observed_monotonic_ns
                    or not 0 < self.expires_monotonic_ns - self.not_before_monotonic_ns <= 300000000000):
                raise ValueError("CUDA authorization must bind the observed target boot clock and a bounded five-minute grant")
        elif self.authorization_clock != "WALL" or self.not_before_monotonic_ns is not None or self.expires_monotonic_ns is not None:
            raise ValueError("legacy grants keep their original wall-clock semantics")
        for value in (self.authorization_reference, self.operator_id, self.platform_probe_id,
                      self.tool_resolved_path, self.fixture_id):
            if not value.strip() or "\0" in value:
                raise ValueError("authorization identifiers must be nonblank and contain no NUL")
        if aware_time(self.expires_at) <= aware_time(self.not_before):
            raise ValueError("authorization expiry must follow its not-before time")
        if not (PurePosixPath(self.tool_resolved_path).is_absolute()
                or PureWindowsPath(self.tool_resolved_path).is_absolute()):
            raise ValueError("authorization tool path must be absolute")
        return self

    @model_serializer(mode="wrap")
    def preserve_legacy(self, handler):
        data = handler(self)
        if self.authorization_schema_version == "1.0":
            data.pop("cuda_toolchain", None)
            for field in ("authorization_clock", "not_before_monotonic_ns", "expires_monotonic_ns"):
                data.pop(field, None)
        return data


class ResourceSupport(StrictContract):
    """Capabilities measured by trusted worker setup, never inferred from a request."""

    status: Literal["OBSERVED", "UNKNOWN", "UNSUPPORTED"]
    mechanisms: list[ResourceMechanism]
    source: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def valid_capabilities(self):
        if not self.source.strip() or len(set(self.mechanisms)) != len(self.mechanisms):
            raise ValueError("capability source must be nonblank and mechanisms unique")
        if self.status != "OBSERVED" and self.mechanisms:
            raise ValueError("unconfirmed resource capabilities cannot claim enforcement")
        return self


class PreflightPolicy(StrictContract):
    """Trusted local configuration, supplied independently of request/LLM JSON."""

    policy_schema_version: Literal["1.0", "1.1"] = "1.0"
    expected_environment_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    expected_probe_id: str = Field(min_length=1, max_length=128)
    expected_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_target_environment: str = Field(min_length=1, max_length=128)
    execution_backend: Literal["local", "wsl"]
    allowed_operator_ids: list[str] = Field(min_length=1, max_length=16)
    allowed_authorization_references: list[str] = Field(min_length=1, max_length=16)
    scope_root: str = Field(min_length=1, max_length=4096)
    allowed_tools: dict[str, str] = Field(min_length=1, max_length=16)
    fixture_hashes: dict[str, str] = Field(min_length=1, max_length=16)
    max_snapshot_age_seconds: int = Field(ge=1, le=3600, default=300)
    max_candidate_bytes: int = Field(ge=1, le=1048576, default=1048576)
    resource_support: ResourceSupport
    max_resource_limits: ExecutionResourceLimits | CudaResourceLimits
    cuda_toolchain: CudaToolchainScope | None = None

    @model_validator(mode="after")
    def valid_trusted_policy(self):
        cuda = self.policy_schema_version == "1.1"
        if cuda != (isinstance(self.max_resource_limits, CudaResourceLimits) and self.cuda_toolchain is not None):
            raise ValueError("policy version and safe CUDA profile/scope disagree")
        if not cuda and (self.cuda_toolchain is not None or isinstance(self.max_resource_limits, CudaResourceLimits)):
            raise ValueError("legacy policy cannot enable CUDA resources")
        import re
        values = (self.expected_probe_id, self.expected_target_environment,
                  *self.allowed_operator_ids, *self.allowed_authorization_references, *self.fixture_hashes)
        if any(not value.strip() or "\0" in value for value in values):
            raise ValueError("policy identifiers must be nonblank and contain no NUL")
        if any(len(values) != len(set(values)) for values in
               (self.allowed_operator_ids, self.allowed_authorization_references)):
            raise ValueError("policy allowlists must not contain duplicates")
        if not absolute_target_path(self.scope_root, self.execution_backend):
            raise ValueError("scope root must be an absolute target-environment path")
        for path, digest in self.allowed_tools.items():
            if not absolute_target_path(path, self.execution_backend) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("tool allowlist must bind absolute target paths to SHA-256 digests")
        if any(not re.fullmatch(r"[0-9a-f]{64}", digest) for digest in self.fixture_hashes.values()):
            raise ValueError("fixture allowlist must contain SHA-256 digests")
        return self

    @model_serializer(mode="wrap")
    def preserve_legacy(self, handler):
        data = handler(self)
        if self.policy_schema_version == "1.0":
            data.pop("cuda_toolchain", None)
        return data


class PreflightDiagnostic(StrictContract):
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)


class PreflightResult(StrictContract):
    preflight_schema_version: Literal["1.0"] = "1.0"
    request_id: str | None
    status: Literal["READY", "REJECTED", "UNKNOWN", "UNSUPPORTED"]
    diagnostics: list[PreflightDiagnostic]
    checked_at: str
    measured_candidate_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    measured_tool_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    verification_status: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"

    @model_validator(mode="after")
    def outcome_consistent(self):
        aware_time(self.checked_at)
        if (self.status == "READY") == bool(self.diagnostics):
            raise ValueError("READY requires no diagnostic; a failed preflight requires a reason")
        if self.status == "READY" and (self.request_id is None or self.measured_candidate_sha256 is None
                                       or self.measured_tool_sha256 is None):
            raise ValueError("READY requires measured candidate and tool identities")
        return self


def request_sha256(request: ExecutionRequest | dict) -> str:
    model = ExecutionRequest.model_validate(request.model_dump(mode="python") if isinstance(request, ExecutionRequest) else request)
    encoded = json.dumps(model.model_dump(mode="json"), sort_keys=True, ensure_ascii=False,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def snapshot_sha256(snapshot: PlatformSnapshot | dict) -> str:
    """Bind the complete stored snapshot, including probe time and provenance.

    The scientific environment_id deliberately excludes volatile metadata. It
    cannot by itself authenticate freshness of a particular observation.
    """
    model = PlatformSnapshot.model_validate(snapshot.model_dump(mode="python")
                                            if isinstance(snapshot, PlatformSnapshot) else snapshot)
    encoded = json.dumps(model.model_dump(mode="json"), sort_keys=True, ensure_ascii=False,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
