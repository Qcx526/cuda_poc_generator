"""New no-CVE fixed Memcheck contracts. Historical P2/P3 objects stay frozen."""

from typing import Literal

from pydantic import Field, model_validator

from .execution import StrictContract, absolute_target_path
from .lifecycle import (ArtifactReference, LifecycleContract, LifecycleEvent, LifecycleState,
                        ProcessObservation, ResourceObservation, TERMINAL_STATES, validate_events,
                        canonical_sha256)
from .platform import PlatformSnapshot
from .tool_result import ToolIdentity, ToolResult

ID = r"^[0-9a-f]{32}$"
SHA = r"^[0-9a-f]{64}$"
TaskID = Literal["p3c-normal-v1", "p3c-invalid-write-v1"]
TOOLS = frozenset({"compiler", "valgrind", "valgrind_launcher", "memcheck", "bwrap", "guard_python"})


def _images(tools, helpers):
    import re
    images = {}
    for path, digest in [(x.resolved_path,x.file_sha256) for x in tools.values()] + list(helpers.items()):
        if (not isinstance(path,str) or not absolute_target_path(path,"wsl") or not isinstance(digest,str)
                or re.fullmatch(SHA,digest) is None):
            raise ValueError("工具允许列表必须是原生 POSIX 绝对路径和 SHA-256")
        if path in images and images[path] != digest:
            raise ValueError("同一路径不能绑定冲突的工具字节身份")
        images[path] = digest
    return images


class MemcheckResourceLimits(StrictContract):
    resource_profile: Literal["P3D_FIXED_CPU_MEMCHECK_V1"] = "P3D_FIXED_CPU_MEMCHECK_V1"
    wall_time_seconds: float = Field(default=30.0, ge=0.1, le=60)
    cpu_seconds: int = Field(default=10, ge=1, le=30)
    memory_bytes: int = Field(default=4294967296, ge=1073741824, le=8589934592)
    max_output_bytes: int = Field(default=1048576, ge=1, le=1048576)
    max_xml_bytes: int = Field(default=2097152, ge=1, le=2097152)
    max_file_bytes: int = Field(default=4194304, ge=1048576, le=4194304)
    max_open_files: Literal[128] = 128
    max_tracees: Literal[32] = 32
    core_bytes: Literal[0] = 0
    limit_scope: Literal["PER_PROCESS_RLIMITS_AND_TASK_WALL_WATCHDOG"] = "PER_PROCESS_RLIMITS_AND_TASK_WALL_WATCHDOG"
    cgroup_enforcement: Literal["NOT_IMPLEMENTED"] = "NOT_IMPLEMENTED"
    gpu_vram_limit: Literal["NOT_IMPLEMENTED"] = "NOT_IMPLEMENTED"


class MemcheckDescription(LifecycleContract):
    description_schema_version: Literal["1.0"] = "1.0"
    description_id: str = Field(pattern=ID)
    status: Literal["DESCRIBED", "UNKNOWN", "UNSUPPORTED"]
    target_environment: str
    snapshot: PlatformSnapshot | None
    native_task_root: str
    tools: dict[str, ToolIdentity]
    helper_images: dict[str, str]
    collector_sha256: str = Field(pattern=SHA)
    versions: dict[str, ToolResult]
    target_boot_id: str
    observed_monotonic_ns: int = Field(ge=0)
    diagnostics: list[str]
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    verification_status: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"

    @model_validator(mode="after")
    def described(self):
        if not absolute_target_path(self.native_task_root,"wsl"):
            raise ValueError("WSL 固定工作区必须是原生 POSIX 绝对路径")
        if self.status == "DESCRIBED":
            if self.snapshot is None or set(self.tools) != TOOLS or any(x.status != "OBSERVED" for x in self.tools.values()):
                raise ValueError("固定诊断描述必须包含真实平台和全部实测工具身份")
            _images(self.tools,self.helper_images)
            if set(self.versions) != {"compiler", "valgrind", "bwrap"}:
                raise ValueError("固定描述缺少版本原始记录")
            for role, result in self.versions.items():
                expected = self.tools[role]
                if (not result.ok or result.truncated or result.capture_failed
                        or result.argv != [expected.resolved_path, "--version"]
                        or result.tool_identity.file_sha256 != expected.file_sha256
                        or result.target_environment != self.target_environment):
                    raise ValueError("版本查询未绑定完整真实输出和工具身份")
        return self


class MemcheckRequest(LifecycleContract):
    request_schema_version: Literal["memcheck-1.0"] = "memcheck-1.0"
    authorized_action: Literal["FIXED_MEMCHECK_DIAGNOSTIC"] = "FIXED_MEMCHECK_DIAGNOSTIC"
    request_id: str = Field(pattern=ID)
    run_id: str = Field(pattern=ID)
    task_id: TaskID
    source_sha256: str = Field(pattern=SHA)
    description_sha256: str = Field(pattern=SHA)
    collector_sha256: str = Field(pattern=SHA)
    platform_environment_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    platform_probe_id: str
    snapshot_sha256: str = Field(pattern=SHA)
    target_environment: str
    execution_backend: Literal["wsl"] = "wsl"
    target_boot_id: str
    observed_monotonic_ns: int = Field(ge=0)
    tools: dict[str, ToolIdentity]
    helper_images: dict[str, str]
    resource_limits: MemcheckResourceLimits
    authorization_reference: str = Field(min_length=1, max_length=256)
    expected_artifacts: Literal["FIXED_SOURCE_BUILD_XML_STREAMS_AND_PROCESS_RECORDS"] = "FIXED_SOURCE_BUILD_XML_STREAMS_AND_PROCESS_RECORDS"

    @model_validator(mode="after")
    def fixed_scope(self):
        from ..memcheck_registry import get_memcheck_task
        if self.source_sha256 != get_memcheck_task(self.task_id).source_sha256:
            raise ValueError("请求不能改变固定 fixture 的源码身份")
        if set(self.tools) != TOOLS or any(x.status != "OBSERVED" for x in self.tools.values()):
            raise ValueError("固定诊断请求必须绑定全部工具身份")
        _images(self.tools,self.helper_images)
        if not self.target_environment.startswith("wsl:") or any(c in self.authorization_reference for c in "\0\r\n"):
            raise ValueError("目标或授权引用无效")
        return self


class MemcheckAuthorization(LifecycleContract):
    authorization_schema_version: Literal["memcheck-1.0"] = "memcheck-1.0"
    authorized_action: Literal["FIXED_MEMCHECK_DIAGNOSTIC"] = "FIXED_MEMCHECK_DIAGNOSTIC"
    request_id: str = Field(pattern=ID)
    run_id: str = Field(pattern=ID)
    task_id: TaskID
    request_sha256: str = Field(pattern=SHA)
    operator_id: str = Field(min_length=1, max_length=128)
    authorization_reference: str = Field(min_length=1, max_length=256)
    issuer_kind: Literal["operator", "trusted_policy"]
    target_boot_id: str
    not_before_monotonic_ns: int = Field(ge=0)
    expires_monotonic_ns: int = Field(ge=0)

    @model_validator(mode="after")
    def bounded_authority(self):
        if not 0 < self.expires_monotonic_ns - self.not_before_monotonic_ns <= 300000000000:
            raise ValueError("固定诊断授权期限最长五分钟")
        if any(not x.strip() or any(c in x for c in "\0\r\n") for x in (self.operator_id, self.authorization_reference)):
            raise ValueError("操作者和授权引用必须是单行非空标识")
        return self


class MemcheckPolicy(LifecycleContract):
    policy_schema_version: Literal["memcheck-1.0"] = "memcheck-1.0"
    request_sha256: str = Field(pattern=SHA)
    description_sha256: str = Field(pattern=SHA)
    allowed_operator_ids: list[str] = Field(min_length=1, max_length=16)
    allowed_authorization_references: list[str] = Field(min_length=1, max_length=16)
    allowed_images: dict[str, str]
    native_task_root: str
    resource_limits: MemcheckResourceLimits
    max_description_age_seconds: int = Field(default=300, ge=1, le=300)
    sandbox_profile: Literal["P3D_FIXED_CPU_MEMCHECK_V1"] = "P3D_FIXED_CPU_MEMCHECK_V1"

    @model_validator(mode="after")
    def native_scope(self):
        if not absolute_target_path(self.native_task_root,"wsl"):
            raise ValueError("固定策略范围必须是原生 POSIX 绝对路径")
        _images({},self.allowed_images)
        return self


class MemcheckResources(ResourceObservation):
    cpu_seconds: int | None = Field(default=None, ge=1, le=30)
    memory_bytes: int | None = Field(default=None, ge=1073741824, le=8589934592)
    network_isolation: Literal["NOT_IMPLEMENTED", "NAMESPACE_CONFIRMED"] = "NOT_IMPLEMENTED"


class MemcheckProcess(ProcessObservation):
    process_schema_version: Literal["memcheck-1.0"] = "memcheck-1.0"
    resource_limits: MemcheckResourceLimits
    resources: MemcheckResources
    inner_argv: list[str]
    ready_observation: dict | None
    host_observation: dict | None = None
    inner_result: dict | None
    trace_events: list[dict] = Field(max_length=512)
    inner_pid: int | None = Field(default=None, gt=0)
    inner_returncode: int | None
    inner_linux_signal: int | None


class MemcheckStep(LifecycleContract):
    step_id: Literal["compile", "memcheck"]
    status: LifecycleState
    process: MemcheckProcess

    @model_validator(mode="after")
    def terminal(self):
        if self.status not in TERMINAL_STATES:
            raise ValueError("已保存步骤必须是终态")
        if self.status == "COMPLETED" and (not self.process.action_started or self.process.returncode != 0
                or self.process.inner_returncode != 0 or self.process.inner_result is None
                or self.process.cleanup.status != "CONFIRMED" or self.process.capture_failed
                or self.process.timed_out or self.process.cancelled or self.process.truncated):
            raise ValueError("步骤完成须有真实启动、零退出、完整采集和确认回收")
        return self


class MemcheckExecutionRecord(LifecycleContract):
    execution_schema_version: Literal["memcheck-1.0"] = "memcheck-1.0"
    report_locale: Literal["zh-CN"] = "zh-CN"
    domain: Literal["RECORDED_FIXED_CPU_DIAGNOSTIC"] = "RECORDED_FIXED_CPU_DIAGNOSTIC"
    cve_id: None = None
    collector_version: Literal["p3d-fixed-memcheck-1.0"] = "p3d-fixed-memcheck-1.0"
    request_id: str = Field(pattern=ID)
    run_id: str = Field(pattern=ID)
    task_id: TaskID
    request_sha256: str = Field(pattern=SHA)
    authorization_sha256: str = Field(pattern=SHA)
    policy_sha256: str = Field(pattern=SHA)
    snapshot_sha256: str = Field(pattern=SHA)
    platform_environment_id: str
    platform_probe_id: str
    target_environment: str
    source_sha256: str = Field(pattern=SHA)
    executable_sha256: str | None = Field(default=None, pattern=SHA)
    worker_identity: dict
    status: LifecycleState
    events: list[LifecycleEvent]
    steps: list[MemcheckStep] = Field(max_length=2)
    artifacts: dict[str, ArtifactReference]
    diagnostics: list[str]
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    verification_status: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"

    @model_validator(mode="after")
    def ordered(self):
        validate_events(self.events, self.status)
        ids = [s.step_id for s in self.steps]
        if ids != ["compile", "memcheck"][:len(ids)]:
            raise ValueError("固定诊断必须先编译再运行 Memcheck")
        if len(self.steps) > 1 and (self.steps[0].status != "COMPLETED" or self.executable_sha256 is None):
            raise ValueError("Memcheck 不得使用未成功构建并绑定的产物")
        if self.status == "COMPLETED" and (len(self.steps) != 2 or any(s.status != "COMPLETED" for s in self.steps)
                or "memcheck.xml" not in self.artifacts):
            raise ValueError("诊断完成必须有两步执行和原始 XML")
        if any(k != v.file for k, v in self.artifacts.items()):
            raise ValueError("证据键与安全文件名不一致")
        return self


def validate_memcheck_binding(record, request, authorization, policy):
    """No self-asserted capture flag: all independently stored identities bind."""
    record = MemcheckExecutionRecord.model_validate(record)
    req = MemcheckRequest.model_validate(request)
    auth = MemcheckAuthorization.model_validate(authorization)
    trusted = MemcheckPolicy.model_validate(policy)
    if (record.request_id, record.run_id, record.task_id, record.source_sha256) != (req.request_id, req.run_id, req.task_id, req.source_sha256):
        raise ValueError("执行记录与固定请求身份冲突")
    if (record.request_sha256 != canonical_sha256(req) or auth.request_sha256 != record.request_sha256
            or trusted.request_sha256 != record.request_sha256
            or record.authorization_sha256 != canonical_sha256(auth) or record.policy_sha256 != canonical_sha256(trusted)):
        raise ValueError("执行、授权或策略摘要冲突")
    if (auth.request_id, auth.run_id, auth.task_id) != (req.request_id, req.run_id, req.task_id):
        raise ValueError("授权跨 request/run/fixture 混淆")
    if (auth.operator_id not in trusted.allowed_operator_ids or auth.authorization_reference not in trusted.allowed_authorization_references
            or auth.authorization_reference != req.authorization_reference):
        raise ValueError("授权不在独立策略允许范围")
    if (trusted.description_sha256 != req.description_sha256 or trusted.resource_limits != req.resource_limits
            or auth.target_boot_id != req.target_boot_id):
        raise ValueError("策略、授权或采集器范围与请求不一致")
    if (record.platform_environment_id, record.platform_probe_id, record.snapshot_sha256, record.target_environment) != (
            req.platform_environment_id, req.platform_probe_id, req.snapshot_sha256, req.target_environment):
        raise ValueError("执行记录的平台与请求不一致")
    for step in record.steps:
        from ..memcheck_registry import inner_argv
        if step.process.inner_argv != inner_argv(step.step_id, req.tools) or step.process.resource_limits != req.resource_limits:
            raise ValueError("步骤改变了固定 argv 或资源限制")
    return record, req, auth, trusted
