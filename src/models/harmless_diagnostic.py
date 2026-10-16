"""No-CVE diagnostic preparation/import contracts; none grants execution."""

from typing import Literal

from pydantic import Field, model_validator

from .execution import ExecutionResourceLimits, absolute_target_path
from .host_parser import HostArtifactIdentity, HostMemoryObservation, HostRawArtifact
from .lifecycle import LifecycleContract
from .tool_result import ToolIdentity, ToolResult

DiagnosticTaskID = Literal["p3c-normal-v1", "p3c-invalid-read-v1", "p3c-invalid-write-v1", "p3c-freed-read-v1"]
SHA = r"^[0-9a-f]{64}$"
ID = r"^[0-9a-f]{32}$"


class DiagnosticPreparation(LifecycleContract):
    preparation_schema_version: Literal["1.0"] = "1.0"
    report_locale: Literal["zh-CN"] = "zh-CN"
    domain: Literal["HARMLESS_DIAGNOSTIC_PREPARATION"] = "HARMLESS_DIAGNOSTIC_PREPARATION"
    cve_id: None = None
    request_id: str = Field(pattern=ID)
    run_id: str = Field(pattern=ID)
    task_id: DiagnosticTaskID
    source_sha256: str = Field(pattern=SHA)
    probe_id: str = Field(pattern=ID)
    probe_record_sha256: str = Field(pattern=SHA)
    requested_environment: str
    diagnostic_tool: ToolIdentity | None
    tool_version: str | None
    authorization_status: Literal["NOT_PROVIDED"] = "NOT_PROVIDED"
    isolation_status: Literal["NOT_CHECKED"] = "NOT_CHECKED"
    p2_preflight_status: Literal["UNSUPPORTED"] = "UNSUPPORTED"
    resource_status: Literal["UNSUPPORTED"] = "UNSUPPORTED"
    requested_limits: ExecutionResourceLimits
    status: Literal["REJECTED"] = "REJECTED"
    blockers: list[str] = Field(min_length=1)
    experiment_status: Literal["NOT_CHECKED"] = "NOT_CHECKED"
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    real_cve_verification: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"


class HarmlessDiagnosticCollection(LifecycleContract):
    """Offline data only. Imported data has no authenticated collector claim.

    P3-B's CVE-specific collection stays frozen. This parallel no-CVE context
    shares its XML parser/locators but cannot be projected into a CVE Oracle.
    """
    collection_schema_version: Literal["1.0"] = "1.0"
    domain: Literal["SYNTHETIC", "UNVERIFIED_IMPORT"]
    collector: Literal["p3c-synthetic-xml4/1.0", "p3c-unverified-import-xml4/1.0"]
    cve_id: None = None
    collection_id: str = Field(pattern=ID)
    request_id: str = Field(pattern=ID)
    run_id: str = Field(pattern=ID)
    task_id: DiagnosticTaskID
    source_sha256: str = Field(pattern=SHA)
    executable: ToolIdentity
    build_record_sha256: str = Field(pattern=SHA)
    platform_environment_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    platform_probe_id: str = Field(min_length=1)
    snapshot_sha256: str = Field(pattern=SHA)
    diagnostic_tool: ToolIdentity
    diagnostic_tool_version: str = Field(min_length=1)
    diagnostic_version_record_sha256: str = Field(pattern=SHA)
    diagnostic_format: Literal["VALGRIND_MEMCHECK_XML_V4"] = "VALGRIND_MEMCHECK_XML_V4"
    target_argv: list[str] = Field(min_length=1, max_length=1)
    process: ToolResult
    observed_pid: int = Field(gt=0)
    diagnostic_artifact: HostArtifactIdentity
    stdout_artifact: HostArtifactIdentity
    stderr_artifact: HostArtifactIdentity
    capture_complete: bool
    cleanup_status: Literal["CONFIRMED", "UNKNOWN", "FAILED"]
    execution_authorized: Literal[False] = False

    @model_validator(mode="after")
    def binding(self):
        if (self.domain == "SYNTHETIC") != (self.collector == "p3c-synthetic-xml4/1.0"):
            raise ValueError("合成与未认证导入采集器不能互换")
        if self.process.run_id != self.run_id or self.process.platform_type not in {"linux", "wsl"}:
            raise ValueError("诊断进程的 run 或目标平台不一致")
        if self.executable.status != "OBSERVED" or self.diagnostic_tool.status != "OBSERVED":
            raise ValueError("导入记录仍须包含声明的实际文件身份；声明不等于独立认证")
        for path in (self.executable.resolved_path, self.diagnostic_tool.resolved_path,
                     self.diagnostic_artifact.original_path, self.process.cwd):
            if "\0" in path or not absolute_target_path(path, "wsl"):
                raise ValueError("Linux 诊断实际路径必须是无遍历、无 Windows drive 的绝对 POSIX 路径")
        if self.process.tool_identity != self.diagnostic_tool or self.target_argv != [self.executable.resolved_path]:
            raise ValueError("宿主工具、固定目标或 argv 身份混淆")
        expected = [self.diagnostic_tool.resolved_path, "--tool=memcheck", "--xml=yes",
                    "--xml-file=" + self.diagnostic_artifact.original_path] + self.target_argv
        if self.process.argv != expected:
            raise ValueError("诊断记录不符合固定无参数 fixture 采集格式")
        names = [self.diagnostic_artifact.artifact_file, self.stdout_artifact.artifact_file, self.stderr_artifact.artifact_file]
        from .artifact_package import safe_member
        for name in names:
            safe_member(name)
        if len({x.casefold() for x in names}) != 3:
            raise ValueError("三个原始流必须采用不同文件名")
        for stream in ("stdout", "stderr"):
            identity = getattr(self, stream + "_artifact")
            raw = getattr(self.process, stream + "_bytes")()
            from .tool_result import digest_bytes
            if len(raw) != identity.size_bytes or digest_bytes(raw) != identity.sha256:
                raise ValueError("原始流与 ToolResult 身份不同")
        return self


class HarmlessDiagnosticEvidence(LifecycleContract):
    evidence_schema_version: Literal["1.0"] = "1.0"
    parser_version: Literal["p3b-memcheck-xml4-parser-1.0"] = "p3b-memcheck-xml4-parser-1.0"
    report_locale: Literal["zh-CN"] = "zh-CN"
    collection: HarmlessDiagnosticCollection
    collection_sha256: str = Field(pattern=SHA)
    raw_artifacts: list[HostRawArtifact] = Field(min_length=3, max_length=3)
    parse_status: Literal["PARSED", "REJECTED"]
    diagnostic_codes: list[str]
    observations: list[HostMemoryObservation]
    authenticated_real_capture: Literal[False] = False
    qualified_for_cve_verification: Literal[False] = False
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    real_cve_verification: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
