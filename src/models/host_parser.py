"""P3-B host diagnostics: an observation is never a specific CVE proof."""

import base64
from typing import Literal

from pydantic import Field, model_validator

from .lifecycle import LifecycleContract
from .tool_result import ToolIdentity, ToolResult, digest_bytes


KnowledgeStatus = Literal["OBSERVED", "DOCUMENTED", "INFERRED", "UNKNOWN", "UNSUPPORTED", "NOT_CHECKED"]
HostCVE = Literal["CVE-2025-23308", "CVE-2025-23339"]


class HostArtifactIdentity(LifecycleContract):
    artifact_file: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    original_path: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0, le=16777216)


class HostProgramIdentity(LifecycleContract):
    component: Literal["nvdisasm", "cuobjdump"]
    executable: ToolIdentity
    build: str | None = Field(default=None, min_length=1)
    build_status: KnowledgeStatus
    version_record_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def observed_build(self):
        if self.executable.status != "OBSERVED":
            raise ValueError("host executable identity must be measured")
        if self.build_status == "OBSERVED" and (self.build is None or self.version_record_sha256 is None):
            raise ValueError("observed build requires the version record digest")
        if self.build_status in {"UNKNOWN", "UNSUPPORTED", "NOT_CHECKED"} and self.build is not None:
            raise ValueError("unknown build cannot contain a version assertion")
        return self


class HostInputIdentity(LifecycleContract):
    file: HostArtifactIdentity
    container_format: Literal["ELF32", "ELF64", "CUDA_FATBIN", "UNKNOWN"]
    payload_format: Literal["CUDA_CUBIN", "DEBUG_INFO", "RELOCATION_DATA", "UNKNOWN"]
    format_status: KnowledgeStatus
    # These are independent: cubin is not an ELF class and fatbin is not cubin.
    format_evidence: str | None = None


class HostParserCollection(LifecycleContract):
    collection_schema_version: Literal["1.0"] = "1.0"
    collection_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    cve_id: HostCVE
    domain: Literal["SYNTHETIC", "IMPORTED_OBSERVATION"]
    collector: Literal["p3b-synthetic-valgrind-1.0", "p3b-imported-valgrind-1.0"]
    diagnostic_format: Literal["VALGRIND_MEMCHECK_XML_V4", "ASAN_UNSUPPORTED", "UBSAN_UNSUPPORTED"]
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    platform_environment_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    platform_probe_id: str = Field(min_length=1)
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target: HostProgramIdentity
    input: HostInputIdentity
    diagnostic_tool: ToolIdentity
    diagnostic_tool_version: str = Field(min_length=1)
    diagnostic_tool_version_status: KnowledgeStatus = "UNKNOWN"
    diagnostic_version_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_argv: list[str] = Field(min_length=2, max_length=64)
    process: ToolResult
    observed_pid: int = Field(gt=0)
    diagnostic_artifact: HostArtifactIdentity
    stdout_artifact: HostArtifactIdentity
    stderr_artifact: HostArtifactIdentity
    capture_complete: bool
    cleanup_status: Literal["CONFIRMED", "UNKNOWN", "FAILED"]
    source_scope: Literal["SYNTHETIC", "IMPORTED_HOST_DIAGNOSTIC"]
    execution_authorized: Literal[False] = False

    @model_validator(mode="after")
    def bindings(self):
        if (self.domain == "SYNTHETIC") != (self.collector == "p3b-synthetic-valgrind-1.0"):
            raise ValueError("synthetic/imported collector domains cannot mix")
        if (self.domain == "SYNTHETIC") != (self.source_scope == "SYNTHETIC"):
            raise ValueError("synthetic source scope cannot be relabeled")
        expected_component = "nvdisasm" if self.cve_id == "CVE-2025-23308" else "cuobjdump"
        if self.target.component != expected_component:
            raise ValueError("CVE target and actual host component conflict")
        if self.process.run_id != self.run_id:
            raise ValueError("process run differs from collection run")
        if self.process.platform_type not in {"linux", "wsl"}:
            raise ValueError("Memcheck collection requires an explicitly Linux process")
        if self.diagnostic_tool.status != "OBSERVED" or self.process.tool_identity != self.diagnostic_tool:
            raise ValueError("diagnostic executable identity differs from actual process")
        if self.target_argv[0] != self.target.executable.resolved_path:
            raise ValueError("target argv does not start with the measured target executable")
        if self.target_argv.count(self.input.file.original_path) != 1:
            raise ValueError("target argv must bind the exact input path once")
        expected = [self.diagnostic_tool.resolved_path, "--tool=memcheck", "--xml=yes",
                    "--xml-file=" + self.diagnostic_artifact.original_path] + self.target_argv
        if self.diagnostic_format == "VALGRIND_MEMCHECK_XML_V4" and self.process.argv != expected:
            raise ValueError("actual diagnostic argv differs from the registered capture profile")
        names = [self.diagnostic_artifact.artifact_file, self.stdout_artifact.artifact_file,
                 self.stderr_artifact.artifact_file]
        if len(set(names)) != 3:
            raise ValueError("diagnostic/stdout/stderr artifact names must differ")
        for name in ("stdout", "stderr"):
            item = getattr(self, name + "_artifact")
            raw = getattr(self.process, name + "_bytes")()
            if item.sha256 != digest_bytes(raw) or item.size_bytes != len(raw):
                raise ValueError("stream artifact differs from the ToolResult raw bytes")
        return self


class HostRawArtifact(LifecycleContract):
    identity: HostArtifactIdentity
    raw_b64: str

    def raw_bytes(self) -> bytes:
        return base64.b64decode(self.raw_b64, validate=True)

    @model_validator(mode="after")
    def exact_bytes(self):
        try:
            raw = self.raw_bytes()
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid original diagnostic bytes") from exc
        if len(raw) != self.identity.size_bytes or digest_bytes(raw) != self.identity.sha256:
            raise ValueError("raw artifact size or SHA-256 differs")
        return self


class HostEvidenceLocator(LifecycleContract):
    artifact_file: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    # Exact indexed XML nodes, not translated summaries or Markdown offsets.
    xml_node: str = Field(pattern=r"^/valgrindoutput(?:/[a-z_]+\[[1-9][0-9]*\])+$")


class HostStackFrame(LifecycleContract):
    instruction_pointer: str | None = None
    object_file: str | None = None
    function: str | None = None
    directory: str | None = None
    file: str | None = None
    line: int | None = Field(default=None, ge=0)
    locator: HostEvidenceLocator
    # Every populated field has its original structured node, never prose extraction.
    field_locators: dict[str, HostEvidenceLocator]


class HostMemoryObservation(LifecycleContract):
    observation_id: str
    source_kind: str
    classification: Literal["INVALID_READ", "INVALID_WRITE", "INVALID_FREE", "UNINITIALIZED_VALUE", "OTHER", "UNSUPPORTED"]
    status: Literal["OBSERVED"] = "OBSERVED"
    access_type: Literal["READ", "WRITE", "UNKNOWN"]
    # XML v4 InvalidRead/InvalidWrite alone does not distinguish OOB/UAF/heap/stack.
    memory_region: Literal["UNKNOWN"] = "UNKNOWN"
    lifetime_category: Literal["UNKNOWN"] = "UNKNOWN"
    fault_address: None = None
    access_size_bytes: None = None
    description_original: str | None = None
    description_status: Literal["UNINTERPRETED_DIAGNOSTIC_PROSE"] = "UNINTERPRETED_DIAGNOSTIC_PROSE"
    locator: HostEvidenceLocator
    kind_locator: HostEvidenceLocator
    frames: list[HostStackFrame]
    root_cause_status: Literal["UNKNOWN"] = "UNKNOWN"


class HostParserEvidence(LifecycleContract):
    evidence_schema_version: Literal["1.0"] = "1.0"
    parser_version: Literal["p3b-memcheck-xml4-parser-1.0"] = "p3b-memcheck-xml4-parser-1.0"
    collection: HostParserCollection
    collection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_artifacts: list[HostRawArtifact] = Field(min_length=3, max_length=3)
    parse_status: Literal["PARSED", "REJECTED", "UNSUPPORTED"]
    observation_status: KnowledgeStatus
    diagnostic_codes: list[str]
    observations: list[HostMemoryObservation]
    production_qualification: Literal["UNSUPPORTED"] = "UNSUPPORTED"
    qualified_for_cve_verification: Literal[False] = False
    missing_evidence: list[str]
    real_cve_verification: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"


class HostObjectiveRequirement(LifecycleContract):
    requirement_id: str = Field(pattern=r"^[a-f]_[a-z_]+$")
    category: Literal["A_EXACT_BUILD", "B_INPUT_IDENTITY_FORMAT", "C_EXECUTION_PATH", "D_MEMORY_ANOMALY", "E_MECHANISM_LOCATION", "F_ROOT_CAUSE_DIFFERENTIAL"]
    description: str = Field(min_length=1)
    status: Literal["SATISFIED", "NOT_SATISFIED", "UNKNOWN", "CONFLICT"]
    method_status: Literal["OBSERVED", "UNKNOWN", "UNIMPLEMENTED"]
    reason_code: str
    evidence_locators: list[HostEvidenceLocator]
    required: Literal[True] = True


class HostOracleAssessment(LifecycleContract):
    assessment_schema_version: Literal["1.0"] = "1.0"
    cve_id: HostCVE
    collection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    domain: Literal["SYNTHETIC", "IMPORTED_OBSERVATION"]
    requirements: list[HostObjectiveRequirement]
    eligibility: Literal["UNKNOWN"] = "UNKNOWN"
    real_cve_verification: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    verdict: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    reasons: list[str]
