"""Versioned, read-only CPU diagnostic capability observations."""

import re
from typing import Literal

from pydantic import Field, JsonValue, model_validator

from .lifecycle import LifecycleContract, canonical_sha256
from .tool_result import ToolIdentity, ToolResult


class DiagnosticTarget(LifecycleContract):
    platform_type: Literal["linux", "wsl"]
    environment_label: str
    wsl_distribution: str | None
    kernel: str = Field(min_length=1)
    architecture: str = Field(min_length=1)
    boot_id_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    diagnostic_environment_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @model_validator(mode="after")
    def identity(self):
        if self.platform_type == "wsl":
            if self.wsl_distribution is None or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,127}", self.wsl_distribution):
                raise ValueError("WSL diagnostic target requires an observed distribution")
            if self.environment_label != "wsl:" + self.wsl_distribution or "microsoft" not in self.kernel.lower():
                raise ValueError("WSL target label/kernel disagree")
        elif self.environment_label != "local" or self.wsl_distribution is not None:
            raise ValueError("plain Linux cannot claim a WSL label")
        value = self.model_dump(mode="json", exclude={"diagnostic_environment_id"})
        if self.diagnostic_environment_id != "sha256:" + canonical_sha256(value):
            raise ValueError("diagnostic target content identity mismatch")
        return self


class DiagnosticToolCapability(LifecycleContract):
    tool_id: Literal["valgrind", "gdb", "cuobjdump", "nvdisasm"]
    identity: ToolIdentity
    identity_after: ToolIdentity | None
    process: ToolResult | None
    version: str | None
    version_status: Literal["OBSERVED", "UNKNOWN", "NOT_CHECKED"]
    diagnostic_effectiveness: Literal["NOT_CHECKED"] = "NOT_CHECKED"

    @model_validator(mode="after")
    def fixed_query(self):
        if self.identity.requested_executable != self.tool_id:
            raise ValueError("diagnostic executable role mismatch")
        if self.process is not None:
            if self.process.argv != [self.identity.resolved_path, "--version"]:
                raise ValueError("capability probe accepts only the fixed --version query")
            if self.process.tool_identity != self.identity:
                raise ValueError("capability process executable identity mismatch")
        elif self.identity.status == "OBSERVED" or self.identity_after is not None:
            raise ValueError("discovered diagnostic tool requires a version process record")
        if self.version_status == "OBSERVED":
            if self.version is None or not self.version.strip() or self.process is None or not self.process.ok:
                raise ValueError("observed version requires a successful captured query")
            if self.identity_after != self.identity or self.process.truncated or self.process.capture_failed:
                raise ValueError("changed identity or incomplete capture cannot establish a version")
        elif self.version is not None:
            raise ValueError("unobserved version must remain null")
        return self


class DiagnosticFact(LifecycleContract):
    status: Literal["OBSERVED", "DOCUMENTED", "INFERRED", "UNKNOWN", "UNSUPPORTED", "NOT_CHECKED"]
    value: JsonValue
    reason_zh: str = Field(min_length=1)
    sources: list[str]

    @model_validator(mode="after")
    def state(self):
        if self.status in {"UNKNOWN", "UNSUPPORTED", "NOT_CHECKED"} and self.value is not None:
            raise ValueError("unknown capability must have a null value")
        if self.status in {"OBSERVED", "DOCUMENTED", "INFERRED"} and (self.value is None or not self.sources):
            raise ValueError("known capability needs its source")
        return self


class HostDiagnosticsProbe(LifecycleContract):
    probe_schema_version: Literal["1.0"] = "1.0"
    probe_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    report_locale: Literal["zh-CN"] = "zh-CN"
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    domain: Literal["READ_ONLY_CAPABILITY"] = "READ_ONLY_CAPABILITY"
    backend: Literal["local", "wsl"]
    requested_environment: str
    worker_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: str
    status: Literal["COMPLETE", "PARTIAL", "FAILED"]
    target: DiagnosticTarget | None
    tools: list[DiagnosticToolCapability]
    capabilities: dict[str, DiagnosticFact]
    launcher: ToolResult | None
    worker_packet_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    diagnostics_zh: list[str]
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    verification_status: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"

    @model_validator(mode="after")
    def bindings(self):
        from .execution import aware_time
        aware_time(self.observed_at)
        names = [tool.tool_id for tool in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("duplicate diagnostic capability tool")
        if self.target is None:
            if self.status != "FAILED" or self.tools:
                raise ValueError("missing target cannot establish capabilities")
        else:
            if self.launcher is None or not self.launcher.ok or self.worker_packet_sha256 is None:
                raise ValueError("observed diagnostic target requires its complete successful transport")
            if self.launcher.stdout_sha256 != self.worker_packet_sha256:
                raise ValueError("diagnostic worker packet is not the captured launcher output")
            if set(names) != {"valgrind", "gdb", "cuobjdump", "nvdisasm"}:
                raise ValueError("validated target requires the fixed capability registry")
            if self.backend == "wsl" and (self.target.platform_type != "wsl" or self.target.environment_label != self.requested_environment):
                raise ValueError("diagnostic response belongs to another WSL environment")
            for tool in self.tools:
                if tool.process and (tool.process.target_environment != self.target.environment_label or tool.process.platform_type != self.target.platform_type):
                    raise ValueError("tool query belongs to another observed target")
        if self.record_sha256 != canonical_sha256(self.model_dump(mode="json", exclude={"record_sha256"})):
            raise ValueError("diagnostic probe content identity mismatch")
        return self
