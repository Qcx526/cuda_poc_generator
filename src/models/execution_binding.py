"""P2 identity preparation only: no command dispatch or execution authorization."""

import hashlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .platform import PlatformSnapshot
from .tool_result import ToolResult


class CandidateToolBinding(BaseModel):
    """References exact candidate bytes, a validated snapshot and a tool record.

    A consistent binding does not grant permission, establish current readiness,
    attest hardware/software authenticity, or verify a vulnerability.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    platform_environment_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    platform_probe_id: str = Field(min_length=1)
    execution_backend: Literal["local", "wsl"]
    platform_type: Literal["windows", "linux", "wsl"]
    target_environment: str = Field(min_length=1)
    tool_record_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    tool_run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    tool_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_resolved_path: str = Field(min_length=1)
    tool_command_argv_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def nonblank(self):
        if any(not value.strip() for value in (self.platform_probe_id, self.target_environment, self.tool_resolved_path)):
            raise ValueError("binding identifiers and path must not be blank")
        if self.execution_backend == "wsl" and self.platform_type != "wsl":
            raise ValueError("WSL binding requires a WSL snapshot")
        return self


def bind_candidate_to_tool(candidate_bytes: bytes, snapshot: PlatformSnapshot | dict,
                           tool_result: ToolResult | dict, *, expected_probe_id: str,
                           expected_tool_record_id: str) -> CandidateToolBinding:
    """Validate supplied records and return references without executing anything.

    The caller must supply independently selected expected identities. Freshness,
    authorization, rehashing at execution time and isolation belong to P2.
    """
    if not isinstance(candidate_bytes, bytes) or not candidate_bytes:
        raise ValueError("candidate bytes must be a nonempty byte string")
    platform = PlatformSnapshot.model_validate(snapshot.model_dump(mode="python") if
                                               isinstance(snapshot, PlatformSnapshot) else snapshot)
    tool = ToolResult.model_validate(tool_result.model_dump(mode="python") if
                                    isinstance(tool_result, ToolResult) else tool_result)
    if platform.metadata["probe_id"] != expected_probe_id or tool.record_id != expected_tool_record_id:
        raise ValueError("binding records do not match expected identities")
    if (tool.platform_type != platform.platform_type or
            tool.target_environment != platform.metadata["environment_label"]):
        raise ValueError("tool record and platform snapshot describe different environments")
    if tool.tool_identity.status != "OBSERVED":
        raise ValueError("binding requires a measured executable identity")
    return CandidateToolBinding(
        candidate_sha256=hashlib.sha256(candidate_bytes).hexdigest(),
        platform_environment_id=platform.environment_id,
        platform_probe_id=expected_probe_id, execution_backend=platform.execution_backend,
        platform_type=platform.platform_type, target_environment=tool.target_environment,
        tool_record_id=tool.record_id, tool_run_id=tool.run_id,
        tool_file_sha256=tool.tool_identity.file_sha256,
        tool_resolved_path=tool.tool_identity.resolved_path,
        tool_command_argv_sha256=tool.command_identity.argv_sha256,
    )
