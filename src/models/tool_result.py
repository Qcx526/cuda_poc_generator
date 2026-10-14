"""Byte-preserving process observations, independent of CVE verification."""

import base64
from datetime import datetime
import hashlib
import json
from pathlib import PurePosixPath, PureWindowsPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


# Recognized Windows exception/status bit patterns. A matching process exit
# code is an observation, not proof that the OS raised it (an application can
# deliberately return the same value). Unrecognized high exit codes stay ordinary
# NONZERO_EXIT; in particular -1 / 0xffffffff is not an access violation.
WINDOWS_EXCEPTION_CODES = frozenset({
    0x80000001, 0x80000002, 0x80000003, 0x80000004,
    0xc0000005, 0xc0000006, 0xc000001d, 0xc0000025, 0xc0000026,
    0xc000008c, 0xc000008d, 0xc000008e, 0xc000008f, 0xc0000090,
    0xc0000091, 0xc0000092, 0xc0000093, 0xc0000094, 0xc0000095,
    0xc0000096, 0xc00000fd, 0xc000013a, 0xc0000374, 0xc0000409,
})


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_argv(argv: list[str]) -> str:
    return digest_bytes(json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


class ToolResourceLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)

    timeout_seconds: float = Field(gt=0, le=300)
    max_output_bytes: int = Field(ge=1, le=16777216)
    termination_scope: Literal["POSIX_PROCESS_GROUP", "WINDOWS_DIRECT_CHILD"]
    memory_bytes: None = None
    cpu_seconds: None = None
    memory_limit_status: Literal["NOT_ENFORCED"] = "NOT_ENFORCED"
    cpu_limit_status: Literal["NOT_ENFORCED"] = "NOT_ENFORCED"


class CommandIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    source: str = Field(min_length=1)
    argv_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def nonblank(self):
        if not self.source.strip():
            raise ValueError("command source must not be blank")
        return self


class ToolIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    requested_executable: str = Field(min_length=1)
    resolved_path: str | None
    status: Literal["OBSERVED", "UNKNOWN"]
    file_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source: str = Field(min_length=1)

    @model_validator(mode="after")
    def identity_state(self):
        if not self.source.strip():
            raise ValueError("tool source must not be blank")
        if self.status == "OBSERVED" and (self.resolved_path is None or self.file_sha256 is None):
            raise ValueError("observed executable identity requires a resolved file and measured digest")
        if self.status == "UNKNOWN" and self.file_sha256 is not None:
            raise ValueError("unknown executable identity cannot contain a measured digest")
        if self.resolved_path is not None and not (
                PurePosixPath(self.resolved_path).is_absolute() or PureWindowsPath(self.resolved_path).is_absolute()):
            raise ValueError("resolved tool identity path must be absolute")
        return self


class ToolDiagnostic(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    code: str = Field(min_length=1)
    message: str = Field(min_length=1)


EndStatus = Literal["NORMAL_EXIT", "NONZERO_EXIT", "TIMED_OUT", "START_FAILED",
                    "SIGNAL_TERMINATED", "WINDOWS_EXCEPTION", "OUTPUT_LIMIT", "CAPTURE_FAILED"]


def classify_returncode(returncode: int | None, platform_type: str, *, timed_out=False,
                        truncated=False, capture_failed=False, started=True):
    """Decode local OS return codes with explicit, ordered capture outcomes."""
    if platform_type not in {"windows", "linux", "wsl"}:
        raise ValueError("unsupported process platform")
    linux_signal = None
    windows_exception_code = None
    if returncode is not None:
        if platform_type != "windows" and returncode < 0:
            linux_signal = -returncode
        elif platform_type == "windows" and (returncode & 0xffffffff) in WINDOWS_EXCEPTION_CODES:
            windows_exception_code = returncode & 0xffffffff
    if not started:
        status = "START_FAILED"
    elif timed_out:
        status = "TIMED_OUT"
    elif truncated:
        status = "OUTPUT_LIMIT"
    elif capture_failed or returncode is None:
        status = "CAPTURE_FAILED"
    elif linux_signal is not None:
        status = "SIGNAL_TERMINATED"
    elif windows_exception_code is not None:
        status = "WINDOWS_EXCEPTION"
    elif returncode == 0:
        status = "NORMAL_EXIT"
    else:
        status = "NONZERO_EXIT"
    return status, linux_signal, windows_exception_code


class ToolResult(BaseModel):
    """Captured process evidence; success says nothing about a target vulnerability.

    Digests cover exactly the retained bytes. When truncated, neither the digest
    nor the saved files claim to cover the uncaptured output suffix.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)

    schema_version: Literal["1.0"] = "1.0"
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    record_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    argv: list[str] = Field(min_length=1)
    cwd: str = Field(min_length=1)
    target_environment: str = Field(min_length=1)
    platform_type: Literal["windows", "linux", "wsl"]
    start_status: Literal["STARTED", "START_FAILED"]
    end_status: EndStatus
    returncode: int | None
    linux_signal: int | None = Field(default=None, ge=1, le=127)
    windows_exception_code: int | None = Field(default=None, ge=2147483648, le=4294967295)
    timed_out: bool
    truncated: bool
    capture_failed: bool = False
    started_at: str
    finished_at: str
    duration_seconds: float = Field(ge=0)
    resource_limits: ToolResourceLimits
    stdout_b64: str
    stderr_b64: str
    stdout_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stderr_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stdin_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    stdin_size_bytes: int = Field(default=0, ge=0)
    command_identity: CommandIdentity
    tool_identity: ToolIdentity
    diagnostics: list[ToolDiagnostic]
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    verification_status: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    evidence_directory: str

    def stdout_bytes(self) -> bytes:
        return base64.b64decode(self.stdout_b64, validate=True)

    def stderr_bytes(self) -> bytes:
        return base64.b64decode(self.stderr_b64, validate=True)

    @property
    def ok(self) -> bool:
        return self.end_status == "NORMAL_EXIT"

    @model_validator(mode="after")
    def validate_observation(self):
        if not self.argv[0] or any("\0" in value for value in self.argv):
            raise ValueError("argv must contain a nonempty executable and no NUL bytes")
        for name, value in (("cwd", self.cwd), ("resolved executable", self.tool_identity.resolved_path)):
            if value is None:
                continue
            if self.platform_type == "windows":
                if not PureWindowsPath(value).is_absolute():
                    raise ValueError(name + " must be an absolute Windows path")
            elif not PurePosixPath(value).is_absolute() or "\\" in value or PureWindowsPath(value).drive:
                raise ValueError(name + " must be an absolute POSIX path without Windows drive syntax")
        if self.tool_identity.resolved_path is not None and self.argv[0] != self.tool_identity.resolved_path:
            raise ValueError("actual argv executable must match the recorded resolved tool identity")
        if self.command_identity.argv_sha256 != digest_argv(self.argv):
            raise ValueError("recorded argv does not match command identity")
        for name in ("stdout", "stderr"):
            try:
                raw = base64.b64decode(getattr(self, name + "_b64"), validate=True)
            except (ValueError, TypeError) as exc:
                raise ValueError("invalid raw output encoding") from exc
            if digest_bytes(raw) != getattr(self, name + "_sha256"):
                raise ValueError("raw output digest mismatch")
        if len(self.stdout_bytes()) + len(self.stderr_bytes()) > self.resource_limits.max_output_bytes:
            raise ValueError("captured output exceeds declared aggregate limit")
        if self.start_status == "START_FAILED":
            if self.end_status != "START_FAILED" or self.returncode is not None or self.timed_out or self.truncated or self.capture_failed:
                raise ValueError("start failure cannot have a process exit code")
        elif self.end_status == "START_FAILED":
            raise ValueError("started process cannot be classified as a start failure")
        if self.linux_signal is not None and (
                self.platform_type == "windows" or self.returncode != -self.linux_signal):
            raise ValueError("signal must match a Linux negative process return code")
        if self.windows_exception_code is not None and (
                self.platform_type != "windows" or self.returncode is None
                or (self.returncode & 0xffffffff) != self.windows_exception_code
                or self.windows_exception_code not in WINDOWS_EXCEPTION_CODES):
            raise ValueError("Windows exception code must match the Windows process return code")
        if self.returncode is not None:
            lower, upper = (-2147483648, 4294967295) if self.platform_type == "windows" else (-127, 255)
            if not lower <= self.returncode <= upper:
                raise ValueError("return code is outside the recorded OS process range")
        if self.start_status == "STARTED" and self.returncode is None and not self.capture_failed:
            raise ValueError("started process with unknown return code must record capture failure")
        expected = classify_returncode(self.returncode, self.platform_type, timed_out=self.timed_out,
                                       truncated=self.truncated, capture_failed=self.capture_failed,
                                       started=self.start_status == "STARTED")
        if (self.end_status, self.linux_signal, self.windows_exception_code) != expected:
            raise ValueError("process status or signal/exception metadata contradicts the observed OS return code")
        expected_scope = "WINDOWS_DIRECT_CHILD" if self.platform_type == "windows" else "POSIX_PROCESS_GROUP"
        if self.resource_limits.termination_scope != expected_scope:
            raise ValueError("termination scope contradicts process platform")
        if self.end_status == "NORMAL_EXIT" and (self.returncode != 0 or self.timed_out or self.truncated):
            raise ValueError("normal exit requires zero return code and complete bounded capture")
        if self.end_status == "NONZERO_EXIT" and (
                self.returncode is None or self.returncode == 0 or self.linux_signal is not None
                or self.windows_exception_code is not None or self.timed_out or self.truncated):
            raise ValueError("nonzero exit must be distinct from timeout, signal and exception")
        if self.end_status == "TIMED_OUT" and not self.timed_out:
            raise ValueError("timeout result must record timed_out")
        if self.end_status == "OUTPUT_LIMIT" and not self.truncated:
            raise ValueError("output limit result must record truncation")
        if self.end_status == "SIGNAL_TERMINATED" and self.linux_signal is None:
            raise ValueError("signal termination requires an observed signal number")
        if self.end_status == "WINDOWS_EXCEPTION" and self.windows_exception_code is None:
            raise ValueError("Windows exception requires an observed exception code")
        times = [datetime.fromisoformat(value) for value in (self.started_at, self.finished_at)]
        if any(value.tzinfo is None for value in times) or times[1] < times[0]:
            raise ValueError("tool timestamps must be timezone aware and ordered")
        if self.record_id != compute_record_id(self.model_dump(mode="json")):
            raise ValueError("tool result content identity mismatch")
        return self


def compute_record_id(payload: dict) -> str:
    content = {key: value for key, value in payload.items() if key not in {"record_id", "evidence_directory"}}
    encoded = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "sha256:" + digest_bytes(encoded.encode("utf-8"))


def seal_tool_result(payload: dict) -> ToolResult:
    """Seal newly collected observations; never repair loaded historical records."""
    # Normalize omitted model defaults before computing the canonical identity.
    defaults = {"schema_version": "1.0", "linux_signal": None, "windows_exception_code": None,
                "stdin_sha256": None, "stdin_size_bytes": 0,
                "capture_failed": False,
                "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    value = {**defaults, **payload}
    # Pydantic legitimately supplies nested defaults and represents numeric
    # float fields canonically. Hash exactly that normalized representation;
    # loaded records still undergo ordinary validation without re-sealing.
    value["resource_limits"] = ToolResourceLimits.model_validate(value["resource_limits"]).model_dump(mode="json")
    value["tool_identity"] = ToolIdentity.model_validate(value["tool_identity"]).model_dump(mode="json")
    value["command_identity"] = CommandIdentity.model_validate(value["command_identity"]).model_dump(mode="json")
    value["diagnostics"] = [ToolDiagnostic.model_validate(item).model_dump(mode="json") for item in value["diagnostics"]]
    if type(value["duration_seconds"]) in (int, float):
        value["duration_seconds"] = float(value["duration_seconds"])
    value["record_id"] = compute_record_id(value)
    return ToolResult.model_validate(value)
