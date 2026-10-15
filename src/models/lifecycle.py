"""Strict P2-B execution observations; all outcomes remain NOT_VERIFIED."""

import base64
import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .execution import StrictContract, ExecutionResourceLimits, aware_time
from .tool_result import ToolIdentity


class LifecycleContract(StrictContract):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False,
                              revalidate_instances="always")

    @model_validator(mode="before")
    @classmethod
    def recheck_nested_models(cls, value):
        # A frozen BaseModel can still be manufactured using model_copy/update.
        # Convert existing models to their original Python values, without JSON
        # coercion, before nested Pydantic fields see them.
        def plain(item):
            if isinstance(item, BaseModel):
                return plain(item.model_dump(mode="python"))
            if isinstance(item, dict):
                return {key: plain(child) for key, child in item.items()}
            if isinstance(item, list):
                return [plain(child) for child in item]
            if isinstance(item, tuple):
                return tuple(plain(child) for child in item)
            return item
        return plain(value)


LifecycleState = Literal["CREATED", "AUTHORIZED", "PREFLIGHT_READY", "STARTING", "RUNNING",
                         "COMPLETED", "NONZERO_EXIT", "TIMED_OUT", "CANCELLED", "START_FAILED",
                         "RESOURCE_LIMIT", "CAPTURE_FAILED", "CLEANUP_FAILED", "REJECTED", "UNKNOWN", "UNSUPPORTED"]
TERMINAL_STATES = frozenset({"COMPLETED", "NONZERO_EXIT", "TIMED_OUT", "CANCELLED", "START_FAILED",
                             "RESOURCE_LIMIT", "CAPTURE_FAILED", "CLEANUP_FAILED", "REJECTED", "UNKNOWN", "UNSUPPORTED"})
_TRANSITIONS = {
    "CREATED": frozenset({"AUTHORIZED", "REJECTED", "UNKNOWN", "UNSUPPORTED"}),
    "AUTHORIZED": frozenset({"PREFLIGHT_READY", "REJECTED", "UNKNOWN", "UNSUPPORTED"}),
    "PREFLIGHT_READY": frozenset({"STARTING", "CANCELLED", "START_FAILED", "REJECTED", "UNKNOWN", "UNSUPPORTED"}),
    "STARTING": frozenset({"RUNNING", "START_FAILED", "CANCELLED", "TIMED_OUT", "RESOURCE_LIMIT", "REJECTED",
                             "CAPTURE_FAILED", "CLEANUP_FAILED", "UNKNOWN", "UNSUPPORTED"}),
    "RUNNING": TERMINAL_STATES - {"REJECTED", "UNSUPPORTED", "START_FAILED"},
}


def validate_transition(previous: str, following: str) -> None:
    if following not in _TRANSITIONS.get(previous, frozenset()):
        raise ValueError("illegal lifecycle transition: " + previous + " -> " + following)


def canonical_sha256(value) -> str:
    if hasattr(value, "model_dump"):
        value = type(value).model_validate(value.model_dump(mode="python")).model_dump(mode="json")
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


class LifecycleEvent(LifecycleContract):
    sequence: int = Field(ge=0)
    state: LifecycleState
    observed_at: str
    source: str = Field(min_length=1)
    reason: str = Field(min_length=1)

    @model_validator(mode="after")
    def timestamp(self):
        aware_time(self.observed_at)
        if not self.source.strip() or not self.reason.strip():
            raise ValueError("event source and reason must be nonblank")
        return self


def validate_events(events: list[LifecycleEvent], final_state: str) -> None:
    if not events or events[0].state != "CREATED" or events[-1].state != final_state:
        raise ValueError("lifecycle must begin CREATED and end in the recorded status")
    previous_time = None
    for index, event in enumerate(events):
        if event.sequence != index:
            raise ValueError("event sequences must be contiguous from zero")
        stamp = aware_time(event.observed_at)
        if previous_time is not None and stamp < previous_time:
            raise ValueError("lifecycle observation times must be ordered")
        if index:
            validate_transition(events[index - 1].state, event.state)
        previous_time = stamp


class ResourceObservation(LifecycleContract):
    status: Literal["ENFORCED", "NOT_STARTED", "UNKNOWN", "UNSUPPORTED"]
    wall_watchdog: bool = False
    output_cap: bool = False
    process_group: bool = False
    cpu_seconds: int | None = Field(default=None, ge=1, le=30)
    memory_bytes: int | None = Field(default=None, ge=67108864, le=1073741824)
    verification_source: str = Field(min_length=1)
    cgroup_v2_status: Literal["OBSERVED_NOT_USED", "UNAVAILABLE", "NOT_CHECKED"] = "NOT_CHECKED"
    cgroup_v2_detail: str = "not checked"
    gpu_vram_limit: Literal["NOT_IMPLEMENTED"] = "NOT_IMPLEMENTED"
    network_isolation: Literal["NOT_IMPLEMENTED"] = "NOT_IMPLEMENTED"

    @model_validator(mode="after")
    def actual_limits(self):
        if self.status == "ENFORCED" and not (self.wall_watchdog and self.output_cap and self.process_group
                                              and self.cpu_seconds is not None and self.memory_bytes is not None):
            raise ValueError("ENFORCED requires every supported bound to be observed")
        return self


class CleanupObservation(LifecycleContract):
    status: Literal["CONFIRMED", "NOT_STARTED", "UNKNOWN", "FAILED"]
    termination_method: Literal["NONE", "SIGTERM", "SIGKILL", "SIGTERM_THEN_SIGKILL", "UNKNOWN"]
    parent_reaped: bool
    group_absent: bool
    descendants_absent: bool
    checked_at: str
    source: str = Field(min_length=1)
    observed_descendant_pids: list[int] = Field(default_factory=list)
    remaining_pids: list[int] = Field(default_factory=list)
    diagnostics: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def confirmed(self):
        aware_time(self.checked_at)
        if self.status == "CONFIRMED" and not (self.parent_reaped and self.group_absent and self.descendants_absent
                                                and not self.remaining_pids):
            raise ValueError("cleanup confirmation requires reaping and independent absence observations")
        if any(type(pid) is not int or pid <= 0 for pid in self.observed_descendant_pids + self.remaining_pids):
            raise ValueError("process IDs must be positive integers")
        return self


class ProcessObservation(LifecycleContract):
    process_schema_version: Literal["1.0"] = "1.0"
    started: bool
    action_started: bool
    argv: list[str]
    cwd: str
    target_environment: str
    tool_identity: ToolIdentity
    pid: int | None = Field(default=None, gt=0)
    pgid: int | None = Field(default=None, gt=0)
    session_id: int | None = Field(default=None, gt=0)
    start_ticks: int | None = Field(default=None, gt=0)
    uid: int | None = Field(default=None, ge=0)
    gid: int | None = Field(default=None, ge=0)
    cpu_usage_seconds: float | None = Field(default=None, ge=0)
    worker_pid: int = Field(gt=0)
    started_at: str | None
    finished_at: str
    duration_seconds: float = Field(ge=0)
    returncode: int | None
    linux_signal: int | None = Field(default=None, ge=1, le=127)
    timed_out: bool
    cancelled: bool
    truncated: bool
    capture_failed: bool
    resource_limit_reason: str | None = None
    stdout_b64: str
    stderr_b64: str
    stdout_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stderr_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stdout_size_bytes: int = Field(ge=0)
    stderr_size_bytes: int = Field(ge=0)
    resource_limits: ExecutionResourceLimits
    resources: ResourceObservation
    cleanup: CleanupObservation
    diagnostics: list[str]

    def stdout_bytes(self) -> bytes:
        return base64.b64decode(self.stdout_b64, validate=True)

    def stderr_bytes(self) -> bytes:
        return base64.b64decode(self.stderr_b64, validate=True)

    @model_validator(mode="after")
    def observations_match(self):
        finish = aware_time(self.finished_at)
        if self.started_at is not None and aware_time(self.started_at) > finish:
            raise ValueError("process finish precedes start")
        for name in ("stdout", "stderr"):
            try:
                raw = getattr(self, name + "_bytes")()
            except (ValueError, TypeError) as exc:
                raise ValueError("invalid raw output encoding") from exc
            if hashlib.sha256(raw).hexdigest() != getattr(self, name + "_sha256") or len(raw) != getattr(self, name + "_size_bytes"):
                raise ValueError("raw output does not match its hash and length")
        if self.stdout_size_bytes + self.stderr_size_bytes > self.resource_limits.max_output_bytes:
            raise ValueError("retained output exceeds the aggregate cap")
        if self.started and (self.pid is None or self.started_at is None):
            raise ValueError("started process requires observed PID and start time")
        if not self.started and any(value is not None for value in (self.pid, self.pgid, self.session_id, self.start_ticks,
                                                                   self.started_at, self.returncode, self.linux_signal)):
            raise ValueError("nonstarted process cannot claim a native identity or exit")
        if self.action_started and (not self.started or self.resources.status != "ENFORCED"
                                    or self.tool_identity.status != "OBSERVED"
                                    or None in (self.pgid, self.session_id, self.start_ticks, self.uid, self.gid)):
            raise ValueError("action cannot start before all resource bounds are confirmed")
        if self.linux_signal != (-self.returncode if self.returncode is not None and self.returncode < 0 else None):
            raise ValueError("Linux signal disagrees with the observed return code")
        if self.resources.status == "ENFORCED" and (self.resources.cpu_seconds != self.resource_limits.cpu_seconds
                                                     or self.resources.memory_bytes != self.resource_limits.memory_bytes):
            raise ValueError("observed hard limits disagree with request")
        return self


class ExecutionRecord(LifecycleContract):
    execution_schema_version: Literal["1.0"] = "1.0"
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    platform_environment_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    platform_probe_id: str = Field(min_length=1)
    execution_backend: Literal["wsl"] = "wsl"
    target_environment: str = Field(min_length=1)
    tool_record_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    tool_identity: ToolIdentity
    authorization_reference: str | None
    operator_id: str | None
    action_id: str = Field(min_length=1)
    status: LifecycleState
    events: list[LifecycleEvent] = Field(min_length=1)
    process: ProcessObservation | None
    worker_pid: int | None = Field(default=None, gt=0)
    started_at: str
    finished_at: str
    diagnostics: list[str]
    evidence_files: list[str] = Field(default_factory=list)
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    fixture_execution_status: Literal["NOT_STARTED", "STARTED", "UNKNOWN"] = "NOT_STARTED"
    verification_status: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"

    @model_validator(mode="after")
    def scientific_boundaries(self):
        validate_events(self.events, self.status)
        if self.status not in TERMINAL_STATES:
            raise ValueError("persisted execution record must have a terminal state")
        if aware_time(self.finished_at) < aware_time(self.started_at):
            raise ValueError("execution finish precedes start")
        if self.events[0].observed_at != self.started_at or self.events[-1].observed_at != self.finished_at:
            raise ValueError("record timestamps must match first and last lifecycle events")
        if any(event.state == "AUTHORIZED" for event in self.events) and (
                self.authorization_sha256 is None or not self.authorization_reference or not self.operator_id):
            raise ValueError("AUTHORIZED requires the separately bound authority identity")
        process = self.process
        if process is not None:
            if process.target_environment != self.target_environment or process.tool_identity != self.tool_identity:
                raise ValueError("process target or actual tool identity disagrees with the record")
            if process.worker_pid != self.worker_pid:
                raise ValueError("process and worker PID disagree")
            if (aware_time(process.finished_at) > aware_time(self.finished_at)
                    or (process.started_at is not None and aware_time(process.started_at) < aware_time(self.started_at))):
                raise ValueError("process observations must lie inside the lifecycle observation window")
            if (self.fixture_execution_status == "STARTED") != process.action_started:
                raise ValueError("fixture execution state disagrees with the observed action gate")
            if process.started and process.cleanup.status != "CONFIRMED" and self.status not in {"CLEANUP_FAILED", "UNKNOWN"}:
                raise ValueError("unconfirmed cleanup cannot be a completed terminal result")
            if process.action_started:
                from ..registered_actions import get_registered_action
                registered = get_registered_action(self.action_id)
                expected_argv = [process.tool_identity.resolved_path, "-I", "-c", registered.source.decode("utf-8")]
                if self.candidate_sha256 != registered.sha256 or process.argv != expected_argv:
                    raise ValueError("an observed action must match exact registered bytes and fixed argv")
        elif self.fixture_execution_status == "STARTED":
            raise ValueError("a started fixed action requires process observations")
        elif any(event.state == "RUNNING" for event in self.events) and (
                self.fixture_execution_status != "UNKNOWN" or self.status not in {"UNKNOWN", "CAPTURE_FAILED", "CLEANUP_FAILED"}):
            raise ValueError("lost running-process observations require UNKNOWN fixture execution, never NOT_STARTED")
        if self.status == "COMPLETED" and (process is None or not process.action_started or process.returncode != 0
                                             or process.timed_out or process.cancelled or process.truncated
                                             or process.capture_failed or process.cleanup.status != "CONFIRMED"):
            raise ValueError("COMPLETED requires an authorized observed zero exit with complete capture and cleanup")
        if self.status == "NONZERO_EXIT" and (process is None or process.returncode in (None, 0)):
            raise ValueError("NONZERO_EXIT requires an observed nonzero exit")
        if self.status == "TIMED_OUT" and (process is None or not process.timed_out):
            raise ValueError("TIMED_OUT requires a watchdog observation")
        if self.status == "CANCELLED" and process is not None and not process.cancelled:
            raise ValueError("CANCELLED requires an observed cancellation")
        if self.status == "RESOURCE_LIMIT" and (process is None or process.resource_limit_reason is None):
            raise ValueError("RESOURCE_LIMIT requires an observed limit reason")
        if self.status == "CAPTURE_FAILED" and process is not None and not process.capture_failed:
            raise ValueError("CAPTURE_FAILED requires failed capture")
        if self.status == "CLEANUP_FAILED" and (process is None or process.cleanup.status not in {"FAILED", "UNKNOWN"}):
            raise ValueError("CLEANUP_FAILED requires failed or unconfirmed cleanup")
        if len(set(self.evidence_files)) != len(self.evidence_files):
            raise ValueError("evidence filenames must be unique")
        return self


class ArtifactReference(LifecycleContract):
    file: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,100}$")
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class RemoteRecoveryCheck(LifecycleContract):
    """A separate post-run observer; a launcher exit is never this proof."""

    recovery_schema_version: Literal["1.0"] = "1.0"
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    status: Literal["CONFIRMED", "UNKNOWN", "FAILED"]
    worker_alive: bool | None
    group_empty: bool | None
    identity_match: bool
    checked_at: str
    observer_pid: int = Field(gt=0)
    observer_uid: int = Field(ge=0)
    diagnostics: list[str]

    @model_validator(mode="after")
    def actually_observed(self):
        aware_time(self.checked_at)
        if self.status == "CONFIRMED" and not (self.identity_match and self.worker_alive is False
                                                and self.group_empty is True):
            raise ValueError("remote recovery confirmation needs exact identity, dead worker and empty group")
        return self


class EvidenceManifest(LifecycleContract):
    evidence_schema_version: Literal["1.0"] = "1.0"
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    execution_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    platform_environment_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    platform_probe_id: str = Field(min_length=1)
    tool_record_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    tool_file_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    collector_version: Literal["p2b-1.0"] = "p2b-1.0"
    remote_status: LifecycleState
    effective_status: LifecycleState
    cleanup_confirmation: Literal["CONFIRMED", "UNKNOWN", "FAILED", "NOT_STARTED"]
    artifacts: dict[str, ArtifactReference] = Field(min_length=1)
    capture_complete: bool
    truncated: bool
    protection: dict[str, str | bool]
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    verification_status: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"

    @model_validator(mode="after")
    def unique_safe_files(self):
        if any(key != artifact.file for key, artifact in self.artifacts.items()):
            raise ValueError("artifact dictionary keys must match exact safe filenames")
        if self.capture_complete and self.truncated:
            raise ValueError("truncated evidence cannot claim complete capture")
        if self.effective_status == "COMPLETED" and self.cleanup_confirmation != "CONFIRMED":
            raise ValueError("effective completion needs independent cleanup confirmation")
        return self
