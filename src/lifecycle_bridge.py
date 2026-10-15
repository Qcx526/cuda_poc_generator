"""Fixed Windows-to-WSL lifecycle dispatch, scoped cancellation and recovery."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
import time
from typing import Literal
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer, model_validator

from .execution_bridge import build_execution_worker_source, _linux_root
from .execution_worker import contract_digest
from .models.execution import ExecutionRequest, OperatorAuthorization, PreflightPolicy, request_sha256, snapshot_sha256
from .models.lifecycle import ExecutionRecord, LifecycleEvent, RemoteRecoveryCheck
from .models.platform import PlatformSnapshot
from .models.tool_result import ToolResult
from .tool_artifacts import ToolEvidenceError
from .tools.process import measure_tool_identity, run_tool
from .wsl_bridge import validate_wsl_options


class WorkerIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    pid: int = Field(gt=0)
    ppid: int = Field(ge=0)
    pgid: int = Field(gt=0)
    session_id: int = Field(gt=0)
    start_ticks: int = Field(gt=0)
    uid: int = Field(ge=0)
    gid: int = Field(ge=0)
    state: str = Field(min_length=1, max_length=1)


class LifecyclePacket(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)
    schema_version: Literal["1.0"]
    operation: Literal["EXECUTE", "STATUS", "CANCEL", "DESCRIBE_CUDA"]
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    worker_exit_code: Literal[0]
    target_environment: str | None
    worker_identity: WorkerIdentity | None
    record: ExecutionRecord | None
    recovery: RemoteRecoveryCheck | None
    worker_events: list[dict] = Field(max_length=1024)
    diagnostics: list[str]
    candidate_execution_status: Literal["NOT_EXECUTED"]
    verification_status: Literal["NOT_VERIFIED"]
    cuda_description: dict | None = None
    native_evidence: dict | None = None

    @model_serializer(mode="wrap")
    def compatible_dump(self, handler):
        data = handler(self)
        for key in ("cuda_description", "native_evidence"):
            if data[key] is None:
                data.pop(key)
        return data

    @field_validator("worker_exit_code", mode="before")
    @classmethod
    def integer_exit(cls, value):
        if type(value) is not int:
            raise ValueError("worker exit code must be an actual integer")
        return value

    @model_validator(mode="after")
    def identities(self):
        if self.cuda_description is not None:
            from .cuda_smoke_worker import CudaSmokeDescription
            description = CudaSmokeDescription.model_validate(self.cuda_description)
            if self.operation != "DESCRIBE_CUDA" or self.record is not None:
                raise ValueError("CUDA description cannot dispatch an execution")
            if description.snapshot is not None and description.snapshot.metadata.get("environment_label") not in (None, self.target_environment):
                raise ValueError("CUDA description belongs to a foreign environment")
        if self.native_evidence is not None:
            from .native_evidence import NativeEvidenceBundle
            native = NativeEvidenceBundle.model_validate(self.native_evidence)
            if self.record is None or self.record.execution_schema_version != "1.1":
                raise ValueError("native evidence requires its corresponding new execution record")
            if native.index.request_id != self.request_id or native.index.run_id != self.run_id:
                raise ValueError("native evidence belongs to another request or run")
        if self.record is not None and (self.record.request_id != self.request_id or self.record.run_id != self.run_id
                                        or self.record.target_environment != self.target_environment):
            raise ValueError("lifecycle record belongs to another task or target")
        if self.recovery is not None and (self.recovery.request_id != self.request_id or self.recovery.run_id != self.run_id
                                          or self.operation == "EXECUTE"):
            raise ValueError("independent recovery belongs to another operation or task")
        if self.record is not None and self.operation == "EXECUTE" and self.worker_identity is not None:
            if self.record.worker_pid != self.worker_identity.pid:
                raise ValueError("worker PID differs from native observation")
        if self.record is not None and self.operation == "EXECUTE" and self.worker_identity is None:
            raise ValueError("remote record requires its actual worker identity")
        if self.recovery is not None and (self.worker_identity is None
                or self.recovery.observer_pid != self.worker_identity.pid
                or self.recovery.observer_uid != self.worker_identity.uid):
            raise ValueError("recovery observer differs from the actual control worker")
        return self


def parse_lifecycle_packet(raw, *, operation, nonce, request_id, run_id, target_environment, expected_request=None):
    if not isinstance(raw, bytes) or len(raw) > 16777216:
        raise ValueError("invalid lifecycle response size")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate lifecycle response key")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("nonfinite lifecycle response")
    packet = LifecyclePacket.model_validate(json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid))
    if (packet.operation, packet.nonce, packet.request_id, packet.run_id, packet.target_environment) != (
            operation, nonce, request_id, run_id, target_environment):
        raise ValueError("lifecycle response request/run/nonce/target mismatch")
    if expected_request is not None:
        req = ExecutionRequest.model_validate(expected_request.model_dump(mode="python") if isinstance(expected_request, ExecutionRequest) else expected_request)
        if req.request_id != request_id:
            raise ValueError("expected request belongs to another task")
        record = packet.record
        if record is not None:
            if (record.request_sha256 != request_sha256(req) or record.action_id != req.fixture_id
                    or record.candidate_sha256 != req.candidate_sha256
                    or record.platform_environment_id != req.platform_environment_id
                    or record.platform_probe_id != req.platform_probe_id
                    or record.tool_record_id != req.binding.tool_record_id):
                raise ValueError("record changed its exact bound execution request")
            if record.process is not None and record.process.action_started:
                process = record.process
                if req.request_schema_version == "1.2":
                    from .cuda_registry import build_cuda_step_argv
                    if record.cuda_smoke is None or record.cuda_smoke.arch != req.cuda_toolchain.arch:
                        raise ValueError("CUDA observation changed its authorized architecture")
                    for step in record.cuda_smoke.steps:
                        role = "nvcc" if step.step_id == "compile" else step.step_id.removesuffix("_version")
                        expected_tool = req.cuda_toolchain.tools[role]
                        observed = step.process
                        if (observed.cwd != req.cwd or observed.resource_limits != req.resource_limits
                                or observed.target_environment != target_environment
                                or observed.argv != build_cuda_step_argv(step.step_id, req.cuda_toolchain.tools, req.cuda_toolchain.arch, req.cwd)
                                or (observed.tool_identity.resolved_path, observed.tool_identity.file_sha256)
                                != (expected_tool.resolved_path, expected_tool.file_sha256)):
                            raise ValueError("CUDA step changed fixed argv, actual tool, target or limits")
                elif (process.cwd != req.cwd or process.resource_limits != req.resource_limits
                        or process.tool_identity.resolved_path != req.tool_identity.resolved_path
                        or process.tool_identity.file_sha256 != req.tool_identity.file_sha256):
                    raise ValueError("native process changed tool, working directory or limits")
    return packet.model_dump(mode="json")


class TaskHandle(BaseModel):
    """Trusted operator capability; never print or accept this from an LLM."""
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    control_token: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False)
    distro: str
    user: str
    linux_python: str
    linux_project_root: str


class LifecycleDispatchError(OSError):
    """No fabricated ToolResult when the observer itself could not record one."""

    def __init__(self, result, diagnostics):
        super().__init__("Lifecycle observation or storage is incomplete")
        self.result = result
        self.record = ExecutionRecord.model_validate(result["record"])
        self.storage_status = "INCOMPLETE"
        self.report = ("# P2-B controller observation failure\n\nRequest: " + self.record.request_id
                       + "\nRun: " + self.record.run_id + "\nStatus: UNKNOWN\nStorage: INCOMPLETE\n"
                       + "\nDiagnostics: " + "; ".join(diagnostics)
                       + "\n\nRemote execution or cleanup could not be fully confirmed."
                       + "\nCandidate execution: NOT_EXECUTED. CVE verification: NOT_VERIFIED.\n")


def _transport(payload, handle, *, expected_request=None, artifact_root=None):
    handle = TaskHandle.model_validate(handle.model_dump(mode="python") if isinstance(handle, TaskHandle) else handle)
    validate_wsl_options(handle.distro, handle.linux_python, handle.user)
    root = _linux_root(handle.linux_project_root)
    if os.name != "nt":
        raise ValueError("lifecycle transport requires Windows Python")
    launcher = measure_tool_identity("wsl.exe", source="native Windows WSL launcher measurement")
    source = build_execution_worker_source(payload, linux_project_root=root, worker_entrypoint="lifecycle")
    # An unmeasurable launcher is still recorded by run_tool without launching.
    executable = launcher.resolved_path or "wsl.exe"
    diagnostics = []
    try:
        record = run_tool([executable, "--distribution", handle.distro, "--user", handle.user,
                           "--exec", handle.linux_python, "-I", "-"], timeout_seconds=(300 if expected_request is not None
                           and expected_request.request_schema_version == "1.2" else 120) if payload["operation"] == "EXECUTE"
                           else 60 if payload["operation"] == "DESCRIBE_CUDA" else 30,
                          max_output_bytes=16777216, input_bytes=source, artifact_root=artifact_root,
                          allowed_tool_identities={} if launcher.status != "OBSERVED" else {launcher.resolved_path: launcher.file_sha256},
                          command_source="fixed registered P2-B lifecycle " + payload["operation"])
    except ToolEvidenceError as exc:
        if exc.tool_result is None:
            raise
        record = ToolResult.model_validate(exc.tool_result.model_dump(mode="python"))
        diagnostics.append("LAUNCHER_EVIDENCE_WRITE_FAILED_RAW_OBSERVATION_RECOVERED")
    packet = None
    if record.ok:
        try:
            packet = parse_lifecycle_packet(record.stdout_bytes(), operation=payload["operation"], nonce=payload["nonce"],
                                             request_id=handle.request_id, run_id=handle.run_id,
                                             target_environment="wsl:" + handle.distro, expected_request=expected_request)
        except (ValueError, TypeError, KeyError):
            diagnostics.append("WSL_LIFECYCLE_PROTOCOL_INVALID")
    else:
        diagnostics.append("WSL_LAUNCHER_" + record.end_status)
    return record, packet, diagnostics


def describe_cuda_smoke_wsl(*, distro="Ubuntu-22.04", user="pocdev",
                            linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python",
                            linux_project_root, artifact_root=None):
    """Fixed read-only CUDA description; never accepts source, argv or flags."""
    handle = TaskHandle(request_id=uuid.uuid4().hex, run_id=uuid.uuid4().hex,
        control_token=uuid.uuid4().hex + uuid.uuid4().hex, distro=distro, user=user,
        linux_python=linux_python, linux_project_root=linux_project_root)
    payload = {"operation": "DESCRIBE_CUDA", "nonce": uuid.uuid4().hex,
        "request_id": handle.request_id, "run_id": handle.run_id, "control_token": handle.control_token,
        "request": None, "authorization": None, "policy": None, "snapshot": None, "tool_record": None}
    return _transport(payload, handle, artifact_root=artifact_root)


def control_task_wsl(handle, *, operation="STATUS", expected_request=None, artifact_root=None):
    if operation not in {"STATUS", "CANCEL"}:
        raise ValueError("only scoped status and cancellation are supported")
    handle = TaskHandle.model_validate(handle.model_dump(mode="python") if isinstance(handle, TaskHandle) else handle)
    payload = {"operation": operation, "nonce": uuid.uuid4().hex, "request_id": handle.request_id,
               "run_id": handle.run_id, "control_token": handle.control_token,
               "request": None, "authorization": None, "policy": None, "snapshot": None, "tool_record": None}
    return _transport(payload, handle, expected_request=expected_request, artifact_root=artifact_root)


def _unknown_record(req, auth, policy, snapshot, handle, diagnostics):
    now = datetime.now(timezone.utc).isoformat()
    return ExecutionRecord(
        execution_schema_version="1.1" if req.request_schema_version == "1.2" else "1.0",
        request_id=req.request_id, run_id=handle.run_id, request_sha256=request_sha256(req),
        authorization_sha256=None if auth is None else contract_digest(OperatorAuthorization, auth),
        policy_sha256=contract_digest(PreflightPolicy, policy), snapshot_sha256=snapshot_sha256(snapshot),
        candidate_sha256=req.candidate_sha256, platform_environment_id=req.platform_environment_id,
        platform_probe_id=req.platform_probe_id, target_environment=req.binding.target_environment,
        tool_record_id=req.binding.tool_record_id, tool_identity=req.tool_identity,
        authorization_reference=None if auth is None else auth.authorization_reference,
        operator_id=None if auth is None else auth.operator_id, action_id=req.fixture_id, status="UNKNOWN",
        events=[LifecycleEvent(sequence=0, state="CREATED", observed_at=now, source="Windows controller", reason="Task dispatch attempted"),
                LifecycleEvent(sequence=1, state="UNKNOWN", observed_at=now, source="Windows controller", reason="; ".join(diagnostics) or "Remote execution unconfirmed")],
        process=None, worker_pid=None, started_at=now, finished_at=now, diagnostics=diagnostics,
        fixture_execution_status="UNKNOWN",
        evidence_files=["stdout.bin", "stderr.bin", "lifecycle.json", "process_result.json"])


def run_task_wsl(request, authorization, policy, snapshot, tool_record, *, distro="Ubuntu-22.04", user="pocdev",
                 linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python", linux_project_root,
                 run_id=None, cancel_after_seconds=None, artifact_root=None, on_task_created=None):
    def checked(model, value):
        return model.model_validate(value.model_dump(mode="python") if isinstance(value, model) else value)
    req = checked(ExecutionRequest, request)
    auth = None if authorization is None else checked(OperatorAuthorization, authorization)
    trusted = checked(PreflightPolicy, policy)
    platform = checked(PlatformSnapshot, snapshot)
    tool = checked(ToolResult, tool_record)
    if cancel_after_seconds is not None and (type(cancel_after_seconds) not in (int, float) or not 0 <= cancel_after_seconds <= 30):
        raise ValueError("cancellation delay must be in [0,30] seconds")
    if on_task_created is not None and not callable(on_task_created):
        raise ValueError("task creation observer must be a trusted callable")
    handle = TaskHandle(request_id=req.request_id, run_id=run_id or uuid.uuid4().hex, control_token=uuid.uuid4().hex + uuid.uuid4().hex,
                        distro=distro, user=user, linux_python=linux_python, linux_project_root=linux_project_root)
    payload = {"operation": "EXECUTE", "nonce": uuid.uuid4().hex, "request_id": req.request_id, "run_id": handle.run_id,
               "control_token": handle.control_token, "request": req.model_dump(mode="json"),
               "authorization": None if auth is None else auth.model_dump(mode="json"), "policy": trusted.model_dump(mode="json"),
               "snapshot": platform.model_dump(mode="json"), "tool_record": tool.model_dump(mode="json")}
    if on_task_created is not None:
        # Gives a trusted operator/controller the scoped cancellation capability
        # before dispatch; it never grants a new execution action.
        on_task_created(handle)
    cancellation = None
    dispatch_errors = []

    def observe_control(operation):
        try:
            return control_task_wsl(handle, operation=operation, expected_request=req, artifact_root=artifact_root)
        except (OSError, ValueError) as exc:
            dispatch_errors.append(operation + "_OBSERVER_UNAVAILABLE:" + type(exc).__name__)
            return None, None, [operation + "_OBSERVER_UNAVAILABLE"]

    with ThreadPoolExecutor(max_workers=1) as executor:
        running = executor.submit(_transport, payload, handle, expected_request=req, artifact_root=artifact_root)
        if cancel_after_seconds is not None:
            deadline = time.monotonic() + cancel_after_seconds
            while not running.done() and time.monotonic() < deadline:
                time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            if not running.done():
                # A cancel can race creation of the durable lease. Retry only
                # this task's scoped control while it is still running.
                for _ in range(3):
                    cancellation = observe_control("CANCEL")
                    if cancellation[1] is not None and cancellation[1]["recovery"] is not None:
                        break
                    if running.done():
                        break
                    time.sleep(0.05)
        try:
            transport, packet, diagnostics = running.result()
        except (OSError, ValueError) as exc:
            transport, packet = None, None
            diagnostics = ["DISPATCH_OBSERVER_UNAVAILABLE:" + type(exc).__name__]
            dispatch_errors.extend(diagnostics)
    if packet is None:
        # Independent, task-scoped cancellation; never kill all of WSL.
        cancellation = observe_control("CANCEL")
    recovery_transport, recovery_packet, recovery_diagnostics = observe_control("STATUS")
    record = None if packet is None else packet["record"]
    if record is None and recovery_packet is not None:
        record = recovery_packet["record"]
    if record is None:
        record = _unknown_record(req, auth, trusted, platform, handle, diagnostics + recovery_diagnostics).model_dump(mode="json")
    result = {"record": record, "transport": None if transport is None else transport.model_dump(mode="json"), "worker_packet": packet,
              "recovery_transport": None if recovery_transport is None else recovery_transport.model_dump(mode="json"), "recovery_packet": recovery_packet,
              "effective_state": "UNKNOWN"}
    remote = ExecutionRecord.model_validate(record)
    if remote.worker_pid is None and remote.process is None and remote.status in {"REJECTED", "UNSUPPORTED", "START_FAILED"}:
        result["effective_state"] = remote.status
    elif recovery_packet is not None and recovery_packet["recovery"] is not None:
        confirmation = recovery_packet["recovery"]
        if confirmation["status"] == "CONFIRMED":
            result["effective_state"] = remote.status
        elif confirmation["status"] == "FAILED":
            result["effective_state"] = "CLEANUP_FAILED"
    # Every transport is already independently persisted by run_tool, including
    # cancellation; callers retain this reference if a final evidence write fails.
    if cancellation is not None:
        result["cancellation_transport"] = None if cancellation[0] is None else cancellation[0].model_dump(mode="json")
        result["cancellation_packet"] = cancellation[1]
    if transport is None or recovery_transport is None:
        raise LifecycleDispatchError(result, dispatch_errors + recovery_diagnostics)
    return result
