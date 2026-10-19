"""WSL worker for one received copy of the reviewed P2-B normal fixture."""

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import uuid

from .execution_preflight import target_boot_id
from .execution_worker import _snapshot, resource_capabilities
from .lifecycle_process import describe_process_identity, _group_members, _same_process
from .memcheck_process import json_bytes, read_regular, write_new
from .models.execution import ExecutionResourceLimits
from .models.lifecycle import ArtifactReference, LifecycleEvent, RemoteRecoveryCheck, canonical_sha256
from .models.staged_fixture import (StagedFixtureAuthorization, StagedFixtureDescription,
    StagedFixturePolicy, StagedFixtureRecord, StagedFixtureRequest, StagedSourceIdentity,
    validate_staged_binding)
from .staged_fixture_process import inspect_staged_fixture, run_staged_fixture
from .tools.process import canonical_target_environment, current_platform_type, measure_tool_identity


def task_root():
    return Path.home() / ".local" / "state" / "cuda-poc-generator" / "staged_fixture_tasks"


def _protected_root():
    root = task_root()
    if any(path.is_symlink() for path in (root, *root.parents)):
        raise ValueError("fixed staged task root contains a symbolic link")
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = root.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("fixed staged task root is not private")
    return root


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _replace(path, value):
    temporary = path.with_name("." + path.name + ".new")
    write_new(temporary, json_bytes(value))
    os.replace(temporary, path)


def describe(receipt, receipt_sha256):
    from .candidate_adapter import CandidateTransferReceipt

    submitted = CandidateTransferReceipt.model_validate(receipt)
    root = _protected_root()
    target = canonical_target_environment()
    data = dict(description_id=uuid.uuid4().hex, status="UNSUPPORTED", target_environment=target,
        snapshot=None, native_task_root=str(root), receipt=submitted, source_identity=None,
        tool_identity=None, target_boot_id=target_boot_id(), observed_monotonic_ns=time.monotonic_ns(),
        resource_support=resource_capabilities(), diagnostics=[])
    try:
        if current_platform_type() != "wsl":
            raise ValueError("received-file experiment requires WSL")
        identity = StagedSourceIdentity.model_validate(inspect_staged_fixture(submitted, receipt_sha256))
        tool = measure_tool_identity(sys.executable, source="fixed staged harmless WSL Python identity")
        support = resource_capabilities(ExecutionResourceLimits(
            wall_time_seconds=10, cpu_seconds=2, memory_bytes=268435456, max_output_bytes=65536))
        if tool.status != "OBSERVED" or support["status"] != "OBSERVED":
            raise ValueError("fixed Python or required native resource mechanisms unavailable")
        snapshot = _snapshot(target)
        if snapshot.probe_status == "FAILED":
            raise ValueError("target platform probe failed")
        data.update(status="DESCRIBED", source_identity=identity, tool_identity=tool,
                    snapshot=snapshot, resource_support=support,
                    observed_monotonic_ns=time.monotonic_ns())
    except (OSError, ValueError) as exc:
        data.update(status="UNSUPPORTED", diagnostics=[type(exc).__name__ + ":" + str(exc)])
    return StagedFixtureDescription.model_validate(data)


def preflight_staged_fixture(req, auth, policy, desc):
    """Fail closed before spawning; all compared values come from the fixed worker."""
    req = StagedFixtureRequest.model_validate(req)
    auth = None if auth is None else StagedFixtureAuthorization.model_validate(auth)
    policy = StagedFixturePolicy.model_validate(policy)
    desc = StagedFixtureDescription.model_validate(desc)
    failures = []
    if auth is None:
        failures.append("OPERATOR_AUTHORIZATION_MISSING")
    elif ((auth.request_id, auth.run_id, auth.transfer_id, auth.receipt_sha256,
            auth.source_sha256, auth.request_sha256, auth.authorization_reference,
            auth.target_boot_id) != (req.request_id, req.run_id, req.transfer_id,
                req.receipt_sha256, req.source_identity.source_sha256, canonical_sha256(req),
                req.authorization_reference, req.target_boot_id)
            or auth.operator_id not in policy.allowed_operator_ids
            or auth.authorization_reference not in policy.allowed_authorization_references):
        failures.append("OPERATOR_AUTHORIZATION_IDENTITY_CONFLICT")
    if (desc.status != "DESCRIBED" or desc.snapshot is None or desc.source_identity is None
            or desc.tool_identity is None or desc.resource_support.status != "OBSERVED"):
        failures.append("TARGET_DESCRIPTION_INCOMPLETE")
    if (policy.request_sha256 != canonical_sha256(req)
            or policy.description_sha256 != canonical_sha256(desc)
            or req.description_sha256 != canonical_sha256(desc)
            or policy.native_task_root != str(_protected_root())
            or policy.transfer_id != req.transfer_id
            or policy.receipt_sha256 != req.receipt_sha256
            or policy.source_sha256 != req.source_identity.source_sha256
            or policy.resource_limits != req.resource_limits):
        failures.append("INDEPENDENT_POLICY_SCOPE_CONFLICT")
    if (desc.source_identity != req.source_identity or desc.receipt.transfer_id != req.transfer_id
            or desc.receipt.request_id != req.transfer_request_id
            or desc.receipt.source_sha256 != req.source_identity.source_sha256
            or desc.tool_identity != req.tool_identity):
        failures.append("STAGED_SOURCE_OR_TOOL_DESCRIPTION_CONFLICT")
    if (desc.snapshot is None or canonical_sha256(desc.snapshot) != req.snapshot_sha256
            or desc.snapshot.environment_id != req.platform_environment_id
            or desc.snapshot.metadata.get("probe_id") != req.platform_probe_id
            or desc.target_environment != req.target_environment
            or canonical_target_environment() != req.target_environment):
        failures.append("TARGET_PLATFORM_IDENTITY_CONFLICT")
    now = time.monotonic_ns()
    if (target_boot_id() != req.target_boot_id or desc.target_boot_id != req.target_boot_id
            or desc.observed_monotonic_ns != req.observed_monotonic_ns
            or now < req.observed_monotonic_ns
            or now - req.observed_monotonic_ns > policy.max_description_age_seconds * 1000000000):
        failures.append("TARGET_BOOT_OR_DESCRIPTION_EXPIRED")
    if auth is not None and not (auth.not_before_monotonic_ns <= now < auth.expires_monotonic_ns):
        failures.append("OPERATOR_AUTHORIZATION_EXPIRED")
    actual_tool = measure_tool_identity(sys.executable, source="fixed staged preflight Python remeasurement")
    if (actual_tool.status != "OBSERVED"
            or actual_tool.resolved_path != req.tool_identity.resolved_path
            or actual_tool.file_sha256 != req.tool_identity.file_sha256
            or policy.allowed_tool_path != actual_tool.resolved_path
            or policy.allowed_tool_sha256 != actual_tool.file_sha256):
        failures.append("PYTHON_EXECUTABLE_IDENTITY_CHANGED")
    support = resource_capabilities(req.resource_limits)
    if support["status"] != "OBSERVED":
        failures.append("RESOURCE_LIMITS_UNSUPPORTED")
    try:
        measured = StagedSourceIdentity.model_validate(inspect_staged_fixture(desc.receipt, req.receipt_sha256))
        if measured != req.source_identity:
            failures.append("STAGED_RECEIPT_OR_INODE_CHANGED")
    except (OSError, ValueError) as exc:
        failures.append("STAGED_RECEIPT_OR_SOURCE_UNREADABLE:" + type(exc).__name__)
    return {"status": "READY" if not failures else "REJECTED", "diagnostics": failures,
            "checked_at": _utc(), "target_boot_id": target_boot_id(), "checked_monotonic_ns": now}


def execute(payload):
    req = StagedFixtureRequest.model_validate(payload["request"])
    auth = None if payload["authorization"] is None else StagedFixtureAuthorization.model_validate(payload["authorization"])
    policy = StagedFixturePolicy.model_validate(payload["policy"])
    desc = StagedFixtureDescription.model_validate(payload["description"])
    if (payload["request_id"], payload["run_id"]) != (req.request_id, req.run_id):
        raise ValueError("worker envelope and request identity conflict")
    folder = _protected_root() / req.run_id
    folder.mkdir(mode=0o700, exist_ok=False)
    worker_identity = describe_process_identity(os.getpid())
    lease = {"request_id": req.request_id, "run_id": req.run_id, "nonce": payload["nonce"],
             "control_token_sha256": hashlib.sha256(payload["control_token"].encode("ascii")).hexdigest(),
             "target_environment": canonical_target_environment(), "target_boot_id": target_boot_id(),
             "worker": worker_identity, "groups": [], "spawn_pending": False}
    write_new(folder / "lease.json", json_bytes(lease))
    for name, value in (("request.json", req), ("authorization.json", auth),
                        ("policy.json", policy), ("description.json", desc)):
        write_new(folder / name, json_bytes(None if value is None else value.model_dump(mode="json")))
    events = []
    def event(state, reason):
        events.append(LifecycleEvent(sequence=len(events), state=state, observed_at=_utc(),
            source="fixed staged WSL worker", reason=reason, monotonic_ns=time.monotonic_ns()))
    event("CREATED", "收到固定无害文件执行请求")
    preflight = preflight_staged_fixture(req, auth, policy, desc)
    write_new(folder / "preflight.json", json_bytes(preflight))
    process = outcome = None
    diagnostics = list(preflight["diagnostics"])
    state = preflight["status"]
    if state == "READY":
        event("AUTHORIZED", "独立操作员授权和固定源文件身份已匹配")
        event("PREFLIGHT_READY", "目标、工具、资源和私有目录已通过只读前置检查")
        def observed(kind, detail):
            if kind == "STARTING":
                lease["spawn_pending"] = True
                _replace(folder / "lease.json", lease)
                if events[-1].state == "PREFLIGHT_READY":
                    event("STARTING", "正在启动固定接收文件的受限 Python 进程")
            elif kind == "WORKER_CHILD_STARTED":
                lease["groups"].append({key: detail[key] for key in (
                    "pid", "ppid", "pgid", "session_id", "start_ticks", "uid", "gid")})
                lease["spawn_pending"] = False
                _replace(folder / "lease.json", lease)
            elif kind == "RUNNING" and events[-1].state == "STARTING":
                event("RUNNING", "已核对文件描述符、源码 SHA-256 和资源约束并放行")
            journal = folder / "worker_events.jsonl"
            fd = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, json_bytes({"event": kind, "observed_at": _utc(), "detail": detail}))
                os.fsync(fd)
            finally:
                os.close(fd)
        try:
            outcome = run_staged_fixture(desc.receipt, req.receipt_sha256, req.resource_limits,
                expected_source_identity=req.source_identity.model_dump(mode="json"),
                expected_tool=req.tool_identity, cwd=Path(req.source_identity.source_path).parent,
                target_environment=req.target_environment, request_id=req.request_id, run_id=req.run_id,
                nonce=payload["nonce"], cancellation_file=folder / "cancel.json", on_event=observed)
            process = outcome.process
            state = outcome.state
            diagnostics += process.diagnostics
        except (OSError, ValueError) as exc:
            state = "UNKNOWN" if events[-1].state in {"STARTING", "RUNNING"} else "START_FAILED"
            diagnostics.append("FIXED_STAGED_PROCESS_ERROR:" + type(exc).__name__ + ":" + str(exc))
    if state == "READY":
        state = "UNKNOWN"
        diagnostics.append("PROCESS_RESULT_MISSING")
    if state == "COMPLETED" and (outcome is None or outcome.observation is None):
        state = "CAPTURE_FAILED"
        diagnostics.append("STAGED_FD_OBSERVATION_MISSING")
    fixed_output_observed = (process is not None and process.action_started
        and process.stdout_bytes() == b"P2-B harmless normal exit\n")
    if state == "COMPLETED" and not fixed_output_observed:
        state = "CAPTURE_FAILED"
        diagnostics.append("FIXED_SOURCE_OUTPUT_PROOF_MISSING")
    event(state, "; ".join(diagnostics) if diagnostics else "保留真实退出状态、原始输出及回收结果")
    raw = {}
    if process is not None:
        raw["stdout.bin"] = process.stdout_bytes()
        raw["stderr.bin"] = process.stderr_bytes()
        raw["process_result.json"] = json_bytes(process.model_dump(mode="json"))
    if outcome is not None and outcome.observation is not None:
        raw["staged_observation.json"] = json_bytes(outcome.observation)
    if (folder / "worker_events.jsonl").exists():
        raw["worker_events.jsonl"] = read_regular(folder / "worker_events.jsonl", 4194304)
    record = StagedFixtureRecord(request_id=req.request_id, run_id=req.run_id,
        transfer_id=req.transfer_id, receipt_sha256=req.receipt_sha256, source_identity=req.source_identity,
        request_sha256=canonical_sha256(req), authorization_sha256=None if auth is None else canonical_sha256(auth),
        policy_sha256=canonical_sha256(policy), description_sha256=canonical_sha256(desc),
        snapshot_sha256=req.snapshot_sha256, platform_environment_id=req.platform_environment_id,
        platform_probe_id=req.platform_probe_id, target_environment=req.target_environment,
        tool_identity=req.tool_identity, worker_identity=worker_identity, status=state,
        events=events, process=process, staged_observation=None if outcome is None else outcome.observation,
        artifacts={name: ArtifactReference(file=name, size_bytes=len(value), sha256=hashlib.sha256(value).hexdigest())
                   for name, value in raw.items()}, diagnostics=diagnostics,
        fixed_source_execution_status=("EXECUTED" if fixed_output_observed else
            "UNKNOWN" if process is not None and process.action_started else "NOT_EXECUTED"))
    (folder / "evidence").mkdir(mode=0o700, exist_ok=False)
    for name, value in raw.items():
        write_new(folder / "evidence" / name, value)
    write_new(folder / "execution_record.json", json_bytes(record.model_dump(mode="json")))
    return record.model_dump(mode="json"), {name: base64.b64encode(value).decode("ascii") for name, value in raw.items()}


def control(payload):
    folder = _protected_root() / payload["run_id"]
    lease = json.loads(read_regular(folder / "lease.json", 131072))
    if (lease["request_id"] != payload["request_id"] or lease["run_id"] != payload["run_id"]
            or lease["control_token_sha256"] != hashlib.sha256(payload["control_token"].encode()).hexdigest()
            or lease["target_environment"] != canonical_target_environment()
            or lease["target_boot_id"] != target_boot_id()
            or lease["worker"]["uid"] != os.getuid()):
        raise ValueError("fixed staged control identity conflict")
    if payload["operation"] == "CANCEL" and not (folder / "execution_record.json").exists():
        cancel = {"request_id": lease["request_id"], "run_id": lease["run_id"],
                  "nonce": lease["nonce"], "action": "CANCEL"}
        try:
            write_new(folder / "cancel.json", json_bytes(cancel))
        except FileExistsError:
            if json.loads(read_regular(folder / "cancel.json", 1024)) != cancel:
                raise ValueError("conflicting cancellation record")
    try:
        worker_alive = _same_process(describe_process_identity(lease["worker"]["pid"]), lease["worker"])
    except (FileNotFoundError, ProcessLookupError):
        worker_alive = False
    remaining = sorted({item["pid"] for group in lease["groups"] for item in
        _group_members(group["pgid"], group["session_id"])})
    unknown = bool(lease["spawn_pending"] or worker_alive)
    recovery = RemoteRecoveryCheck(request_id=lease["request_id"], run_id=lease["run_id"],
        status="UNKNOWN" if unknown else "FAILED" if remaining else "CONFIRMED",
        worker_alive=worker_alive, group_empty=None if lease["spawn_pending"] else not remaining,
        identity_match=True, checked_at=_utc(), observer_pid=os.getpid(), observer_uid=os.getuid(),
        target_boot_id=target_boot_id(), checked_monotonic_ns=time.monotonic_ns(),
        diagnostics=["WORKER_OR_SPAWN_STATE_UNKNOWN"] if unknown else ["REMAINING_GROUP_MEMBERS"] if remaining else [])
    record = None
    raw = {}
    if (folder / "execution_record.json").exists():
        record = StagedFixtureRecord.model_validate(json.loads(read_regular(folder / "execution_record.json"))).model_dump(mode="json")
        for name, item in record["artifacts"].items():
            value = read_regular(folder / "evidence" / name, 4194304)
            if len(value) != item["size_bytes"] or hashlib.sha256(value).hexdigest() != item["sha256"]:
                raise ValueError("native fixed staged evidence integrity failure")
            raw[name] = base64.b64encode(value).decode("ascii")
    return recovery.model_dump(mode="json"), record, raw


def main(payload=None, *, project_root=None):
    required = {"schema_version", "operation", "nonce", "request_id", "run_id", "control_token",
                "receipt", "receipt_sha256", "request", "authorization", "policy", "description"}
    if not isinstance(payload, dict) or set(payload) != required or payload["schema_version"] != "1.0":
        raise ValueError("invalid fixed staged worker envelope")
    for name, length in (("nonce", 32), ("request_id", 32), ("run_id", 32), ("control_token", 64)):
        if not isinstance(payload[name], str) or re.fullmatch("[0-9a-f]{" + str(length) + "}", payload[name]) is None:
            raise ValueError("invalid fixed staged request or control identity")
    packet = {"schema_version": "1.0", "operation": payload["operation"], "nonce": payload["nonce"],
              "request_id": payload["request_id"], "run_id": payload["run_id"],
              "target_environment": canonical_target_environment(),
              "worker_identity": describe_process_identity(os.getpid()), "status": "UNKNOWN",
              "description": None, "record": None, "recovery": None, "raw_files": {}, "diagnostics": []}
    try:
        if current_platform_type() != "wsl":
            raise ValueError("fixed staged worker requires WSL")
        if payload["operation"] == "DESCRIBE":
            if payload["receipt"] is None or payload["receipt_sha256"] is None or any(
                    payload[name] is not None for name in ("request", "authorization", "policy", "description")):
                raise ValueError("description requires exact receipt but no execution inputs")
            result = describe(payload["receipt"], payload["receipt_sha256"])
            packet.update(description=result.model_dump(mode="json"), status=result.status)
        elif payload["operation"] == "EXECUTE":
            if payload["receipt"] is not None or payload["receipt_sha256"] is not None:
                raise ValueError("execution must use description-bound receipt only")
            packet["record"], packet["raw_files"] = execute(payload)
            packet["status"] = packet["record"]["status"]
        elif payload["operation"] in {"STATUS", "CANCEL"}:
            if any(payload[name] is not None for name in (
                    "receipt", "receipt_sha256", "request", "authorization", "policy", "description")):
                raise ValueError("status and cancel accept no execution inputs")
            packet["recovery"], packet["record"], packet["raw_files"] = control(payload)
            packet["status"] = packet["recovery"]["status"]
        else:
            raise ValueError("unknown fixed staged operation")
    except FileExistsError:
        packet.update(status="REJECTED", diagnostics=["RUN_ID_CONFLICT"])
    except (OSError, ValueError, KeyError) as exc:
        packet.update(status="UNKNOWN", diagnostics=[type(exc).__name__ + ":" + str(exc)])
    sys.stdout.buffer.write(json_bytes(packet))
    return 0
