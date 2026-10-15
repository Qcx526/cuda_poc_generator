"""WSL lifecycle control plane for reviewed harmless actions only."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from .execution_preflight import preflight_execution
from .execution_worker import _snapshot, contract_digest, resource_capabilities
from .models.execution import ExecutionRequest, OperatorAuthorization, PreflightPolicy, request_sha256, snapshot_sha256, aware_time
from .models.lifecycle import ExecutionRecord, LifecycleEvent
from .models.platform import PlatformSnapshot
from .models.tool_result import ToolResult
from .probe_artifacts import protect_directory
from .registered_actions import get_registered_action
from .tools.process import canonical_target_environment, current_platform_type, measure_tool_identity


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def task_root():
    return Path.home() / ".local" / "state" / "cuda-poc-generator" / "lifecycle_tasks"


def _read_json(path, limit=16777216):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("unsafe or missing lifecycle record")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate lifecycle key")
            result[key] = value
        return result
    raw = path.read_bytes()
    if len(raw) > limit:
        raise ValueError("lifecycle record exceeds limit")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def _write_json(path, value, *, exclusive=True):
    raw = (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)


def _identity(pid):
    from .lifecycle_process import describe_process_identity
    return describe_process_identity(pid)


def _boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()


def _group_members(pgid, session_id):
    found = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            item = _identity(int(path.name))
            if item["pgid"] == pgid or item["session_id"] == session_id:
                found.append(item["pid"])
        except (FileNotFoundError, ProcessLookupError):
            continue
    return sorted(found)


def _control(payload):
    from .models.lifecycle import RemoteRecoveryCheck
    folder = task_root() / payload["run_id"]
    try:
        lease = _read_json(folder / "lease.json", 65536)
        if (lease["request_id"] != payload["request_id"] or lease["run_id"] != payload["run_id"]
                or lease["control_token_sha256"] != hashlib.sha256(payload["control_token"].encode("ascii")).hexdigest()
                or lease["target_environment"] != canonical_target_environment()
                or lease["worker"]["uid"] != os.getuid() or lease["boot_id"] != _boot_id()):
            raise ValueError("control identity mismatch")
        if payload["operation"] == "CANCEL":
            cancel = {"request_id": lease["request_id"], "run_id": lease["run_id"],
                      "nonce": lease["nonce"], "action": "CANCEL"}
            try:
                _write_json(folder / "cancel.json", cancel)
            except FileExistsError:
                if _read_json(folder / "cancel.json", 4096) != cancel:
                    raise ValueError("conflicting cancellation")
        record = None
        if (folder / "execution_record.json").exists():
            record = ExecutionRecord.model_validate(_read_json(folder / "execution_record.json")).model_dump(mode="json")
        try:
            current = _identity(lease["worker"]["pid"])
            worker_alive = all(current[key] == lease["worker"][key] for key in
                               ("pid", "pgid", "session_id", "start_ticks", "uid", "gid"))
        except (FileNotFoundError, ProcessLookupError):
            worker_alive = False
        process = lease.get("process")
        no_process_confirmed = (record is not None and record["process"] is not None and not record["process"]["started"])
        if process is None and lease.get("spawn_intent") and not no_process_confirmed:
            recovery = RemoteRecoveryCheck(request_id=lease["request_id"], run_id=lease["run_id"], checked_at=utc_now(),
                                             worker_alive=worker_alive, group_empty=None, identity_match=True,
                                             status="UNKNOWN", observer_pid=os.getpid(), observer_uid=os.getuid(),
                                             diagnostics=["SPAWN_IDENTITY_UNKNOWN"])
            return record, recovery.model_dump(mode="json"), []
        members = _group_members(process["pgid"], process["session_id"]) if process is not None else []
        confirmed = not worker_alive and not members
        recovery = RemoteRecoveryCheck(
            request_id=lease["request_id"], run_id=lease["run_id"], checked_at=utc_now(),
            worker_alive=worker_alive, group_empty=not members, identity_match=True,
            status="CONFIRMED" if confirmed else ("UNKNOWN" if worker_alive else "FAILED"),
            observer_pid=os.getpid(), observer_uid=os.getuid(),
            diagnostics=[] if confirmed else ["WORKER_STILL_RUNNING" if worker_alive else "REMAINING_GROUP_MEMBERS"])
        return record, recovery.model_dump(mode="json"), []
    except (OSError, ValueError, KeyError, TypeError):
        return None, None, ["CONTROL_IDENTITY_OR_RECOVERY_UNKNOWN"]


def handle_worker(payload, *, project_root=None):
    required = {"operation", "nonce", "request_id", "run_id", "control_token", "request", "authorization", "policy", "snapshot", "tool_record"}
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("invalid lifecycle worker envelope")
    for name, pattern in (("nonce", r"[0-9a-f]{32}"), ("request_id", r"[0-9a-f]{32}"),
                          ("run_id", r"[0-9a-f]{32}"), ("control_token", r"[0-9a-f]{64}")):
        if not isinstance(payload[name], str) or not re.fullmatch(pattern, payload[name]):
            raise ValueError("invalid lifecycle identity")
    if payload["operation"] not in {"EXECUTE", "STATUS", "CANCEL"}:
        raise ValueError("unregistered lifecycle operation")
    packet = {"schema_version": "1.0", "operation": payload["operation"], "nonce": payload["nonce"],
              "request_id": payload["request_id"], "run_id": payload["run_id"], "worker_exit_code": 0,
              "target_environment": None, "worker_identity": None, "record": None, "recovery": None,
              "worker_events": [], "diagnostics": [], "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    if current_platform_type() != "wsl":
        packet["diagnostics"] = ["WORKER_NOT_WSL"]
        return packet
    packet["target_environment"] = canonical_target_environment()
    packet["worker_identity"] = _identity(os.getpid())
    if payload["operation"] != "EXECUTE":
        if any(payload[name] is not None for name in ("request", "authorization", "policy", "snapshot", "tool_record")):
            packet["diagnostics"] = ["CONTROL_HAS_EXECUTION_INPUTS"]
            return packet
        packet["record"], packet["recovery"], packet["diagnostics"] = _control(payload)
        return packet

    req = ExecutionRequest.model_validate(payload["request"])
    auth = None if payload["authorization"] is None else OperatorAuthorization.model_validate(payload["authorization"])
    policy = PreflightPolicy.model_validate(payload["policy"])
    snapshot = PlatformSnapshot.model_validate(payload["snapshot"])
    tool = ToolResult.model_validate(payload["tool_record"])
    if req.request_id != payload["request_id"]:
        raise ValueError("task request identity mismatch")
    events = [LifecycleEvent(sequence=0, state="CREATED", observed_at=utc_now(),
                              source="WSL lifecycle worker", reason="Validated request received")]
    process = None
    folder = None
    lease = None
    native_events = []
    gate_failures = []

    def event(state, reason):
        events.append(LifecycleEvent(sequence=len(events), state=state, observed_at=utc_now(),
                                     source="WSL lifecycle worker", reason=reason))

    def finish(state, diagnostics):
        actual_tool = process.tool_identity if process is not None else req.tool_identity
        event(state, "; ".join(diagnostics) if diagnostics else "Observed terminal process and cleanup state")
        record = ExecutionRecord(
            request_id=req.request_id, run_id=payload["run_id"], request_sha256=request_sha256(req),
            authorization_sha256=None if auth is None else contract_digest(OperatorAuthorization, auth),
            policy_sha256=contract_digest(PreflightPolicy, policy), snapshot_sha256=snapshot_sha256(snapshot),
            candidate_sha256=req.candidate_sha256, platform_environment_id=req.platform_environment_id,
            platform_probe_id=req.platform_probe_id, target_environment=req.binding.target_environment,
            tool_record_id=req.binding.tool_record_id, tool_identity=actual_tool,
            authorization_reference=None if auth is None else auth.authorization_reference,
            operator_id=None if auth is None else auth.operator_id, action_id=req.fixture_id,
            status=state, events=events, process=process, worker_pid=os.getpid(),
            started_at=events[0].observed_at, finished_at=events[-1].observed_at,
            diagnostics=diagnostics, evidence_files=["stdout.bin", "stderr.bin", "lifecycle.json", "process_result.json"],
            fixture_execution_status=("STARTED" if process is not None and process.action_started else
                                      "UNKNOWN" if process is None and (lease or {}).get("spawn_intent") else "NOT_STARTED"))
        packet["record"] = record.model_dump(mode="json")
        packet["worker_events"] = native_events
        if folder is not None:
            for name, raw in (("stdout.bin", process.stdout_bytes() if process else b""),
                              ("stderr.bin", process.stderr_bytes() if process else b"")):
                fd = os.open(folder / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            _write_json(folder / "execution_record.json", packet["record"])
        return packet

    try:
        root = Path(project_root or Path(__file__).resolve().parent.parent).resolve(strict=True)
        base = task_root()
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
        claims = base / "requests"
        claims.mkdir(exist_ok=True, mode=0o700)
        reserved = base / payload["run_id"]
        protect_directory(reserved)
        _write_json(claims / (req.request_id + ".json"), {"request_id": req.request_id, "run_id": payload["run_id"]})
        folder = reserved
        lease = {"request_id": req.request_id, "run_id": payload["run_id"], "nonce": payload["nonce"],
                 "control_token_sha256": hashlib.sha256(payload["control_token"].encode("ascii")).hexdigest(),
                 "target_environment": packet["target_environment"], "worker": packet["worker_identity"],
                 "boot_id": _boot_id(), "process": None, "spawn_intent": False}
        _write_json(folder / "lease.json", lease)
        for name, model in (("request.json", req), ("authorization.json", auth), ("policy.json", policy), ("snapshot.json", snapshot)):
            _write_json(folder / name, None if model is None else model.model_dump(mode="json"))
    except FileExistsError:
        folder = None
        return finish("REJECTED", ["TASK_ID_CONFLICT"])
    except (OSError, ValueError):
        folder = None
        return finish("UNKNOWN", ["PRIVATE_TASK_STORAGE_UNAVAILABLE"])
    try:
        action = get_registered_action(req.fixture_id)
    except ValueError:
        return finish("UNSUPPORTED", ["ACTION_NOT_REGISTERED"])
    if (req.request_schema_version != "1.1" or req.authorized_action != "FIXED_FIXTURE_CHECK" or req.tool_role != "fixture_python"
            or req.candidate_path != str(root / action.relative_path) or req.cwd != str(root)
            or req.candidate_sha256 != action.sha256 or policy.scope_root != str(root)
            or policy.fixture_hashes != {action.fixture_id: action.sha256}):
        return finish("UNSUPPORTED", ["REGISTERED_ACTION_SCOPE_REQUIRED"])
    actual_policy = policy.model_dump(mode="json")
    actual_support = resource_capabilities(req.resource_limits)
    if policy.resource_support.status == "OBSERVED":
        actual_support["mechanisms"] = [value for value in actual_support["mechanisms"] if value in policy.resource_support.mechanisms]
        actual_policy["resource_support"] = actual_support
    elif actual_support["status"] != "OBSERVED":
        actual_policy["resource_support"] = actual_support
    try:
        current = _snapshot(packet["target_environment"])
        if current.environment_id != req.platform_environment_id:
            return finish("REJECTED", ["CURRENT_TARGET_IDENTITY_MISMATCH"])
        actual_python = measure_tool_identity(sys.executable, cwd=root)
        if actual_python.status != "OBSERVED":
            return finish("UNKNOWN", ["WORKER_TOOL_IDENTITY_UNKNOWN"])
        if (actual_python.resolved_path, actual_python.file_sha256) != (req.tool_identity.resolved_path, req.tool_identity.file_sha256):
            return finish("REJECTED", ["WORKER_TOOL_IDENTITY_MISMATCH"])
        checked = preflight_execution(req, snapshot, tool, auth, actual_policy,
                                      observed_platform_type="wsl", observed_target_environment=packet["target_environment"])
        _write_json(folder / "preflight.json", checked.model_dump(mode="json"))
        if checked.status != "READY":
            return finish(checked.status, [entry.code for entry in checked.diagnostics])
    except (OSError, ValueError):
        return finish("UNKNOWN", ["PLATFORM_OR_PREFLIGHT_OBSERVATION_FAILED"])
    event("AUTHORIZED", "Independent operator authorization accepted by strict preflight")
    event("PREFLIGHT_READY", "Target files, identities and supported resource policy checked")

    def observed(kind, details):
        if kind in {"STARTING", "RESOURCE_READY"} and not (
                aware_time(auth.not_before) <= datetime.now(timezone.utc) < aware_time(auth.expires_at)):
            gate_failures.append("AUTHORIZATION_EXPIRED_AT_GATE")
            native_events.append({"kind": "AUTHORIZATION_GATE_REJECTED", "observed_at": utc_now(),
                                  "details": {"code": "AUTHORIZATION_EXPIRED_AT_GATE", "gate": kind}})
            raise PermissionError("AUTHORIZATION_EXPIRED_AT_GATE")
        native_events.append({"kind": kind, "observed_at": utc_now(), "details": details})
        if len(native_events) > 1024:
            raise OSError("native lifecycle event bound exceeded")
        with (folder / "worker_events.jsonl").open("ab") as stream:
            stream.write((json.dumps(native_events[-1], sort_keys=True, allow_nan=False) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        (folder / "worker_events.jsonl").chmod(0o600)
        if kind in {"STARTING", "WORKER_CHILD_STARTED"}:
            if kind == "STARTING":
                lease["spawn_intent"] = True
            else:
                lease["process"] = details
            update = folder / "lease.next.json"
            _write_json(update, lease)
            os.replace(update, folder / "lease.json")
        if kind in {"STARTING", "RUNNING"}:
            event(kind, "Observed registered process " + kind.lower())

    from .lifecycle_process import run_registered_action
    try:
        outcome = run_registered_action(req.fixture_id, req.resource_limits, expected_tool=req.tool_identity,
                                         cwd=req.cwd, target_environment=packet["target_environment"],
                                         request_id=req.request_id, run_id=payload["run_id"], nonce=payload["nonce"],
                                         cancellation_file=folder / "cancel.json", on_event=observed)
        process = outcome.process
        if gate_failures and not process.action_started:
            return finish("REJECTED", gate_failures + process.diagnostics)
        return finish(outcome.state, process.diagnostics)
    except (OSError, ValueError):
        # A runner failure cannot establish cleanup or execution success.
        return finish("UNKNOWN", ["RUNNER_OR_EVIDENCE_FAILURE"])


def main(payload=None, *, project_root=None):
    packet = handle_worker(payload, project_root=project_root)
    sys.stdout.buffer.write((json.dumps(packet, sort_keys=True, allow_nan=False) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0
