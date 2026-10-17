"""WSL worker for versioned fixed CPU Memcheck tasks. No candidate dispatch."""

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

from .execution_preflight import preflight_fixed_memcheck, target_boot_id
from .execution_worker import _snapshot
from .lifecycle_process import describe_process_identity, _group_members, _same_process
from .memcheck_process import json_bytes, read_regular, run_fixed_memcheck_step, write_new
from .memcheck_registry import fixed_source
from .models.execution import snapshot_sha256
from .models.lifecycle import ArtifactReference, LifecycleEvent, RemoteRecoveryCheck, canonical_sha256
from .models.memcheck import (MemcheckDescription, MemcheckRequest, MemcheckAuthorization, MemcheckPolicy,
                              MemcheckStep, MemcheckExecutionRecord)
from .tools.process import canonical_target_environment, current_platform_type, measure_tool_identity, run_tool


def task_root():
    return Path.home() / ".local" / "state" / "cuda-poc-generator" / "memcheck_tasks"


def _protected_root():
    root = task_root()
    if any(p.is_symlink() for p in (root, *root.parents)):
        raise ValueError("fixed task root contains a link")
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if root.stat().st_uid != os.getuid() or stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise ValueError("fixed task root must be private and owned by the worker")
    return root


def describe(project_root):
    from . import memcheck_sandbox
    root = _protected_root()
    identifier = uuid.uuid4().hex
    data = dict(description_id=identifier, status="UNKNOWN", target_environment=canonical_target_environment(),
                snapshot=None, native_task_root=str(root), tools={}, helper_images={}, versions={},
                collector_sha256=hashlib.sha256(Path(memcheck_sandbox.__file__).read_bytes()).hexdigest(),
                target_boot_id=target_boot_id(), observed_monotonic_ns=time.monotonic_ns(), diagnostics=[])
    try:
        if current_platform_type() != "wsl":
            raise ValueError("fixed live diagnostic requires WSL")
        for task in ("p3c-normal-v1", "p3c-invalid-write-v1"):
            fixed_source(task, project_root)
        roles = {"compiler":"/usr/bin/gcc", "valgrind":"/usr/bin/valgrind", "valgrind_launcher":"/usr/bin/valgrind.bin",
                 "memcheck":"/usr/libexec/valgrind/memcheck-amd64-linux", "bwrap":"/usr/bin/bwrap", "guard_python":sys.executable}
        tools = {key:measure_tool_identity(path, source="fixed Memcheck read-only byte identity") for key,path in roles.items()}
        if any(x.status != "OBSERVED" for x in tools.values()):
            data.update(status="UNSUPPORTED", diagnostics=["REQUIRED_MEMCHECK_TOOL_IDENTITY_UNAVAILABLE"])
            return MemcheckDescription.model_validate(data)
        compiler = Path(tools["compiler"].resolved_path)
        match = re.fullmatch(r"(.+)-gcc-(\d+)", compiler.name)
        if match is None:
            raise ValueError("only measured distribution GCC versioned paths are supported")
        target, major = match.groups()
        paths = [Path("/usr/lib/gcc")/target/major/name for name in ("cc1", "collect2")]
        paths += [Path("/usr/bin")/(target+"-"+name) for name in ("as", "ld")]
        helpers = {}
        for path in paths:
            identity = measure_tool_identity(str(path), source="fixed C compiler helper identity")
            if identity.status != "OBSERVED":
                raise ValueError("required GCC assistant identity is unavailable")
            helpers[identity.resolved_path] = identity.file_sha256
        versions = {}
        for role in ("compiler", "valgrind", "bwrap"):
            tool = tools[role]
            result = run_tool([tool.resolved_path,"--version"], cwd=project_root, timeout_seconds=10,
                max_output_bytes=32768, env={"PATH":"/usr/bin:/bin","LANG":"C"},
                target_environment=data["target_environment"], platform_type="wsl",
                allowed_tool_identities={tool.resolved_path:tool.file_sha256},
                command_source="fixed Memcheck read-only version observation", artifact_root=root/"descriptions"/identifier)
            versions[role] = result
            tools[role] = result.tool_identity
        snapshot = _snapshot(data["target_environment"])
        if snapshot.probe_status == "FAILED":
            raise ValueError("platform snapshot failed")
        data.update(status="DESCRIBED", tools=tools, helper_images=helpers, versions=versions,
                    snapshot=snapshot, observed_monotonic_ns=time.monotonic_ns())
    except (OSError, ValueError) as exc:
        data.update(status="UNSUPPORTED", diagnostics=[type(exc).__name__+":"+str(exc)])
    return MemcheckDescription.model_validate(data)


def _write_replace(path, value):
    temporary = path.with_name("."+path.name+".new")
    write_new(temporary, json_bytes(value))
    os.replace(temporary,path)


def control(payload):
    root = task_root()/payload["run_id"]
    lease = json.loads(read_regular(root/"lease.json",131072))
    if (lease["request_id"] != payload["request_id"] or lease["run_id"] != payload["run_id"]
            or lease["control_token_sha256"] != hashlib.sha256(payload["control_token"].encode()).hexdigest()
            or lease["target_environment"] != canonical_target_environment() or lease["target_boot_id"] != target_boot_id()
            or lease["worker"]["uid"] != os.getuid()):
        raise ValueError("fixed diagnostic control identity mismatch")
    if payload["operation"] == "CANCEL" and not (root/"execution_record.json").exists():
        cancellation={"request_id":lease["request_id"],"run_id":lease["run_id"],"nonce":lease["nonce"],"action":"CANCEL"}
        if not (root/"cancel.json").exists(): write_new(root/"cancel.json",json_bytes(cancellation))
        elif json.loads(read_regular(root/"cancel.json",1024)) != cancellation:raise ValueError("conflicting cancellation")
    try:
        worker = describe_process_identity(lease["worker"]["pid"])
        worker_alive = _same_process(worker,lease["worker"])
    except (FileNotFoundError, ProcessLookupError):
        worker_alive=False
    remaining=[]
    for identity in lease.get("groups",[]):
        remaining += [x["pid"] for x in _group_members(identity["pgid"],identity["session_id"])]
    unknown = lease.get("spawn_pending",False)
    recovery = RemoteRecoveryCheck(request_id=lease["request_id"],run_id=lease["run_id"],
        status="UNKNOWN" if unknown or worker_alive else "FAILED" if remaining else "CONFIRMED",
        worker_alive=worker_alive,group_empty=None if unknown else not remaining,identity_match=True,
        checked_at=datetime.now(timezone.utc).isoformat(),observer_pid=os.getpid(),observer_uid=os.getuid(),
        diagnostics=["SPAWN_OR_WORKER_STATE_UNKNOWN"] if unknown or worker_alive else ["REMAINING_GROUP_MEMBERS"] if remaining else [])
    record = None
    raw = {}
    if (root/"execution_record.json").exists():
        record = MemcheckExecutionRecord.model_validate(json.loads(read_regular(root/"execution_record.json"))).model_dump(mode="json")
        for name,item in record["artifacts"].items():
            value=read_regular(root/"evidence"/name)
            if hashlib.sha256(value).hexdigest()!=item["sha256"] or len(value)!=item["size_bytes"]:
                raise ValueError("native retained evidence integrity failure")
            raw[name]=base64.b64encode(value).decode()
    return recovery.model_dump(mode="json"),record,raw


def execute(payload, project_root):
    req = MemcheckRequest.model_validate(payload["request"])
    auth = MemcheckAuthorization.model_validate(payload["authorization"]) if payload["authorization"] is not None else None
    policy = MemcheckPolicy.model_validate(payload["policy"])
    desc = MemcheckDescription.model_validate(payload["description"])
    if req.request_id != payload["request_id"] or req.run_id != payload["run_id"]:
        raise ValueError("worker envelope and request identity conflict")
    root = _protected_root()/req.run_id
    root.mkdir(mode=0o700,exist_ok=False)
    events=[]
    steps=[]
    diagnostics=[]
    executable_sha=None
    raw={}
    def event(state, reason):
        events.append(LifecycleEvent(sequence=len(events),state=state,observed_at=datetime.now(timezone.utc).isoformat(),
            source="fixed Memcheck WSL worker",reason=reason,monotonic_ns=time.monotonic_ns()))
    event("CREATED","收到独立版本的固定 CPU 诊断请求")
    lease={"request_id":req.request_id,"run_id":req.run_id,"nonce":payload["nonce"],
           "control_token_sha256":hashlib.sha256(payload["control_token"].encode()).hexdigest(),
           "target_environment":canonical_target_environment(),"target_boot_id":target_boot_id(),
           "worker":describe_process_identity(os.getpid()),"groups":[],"spawn_pending":False}
    write_new(root/"lease.json",json_bytes(lease))
    for name,value in (("request.json",req),("authorization.json",auth),("policy.json",policy),("description.json",desc)):
        write_new(root/name,json_bytes(None if value is None else value.model_dump(mode="json")))
    preflight=preflight_fixed_memcheck(req,auth,policy,desc,project_root=project_root)
    write_new(root/"preflight.json",json_bytes(preflight.model_dump(mode="json")))
    state=preflight.status
    if preflight.status == "READY":
        event("AUTHORIZED","操作者授权、期限和固定请求身份已匹配")
        event("PREFLIGHT_READY","只读检查通过；原生程序仍须等待实际资源和隔离 gate")
        from . import memcheck_sandbox
        write_new(root/"fixture.c",fixed_source(req.task_id,project_root))
        write_new(root/"sandbox_guard.py",Path(memcheck_sandbox.__file__).read_bytes())
        def observed(kind, detail):
            if kind == "STARTING":
                lease["spawn_pending"]=True
                _write_replace(root/"lease.json",lease)
                if events[-1].state == "PREFLIGHT_READY":event("STARTING","启动固定 bwrap guard，尚未放行目标工具")
            elif kind == "CHILD_STARTED":
                lease["groups"].append({k:detail[k] for k in ("pid","ppid","pgid","session_id","start_ticks","uid","gid")})
                lease["spawn_pending"]=False
                _write_replace(root/"lease.json",lease)
            elif kind == "RUNNING" and events[-1].state == "STARTING":
                event("RUNNING","实际资源、固定源码和 sandbox 边界核对后放行工具")
            journal=root/"worker_events.jsonl"
            fd=os.open(journal,os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
            try:os.write(fd,json_bytes({"event":kind,"observed_at":datetime.now(timezone.utc).isoformat(),"detail":detail}));os.fsync(fd)
            finally:os.close(fd)
        for step in ("compile","memcheck"):
            # The independent authorization and all identities are checked again between steps.
            again=preflight_fixed_memcheck(req,auth,policy,desc,project_root=project_root)
            if again.status != "READY":
                state="UNKNOWN" if steps else again.status
                diagnostics += [x.code for x in again.diagnostics]
                break
            try:
                state,process=run_fixed_memcheck_step(req,step,root,cancellation_file=root/"cancel.json",nonce=payload["nonce"],on_event=observed,
                    expected_executable_sha256=executable_sha)
                steps.append(MemcheckStep(step_id=step,status=state,process=process))
                write_new(root/step/"process_result.json",json_bytes(process.model_dump(mode="json")))
                if state != "COMPLETED":break
                if step == "compile":
                    binary=read_regular(root/"compile"/"out"/"fixture.bin")
                    if binary[:6] != b"\x7fELF\x02\x01" or int.from_bytes(binary[18:20],"little") != 62:
                        raise ValueError("fixed compiler output is not the expected native x86-64 ELF")
                    executable_sha=hashlib.sha256(binary).hexdigest()
            except (OSError,ValueError) as exc:
                state="UNKNOWN" if steps else "START_FAILED"
                diagnostics.append(type(exc).__name__+":"+str(exc))
                break
        for name,path in (("fixture.c",root/"fixture.c"),("sandbox_guard.py",root/"sandbox_guard.py"),
                          ("fixture.bin",root/"compile"/"out"/"fixture.bin"),("memcheck.xml",root/"memcheck"/"out"/"memcheck.xml")):
            if path.exists():raw[name]=read_regular(path)
        for step in steps:
            for name in ("stdout.bin","stderr.bin","argv.json","config.json","process_result.json","host_identity.json"):
                path=root/step.step_id/name
                if path.exists():raw[step.step_id+"."+name]=read_regular(path)
            for name in ("ready.json","result.json","trace.jsonl","guard_failure.json"):
                path=root/step.step_id/"control"/name
                if path.exists():raw[step.step_id+"."+name]=read_regular(path)
        if state == "COMPLETED" and "memcheck.xml" not in raw:
            state="CAPTURE_FAILED";diagnostics.append("MEMCHECK_XML_MISSING")
    else:
        diagnostics=[x.code for x in preflight.diagnostics]
    if events[-1].state == "RUNNING" and state in {"START_FAILED","REJECTED","UNSUPPORTED"}:state="UNKNOWN"
    event(state,"; ".join(diagnostics) if diagnostics else "固定步骤退出、原始采集和 Linux 回收状态已记录")
    # A missing authorization cannot claim an AUTHORIZED event; its absent
    # content has a stable digest and the refusal still gets an immutable record.
    record=MemcheckExecutionRecord(request_id=req.request_id,run_id=req.run_id,task_id=req.task_id,
        request_sha256=canonical_sha256(req),authorization_sha256=canonical_sha256(auth),policy_sha256=canonical_sha256(policy),
        snapshot_sha256=req.snapshot_sha256,platform_environment_id=req.platform_environment_id,platform_probe_id=req.platform_probe_id,
        target_environment=req.target_environment,source_sha256=req.source_sha256,executable_sha256=executable_sha,
        worker_identity=lease["worker"],status=state,events=events,steps=steps,
        artifacts={name:ArtifactReference(file=name,size_bytes=len(value),sha256=hashlib.sha256(value).hexdigest()) for name,value in raw.items()},
        diagnostics=diagnostics)
    (root/"evidence").mkdir(mode=0o700,exist_ok=False)
    for name,value in raw.items():write_new(root/"evidence"/name,value)
    write_new(root/"execution_record.json",json_bytes(record.model_dump(mode="json")))
    return record.model_dump(mode="json"),{name:base64.b64encode(value).decode() for name,value in raw.items()}


def main(payload=None, *, project_root=None):
    required={"schema_version","operation","nonce","request_id","run_id","control_token","request","authorization","policy","description"}
    if not isinstance(payload,dict) or set(payload)!=required or payload["schema_version"]!="1.0":
        raise ValueError("invalid fixed Memcheck worker envelope")
    for key,length in (("nonce",32),("request_id",32),("run_id",32),("control_token",64)):
        if not isinstance(payload[key],str) or re.fullmatch("[0-9a-f]{"+str(length)+"}",payload[key]) is None:
            raise ValueError("invalid fixed task/control identity")
    packet={"schema_version":"1.0","operation":payload["operation"],"nonce":payload["nonce"],
        "request_id":payload["request_id"],"run_id":payload["run_id"],"target_environment":canonical_target_environment(),
        "worker_identity":describe_process_identity(os.getpid()),"status":"UNKNOWN","description":None,
        "record":None,"recovery":None,"raw_files":{},"diagnostics":[]}
    try:
        if current_platform_type()!="wsl":raise ValueError("fixed diagnostic worker is WSL-only")
        if payload["operation"]=="DESCRIBE":
            if any(payload[x] is not None for x in ("request","authorization","policy","description")):raise ValueError("description received execution inputs")
            result=describe(Path(project_root))
            packet.update(description=result.model_dump(mode="json"),status=result.status)
        elif payload["operation"]=="EXECUTE":
            packet["record"],packet["raw_files"]=execute(payload,Path(project_root))
            packet["status"]=packet["record"]["status"]
        elif payload["operation"] in {"STATUS","CANCEL"}:
            if any(payload[x] is not None for x in ("request","authorization","policy","description")):raise ValueError("control received execution inputs")
            packet["recovery"],packet["record"],packet["raw_files"]=control(payload)
            packet["status"]=packet["recovery"]["status"]
        else:raise ValueError("unregistered fixed diagnostic operation")
    except FileExistsError:
        packet.update(status="REJECTED",diagnostics=["RUN_ID_CONFLICT"])
    except (OSError,ValueError,KeyError) as exc:
        packet.update(status="UNKNOWN",diagnostics=[type(exc).__name__+":"+str(exc)])
    sys.stdout.buffer.write(json_bytes(packet))
    return 0
