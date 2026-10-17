"""Bounded bwrap adapter for the two fixed, reviewed CPU diagnostics only.

Reuses P2 Linux process identity, subreaper, cancellation and cleanup contracts.
It is not a general command runner or an untrusted-candidate sandbox.
"""

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time

from .lifecycle_process import (_cancel_requested, _group_members, _same_process,
                                _set_subreaper, assess_cgroup_v2, describe_process_identity)
from .memcheck_registry import inner_argv
from .models.lifecycle import CleanupObservation
from .models.memcheck import MemcheckProcess, MemcheckResources
from .tools.process import measure_tool_identity


def utc():
    return datetime.now(timezone.utc).isoformat()


def write_new(path, raw):
    path = Path(path)
    temporary = path.with_name("." + path.name + ".pending")
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.link(temporary, path, follow_symlinks=False)
    temporary.unlink()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def read_regular(path, maximum=4194304):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("evidence is nonregular or exceeds its fixed bound")
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("evidence grew beyond its fixed bound")
    return raw


def sandbox_argv(tools, *, source, guard, config, control, output, executable=None):
    """Exact mount list. No project/home/Windows mount or device passthrough."""
    argv = [tools["bwrap"].resolved_path, "--unshare-all", "--die-with-parent", "--cap-drop", "ALL", "--clearenv",
            "--setenv", "LANG", "C", "--setenv", "LC_ALL", "C", "--setenv", "PATH", "/usr/bin:/bin"]
    for path in ("/usr", "/bin", "/lib", "/lib64"):
        argv += ["--ro-bind", path, path]
    argv += ["--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
             "--ro-bind", str(source), "/input/fixture.c", "--ro-bind", str(guard), "/guard.py",
             "--ro-bind", str(config), "/config.json", "--bind", str(control), "/control",
             "--bind", str(output), "/out", "--chdir", "/out"]
    if executable is not None:
        argv += ["--ro-bind", str(executable), "/target/fixture.bin"]
    return argv + ["--", tools["guard_python"].resolved_path, "-I", "/guard.py"]


def _guard_host_identity(ready, pgid, session_id, limits):
    matches = []
    for item in _group_members(pgid, session_id):
        if item["start_ticks"] != ready["start_ticks"] or item["uid"] != os.getuid():
            continue
        status = Path(f"/proc/{item['pid']}/status").read_text()
        namespace_pid = next((line for line in status.splitlines() if line.startswith("NSpid:")), None)
        if namespace_pid is None or int(namespace_pid.split()[-1]) != ready["pid"]:
            continue
        # Independent kernel-side check of the exact limits reported by the measured guard.
        from .memcheck_sandbox import proc_limits
        observed = proc_limits(item["pid"])
        required = {key: [getattr(limits, key)] * 2 for key in observed}
        if observed != required or observed != ready["limits"]:
            raise ValueError("guard limits disagree with the independent host /proc observation")
        matches.append(item)
    if len(matches) != 1:
        raise ValueError("sandbox guard PID/start identity is not independently established")
    return matches[0]


def run_fixed_memcheck_step(request, step_id, folder, *, cancellation_file, nonce, on_event,
                            expected_executable_sha256=None):
    """Internal worker adapter; a successful versioned preflight is mandatory."""
    from .models.memcheck import MemcheckRequest
    from .tools.process import current_platform_type, canonical_target_environment
    request = MemcheckRequest.model_validate(request)
    if current_platform_type() != "wsl" or canonical_target_environment() != request.target_environment:
        raise ValueError("fixed Memcheck adapter requires its actual bound WSL environment")
    if step_id not in {"compile", "memcheck"}:
        raise ValueError("unregistered diagnostic step")
    limits, tools = request.resource_limits, request.tools
    work = Path(folder)
    source, guard = work / "fixture.c", work / "sandbox_guard.py"
    if hashlib.sha256(read_regular(source)).hexdigest() != request.source_sha256:
        raise ValueError("reviewed source identity changed before controlled launch")
    for expected in tools.values():
        actual = measure_tool_identity(expected.resolved_path, source="fresh fixed Memcheck step identity")
        if actual.status != "OBSERVED" or actual.file_sha256 != expected.file_sha256:
            raise ValueError("required executable identity changed before launch")
    from . import memcheck_sandbox
    if read_regular(guard) != Path(memcheck_sandbox.__file__).read_bytes():
        raise ValueError("measured sandbox guard source changed")
    step_root = work / step_id
    step_root.mkdir(mode=0o700, exist_ok=False)
    control, output = step_root / "control", step_root / "out"
    control.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    executable = None if step_id == "compile" else work / "compile" / "out" / "fixture.bin"
    executable_sha = None if executable is None else hashlib.sha256(read_regular(executable)).hexdigest()
    if step_id == "memcheck" and (expected_executable_sha256 is None or executable_sha != expected_executable_sha256):
        raise ValueError("compiled fixture changed since this run's successful compiler observation")
    images = {tool.resolved_path: tool.file_sha256 for tool in tools.values()}
    images.update(request.helper_images)
    config = {"schema_version": "1.0", "request_id": request.request_id, "run_id": request.run_id,
              "nonce": nonce, "step_id": step_id, "task_id": request.task_id, "source_sha256": request.source_sha256,
              "executable_sha256": executable_sha, "tools": {k: t.model_dump(mode="json") for k, t in tools.items()},
              "allowed_images": images, "limits": limits.model_dump(mode="json"),
              "outer_namespaces": {key: os.readlink("/proc/self/ns/" + key) for key in ("user", "mnt", "net", "pid", "ipc", "uts")}}
    config_path = step_root / "config.json"
    write_new(config_path, json_bytes(config))
    argv = sandbox_argv(tools, source=source, guard=guard, config=config_path, control=control,
                        output=output, executable=executable)
    write_new(step_root / "argv.json", json_bytes(argv))
    start, began = utc(), time.monotonic()
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    proc = None
    identity = ready = result = host_observation = None
    state = "START_FAILED"
    timed_out = cancelled = truncated = capture_failed = gated = False
    diagnostics, observed_pids = [], {}
    subreaper_before = _set_subreaper(True)
    selector = selectors.DefaultSelector()
    termination = "NONE"
    def terminate():
        nonlocal termination
        if proc is None:
            return
        members = _group_members(proc.pid, proc.pid)
        for member in members:
            observed_pids[member["pid"]] = member
        if members:
            leader = next((x for x in members if x["pid"] == proc.pid), None)
            if identity is not None and leader is not None and not _same_process(identity, leader):
                raise OSError("refusing to terminate a reused group identity")
            os.killpg(proc.pid, signal.SIGKILL)
            termination = "SIGKILL"
    def setup():
        import resource
        for kind, key in ((resource.RLIMIT_CPU, "cpu_seconds"), (resource.RLIMIT_AS, "memory_bytes"),
                          (resource.RLIMIT_FSIZE, "max_file_bytes"), (resource.RLIMIT_NOFILE, "max_open_files"),
                          (resource.RLIMIT_CORE, "core_bytes")):
            resource.setrlimit(kind, (getattr(limits, key),) * 2)
        import ctypes
        if ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
            raise OSError("parent death signal could not be applied")
    try:
        on_event("STARTING", {"step_id": step_id})
        proc = subprocess.Popen(argv, cwd=str(work), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                                shell=False, start_new_session=True, preexec_fn=setup)
        identity = describe_process_identity(proc.pid)
        observed_pids[proc.pid] = identity
        on_event("CHILD_STARTED", {"step_id": step_id, **identity})
        for name in chunks:
            stream = getattr(proc, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        stopped_at = None
        while selector.get_map() or proc.poll() is None:
            now = time.monotonic()
            if stopped_at is None:
                if _cancel_requested(cancellation_file, request_id=request.request_id, run_id=request.run_id, nonce=nonce):
                    cancelled, state = True, "CANCELLED"
                    terminate(); stopped_at = now
                elif now - began >= limits.wall_time_seconds:
                    timed_out, state = True, "TIMED_OUT"
                    terminate(); stopped_at = now
                elif (output / "memcheck.xml").exists() and (output / "memcheck.xml").stat().st_size > limits.max_xml_bytes:
                    truncated, state = True, "RESOURCE_LIMIT"
                    terminate(); stopped_at = now
            if ready is None and (control / "ready.json").exists() and stopped_at is None:
                ready = json.loads(read_regular(control / "ready.json", 65536))
                if (ready["request_id"], ready["run_id"], ready["nonce"], ready["step_id"], ready["source_sha256"], ready["argv"]) != (
                        request.request_id, request.run_id, nonce, step_id, request.source_sha256, inner_argv(step_id, tools)):
                    raise ValueError("sandbox readiness identity differs from the authorized fixed request")
                if not ready["boundaries"] or not all(ready["boundaries"].values()):
                    raise ValueError("required sandbox file/network/process boundaries not confirmed")
                if ready.get("guard_python_image") != {"path":tools["guard_python"].resolved_path,"sha256":tools["guard_python"].file_sha256}:
                    raise ValueError("actual guard interpreter image conflicts with its authorized identity")
                native_guard = _guard_host_identity(ready, proc.pid, proc.pid, limits)
                from .cuda_process import _actual_image
                actual_bwrap = _actual_image(proc.pid)
                from .models.tool_result import ToolIdentity
                actual_bwrap = ToolIdentity.model_validate({**actual_bwrap.model_dump(mode="python"),
                    "source":"Linux host /proc executable image handle SHA-256 while measured sandbox guard waits before GO"})
                if (actual_bwrap.resolved_path,actual_bwrap.file_sha256) != (tools["bwrap"].resolved_path,tools["bwrap"].file_sha256):
                    raise ValueError("actual bubblewrap kernel image differs from its allowed identity")
                host_observation={"bwrap_identity":identity,"bwrap_image":actual_bwrap.model_dump(mode="json"),"guard_identity":native_guard}
                write_new(step_root/"host_identity.json",json_bytes(host_observation))
                observed_pids[native_guard["pid"]] = native_guard
                on_event("RESOURCE_READY", {"step_id": step_id, "host_guard": native_guard, "sandbox_ready": ready})
                write_new(control / "go.json", json_bytes({"request_id": request.request_id, "run_id": request.run_id, "nonce": nonce, "action": "GO"}))
                gated = True
                on_event("RUNNING", {"step_id": step_id})
            for item in _group_members(proc.pid, proc.pid):
                observed_pids[item["pid"]] = item
            for key, _ in selector.select(0.01):
                block = os.read(key.fd, 65536)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                remaining = max(0, limits.max_output_bytes - sum(map(len, chunks.values())))
                chunks[key.data].extend(block[:remaining])
                if len(block) > remaining and stopped_at is None:
                    truncated, state = True, "RESOURCE_LIMIT"
                    terminate(); stopped_at = time.monotonic()
            if stopped_at is not None and now - stopped_at > 3:
                break
        if proc.poll() is None:
            terminate()
        code = proc.wait(timeout=3)
        if (control / "result.json").exists():
            result = json.loads(read_regular(control / "result.json", 131072))
            if (result["request_id"], result["run_id"], result["nonce"], result["step_id"], result["argv"]) != (
                    request.request_id, request.run_id, nonce, step_id, inner_argv(step_id, tools)):
                raise ValueError("sandbox result identity conflict")
        if state not in {"CANCELLED", "TIMED_OUT", "RESOURCE_LIMIT"}:
            state = "COMPLETED" if gated and code == 0 and result is not None and result["returncode"] == 0 and not result["error"] and result["all_tracees_reaped"] else "NONZERO_EXIT" if gated else "START_FAILED"
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        diagnostics.append(type(exc).__name__ + ":" + str(exc))
        state = "CAPTURE_FAILED" if gated else "START_FAILED" if proc is None else "UNSUPPORTED"
        capture_failed = gated
        terminate()
        if proc is not None:
            try: proc.wait(timeout=3)
            except subprocess.SubprocessError: pass
    finally:
        selector.close()
        if proc is not None:
            for name in chunks:
                getattr(proc, name).close()
        # Kill only this new session, then reap adopted descendants in this dedicated worker.
        terminate()
        cleanup_deadline = time.monotonic() + 3
        while time.monotonic() < cleanup_deadline:
            try:
                while True:
                    child, _ = os.waitpid(-1, os.WNOHANG)
                    if not child: break
            except ChildProcessError:
                pass
            members = [] if proc is None else _group_members(proc.pid, proc.pid)
            if not members: break
            time.sleep(0.01)
        remaining = [] if proc is None else [x["pid"] for x in _group_members(proc.pid, proc.pid)]
        for pid, old in observed_pids.items():
            try:
                current = describe_process_identity(pid)
                if _same_process(old, current):
                    remaining.append(pid)
            except (FileNotFoundError, ProcessLookupError):
                pass
        remaining = sorted(set(remaining))
        _set_subreaper(subreaper_before)
    trace = []
    if (control / "trace.jsonl").exists():
        try:
            trace = [json.loads(x) for x in read_regular(control / "trace.jsonl").splitlines() if x]
        except (ValueError, OSError):
            capture_failed, state = True, "CAPTURE_FAILED"
    started_native = any(e.get("event") == "EXEC" for e in trace)
    main_exec = next((e for e in trace if e.get("event") == "EXEC"), None)
    inner_pid = result["child_pid"] if result is not None else None if main_exec is None else main_exec["pid"]
    main_reap = next((e for e in trace if e.get("event") == "REAPED" and e.get("pid") == inner_pid), None)
    inner_code = result["returncode"] if result is not None else None if main_reap is None else main_reap["returncode"]
    for event in trace:
        if event.get("event") in {"EXEC", "CHILD_STOP"} and request.helper_images.get(event["image_path"], images.get(event["image_path"])) != event["image_sha256"]:
            capture_failed, state = True, "CAPTURE_FAILED"
            diagnostics.append("NATIVE_IMAGE_IDENTITY_CONFLICT")
    if remaining:
        state = "CLEANUP_FAILED"
    ended = utc()
    cleanup = CleanupObservation(status="CONFIRMED" if proc is not None and not remaining else "NOT_STARTED" if proc is None else "FAILED",
        termination_method=termination, parent_reaped=proc is not None and proc.returncode is not None,
        group_absent=not remaining, descendants_absent=not remaining, checked_at=ended,
        source="P2 Linux subreaper waitpid and independent host /proc group/session scan; inner ptrace EXITKILL and reap log",
        observed_descendant_pids=sorted(pid for pid in observed_pids if proc is not None and pid != proc.pid), remaining_pids=remaining)
    code = None if proc is None else proc.returncode
    resources = MemcheckResources(status="ENFORCED" if gated else "UNKNOWN" if proc else "NOT_STARTED",
        wall_watchdog=gated, output_cap=gated, process_group=gated,
        cpu_seconds=limits.cpu_seconds if gated else None, memory_bytes=limits.memory_bytes if gated else None,
        verification_source="measured sandbox guard getrlimit, independent host /proc/limits before GO, native exec-stop /proc/limits for each image",
        cgroup_v2_status="OBSERVED_NOT_USED" if assess_cgroup_v2()["status"] == "OBSERVED" else "UNAVAILABLE",
        cgroup_v2_detail="read-only capability only; no delegated task cgroup limits applied",
        network_isolation="NAMESPACE_CONFIRMED" if gated else "NOT_IMPLEMENTED")
    payload = dict(started=proc is not None, action_started=started_native, argv=argv, cwd=str(work),
        target_environment=request.target_environment, tool_identity=tools["bwrap"], worker_pid=os.getpid(),
        started_at=start if proc else None, finished_at=ended, duration_seconds=time.monotonic()-began,
        returncode=code, linux_signal=-code if code is not None and code < 0 else None,
        timed_out=timed_out, cancelled=cancelled, truncated=truncated, capture_failed=capture_failed,
        resource_limit_reason="XML or stdout/stderr output bound exceeded" if truncated else None,
        resource_limits=limits, resources=resources, cleanup=cleanup, diagnostics=diagnostics,
        inner_argv=inner_argv(step_id, tools), ready_observation=ready, inner_result=result, trace_events=trace,
        host_observation=host_observation,
        inner_pid=inner_pid, inner_returncode=inner_code,
        inner_linux_signal=-inner_code if inner_code is not None and inner_code < 0 else None)
    for name in ("pid", "pgid", "session_id", "start_ticks", "uid", "gid"):
        payload[name] = None if identity is None else identity[name]
    for name, data in chunks.items():
        raw = bytes(data)
        payload.update({name+"_b64":base64.b64encode(raw).decode(), name+"_sha256":hashlib.sha256(raw).hexdigest(), name+"_size_bytes":len(raw)})
        try:
            write_new(step_root / (name + ".bin"), raw)
        except OSError as exc:
            payload["capture_failed"] = True
            payload["diagnostics"].append("RAW_STREAM_WRITE_FAILED:"+type(exc).__name__)
            state = "CAPTURE_FAILED" if started_native else "START_FAILED"
    return state, MemcheckProcess.model_validate(payload)
