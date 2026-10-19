"""Linux runner for the immutable P2-B harmless action registry only.

This is not an untrusted-code sandbox.  Neither argv nor source is accepted from
a request.  The WSL worker must independently authorize and preflight a request
before calling this internal adapter.  A private control socket gates the fixed
action until resource limits and the actual child executable are observed.
"""

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time

from .models.execution import ExecutionResourceLimits
from .models.lifecycle import CleanupObservation, ProcessObservation, ResourceObservation
from .models.tool_result import ToolIdentity
from .tools.process import canonical_target_environment, measure_tool_identity


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _process_identity(pid):
    """Read Linux identity without confusing spaces/parentheses in comm."""
    root = Path("/proc") / str(pid)
    data = (root / "stat").read_text(encoding="utf-8")
    end = data.rfind(")")
    fields = data[end + 2:].split()
    if end < 0 or len(fields) < 20:
        raise OSError("invalid /proc process stat")
    status = (root / "status").read_text(encoding="utf-8")
    ids = {}
    for key, name in (("Uid:", "uid"), ("Gid:", "gid")):
        line = next((line for line in status.splitlines() if line.startswith(key)), None)
        if line is None:
            raise OSError("missing /proc identity field")
        ids[name] = int(line.split()[1])
    return {"pid": pid, "ppid": int(fields[1]), "pgid": int(fields[2]),
            "session_id": int(fields[3]), "start_ticks": int(fields[19]),
            "state": fields[0], **ids}


def _same_process(left, right):
    return all(left[name] == right[name] for name in
               ("pid", "pgid", "session_id", "start_ticks", "uid", "gid"))


def _group_members(pgid, session_id):
    members = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            member = _process_identity(int(entry.name))
        except FileNotFoundError:
            continue
        except PermissionError:
            # A foreign unreadable process cannot belong to this worker's UID.
            # A same-user process with unreadable status cannot be ruled out.
            if entry.stat().st_uid == os.getuid():
                raise
            continue
        if member["pgid"] == pgid or member["session_id"] == session_id:
            members.append(member)
    return members


def assess_cgroup_v2():
    """Read availability only; never create a cgroup or change system settings."""
    root = Path("/sys/fs/cgroup")
    try:
        controllers = (root / "cgroup.controllers").read_text(encoding="ascii").split()
        membership = Path("/proc/self/cgroup").read_text(encoding="ascii")
        if not any(line.startswith("0::") for line in membership.splitlines()):
            return {"status": "UNKNOWN", "implemented": False, "controllers": [],
                    "reason": "unified cgroup membership was not observed"}
        return {"status": "OBSERVED", "implemented": False, "controllers": controllers,
                "reason": "read-only cgroup v2 observation; no delegated subtree or cgroup limits used"}
    except FileNotFoundError:
        return {"status": "UNSUPPORTED", "implemented": False, "controllers": [],
                "reason": "cgroup v2 controller file absent"}
    except (OSError, UnicodeError):
        return {"status": "UNKNOWN", "implemented": False, "controllers": [],
                "reason": "cgroup v2 capability observation failed"}


def _set_subreaper(value):
    libc = ctypes.CDLL(None, use_errno=True)
    old = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(old), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_GET_CHILD_SUBREAPER failed")
    if libc.prctl(36, int(value), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER failed")
    return old.value


@dataclass(frozen=True)
class RegisteredProcessOutcome:
    state: str
    process: ProcessObservation
    observation: dict | None = None

    @property
    def stdout(self):
        return self.process.stdout_bytes()

    @property
    def stderr(self):
        return self.process.stderr_bytes()


describe_process_identity = _process_identity


def inspect_cleanup(observation):
    """A second /proc observation; absence is never inferred from kill success."""
    if isinstance(observation, ProcessObservation):
        if observation.started and None in (observation.pgid, observation.session_id, observation.start_ticks,
                                            observation.uid, observation.gid):
            return {"status": "UNKNOWN", "remaining_pids": [], "checked_at": _utc(),
                    "reason": "started process has no complete observed group identity"}
        identity = None if not observation.started else {
            name: getattr(observation, name) for name in
            ("pid", "pgid", "session_id", "start_ticks", "uid", "gid")}
        observed_descendants = observation.cleanup.observed_descendant_pids
    else:
        identity = observation.get("process_identity")
        observed_descendants = [event["details"]["pid"] for event in observation.get("events", [])
                                if event["event"] == "DESCENDANT_OBSERVED"]
    if not identity:
        return {"status": "NOT_STARTED", "remaining_pids": [], "checked_at": _utc()}
    try:
        members = _group_members(identity["pgid"], identity["session_id"])
        observed_remaining = []
        for pid in observed_descendants:
            try:
                _process_identity(pid)
                observed_remaining.append(pid)
            except FileNotFoundError:
                pass
        # A reused group leader must not be reported as the old task's process.
        leader = next((value for value in members if value["pid"] == identity["pid"]), None)
        if leader is not None and not _same_process(leader, identity):
            return {"status": "UNKNOWN", "remaining_pids": [value["pid"] for value in members],
                    "checked_at": _utc(), "reason": "process group identity was reused"}
        remaining = sorted(set([value["pid"] for value in members] + observed_remaining))
        return {"status": "CONFIRMED" if not remaining else "FAILED",
                "remaining_pids": remaining, "checked_at": _utc()}
    except (OSError, ValueError, KeyError):
        return {"status": "UNKNOWN", "remaining_pids": [], "checked_at": _utc(),
                "reason": "independent /proc cleanup observation failed"}


def _cancel_requested(path, *, request_id, run_id, nonce):
    if path is None:
        return False
    selected = Path(path)
    try:
        info = selected.lstat()
    except FileNotFoundError:
        return False
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1024):
        raise OSError("cancellation record is not a protected regular file")
    with selected.open("rb") as handle:
        current = os.fstat(handle.fileno())
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise OSError("cancellation record identity changed")
        payload = json.loads(handle.read(1025))
    return payload == {"request_id": request_id, "run_id": run_id, "nonce": nonce,
                       "action": "CANCEL"}


def run_registered_action(fixture_id, limits, *, expected_tool, cwd, target_environment,
                          request_id, run_id, nonce, cancellation_file=None, on_event=None):
    """Execute only registered immutable source, with independently observed limits.

    The caller must supply an already authorized/preflighted request.  This
    function additionally remeasures the executable, accepts no argv/source,
    and refuses unknown action IDs. Linux and one isolated worker per task are
    deliberately required: the subreaper setting belongs to the worker process.
    """
    from .registered_actions import get_registered_action
    action = get_registered_action(fixture_id)
    return _run_controlled_action(action, limits, expected_tool=expected_tool, cwd=cwd,
                                   target_environment=target_environment, request_id=request_id, run_id=run_id,
                                   nonce=nonce, cancellation_file=cancellation_file, on_event=on_event)


def _run_controlled_action(action, limits, *, expected_tool, cwd, target_environment,
                           request_id, run_id, nonce, cancellation_file=None, on_event=None, native_plan=None,
                           staged_plan=None):
    """Shared private process engine; action bytes come from reviewed registries."""
    fixture_id = action.fixture_id
    if staged_plan is not None:
        from .staged_fixture_process import _StagedHarmlessPlan
        if not isinstance(staged_plan, _StagedHarmlessPlan) or fixture_id != "p2b-normal-v1" or native_plan is not None:
            raise ValueError("staged plans are reserved for the frozen harmless normal fixture")
    if native_plan is not None:
        from .cuda_process import _NativePlan
        from .models.execution import CudaResourceLimits
        if not isinstance(native_plan, _NativePlan):
            raise ValueError("native tool plan must come from the fixed CUDA registry adapter")
        limits_model = CudaResourceLimits
    else:
        limits_model = ExecutionResourceLimits
    limits = limits_model.model_validate(limits.model_dump(mode="python")
                                        if isinstance(limits, limits_model) else limits)
    expected = ToolIdentity.model_validate(expected_tool.model_dump(mode="python")
                                            if isinstance(expected_tool, ToolIdentity) else expected_tool)
    for value in (request_id, run_id, nonce):
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value) is None:
            raise ValueError("runner identities must be 32-character hexadecimal strings")
    if not isinstance(target_environment, str) or not target_environment.strip():
        raise ValueError("runner target environment is required")
    if on_event is not None and not callable(on_event):
        raise ValueError("event sink must be callable")
    if not Path(cwd).is_absolute():
        raise ValueError("runner cwd must be absolute")
    started_at, began = _utc(), time.monotonic()
    observation = {"fixture_id": fixture_id, "request_id": request_id, "run_id": run_id,
                   "target_environment": target_environment, "started_at": started_at,
                   "finished_at": None, "duration_seconds": 0.0, "argv": [], "cwd": str(cwd),
                   "process_identity": None, "actual_tool_identity": None,
                   "returncode": None, "linux_signal": None, "resource_usage": None,
                   "termination_method": "NOT_STARTED", "parent_reaped": False,
                   "cleanup_status": "NOT_STARTED", "remaining_pids": [],
                   "reaped_descendant_pids": [], "resource_limits_applied": None,
                   "timed_out": False, "cancelled": False, "truncated": False,
                   "capture_failed": False, "diagnostics": [], "events": [],
                   "cgroup_assessment": assess_cgroup_v2()}
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    state = "START_FAILED"
    proc = None
    subreaper_before = None
    selector = None
    parent_control = child_control = None
    ready = False
    staged_ready = False
    finished = False
    control_buffer = bytearray()
    cleanup_error = False
    sink_failed = False
    native_started_at = None
    process_deadline = None
    native_tracer = None
    launcher_identity = None

    def emit(kind, **details):
        nonlocal sink_failed, state
        if kind == "RUNNING":
            state = "RUNNING"
        event = {"event": kind, "observed_at": _utc(), "details": details}
        observation["events"].append(event)
        if on_event is not None and not sink_failed:
            try:
                on_event(kind, {"observed_at": event["observed_at"], **details})
            except Exception as exc:
                sink_failed = True
                observation["capture_failed"] = True
                observation["diagnostics"].append("EVENT_SINK_FAILED: " + type(exc).__name__)
        return not sink_failed

    def kill_owned_group(reason):
        nonlocal cleanup_error
        if proc is None:
            return
        identity = observation["process_identity"]
        try:
            if identity is None and observation["parent_reaped"]:
                raise OSError("native group identity is unknown after parent reaping; refusing to signal a reused PID")
            if identity is not None:
                try:
                    current = _process_identity(proc.pid)
                except FileNotFoundError:
                    current = None
                if current is not None and not _same_process(current, identity):
                    raise OSError("process identity changed; refusing to signal reused group")
            # start_new_session guarantees the direct child group ID even before
            # the resource handshake. No caller-specified PGID can enter here.
            os.killpg(proc.pid, signal.SIGKILL)
            if native_tracer is not None:
                native_tracer.terminate_owned()
            observation["termination_method"] = "SIGKILL_PROCESS_GROUP"
            emit("GROUP_SIGNALLED", signal=signal.SIGKILL, reason=reason, pgid=proc.pid)
        except ProcessLookupError:
            pass
        except OSError as exc:
            cleanup_error = True
            observation["diagnostics"].append("GROUP_TERMINATION_FAILED: " + str(exc))

    def collect_parent():
        nonlocal finished
        if proc is None:
            return
        if finished:
            if native_tracer is not None:
                native_tracer.poll()
            return
        try:
            pid, status, usage = (os.wait4(proc.pid, os.WNOHANG) if native_tracer is None
                                  else native_tracer.poll())
            if pid:
                proc.returncode = os.waitstatus_to_exitcode(status)
                observation["returncode"] = proc.returncode
                observation["linux_signal"] = -proc.returncode if proc.returncode < 0 else None
                observation["resource_usage"] = {"user_cpu_seconds": usage.ru_utime,
                                                   "system_cpu_seconds": usage.ru_stime,
                                                   "max_rss_kib": usage.ru_maxrss}
                observation["parent_reaped"] = True
                finished = True
                emit("PARENT_REAPED", returncode=proc.returncode)
        except ChildProcessError:
            finished = True
            observation["diagnostics"].append("PARENT_REAP_UNKNOWN")

    try:
        if os.name != "posix" or not sys.platform.startswith("linux"):
            state = "UNSUPPORTED"
            raise OSError("controlled lifecycle requires Linux /proc and POSIX resource limits")
        if target_environment != canonical_target_environment():
            state = "REJECTED"
            raise OSError("runner target identity disagrees with the actual Linux/WSL environment")
        import resource
        for limit_type, requested in ((resource.RLIMIT_CPU, limits.cpu_seconds),
                                      (resource.RLIMIT_AS, limits.memory_bytes)):
            hard = resource.getrlimit(limit_type)[1]
            if hard != resource.RLIM_INFINITY and hard < requested:
                state = "UNSUPPORTED"
                raise OSError("requested resource limit cannot be applied under inherited hard limit")
        if expected.status != "OBSERVED" or expected.resolved_path is None:
            state = "REJECTED"
            raise OSError("expected tool identity is not an observed executable")
        actual = measure_tool_identity(expected.resolved_path, cwd=cwd,
                                       source="P2-B executable immediately before isolated launch")
        observation["actual_tool_identity"] = actual.model_dump(mode="json")
        launcher_identity = actual
        if (expected.status != "OBSERVED" or actual.status != "OBSERVED"
                or actual.resolved_path != expected.resolved_path
                or actual.file_sha256 != expected.file_sha256):
            state = "REJECTED"
            raise OSError("tool identity changed or could not be measured")
        own_python = measure_tool_identity(sys.executable, cwd=cwd,
                                          source="trusted worker Python interpreter identity")
        if (own_python.status != "OBSERVED" or own_python.resolved_path != actual.resolved_path
                or own_python.file_sha256 != actual.file_sha256):
            state = "REJECTED"
            raise OSError("registered Python action requires the measured trusted worker interpreter")
        # A subreaper is necessary to collect grandchildren after their fixed
        # parent is killed. The worker is isolated; the previous setting is
        # restored only after this task's descendants have been collected.
        state = "UNSUPPORTED"
        subreaper_before = _set_subreaper(True)
        state = "START_FAILED"
        parent_control, child_control = socket.socketpair()
        child_control.set_inheritable(True)
        parent_control.setblocking(False)
        config = {"request_id": request_id, "nonce": nonce,
                  "cpu_seconds": limits.cpu_seconds, "memory_bytes": limits.memory_bytes,
                  "control_fd": child_control.fileno(), "parent_pid": os.getpid()}
        if native_plan is not None:
            config.update(native_plan.configuration())
        if staged_plan is None:
            argv = [actual.resolved_path, "-I", "-c", action.source.decode("utf-8")]
        else:
            argv = [actual.resolved_path, "-I", "-c", staged_plan.bootstrap(
                control_fd=child_control.fileno(), limits=limits, request_id=request_id,
                run_id=run_id, nonce=nonce)]
            emit("STAGED_FILE_PINNED", **staged_plan.source_observation)
        observation["argv"] = argv
        emit("STARTING", fixture_id=fixture_id)
        if sink_failed:
            raise OSError("lifecycle journal unavailable before start")
        if _cancel_requested(cancellation_file, request_id=request_id, run_id=run_id, nonce=nonce):
            state = "CANCELLED"
            observation["cancelled"] = True
            raise OSError("bound cancellation was received before child launch")
        native_started_at = _utc()
        process_deadline = time.monotonic() + limits.wall_time_seconds
        proc = subprocess.Popen(argv, shell=False, cwd=str(cwd), stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, pass_fds=((child_control.fileno(),) if staged_plan is None
                                    else (child_control.fileno(), staged_plan.source_fd)),
                                env={"PATH": os.defpath, "LANG": "C.UTF-8"})
        if native_plan is not None:
            from .cuda_process import NativeCudaTracer
            native_tracer = NativeCudaTracer(native_plan, limits, emit)
            native_tracer.attach_created_child(proc.pid)
        child_control.close()
        child_control = None
        proc.stdin.write(json.dumps(config, sort_keys=True, separators=(",", ":")).encode("ascii"))
        proc.stdin.close()
        observation["process_identity"] = _process_identity(proc.pid)
        emit("WORKER_CHILD_STARTED", **observation["process_identity"])
        selector = selectors.DefaultSelector()
        for name in ("stdout", "stderr"):
            stream = getattr(proc, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        selector.register(parent_control, selectors.EVENT_READ, "control")
        state = "STARTING"
        stop_deadline = None
        while True:
            collect_parent()
            if sink_failed and stop_deadline is None:
                state = "CAPTURE_FAILED"
                kill_owned_group("lifecycle journal failed")
                stop_deadline = time.monotonic() + 2
            try:
                cancelled = _cancel_requested(cancellation_file, request_id=request_id, run_id=run_id, nonce=nonce)
            except (OSError, ValueError) as exc:
                cancelled = False
                message = "CANCEL_RECORD_REJECTED: " + str(exc)
                if message not in observation["diagnostics"]:
                    observation["diagnostics"].append(message)
            if cancelled and stop_deadline is None:
                observation["cancelled"] = True
                state = "CANCELLED"
                kill_owned_group("bound cancellation request")
                stop_deadline = time.monotonic() + 2
            if time.monotonic() >= process_deadline and stop_deadline is None:
                observation["timed_out"] = True
                state = "TIMED_OUT"
                kill_owned_group("wall-clock deadline")
                stop_deadline = time.monotonic() + 2
            if finished and stop_deadline is None:
                if not ready or (native_plan is not None and not native_tracer.native_started):
                    state = "START_FAILED"
                elif native_tracer is not None and native_tracer.resource_limit_hit:
                    state = "RESOURCE_LIMIT"
                    observation["diagnostics"].append("Native tracee CPU boundary: SIGKILL and wait4 CPU use at configured per-process limit; cause not separately kernel-attested")
                elif observation["returncode"] == 0:
                    state = "COMPLETED"
                elif (fixture_id == "p2b-cpu-limit-v1"
                      and observation["linux_signal"] == signal.SIGKILL
                      and observation["resource_usage"] is not None
                      and sum(observation["resource_usage"][key] for key in
                              ("user_cpu_seconds", "system_cpu_seconds"))
                      >= limits.cpu_seconds - 1 / os.sysconf("SC_CLK_TCK")):
                    state = "RESOURCE_LIMIT"
                    observation["diagnostics"].append(
                        "RLIMIT_CPU boundary: fixed CPU fixture SIGKILL, no parent termination request, "
                        "wait4 CPU usage within one observed SC_CLK_TCK tick of configured hard limit; "
                        "Linux wait status does not separately attest the kernel kill cause")
                else:
                    state = "NONZERO_EXIT"
                # A normal parent exit does not prove child pipes/groups empty.
                kill_owned_group("parent exited; collect all remaining fixed-action descendants")
                stop_deadline = time.monotonic() + 2
            for key, _ in selector.select(0.01):
                name = key.data
                try:
                    data = os.read(key.fd, 4096)
                except (OSError, ValueError) as exc:
                    observation["capture_failed"] = True
                    observation["diagnostics"].append("PIPE_READ_FAILED: " + str(exc))
                    selector.unregister(key.fileobj)
                    if stop_deadline is None:
                        state = "CAPTURE_FAILED"
                        kill_owned_group("pipe read failed")
                        stop_deadline = time.monotonic() + 2
                    continue
                if not data:
                    selector.unregister(key.fileobj)
                    if name == "control" and control_buffer:
                        raise OSError("private control message was truncated")
                    continue
                if name != "control":
                    remaining = limits.max_output_bytes - sum(len(value) for value in chunks.values())
                    chunks[name].extend(data[:max(0, remaining)])
                    if len(data) > remaining:
                        observation["truncated"] = True
                        if state not in {"TIMED_OUT", "CANCELLED", "CAPTURE_FAILED", "CLEANUP_FAILED"}:
                            state = "RESOURCE_LIMIT"
                        if stop_deadline is None:
                            kill_owned_group("aggregate output limit")
                            stop_deadline = time.monotonic() + 2
                    continue
                control_buffer.extend(data)
                if len(control_buffer) > 16384:
                    raise OSError("private control channel exceeded fixed protocol bound")
                while b"\n" in control_buffer:
                    line, _, tail = control_buffer.partition(b"\n")
                    control_buffer[:] = tail
                    proof = json.loads(line)
                    if stop_deadline is not None:
                        # A READY message may already be buffered when a scoped
                        # cancellation/deadline kills the guard. Never inspect a
                        # dead executable or release GO after termination began.
                        emit("CONTROL_MESSAGE_AFTER_STOP", message=proof)
                        continue
                    if (proof.get("event") == "STAGED_SOURCE_READY" and staged_plan is not None
                            and not staged_ready and not ready):
                        staged_plan.verify_proof(proof, request_id=request_id, run_id=run_id,
                            nonce=nonce, pid=proc.pid)
                        staged_ready = True
                        emit("STAGED_SOURCE_READY", **proof)
                    elif proof.get("event") == "RESOURCE_READY" and not ready:
                        if staged_plan is not None and not staged_ready:
                            raise OSError("resource gate arrived without the received-file identity proof")
                        if set(proof) != {"event", "request_id", "nonce", "pid", "pgid", "session_id",
                                          "start_ticks", "cpu_seconds", "memory_bytes", "parent_pid",
                                          "parent_death_signal"}:
                            raise OSError("invalid private resource proof structure")
                        observed = _process_identity(proc.pid)
                        if not _same_process(observed, observation["process_identity"]):
                            raise OSError("child process identity changed during startup")
                        for name in ("pid", "pgid", "session_id", "start_ticks"):
                            if type(proof.get(name)) is not int or proof.get(name) != observed[name]:
                                raise OSError("private resource proof disagrees with /proc identity")
                        if (proof.get("request_id") != request_id or proof.get("nonce") != nonce
                                or type(proof.get("parent_pid")) is not int
                                or proof.get("parent_pid") != os.getpid()
                                or type(proof.get("parent_death_signal")) is not int
                                or proof.get("parent_death_signal") != signal.SIGKILL
                                or type(proof.get("cpu_seconds")) is not int
                                or type(proof.get("memory_bytes")) is not int
                                or proof.get("cpu_seconds") != limits.cpu_seconds
                                or proof.get("memory_bytes") != limits.memory_bytes):
                            raise OSError("private resource proof disagrees with requested limits")
                        executed = measure_tool_identity(str(Path("/proc") / str(proc.pid) / "exe"), cwd=cwd,
                                                         source="kernel /proc child executable bytes before fixed action GO")
                        observation["actual_tool_identity"] = executed.model_dump(mode="json")
                        if (executed.status != "OBSERVED" or executed.resolved_path != actual.resolved_path
                                or executed.file_sha256 != actual.file_sha256):
                            state = "REJECTED"
                            raise OSError("actual child executable identity mismatched before fixed action")
                        observation["actual_tool_identity"] = executed.model_dump(mode="json")
                        observation["resource_limits_applied"] = {
                            "wall_time_seconds": limits.wall_time_seconds,
                            "cpu_seconds": limits.cpu_seconds, "memory_bytes": limits.memory_bytes,
                            "max_output_bytes": limits.max_output_bytes,
                            "process_scope": "POSIX_PROCESS_GROUP", "rlimit_cpu": [limits.cpu_seconds] * 2,
                            "rlimit_as": [limits.memory_bytes] * 2,
                            "parent_death_signal": "SIGKILL", "gpu_vram_limit": "NOT_IMPLEMENTED", "network_isolation": "NOT_IMPLEMENTED",
                            "cgroup_limits": "NOT_IMPLEMENTED"}
                        emit("RESOURCE_READY", **proof)
                        if sink_failed:
                            raise OSError("lifecycle journal failed before fixed action GO")
                        if time.monotonic() >= process_deadline:
                            observation["timed_out"] = True
                            state = "TIMED_OUT"
                            kill_owned_group("deadline expired while validating the action gate")
                            raise OSError("wall-clock deadline expired before fixed action GO")
                        if _cancel_requested(cancellation_file, request_id=request_id, run_id=run_id, nonce=nonce):
                            observation["cancelled"] = True
                            state = "CANCELLED"
                            kill_owned_group("bound cancellation received while validating the action gate")
                            raise OSError("bound cancellation received before fixed action GO")
                        parent_control.sendall(b"GO\n")
                        ready = True
                        if native_plan is None:
                            state = "RUNNING"
                            emit("RUNNING", pid=proc.pid)
                    elif proof.get("event") == "NATIVE_UNSUPPORTED" and native_plan is not None:
                        if (set(proof) != {"event", "reason", "request_id", "nonce"}
                                or proof.get("request_id") != request_id or proof.get("nonce") != nonce):
                            raise OSError("native unsupported message has a different request identity")
                        state = "UNSUPPORTED"
                        observation["diagnostics"].append("NATIVE_SETUP_UNSUPPORTED: " + str(proof["reason"]))
                        kill_owned_group("native enforcement setup unsupported")
                        stop_deadline = time.monotonic() + 2
                    elif proof.get("event") == "CHILD_CREATED" and ready:
                        if (set(proof) != {"event", "request_id", "nonce", "pid"}
                                or proof.get("request_id") != request_id or proof.get("nonce") != nonce):
                            raise OSError("descendant control message identity disagrees with the run")
                        child_pid = proof.get("pid")
                        if type(child_pid) is not int or child_pid <= 0:
                            raise OSError("invalid descendant identity on private channel")
                        child = _process_identity(child_pid)
                        if (child["pgid"] != proc.pid or child["session_id"] != proc.pid
                                or child["uid"] != os.getuid()):
                            raise OSError("descendant identity escaped the fixed-action group")
                        emit("DESCENDANT_OBSERVED", **child)
                    else:
                        raise OSError("unknown or out-of-order private resource message")
            collect_parent()
            if finished and not selector.get_map() and stop_deadline is not None:
                break
            if stop_deadline is not None and time.monotonic() >= stop_deadline:
                if selector.get_map():
                    observation["capture_failed"] = True
                    observation["diagnostics"].append("PIPE_EOF_NOT_CONFIRMED")
                break
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        if native_plan is not None and getattr(exc, "execution_state", None) is not None:
            state = exc.execution_state
            if native_tracer is not None and native_tracer.native_started and state in {"REJECTED", "UNSUPPORTED"}:
                state = "UNKNOWN"
        observation["diagnostics"].append(type(exc).__name__ + ": " + str(exc))
        if proc is not None:
            if state not in {"REJECTED", "TIMED_OUT", "CANCELLED", "RESOURCE_LIMIT", "UNSUPPORTED", "UNKNOWN", "CAPTURE_FAILED"}:
                state = "CAPTURE_FAILED" if ready else "START_FAILED"
            observation["capture_failed"] = True
            kill_owned_group("startup or capture exception")
    finally:
        if proc is not None:
            # Independent group scan/reap continues even if pipes or the parent
            # have disappeared. Zombies are not described as cleaned up.
            cleanup_deadline = time.monotonic() + 2
            while time.monotonic() < cleanup_deadline:
                try:
                    collect_parent()
                except OSError as exc:
                    cleanup_error = True
                    observation["diagnostics"].append("NATIVE_REAP_FAILED: " + str(exc))
                    kill_owned_group("native reaping observation failure")
                try:
                    members = _group_members(proc.pid, proc.pid)
                    for member in members:
                        if member["pid"] == proc.pid or member["uid"] != os.getuid():
                            continue
                        if member["ppid"] == os.getpid():
                            try:
                                reaped, _ = os.waitpid(member["pid"], os.WNOHANG)
                                if reaped:
                                    observation["reaped_descendant_pids"].append(reaped)
                                    emit("DESCENDANT_REAPED", pid=reaped)
                            except ChildProcessError:
                                pass
                    members = _group_members(proc.pid, proc.pid)
                    if not members:
                        break
                    kill_owned_group("independent final group cleanup")
                except (OSError, ValueError):
                    cleanup_error = True
                    break
                time.sleep(0.01)
            check = inspect_cleanup(observation)
            observation["cleanup_status"] = check["status"]
            observation["remaining_pids"] = check["remaining_pids"]
            if (cleanup_error or check["status"] != "CONFIRMED"
                    or not observation["parent_reaped"]):
                observation["cleanup_status"] = "UNKNOWN" if check["status"] == "UNKNOWN" else "FAILED"
                state = "CLEANUP_FAILED"
            emit("CLEANUP_CHECKED", **check)
        if selector is not None:
            selector.close()
        for endpoint in (parent_control, child_control):
            if endpoint is not None:
                endpoint.close()
        if proc is not None:
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        if subreaper_before is not None:
            try:
                _set_subreaper(subreaper_before)
            except OSError:
                observation["diagnostics"].append("SUBREAPER_RESTORE_FAILED")
                observation["cleanup_status"] = "UNKNOWN"
                state = "CLEANUP_FAILED"
        if observation["capture_failed"] and state in {"COMPLETED", "NONZERO_EXIT", "RUNNING"}:
            state = "CAPTURE_FAILED"
        observation["finished_at"] = _utc()
        observation["duration_seconds"] = time.monotonic() - began
        observation["state"] = state
        for name, data in chunks.items():
            observation[name + "_b64"] = base64.b64encode(data).decode("ascii")
            observation[name + "_sha256"] = _sha(data)
        emit("PROCESS_FINISHED", state=state)
        if observation["capture_failed"] and state in {"COMPLETED", "NONZERO_EXIT", "RUNNING"}:
            state = "CAPTURE_FAILED"
            observation["state"] = state
    identity = observation["process_identity"]
    enforced = observation["resource_limits_applied"] is not None
    cgroup = observation["cgroup_assessment"]
    resource_model = ResourceObservation
    process_model = ProcessObservation
    if native_plan is not None:
        from .models.lifecycle import CudaProcessObservation, CudaResourceObservation
        resource_model, process_model = CudaResourceObservation, CudaProcessObservation
    resources = resource_model(
        status="ENFORCED" if enforced else ("UNKNOWN" if proc is not None else
                                            ("UNSUPPORTED" if state == "UNSUPPORTED" else "NOT_STARTED")),
        wall_watchdog=enforced, output_cap=enforced, process_group=enforced,
        cpu_seconds=limits.cpu_seconds if enforced else None,
        memory_bytes=limits.memory_bytes if enforced else None,
        verification_source=("private guard socket, kernel ptrace exec/fork stops and /proc limits, per-process CPU/AS, EXITKILL" if native_plan is not None else
                             "private child control socket, independent /proc executable identity, trusted fixed guard getrlimit"),
        cgroup_v2_status={"OBSERVED": "OBSERVED_NOT_USED", "UNSUPPORTED": "UNAVAILABLE"}.get(cgroup["status"], "NOT_CHECKED"),
        cgroup_v2_detail=cgroup["reason"])
    descendants = sorted({event["details"]["pid"] for event in observation["events"]
                          if event["event"] == "DESCENDANT_OBSERVED"})
    cleanup = CleanupObservation(
        status=observation["cleanup_status"],
        termination_method="SIGKILL" if observation["termination_method"] == "SIGKILL_PROCESS_GROUP" else "NONE",
        parent_reaped=observation["parent_reaped"],
        group_absent=observation["cleanup_status"] == "CONFIRMED",
        descendants_absent=observation["cleanup_status"] == "CONFIRMED",
        checked_at=observation["finished_at"],
        source="wait4 direct child, Linux subreaper waitpid descendants, independent /proc group/session absence scan",
        observed_descendant_pids=descendants, remaining_pids=observation["remaining_pids"],
        diagnostics=[message for message in observation["diagnostics"] if "REAP" in message or "TERMINATION" in message])
    resource_reason = None
    if observation["truncated"]:
        resource_reason = "aggregate stdout/stderr output exceeded the configured retained byte cap"
    elif state == "RESOURCE_LIMIT":
        resource_reason = ("RLIMIT_CPU boundary inferred from traced process SIGKILL and wait4 CPU usage; wait status alone does not uniquely establish the kill cause"
                           if native_plan is not None else
                           "RLIMIT_CPU boundary: fixed CPU action SIGKILL with wait4 CPU usage within one kernel accounting tick of configured hard limit")
    native_started = native_tracer is not None and native_tracer.native_started
    payload = {"started": proc is not None, "action_started": ready if native_plan is None else native_started,
               "argv": observation["argv"] if native_plan is None else native_plan.argv,
               "cwd": str(cwd), "target_environment": target_environment,
               "tool_identity": ((observation["actual_tool_identity"] or expected.model_dump(mode="json")) if native_plan is None else
                                  native_tracer.actual_tool_identity if native_started else native_plan.expected),
               "pid": (None if proc is None else proc.pid) if identity is None else identity["pid"],
               "pgid": None if identity is None else identity["pgid"],
               "session_id": None if identity is None else identity["session_id"],
               "start_ticks": None if identity is None else identity["start_ticks"],
               "worker_pid": os.getpid(),
               "started_at": native_started_at if proc is not None else None,
               "finished_at": observation["finished_at"], "duration_seconds": observation["duration_seconds"],
               "returncode": observation["returncode"], "linux_signal": observation["linux_signal"],
               "timed_out": observation["timed_out"], "cancelled": observation["cancelled"],
               "truncated": observation["truncated"], "capture_failed": observation["capture_failed"],
               "resource_limit_reason": resource_reason, "resource_limits": limits,
               "resources": resources, "cleanup": cleanup, "diagnostics": observation["diagnostics"]}
    if native_plan is not None:
        payload.update(launcher_tool_identity=launcher_identity or expected,
                       ppid=None if identity is None else identity["ppid"],
                       started_monotonic_ns=int(began * 1000000000), finished_monotonic_ns=time.monotonic_ns(),
                       launcher_argv=observation["argv"],
                       actual_tool_identity=None if native_tracer is None else native_tracer.actual_tool_identity,
                       descendant_identities=[] if native_tracer is None else native_tracer.records)
    if "uid" in process_model.model_fields:
        payload["uid"] = None if identity is None else identity["uid"]
        payload["gid"] = None if identity is None else identity["gid"]
    if "resource_usage" in process_model.model_fields:
        payload["resource_usage"] = observation["resource_usage"]
    if "cpu_usage_seconds" in process_model.model_fields:
        usage = observation["resource_usage"]
        payload["cpu_usage_seconds"] = None if usage is None else usage["user_cpu_seconds"] + usage["system_cpu_seconds"]
    for name in ("stdout", "stderr"):
        raw = bytes(chunks[name])
        payload[name + "_b64"] = base64.b64encode(raw).decode("ascii")
        payload[name + "_sha256"] = _sha(raw)
        payload[name + "_size_bytes"] = len(raw)
    return RegisteredProcessOutcome(state=state, process=process_model.model_validate(payload), observation=observation)
