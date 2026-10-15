"""Fixed CUDA tool plans and Linux kernel-observed exec/fork lifecycle tracing.

No public function accepts argv, flags or source. Tracing is restricted to the
isolated child created by lifecycle_process and its kernel-reported descendants.
It is not a GPU sandbox or a complete toolchain supply-chain attestation.
"""

from dataclasses import dataclass
import ctypes
import hashlib
import os
from pathlib import Path
import re
import signal
import stat
import sys

from .cuda_guard import CUDA_GUARD_SOURCE
from .models.execution import CudaResourceLimits
from .models.tool_result import ToolIdentity
from .registered_actions import RegisteredAction
from .tools.process import measure_tool_identity


_ROLES = {"nvcc_version": "nvcc", "cuobjdump_version": "cuobjdump", "nvdisasm_version": "nvdisasm",
          "compile": "nvcc", "cuobjdump": "cuobjdump", "nvdisasm": "nvdisasm"}
_PTRACE_CONT = 7
_PTRACE_SETOPTIONS = 0x4200
_PTRACE_GETEVENTMSG = 0x4201
_TRACE_OPTIONS = 0x2 | 0x4 | 0x8 | 0x10 | 0x00100000  # FORK/VFORK/CLONE/EXEC/EXITKILL
_WAIT_ALL = 0x40000000


class CudaTraceError(OSError):
    def __init__(self, message, *, state="UNKNOWN"):
        super().__init__(message)
        self.execution_state = state


def _actual_image(pid):
    """Hash the kernel image handle, rather than resolving /proc back to a name."""
    proc_image = Path("/proc") / str(pid) / "exe"
    name = os.readlink(proc_image)
    if not name.startswith("/") or name.endswith(" (deleted)"):
        raise CudaTraceError("native executable path is unavailable or deleted", state="REJECTED")
    checksum = hashlib.sha256()
    with proc_image.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise CudaTraceError("native image is nonregular or privileged", state="REJECTED")
        for block in iter(lambda: stream.read(1048576), b""):
            checksum.update(block)
        after = os.fstat(stream.fileno())
    current = Path(name).stat()
    fingerprint = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if fingerprint(before) != fingerprint(after) or fingerprint(before) != fingerprint(current):
        raise CudaTraceError("native executable was replaced during measurement", state="REJECTED")
    return ToolIdentity(requested_executable=str(proc_image), resolved_path=name, status="OBSERVED",
                        file_sha256=checksum.hexdigest(),
                        source="Linux ptrace exec-stop kernel /proc image handle SHA-256 and current inode comparison")


def _read_limits(pid, limits):
    lines = (Path("/proc") / str(pid) / "limits").read_text(encoding="ascii").splitlines()
    observed = {}
    for label, key, maximum in (("Max cpu time", "cpu_seconds", limits.cpu_seconds),
                                 ("Max address space", "memory_bytes", limits.memory_bytes)):
        line = next((line for line in lines if line.startswith(label)), None)
        if line is None:
            raise CudaTraceError("native child resource limits unavailable")
        values = line[len(label):].split()
        if len(values) < 2 or not values[0].isdigit() or not values[1].isdigit():
            raise CudaTraceError("native child has an unbounded required resource limit", state="REJECTED")
        soft, hard = map(int, values[:2])
        if soft > maximum or hard > maximum or soft < 1:
            raise CudaTraceError("native child resource limits exceed authorized bounds", state="REJECTED")
        observed[key] = {"soft": soft, "hard": hard}
    return observed


def _helper_allowlist(tools, workspace):
    """Pin a narrow set of known installed compiler assistants before dispatch.

    Missing optional assistants remain unallowed; a later unexpected exec is a
    rejection before its first instruction, never an implicit PATH fallback.
    """
    result = {tool.resolved_path: tool.file_sha256 for role, tool in tools.items() if role != "guard_python"}
    toolkit = Path(tools["nvcc"].resolved_path).parent.parent
    candidates = [toolkit / value for value in ("bin/ptxas", "bin/fatbinary", "bin/nvlink", "bin/cudafe++",
                                               "bin/bin2c", "nvvm/bin/cicc")]
    candidates.extend(Path("/usr/bin") / name for name in
                      ("sh", "dash", "bash", "rm", "mkdir", "cat", "as", "ld", "ld.bfd"))
    host = Path(tools["host_compiler"].resolved_path)
    match = re.fullmatch(r"(?:(.+)-)?g\+\+-(\d+)", host.name)
    if match is not None:
        target, major = match.groups()
        target = target or "x86_64-linux-gnu"
        candidates.extend(Path("/usr/bin") / name for name in
                          (target + "-gcc-" + major, target + "-g++-" + major,
                           target + "-as", target + "-ld", target + "-ld.bfd"))
        candidates.extend(Path("/usr/lib/gcc") / target / major / name for name in
                          ("cc1", "cc1plus", "collect2", "lto1", "lto-wrapper"))
    for candidate in candidates:
        if not candidate.is_file():
            continue
        identity = measure_tool_identity(str(candidate), cwd=workspace,
                                         source="P2-C known compiler assistant identity pinned before native dispatch")
        if identity.status != "OBSERVED":
            raise CudaTraceError("known compiler assistant could not be measured", state="REJECTED")
        previous = result.setdefault(identity.resolved_path, identity.file_sha256)
        if previous != identity.file_sha256:
            raise CudaTraceError("conflicting toolchain assistant identity", state="REJECTED")
    return result


@dataclass(frozen=True)
class _NativePlan:
    step_id: str
    argv: list[str]
    tools: dict[str, ToolIdentity]
    allowed_images: dict[str, str]
    environment: dict[str, str]

    @property
    def expected(self):
        return self.tools[_ROLES[self.step_id]]

    def configuration(self):
        return {"tool_path": self.expected.resolved_path, "tool_sha256": self.expected.file_sha256,
                "argv": self.argv, "environment": self.environment}


class NativeCudaTracer:
    """Bounded ptrace state; every wait stop is distinguished from an exit."""

    def __init__(self, plan, limits, emit):
        self.plan, self.limits, self.emit = plan, limits, emit
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.ptrace.restype = ctypes.c_long
        self.main_pid = None
        self.known = {}
        self.stopped = set()
        self.native_started = False
        self.actual_tool_identity = None
        self.records = []
        self.main_exit = None
        self.resource_limit_hit = False
        self.polls = 0

    def attach_created_child(self, pid):
        self.main_pid = pid
        self.known[pid] = None

    def _ptrace(self, operation, pid, data=0):
        ctypes.set_errno(0)
        result = self.libc.ptrace(operation, pid, 0, data)
        if result == -1:
            raise CudaTraceError("ptrace operation failed: " + str(ctypes.get_errno()), state="UNSUPPORTED")
        return result

    def _record(self, event, pid, *, executable=False):
        from .lifecycle_process import describe_process_identity
        identity = describe_process_identity(pid)
        if (identity["pgid"] != self.main_pid or identity["session_id"] != self.main_pid
                or identity["uid"] != os.getuid() or identity["gid"] != os.getgid()):
            raise CudaTraceError("native descendant escaped its observed group/session/UID/GID", state="REJECTED")
        previous = self.known.get(pid)
        if previous is not None and previous["start_ticks"] != identity["start_ticks"]:
            raise CudaTraceError("traced native PID identity was reused", state="REJECTED")
        self.known[pid] = identity
        measured_limits = _read_limits(pid, self.limits)
        image = _actual_image(pid)
        if self.plan.allowed_images.get(image.resolved_path) != image.file_sha256:
            raise CudaTraceError("native helper path/hash is not in the measured known-assistant allowlist", state="REJECTED")
        if len(self.records) >= 512:
            raise CudaTraceError("native lifecycle event budget exceeded", state="REJECTED")
        raw_argv = (Path("/proc") / str(pid) / "cmdline").read_bytes()
        if len(raw_argv) > 65536:
            raise CudaTraceError("native command identity exceeds fixed bound", state="REJECTED")
        record = {"event": event, **identity, "tool_identity": image.model_dump(mode="json"),
                  "resource_limits": measured_limits,
                  "argv": [value.decode("utf-8", errors="replace") for value in raw_argv.rstrip(b"\0").split(b"\0")]}
        self.records.append(record)
        if not self.emit("NATIVE_" + event, **record):
            raise CudaTraceError("native identity evidence could not be persisted before tracee resume", state="CAPTURE_FAILED")
        if pid != self.main_pid:
            if not self.emit("DESCENDANT_OBSERVED", **identity):
                raise CudaTraceError("native descendant evidence unavailable before resume", state="CAPTURE_FAILED")
        return image

    def _resume(self, pid, delivered_signal=0):
        self._ptrace(_PTRACE_CONT, pid, delivered_signal)
        self.stopped.discard(pid)

    def poll(self):
        """Collect bounded kernel events and return the direct-child exit once."""
        for _ in range(64):
            progressed = False
            for pid in tuple(self.known):
                try:
                    waited, status, usage = os.wait4(pid, os.WNOHANG | _WAIT_ALL)
                except ChildProcessError:
                    # A kernel-reported fork child can be pending its initial
                    # trace stop; never turn this transient condition into exit.
                    continue
                if not waited:
                    continue
                progressed = True
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    code = os.waitstatus_to_exitcode(status)
                    cpu = usage.ru_utime + usage.ru_stime
                    if (code == -signal.SIGKILL and cpu >= self.limits.cpu_seconds - 1 / os.sysconf("SC_CLK_TCK")):
                        self.resource_limit_hit = True
                    self.emit("NATIVE_REAPED", pid=pid, returncode=code, cpu_usage_seconds=cpu)
                    self.known.pop(pid, None)
                    self.stopped.discard(pid)
                    if pid == self.main_pid:
                        self.main_exit = (pid, status, usage)
                    continue
                if not os.WIFSTOPPED(status):
                    raise CudaTraceError("unrecognized native wait status")
                self.stopped.add(pid)
                stop_signal, event = os.WSTOPSIG(status), status >> 16
                if pid == self.main_pid and not self.native_started and stop_signal == signal.SIGTRAP:
                    image = self._record("EXEC", pid, executable=True)
                    expected = self.plan.expected
                    if image.resolved_path != expected.resolved_path or image.file_sha256 != expected.file_sha256:
                        raise CudaTraceError("initial native tool image differs from the bound role identity", state="REJECTED")
                    self._ptrace(_PTRACE_SETOPTIONS, pid, _TRACE_OPTIONS)
                    self.actual_tool_identity = image
                    if not self.emit("TOOL_EXEC_READY", pid=pid, tool_identity=image.model_dump(mode="json")):
                        raise CudaTraceError("native exec evidence unavailable before first native instruction", state="CAPTURE_FAILED")
                    self._resume(pid)
                    self.native_started = True
                    self.emit("RUNNING", pid=pid)
                elif event in (1, 2, 3):
                    child = ctypes.c_ulong()
                    self._ptrace(_PTRACE_GETEVENTMSG, pid, ctypes.byref(child))
                    child_pid = child.value
                    if child_pid <= 0 or len(self.known) >= 128:
                        raise CudaTraceError("native descendant count or identity unsupported", state="REJECTED")
                    self.known.setdefault(child_pid, None)
                    self._record({1: "FORK", 2: "VFORK", 3: "CLONE"}[event], child_pid)
                    self._resume(pid)
                elif event == 4:
                    previous_tid = ctypes.c_ulong()
                    self._ptrace(_PTRACE_GETEVENTMSG, pid, ctypes.byref(previous_tid))
                    if previous_tid.value != pid and previous_tid.value in self.known:
                        self.known.pop(previous_tid.value)
                        self.stopped.discard(previous_tid.value)
                        self.known[pid] = None
                    self._record("EXEC", pid, executable=True)
                    self._resume(pid)
                elif stop_signal == signal.SIGSTOP:
                    self._record("CHILD_STOP", pid)
                    self._resume(pid)
                else:
                    # Preserve actual tool signal behavior. SIGCHLD, faults and
                    # debugger traps are not recategorized as vulnerability proof.
                    self._resume(pid, stop_signal)
            if not progressed:
                break
        result, self.main_exit = self.main_exit, None
        return result or (0, 0, None)

    def terminate_owned(self):
        """Kill only known tracees after comparing their observed start identity."""
        from .lifecycle_process import describe_process_identity
        for pid, previous in tuple(self.known.items()):
            try:
                current = describe_process_identity(pid)
                if previous is not None and current["start_ticks"] != previous["start_ticks"]:
                    raise CudaTraceError("refusing to signal a reused traced process")
                if current["uid"] != os.getuid():
                    raise CudaTraceError("refusing to signal a foreign traced process")
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def run_registered_cuda_tool(step_id, *, tools, arch, workspace, limits, target_environment,
                             request_id, run_id, nonce, cancellation_file=None, on_event=None,
                             expected_artifact_sha256=None):
    """Use the bounded lifecycle engine for one immutable CUDA step.

    The trusted worker must already have authorized and preflighted the task.
    An inspection hash must come from that worker's successful fixed-source
    compilation chain; the hash argument grants no execution authorization.
    """
    from .cuda_registry import (CUDA_SMOKE_SOURCE, build_cuda_step_argv,
                               observe_smoke_cubin)
    from .lifecycle_process import _run_controlled_action
    if step_id not in _ROLES:
        raise ValueError("unregistered CUDA step")
    limits = CudaResourceLimits.model_validate(limits.model_dump(mode="python")
                                               if isinstance(limits, CudaResourceLimits) else limits)
    if not isinstance(tools, dict) or set(tools) != {"nvcc", "cuobjdump", "nvdisasm", "host_compiler", "guard_python"}:
        raise ValueError("CUDA steps require the exact observed tool and guard roles")
    checked = {role: ToolIdentity.model_validate(value.model_dump(mode="python")
                                                if isinstance(value, ToolIdentity) else value)
               for role, value in tools.items()}
    if any(value.status != "OBSERVED" for value in checked.values()):
        raise ValueError("every CUDA tool role requires an observed identity")
    argv = build_cuda_step_argv(step_id, checked, arch, workspace)
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise CudaTraceError("native CUDA lifecycle requires Linux ptrace and /proc", state="UNSUPPORTED")
    workspace = Path(workspace)
    if os.name == "posix":
        for value in (workspace, *workspace.parents):
            if value.is_symlink():
                raise ValueError("controlled CUDA workspace cannot contain symlinks")
        info = workspace.stat()
        if not workspace.is_dir() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("CUDA workspace must be a private native Linux directory owned by the worker")
    if step_id == "compile":
        source = workspace / "safe_smoke.cu"
        output = workspace / "out" / "safe_smoke.cubin"
        if source.is_symlink() or not source.is_file() or source.stat().st_size != len(CUDA_SMOKE_SOURCE):
            raise CudaTraceError("fixed CUDA source is missing or changed", state="REJECTED")
        if source.read_bytes() != CUDA_SMOKE_SOURCE:
            raise CudaTraceError("fixed CUDA source bytes differ from the reviewed registry", state="REJECTED")
        if output.exists() or output.is_symlink():
            raise CudaTraceError("exclusive CUDA output already exists; overwrite forbidden", state="REJECTED")
    elif step_id in {"cuobjdump", "nvdisasm"}:
        if (not isinstance(expected_artifact_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", expected_artifact_sha256) is None):
            raise CudaTraceError("native inspection requires its bound fixed-source compiler artifact hash", state="REJECTED")
        observe_smoke_cubin(workspace / "out" / "safe_smoke.cubin", expected_sha256=expected_artifact_sha256)
    for role, expected in checked.items():
        actual = measure_tool_identity(expected.resolved_path, cwd=workspace,
                                       source="fresh fixed CUDA toolchain role identity before controlled step")
        if (actual.status != "OBSERVED" or actual.resolved_path != expected.resolved_path
                or actual.file_sha256 != expected.file_sha256):
            raise CudaTraceError("CUDA toolchain role identity changed before launch: " + role, state="REJECTED")
    temporary = workspace / "tmp"
    if temporary.exists():
        if temporary.is_symlink() or not temporary.is_dir() or stat.S_IMODE(temporary.stat().st_mode) != 0o700:
            raise ValueError("CUDA tool temporary directory is not private")
    else:
        temporary.mkdir(mode=0o700)
    environment = {"PATH": str(Path(checked["nvcc"].resolved_path).parent) + ":" +
                   str(Path(checked["host_compiler"].resolved_path).parent) + ":" + os.defpath,
                   "LANG": "C.UTF-8", "TMPDIR": str(temporary), "TEMP": str(temporary), "TMP": str(temporary)}
    plan = _NativePlan(step_id=step_id, argv=argv, tools=checked,
                       allowed_images=_helper_allowlist(checked, workspace), environment=environment)
    action = RegisteredAction("p2c-native-" + step_id, CUDA_GUARD_SOURCE, "", "fixed resource-gated CUDA native step")
    return _run_controlled_action(action, limits, expected_tool=checked["guard_python"], cwd=workspace,
                                  target_environment=target_environment, request_id=request_id, run_id=run_id,
                                  nonce=nonce, cancellation_file=cancellation_file, on_event=on_event,
                                  native_plan=plan)
