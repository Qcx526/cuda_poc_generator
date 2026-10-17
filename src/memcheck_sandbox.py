"""Standalone, measured fixed-task guard copied into a minimal bwrap filesystem.

Only the trusted worker writes /config.json. No user source, shell or free argv
is accepted here. The two registered C inputs are never CVE reproductions.
"""

import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import time


def dump_new(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    path = Path(path)
    temporary = path.with_name("." + path.name + ".pending")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.link(temporary, path, follow_symlinks=False)
    temporary.unlink()


def sha_file(path):
    with open(path, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise ValueError("nonregular or privileged executable/input")
        h = hashlib.sha256()
        for block in iter(lambda: stream.read(1048576), b""):
            h.update(block)
        after = os.fstat(stream.fileno())
    fingerprint = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
    if fingerprint(before) != fingerprint(after):
        raise ValueError("file changed during byte measurement")
    return h.hexdigest()


def proc_identity(pid):
    raw = Path(f"/proc/{pid}/stat").read_text()
    fields = raw[raw.rfind(")") + 2:].split()
    return {"pid": pid, "ppid": int(fields[1]), "pgid": int(fields[2]),
            "session_id": int(fields[3]), "start_ticks": int(fields[19])}


def proc_limits(pid):
    text = Path(f"/proc/{pid}/limits").read_text()
    result = {}
    for label, key in (("Max cpu time", "cpu_seconds"), ("Max address space", "memory_bytes"),
                       ("Max file size", "max_file_bytes"), ("Max open files", "max_open_files"),
                       ("Max core file size", "core_bytes")):
        line = next(x for x in text.splitlines() if x.startswith(label))
        values = line[len(label):].split()
        result[key] = [int(values[0]), int(values[1])]
    return result


def main():
    import resource
    config = json.loads(Path("/config.json").read_bytes())
    expected = {"schema_version", "request_id", "run_id", "nonce", "step_id", "task_id", "source_sha256",
                "executable_sha256", "tools", "allowed_images", "limits", "outer_namespaces"}
    if set(config) != expected or config["schema_version"] != "1.0":
        raise ValueError("invalid fixed guard configuration")
    tasks = {"p3c-normal-v1": "430cb14334f368538ab36462b8956ab42b9727d7b0a10663c0196f4b8445e107",
             "p3c-invalid-write-v1": "d69b5329039d1548c977ee3e86e8a895e9b79e10585a1bc09ca08817cd56ef7c"}
    if tasks.get(config["task_id"]) != config["source_sha256"] or sha_file("/input/fixture.c") != config["source_sha256"]:
        raise ValueError("fixed reviewed source identity mismatch")
    for key in ("request_id", "run_id", "nonce"):
        if len(config[key]) != 32 or any(c not in "0123456789abcdef" for c in config[key]):
            raise ValueError("invalid task identity")
    limits = config["limits"]
    if (limits["resource_profile"] != "P3D_FIXED_CPU_MEMCHECK_V1" or not 1 <= limits["cpu_seconds"] <= 30
            or not 1073741824 <= limits["memory_bytes"] <= 8589934592):
        raise ValueError("unsupported fixed CPU resource profile")
    for kind, key in ((resource.RLIMIT_CPU, "cpu_seconds"), (resource.RLIMIT_AS, "memory_bytes"),
                      (resource.RLIMIT_FSIZE, "max_file_bytes"), (resource.RLIMIT_NOFILE, "max_open_files"),
                      (resource.RLIMIT_CORE, "core_bytes")):
        resource.setrlimit(kind, (limits[key], limits[key]))
        if resource.getrlimit(kind) != (limits[key], limits[key]):
            raise ValueError("required resource bound not applied")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(39, 0, 0, 0, 0) != 1:
        raise OSError("no_new_privs unavailable")
    parent = os.getppid()
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        raise OSError("parent-death signal unavailable")
    namespaces = {key: os.readlink("/proc/self/ns/" + key) for key in ("user", "mnt", "net", "pid", "ipc", "uts")}
    boundaries = {"private_" + key: namespaces[key] != config["outer_namespaces"][key] for key in namespaces}
    boundaries["host_paths_absent"] = all(not Path(p).exists() for p in ("/home", "/mnt", "/root", "/sys"))
    boundaries["gpu_devices_absent"] = all(not Path(p).exists() for p in ("/dev/nvidia0", "/dev/nvidiactl", "/dev/dri"))
    boundaries["no_new_privs"] = True
    try:
        fd = os.open("/input/fixture.c", os.O_WRONLY)
    except OSError as exc:
        boundaries["source_readonly"] = exc.errno in (errno.EROFS, errno.EACCES)
    else:
        os.close(fd)
        boundaries["source_readonly"] = False
    if not all(boundaries.values()):
        raise ValueError("required sandbox boundary was not observed")
    tools = config["tools"]
    step = config["step_id"]
    if step == "compile":
        argv = [tools["compiler"]["resolved_path"], "-std=c11", "-g", "-O0", "-Wall", "-Wextra",
                "-fno-omit-frame-pointer", "/input/fixture.c", "-o", "/out/fixture.bin"]
    elif step == "memcheck":
        if sha_file("/target/fixture.bin") != config["executable_sha256"]:
            raise ValueError("compiled target identity mismatch")
        try:
            fd = os.open("/target/fixture.bin", os.O_WRONLY)
        except OSError as exc:
            boundaries["target_readonly"] = exc.errno in (errno.EROFS, errno.EACCES)
        else:
            os.close(fd)
            raise ValueError("compiled target is writable")
        argv = [tools["valgrind_launcher"]["resolved_path"], "--tool=memcheck", "--xml=yes",
                "--xml-file=/out/memcheck.xml", "/target/fixture.bin"]
    else:
        raise ValueError("unregistered fixed diagnostic step")
    tool_fd = os.open(argv[0], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    if sha_file(f"/proc/self/fd/{tool_fd}") != config["allowed_images"].get(argv[0]):
        raise ValueError("pinned launcher hash mismatch")
    ready = {"schema_version": "1.0", "request_id": config["request_id"], "run_id": config["run_id"],
             "nonce": config["nonce"], "step_id": step, **proc_identity(os.getpid()),
             "limits": proc_limits(os.getpid()), "namespaces": namespaces, "boundaries": boundaries,
             "source_sha256": config["source_sha256"], "argv": argv}
    ready["guard_python_image"] = {"path":os.readlink("/proc/self/exe"),"sha256":sha_file("/proc/self/exe")}
    if ready["guard_python_image"] != {"path":tools["guard_python"]["resolved_path"],"sha256":tools["guard_python"]["file_sha256"]}:
        raise ValueError("actual sandbox Python image differs from the measured guard interpreter")
    dump_new("/control/ready.json", ready)
    deadline = time.monotonic() + limits["wall_time_seconds"]
    while not Path("/control/go.json").exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("trusted resource/identity gate not granted")
        time.sleep(0.01)
    gate = json.loads(Path("/control/go.json").read_bytes())
    if gate != {"request_id": config["request_id"], "run_id": config["run_id"], "nonce": config["nonce"], "action": "GO"}:
        raise ValueError("trusted gate identity mismatch")
    trace_path = Path("/control/trace.jsonl")
    trace_fd = os.open(trace_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    events, known, stopped, main_exit = [], {}, set(), None
    trace_options = 0x2 | 0x4 | 0x8 | 0x10 | 0x00100000
    def ptrace(op, pid, data=0):
        ctypes.set_errno(0)
        if libc.ptrace(op, pid, 0, data) == -1:
            raise OSError(ctypes.get_errno(), "fixed trace operation failed")
    def emit(kind, pid, **detail):
        event = {"event": kind, "pid": pid, "monotonic_ns": time.monotonic_ns(), **detail}
        if len(events) >= 512:
            raise ValueError("fixed diagnostic trace event bound exceeded")
        events.append(event)
        os.write(trace_fd, (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode())
        os.fsync(trace_fd)
    def image_event(kind, pid):
        identity = proc_identity(pid)
        image = os.readlink(f"/proc/{pid}/exe")
        digest = sha_file(f"/proc/{pid}/exe")
        if config["allowed_images"].get(image) != digest:
            raise ValueError("unexpected native executable at stopped exec: " + image)
        observed = proc_limits(pid)
        if any(observed[key] != [limits[key], limits[key]] for key in observed):
            raise ValueError("native process did not inherit exact required resource bounds")
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        if len(cmdline) > 65536:
            raise ValueError("native argv exceeds fixed bound")
        emit(kind, pid, identity=identity, image_path=image, image_sha256=digest,
             argv=[x.decode("utf-8", "strict") for x in cmdline.rstrip(b"\0").split(b"\0")], limits=observed)
    child = os.fork()
    if child == 0:
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != ready["pid"]:
            os._exit(120)
        if libc.ptrace(0, 0, 0, 0) != 0:
            os._exit(121)
        os.execve(tool_fd, argv, {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TMPDIR": "/tmp"})
    known[child] = None
    error = None
    try:
        while known:
            if time.monotonic() >= deadline:
                raise TimeoutError("inner fixed diagnostic deadline")
            progressed = False
            for pid in tuple(known):
                try:
                    found, status, usage = os.wait4(pid, os.WNOHANG | 0x40000000)
                except ChildProcessError:
                    continue
                if not found:
                    continue
                progressed = True
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    code = os.waitstatus_to_exitcode(status)
                    emit("REAPED", pid, returncode=code, cpu_seconds=usage.ru_utime + usage.ru_stime)
                    known.pop(pid)
                    stopped.discard(pid)
                    if pid == child:
                        main_exit = code
                    continue
                if not os.WIFSTOPPED(status):
                    raise ValueError("unsupported native wait state")
                stopped.add(pid)
                sig, event = os.WSTOPSIG(status), status >> 16
                if known[pid] is None:
                    known[pid] = proc_identity(pid)
                    ptrace(0x4200, pid, trace_options)
                    image_event("EXEC" if pid == child else "CHILD_STOP", pid)
                elif event in (1, 2, 3):
                    value = ctypes.c_ulong()
                    ptrace(0x4201, pid, ctypes.byref(value))
                    if len(known) >= limits["max_tracees"]:
                        raise ValueError("fixed native descendant bound exceeded")
                    known[value.value] = None
                    emit("FORK", pid, child_pid=value.value)
                elif event == 4:
                    image_event("EXEC", pid)
                delivered = 0 if event or sig in (signal.SIGSTOP, signal.SIGTRAP) else sig
                ptrace(7, pid, delivered)
                stopped.discard(pid)
            if not progressed:
                time.sleep(0.001)
    except Exception as exc:
        error = type(exc).__name__ + ":" + str(exc)
    finally:
        for pid in tuple(known):
            try:
                os.kill(pid, signal.SIGKILL)
                if pid in stopped:
                    ptrace(7, pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        reap_deadline = time.monotonic() + 2
        while known and time.monotonic() < reap_deadline:
            for pid in tuple(known):
                try:
                    found, status = os.waitpid(pid, os.WNOHANG | 0x40000000)
                except ChildProcessError:
                    known.pop(pid, None)
                    continue
                if found and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                    emit("REAPED", pid, returncode=os.waitstatus_to_exitcode(status))
                    known.pop(pid, None)
            time.sleep(0.005)
        os.close(trace_fd)
        os.close(tool_fd)
    result = {"schema_version": "1.0", "request_id": config["request_id"], "run_id": config["run_id"],
              "nonce": config["nonce"], "step_id": step, "guard_pid": ready["pid"],
              "child_pid": child, "returncode": main_exit, "linux_signal": -main_exit if main_exit is not None and main_exit < 0 else None,
              "error": error, "remaining_pids": sorted(known), "all_tracees_reaped": not known,
              "source_sha256": config["source_sha256"], "executable_sha256": config["executable_sha256"],
              "argv": argv, "finished_monotonic_ns": time.monotonic_ns()}
    dump_new("/control/result.json", result)
    if error or known or main_exit is None:
        return 125
    return main_exit if main_exit >= 0 else 128 - main_exit


if __name__ == "__main__":
    try:
        code = main()
    except Exception as exc:
        try:
            dump_new("/control/guard_failure.json", {"error": type(exc).__name__, "message": str(exc)})
        finally:
            raise
    raise SystemExit(code)
