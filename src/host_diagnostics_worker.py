"""Fixed, standard-library-only version queries; never accepts program input.

This source is shipped verbatim to a selected Linux Python interpreter. It has
no request fields for commands, files to parse, working directories or scripts.
"""

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import subprocess
import sys
import time
import uuid


TOOLS = ("valgrind", "gdb", "cuobjdump", "nvdisasm")


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _identity(path, requested):
    result = {"requested_executable": requested, "resolved_path": None,
              "status": "UNKNOWN", "file_sha256": None,
              "source": "fixed diagnostic version worker executable byte measurement"}
    try:
        resolved = Path(path).resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            return result
        with resolved.open("rb") as stream:
            before = os.fstat(stream.fileno())
            checksum = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1048576), b""):
                checksum.update(chunk)
            after, current = os.fstat(stream.fileno()), resolved.stat()
        keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        stamp = lambda stat: tuple(getattr(stat, key) for key in keys)
        if stamp(before) != stamp(after) or stamp(before) != stamp(current):
            return result
        result.update(resolved_path=str(resolved), status="OBSERVED", file_sha256=checksum.hexdigest())
    except (OSError, RuntimeError):
        pass
    return result


def _find(name):
    # No PATH, environment CUDA roots, shell, or caller-supplied paths. The
    # conventional active Toolkit symlink is measured through its real file.
    choices = [Path("/usr/bin") / name]
    if name in {"cuobjdump", "nvdisasm"}:
        choices += [Path("/usr/local/cuda/bin") / name]
    for choice in choices:
        identity = _identity(choice, name)
        if identity["status"] == "OBSERVED":
            return identity
    return _identity("/nonexistent-fixed-diagnostic-tool/" + name, name)


def _capture(identity, environment, platform_type):
    """A bounded version-only process group; no target parser input is passed."""
    argv = [identity["resolved_path"], "--version"]
    begin, start = time.monotonic(), datetime.now(timezone.utc).isoformat()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    maximum, timeout = 32768, 3.0
    timed_out = truncated = capture_failed = False
    process, code, started = None, None, False
    diagnostics = []
    selector = selectors.DefaultSelector()
    try:
        second = _identity(identity["resolved_path"], identity["requested_executable"])
        if second != identity:
            raise OSError("executable identity changed before launch")
        process = subprocess.Popen(argv, cwd="/", stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   shell=False, start_new_session=True,
                                   env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        started = True
        for name in output:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map() or process.poll() is None:
            if time.monotonic() - begin >= timeout:
                timed_out = True
                break
            for key, _ in selector.select(timeout=0.02):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                remaining = maximum - sum(len(raw) for raw in output.values())
                output[key.data].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    break
            if truncated:
                break
        if timed_out or truncated:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        code = process.wait(timeout=1)
    except (OSError, subprocess.SubprocessError) as exc:
        capture_failed = started
        diagnostics.append({"code": "VERSION_CAPTURE_FAILED", "message": type(exc).__name__})
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            try:
                code = process.wait(timeout=1)
            except subprocess.SubprocessError:
                code = None
    finally:
        selector.close()
        if process is not None:
            for name in output:
                getattr(process, name).close()
    after = _identity(identity["resolved_path"], identity["requested_executable"])
    if after != identity:
        diagnostics.append({"code": "TOOL_IDENTITY_CHANGED", "message": "Executable identity changed after the version query."})
    linux_signal = -code if code is not None and code < 0 else None
    if not started:
        status = "START_FAILED"
    elif timed_out:
        status = "TIMED_OUT"
    elif truncated:
        status = "OUTPUT_LIMIT"
    elif capture_failed or code is None:
        capture_failed, status = True, "CAPTURE_FAILED"
    elif linux_signal:
        status = "SIGNAL_TERMINATED"
    else:
        status = "NORMAL_EXIT" if code == 0 else "NONZERO_EXIT"
    raw = {name: bytes(value) for name, value in output.items()}
    value = {"schema_version": "1.0", "run_id": uuid.uuid4().hex,
             "argv": argv, "cwd": "/", "target_environment": environment,
             "platform_type": platform_type,
             "start_status": "STARTED" if started else "START_FAILED", "end_status": status,
             "returncode": code, "linux_signal": linux_signal, "windows_exception_code": None,
             "timed_out": timed_out, "truncated": truncated, "capture_failed": capture_failed,
             "started_at": start, "finished_at": datetime.now(timezone.utc).isoformat(),
             "duration_seconds": float(time.monotonic() - begin),
             "resource_limits": {"timeout_seconds": timeout, "max_output_bytes": maximum,
                                 "termination_scope": "POSIX_PROCESS_GROUP", "memory_bytes": None,
                                 "cpu_seconds": None, "memory_limit_status": "NOT_ENFORCED", "cpu_limit_status": "NOT_ENFORCED"},
             "stdin_sha256": None, "stdin_size_bytes": 0,
             "command_identity": {"source": "fixed read-only diagnostic registry --version-v1",
                                  "argv_sha256": _digest(json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))},
             "tool_identity": identity, "diagnostics": diagnostics,
             "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED",
             "evidence_directory": "worker-packet:inline-only"}
    for name in raw:
        value[name + "_b64"] = base64.b64encode(raw[name]).decode("ascii")
        value[name + "_sha256"] = _digest(raw[name])
    value["record_id"] = "sha256:" + _digest(_canonical({key: item for key, item in value.items() if key != "evidence_directory"}))
    return value, after


def probe(request):
    if set(request) != {"schema_version", "probe_id", "nonce", "backend", "environment_label", "worker_source_sha256"}:
        raise ValueError("unsupported diagnostic request")
    if request["schema_version"] != "1.0" or sys.platform != "linux":
        raise ValueError("only the fixed Linux read-only worker is supported")
    actual_wsl = "microsoft" in platform.release().lower()
    distro = os.environ.get("WSL_DISTRO_NAME") if actual_wsl else None
    environment = "wsl:" + (distro or "") if actual_wsl else "local"
    if request["backend"] == "wsl" and (not actual_wsl or environment != request["environment_label"] or not distro):
        raise ValueError("actual WSL target identity disagrees with the request")
    if request["backend"] not in {"local", "wsl"}:
        raise ValueError("unsupported backend")
    try:
        boot = Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()
        boot_digest = _digest(boot) if boot else None
    except OSError:
        boot_digest = None
    target = {"platform_type": "wsl" if actual_wsl else "linux", "environment_label": environment,
              "wsl_distribution": distro, "kernel": platform.release(), "architecture": platform.machine(),
              "boot_id_sha256": boot_digest}
    target["diagnostic_environment_id"] = "sha256:" + _digest(_canonical(target))
    tools = []
    for name in TOOLS:
        identity = _find(name)
        record, after = _capture(identity, environment, target["platform_type"]) if identity["status"] == "OBSERVED" else (None, None)
        tools.append({"tool_id": name, "identity": identity, "identity_after": after, "process": record})
    return {"schema_version": "1.0", "probe_id": request["probe_id"], "nonce": request["nonce"],
            "worker_source_sha256": request["worker_source_sha256"], "target": target, "tools": tools}


if __name__ == "__main__":
    sys.stdout.buffer.write(_canonical(probe(globals().get("PROBE_REQUEST", {}))) + b"\n")
