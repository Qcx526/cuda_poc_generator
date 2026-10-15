"""Internal, local-only argv runner; not a platform-probe command interface."""

import base64
from datetime import datetime, timezone
import hashlib
import math
import os
from pathlib import Path, PureWindowsPath
import platform
import re
import shutil
import signal
import subprocess
import threading
import time
from typing import Mapping, Sequence
import uuid

from ..models.tool_result import (ToolIdentity, ToolResult, classify_returncode, digest_argv,
                                  digest_bytes, seal_tool_result)
from ..tool_artifacts import prepare_tool_directory, write_tool_evidence


def current_platform_type() -> str:
    if os.name == "nt":
        return "windows"
    if "microsoft" in platform.release().lower():
        return "wsl"
    return "linux"


def canonical_target_environment(platform_type: str | None = None) -> str:
    """Name the current target, using the WSL launcher's actual distro label.

    WSL_DISTRO_NAME is local launcher metadata, not a hardware attestation. A
    configured request label cannot replace a missing or different local label.
    The caller must separately bind the snapshot and its independently selected
    Windows distribution. Plain Linux and Windows retain the local P1 label.
    """
    actual_platform = current_platform_type()
    if platform_type is not None and platform_type != actual_platform:
        raise ValueError("target identity cannot relabel the local platform")
    if actual_platform != "wsl":
        return "local"
    distro = os.environ.get("WSL_DISTRO_NAME", "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,127}", distro) or distro != distro.strip():
        raise ValueError("WSL target identity requires a valid observed WSL_DISTRO_NAME")
    return "wsl:" + distro


def _tool_identity(executable: str, cwd: Path, env: Mapping[str, str] | None, source: str):
    resolved = None
    digest = None
    try:
        path = Path(executable)
        if path.is_absolute() or any(separator in executable for separator in ("/", "\\")):
            selected = path if path.is_absolute() else cwd / path
            resolved = str(selected.resolve()) if selected.is_file() else None
        else:
            path_value = os.environ.get("PATH", "") if env is None else env.get("PATH", "")
            # Resolve relative PATH entries against the intended process cwd.
            paths = [str((cwd / value).resolve()) if not Path(value).is_absolute() else value
                     for value in path_value.split(os.pathsep) if value]
            resolved = shutil.which(executable, path=os.pathsep.join(paths))
            if resolved is not None:
                resolved = str(Path(resolved).resolve())
        if resolved is not None:
            checksum = hashlib.sha256()
            with open(resolved, "rb") as stream:
                before = os.fstat(stream.fileno())
                for block in iter(lambda: stream.read(1048576), b""):
                    checksum.update(block)
                after = os.fstat(stream.fileno())
                current = os.stat(resolved)
            # Refuse an observation made while the file was changing or replaced.
            # Windows fstat/stat can expose different creation/change-time values
            # for the same handle/path. Compare file identity, size and mtime;
            # never treat that API discrepancy as evidence of replacement.
            keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
            if os.name != "nt":
                # POSIX ctime also catches an in-place write whose mtime was
                # restored. Windows fstat/stat ctime are not comparable above.
                keys += ("st_ctime_ns",)
            fingerprint = lambda value: tuple(getattr(value, key) for key in keys)
            if fingerprint(before) == fingerprint(after) == fingerprint(current):
                digest = checksum.hexdigest()
    except (OSError, RuntimeError):
        # A failed read/resolve is an UNKNOWN measurement and never authorizes a
        # fallback executable lookup or launch.
        pass
    return {"requested_executable": executable, "resolved_path": resolved,
            "status": "OBSERVED" if digest is not None else "UNKNOWN",
            "file_sha256": digest, "source": source}


def measure_tool_identity(executable: str, *, cwd: str | Path | None = None,
                          env: Mapping[str, str] | None = None,
                          source: str = "local executable SHA-256 measurement") -> ToolIdentity:
    """Measure a local executable without launching it; failures stay UNKNOWN."""
    if not isinstance(executable, str) or not executable or "\0" in executable:
        raise ValueError("tool executable must be a nonempty string without NUL bytes")
    if not isinstance(source, str) or not source.strip():
        raise ValueError("tool identity source must not be blank")
    if env is not None and (not isinstance(env, Mapping) or any(not isinstance(key, str) or not isinstance(value, str)
                               or "\0" in key or "\0" in value or "=" in key for key, value in env.items())):
        raise ValueError("invalid tool measurement environment")
    directory = Path(os.getcwd() if cwd is None else cwd).resolve()
    return ToolIdentity.model_validate(_tool_identity(executable, directory, env, source))


def _validated_allowlist(value: Mapping[str, str] | None, actual_platform: str):
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("allowed tool identities must map absolute paths to SHA-256 digests")
    result = {}
    for path, digest in value.items():
        if not isinstance(path, str) or "\0" in path or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("allowed tool identity has an invalid path or SHA-256 digest")
        if not Path(path).is_absolute() or (actual_platform != "windows" and (PureWindowsPath(path).drive or "\\" in path)) or (actual_platform == "windows" and path.startswith("/")):
            raise ValueError("allowed tool identity requires an absolute native path")
        # Resolve trusted paths independently of the requested command's spelling.
        selected = os.path.normcase(str(Path(path).resolve()))
        if selected in result and result[selected] != digest:
            raise ValueError("conflicting allowed tool identities")
        result[selected] = digest
    return result


def run_tool(argv: Sequence[str], *, cwd: str | Path | None = None,
             target_environment: str = "local", platform_type: str | None = None,
             timeout_seconds: float = 30, max_output_bytes: int = 1048576,
             env: Mapping[str, str] | None = None, command_source: str = "internal tool adapter",
             tool_source: str = "local executable file SHA-256 before launch",
             artifact_root: str | Path | None = None, input_bytes: bytes | None = None,
             allowed_tool_identities: Mapping[str, str] | None = None,
             _startup_error: FileNotFoundError | None = None) -> ToolResult:
    """Run a local tool with shell=False and persist evidence for every outcome.

    No remote dispatch, candidate execution authorization, vulnerability judgment,
    CPU quota or memory quota is supplied by this helper. Every executable must
    be measurable; a supplied trusted allowlist additionally pins its path/hash.
    The second measurement reduces filesystem races, without claiming atomic
    OS-level executable attestation. Windows termination is
    limited to the direct child; P2 must provide stronger isolation independently.
    """
    if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes)) or not argv or any(not isinstance(value, str) or "\0" in value for value in argv) or not argv[0]:
        raise ValueError("tool argv must be a nonempty sequence of strings without NUL bytes")
    if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300:
        raise ValueError("tool timeout must be within (0,300] seconds")
    if type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 16777216:
        raise ValueError("tool output limit must be within [1,16777216] bytes")
    if input_bytes is not None and not isinstance(input_bytes, bytes):
        raise ValueError("tool input must be bytes")
    if _startup_error is not None and not isinstance(_startup_error, FileNotFoundError):
        raise ValueError("internal startup error must be a tool discovery FileNotFoundError")
    actual_platform = current_platform_type()
    if platform_type is not None and platform_type != actual_platform:
        raise ValueError("local runner cannot relabel the process as a foreign platform")
    if not isinstance(target_environment, str) or not target_environment.strip():
        raise ValueError("target environment identity must not be blank")
    canonical_environment = canonical_target_environment(actual_platform)
    allowed_environment = {"local", actual_platform, canonical_environment}
    if target_environment not in allowed_environment:
        raise ValueError("local runner cannot claim a foreign target environment")
    if actual_platform == "wsl":
        target_environment = canonical_environment
    allowlist = _validated_allowlist(allowed_tool_identities, actual_platform)
    if not isinstance(command_source, str) or not isinstance(tool_source, str) or not command_source.strip() or not tool_source.strip():
        raise ValueError("command and tool source identities must not be blank")
    if env is not None and (not isinstance(env, Mapping) or any(not isinstance(key, str) or not isinstance(value, str)
                               or "\0" in key or "\0" in value or "=" in key for key, value in env.items())):
        raise ValueError("invalid subprocess environment")
    if cwd is not None:
        supplied_cwd = str(cwd)
        if actual_platform != "windows" and (PureWindowsPath(supplied_cwd).drive or "\\" in supplied_cwd):
            raise ValueError("Linux/WSL cwd cannot use Windows drive or separator syntax")
        if actual_platform == "windows" and supplied_cwd.startswith("/"):
            raise ValueError("Windows cwd cannot use an absolute Linux/WSL path")
    directory = Path(os.getcwd() if cwd is None else cwd).resolve()
    selected_argv = list(argv)
    identity = (_tool_identity(selected_argv[0], directory, env, tool_source) if _startup_error is None else
                {"requested_executable": selected_argv[0], "resolved_path": None, "status": "UNKNOWN",
                 "file_sha256": None, "source": tool_source})
    if identity["resolved_path"] is not None:
        # Invoke precisely the executable whose bytes were hashed, independent of
        # platform-specific PATH lookup behavior. No authenticity/TOCTOU attestation.
        selected_argv[0] = identity["resolved_path"]
    run_id = uuid.uuid4().hex
    folder, protection = prepare_tool_directory(artifact_root, run_id)
    started_at = datetime.now(timezone.utc).isoformat()
    begin = time.monotonic()
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    lock = threading.Lock()
    output_limit = threading.Event()
    capture_failure = threading.Event()
    proc = None
    threads = []
    diagnostics = []
    timed_out = False
    returncode = None

    def read_stream(stream, name):
        try:
            while True:
                data = stream.read1(4096) if hasattr(stream, "read1") else stream.read(4096)
                if not data:
                    break
                with lock:
                    remaining = max_output_bytes - sum(map(len, chunks.values()))
                    chunks[name].extend(data[:max(0, remaining)])
                    if len(data) > remaining:
                        output_limit.set()
        except (OSError, ValueError):
            capture_failure.set()

    def send_input():
        try:
            proc.stdin.write(input_bytes)
            proc.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            pass

    def terminate_owned_process():
        if proc is None:
            return
        try:
            if actual_platform != "windows":
                os.killpg(proc.pid, signal.SIGKILL)
            elif proc.poll() is None:
                proc.kill()
        except (ProcessLookupError, OSError):
            pass

    try:
        if _startup_error is not None:
            # A failed resolver must never retry a guessed executable path that
            # happens to exist. Record the failed startup phase without Popen.
            raise _startup_error
        if identity["status"] != "OBSERVED":
            diagnostics.append({"code": "TOOL_IDENTITY_UNKNOWN", "message": "Executable file identity could not be measured; launch denied."})
            raise PermissionError("tool identity measurement failed; execution is forbidden")
        if allowlist is not None and allowlist.get(os.path.normcase(identity["resolved_path"])) != identity["file_sha256"]:
            diagnostics.append({"code": "TOOL_IDENTITY_NOT_ALLOWED", "message": "Executable path/hash is absent from the trusted allowlist; launch denied."})
            raise PermissionError("tool identity does not match the trusted allowlist")
        options = {"cwd": str(directory), "env": None if env is None else dict(env),
                   "shell": False, "stdin": subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                   "stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
        if actual_platform == "windows":
            options["creationflags"] = subprocess.CREATE_NO_WINDOW
        else:
            options["start_new_session"] = True
        launch_identity = _tool_identity(selected_argv[0], directory, env, tool_source)
        if (launch_identity["status"] != "OBSERVED" or
                launch_identity["resolved_path"] != identity["resolved_path"] or
                launch_identity["file_sha256"] != identity["file_sha256"]):
            diagnostics.append({"code": "TOOL_IDENTITY_CHANGED", "message": "Executable identity changed or became unreadable before launch; launch denied."})
            raise PermissionError("tool identity changed before launch")
        proc = subprocess.Popen(selected_argv, **options)
        for name in ("stdout", "stderr"):
            thread = threading.Thread(target=read_stream, args=(getattr(proc, name), name), daemon=True)
            thread.start()
            threads.append(thread)
        if input_bytes is not None:
            thread = threading.Thread(target=send_input, daemon=True)
            thread.start()
            threads.append(thread)
        while proc.poll() is None or any(thread.is_alive() for thread in threads):
            if output_limit.is_set():
                terminate_owned_process()
                break
            if time.monotonic() - begin >= timeout_seconds:
                timed_out = True
                terminate_owned_process()
                break
            if capture_failure.is_set():
                terminate_owned_process()
                break
            time.sleep(0.005)
        returncode = proc.wait(timeout=2)
        join_deadline = time.monotonic() + 1
        for thread in threads:
            thread.join(timeout=max(0, join_deadline - time.monotonic()))
        if any(thread.is_alive() for thread in threads):
            capture_failure.set()
            diagnostics.append({"code": "CAPTURE_INCOMPLETE", "message": "A pipe reader remained alive after process termination; captured prefixes only."})
    except (OSError, subprocess.SubprocessError) as exc:
        if isinstance(exc, subprocess.TimeoutExpired):
            # Also preserve timeouts raised by the subprocess wait/reap APIs,
            # independently of the monotonic deadline in the capture loop.
            timed_out = True
        diagnostics.append({"code": "START_FAILED" if proc is None else "PROCESS_CAPTURE_ERROR", "message": str(exc) or type(exc).__name__})
        if proc is not None:
            capture_failure.set()
            terminate_owned_process()
            try:
                returncode = proc.wait(timeout=2)
            except (OSError, subprocess.SubprocessError):
                pass
    finally:
        if proc is not None and not any(thread.is_alive() for thread in threads):
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass
    with lock:
        captured = {name: bytes(data) for name, data in chunks.items()}
    truncated = output_limit.is_set()
    end_status, linux_signal, windows_exception = classify_returncode(
        returncode, actual_platform, timed_out=timed_out, truncated=truncated,
        capture_failed=capture_failure.is_set(), started=proc is not None)
    payload = {"run_id": run_id, "argv": selected_argv, "cwd": str(directory),
               "target_environment": target_environment, "platform_type": actual_platform,
               "start_status": "START_FAILED" if proc is None else "STARTED", "end_status": end_status,
               "returncode": returncode, "linux_signal": linux_signal, "windows_exception_code": windows_exception,
               "timed_out": timed_out, "truncated": truncated, "capture_failed": capture_failure.is_set(), "started_at": started_at,
               "finished_at": datetime.now(timezone.utc).isoformat(), "duration_seconds": time.monotonic() - begin,
               "resource_limits": {"timeout_seconds": float(timeout_seconds), "max_output_bytes": max_output_bytes,
                                   "termination_scope": "WINDOWS_DIRECT_CHILD" if actual_platform == "windows" else "POSIX_PROCESS_GROUP",
                                   "memory_bytes": None, "cpu_seconds": None,
                                   "memory_limit_status": "NOT_ENFORCED", "cpu_limit_status": "NOT_ENFORCED"},
               "stdin_sha256": None if input_bytes is None else digest_bytes(input_bytes),
               "stdin_size_bytes": 0 if input_bytes is None else len(input_bytes),
               "command_identity": {"source": command_source, "argv_sha256": digest_argv(selected_argv)},
               "tool_identity": identity, "diagnostics": diagnostics, "evidence_directory": str(folder)}
    for name, data in captured.items():
        payload[name + "_b64"] = base64.b64encode(data).decode("ascii")
        payload[name + "_sha256"] = digest_bytes(data)
    result = seal_tool_result(payload)
    write_tool_evidence(folder, result, protection)
    return result
