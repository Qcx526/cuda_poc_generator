"""Bounded, byte-preserving process capture used only by fixed probe actions."""

import base64
from datetime import datetime, timezone
import hashlib
import math
import subprocess
import threading
import time


def run_bounded(argv, timeout_seconds=10, max_output_bytes=1048576, input_bytes=None,
                environment="local", command_id=None, env=None):
    if not isinstance(argv, list) or not argv or any(not isinstance(s, str) or "\0" in s for s in argv):
        raise ValueError("probe argv must be a nonempty string list")
    if isinstance(timeout_seconds, bool) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 120:
        raise ValueError("probe timeout outside [0,120]")
    if type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 4194304:
        raise ValueError("probe output bound outside [1,4194304]")
    if input_bytes is not None and not isinstance(input_bytes, bytes):
        raise ValueError("probe input must be bytes")
    started = datetime.now(timezone.utc).isoformat()
    begin = time.monotonic()
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    lock = threading.Lock()
    exceeded = threading.Event()
    readers_failed = threading.Event()
    proc = None
    status, returncode, timed_out = "START_FAILED", None, False

    def read_stream(stream, name):
        try:
            while True:
                block = stream.read1(4096) if hasattr(stream, "read1") else stream.read(4096)
                if not block:
                    break
                with lock:
                    remaining = max_output_bytes - sum(len(value) for value in chunks.values())
                    chunks[name].extend(block[:max(0, remaining)])
                    if len(block) > remaining:
                        exceeded.set()
        except (OSError, ValueError):
            readers_failed.set()

    def send_input():
        try:
            proc.stdin.write(input_bytes)
            proc.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            pass

    threads = []
    try:
        options = {"stdin": subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                   "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "shell": False, "env": env}
        # Avoid console windows while preserving a normal noninteractive subprocess.
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            options["creationflags"] = subprocess.CREATE_NO_WINDOW
        proc = subprocess.Popen(argv, **options)
        for name in ("stdout", "stderr"):
            thread = threading.Thread(target=read_stream, args=(getattr(proc, name), name), daemon=True)
            thread.start()
            threads.append(thread)
        if input_bytes is not None:
            thread = threading.Thread(target=send_input, daemon=True)
            thread.start()
            threads.append(thread)
        status = "COMPLETED"
        while proc.poll() is None:
            if exceeded.is_set():
                status = "OUTPUT_LIMIT"
                break
            if time.monotonic() - begin >= timeout_seconds:
                status, timed_out = "TIMED_OUT", True
                break
            time.sleep(0.005)
        if proc.poll() is None:
            proc.kill()
        returncode = proc.wait(timeout=2)
        for thread in threads:
            thread.join(timeout=0.5)
        if exceeded.is_set():
            status = "OUTPUT_LIMIT"
        elif any(thread.is_alive() for thread in threads) or readers_failed.is_set():
            status = "CAPTURE_FAILED"
    except (OSError, subprocess.SubprocessError):
        status = "START_FAILED" if proc is None else "CAPTURE_FAILED"
        if proc is not None:
            try:
                proc.kill()
                returncode = proc.wait(timeout=2)
            except (OSError, subprocess.SubprocessError):
                pass
    finally:
        if proc is not None:
            # Closing a pipe with a live blocking reader can itself wait indefinitely.
            live_readers = any(thread.is_alive() for thread in threads)
            for stream in (() if live_readers else (proc.stdin, proc.stdout, proc.stderr)):
                if stream is not None:
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass
    result = {"command_id": command_id, "argv": argv, "environment": environment,
              "timeout_seconds": timeout_seconds, "max_output_bytes": max_output_bytes,
              "status": status, "returncode": returncode, "started_at": started,
              "finished_at": datetime.now(timezone.utc).isoformat(),
              "duration_seconds": time.monotonic() - begin, "timed_out": timed_out,
              "truncated": exceeded.is_set()}
    result["input_sha256"] = None if input_bytes is None else hashlib.sha256(input_bytes).hexdigest()
    result["input_size_bytes"] = 0 if input_bytes is None else len(input_bytes)
    with lock:
        captured = {name: bytes(data) for name, data in chunks.items()}
    for name, data in captured.items():
        result[name + "_b64"] = base64.b64encode(data).decode("ascii")
        result[name + "_sha256"] = hashlib.sha256(data).hexdigest()
    return result
