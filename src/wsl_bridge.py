"""Explicit, nonce-bound Windows to WSL read-only probe transport."""

import base64
from datetime import datetime
import hashlib
import json
import math
import re
import shutil

from .models.platform import PlatformSnapshot
from .platform_worker import build_worker_source
from .probe_process import run_bounded


def decode_wsl_list(raw):
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16")
    elif b"\0" in raw:
        text = raw.decode("utf-16-le")
    else:
        text = raw.decode("utf-8-sig")
    return [line.strip() for line in text.splitlines() if line.strip()]


def parse_packet(raw, *, probe_id, nonce, backend):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("nonfinite number")

    try:
        packet = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=pairs, parse_constant=invalid)
        if set(packet) != {"protocol_version", "nonce", "worker_exit_code", "snapshot", "commands"}:
            raise ValueError("worker envelope mismatch")
        if packet["protocol_version"] != "1.0" or packet["nonce"] != nonce or type(packet["worker_exit_code"]) is not int or packet["worker_exit_code"] != 0:
            raise ValueError("worker response identity mismatch")
        snapshot = PlatformSnapshot.model_validate(packet["snapshot"])
        if snapshot.execution_backend != backend or (backend == "wsl" and snapshot.platform_type != "wsl"):
            raise ValueError("wrong environment")
        if snapshot.metadata.get("probe_id") != probe_id or snapshot.metadata.get("nonce") != nonce:
            raise ValueError("stale snapshot")
        if not isinstance(packet["commands"], list):
            raise ValueError("commands must be a list")
        commands = {c["command_id"]: c for c in packet["commands"]}
        if len(commands) != len(packet["commands"]):
            raise ValueError("duplicate command identity")
        for command in packet["commands"]:
            if (not isinstance(command["command_id"], str) or not command["command_id"].strip()
                    or not isinstance(command["argv"], list) or not command["argv"]
                    or any(not isinstance(arg, str) or "\0" in arg for arg in command["argv"])
                    or command["environment"] != snapshot.metadata["environment_label"]):
                raise ValueError("command environment mismatch")
            if (command["status"] not in {"COMPLETED", "TIMED_OUT", "OUTPUT_LIMIT", "START_FAILED", "CAPTURE_FAILED"}
                    or type(command["max_output_bytes"]) is not int or not 1 <= command["max_output_bytes"] <= 1048576
                    or type(command["timeout_seconds"]) not in (int, float)
                    or not math.isfinite(command["timeout_seconds"]) or not 0 < command["timeout_seconds"] <= 10
                    or type(command["duration_seconds"]) not in (int, float)
                    or not math.isfinite(command["duration_seconds"]) or command["duration_seconds"] < 0
                    or type(command["timed_out"]) is not bool or type(command["truncated"]) is not bool
                    or (command["returncode"] is not None and type(command["returncode"]) is not int)
                    or (command["status"] == "COMPLETED" and command["returncode"] is None)):
                raise ValueError("invalid command limits/status")
            for name in ("started_at", "finished_at"):
                if datetime.fromisoformat(command[name]).tzinfo is None:
                    raise ValueError("command timestamps require timezone")
            total_bytes = 0
            for stream in ("stdout", "stderr"):
                data = base64.b64decode(command[stream + "_b64"], validate=True)
                total_bytes += len(data)
                if hashlib.sha256(data).hexdigest() != command[stream + "_sha256"]:
                    raise ValueError("raw command digest mismatch")
            if total_bytes > command["max_output_bytes"]:
                raise ValueError("record exceeds its capture limit")
        for source in snapshot.provenance.values():
            if source.command_id is not None and source.command_id not in commands:
                raise ValueError("source lacks command record")
        return snapshot.model_dump(mode="json"), packet["commands"], packet["worker_exit_code"]
    except (ValueError, TypeError, KeyError, RecursionError):
        raise ValueError("Probe response rejected: protocol/schema/integrity/freshness.") from None


def validate_wsl_options(distro, linux_python, user):
    """Reject foreign interpreters and shell arguments before any host query."""
    if not isinstance(distro, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,127}", distro):
        raise ValueError("invalid WSL distro name")
    if not isinstance(user, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        raise ValueError("invalid Linux user name")
    if (not isinstance(linux_python, str) or not linux_python.startswith("/") or "\\" in linux_python
            or any(ch in linux_python for ch in "\r\n\0")
            or not re.fullmatch(r"python(?:3(?:\.[0-9]+)?)?", linux_python.rsplit("/", 1)[-1])):
        raise ValueError("WSL requires a configured absolute Linux Python interpreter")


def probe_wsl(*, distro="Ubuntu-22.04", linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python",
              user="pocdev", timeout_seconds=45, max_output_bytes=1048576, probe_id, nonce):
    validate_wsl_options(distro, linux_python, user)
    result = {"status": "FAILED", "snapshot": None, "commands": [], "diagnostics": [],
              "transport": {"launcher_returncode": None, "worker_reported_exit_code": None},
              "stdout_b64": "", "stderr_b64": ""}

    def fail(code):
        result["diagnostics"].append({"code": code, "field": "wsl_bridge", "message": "Read-only WSL probe did not produce a validated current snapshot."})
        return result

    executable = shutil.which("wsl.exe")
    if not executable:
        return fail("WSL_UNAVAILABLE")
    listing = run_bounded([executable, "--list", "--quiet"], timeout_seconds=min(timeout_seconds, 10),
                          max_output_bytes=max_output_bytes, environment="windows_dispatcher", command_id="wsl_distro_list")
    result["commands"].append(listing)
    if listing["status"] != "COMPLETED" or listing["returncode"] != 0:
        result.update(stdout_b64=listing["stdout_b64"], stderr_b64=listing["stderr_b64"])
        result["transport"]["launcher_returncode"] = listing["returncode"]
        return fail("WSL_LIST_" + listing["status"])
    try:
        distros = decode_wsl_list(base64.b64decode(listing["stdout_b64"]))
    except UnicodeError:
        return fail("WSL_DISTRO_LIST_INVALID")
    if distro not in distros:
        return fail("WSL_DISTRO_NOT_FOUND")
    request = {"probe_id": probe_id, "nonce": nonce, "execution_backend": "wsl",
               "environment_label": "wsl:" + distro, "command_timeout_seconds": 3,
               "total_budget_seconds": max(0.1, min(40, timeout_seconds - 2)), "max_output_bytes": 32768}
    argv = [executable, "--distribution", distro, "--user", user, "--exec", linux_python, "-I", "-"]
    record = run_bounded(argv, timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes,
                         input_bytes=build_worker_source(request), environment="windows_dispatcher", command_id="wsl_worker")
    result["commands"].append(record)
    result.update(stdout_b64=record["stdout_b64"], stderr_b64=record["stderr_b64"])
    result["transport"]["launcher_returncode"] = record["returncode"]
    if record["status"] != "COMPLETED" or record["returncode"] != 0:
        return fail("WSL_WORKER_" + record["status"] if record["status"] != "COMPLETED" else "WSL_WORKER_NONZERO")
    try:
        snapshot, commands, exit_code = parse_packet(base64.b64decode(record["stdout_b64"]), probe_id=probe_id, nonce=nonce, backend="wsl")
    except ValueError:
        return fail("WSL_RESPONSE_INVALID")
    result.update(snapshot=snapshot, status=snapshot["probe_status"])
    result["commands"].extend(commands)
    result["transport"]["worker_reported_exit_code"] = exit_code
    return result
