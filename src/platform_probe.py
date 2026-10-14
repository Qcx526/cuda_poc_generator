"""Formal local / Windows-to-WSL read-only probing entry point."""

import argparse
import base64
import math
import os
from pathlib import Path
import sys
import uuid

from .platform_worker import build_worker_source
from .probe_artifacts import write_probe_artifacts
from .probe_process import run_bounded
from .wsl_bridge import parse_packet, probe_wsl, validate_wsl_options


def read_snapshot(path, *, expected_probe_id):
    """Validate an exact stored record; never relabel a historical probe as current."""
    import json
    from .models.platform import PlatformSnapshot
    source = Path(path)
    if source.stat().st_size > 4194304:
        raise ValueError("Stored snapshot exceeds the read limit")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Stored snapshot contains duplicate keys")
            result[key] = value
        return result
    snapshot = PlatformSnapshot.model_validate(json.loads(source.read_bytes(), object_pairs_hook=pairs))
    if snapshot.metadata.get("probe_id") != expected_probe_id:
        raise ValueError("Stored snapshot does not belong to the expected probe")
    return snapshot


def _collect_local(probe_id, nonce, timeout_seconds, max_output_bytes):
    request = {"probe_id": probe_id, "nonce": nonce, "execution_backend": "local",
               "environment_label": "local", "command_timeout_seconds": 3,
               "total_budget_seconds": max(0.1, min(40, timeout_seconds - 2)), "max_output_bytes": 32768}
    allowed = {"PATH", "SYSTEMROOT", "COMSPEC", "WINDIR", "TEMP", "TMP", "HOME", "LANG", "LC_ALL",
               "PROGRAMFILES", "PROGRAMFILES(X86)", "CUDA_PATH", "CUDA_ROOT", "CUDA_HOME"}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    record = run_bounded([sys.executable, "-I", "-"], timeout_seconds=timeout_seconds,
                         max_output_bytes=max_output_bytes, input_bytes=build_worker_source(request),
                         environment="local_dispatcher", command_id="local_worker", env=env)
    result = {"status": "FAILED", "snapshot": None, "commands": [record], "diagnostics": [],
              "stdout_b64": record["stdout_b64"], "stderr_b64": record["stderr_b64"],
              "transport": {"launcher_returncode": record["returncode"], "worker_reported_exit_code": None}}
    if record["status"] == "COMPLETED" and record["returncode"] == 0:
        try:
            snapshot, commands, code = parse_packet(base64.b64decode(record["stdout_b64"]), probe_id=probe_id, nonce=nonce, backend="local")
            result.update(snapshot=snapshot, status=snapshot["probe_status"])
            result["commands"].extend(commands)
            result["transport"]["worker_reported_exit_code"] = code
        except ValueError:
            result["diagnostics"].append({"code": "LOCAL_RESPONSE_INVALID", "field": "local_probe", "message": "Local worker response failed validation."})
    else:
        result["diagnostics"].append({"code": "LOCAL_WORKER_" + record["status"], "field": "local_probe", "message": "Local worker did not complete successfully."})
    return result


def run_platform_probe(*, backend="local", distro="Ubuntu-22.04",
                       linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python", user="pocdev",
                       timeout_seconds=45, max_output_bytes=1048576, output_root=None):
    if backend not in {"local", "wsl"}:
        raise ValueError("Only local and explicitly selected wsl probing are supported")
    if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or not 1 <= timeout_seconds <= 120:
        raise ValueError("Probe timeout must be in [1,120] seconds")
    if type(max_output_bytes) is not int or not 4096 <= max_output_bytes <= 4194304:
        raise ValueError("Probe output bound must be in [4096,4194304] bytes")
    if backend == "wsl":
        validate_wsl_options(distro, linux_python, user)
    probe_id, nonce = uuid.uuid4().hex, uuid.uuid4().hex
    if backend == "wsl":
        host = _collect_local(probe_id + "-host", nonce + "-host", timeout_seconds, max_output_bytes)
        result = probe_wsl(distro=distro, linux_python=linux_python, user=user,
                           timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes,
                           probe_id=probe_id, nonce=nonce)
        result["host_snapshot"] = host["snapshot"]
        result["commands"] = host["commands"] + result["commands"]
        result["diagnostics"] = host["diagnostics"] + result["diagnostics"]
        if host["snapshot"] is None and result["status"] != "FAILED":
            result["status"] = "PARTIAL"
    else:
        result = _collect_local(probe_id, nonce, timeout_seconds, max_output_bytes)
        result["host_snapshot"] = result["snapshot"]
    result.update(probe_id=probe_id, backend=backend, execution="NOT_EXECUTED", verification="NOT_VERIFIED")
    for snapshot in (result["snapshot"], result["host_snapshot"]):
        if snapshot is not None:
            result["diagnostics"].extend(snapshot["diagnostics"])
    root = output_root or Path(__file__).resolve().parent.parent / "data" / "outputs" / "platform_probes"
    folder = write_probe_artifacts(root, result)
    result["run_directory"] = str(folder)
    if result["snapshot"] is not None:
        result["snapshot"]["metadata"]["record_directory"] = str(folder)
    return result


def main():
    parser = argparse.ArgumentParser(description="Read-only platform probe; never executes CUDA or PoCs")
    parser.add_argument("--backend", choices=("local", "wsl"), default="local")
    parser.add_argument("--distro", default="Ubuntu-22.04")
    parser.add_argument("--linux-python", default="/home/pocdev/.venvs/cuda-poc-generator/bin/python")
    parser.add_argument("--wsl-user", default="pocdev")
    parser.add_argument("--timeout", type=float, default=45)
    parser.add_argument("--max-output-bytes", type=int, default=1048576)
    parser.add_argument("--output-root", default=None)
    args = parser.parse_args()
    try:
        result = run_platform_probe(backend=args.backend, distro=args.distro, linux_python=args.linux_python,
                                    user=args.wsl_user, timeout_seconds=args.timeout,
                                    max_output_bytes=args.max_output_bytes, output_root=args.output_root)
    except (ValueError, OSError) as exc:
        print("[ERROR] Read-only probe failed: " + str(exc), file=sys.stderr)
        return 1
    print(f"Read-only probe: {result['status']}; records: {result['run_directory']}")
    print("NOT_EXECUTED / NOT_VERIFIED")
    return 1 if result["status"] == "FAILED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
