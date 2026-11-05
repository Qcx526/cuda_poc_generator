# -*- coding: utf-8 -*-
"""Run a generated program against the native benchmark, under a trusted recorder.

Shape of one run:

    runner  --spawn-->  server (loads the DLL, keeps the authoritative trace)
    runner  --spawn-->  candidate (gets endpoint + client token only)
    runner  --query-->  server (judge token) -> verdict

The candidate therefore cannot write the trace, cannot read it, and cannot see the
verdict. What it can do is call the API - which is the whole point of the exercise.
"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

DLL = ROOT / "mock_native" / "mock_gpu.dll"
FACTS = ROOT / "data" / "driver" / "mock_facts" / "mock_gpu_facts.json"


def _read_handshake(server: subprocess.Popen, timeout: float = 20.0) -> dict:
    """The server prints one JSON line with port and both tokens.

    Reading it from the pipe is the point: no file is created, so a sibling process
    has nothing to read even though it runs as the same user.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = server.stdout.readline()
        if line:
            return json.loads(line)
        if server.poll() is not None:
            break
        time.sleep(0.02)
    raise TimeoutError("server 未在 %.0fs 内完成握手" % timeout)


def _query(port: int, token: str, payload: dict) -> dict:
    request = dict(payload)
    request["token"] = token
    with socket.create_connection(("127.0.0.1", port), timeout=20) as sock:
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    return json.loads(data.decode("utf-8") or "{}")


def _declared_sha() -> str:
    if not FACTS.is_file():
        return ""
    try:
        return json.loads(FACTS.read_text(encoding="utf-8"))["artifact"]["sha256"]
    except (ValueError, KeyError):
        return ""


def run_candidate(candidate: Path, timeout: int = 60,
                  trace_path: Path = None) -> dict:
    if not DLL.is_file():
        raise FileNotFoundError("原生 DLL 缺失，正式验收不允许跳过: %s" % DLL)

    candidate = Path(candidate).resolve()
    workdir = Path(tempfile.mkdtemp(prefix="bench_"))
    server = subprocess.Popen(
        [sys.executable, "-B", "-m", "mock_native.server", "--dll", str(DLL)],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        creds = _read_handshake(server)
        port = int(creds["port"])

        env = dict(os.environ)
        env.pop("MOCK_GPU_ORACLE", None)
        env.pop("MOCK_GPU_TRACE", None)          # 轨迹路径根本不交给候选
        env["PYTHONPATH"] = str(ROOT)
        env["MOCK_GPU_ENDPOINT"] = "127.0.0.1:%d" % port
        env["MOCK_GPU_CLIENT_TOKEN"] = creds["client_token"]

        done = subprocess.run([sys.executable, "-B", str(candidate)], capture_output=True,
                              text=True, errors="replace", timeout=timeout, env=env,
                              cwd=str(ROOT))
        claimed = {}
        for line in (done.stdout or "").splitlines():
            if line.startswith("CPG_RESULT "):
                try:
                    claimed = json.loads(line[len("CPG_RESULT "):])
                except ValueError:
                    claimed = {"parse_error": True}

        verdict = _query(port, creds["judge_token"], {"action": "verdict"})
        if trace_path is not None:
            Path(trace_path).write_text(
                json.dumps({"dll_sha256": creds.get("dll_sha256"),
                            "trace": verdict.get("trace", []),
                            "facts": verdict.get("facts", {})},
                           ensure_ascii=False, indent=1), encoding="utf-8")
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
        shutil.rmtree(workdir, ignore_errors=True)

    facts = verdict.get("facts", {})
    claimed_reached = bool(claimed.get("reached"))
    # Each stage is reported on its own; trace_len > 0 only proves that *something*
    # reached the DLL, which is the weakest of the five facts.
    if not facts.get("native_api_called"):
        level = "SELF_REPORT_ONLY" if claimed_reached else "NO_EXECUTION"
    elif not facts.get("valid_objects_built"):
        level = "NATIVE_CALLS_ONLY"
    elif not facts.get("escape_called"):
        level = "OBJECTS_BUILT_ONLY"
    elif not facts.get("escape_with_valid_objects"):
        level = "ESCAPE_WITH_INVALID_OBJECTS"
    elif not facts.get("oracle_confirmed"):
        level = "ESCAPE_VALID_NO_TRIGGER"
    else:
        level = "TRIGGER_CONFIRMED"
    executed = bool(facts.get("native_api_called"))

    return {
        "candidate": str(candidate),
        "exit_code": done.returncode,
        "ran": done.returncode == 0 and bool(claimed),
        "claimed": claimed,
        "external": verdict,
        "verification_level": level,
        "executed_on_native": executed,
        "facts": facts,
        "oracle_confirmed": bool(facts.get("oracle_confirmed")),
        "self_report_matches_external": claimed_reached == bool(verdict.get("triggered")),
        "false_positive": claimed_reached and not verdict.get("triggered"),
        "dll_sha256_matches_facts": bool(verdict.get("dll_sha256")) and
                                    verdict.get("dll_sha256") == _declared_sha(),
        "observed_calls": verdict.get("calls", []),
        "stderr_tail": (done.stderr or "")[-400:],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args(argv)
    verdict = run_candidate(Path(args.candidate), args.timeout)
    print(json.dumps(verdict, ensure_ascii=False, indent=2))
    return 0 if verdict["ran"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
