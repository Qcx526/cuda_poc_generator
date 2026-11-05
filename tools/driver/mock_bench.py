# -*- coding: utf-8 -*-
"""Run a generated program against the mock benchmark and judge it objectively.

The verdict comes from two places only: the process exit/CPG_RESULT line, and the
oracle file the mock wrote. What the program says about itself is recorded but not
trusted.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from mock_gpu import evaluator  # noqa: E402


def run_candidate(candidate: Path, timeout: int = 60) -> dict:
    candidate = Path(candidate).resolve()
    trace_path = candidate.parent / "trace.json"
    for stale in (trace_path, candidate.parent / "oracle.jsonl"):
        if stale.exists():
            stale.unlink()
    env = dict(os.environ)
    # The candidate can only leave a trace. The oracle path is deliberately not
    # exported to it, so it has nothing to write a verdict into.
    env.pop("MOCK_GPU_ORACLE", None)
    env["MOCK_GPU_TRACE"] = str(trace_path)
    env["PYTHONPATH"] = str(ROOT)
    done = subprocess.run([sys.executable, "-B", str(candidate)], capture_output=True,
                          text=True, errors="replace", timeout=timeout, env=env,
                          cwd=str(ROOT))
    result_line = ""
    for line in (done.stdout or "").splitlines():
        if line.startswith("CPG_RESULT "):
            result_line = line
    claimed = {}
    if result_line:
        try:
            claimed = json.loads(result_line[len("CPG_RESULT "):])
        except ValueError:
            claimed = {"parse_error": True}
    trace = evaluator.load_trace(trace_path)
    truth = evaluator.replay(trace)
    truth["trace_steps"] = len(trace)
    return {
        "candidate": str(candidate),
        "exit_code": done.returncode,
        "ran": done.returncode == 0 and bool(result_line),
        "claimed": claimed,
        "external": truth,
        "self_report_matches_external": bool(claimed.get("reached")) == truth["triggered"],
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
