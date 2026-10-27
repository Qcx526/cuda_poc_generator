# -*- coding: utf-8 -*-
"""Offer one escape code at a time, and stop at the first surprise.

Each code runs in its own process because a wrong guess can end the process, the
session, or the machine; keeping them separate means the last line printed names
the code that did it. The marker is written before every attempt, so a bugcheck
is attributed to one code rather than to "the sweep".

A status of INVALID_PARAMETER or NOT_SUPPORTED means the driver looked at the
code and refused it. Anything else - including a process that dies without
reporting - is worth stopping for.

  python -m tools.sweep_escapes --limit 5
  python -m tools.sweep_escapes --codes 0x10001002 0x10000402
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

REFUSED = {-1073741811, -1073741637}  # INVALID_PARAMETER, NOT_SUPPORTED


def arm_marker(workdir: Path, code: int) -> None:
    from src.driver_probe import arm
    arm(workdir, Path("tools/probe_d3dkmt.py"),
        note="escape sweep", variant="escape_0x%08x" % code)


def offer(code: int, timeout: int) -> Dict[str, object]:
    command = [sys.executable, "-u", "-B", "-m", "tools.probe_d3dkmt",
               "--stage", "escape", "--escape-code", "0x%08x" % code,
               "--payload-size", "16"]
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"code": "0x%08x" % code, "outcome": "timeout"}
    text = (completed.stdout or "") + (completed.stderr or "")
    status = None
    for line in text.splitlines():
        if line.startswith("escape") and "status=" in line:
            status = int(line.rsplit("status=", 1)[1].split()[0])
    return {"code": "0x%08x" % code, "returncode": completed.returncode,
            "status": status, "tail": text.strip().splitlines()[-1] if text.strip() else ""}


def classify(result: Dict[str, object]) -> str:
    if result.get("outcome") == "timeout":
        return "stop"
    status = result.get("status")
    if status is None:
        return "stop"          # died without reporting: the code did something
    if status in REFUSED:
        return "refused"
    return "stop"              # accepted, or a fault we have not seen before


def main() -> int:
    parser = argparse.ArgumentParser(description="offer escape codes one by one")
    parser.add_argument("--codes", nargs="*", default=None)
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--source", default="data/probe/escape_codes.json")
    parser.add_argument("--workdir", default="data/probe")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--json", default="data/probe/escape_sweep.json")
    args = parser.parse_args()

    if args.codes:
        codes = [int(item, 16) for item in args.codes]
    else:
        source = Path(args.source)
        rows = json.loads(source.read_text(encoding="utf-8"))["candidates"]
        codes = [row["value"] for row in rows[:args.limit]]

    results: List[Dict[str, object]] = []
    for index, code in enumerate(codes, 1):
        print("[%d/%d] 0x%08x ... " % (index, len(codes), code), end="", flush=True)
        arm_marker(Path(args.workdir), code)
        result = offer(code, args.timeout)
        verdict = classify(result)
        results.append(dict(result, verdict=verdict))
        print("%s status=%s" % (verdict, result.get("status")))
        if verdict == "stop":
            print("stopping: this code did not simply get refused")
            break

    target = Path(args.json)
    target.parent.mkdir(parents=True, exist_ok=True)
    history = []
    if target.is_file():
        try:
            history = json.loads(target.read_text(encoding="utf-8")).get("runs", [])
        except ValueError:
            history = []
    history.append(results)
    target.write_text(json.dumps({"runs": history}, ensure_ascii=False, indent=2),
                      encoding="utf-8")
    print("written to %s" % target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
