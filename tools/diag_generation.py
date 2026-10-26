# -*- coding: utf-8 -*-
"""Where does a generated candidate actually lose?

Counting successes tells you the rate; it does not tell you what to fix. This
reads the observation logs of finished runs and names the first step that
failed, so the failure modes can be ranked instead of guessed.

Usage:
  python -m tools.diag_generation data/loop/ab_flash data/loop/s5k_gate2
"""

import argparse
import collections
import re
from pathlib import Path
from typing import Dict, List, Optional

STEP_FAIL = re.compile(r"\[CUDA_STEP:(S\d+)\]\s*(.*?)\s+—\s+FAIL:\s*(.*)")
RUN_LINE = re.compile(r"\[CPG_RUN\]\s+(\S+)\s+exit=(-?\d+)")


def _status(report: Path) -> Optional[str]:
    for line in report.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("| 状态 |"):
            return line.split("|")[2].strip().strip("`")
    return None


def analyse(workdir: Path) -> List[Dict[str, object]]:
    rows = []
    for report in sorted(workdir.rglob("loop_report.zh-CN.md")):
        run_dir = report.parent
        status = _status(report)
        first_fail = ""
        executed = 0
        crashed = 0
        for obs in sorted(run_dir.glob("iteration_*_observation.txt")):
            text = obs.read_text(encoding="utf-8", errors="ignore")
            for match in STEP_FAIL.finditer(text):
                if not first_fail:
                    first_fail = "%s %s" % (match.group(1), match.group(3).strip()[:70])
            for match in RUN_LINE.finditer(text):
                executed += 1
                if match.group(2) not in ("0",):
                    crashed += 1
            if first_fail:
                break
        rows.append({"run": str(run_dir.relative_to(workdir)), "status": status,
                     "first_fail": first_fail, "executed": executed,
                     "crashed": crashed})
    return rows


def summarise(rows: List[Dict[str, object]]) -> str:
    by_status = collections.Counter(str(r["status"]) for r in rows)
    fails = collections.Counter(str(r["first_fail"]) for r in rows
                                if r["status"] != "SUPPORTED" and r["first_fail"])
    lines = ["runs: %d | %s" % (len(rows), dict(by_status)), ""]
    if fails:
        lines.append("first failing step among unsuccessful runs:")
        for text, count in fails.most_common(10):
            lines.append("  %2dx  %s" % (count, text))
    else:
        lines.append("no step-level failures recorded")
    no_exec = [r for r in rows if r["executed"] == 0]
    lines.append("")
    lines.append("runs that executed nothing: %d" % len(no_exec))
    return "\n".join(lines)


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="diagnose generation failure modes")
    parser.add_argument("workdirs", nargs="+")
    args = parser.parse_args(argv)
    for path in args.workdirs:
        workdir = Path(path)
        if not workdir.is_dir():
            continue
        print("== %s" % path)
        print(summarise(analyse(workdir)))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
