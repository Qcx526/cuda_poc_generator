# -*- coding: utf-8 -*-
"""Compare two loop runs of the same CVE.

Two arms of an experiment differ in exactly one thing, and the report has to make
that difference visible without asking anyone to read both files. What matters is
not only who succeeded: the number of iterations, the diagnosis each round earned,
and whether the failing rounds repeated the same mistake all say something about
whether the changed input helped.

  python -m src.loop_compare --a data/loop/c3_A --b data/loop/c3_B --cve CVE-2025-23340
"""

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

_ROW = re.compile(r"^\|\s*(\d+)\s*\|\s*`([^`]+)`\s*\|\s*`?([^|`]*)`?\s*\|", re.MULTILINE)
_STATUS = re.compile(r"\|\s*状态\s*\|\s*`([^`]+)`\s*\|")
_VERDICT = re.compile(r"\|\s*最终判定\s*\|\s*`([^`]+)`\s*\|")


@dataclass
class Arm:
    name: str
    status: str = "?"
    verdict: str = "?"
    iterations: int = 0
    diagnoses: List[str] = None

    def __post_init__(self):
        self.diagnoses = self.diagnoses or []


def read_arm(directory: Path, name: str) -> Arm:
    directory = Path(directory)
    report = directory / "loop_report.zh-CN.md"
    arm = Arm(name=name)
    if not report.is_file():
        return arm
    text = report.read_text(encoding="utf-8", errors="replace")
    status = _STATUS.search(text)
    verdict = _VERDICT.search(text)
    arm.status = status.group(1) if status else "?"
    arm.verdict = verdict.group(1) if verdict else "?"
    for index, code, _directive in _ROW.findall(text):
        arm.diagnoses.append(code.strip())
        arm.iterations = max(arm.iterations, int(index))
    return arm


def mentions(directory: Path, needle: str) -> int:
    """How often an arm's observations bring the term up."""
    total = 0
    for path in sorted(Path(directory).glob("iteration_*_observation.txt")):
        total += path.read_text(encoding="utf-8", errors="replace").count(needle)
    return total


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="compare two loop arms")
    parser.add_argument("--a", required=True)
    parser.add_argument("--b", required=True)
    parser.add_argument("--cve", default="")
    parser.add_argument("--probe", action="append", default=[],
                        help="term to count in observations, e.g. sh_type")
    args = parser.parse_args(argv)

    a = read_arm(Path(args.a) / args.cve, "A")
    b = read_arm(Path(args.b) / args.cve, "B")
    lines = ["| 指标 | A | B |", "|---|---|---|",
             "| 状态 | `%s` | `%s` |" % (a.status, b.status),
             "| 最终判定 | `%s` | `%s` |" % (a.verdict, b.verdict),
             "| 迭代轮数 | %d | %d |" % (a.iterations, b.iterations),
             "| 逐轮诊断 | %s | %s |" % (" / ".join(a.diagnoses) or "-",
                                        " / ".join(b.diagnoses) or "-")]
    for term in args.probe:
        lines.append("| 观察中提及「%s」 | %d | %d |" % (
            term, mentions(Path(args.a) / args.cve, term),
            mentions(Path(args.b) / args.cve, term)))
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
