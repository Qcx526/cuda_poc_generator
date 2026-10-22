# -*- coding: utf-8 -*-
"""Compare two batch runs: the ablation table.

A change is only evidence if the same CVEs were measured before and after it
under the same protocol. This tool takes two batch summaries and reports the
per-CVE difference in success@k plus how the failure diagnoses moved.

Usage:  python -m tools.compare_runs --a data/loop/successk --b data/loop/successk_b
"""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

Row = Dict[str, object]


def load(workdir: Path) -> Dict[str, Row]:
    path = workdir / "batch_summary.json"
    if not path.is_file():
        raise SystemExit("no batch_summary.json in %s" % workdir)
    return {row["cve_id"]: row for row in json.loads(path.read_text(encoding="utf-8"))}


def _rate(row: Optional[Row]) -> Tuple[int, int]:
    if not row:
        return (0, 0)
    return (int(row.get("successes", 0)), int(row.get("attempts", 1)))


def compare(before: Dict[str, Row], after: Dict[str, Row]) -> str:
    lines = ["| CVE | A: success@k | B: success@k | 变化 | A 终止诊断 | B 终止诊断 |",
             "|---|---|---|---|---|---|"]
    improved = regressed = 0
    for cve in sorted(set(before) | set(after)):
        a_success, a_attempts = _rate(before.get(cve))
        b_success, b_attempts = _rate(after.get(cve))
        a_rate = a_success / a_attempts if a_attempts else 0.0
        b_rate = b_success / b_attempts if b_attempts else 0.0
        if b_rate > a_rate:
            delta, improved = "↑ %.0f%%" % (100 * (b_rate - a_rate)), improved + 1
        elif b_rate < a_rate:
            delta, regressed = "↓ %.0f%%" % (100 * (b_rate - a_rate)), regressed + 1
        else:
            delta = "="
        lines.append("| %s | %d/%d | %d/%d | %s | %s | %s |" % (
            cve, a_success, a_attempts, b_success, b_attempts, delta,
            (before.get(cve) or {}).get("diagnosis") or "—",
            (after.get(cve) or {}).get("diagnosis") or "—"))

    def totals(rows: Dict[str, Row]) -> Tuple[int, int]:
        return (sum(_rate(r)[0] for r in rows.values()),
                sum(_rate(r)[1] for r in rows.values()))

    a_ok, a_all = totals(before)
    b_ok, b_all = totals(after)
    lines += ["", "**汇总**", "",
              "- A：success = %d/%d = %.0f%%" % (a_ok, a_all, 100.0 * a_ok / a_all if a_all else 0),
              "- B：success = %d/%d = %.0f%%" % (b_ok, b_all, 100.0 * b_ok / b_all if b_all else 0),
              "- 提升 %d 个 CVE，退化 %d 个 CVE" % (improved, regressed),
              ""]
    if a_all and b_all:
        lines.append("- 总体变化：%+.1f 个百分点" % (100.0 * (b_ok / b_all - a_ok / a_all)))
    return "\n".join(lines)


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="compare two batch runs")
    parser.add_argument("--a", required=True, help="baseline workdir")
    parser.add_argument("--b", required=True, help="changed workdir")
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    text = compare(load(Path(args.a)), load(Path(args.b)))
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print("written: %s" % args.out)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
