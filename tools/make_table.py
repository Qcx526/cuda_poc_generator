# -*- coding: utf-8 -*-
"""Turn batch results into the table the thesis reports.

The raw summary answers "what happened". A paper needs "what happened, under
which input quality, with how much repetition": success@k per CVE next to the
specification's operational coverage and the diagnosis that ended it.

Usage:  python -m tools.make_table --workdir data/loop/successk
"""

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional


def _spec_facts(project_root: Path, cve_id: str) -> Dict[str, str]:
    """Operational coverage and routing for a CVE, when a spec exists."""
    from src.spec_model import load

    path = project_root / "specs" / cve_id / "spec.json"
    if not path.is_file():
        return {"band": "无规格", "coverage": "0%", "strategy": "—"}
    try:
        spec = load(path)
    except Exception:  # noqa: BLE001 - a broken spec must not break the table
        return {"band": "规格损坏", "coverage": "—", "strategy": "—"}
    return {"band": "有规格",
            "coverage": "%.0f%%" % (100 * spec.operational_coverage()),
            "strategy": spec.strategy}


def build_table(rows: List[dict], project_root: Path) -> str:
    lines = ["| CVE | 规格 | 覆盖率 | 策略 | 状态 | success@k | 轮数 | 终止诊断 | 耗时(s) |",
             "|---|---|---|---|---|---|---|---|---|"]
    for row in rows:
        facts = _spec_facts(project_root, row["cve_id"])
        attempts = row.get("attempts", 1)
        successes = row.get("successes", 0)
        lines.append("| %s | %s | %s | %s | %s | %d/%d | %d | %s | %.0f |" % (
            row["cve_id"], facts["band"], facts["coverage"], facts["strategy"],
            row.get("status", ""), successes, attempts,
            row.get("iterations", 0), row.get("diagnosis") or "—",
            row.get("seconds", 0.0)))
    return "\n".join(lines)


def summarise(rows: List[dict]) -> str:
    attempts = sum(row.get("attempts", 1) for row in rows)
    successes = sum(row.get("successes", 0) for row in rows)
    by_k = max((row.get("attempts", 1) for row in rows), default=1)
    solved = sum(1 for row in rows if row.get("successes", 0) > 0)
    diagnoses = Counter(row.get("diagnosis") or "—" for row in rows
                        if row.get("status") != "SUPPORTED")
    parts = ["**汇总**", "",
             "- CVE 数：%d，其中至少一次成功：%d（%.0f%%）"
             % (len(rows), solved, 100.0 * solved / len(rows) if rows else 0),
             "- success@%d：%d/%d = %.0f%%"
             % (by_k, successes, attempts,
                100.0 * successes / attempts if attempts else 0)]
    if diagnoses:
        detail = "；".join("`%s` %d" % (code, count)
                          for code, count in diagnoses.most_common())
        parts.append("- 未成功样本的终止诊断：%s" % detail)
    return "\n".join(parts)


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="render the success@k table")
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    workdir = Path(args.workdir)
    summary = workdir / "batch_summary.json"
    if not summary.is_file():
        raise SystemExit("no batch_summary.json in %s" % workdir)
    rows = json.loads(summary.read_text(encoding="utf-8"))
    project_root = Path(args.project_root)

    text = "\n\n".join([build_table(rows, project_root), summarise(rows)]) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print("written: %s" % args.out)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
