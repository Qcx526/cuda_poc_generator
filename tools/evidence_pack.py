# -*- coding: utf-8 -*-
"""Assemble the evidence pack a report or thesis appendix needs.

One command should turn the raw run directories into: a per-CVE table with the
success rate over independent runs, the pooled rate with a confidence interval,
the diagnosis that ended each run, and the commands needed to reproduce it.

A single run is not evidence - the same CVE reached SUPPORTED in two of six
identical runs - so the pack always reports successes over attempts, never a
bare verdict.

Usage:
  python -m tools.evidence_pack --workdir data/loop/success5a --out docs/evidence_pack.md
"""

import argparse
import json
import math
from pathlib import Path
from typing import Dict, List, Optional


def wilson(successes: int, attempts: int, z: float = 1.96) -> tuple:
    """95% interval for a proportion; empty data returns (0, 0)."""
    if attempts == 0:
        return (0.0, 0.0)
    p = successes / attempts
    denom = 1 + z * z / attempts
    centre = (p + z * z / (2 * attempts)) / denom
    half = z * math.sqrt(p * (1 - p) / attempts + z * z / (4 * attempts * attempts)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _report_line(workdir: Path, cve: str) -> str:
    """Pull the verdict out of a per-CVE loop report, when one exists."""
    for path in sorted(workdir.glob("%s/loop_report.zh-CN.md" % cve)):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("| 状态 |"):
                return line.replace("| 状态 |", "").replace("|", "").strip()
    return "—"


def build(workdir: Path, project_root: Path) -> str:
    summary = workdir / "batch_summary.json"
    if not summary.is_file():
        raise SystemExit("no batch_summary.json in %s" % workdir)
    rows: List[Dict[str, object]] = json.loads(summary.read_text(encoding="utf-8"))

    lines = ["# 证据包：工具链复现率", "",
             "口径：每次独立运行记一次，`success@k` = 成功次数 / 独立运行次数。", "",
             "| CVE | success@k | 成功率 | 95% CI | 平均轮数 | 终止诊断 | 规格 |",
             "|---|---|---|---|---|---|---|"]

    total_ok = total_n = 0
    for row in rows:
        cve = str(row["cve_id"])
        ok = int(row.get("successes", 0))
        n = int(row.get("attempts", 1))
        lo, hi = wilson(ok, n)
        total_ok += ok
        total_n += n
        spec = project_root / "specs" / cve / "spec.json"
        spec_note = "有" if spec.is_file() else "无"
        lines.append("| %s | %d/%d | %.0f%% | [%.0f%%, %.0f%%] | %s | %s | %s |" % (
            cve, ok, n, 100 * ok / n if n else 0, 100 * lo, 100 * hi,
            row.get("iterations", "—"), row.get("diagnosis") or "—", spec_note))

    lo, hi = wilson(total_ok, total_n)
    lines += ["", "## 汇总", "",
              "- 独立运行：%d 次，成功 %d 次" % (total_n, total_ok),
              "- **success = %.0f%%**，95%% CI [%.0f%%, %.0f%%]"
              % (100 * total_ok / total_n if total_n else 0, 100 * lo, 100 * hi),
              "- 至少一次成功的 CVE：%d / %d"
              % (len([r for r in rows if int(r.get("successes", 0)) > 0]), len(rows)),
              "", "> 区间宽度说明样本量：CI 越宽，结论越只能当方向看。", ""]

    lines += ["## 判定依据", "",
              "每个 `SUPPORTED` 都满足三条：受控样本崩溃、良性基线干净、单变量对照未全崩。",
              "只有 `SUPPORTED` 计入上表；`NOT_VERIFIED` 与 `UNKNOWN` 都算未成功。", ""]

    lines += ["## 复现命令", "",
              "```bash",
              "python -m src.batch_loop --cve %s --iterations 2 --repeat 5 --workdir %s"
              % (" ".join("--cve %s" % r["cve_id"] for r in rows), workdir),
              "python -m tools.make_table --workdir %s" % workdir,
              "```", ""]
    return "\n".join(lines)


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="build the evidence pack")
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    text = build(Path(args.workdir), Path(args.project_root))
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print("written: %s" % args.out)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
