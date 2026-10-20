# -*- coding: utf-8 -*-
"""Batch runner for the closed loop over a class of CVEs.

The thesis table needs one row per CVE: status, iterations, verdict, and the
diagnosis that stopped it. This module classifies the input set by component,
runs each CVE through the same controller, and renders the table.

Classification is deliberately narrow: only CUDA *toolchain* components run
unattended here. Driver and library targets have different risk and entry
conditions and are handled separately.
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

TOOLCHAIN_MARKERS = ("cuobjdump", "nvdisasm", "nvcc", "ptxas", "fatbinary",
                     "cuda binary utilit")


def classify(inputs_root: Path) -> List[str]:
    """Return CVE ids whose affected component is a CUDA binary utility."""
    found: List[str] = []
    for directory in sorted(inputs_root.iterdir()):
        if not directory.is_dir():
            continue
        component = directory / "3_affected_component.json"
        if not component.is_file():
            continue
        try:
            text = component.read_text(encoding="utf-8").lower()
        except OSError:
            continue
        if any(marker in text for marker in TOOLCHAIN_MARKERS):
            found.append(directory.name)
    return found


@dataclass
class BatchRow:
    """One CVE's outcome, shaped for the markdown table."""

    cve_id: str
    status: str
    iterations: int = 0
    verdict: str = ""
    diagnosis: str = ""
    seconds: float = 0.0
    reason: str = ""
    diagnoses: List[str] = field(default_factory=list)


def run_one(cve_id: str, iterations: int, workdir: Path, project_root: Path,
            python_exe: str, image: str) -> BatchRow:
    """Run the loop for one CVE; never raises, always returns a row."""
    from .closed_loop import TargetTier
    from .loop_runner import build_controller, write_outputs

    started = time.time()
    try:
        controller = build_controller(
            cve_id=cve_id, tier=TargetTier.TOOLCHAIN, iterations=iterations,
            image=image, workdir=workdir / cve_id, project_root=project_root,
            version_in_range=None, allow_kernel=False, python_exe=python_exe)
        result = controller.run()
        write_outputs(result, workdir / cve_id)
        diagnoses = [record.diagnosis_code for record in result.trace
                     if record.diagnosis_code]
        return BatchRow(
            cve_id=cve_id, status=result.status,
            iterations=result.iterations_used, verdict=result.final_verdict or "",
            diagnosis=diagnoses[-1] if diagnoses else "",
            seconds=round(time.time() - started, 1),
            reason=(result.reasons[0] if result.reasons else "")[:160],
            diagnoses=diagnoses)
    except Exception as exc:  # noqa: BLE001 - one bad CVE must not stop the batch
        return BatchRow(cve_id=cve_id, status="CRASHED", diagnosis=type(exc).__name__,
                        seconds=round(time.time() - started, 1),
                        reason=str(exc)[:160])


def run_batch(cve_ids: List[str], *, iterations: int, workdir: Path,
              project_root: Path, python_exe: str, image: str,
              runner: Optional[Callable[..., BatchRow]] = None,
              progress: Optional[Callable[[BatchRow], None]] = None) -> List[BatchRow]:
    """Run every CVE in order, reporting each row as it completes."""
    runner = runner or run_one
    rows: List[BatchRow] = []
    for cve_id in cve_ids:
        row = runner(cve_id, iterations, workdir, project_root, python_exe, image)
        rows.append(row)
        if progress is not None:
            progress(row)
    return rows


def render_summary(rows: List[BatchRow]) -> str:
    """Markdown table plus the aggregate counts the thesis reports."""
    lines = ["# 工具链闭环批跑结果", "",
             "| CVE | 状态 | 轮数 | 判定 | 终止诊断 | 耗时(s) | 原因 |",
             "|---|---|---|---|---|---|---|"]
    for row in rows:
        reason = row.reason.replace("|", "/").replace("\n", " ")
        lines.append("| %s | %s | %d | %s | %s | %.0f | %s |" % (
            row.cve_id, row.status, row.iterations, row.verdict or "—",
            row.diagnosis or "—", row.seconds, reason))
    total = len(rows)
    supported = sum(1 for r in rows if r.status == "SUPPORTED")
    converged = sum(1 for r in rows if r.status == "SUPPORTED" and r.iterations == 1)
    lines += ["", "## 汇总", "",
              "- 总数：%d" % total,
              "- `SUPPORTED`：%d（一轮收敛 %d）" % (supported, converged),
              "- 其余：%d" % (total - supported), ""]
    return "\n".join(lines)


def write_summary(rows: List[BatchRow], workdir: Path) -> Path:
    workdir.mkdir(parents=True, exist_ok=True)
    path = workdir / "batch_summary.zh-CN.md"
    path.write_text(render_summary(rows), encoding="utf-8")
    data = workdir / "batch_summary.json"
    data.write_text(json.dumps([row.__dict__ for row in rows], ensure_ascii=False,
                               indent=1), encoding="utf-8")
    return path


def main(argv: Optional[list] = None) -> int:
    import argparse, sys
    from .config_loader import resolve_project_root

    parser = argparse.ArgumentParser(description="run the toolchain CVEs in batch")
    parser.add_argument("--iterations", type=int, default=2)
    parser.add_argument("--workdir", default="data/loop/batch")
    parser.add_argument("--image", default="cpg/cuda112-py3:1.0")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--cve", action="append", default=[])
    args = parser.parse_args(argv)

    root = Path(resolve_project_root())
    workdir = root / args.workdir
    cves = args.cve or classify(root / "data" / "inputs")
    if args.limit:
        cves = cves[:args.limit]
    print("[batch] %d 个工具链 CVE: %s" % (len(cves), ", ".join(cves)), flush=True)

    def report(row: BatchRow) -> None:
        print("[batch] %-16s %-10s it=%d %-12s %-20s %.0fs" % (
            row.cve_id, row.status, row.iterations, row.verdict,
            row.diagnosis, row.seconds), flush=True)

    rows = run_batch(cves, iterations=args.iterations, workdir=workdir,
                     project_root=root, python_exe=sys.executable,
                     image=args.image, progress=report)
    path = write_summary(rows, workdir)
    print("[batch] 汇总: %s" % path, flush=True)
    return 0 if all(r.status == "SUPPORTED" for r in rows) else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
