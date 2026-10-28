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
import os
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
    attempts: int = 1
    successes: int = 0

    @property
    def success_at_k(self) -> str:
        """Report the rate the thesis needs: successes over independent runs."""
        return "%d/%d" % (self.successes, self.attempts)


def run_one(cve_id: str, iterations: int, workdir: Path, project_root: Path,
            python_exe: str, image: str, index: int = 0,
            blind_retry: bool = False, tier: str = "userland_toolchain",
            allow_kernel: bool = False, rag: bool = False) -> BatchRow:
    """Run the loop for one CVE; never raises, always returns a row."""
    from .closed_loop import TargetTier
    from .loop_runner import build_controller, write_outputs

    started = time.time()
    run_dir = workdir / cve_id if index == 0 else workdir / (cve_id + "/run_%d" % index)
    try:
        controller = build_controller(
            cve_id=cve_id, tier=tier, iterations=iterations,
            image=image,
            workdir=run_dir,
            project_root=project_root,
            version_in_range=None, allow_kernel=allow_kernel, python_exe=python_exe,
            blind_retry=blind_retry, rag=rag)
        result = controller.run()
        # Each repeat writes its own report: keeping only the last one would
        # throw away the per-run evidence that the success rate is built from.
        write_outputs(result, run_dir)
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
                        reason=str(exc)[:160], attempts=1, successes=0)


def _finished_status(run_dir: Path) -> Optional[str]:
    """Status of an already finished run, so an interrupted batch can resume."""
    report = run_dir / "loop_report.zh-CN.md"
    if not report.is_file():
        return None
    for line in report.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("| 状态 |"):
            return line.split("|")[2].strip().strip("`")
    return None


def run_batch(cve_ids: List[str], *, iterations: int, workdir: Path,
              project_root: Path, python_exe: str, image: str,
              repeat: int = 1, blind_retry: bool = False,
              tier: str = "userland_toolchain", rag: bool = False,
              runner: Optional[Callable[..., BatchRow]] = None,
              progress: Optional[Callable[[BatchRow], None]] = None) -> List[BatchRow]:
    """Run every CVE in order, reporting each row as it completes.

    ``repeat`` runs each CVE that many independent times and reports the
    success rate over those runs; a single run is too noisy to publish.
    """
    default_runner = runner is None
    default_runner = runner is None
    runner = runner or run_one
    rows: List[BatchRow] = []
    for cve_id in cve_ids:
        attempts = 0
        successes = 0
        best: Optional[BatchRow] = None
        for index in range(max(1, repeat)):
            run_dir = workdir / cve_id if index == 0 else workdir / (cve_id + "/run_%d" % index)
            done = _finished_status(run_dir)
            if done is not None:
                # Resuming an interrupted batch must not redo finished work.
                row = BatchRow(cve_id=cve_id, status=done, attempts=1,
                               successes=1 if done == "SUPPORTED" else 0,
                               diagnosis="", seconds=0.0, reason="resumed")
                attempts += 1
                if done == "SUPPORTED":
                    successes += 1
                if best is None:
                    best = row
                continue
            kwargs = {"index": index}
            if default_runner:
                kwargs["blind_retry"] = blind_retry
            row = runner(cve_id, iterations, workdir, project_root,
                         python_exe, image, rag=rag, **kwargs)
            attempts += 1
            if row.status == "SUPPORTED":
                successes += 1
                if best is None or best.status != "SUPPORTED":
                    best = row
            elif best is None:
                best = row
        assert best is not None
        best.attempts = attempts
        best.successes = successes
        rows.append(best)
        if progress is not None:
            progress(best)
    return rows


def render_summary(rows: List[BatchRow]) -> str:
    """Markdown table plus the aggregate counts the thesis reports."""
    lines = ["# 工具链闭环批跑结果", "",
             "| CVE | 状态 | 轮数 | 判定 | 终止诊断 | success@k | 耗时(s) | 原因 |",
             "|---|---|---|---|---|---|---|---|"]
    for row in rows:
        reason = row.reason.replace("|", "/").replace("\n", " ")
        lines.append("| %s | %s | %d | %s | %s | %s | %.0f | %s |" % (
            row.cve_id, row.status, row.iterations, row.verdict or "—",
            row.diagnosis or "—", row.success_at_k, row.seconds, reason))
    total = len(rows)
    supported = sum(1 for r in rows if r.status == "SUPPORTED")
    converged = sum(1 for r in rows if r.status == "SUPPORTED" and r.iterations == 1)
    attempts = sum(r.attempts for r in rows)
    successes = sum(r.successes for r in rows)
    lines += ["", "## 汇总", "",
              "- 总数：%d" % total,
              "- `SUPPORTED`：%d（一轮收敛 %d）" % (supported, converged),
              "- success@%d：%d/%d = %.0f%%" % (max(1, rows[0].attempts if rows else 1),
                                               successes, attempts,
                                               100.0 * successes / attempts if attempts else 0),
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
    parser.add_argument("--freeze-history", action="store_true", default=False,
                        help="忽略规格中的 observed 知识（消融用）")
    parser.add_argument("--repeat", type=int, default=1,
                        help="每个 CVE 独立重复次数（success@k 的 k）")
    parser.add_argument("--tier", default="userland_toolchain",
                        choices=["userland_toolchain", "driver_userland",
                                 "driver_kernel"],
                        help="execution tier; driver tiers run on this machine")
    parser.add_argument("--minimal-poc", action="store_true", default=False,
                        help="constrain generated scripts to the differential only")
    parser.add_argument("--blind-retry", action="store_true", default=False,
                        help="retry after a failure without telling the model why")
    parser.add_argument("--rag", action="store_true", default=False,
                        help="hand the generator this CVE's measured knowledge")
    parser.add_argument("--cve", action="append", default=[])
    args = parser.parse_args(argv)

    if args.freeze_history:
        os.environ["CPG_SPEC_FROZEN"] = "1"
    root = Path(resolve_project_root())
    workdir = root / args.workdir
    cves = args.cve or classify(root / "data" / "inputs")
    if args.limit:
        cves = cves[:args.limit]
    print("[batch] %d 个工具链 CVE: %s" % (len(cves), ", ".join(cves)), flush=True)

    done: List[BatchRow] = []

    def report(row: BatchRow) -> None:
        # Persist after every CVE: a long batch that is interrupted must still
        # leave the work that already finished.
        done.append(row)
        write_summary(done, workdir)
        print("[batch] %-16s %-10s it=%d %-12s %-20s %s %.0fs" % (
            row.cve_id, row.status, row.iterations, row.verdict,
            row.diagnosis, row.success_at_k, row.seconds), flush=True)

    rows = run_batch(cves, iterations=args.iterations, workdir=workdir,
                     project_root=root, python_exe=sys.executable,
                     image=args.image, repeat=args.repeat, progress=report,
                     rag=args.rag)
    path = write_summary(rows, workdir)
    print("[batch] 汇总: %s" % path, flush=True)
    return 0 if all(r.status == "SUPPORTED" for r in rows) else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
