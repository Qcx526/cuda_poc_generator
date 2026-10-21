# -*- coding: utf-8 -*-
"""Command-line runner: one command drives the whole closed loop.

    python -m src.loop_runner --cve-id CVE-2025-23340 --iterations 2

The runner only assembles existing pieces; every decision it makes is a
constant pulled from the tier, never a judgement call.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from .closed_loop import (ClosedLoopController, LoopConfig, LoopResult,
                          LoopState, TargetTier)
from .loop_report import render_loop_report
from .loop_stages import (StageContext, make_execute_stage, make_generate_stage,
                          make_grader)


def build_controller(*, cve_id: str, tier: str, iterations: int, image: str,
                     workdir: Path, project_root: Path,
                     version_in_range: Optional[bool], allow_kernel: bool,
                     python_exe: str, runner=None,
                     fixed_candidate: Optional[str] = None,
                     module: str = "", rva: int = 0,
                     cdb_path: str = "") -> ClosedLoopController:
    """Wire the three stages and the grader into a controller."""
    config = LoopConfig(cve_id=cve_id, tier=tier, max_iterations=iterations,
                        container_image=image, samples_dir=str(workdir),
                        allow_kernel=allow_kernel)
    context = StageContext(project_root=project_root, cve_id=cve_id,
                           container_image=image, workdir=workdir, tier=tier,
                           python_exe=python_exe, module=module, rva=rva,
                           cdb_path=cdb_path)
    kwargs = {} if runner is None else {"runner": runner}
    if fixed_candidate:
        # Reuse an existing candidate: lets an operator re-grade a known PoC
        # without paying for another generation round.
        generate = lambda state: LoopState(iteration=state.iteration,
                                           candidate_file=fixed_candidate,
                                           diagnosis_code=state.diagnosis_code,
                                           directive=state.directive)
    else:
        generate = make_generate_stage(context, **kwargs)
    stages = {"generate": generate,
              "execute": make_execute_stage(context, **kwargs)}
    return ClosedLoopController(config, stages, make_grader(config, version_in_range))


def write_outputs(result: LoopResult, workdir: Path,
                  project_root: Optional[Path] = None) -> Path:
    """Persist the trace report next to the observations."""
    workdir.mkdir(parents=True, exist_ok=True)
    report = workdir / "loop_report.zh-CN.md"
    report.write_text(render_loop_report(result), encoding="utf-8")
    record_history(result, project_root or Path.cwd())
    return report


def record_history(result: LoopResult, project_root: Path) -> None:
    """Append this run to the specification's history (the write-back loop).

    A specification that never learns from its own runs is a static document;
    recording attempts is what makes the next run on this target cheaper.
    """
    from .spec_model import load as load_spec

    path = project_root / "specs" / result.cve_id / "spec.json"
    if not path.is_file():
        return
    try:
        spec = load_spec(path)
    except Exception:  # noqa: BLE001 - never fail a run over its record
        return
    for record in result.trace:
        spec.record_attempt(iteration=record.iteration,
                            verdict=record.verdict or "",
                            diagnosis=record.diagnosis_code or "")
    spec.save(path)


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="closed-loop PoC synthesis")
    parser.add_argument("--cve-id", required=True)
    parser.add_argument("--tier", default=TargetTier.TOOLCHAIN,
                        choices=[TargetTier.TOOLCHAIN, TargetTier.DRIVER_USERLAND,
                                 TargetTier.DRIVER_KERNEL])
    parser.add_argument("--iterations", type=int, default=2)
    parser.add_argument("--image", default="cpg/cuda112-py3:1.0")
    parser.add_argument("--workdir", default="data/loop")
    parser.add_argument("--version-in-range", default="unknown",
                        choices=["yes", "no", "unknown"])
    parser.add_argument("--allow-kernel", action="store_true")
    parser.add_argument("--candidate", default=None,
                        help="reuse this candidate instead of generating one")
    parser.add_argument("--module", default="",
                        help="target module for the reached-observer")
    parser.add_argument("--rva", default="0", help="hex RVA inside --module")
    parser.add_argument("--cdb", default="", help="path to cdb.exe")
    args = parser.parse_args(argv)

    workdir = Path(args.workdir) / args.cve_id
    version = {"yes": True, "no": False, "unknown": None}[args.version_in_range]
    controller = build_controller(
        cve_id=args.cve_id, tier=args.tier, iterations=args.iterations,
        image=args.image, workdir=workdir, project_root=Path.cwd(),
        version_in_range=version, allow_kernel=args.allow_kernel,
        python_exe=sys.executable, fixed_candidate=args.candidate,
        module=args.module, rva=int(args.rva, 16), cdb_path=args.cdb)
    result = controller.run()
    report = write_outputs(result, workdir)
    print("[loop] status=%s iterations=%d verdict=%s" % (
        result.status, result.iterations_used, result.final_verdict))
    print("[loop] report: %s" % report)
    return 0 if result.status == "SUPPORTED" else 1


if __name__ == "__main__":
    sys.exit(main())
