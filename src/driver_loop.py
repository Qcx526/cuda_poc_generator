# -*- coding: utf-8 -*-
"""Driver loop: one state machine, the project's own ClosedLoopController.

The previous version kept a private for-loop, which meant two places decided what
"next round" means. This one builds three stages and hands them to
``ClosedLoopController``; iteration counting, preflight, stopping rules and the
control arm all come from there, so a driver run and a toolchain run fail the same
way and are reported the same way.

Stages:
    generate  analyst (round 1) or analyst-with-feedback -> candidate program
    execute   backend (userspace or kernel gate) -> ExecutionObservation -> state
    feedback  outcome -> the sentence the next analysis starts from
"""

import argparse
import json
from pathlib import Path
from typing import Callable, Dict, Optional

from . import (driver_analyst, driver_exec, driver_feedback, driver_generator,
               driver_outcome)
from .closed_loop import ClosedLoopController, LoopConfig, LoopState, TargetTier
from .config_loader import ConfigLoader
from .llm_client import LLMClient
from .reproduction import ReproductionResult

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORKDIR = ROOT / "data" / "driver" / "llm_poc"


def load_spec(cve: str) -> Optional[dict]:
    path = ROOT / "specs" / cve / "spec.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def describe(spec: Optional[dict], cve: str) -> str:
    if spec and spec.get("oracle"):
        oracle = spec["oracle"]
        return ("%s。受影响：%s。条件：%s。预期：%s"
                % (oracle.get("advisory", cve), oracle.get("affected", "未知"),
                   oracle.get("condition", "未知"), oracle.get("expected_effect", "未知")))
    return "%s：公告描述缺失，请仅基于官方受影响范围做保守推断。" % cve


def _state_of(observation_file: Optional[str]) -> Optional[dict]:
    if not observation_file or not Path(observation_file).is_file():
        return None
    for line in Path(observation_file).read_text(encoding="utf-8").splitlines():
        if line.startswith("CPG_DRIVER "):
            try:
                return json.loads(line[len("CPG_DRIVER "):])
            except ValueError:
                return None
    return None


def driver_grader(state: LoopState) -> ReproductionResult:
    """Grade by what the run state says, never by completion alone.

    ``TARGET_REACHED`` is deliberately NOT ``SUPPORTED``: reaching the code proves
    the entry path, not the vulnerability. Only a bugcheck attributable to the
    target (which needs dump-level evidence this stage does not have) would.
    """
    # The three-condition counters are the toolchain's differential. A driver run
    # has no benign/control matrix here, so the counters say "not measured"
    # rather than "passed": zero because nothing was run, not because nothing
    # crashed.
    def result(verdict: str, reasons: list) -> ReproductionResult:
        return ReproductionResult(verdict=verdict, reasons=reasons,
                                  failed_steps=[], malicious_runs=1,
                                  malicious_crashes=0, benign_runs=0,
                                  benign_crashes=0)

    payload = _state_of(state.observation_file)
    if not payload:
        return result("NOT_VERIFIED", ["没有 driver 执行记录"])
    name = payload.get("state", "")
    reason = payload.get("reason", "")
    if name == driver_outcome.KERNEL_BUGCHECK:
        return result("NOT_VERIFIED",
                      ["内核崩溃，但缺少 dump 归因，不能算作该 CVE 已复现", reason])
    if name == driver_outcome.TARGET_REACHED:
        return result("NOT_VERIFIED", ["到达目标路径，但未证明漏洞触发", reason])
    return result("NOT_VERIFIED", [name, reason])


def discover_success_path(workdir: Path) -> str:
    """Historical experiments, retrieved across every archive on this machine.

    Looking only inside the current workdir is what made this return empty: the
    one run that created a device lived somewhere else. A setup-path run is now
    looked up by content, not by directory.
    """
    from . import history_index

    roots = history_index.default_roots()
    if Path(workdir) not in roots:
        roots.insert(0, Path(workdir))
    experiments = history_index.scan(roots)
    setup = [item for item in experiments
             if item.classification == history_index.SETUP_PATH_SUCCESS]
    return history_index.render(setup[:2])


def _history_block(workdir: Path, cve: str) -> str:
    from . import history_index

    roots = history_index.default_roots()
    if Path(workdir) not in roots:
        roots.insert(0, Path(workdir))
    experiments = history_index.scan(roots)
    chosen = history_index.select(experiments, cve=cve, limit=3)
    return history_index.render(chosen)


def build_stages(*, cve: str, client: LLMClient, backend, spec: Optional[dict],
                 workdir: Path, timeout: int,
                 static_facts: str = "", mutation_context: str = "") -> Dict[str, Callable]:
    description = describe(spec, cve)
    target_dir = workdir / cve
    target_dir.mkdir(parents=True, exist_ok=True)
    history_text = _history_block(workdir, cve)
    memory: Dict[str, object] = {"payload": None, "source": "", "repeat": 0}

    def generate(state: LoopState) -> LoopState:
        # The controller builds a fresh state per iteration and does not carry the
        # previous observation forward, so the stage keeps it. Without this the
        # feedback block is always empty and every round starts from zero - which
        # is exactly the observed symptom: same call, same failure, twice.
        last_run = _state_of(state.observation_file) or memory["payload"]
        previous_source = str(memory["source"])
        feedback = driver_feedback.build(last_run, previous_source=previous_source,
                                         history=[]) if last_run else None

        # A cosmetic edit cannot pass as progress: the failing call is compared by
        # argument text, not by the file's hash.
        if last_run and previous_source:
            repeated = driver_feedback.is_repeat(feedback, previous_source)
            memory["repeat"] = int(memory["repeat"]) + 1 if repeated else 0
            (target_dir / ("repeat_round%d.json" % state.iteration)).write_text(
                json.dumps({"repeated": repeated,
                            "consecutive": memory["repeat"],
                            "failed_api": feedback.failed_api},
                           ensure_ascii=False, indent=2), encoding="utf-8")
            if int(memory["repeat"]) >= 2:
                raise RuntimeError(
                    "NO_PROGRESS：连续两轮重复同一失败调用 %s，停止迭代，需重新推导假设"
                    % feedback.failed_api)

        analysis = driver_analyst.analyse(client, cve=cve, description=description,
                                          static_facts=static_facts,
                                          mutation_context=mutation_context,
                                          spec=spec, last_run=last_run,
                                          history_text=history_text,
                                          record_dir=workdir,
                                          round_index=state.iteration)
        payload = analysis.model_dump()
        (target_dir / ("analysis_round%d.json" % state.iteration)).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        candidate = driver_generator.generate(
            client, cve=cve, analysis=payload, spec=spec, last_run=last_run,
            workdir=workdir, round_index=state.iteration,
            feedback=None if feedback is None else feedback.as_dict(),
            previous_code=previous_source, history_text=history_text,
            mutation_context=mutation_context)
        memory["payload"] = last_run
        memory["source"] = Path(candidate).read_text(encoding="utf-8", errors="replace")
        return state.model_copy(update={"candidate_file": str(candidate)})

    def execute(state: LoopState) -> LoopState:
        candidate = Path(state.candidate_file or "")
        if not candidate.is_file():
            return state.model_copy(update={"stage_error": "没有候选文件"})
        try:
            run = driver_exec.observe(candidate, backend, timeout=timeout)
        except RuntimeError as exc:
            # The gate refusing to run is not a candidate defect; label it so the
            # report says "cannot run here" instead of "the PoC is wrong".
            return state.model_copy(update={"stage_error": "NEEDS_BACKEND: %s" % exc})
        log_path = candidate.parent / "run.log"
        text = driver_exec.observation_text(cve, run)
        log_path.write_text(text + "\n", encoding="utf-8")
        memory["payload"] = _state_of(str(log_path))
        return state.model_copy(update={"observation_file": str(log_path),
                                        "reached": run.outcome.state == driver_outcome.TARGET_REACHED})

    def feedback(state: LoopState) -> LoopState:
        payload = _state_of(state.observation_file) or {}
        move = payload.get("next_move") or ""
        return state.model_copy(update={"directive": move})

    return {"generate": generate, "execute": execute, "feedback": feedback}


def build_controller(*, cve: str, tier: str = TargetTier.DRIVER_USERLAND,
                     iterations: int = 2, allow_kernel: bool = False,
                     workdir: Path = DEFAULT_WORKDIR, timeout: int = 120,
                     client: Optional[LLMClient] = None,
                     backend=None, static_facts: str = "",
                     mutation_context: str = "") -> ClosedLoopController:
    client = client or LLMClient(ConfigLoader())
    backend = backend or driver_exec.build_backend(tier, allow_kernel=allow_kernel)
    spec = load_spec(cve)
    config = LoopConfig(cve_id=cve, tier=tier, max_iterations=max(1, iterations),
                        allow_kernel=allow_kernel, timeout_seconds=max(60, timeout),
                        project_root=str(ROOT), samples_dir=str(workdir / cve))
    stages = build_stages(cve=cve, client=client, backend=backend, spec=spec,
                          workdir=Path(workdir), timeout=timeout,
                          static_facts=static_facts,
                          mutation_context=mutation_context)
    return ClosedLoopController(config, stages, driver_grader)


def run(cve: str, rounds: int = 1, tier: str = TargetTier.DRIVER_USERLAND,
        allow_kernel: bool = False, workdir: Path = DEFAULT_WORKDIR,
        timeout: int = 120, client: Optional[LLMClient] = None,
        backend=None, static_facts: str = "", mutation_context: str = "") -> list:
    controller = build_controller(cve=cve, tier=tier, iterations=rounds,
                                  allow_kernel=allow_kernel, workdir=Path(workdir),
                                  timeout=timeout, client=client, backend=backend,
                                  static_facts=static_facts,
                          mutation_context=mutation_context)
    result = controller.run()
    print("[%s] %s after %d iteration(s)" % (result.status, cve, result.iterations_used))
    for item in result.trace:
        print("  iter %d  %s  %s" % (item.iteration, item.verdict or item.diagnosis_code,
                                     "; ".join(item.reasons)[:90]))
    return [item.model_dump() for item in result.trace]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="driver LLM PoC loop (closed loop)")
    parser.add_argument("--cve", required=True)
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--tier", default=TargetTier.DRIVER_USERLAND,
                        choices=[TargetTier.DRIVER_USERLAND, TargetTier.DRIVER_KERNEL])
    parser.add_argument("--allow-kernel", action="store_true")
    parser.add_argument("--workdir", default=str(DEFAULT_WORKDIR))
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--static-facts", default="",
                        help="path to verified static facts; empty means baseline")
    parser.add_argument("--mutation-seed", type=int, default=None,
                        help="enable structured mutation with this RNG seed")
    args = parser.parse_args(argv)
    facts = Path(args.static_facts).read_text(encoding="utf-8") if args.static_facts else ""
    mutation = ""
    if args.mutation_seed is not None:
        import random

        from . import driver_mutation

        base = driver_mutation.EscapeInput()
        case = driver_mutation.mutate(base, random.Random(args.mutation_seed)).case
        mutation = driver_mutation.context_block(base, case,
                                                 rng_seed=args.mutation_seed)
    trace = run(args.cve, rounds=args.rounds, tier=args.tier,
                allow_kernel=args.allow_kernel, workdir=Path(args.workdir),
                timeout=args.timeout, static_facts=facts,
                mutation_context=mutation)
    print(json.dumps(trace, ensure_ascii=False, indent=2)[:2000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
