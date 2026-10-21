# -*- coding: utf-8 -*-
"""Closed-loop PoC synthesis controller.

Turns the four manual stages exercised during the live runs — generate,
execute in isolation, grade with differential evidence, feed the failure
back — into a bounded state machine.

Three invariants, all learned from real runs:

1. The loop's objective is the differential verdict (SUPPORTED), never
   "a crash was observed". A loop that stops on the first crash converges to
   CVE-2025-23340-style false positives where every control crashes too.
2. Driver/kernel targets never loop unattended. Each probe may bugcheck the
   host, so the tier gate blocks them unless explicitly allowed, and the
   execution stage is limited to a single shot per iteration.
3. Only attributable failures feed back. "No crash" alone is not a reason;
   the grader's structured reason (missing baseline, controls crashed,
   NOT_INITIALIZED) is.
"""

import subprocess
from typing import Callable, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .failure_taxonomy import diagnose, is_retryable
from .reproduction import ReproductionResult


class TargetTier:
    """Execution risk tier; drives the safety gate."""

    TOOLCHAIN = "userland_toolchain"
    DRIVER_USERLAND = "driver_userland"
    DRIVER_KERNEL = "driver_kernel"


class LoopConfig(BaseModel):
    """Loop configuration; frozen so a stage cannot widen its own budget."""

    model_config = ConfigDict(strict=True, frozen=True)

    cve_id: str
    tier: str = TargetTier.TOOLCHAIN
    max_iterations: int = Field(default=2, ge=1, le=5)
    container_image: str = "cpg/cuda112-py3:1.0"
    samples_dir: str = ""
    allow_kernel: bool = False
    allow_native: bool = False
    timeout_seconds: int = Field(default=600, ge=60, le=3600)
    project_root: str = ""


class LoopState(BaseModel):
    """Everything one iteration produced; fed to the next iteration."""

    model_config = ConfigDict(strict=True, frozen=True)

    iteration: int
    candidate_file: Optional[str] = None
    verdict: Optional[str] = None
    grader_reasons: List[str] = Field(default_factory=list)
    stage_error: Optional[str] = None
    observation_file: Optional[str] = None
    reached: Optional[bool] = None
    diagnosis_code: Optional[str] = None
    directive: Optional[str] = None


class IterationRecord(BaseModel):
    """One line of the audit trail; the thesis appendix reads this."""

    model_config = ConfigDict(strict=True, frozen=True)

    iteration: int
    verdict: Optional[str] = None
    diagnosis_code: Optional[str] = None
    directive: Optional[str] = None
    reasons: List[str] = Field(default_factory=list)
    stage_error: Optional[str] = None


class LoopResult(BaseModel):
    """Final outcome with the full iteration trace for the thesis record."""

    model_config = ConfigDict(strict=True, frozen=True)

    cve_id: str
    status: str  # SUPPORTED | EXHAUSTED | BLOCKED | ERROR
    iterations_used: int
    final_verdict: Optional[str] = None
    reasons: List[str] = Field(default_factory=list)
    trace: List[IterationRecord] = Field(default_factory=list)


Stage = Callable[[LoopState], LoopState]


class ClosedLoopController:
    """Run generate -> execute -> grade -> feedback with bounded iterations."""

    def __init__(self, config: LoopConfig, stages: Dict[str, Stage],
                 grader: Callable[[LoopState], ReproductionResult]) -> None:
        self.config = config
        self.stages = stages
        self.grader = grader

    # -- safety gate ---------------------------------------------------

    def preflight(self) -> Optional[str]:
        """Return a blocking reason, or None when the loop may run."""
        if self.config.tier == TargetTier.DRIVER_KERNEL and not self.config.allow_kernel:
            return ("kernel-tier target requires allow_kernel=True and a host "
                    "snapshot; unattended kernel probing can bugcheck the only "
                    "workstation")
        if not self.stages.get("execute"):
            return "no execution stage configured"
        return None

    # -- loop ------------------------------------------------------------

    def _stage_failure(self, trace: List[IterationRecord], iteration: int,
                       stage_name: str, detail: str) -> LoopResult:
        """Record the failing stage and stop; never continue past a failure."""
        reason = f"stage {stage_name} failed: {detail}"
        # A missing platform is not a candidate defect: label it so the report
        # says "cannot run here" instead of "the PoC is wrong".
        code = "STAGE_ERROR"
        for known in ("PLATFORM_UNAVAILABLE", "NEEDS_BACKEND"):
            if detail.startswith(known):
                code = known
                break
        trace.append(IterationRecord(iteration=iteration,
                                     diagnosis_code=code,
                                     stage_error=reason, reasons=[reason]))
        return LoopResult(cve_id=self.config.cve_id, status="ERROR",
                          iterations_used=iteration, reasons=[reason],
                          trace=trace)

    def run(self) -> LoopResult:
        blocked = self.preflight()
        if blocked:
            return LoopResult(cve_id=self.config.cve_id, status="BLOCKED",
                              iterations_used=0, reasons=[blocked])

        trace: List[IterationRecord] = []
        state = LoopState(iteration=0)
        for iteration in range(1, self.config.max_iterations + 1):
            state = LoopState(iteration=iteration,
                              diagnosis_code=state.diagnosis_code,
                              directive=state.directive)
            for stage_name in ("generate", "execute"):
                try:
                    state = self.stages[stage_name](state)
                except Exception as exc:  # noqa: BLE001 - recorded, not raised
                    return self._stage_failure(trace, iteration, stage_name, str(exc))
                # A stage that reports an error must stop the iteration: letting
                # the next stage run would overwrite the real cause (observed:
                # a generation failure surfaced as "no candidate to execute").
                if state.stage_error:
                    return self._stage_failure(trace, iteration, stage_name,
                                               state.stage_error)

            result = self.grader(state)
            diagnosis = diagnose(verdict=result.verdict,
                                 reasons=list(result.reasons),
                                 stage_error=state.stage_error,
                                 reached=state.reached)
            state = LoopState(
                iteration=iteration, candidate_file=state.candidate_file,
                verdict=result.verdict, grader_reasons=list(result.reasons),
                stage_error=state.stage_error,
                reached=state.reached,
                diagnosis_code=None if diagnosis is None else diagnosis.code,
                directive=None if diagnosis is None else diagnosis.directive)
            trace.append(IterationRecord(
                iteration=iteration, verdict=result.verdict,
                diagnosis_code=state.diagnosis_code,
                directive=state.directive,
                reasons=list(result.reasons), stage_error=state.stage_error))

            if result.verdict == "SUPPORTED":
                return LoopResult(
                    cve_id=self.config.cve_id, status="SUPPORTED",
                    iterations_used=iteration, final_verdict="SUPPORTED",
                    reasons=list(result.reasons), trace=trace)
            if not is_retryable(diagnosis):
                # Unclassified or unactionable: another attempt would not help.
                return LoopResult(
                    cve_id=self.config.cve_id, status="EXHAUSTED",
                    iterations_used=iteration, final_verdict=result.verdict,
                    reasons=list(result.reasons), trace=trace)
            # Attributable failure: hand the directive to the next iteration.
            if "feedback" in self.stages:
                state = self.stages["feedback"](state)

        return LoopResult(
            cve_id=self.config.cve_id, status="EXHAUSTED",
            iterations_used=self.config.max_iterations,
            final_verdict=state.verdict, reasons=list(state.grader_reasons),
            trace=trace)


# -- default execution stage ---------------------------------------------


def docker_matrix_stage(config: LoopConfig,
                        artifacts: List[str]) -> Callable[[LoopState], LoopState]:
    """Build an execution stage that runs artifacts inside the hardened container.

    The command matches the flags validated during the live runs: no network,
    no capabilities, read-only root, bounded memory and pids.
    """
    from pathlib import Path

    def execute(state: LoopState) -> LoopState:
        if config.tier == TargetTier.DRIVER_KERNEL:
            raise RuntimeError("kernel tier allows a single probe per iteration")
        if config.tier == TargetTier.DRIVER_USERLAND:
            # The target is a Windows driver DLL: the Linux container cannot even
            # load it. Run where the target lives, and only with an explicit
            # opt-in - a native probe shares the operator's machine.
            from .backends import BackendRegistry, TargetProfile
            # The specification knows where the target lives; the tier is only a
            # fallback for inputs that have no specification yet.
            profile = TargetProfile.for_tier(config.tier)
            if config.project_root:
                spec_path = (Path(config.project_root) / "specs" / config.cve_id
                             / "spec.json")
                if spec_path.is_file():
                    try:
                        from .spec_model import load as load_spec
                        profile = load_spec(spec_path).target.as_profile()
                    except Exception:  # noqa: BLE001 - fall back to the tier
                        pass
            registry = BackendRegistry()
            backend = registry.select(profile) if config.allow_native else None
            if backend is None:
                reason = ("NEEDS_BACKEND: pass allow_native=True to run a driver "
                          "PoC on this host" if not config.allow_native
                          else registry.describe(profile))
                return LoopState(iteration=state.iteration,
                                 candidate_file=state.candidate_file,
                                 stage_error=reason)
            observation = backend.run(Path(state.candidate_file),
                                      timeout=config.timeout_seconds)
            log = Path(config.samples_dir) / "loop_native_out.txt"
            log.parent.mkdir(parents=True, exist_ok=True)
            # The grader reads this file, so the process result is appended as a
            # note. It is deliberately not a [CPG_RUN] line: an unlabelled crash
            # of the harness would be evidence of nothing.
            log.write_text("%s%s\n[CPG_NOTE] process exit=%s crashed=%s reached=%s\n"
                           % (observation.stdout, observation.stderr,
                              observation.exit_code, observation.crashed,
                              observation.reached), encoding="utf-8")
            return LoopState(iteration=state.iteration,
                             candidate_file=state.candidate_file,
                             observation_file=str(log),
                             reached=observation.reached)
        harness = Path(config.samples_dir) / "run_matrix.sh"
        command = ["docker", "run", "--rm", "--network", "none",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                   "--read-only", "--tmpfs", "/tmp:size=512m",
                   "--pids-limit", "256", "--memory", "2g", "--cpus", "1",
                   "-v", f"{config.samples_dir}:/work:rw",
                   config.container_image, "bash", str(harness)]
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=config.timeout_seconds)
        out = Path(config.samples_dir) / "loop_matrix_out.txt"
        out.write_text(completed.stdout + completed.stderr, encoding="utf-8")
        return LoopState(iteration=state.iteration,
                         candidate_file=state.candidate_file,
                         stage_error=None if completed.returncode == 0
                         else f"executor rc={completed.returncode}")
    return execute
