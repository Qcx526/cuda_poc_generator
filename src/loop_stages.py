# -*- coding: utf-8 -*-
"""Ready-to-wire stages for the closed loop.

Each stage is a plain callable ``LoopState -> LoopState`` so it can be replaced
by a fake in tests or by a different executor for another target class. The
subprocess runner is injected for the same reason: nothing here needs a GPU,
Docker or a model to be unit-testable.
"""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from .closed_loop import LoopConfig, LoopState
from .reproduction import ReproductionResult, decide, evidence_from_runs

Runner = Callable[..., "subprocess.CompletedProcess"]

_CANDIDATE = re.compile(r"Candidate saved:\s*(.+\.py)\s*$", re.MULTILINE)
_RUN_LINE = re.compile(r"([^\s/\\]+\.(?:cubin|elf|bin|dxbc))\s*->\s*exit=(\d+)")


@dataclass(frozen=True)
class StageContext:
    """Where the stages run, which image they use, and how risky the target is."""

    project_root: Path
    cve_id: str
    container_image: str
    workdir: Path
    tier: str = "userland_toolchain"
    python_exe: str = "python"


def _default_runner(command: List[str], *, cwd: Optional[Path] = None,
                    timeout: int = 600) -> "subprocess.CompletedProcess":
    return subprocess.run(command, cwd=None if cwd is None else str(cwd),
                          capture_output=True, text=True, timeout=timeout)


# -- generate ------------------------------------------------------------


def parse_candidate_path(stdout: str) -> Optional[str]:
    """Extract the candidate path printed by the existing CLI."""
    match = _CANDIDATE.search(stdout or "")
    return match.group(1).strip() if match else None


def make_generate_stage(context: StageContext,
                        runner: Runner = _default_runner) -> Callable[[LoopState], LoopState]:
    """Run ``main.py --package`` and return the produced candidate path."""

    def stage(state: LoopState) -> LoopState:
        command = [context.python_exe, "main.py", "--cve-id", context.cve_id,
                   "--no-rag", "--package"]
        completed = runner(command, cwd=context.project_root, timeout=1800)
        candidate = parse_candidate_path(completed.stdout)
        if not candidate:
            detail = (completed.stderr or completed.stdout or "")[-400:]
            return LoopState(iteration=state.iteration,
                             stage_error="generation produced no candidate: %s" % detail,
                             diagnosis_code=state.diagnosis_code)
        return LoopState(iteration=state.iteration, candidate_file=candidate,
                         diagnosis_code=state.diagnosis_code,
                         directive=state.directive)
    return stage


# -- execute -------------------------------------------------------------


def build_docker_command(context: StageContext, candidate: Path) -> List[str]:
    """Hardened container command; identical flags to the validated manual runs."""
    host_dir = candidate.resolve().parent.as_posix()
    return ["docker", "run", "--rm", "--network", "none",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--read-only", "--tmpfs", "/tmp:size=512m",
            "--pids-limit", "256", "--memory", "2g", "--cpus", "1",
            "-v", "%s:/work:rw" % host_dir,
            context.container_image,
            "bash", "-c",
            "cd /work && python3 %s; echo HARNESS_RC=$?" % candidate.name]


def make_execute_stage(context: StageContext,
                       runner: Runner = _default_runner) -> Callable[[LoopState], LoopState]:
    """Run the candidate where its target actually exists, then persist output.

    Toolchain targets run in the hardened container. Driver components run on
    the host because D3D11/driver entry points do not exist inside a Linux
    container; isolation there comes from the process boundary and a timeout.
    """

    def stage(state: LoopState) -> LoopState:
        if not state.candidate_file:
            return LoopState(iteration=state.iteration,
                             stage_error="no candidate to execute")
        candidate = Path(state.candidate_file)
        if context.tier == "userland_toolchain":
            command = build_docker_command(context, candidate)
        else:
            command = [context.python_exe, str(candidate)]
        completed = runner(command, timeout=1800)
        context.workdir.mkdir(parents=True, exist_ok=True)
        log = context.workdir / ("iteration_%d_observation.txt" % state.iteration)
        output = (completed.stdout or "") + (completed.stderr or "")
        log.write_text(output, encoding="utf-8")
        # A non-zero executor with no observations is a harness failure, not a
        # statement about the target; keep the two apart so the diagnosis is
        # actionable.
        error = None
        if completed.returncode != 0 and not parse_runs(completed.stdout or ""):
            error = "executor rc=%d: %s" % (completed.returncode,
                                            (completed.stderr or "")[-300:])
        return LoopState(iteration=state.iteration,
                         candidate_file=state.candidate_file,
                         observation_file=str(log),
                         stage_error=error,
                         diagnosis_code=state.diagnosis_code,
                         directive=state.directive)
    return stage


# -- grade ---------------------------------------------------------------


def parse_runs(log_text: str) -> List[dict]:
    """Read ``name -> exit=N`` lines produced by the harness convention."""
    return [{"artifact": match.group(1), "exit_code": int(match.group(2))}
            for match in _RUN_LINE.finditer(log_text or "")]


def make_grader(project_config: LoopConfig,
                version_in_range: Optional[bool] = None) -> Callable[[LoopState], ReproductionResult]:
    """Turn an observation log into the differential verdict."""

    def grade(state: LoopState) -> ReproductionResult:
        if state.stage_error and not state.observation_file:
            return ReproductionResult(
                verdict="NOT_VERIFIED", reasons=[state.stage_error],
                failed_steps=[], malicious_runs=0, malicious_crashes=0,
                benign_runs=0, benign_crashes=0)
        log_path = Path(state.observation_file or "")
        text = log_path.read_text(encoding="utf-8") if log_path.is_file() else ""
        runs = parse_runs(text)
        if not runs:
            return ReproductionResult(
                verdict="NOT_VERIFIED",
                reasons=["未观察到任何样本退出码；输入可能未到达解析器"],
                failed_steps=[], malicious_runs=0, malicious_crashes=0,
                benign_runs=0, benign_crashes=0)
        import hashlib
        evidence = evidence_from_runs(
            runs=runs, source_sha256=hashlib.sha256(text.encode()).hexdigest(),
            target_version_in_range=version_in_range)
        return decide(evidence)
    return grade
