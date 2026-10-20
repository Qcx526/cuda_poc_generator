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
# The explicit contract is primary; the arrow form stays for older candidates.
_RUN_LINE = re.compile(r"\[CPG_RUN\]\s+(\S+)\s+exit=(-?\d+)")
_LEGACY_RUN_LINE = re.compile(r"([^\s/\\]+\.(?:cubin|elf|bin|dxbc))\s*->\s*exit=(-?\d+)")
# The candidate declares each artifact's role; names alone are not reliable
# ("crafted_overflow.cubin" carries no marker).
_LABEL_LINE = re.compile(r"\[CPG_LABEL\]\s+(\S+)\s+(MALICIOUS|BENIGN|CONTROL)", re.IGNORECASE)


@dataclass(frozen=True)
class StageContext:
    """Where the stages run, which image they use, and how risky the target is."""

    project_root: Path
    cve_id: str
    container_image: str
    workdir: Path
    tier: str = "userland_toolchain"
    python_exe: str = "python"
    module: str = ""
    rva: int = 0
    cdb_path: str = ""


def _default_runner(command: List[str], *, cwd: Optional[Path] = None,
                    timeout: int = 600) -> "subprocess.CompletedProcess":
    return subprocess.run(command, cwd=None if cwd is None else str(cwd),
                          capture_output=True, text=True, timeout=timeout)


# -- generate ------------------------------------------------------------


def parse_candidate_path(stdout: str) -> Optional[str]:
    """Extract the candidate path printed by the existing CLI."""
    match = _CANDIDATE.search(stdout or "")
    return match.group(1).strip() if match else None


def _find_candidate(project_root: Path, cve_id: str) -> Optional[str]:
    """Fall back to the candidate on disk when the CLI exited non-zero."""
    directory = project_root / "data" / "outputs" / cve_id
    candidates = sorted(directory.glob("cuda_poc_v*.py"),
                        key=lambda item: item.stat().st_mtime, reverse=True)
    return str(candidates[0]) if candidates else None


def make_generate_stage(context: StageContext,
                        runner: Runner = _default_runner) -> Callable[[LoopState], LoopState]:
    """Run ``main.py --package`` and return the produced candidate path."""

    def stage(state: LoopState) -> LoopState:
        # No --package: delivering a ZIP is unrelated to grading, and a
        # packaging failure made the stage report "no candidate" even though
        # the candidate had been written.
        command = [context.python_exe, "main.py", "--cve-id", context.cve_id,
                   "--no-rag"]
        if state.directive:
            command += ["--feedback", state.directive]
        completed = runner(command, cwd=context.project_root, timeout=1800)
        candidate = parse_candidate_path(completed.stdout) or _find_candidate(
            context.project_root, context.cve_id)
        if not candidate:
            # Keep the whole subprocess output: a 60-second failure is a startup
            # problem, and the last 400 characters never show it.
            context.workdir.mkdir(parents=True, exist_ok=True)
            log = context.workdir / ("iteration_%d_generate.log" % state.iteration)
            log.write_text((completed.stdout or "") + (completed.stderr or ""),
                           encoding="utf-8")
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
                       runner: Runner = _default_runner,
                       probe: Optional[Callable[..., object]] = None
                       ) -> Callable[[LoopState], LoopState]:
    """Run the candidate where its target exists and record whether it reached it.

    Two observation modes:
    - plain execution (artifact exit codes come from stdout);
    - instrumented execution, when a module+RVA is configured: the candidate
      rendezvouses at ``[CPG_READY]``, a breakpoint is set inside the target
      module, and ``reached`` is recorded alongside its output.
    """

    def stage(state: LoopState) -> LoopState:
        if not state.candidate_file:
            return LoopState(iteration=state.iteration,
                             stage_error="no candidate to execute")
        candidate = Path(state.candidate_file)
        reached: Optional[bool] = None
        detail = ""
        if context.module and context.rva and context.cdb_path:
            observe = probe or _default_probe
            observation = observe(candidate=candidate, cdb_path=context.cdb_path,
                                  expression="%s+0x%x" % (context.module, context.rva),
                                  python_exe=context.python_exe)
            output = getattr(observation, "stdout", "") or ""
            reached = getattr(observation, "reached", None)
            detail = "\n[probe_reached] %s\n" % getattr(observation, "detail", "")
            error = None
        else:
            if context.tier == "userland_toolchain":
                command = build_docker_command(context, candidate)
            else:
                command = [context.python_exe, str(candidate)]
            completed = runner(command, timeout=1800)
            output = (completed.stdout or "") + (completed.stderr or "")
            error = None
            if completed.returncode != 0 and not parse_runs(completed.stdout or ""):
                error = "executor rc=%d: %s" % (completed.returncode,
                                                (completed.stderr or "")[-300:])
        context.workdir.mkdir(parents=True, exist_ok=True)
        log = context.workdir / ("iteration_%d_observation.txt" % state.iteration)
        log.write_text(output + detail, encoding="utf-8")
        return LoopState(iteration=state.iteration,
                         candidate_file=state.candidate_file,
                         observation_file=str(log),
                         stage_error=error,
                         reached=reached,
                         diagnosis_code=state.diagnosis_code,
                         directive=state.directive)
    return stage


def _default_probe(*, candidate: Path, cdb_path: str, expression: str,
                   python_exe: str):
    from .probe_reached import observe_candidate
    return observe_candidate(cdb_path=cdb_path, candidate=candidate,
                             expression=expression, python_exe=python_exe)


# -- grade ---------------------------------------------------------------


def parse_runs(log_text: str) -> List[dict]:
    """Read ``name -> exit=N`` lines produced by the harness convention."""
    text = log_text or ""
    labels = {name: role.upper() for name, role in _LABEL_LINE.findall(text)}
    matches = list(_RUN_LINE.finditer(text))
    if not matches:
        matches = list(_LEGACY_RUN_LINE.finditer(text))
    runs = []
    for match in matches:
        run = {"artifact": match.group(1), "exit_code": int(match.group(2))}
        if match.group(1) in labels:
            run["label"] = labels[match.group(1)]
        runs.append(run)
    return runs


def _first_failed_step(log_text: str) -> str:
    """Return the first ``[CUDA_STEP:..] ... FAIL | detail`` line, if any."""
    for line in (log_text or "").splitlines():
        if "[CUDA_STEP:" in line and "FAIL" in line:
            return line.strip()[:240]
    return ""


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
            step = _first_failed_step(text)
            reason = ("步骤失败：%s" % step) if step else \
                "未观察到任何样本退出码；输入可能未到达解析器"
            return ReproductionResult(
                verdict="NOT_VERIFIED",
                reasons=[reason],
                failed_steps=[], malicious_runs=0, malicious_crashes=0,
                benign_runs=0, benign_crashes=0)
        import hashlib
        try:
            evidence = evidence_from_runs(
                runs=runs, source_sha256=hashlib.sha256(text.encode()).hexdigest(),
                target_version_in_range=version_in_range)
        except ValueError as exc:
            # A contradictory declaration is evidence about the candidate, not
            # a reason to crash the loop.
            return ReproductionResult(
                verdict="NOT_VERIFIED", reasons=["标签冲突：%s" % exc],
                failed_steps=[], malicious_runs=0, malicious_crashes=0,
                benign_runs=0, benign_crashes=0)
        return decide(evidence)
    return grade
