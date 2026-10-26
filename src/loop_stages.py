# -*- coding: utf-8 -*-
"""Ready-to-wire stages for the closed loop.

Each stage is a plain callable ``LoopState -> LoopState`` so it can be replaced
by a fake in tests or by a different executor for another target class. The
subprocess runner is injected for the same reason: nothing here needs a GPU,
Docker or a model to be unit-testable.
"""

import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from .closed_loop import LoopConfig, LoopState
from .reproduction import (ReproductionResult, decide, evidence_from_runs,
                           label_for)

Runner = Callable[..., "subprocess.CompletedProcess"]

_CANDIDATE = re.compile(r"Candidate saved:\s*(.+\.py)\s*$", re.MULTILINE)
# The explicit contract is primary; the arrow form stays for older candidates.
_RUN_LINE = re.compile(r"\[CPG_RUN\]\s+(\S+)\s+exit=(-?\d+)")
_LEGACY_RUN_LINE = re.compile(r"([^\s/\\]+\.(?:cubin|elf|bin|dxbc))\s*->\s*exit=(-?\d+)")
# The candidate declares each artifact's role; names alone are not reliable
# ("crafted_overflow.cubin" carries no marker).
_LABEL_LINE = re.compile(r"\[CPG_LABEL\]\s+(\S+)\s+(MALICIOUS|BENIGN|CONTROL)", re.IGNORECASE)

# Compiling a few cubins takes seconds; anything near this bound is hung.
_EXECUTE_TIMEOUT = 300


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


def _find_candidate(project_root: Path, cve_id: str,
                    since: Optional[float] = None) -> Optional[str]:
    """Fall back to the candidate on disk when the CLI exited non-zero."""
    directory = project_root / "data" / "outputs" / cve_id
    # ``cuda_poc_v*.py`` also matches ``cuda_poc_v1.invalid.py``, which the
    # generator saves precisely because it must not run. Falling back to it
    # executes a file whose first line is "// generation failed".
    candidates = [item for item in directory.glob("cuda_poc_v*.py")
                  if ".invalid" not in item.name]
    if since is not None:
        # A candidate from an earlier run is not this run's output. Without
        # this, a failed generation silently graded yesterday's script and the
        # result was attributed to today's attempt.
        candidates = [item for item in candidates
                      if item.stat().st_mtime >= since - 1]
    candidates.sort(key=lambda item: item.stat().st_mtime, reverse=True)
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
        started = time.time()
        completed = runner(command, cwd=context.project_root, timeout=1800)
        # A candidate the generator itself flagged as invalid must not be
        # executed: running it spends the whole execution round to rediscover a
        # syntax error the generator already knows about.
        invalid = re.search(r"STATIC_INVALID://s*(.*)", completed.stdout or "")
        if invalid:
            return LoopState(iteration=state.iteration,
                             stage_error="generation produced STATIC_INVALID: %s"
                                         % invalid.group(1)[:200],
                             diagnosis_code=state.diagnosis_code)
        candidate = parse_candidate_path(completed.stdout) or _find_candidate(
            context.project_root, context.cve_id, since=started)
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


def ship_helpers(context: StageContext, host_dir: Path) -> None:
    """Copy the helper library next to the candidate before it runs.

    The candidate is generated from scratch every attempt, so the bookkeeping
    that a library gets right - extending the string table, sizing a section -
    is re-derived from nothing each time. Shipping the library removes that
    class of mistake instead of asking the prompt to prevent it.
    """
    source = Path(context.project_root) / "tools" / "cpgkit" / "cpgkit.py"
    if not source.is_file():
        return
    try:
        (Path(host_dir) / "cpgkit.py").write_bytes(source.read_bytes())
    except OSError:
        pass  # a read-only workdir must not take the run down


def spec_invocations(context: StageContext) -> List[List[str]]:
    """Every tool the specification says can observe this fault."""
    from .grader_matrix import parse_invocations
    from .spec_model import load

    path = Path(context.project_root) / "specs" / context.cve_id / "spec.json"
    if not path.is_file():
        return []
    try:
        spec = load(path)
    except Exception:  # noqa: BLE001 - a malformed spec must not break execution
        return []
    return parse_invocations(spec.anchor.invocations, spec.anchor.invocation)


_ARTIFACT_SUFFIXES = (".cubin", ".elf", ".fatbin")


def quarantine_stale_artifacts(directory: Path) -> int:
    """Move artifacts from earlier runs aside before this one starts.

    Left in place, they are indistinguishable from what this run produced: the
    manifest would describe files nobody declared, and the fallback glob would
    happily grade last week's cubin.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return 0
    stale = [entry for entry in directory.iterdir()
             if entry.is_file() and (entry.suffix in _ARTIFACT_SUFFIXES
                                     or entry.name == "artifacts.json")]
    if not stale:
        return 0
    import time as _time
    bucket = directory / ("_stale_%d" % int(_time.time()))
    bucket.mkdir(exist_ok=True)
    moved = 0
    for entry in stale:
        try:
            entry.replace(bucket / entry.name)
            moved += 1
        except OSError:
            continue
    return moved


def _declared_artifacts(directory: Path):
    """Read the manifest; fall back to name prefixes when it is absent."""
    from . import artifacts_manifest

    try:
        manifest = artifacts_manifest.load(directory)
    except artifacts_manifest.ManifestError as exc:
        return None, "[CPG_MANIFEST] invalid: %s" % exc
    pairs = artifacts_manifest.entries(manifest, directory)
    problems = artifacts_manifest.validate(manifest, pairs)
    if not pairs:
        return None, "[CPG_MANIFEST] missing: %s" % "; ".join(problems)
    note = "[CPG_MANIFEST] %d artifacts declared" % len(pairs)
    if problems:
        note += " (%s)" % "; ".join(problems)
    return [list(pair) for pair in pairs], note


def _write_matrix_script(target: Path, invocations: List[List[str]],
                         entries: Optional[List[List[str]]] = None) -> None:
    """Write the generated matrix; bytes so Windows cannot add CRLF."""
    from .grader_matrix import render_matrix_script
    target.write_bytes(render_matrix_script(invocations, entries).encode("utf-8"))


_ARTIFACT_SUFFIXES = (".cubin", ".elf", ".fatbin")


def quarantine_stale_artifacts(directory: Path) -> int:
    """Move artifacts from earlier runs aside before this one starts.

    Left in place, they are indistinguishable from what this run produced: the
    manifest would describe files nobody declared, and the fallback glob would
    happily grade last week's cubin.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return 0
    stale = [entry for entry in directory.iterdir()
             if entry.is_file() and (entry.suffix in _ARTIFACT_SUFFIXES
                                     or entry.name == "artifacts.json")]
    if not stale:
        return 0
    import time as _time
    bucket = directory / ("_stale_%d" % int(_time.time()))
    bucket.mkdir(exist_ok=True)
    moved = 0
    for entry in stale:
        try:
            entry.replace(bucket / entry.name)
            moved += 1
        except OSError:
            continue
    return moved


def _declared_artifacts(directory: Path):
    """Read the manifest; fall back to name prefixes when it is absent."""
    from . import artifacts_manifest

    try:
        manifest = artifacts_manifest.load(directory)
    except artifacts_manifest.ManifestError as exc:
        return None, "[CPG_MANIFEST] invalid: %s" % exc
    pairs = artifacts_manifest.entries(manifest, directory)
    problems = artifacts_manifest.validate(manifest, pairs)
    if not pairs:
        return None, "[CPG_MANIFEST] missing: %s" % "; ".join(problems)
    note = "[CPG_MANIFEST] %d artifacts declared" % len(pairs)
    if problems:
        note += " (%s)" % "; ".join(problems)
    return [list(pair) for pair in pairs], note


def _write_matrix_script(target: Path, invocations: List[List[str]],
                         entries: Optional[List[List[str]]] = None) -> None:
    """Write the generated matrix; bytes so Windows cannot add CRLF."""
    from .grader_matrix import render_matrix_script
    target.write_bytes(render_matrix_script(invocations, entries).encode("utf-8"))


def build_docker_command(context: StageContext, candidate: Path,
                         grader_script: str = "") -> List[str]:
    """Hardened container command; identical flags to the validated manual runs."""
    host_dir = candidate.resolve().parent.as_posix()
    return ["docker", "run", "--rm", "--network", "none",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--read-only", "--tmpfs", "/tmp:size=512m",
            "--pids-limit", "256", "--memory", "2g", "--cpus", "1",
            "-v", "%s:/work:rw" % host_dir,
            context.container_image,
            "bash", "-c",
            "cd /work && python3 %s; RC=$?; %s echo HARNESS_RC=$RC"
            % (candidate.name,
               ("sh ./%s; " % grader_script) if grader_script else "")]


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
        manifest_note = ""
        manifest_note = ""
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
                ship_helpers(context, candidate.resolve().parent)
                quarantine_stale_artifacts(candidate.resolve().parent)
                # The grader exercises the artifacts itself: what the candidate
                # chose to run must not decide which tools see its output.
                invocations = spec_invocations(context)
                declared, manifest_note = _declared_artifacts(candidate.resolve().parent)
                grader_script = ""
                if invocations:
                    from .grader_matrix import render_matrix_script
                    target = candidate.resolve().parent / "_grader_matrix.sh"
                    try:
                        # Bytes, not text: writing on Windows turns every newline
                        # into CRLF, and the container's sh then fails on the
                        # carriage returns without saying so.
                        _write_matrix_script(target, invocations, declared)
                        grader_script = target.name
                    except OSError:
                        grader_script = ""
                command = build_docker_command(context, candidate, grader_script)
            else:
                command = [context.python_exe, str(candidate)]
            # A candidate that cannot finish in a few minutes is stuck, not
            # slow: compiling a handful of cubins takes seconds. Left at the
            # old thirty minutes, one hung run consumed the whole budget.
            try:
                completed = runner(command, timeout=_EXECUTE_TIMEOUT)
            except subprocess.TimeoutExpired:
                return LoopState(
                    iteration=state.iteration,
                    stage_error=("execution timed out after %ds: the candidate or the "
                                 "tool matrix did not finish" % _EXECUTE_TIMEOUT),
                    diagnosis_code=state.diagnosis_code)
            output = (completed.stdout or "") + (completed.stderr or "")
            error = None
            # A candidate that failed at its own step is evidence for the
            # diagnoser, not an executor fault: treating it as the latter ends
            # the run before the feedback loop can act on it.
            step_failure = "[CUDA_STEP:" in output and "FAIL" in output
            if (completed.returncode != 0 and not parse_runs(completed.stdout or "")
                    and not step_failure):
                error = "executor rc=%d: %s" % (completed.returncode,
                                                (completed.stderr or "")[-300:])
        if manifest_note:
            output = output + "\n" + manifest_note + "\n"
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
        notes = []
        # A declaration that contradicts a recognisable name is bookkeeping, not
        # evidence: the name wins, the conflict is reported, and grading goes on.
        for run in runs:
            declared = run.get("label")
            if not declared:
                continue
            derived = label_for(run["artifact"])
            if derived != "UNKNOWN" and derived != declared:
                run.pop("label")
                notes.append("标签冲突：%s 声明为 %s，按文件名判为 %s"
                             % (run["artifact"], declared, derived))
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
        result = decide(evidence)
        if notes:
            return result.model_copy(update={"reasons": list(result.reasons) + notes})
        return result
    return grade
