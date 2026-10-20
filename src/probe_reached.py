# -*- coding: utf-8 -*-
"""Did the candidate actually reach the vulnerable code path?

This is the strongest observation the loop can make: a breakpoint inside the
target module. It answers "was the vulnerability exercised" instead of
inferring it from a crash.

Loading notifications (``sxe ld``) proved unreliable in this environment, so
the observer uses a cooperative rendezvous that the PoC contract provides:
after the target library is loaded and before the first trigger call, the
candidate prints ``[CPG_READY] <pid>`` and sleeps when ``CPG_DEBUG_PAUSE`` is
set. The observer attaches inside that window, sets a module-relative
breakpoint, and reports whether it was hit.
"""

import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

READY = "[CPG_READY]"
DONE = "CPG_DONE"

# cdb prints this line only when a breakpoint actually fires. Markers printed
# by a breakpoint command cannot be trusted: cdb echoes the command text,
# which contains the marker verbatim and produced false positives.
_HIT = re.compile(r"Breakpoint\s+\d+\s+hit", re.IGNORECASE)

Runner = Callable[..., "subprocess.CompletedProcess"]

_READY = re.compile(r"\[CPG_READY\]\s*(\d+)")


@dataclass(frozen=True)
class ReachedObservation:
    """``reached`` is None when the observation itself failed."""

    reached: Optional[bool]
    detail: str
    stdout: str = ""


def build_command_file(module: str, rva: int) -> str:
    """Breakpoint script; the only trustworthy hit signal is cdb's own line."""
    return ("lm m %s\n"
            "bp %s+0x%x\n"
            "g\n"
            ".echo %s\n"
            "q\n" % (module, module, rva, DONE))


def parse_observation(text: str) -> ReachedObservation:
    """Read the marker the command file emits.

    ``CPG_HIT`` is printed by the breakpoint's command, so it can only appear
    when control actually reached the address; ``CPG_NO_HIT`` is the fallback
    printed after the target exits.
    """
    if _HIT.search(text or ""):
        return ReachedObservation(True, "breakpoint hit inside the target module")
    if DONE in (text or ""):
        return ReachedObservation(False, "target module loaded but the address was never executed")
    return ReachedObservation(None, "observation inconclusive: no marker in cdb output")


def observe_pid(*, cdb_path: str, pid: int, module: str, rva: int,
                timeout: int = 90,
                runner: Runner = None) -> ReachedObservation:
    """Attach to ``pid`` and report whether ``module+rva`` executed."""
    runner = runner or _default_runner
    with tempfile.TemporaryDirectory() as tmp:
        command_file = Path(tmp) / "observed.txt"
        command_file.write_text(build_command_file(module, rva), encoding="utf-8")
        completed = runner([cdb_path, "-p", str(pid), "-cf", str(command_file)],
                           timeout=timeout)
    return parse_observation((completed.stdout or "") + (completed.stderr or ""))


def parse_ready(text: str) -> Optional[int]:
    """Extract the pid a candidate announced at its rendezvous point."""
    match = _READY.search(text or "")
    return int(match.group(1)) if match else None


def observe_candidate(*, cdb_path: str, candidate: Path, module: str, rva: int,
                      python_exe: str = "python", pause_seconds: int = 20,
                      timeout: int = 120,
                      launcher: Runner = None,
                      observer: Callable[..., ReachedObservation] = observe_pid
                      ) -> ReachedObservation:
    """Run the candidate, rendezvous at ``[CPG_READY]``, then observe.

    ``launcher`` and ``observer`` are injectable so the flow can be tested
    without a debugger or a GPU.
    """
    launcher = launcher or _popen_launcher
    process = launcher([python_exe, str(candidate)],
                       env_extra={"CPG_DEBUG_PAUSE": str(pause_seconds)})
    collected: List[str] = []
    try:
        pid = None
        for line in _iter_lines(process, timeout):
            collected.append(line)
            if READY in line:
                pid = parse_ready(line)
                break
        if pid is None:
            return ReachedObservation(None, "candidate never announced a rendezvous point",
                                      "".join(collected))
        observation = observer(cdb_path=cdb_path, pid=pid, module=module, rva=rva,
                               timeout=timeout)
        # Keep reading so the caller still sees the trigger lines the candidate
        # prints after the rendezvous.
        for line in _iter_lines(process, timeout):
            collected.append(line)
        return ReachedObservation(observation.reached, observation.detail,
                                  "".join(collected))
    finally:
        _terminate(process)


# -- process plumbing (thin, so tests can replace it) --------------------


def _popen_launcher(command: List[str], env_extra: dict):
    import os
    env = dict(os.environ)
    env.update(env_extra)
    return subprocess.Popen(command, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, env=env,
                            bufsize=1)


def _iter_lines(process, timeout: int):
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = process.stdout.readline()
        if not line:
            if process.poll() is not None:
                return
            continue
        yield line


def _terminate(process) -> None:
    if process.poll() is None:
        process.kill()


def _default_runner(command: List[str], *, timeout: int = 90):
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)
