# -*- coding: utf-8 -*-
"""Run driver candidates through the existing backends, with one kernel gate.

There are three different things this module keeps apart, because conflating them
is what makes a driver loop unsafe:

1. A userspace process that happens to talk to a driver (``driver_userland``).
   It can fault, but it cannot take the machine down, so it runs through the
   ordinary ``WindowsNativeBackend``.
2. A candidate that drives a kernel path (``driver_kernel``). One execution only,
   environment checked first, bugcheck watched after, and no automatic second try.
3. "allow_kernel=True" - an intention, not a capability. It is not sufficient on
   its own; the gate also requires a passing recovery check before every run.

The gate wraps a backend rather than replacing one: ``WindowsNativeBackend`` keeps
its job (start the process, collect output), and this module adds the decisions
around it.
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import driver_outcome
from .backends import (BackendRegistry, ExecutionObservation, TargetProfile,
                       WindowsNativeBackend)

# ---------------------------------------------------------------------------
# environment check
# ---------------------------------------------------------------------------


@dataclass
class GateReport:
    ready: bool
    reasons: List[str] = field(default_factory=list)
    detail: Dict[str, object] = field(default_factory=dict)


def environment_ready() -> GateReport:
    """Can this host survive a bugcheck and come back?

    The check is deliberately about *recovery*, not about permission: a machine
    without a crash dump or auto-restart still runs the probe, it just cannot tell
    anyone what happened afterwards.
    """
    reasons: List[str] = []
    detail: Dict[str, object] = {}
    try:
        from . import driver_crash
        uptime = driver_crash.uptime_seconds()
        detail["uptime_seconds"] = uptime
        bugcheck = driver_crash.last_bugcheck(with_time=True)
        detail["last_bugcheck"] = bugcheck
    except Exception as exc:  # noqa: BLE001 - absence of evidence blocks the run
        reasons.append("无法读取崩溃记录接口: %s" % exc)
        return GateReport(False, reasons, detail)

    if uptime is not None and uptime < 90:
        reasons.append("系统启动不足 90 秒（%.0fs），上次崩溃后的状态尚未稳定" % uptime)
    if not Path("C:/Windows/Minidump").is_dir():
        reasons.append("缺少 Minidump 目录：崩溃后无法取证")
    return GateReport(not reasons, reasons, detail)


# ---------------------------------------------------------------------------
# kernel gate
# ---------------------------------------------------------------------------


class KernelOneShotGate:
    """One execution, with the environment checked on both sides of it.

    ``allow_kernel`` is accepted as an argument for the sake of the caller's
    intent, but it never substitutes for the recovery check. Once a run has been
    made, the gate refuses a second one: after a bugcheck the host may be alive
    but not trustworthy, and a retry loop is how a test machine is lost.
    """

    name = "kernel_one_shot"
    platform = "windows"
    privilege = "kernel"

    def __init__(self, inner=None, *, allow_kernel: bool = False,
                 check: Callable[[], GateReport] = environment_ready) -> None:
        self.inner = inner or WindowsNativeBackend()
        self.allow_kernel = allow_kernel
        self._check = check
        self.consumed = False
        self.last_gate: Optional[GateReport] = None
        self.records: List[Dict[str, object]] = []

    def available(self) -> bool:
        if not self.allow_kernel:
            return False
        return self._check().ready and not self.consumed

    def run(self, candidate: Path, *, timeout: int) -> ExecutionObservation:
        if not self.allow_kernel:
            raise RuntimeError(
                "kernel 执行需要 allow_kernel=True；它只是意图声明，仍会二次校验环境")
        if self.consumed:
            raise RuntimeError(
                "本批次已执行过一次内核候选；BugCheck 后禁止自动重试，请人工确认环境")
        gate = self._check()
        self.last_gate = gate
        if not gate.ready:
            raise RuntimeError("环境未通过恢复检查：%s" % "；".join(gate.reasons))

        started = time.time()
        observation = self.inner.run(candidate, timeout=timeout)
        elapsed = time.time() - started
        self.consumed = True

        after = self._check()
        bugcheck = None
        try:
            from . import driver_crash
            record = driver_crash.last_bugcheck(with_time=True)
            if record and record.get("time") is not None:
                bugcheck = record
        except Exception:  # noqa: BLE001 - absence is not proof of absence
            bugcheck = None

        self.records.append({"elapsed": elapsed, "before": gate.detail,
                             "after": after.detail, "bugcheck": bugcheck})
        note = "one-shot kernel run; elapsed=%.1fs" % elapsed
        return ExecutionObservation(
            backend=self.name, exit_code=observation.exit_code,
            fault_module=observation.fault_module, reached=observation.reached,
            stdout=observation.stdout, stderr=observation.stderr,
            artifacts=list(observation.artifacts), note=note)


# ---------------------------------------------------------------------------
# backend selection and observation
# ---------------------------------------------------------------------------


def build_backend(tier: str, *, allow_kernel: bool = False,
                  registry: Optional[BackendRegistry] = None,
                  check: Callable[[], GateReport] = environment_ready):
    """Return the backend for a tier, or raise NEEDS_BACKEND.

    ``driver_kernel`` never falls back to the userspace backend: a silent
    downgrade would run a kernel probe as a userspace one and report "no crash".
    """
    profile = TargetProfile.for_tier(tier)
    if profile.privilege == "kernel":
        return KernelOneShotGate(allow_kernel=allow_kernel, check=check)
    registry = registry or BackendRegistry()
    chosen = registry.select(profile)
    if chosen is None:
        raise RuntimeError(registry.describe(profile))
    return chosen


@dataclass
class DriverRun:
    """Everything one execution produced, with claims and evidence kept apart.

    ``claims`` is what the candidate said about itself - useful for the next
    prompt, worthless as proof. ``external`` is what an outside observer saw; it
    can only be filled by a producer in :data:`TRUSTED_PRODUCERS`, because a
    field named "external" is not evidence either.
    """

    observation: ExecutionObservation
    outcome: driver_outcome.Outcome
    claims: Dict[str, object] = field(default_factory=dict)
    external: List[Dict[str, object]] = field(default_factory=list)


# A producer must name itself, and only these names are accepted. The list is
# short on purpose: a debugger transcript or a probe runner is an observer; a
# generated candidate printing a line is not.
TRUSTED_PRODUCERS = ("cdb_trace", "probe_runner")
EXTERNAL_SIDECAR = "external_evidence.json"


def parse_claims(text: str) -> Dict[str, object]:
    """The candidate's own account. Kept verbatim, never used as proof."""
    for line in reversed(text.splitlines()):
        if line.startswith("CPG_RESULT "):
            try:
                return json.loads(line[len("CPG_RESULT "):])
            except ValueError:
                return {}
    return {}


def normalise_external(records: Optional[List[Dict[str, object]]]) -> List[Dict[str, object]]:
    """Accept only well-formed records from a producer that can actually observe.

    A record without a trusted producer is dropped: otherwise the name of the
    field becomes the security boundary, and the candidate could write it.
    """
    kept = []
    for record in records or []:
        if not isinstance(record, dict):
            continue
        producer = str(record.get("producer", ""))
        if producer not in TRUSTED_PRODUCERS:
            continue
        kept.append({"producer": producer, "hit": bool(record.get("hit")),
                     "module": record.get("module", ""),
                     "rva": record.get("rva", ""),
                     "where": record.get("where", ""),
                     "command": record.get("command", "")})
    return kept


def make_cdb_observer(trace_call, probe) -> Callable[[Path, int], List[Dict[str, object]]]:
    """Adapt a cdb-style tracer into an evidence producer.

    ``trace_call(program, probe, timeout)`` is the existing tracer; it is passed
    in rather than imported so this module does not grow a dependency on the
    debugger being installed.
    """
    def observer(candidate: Path, timeout: int) -> List[Dict[str, object]]:
        result = trace_call(candidate, probe, timeout)
        return [{"producer": "cdb_trace", "hit": bool(getattr(result, "hit", False)),
                 "module": getattr(probe, "module", ""),
                 "rva": hex(getattr(probe, "rva", 0) or 0),
                 "where": "%s+%s" % (getattr(probe, "module", ""),
                                     hex(getattr(probe, "rva", 0) or 0)),
                 "command": "cdb"}]
    return observer


def observe(candidate: Path, backend, *, timeout: int = 120,
            expected_reached: bool = False,
            observer: Optional[Callable[[Path, int], List[Dict[str, object]]]] = None,
            ) -> DriverRun:
    """Run once through the backend, then attribute what happened.

    The observer runs *after* the candidate, out of process, so nothing the
    candidate prints can reach it.
    """
    observation = backend.run(candidate, timeout=timeout)
    text = (observation.stdout or "") + (observation.stderr or "")
    claims = parse_claims(text)
    external = normalise_external(observer(candidate, timeout) if observer else None)
    # Evidence goes to a sidecar, never into the log text: the log contains the
    # candidate's own stdout, so anything parsed from it could have been printed
    # by the candidate. The sidecar is written here, after the run.
    if external:
        (Path(candidate).parent / EXTERNAL_SIDECAR).write_text(
            json.dumps({"written_by": "driver_exec", "records": external},
                       ensure_ascii=False, indent=2), encoding="utf-8")
    outcome = driver_outcome.classify(returncode=observation.exit_code,
                                      output=text,
                                      expected_reached=expected_reached,
                                      external_evidence=external)
    return DriverRun(observation=observation, outcome=outcome,
                     claims=claims, external=external)


def observation_text(site: str, run: DriverRun) -> str:
    """The text the grader and the next prompt both read.

    Three lines, three different owners: CPG_PROBE is the harness's own summary,
    CPG_CLAIMS is the candidate speaking about itself, and CPG_EXTERNAL appears
    only when an outside observer actually produced a record. Keeping them on
    separate lines is what makes the distinction checkable later.
    """
    observation, outcome = run.observation, run.outcome
    head = "[CPG_PROBE] %s outcome=%s" % (site, outcome.state)
    if outcome.state == driver_outcome.KERNEL_BUGCHECK:
        head += " bugcheck=%s" % (outcome.detail.get("bugcheck") or {}).get("code", "")
    lines = [head, "CPG_DRIVER " + json.dumps(outcome.as_dict(), ensure_ascii=False)]
    if run.claims:
        lines.append("CPG_CLAIMS " + json.dumps(run.claims, ensure_ascii=False))
    if run.external:
        # Named as the sidecar so a reader knows where the authority lives; the
        # records themselves are never inlined into text the candidate shares.
        lines.append("CPG_EXTERNAL sidecar=%s records=%d"
                     % (EXTERNAL_SIDECAR, len(run.external)))
    tail = (observation.stdout or "").strip().splitlines()[-1:] or [""]
    lines.append(tail[0])
    return "\n".join(lines)
