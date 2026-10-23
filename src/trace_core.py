# -*- coding: utf-8 -*-
"""Target-agnostic dynamic tracing.

The fuzzer tells us *whether* an input crashed. This layer answers *what the
target did with the input*: which address it stopped at, what the registers
held, which branch it took. That is the evidence a static specification cannot
carry, and it is what turns "we can't reach the bug" into "here is the field
the decoder read".

The engine is target-agnostic on purpose, exactly like :mod:`src.fuzz_core`:
a *provider* executes a program under some tracer and returns a TraceResult.
Adding a target means adding a provider, not editing this module.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Protocol


@dataclass
class Probe:
    """A place to stop, either by symbol or by module-relative offset."""

    module: str
    rva: int = 0
    symbol: Optional[str] = None
    note: str = ""

    @property
    def expression(self) -> str:
        if self.symbol:
            return self.symbol
        return "%s+0x%x" % (self.module, self.rva)


@dataclass
class TraceResult:
    """What one traced run produced."""

    provider: str
    hit: bool
    probe: Optional[Probe] = None
    registers: Dict[str, str] = field(default_factory=dict)
    frames: List[str] = field(default_factory=list)
    note: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {"provider": self.provider, "hit": self.hit,
                "probe": self.probe.expression if self.probe else "",
                "registers": self.registers, "frames": self.frames,
                "note": self.note}


class TraceProvider(Protocol):
    name: str

    def trace(self, program: Path, probe: Probe, timeout: int = 120) -> TraceResult: ...


def claims_from_trace(result: TraceResult, statement: str,
                      confidence: float = 0.8) -> Dict[str, object]:
    """Turn a trace into a specification claim.

    Only executed evidence earns a claim: a probe that did not hit proves
    absence, which is worth recording too, but with its own wording.
    """
    if result.hit:
        detail = "hit %s; registers %s" % (
            result.probe.expression if result.probe else "?",
            ", ".join("%s=%s" % (k, v) for k, v in sorted(result.registers.items()))
            or "not captured")
    else:
        detail = "probe %s never hit" % (
            result.probe.expression if result.probe else "?")
    return {"value": "%s (%s)" % (statement, detail),
            "source": result.provider, "verified_by": "execution",
            "confidence": confidence}


def merge_claims(spec_path: Path, claims: Dict[str, Dict[str, object]],
                 history_note: str = "") -> Path:
    """Write trace-derived claims back into a specification."""
    data = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    bucket = data.setdefault("claims", {})
    for key, claim in claims.items():
        bucket[key] = claim
    if history_note:
        refuted = data.setdefault("history", {}).setdefault("refuted", [])
        if history_note not in refuted:
            refuted.append(history_note)
    Path(spec_path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return Path(spec_path)


PROVIDERS: Dict[str, TraceProvider] = {}


def register(provider: TraceProvider) -> TraceProvider:
    PROVIDERS[provider.name] = provider
    return provider


def provider_for(name: str) -> TraceProvider:
    if name not in PROVIDERS:
        raise KeyError("unknown trace provider %r (registered: %s)"
                       % (name, ", ".join(sorted(PROVIDERS)) or "none"))
    return PROVIDERS[name]


def run(*, provider: TraceProvider, program: Path,
        probe: Probe) -> TraceResult:
    return provider.trace(Path(program), probe)


def report(results: List[TraceResult], out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps([r.as_dict() for r in results], ensure_ascii=False, indent=1),
                   encoding="utf-8")
    return out


def summarise(results: List[TraceResult]) -> str:
    if not results:
        return "no traces"
    hits = sum(1 for r in results if r.hit)
    probes = sorted({r.probe.expression for r in results if r.probe})
    return "%d/%d traces hit (probes: %s)" % (hits, len(results), ", ".join(probes))
