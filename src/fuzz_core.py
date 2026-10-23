# -*- coding: utf-8 -*-
"""Target-agnostic fuzzing engine.

The engine knows nothing about shaders, drivers or CUDA. A *grammar* turns a
seed into a candidate, a *runner* executes it and reports an outcome, and the
engine does the rest: scheduling, corpus keeping, statistics and crash capture.

Keeping the engine generic is not tidiness - it is what stops the fuzzer from
becoming a script for one CVE. Target knowledge lives in two places only: the
grammar module and the specification's ``search`` block.

Contract
--------
grammar:  ``name``, ``generate(rng, params) -> Candidate``
runner:   ``(candidate) -> Outcome``
"""

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Protocol, Tuple

ACCEPTED = "accepted"
REJECTED = "rejected"
GRAMMAR_ERROR = "grammar_error"
FAULT = "fault"
TIMEOUT = "timeout"


@dataclass
class Candidate:
    """One input the grammar produced, plus what makes it interesting."""

    body: str
    meta: Dict[str, object] = field(default_factory=dict)
    name: str = ""


@dataclass
class Outcome:
    """What the runner observed. Only these five kinds are meaningful."""

    kind: str
    rc: Optional[int] = None
    seconds: float = 0.0
    size: int = 0
    detail: str = ""

    @property
    def is_crash(self) -> bool:
        return self.kind == FAULT


class Grammar(Protocol):
    name: str

    def generate(self, rng: random.Random, params: Dict[str, object]) -> Candidate: ...


GRAMMARS: Dict[str, Grammar] = {}


def register(grammar: Grammar) -> Grammar:
    GRAMMARS[grammar.name] = grammar
    return grammar


def grammar_for(name: str) -> Grammar:
    if name not in GRAMMARS:
        raise KeyError("unknown grammar %r (registered: %s)"
                       % (name, ", ".join(sorted(GRAMMARS)) or "none"))
    return GRAMMARS[name]


def bucket(outcome: Outcome) -> Tuple[str, int, int]:
    """Behavioural signature; the closest thing to coverage without tracing."""
    return (outcome.kind, min(outcome.size // 64, 64), min(int(outcome.seconds * 4), 64))


@dataclass
class Summary:
    iterations: int
    outcomes: Dict[str, int] = field(default_factory=dict)
    corpus: int = 0
    faults: List[Dict[str, object]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {"iterations": self.iterations, "outcomes": self.outcomes,
                "corpus": self.corpus, "faults": self.faults}


def fuzz(*, grammar: Grammar, params: Dict[str, object], runner: Callable[[Candidate], Outcome],
         iterations: int, seed: int = 1, on_new: Optional[Callable[[Outcome, Candidate], None]] = None,
         on_fault: Optional[Callable[[Outcome, Candidate], None]] = None) -> Summary:
    """Run ``iterations`` candidates, keeping one case per behavioural bucket."""
    rng = random.Random(seed)
    seen: Dict[Tuple[str, int, int], int] = {}
    summary = Summary(iterations=iterations)
    for i in range(iterations):
        candidate = grammar.generate(rng, params)
        outcome = runner(candidate)
        summary.outcomes[outcome.kind] = summary.outcomes.get(outcome.kind, 0) + 1
        signature = bucket(outcome)
        if signature not in seen:
            seen[signature] = i
            if on_new is not None:
                on_new(outcome, candidate)
        if outcome.is_crash:
            summary.faults.append({"index": i, "rc": outcome.rc, "detail": outcome.detail,
                                   "meta": candidate.meta, "body": candidate.body})
            if on_fault is not None:
                on_fault(outcome, candidate)
    summary.corpus = len(seen)
    return summary


def save(path: Path, summary: Summary, extra: Optional[Dict[str, object]] = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: Dict[str, object] = {"summary": summary.as_dict()}
    if extra:
        payload.update(extra)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")
