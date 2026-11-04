# -*- coding: utf-8 -*-
"""Structured mutation over legal escape inputs.

The rule that keeps this honest: a mutation may only vary what the headers and
the captured corpus say is legal. Today that means

* ``Type`` stays 0 - no vendor-private type is invented, ever.
* ``Flags`` stays 0 - the bit meanings for escape are not established here.
* ``hContext`` may be absent, a live own context, or a live foreign context.
* ``pPrivateDriverData`` stays empty - a fabricated body is not a seed.

So the space is small on purpose. A large space filled with invented constants
would produce failures that say nothing about the driver.
"""

import random
from dataclasses import dataclass, field, replace
from itertools import product
from typing import Dict, List, Optional, Sequence, Tuple

MAX_TYPE = 0
MAX_FLAGS = 0
CONTEXT_CHOICES = ("none", "own")

# Header field name -> attribute name; hContext is stored as ``context``.
_FIELD_TO_ATTR = {"Type": "type", "Flags": "flags", "hContext": "context"}

ALLOWED = {
    "Type": {"kind": "const", "value": MAX_TYPE,
             "why": "厂商私有 Type 未验证，不得构造"},
    "Flags": {"kind": "const", "value": MAX_FLAGS,
              "why": "escape 的 Flags 位语义未建立"},
    "hContext": {"kind": "choice", "values": list(CONTEXT_CHOICES)},
    "pPrivateDriverData": {"kind": "const", "value": None,
                           "why": "伪造私有命令体被明确禁止"},
    "PrivateDriverDataSize": {"kind": "const", "value": 0},
}


@dataclass(frozen=True)
class EscapeInput:
    type: int = MAX_TYPE
    flags: int = MAX_FLAGS
    context: str = "none"          # none | own | foreign(live)
    body: bytes = b""

    def as_params(self) -> Dict[str, object]:
        return {"Type": self.type, "Flags": self.flags, "hContext": self.context,
                "pPrivateDriverData": None, "PrivateDriverDataSize": 0}

    def key(self) -> Tuple[int, int, str, int]:
        return (self.type, self.flags, self.context, len(self.body))


@dataclass
class Mutation:
    case: EscapeInput
    changed: List[str] = field(default_factory=list)
    reason: str = ""

    def diff(self, before: EscapeInput) -> Dict[str, object]:
        return {"before": before.as_params(), "after": self.case.as_params(),
                "changed_fields": self.changed, "reason": self.reason}


def legal_space(contexts: Sequence[str] = CONTEXT_CHOICES) -> List[EscapeInput]:
    """Enumerate the whole allowed space; it is small enough to be exhaustive."""
    return [EscapeInput(type=t, flags=f, context=c)
            for t, f, c in product([MAX_TYPE], [MAX_FLAGS], contexts)]


def mutate(before: EscapeInput, rng: random.Random,
           contexts: Sequence[str] = CONTEXT_CHOICES) -> Mutation:
    """Change exactly one allowed field, so a failure is attributable."""
    options = [c for c in contexts if c != before.context]
    if options:
        chosen = rng.choice(options)
        return Mutation(replace(before, context=chosen), ["hContext"],
                        "hContext: %s -> %s" % (before.context, chosen))
    return Mutation(before, [], "已穷尽允许空间，无新组合")


class Corpus:
    """Deduplicating store of executed cases.

    A case that differs only by whitespace in a note is the same case; the key is
    the structured tuple, not the text.
    """

    def __init__(self) -> None:
        self.seen: Dict[Tuple, Dict[str, object]] = {}

    def add(self, case: EscapeInput, status: Optional[int], note: str = "") -> bool:
        if case.key() in self.seen:
            return False
        self.seen[case.key()] = {"params": case.as_params(), "status": status,
                                 "note": note}
        return True

    def __len__(self) -> int:
        return len(self.seen)

    def distinct_statuses(self) -> set:
        return {entry["status"] for entry in self.seen.values()}


def attribute(status: Optional[int]) -> str:
    """Say what a status does and does not prove."""
    if status is None:
        return "NO_RESULT"
    if status == 0:
        return "ACCEPTED"
    if status == -1073741811 or status == 0xC000000D:
        return "REJECTED_INVALID_PARAMETER"
    return "OTHER_%08X" % (status & 0xFFFFFFFF)


def next_round(executed: Sequence[Tuple[EscapeInput, Optional[int]]],
               rng: random.Random) -> List[Mutation]:
    """Pick untried cases, preferring the ones adjacent to what already ran."""
    corpus = Corpus()
    for case, status in executed:
        corpus.add(case, status)
    pending = [c for c in legal_space() if c.key() not in corpus.seen]
    rng.shuffle(pending)
    return [Mutation(c, ["hContext"], "未执行组合") for c in pending[:4]]


def context_block(base: EscapeInput, case: EscapeInput, *, rng_seed: int,
                  seed_id: str = "escape_shape",
                  provenance: str = "synthetic",
                  tried: Optional[Sequence[Tuple[EscapeInput, Optional[int]]]] = None,
                  last_run: Optional[dict] = None,
                  unknowns: Optional[Sequence[str]] = None) -> str:
    """Structured mutation context for the analyst and generator prompts.

    It states what changed, what it was derived from, and what is still unknown.
    The last part matters: a context that only lists tried combinations invites
    the model to treat the untried space as safe.
    """
    tried = list(tried or [])
    payload = {
        "seed": {"id": seed_id, "provenance": provenance,
                 "legal": provenance == "captured",
                 "executed": bool(tried)},
        "rng_seed": rng_seed,
        "base": base.as_params(),
        "candidate": case.as_params(),
        "changed_fields": [name for name in ("Type", "Flags", "hContext")
                           if getattr(base, _FIELD_TO_ATTR[name])
                           != getattr(case, _FIELD_TO_ATTR[name])],
        "constraints": ALLOWED,
        "tried_combinations": [
            {"params": c.as_params(), "status": status} for c, status in tried],
        "untried_count": max(0, len(legal_space()) - len(tried)),
        "last_run": last_run or {},
        "unknowns": list(unknowns or [
            "私有 Type 与命令体格式未验证，禁止构造",
            "Flags 位语义未建立",
            "0xC000000D 的具体拒绝来源未知",
        ]),
        "rules": ["不得扩大 Type/Flags/body 的取值范围",
                  "hContext 只能用已验证存在的句柄",
                  "生成程序必须自行构建 ABI 调用与清理，不得只输出参数"],
    }
    import json

    return json.dumps(payload, ensure_ascii=False, indent=2)
