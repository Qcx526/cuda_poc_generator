# -*- coding: utf-8 -*-
"""How much does the seven-layer input actually support a targeted PoC?

The batch showed that content depth, not pipeline code, decides most outcomes:
the only CVE with a populated root-cause layer converged in one iteration,
while the NO_EFFECT cluster all lack the parser detail that a mutation needs.

This module measures that depth instead of leaving it implicit. It is a
diagnostic, not a gate: a thin input can still succeed, so a low score changes
the strategy and the report, never the permission to run.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# Field -> weight. Weights encode "what a mutation must know to be targeted":
# a parser entry and the fields it consumes matter more than a CVSS vector.
CRITICAL_FIELDS: Dict[str, Dict[str, int]] = {
    "3_affected_component.json": {
        "version_range": 2,        # decides whether a crash even counts
        "vulnerable_function": 3,  # where to aim
        "file_format_input": 2,    # what to feed
        "attack_entry_point": 2,   # how to invoke it
    },
    "7_root_cause.json": {
        "function": 3,             # binary-level anchor
        "vulnerable_code_summary": 3,  # the loop shape to violate
        "file": 1,
        "line": 1,
    },
}

# What a mutation must know before it can be targeted. These are the v2
# operational blocks; absent blocks are the current normal, so they must not
# invalidate anything - they only lower the operational score.
OPERATIONAL_FIELDS: Dict[str, Dict[str, int]] = {
    "7_root_cause.json": {
        "parser_model.entry_function": 3,
        "parser_model.consumed_fields": 4,
        "parser_model.loop_pseudocode": 2,
    },
    "3_affected_component.json": {
        "executable_anchor.baseline_recipe": 3,
        "executable_anchor.affected_versions": 2,
        "executable_anchor.input_format": 2,
    },
    "4_attack_surface.json": {
        "observable_signal": 3,
        "invocation": 2,
    },
}

_EMPTY = {"", "n/a", "na", "unknown", "—", "-", "none", "tbd"}


@dataclass(frozen=True)
class Sufficiency:
    """Weighted coverage of the fields a targeted mutation depends on."""

    cve_id: str
    score: int
    maximum: int
    missing: List[str] = field(default_factory=list)
    operational_score: int = 0
    operational_maximum: int = 0
    operational_missing: List[str] = field(default_factory=list)

    @property
    def ratio(self) -> float:
        return 0.0 if self.maximum == 0 else self.score / self.maximum

    @property
    def operational_ratio(self) -> float:
        return 0.0 if self.operational_maximum == 0 else (
            self.operational_score / self.operational_maximum)

    @property
    def strategy(self) -> str:
        """Pick a search strategy from input quality, not from a fixed rule.

        A well-anchored input can be mutated directly. A descriptive-only input
        must first probe the target to learn what it consumes. A thin input has
        to start with reconnaissance, because mutation would be a guess.
        """
        if self.operational_ratio >= 0.6:
            return "MUTATE_DIRECT"
        if self.ratio >= 0.4:
            return "PROBE_THEN_MUTATE"
        return "RECON_FIRST"

    @property
    def band(self) -> str:
        """Coarse label used in reports and in strategy selection."""
        if self.ratio >= 0.8:
            return "RICH"
        if self.ratio >= 0.4:
            return "PARTIAL"
        return "THIN"


def _unwrap(payload: dict, filename: str) -> dict:
    """Accept both shapes seen in the input set: wrapped and flat."""
    wrapper = filename.split("_", 1)[1].rsplit(".", 1)[0]  # e.g. "affected_component"
    if isinstance(payload.get(wrapper), dict):
        return payload[wrapper]
    return payload


def _nested_get(body: dict, dotted: str) -> object:
    current: object = body
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _is_filled(value: object) -> bool:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() not in _EMPTY
    return bool(value)


def assess(input_dir: Path) -> Sufficiency:
    """Score one CVE's input directory."""
    cve_id = input_dir.name
    score = 0
    maximum = 0
    missing: List[str] = []
    operational_score = 0
    operational_maximum = 0
    operational_missing: List[str] = []
    for filename, weights in CRITICAL_FIELDS.items():
        path = input_dir / filename
        body: Dict[str, object] = {}
        if path.is_file():
            try:
                body = _unwrap(json.loads(path.read_text(encoding="utf-8")), filename)
            except (OSError, json.JSONDecodeError):
                body = {}
        for key, weight in weights.items():
            maximum += weight
            if _is_filled(body.get(key)):
                score += weight
            else:
                missing.append("%s.%s" % (filename.split("_")[0], key))

    for filename, weights in OPERATIONAL_FIELDS.items():
        path = input_dir / filename
        body: Dict[str, object] = {}
        if path.is_file():
            try:
                body = _unwrap(json.loads(path.read_text(encoding="utf-8")), filename)
            except (OSError, json.JSONDecodeError):
                body = {}
        for dotted, weight in weights.items():
            operational_maximum += weight
            if _is_filled(_nested_get(body, dotted)):
                operational_score += weight
            else:
                operational_missing.append("%s.%s" % (filename.split("_")[0], dotted))
    return Sufficiency(cve_id=cve_id, score=score, maximum=maximum,
                       missing=missing, operational_score=operational_score,
                       operational_maximum=operational_maximum,
                       operational_missing=operational_missing)


def assess_all(inputs_root: Path) -> List[Sufficiency]:
    return [assess(d) for d in sorted(inputs_root.iterdir()) if d.is_dir()]


def missing_note(sufficiency: Sufficiency) -> Optional[str]:
    """One line for the generation prompt, or None when nothing is missing."""
    if not sufficiency.missing:
        return None
    return ("Input is incomplete for a targeted mutation: missing %s. Prefer a "
            "conservative mutation of the fields the tool is known to parse, and "
            "state explicitly which assumption you had to make."
            % ", ".join(sufficiency.missing))
