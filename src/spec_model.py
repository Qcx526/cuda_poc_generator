# -*- coding: utf-8 -*-
"""Executable Vulnerability Specification (EVS).

The seven-layer input describes a vulnerability the way an advisory does: it
answers "what is this". A PoC generator needs a different kind of statement:
"which bytes does this parser consume, what does it check, and what happens if
the check is missing". This module defines that statement as a typed object.

Three ideas distinguish it from the advisory-shaped input:

1. *Operational facts are first class.* A parser model (entry, consumed fields,
   bound checks) and an executable anchor (binary, invocation, baseline recipe)
   are not prose: each is addressable, so a mutation can target them.
2. *Every claim carries its provenance.* A value is only as good as how it was
   established: `advisory` (someone wrote it), `reverse_engineering` (we read
   the binary), `execution` (we observed it). The controller routes on this.
3. *History is part of the input.* Attempts and refuted hypotheses are stored
   with the specification, so a second run on the same target does not repeat
   a disproved assumption.

Legacy seven-layer directories are imported into this shape rather than
discarded: imported claims are marked `advisory`, which is exactly what makes
their operational coverage zero.
"""

import json
from pathlib import Path
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

Verification = Literal["advisory", "reverse_engineering", "execution", "unverified"]
BoundCheck = Literal["none", "range", "alignment", "length", "unknown"]
SignalKind = Literal["signal", "exit_code", "stderr_pattern", "hresult"]


class Claim(BaseModel):
    """A single assertion plus how it was established."""

    model_config = ConfigDict(extra="forbid")

    value: str
    source: str = "advisory"
    verified_by: Verification = "advisory"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    @property
    def is_operational(self) -> bool:
        """Only claims confirmed against the artifact can steer a mutation."""
        return self.verified_by in ("reverse_engineering", "execution")


class VersionRange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min: str = ""
    max: str = ""
    fixed_in: str = ""
    verified_by: Verification = "advisory"

    def to_evidence(self) -> Optional[bool]:
        """Return True when the range is usable as a version gate."""
        return True if (self.min or self.max or self.fixed_in) else None


class FieldLayout(BaseModel):
    """One field the parser reads, with the check it does or does not perform."""

    model_config = ConfigDict(extra="forbid")

    name: str
    offset: int = Field(ge=0)
    size: int = Field(gt=0)
    semantics: str = ""
    bound_check: BoundCheck = "unknown"
    verified_by: Verification = "advisory"

    @property
    def is_unchecked(self) -> bool:
        return self.bound_check == "none"


class ParserModel(BaseModel):
    """Where the bytes are consumed and why the consumption is unsafe."""

    model_config = ConfigDict(extra="forbid")

    entry_function: str = ""
    entry_rva: str = ""
    loop_pseudocode: str = ""
    consumed_fields: List[FieldLayout] = Field(default_factory=list)
    verified_by: Verification = "advisory"

    def unchecked_fields(self) -> List[FieldLayout]:
        return [f for f in self.consumed_fields if f.is_unchecked]


class ExecutableAnchor(BaseModel):
    """How to build a valid input and how to invoke the target on it."""

    model_config = ConfigDict(extra="forbid")

    binary: str = ""
    invocation: List[str] = Field(default_factory=list)
    input_kind: str = ""
    input_magic: str = ""
    baseline_recipe: str = ""
    versions: VersionRange = Field(default_factory=VersionRange)
    verified_by: Verification = "advisory"


class Observable(BaseModel):
    """The signal that counts as reproduction for this target."""

    model_config = ConfigDict(extra="forbid")

    kind: SignalKind = "signal"
    value: str = ""
    verified_by: Verification = "advisory"


class TriggerOracle(BaseModel):
    """The precondition that must hold for the defect to fire."""

    model_config = ConfigDict(extra="forbid")

    field: str = ""
    condition: str = ""
    expected_effect: str = ""


class Attempt(BaseModel):
    """One recorded run; refutations are the part worth keeping."""

    model_config = ConfigDict(extra="forbid")

    iteration: int
    verdict: str = ""
    diagnosis: str = ""
    note: str = ""


class History(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attempts: List[Attempt] = Field(default_factory=list)
    refuted: List[str] = Field(default_factory=list)

    def add(self, attempt: Attempt) -> None:
        self.attempts.append(attempt)


class VulnSpec(BaseModel):
    """The full specification: who, where, what bytes, what proves it."""

    model_config = ConfigDict(extra="forbid")

    cve_id: str
    component: str = ""
    cwe: str = ""
    anchor: ExecutableAnchor = Field(default_factory=ExecutableAnchor)
    parser: ParserModel = Field(default_factory=ParserModel)
    observable: Observable = Field(default_factory=Observable)
    oracle: TriggerOracle = Field(default_factory=TriggerOracle)
    claims: Dict[str, Claim] = Field(default_factory=dict)
    history: History = Field(default_factory=History)
    origin: str = "native"  # native | legacy

    # -- coverage -------------------------------------------------------
    def operational_coverage(self) -> float:
        """Share of the facts a targeted mutation actually needs."""
        checks = [
            bool(self.anchor.binary),
            bool(self.anchor.invocation),
            bool(self.anchor.baseline_recipe),
            self.anchor.versions.to_evidence() is not None,
            bool(self.parser.entry_function),
            bool(self.parser.consumed_fields),
            bool(self.parser.loop_pseudocode),
            bool(self.observable.value),
            bool(self.oracle.field and self.oracle.condition),
        ]
        return sum(1 for c in checks if c) / len(checks)

    def descriptive_coverage(self) -> float:
        checks = [bool(self.component), bool(self.cwe),
                  bool(self.parser.entry_function), bool(self.parser.loop_pseudocode)]
        return sum(1 for c in checks if c) / len(checks)

    @property
    def strategy(self) -> str:
        """Route the search by what the specification can actually support.

        High coverage is not enough on its own: without the fields the parser
        consumes, a "direct" mutation still has nothing to aim at, so the
        consumed-field list is a hard prerequisite for MUTATE_DIRECT.
        """
        if self.parser.consumed_fields and self.operational_coverage() >= 0.6:
            return "MUTATE_DIRECT"
        if self.descriptive_coverage() >= 0.4:
            return "PROBE_THEN_MUTATE"
        return "RECON_FIRST"

    # -- rendering ------------------------------------------------------
    def prompt_brief(self) -> str:
        """Compact operational brief for the generation prompt.

        Only facts that change what the code does are included; prose belongs
        in the report, not in the prompt.
        """
        lines = ["[EVS] %s | component=%s | strategy=%s | operational=%.0f%%"
                 % (self.cve_id, self.component or "unknown", self.strategy,
                    100 * self.operational_coverage())]
        if self.anchor.binary:
            lines.append("binary: %s" % self.anchor.binary)
        if self.anchor.invocation:
            lines.append("invoke: %s" % " ".join(self.anchor.invocation))
        if self.anchor.input_kind:
            lines.append("input: %s (magic=%s)" % (self.anchor.input_kind,
                                                   self.anchor.input_magic or "unknown"))
        if self.anchor.baseline_recipe:
            lines.append("baseline: %s" % self.anchor.baseline_recipe)
        if self.parser.entry_function:
            lines.append("parser: %s %s" % (self.parser.entry_function,
                                            self.parser.entry_rva))
        for field in self.parser.consumed_fields:
            lines.append("  field %-18s off=%-6d size=%-3d check=%-9s %s"
                         % (field.name, field.offset, field.size,
                            field.bound_check, field.semantics))
        if self.observable.value:
            lines.append("observable: %s=%s" % (self.observable.kind, self.observable.value))
        if self.oracle.field:
            lines.append("oracle: %s must satisfy %s -> %s"
                         % (self.oracle.field, self.oracle.condition,
                            self.oracle.expected_effect))
        if self.history.refuted:
            lines.append("already refuted (do NOT repeat): %s"
                         % "; ".join(self.history.refuted))
        gaps = self.gaps()
        if gaps:
            lines.append("unknown (do not invent): %s" % ", ".join(gaps))
        return "\n".join(lines)

    def gaps(self) -> List[str]:
        gaps = []
        if not self.parser.consumed_fields:
            gaps.append("consumed_fields")
        if not self.anchor.baseline_recipe:
            gaps.append("baseline_recipe")
        if self.anchor.versions.to_evidence() is None:
            gaps.append("affected_versions")
        if not self.observable.value:
            gaps.append("observable")
        return gaps

    def record_attempt(self, iteration: int, verdict: str, diagnosis: str,
                       note: str = "") -> None:
        self.history.add(Attempt(iteration=iteration, verdict=verdict,
                                 diagnosis=diagnosis, note=note))

    def save(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.model_dump(), ensure_ascii=False, indent=2),
                        encoding="utf-8")
        return path


# -- loading -------------------------------------------------------------


def load(path: Path) -> VulnSpec:
    return VulnSpec.model_validate_json(path.read_text(encoding="utf-8"))


def from_legacy(input_dir: Path) -> VulnSpec:
    """Import a seven-layer directory, marking every claim advisory."""
    def read(name: str) -> dict:
        path = input_dir / name
        if not path.is_file():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        for wrapper in ("affected_component", "root_cause", "attack_surface"):
            if isinstance(payload.get(wrapper), dict):
                return payload[wrapper]
        return payload

    component = read("3_affected_component.json")
    surface = read("4_attack_surface.json")
    root = read("7_root_cause.json")
    kind = read("5_vulnerability_type.json")

    spec = VulnSpec(cve_id=input_dir.name, origin="legacy")
    spec.component = str(component.get("name") or component.get("component_name") or "")
    spec.cwe = str(kind.get("cwe_id") or "")
    spec.anchor.binary = str(surface.get("entry_point") or "").split()[0] if surface.get("entry_point") else ""
    spec.anchor.input_kind = str(component.get("file_format_input") or "")
    spec.parser.entry_function = str(root.get("function") or "")
    spec.parser.loop_pseudocode = str(root.get("vulnerable_code_summary") or "")
    if isinstance(component.get("version_range"), str):
        spec.anchor.versions.min = component["version_range"]
    for key, value in (("entry_point", surface.get("entry_point")),
                       ("version_range", component.get("version_range")),
                       ("vulnerable_function", component.get("vulnerable_function"))):
        if isinstance(value, str) and value.strip():
            spec.claims[key] = Claim(value=value, verified_by="advisory",
                                     confidence=0.4)
    return spec
