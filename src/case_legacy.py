# -*- coding: utf-8 -*-
"""Adapter: the CUDA seven-file input -> GPU Vulnerability Case v2.

This is a *view* over ``normalize_input_files``, not a second parser. The normalizer
already records per-file hashes, per-field state, provenance, conflicts and
diagnostics; re-reading the JSON here would produce a summary that looks lossless and
is not.

Nothing is filled in. A conflicting CVE stays unresolved, an invalid file stays
invalid, and every mapped value keeps the state the normalizer assigned to it.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .case_v2 import (SCHEMA_VERSION, CaseIdentity, ConstraintKnowledge,
                      EntrySurface, Evidence, EvidenceKind, ExperimentContract,
                      GPUCase, PlatformExtension, TargetProfile,
                      VerificationStatus, Visibility, VulnerabilityDescription)
from .models.normalized_input import FieldState, normalize_input_files

RESTRICTED = (
    ("attack_surface", "attack_vector"),
    ("attack_surface", "attack_complexity"),
    ("attack_surface", "surface_type"),
    ("vulnerability_type", "subtype"),
    ("impact_controllability", "controllable_fields"),
    ("impact_controllability", "exploitation_difficulty"),
    ("root_cause", "root_cause"),
)

PUBLIC_FACTS = (
    ("A1", "affected_component", "vendor", "\u5382\u5546"),
    ("A2", "affected_component", "version_range", "\u53d7\u5f71\u54cd\u7248\u672c\u8303\u56f4"),
    ("A3", "attack_surface", "entry_point", "\u5165\u53e3"),
    ("A4", "attack_surface", "required_permissions", "\u6240\u9700\u6743\u9650"),
    ("A5", "vulnerability_type", "cwe_id", "CWE"),
    ("A6", "affected_component", "file_format_input", "\u8f93\u5165\u683c\u5f0f"),
)

UNTRUSTED_STATES = {FieldState.MISSING, FieldState.INVALID, FieldState.CONFLICT}

# Reviewed for blind use, one entry at a time. A field being VALID says the file
# parsed; it says nothing about whether the text is safe to show a model.
REVIEWED_PUBLIC = {
    ("affected_component", "vendor"),
    ("affected_component", "version_range"),
    ("affected_component", "file_format_input"),
    ("attack_surface", "entry_point"),
    ("attack_surface", "required_permissions"),
    ("vulnerability_type", "cwe_id"),
}


@dataclass
class LegacyBundle:
    case: GPUCase
    provenance: Dict[str, object] = field(default_factory=dict)
    conflicts: List[str] = field(default_factory=list)


def _state(normalized, dimension: str, key: str) -> str:
    """Look the field up by its exact JSON Pointer.

    The normalizer keys field_states as "/dimensions/<dim>/<key>"; the earlier
    version matched on a dotted suffix, which never hit, so every field came back
    UNKNOWN and no assertion could ever be public. Nested objects are checked one
    level down, matching how _value resolves them.
    """
    pointer = "/dimensions/%s/%s" % (dimension, key)
    if pointer in normalized.field_states:
        return normalized.field_states[pointer].value
    prefix = "/dimensions/%s/" % dimension
    for path, state in normalized.field_states.items():
        if path.startswith(prefix) and path.endswith("/" + key):
            return state.value
    return FieldState.UNKNOWN.value


def _value(normalized, dimension: str, key: str) -> Optional[str]:
    section = normalized.dimensions.get(dimension) or {}
    value = section.get(key)
    if value not in (None, "", [], {}):
        return str(value)
    for nested in section.values():
        if isinstance(nested, dict) and nested.get(key) not in (None, "", [], {}):
            return str(nested[key])
    return None


def adapt(directory: Path) -> LegacyBundle:
    normalized = normalize_input_files(Path(directory))
    errors = [d for d in normalized.diagnostics if d.severity == "ERROR"]
    conflicts = sorted({path for path, state in normalized.field_states.items()
                        if state in (FieldState.CONFLICT, FieldState.INVALID)})

    evidence: List[Evidence] = []
    notes: List[str] = []

    for identifier, dimension, key, label in PUBLIC_FACTS:
        value = _value(normalized, dimension, key)
        if not value:
            continue
        state = _state(normalized, dimension, key)
        trusted = state == FieldState.VALID.value
        reviewed = trusted and (dimension, key) in REVIEWED_PUBLIC
        evidence.append(Evidence(
            id=identifier, kind=EvidenceKind.INPUT_ASSERTION,
            statement="%s: %s" % (label, value),
            source="%s.%s" % (dimension, key),
            status=VerificationStatus.UNKNOWN,
            visible_in=Visibility.PUBLIC if reviewed else Visibility.EVAL,
            public_reviewed=reviewed,
            notes=None if reviewed else "\u5b57\u6bb5\u72b6\u6001 %s\uff0c\u672a\u901a\u8fc7\u516c\u5f00\u5ba1\u67e5" % state))
        if not reviewed:
            notes.append("%s.%s \u72b6\u6001 %s\uff0c\u672a\u4f5c\u4e3a\u516c\u5f00\u65ad\u8a00"
                         % (dimension, key, state))

    for dimension, key in RESTRICTED:
        value = _value(normalized, dimension, key)
        if value:
            evidence.append(Evidence(
                id="E-%s-%s" % (dimension, key), kind=EvidenceKind.EVALUATION_ONLY,
                statement=value, source="%s.%s" % (dimension, key),
                status=VerificationStatus.UNKNOWN, visible_in=Visibility.EVAL))
            notes.append("%s.%s \u542b\u89e6\u53d1\u7ec6\u8282\uff0c\u964d\u4e3a EVALUATION_ONLY"
                         % (dimension, key))

    cve_id = normalized.cve_id
    if cve_id is None:
        notes.append("CVE \u672a\u5f97\u5230\u5355\u4e00\u503c\uff0c\u4fdd\u6301\u672a\u5b9a")

    component = (_value(normalized, "affected_component", "component_name")
                 or _value(normalized, "affected_component", "name") or "unknown")
    case = GPUCase(
        schema_version=SCHEMA_VERSION,
        identity=CaseIdentity(case_id=cve_id or ("case:" + Path(directory).name),
                              cve_id=cve_id, title=component,
                              sources=[str(directory)]),
        target=TargetProfile(
            vendor=_value(normalized, "affected_component", "vendor") or "unknown",
            component=component, platform="linux", execution_tier="userland_toolchain",
            versions={"affected": _value(normalized, "affected_component",
                                         "version_range") or "unknown"}),
        entry_surface=EntrySurface(
            medium=_value(normalized, "attack_surface", "entry_type") or "file",
            interface=_value(normalized, "attack_surface", "entry_point") or component,
            trust_boundary=_value(normalized, "attack_surface",
                                  "required_permissions") or "unknown"),
        description=VulnerabilityDescription(
            public_summary="%s: %s" % (component,
                                       _value(normalized, "vulnerability_type",
                                              "cwe_name") or "\u89c1\u516c\u544a"),
            cwe=_value(normalized, "vulnerability_type", "cwe_id"),
            impact=_value(normalized, "vulnerability_type", "cvss_severity"),
            root_cause_status=VerificationStatus.UNKNOWN),
        knowledge=ConstraintKnowledge(
            evidence=evidence,
            missing=(["根因描述存在但不可投影"]
                     if _value(normalized, "root_cause", "root_cause")
                     else ["根因未公开"])
            + ["未通过公开审查的断言: %d 个"
               % sum(1 for e in evidence
                     if e.kind is EvidenceKind.INPUT_ASSERTION
                     and e.visible_in is not Visibility.PUBLIC)]),
        contract=ExperimentContract(goal="生成能触发该崩溃的完整输入",
                                    backend="cuda_container",
                                    allowed_operations=["build_input", "run_tool"],
                                    risk_level="medium"),
        extension=PlatformExtension(
            name="cuda_toolchain", version="1",
            payload={"affected_tools": _value(normalized, "cuda_environment",
                                              "affected_tools") or "",
                     "cuda_toolkit": _value(normalized, "cuda_environment",
                                            "cuda_toolkit_version") or ""}),
    )

    provenance = {
        "source_directory": str(directory),
        "file_sha256": {name: src.sha256 for name, src in normalized.sources.items()},
        "file_sizes": {name: src.size_bytes for name, src in normalized.sources.items()},
        "field_states": {path: state.value for path, state in normalized.field_states.items()},
        "provenance_entries": len(normalized.provenance),
        "diagnostics": [d.model_dump() for d in normalized.diagnostics][:40],
        "conflicts": conflicts,
        "error_count": len(errors),
        "structural_validity_only": True,
        "note": "结构有效不代表漏洞事实成立；缺失与冲突均未补全",
        "adapter_notes": notes,
    }
    return LegacyBundle(case=case, provenance=provenance, conflicts=conflicts)
