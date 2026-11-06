# -*- coding: utf-8 -*-
"""Adapter: the CUDA seven-file input -> GPU Vulnerability Case v2.

The old input is kept as-is: every file's hash, which fields were present, and any
conflict is recorded. Nothing is inferred to fill a gap, and a structurally valid
seven-file bundle is not evidence that the vulnerability facts are true.

Fields that restate the exploit - attack vector, subtype, controllable fields, root
cause - become EVALUATION_ONLY evidence rather than public assertions. That is the
whole point of the layering: the input contained them, so their presence cannot be
what decides visibility.
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .case_v2 import (SCHEMA_VERSION, CaseIdentity, ConstraintKnowledge,
                      EntrySurface, Evidence, EvidenceKind, ExperimentContract,
                      GPUCase, PlatformExtension, TargetProfile,
                      VerificationStatus, Visibility, VulnerabilityDescription)

FILES = {
    "D1": "1_os_environment",
    "D2": "2_cuda_environment",
    "D3": "3_affected_component",
    "D4": "4_attack_surface",
    "D5": "5_vulnerability_type",
    "D6": "6_impact_controllability",
    "D7": "7_root_cause",
}

# Fields that carry a usable recipe. They are kept, but never as public text.
RESTRICTED_PATHS = {
    ("D4", "attack_vector"), ("D4", "attack_complexity"), ("D4", "surface_type"),
    ("D5", "subtype"), ("D6", "controllable_fields"),
    ("D6", "exploitation_difficulty"), ("D7", "root_cause"),
}


@dataclass
class LegacyBundle:
    case: GPUCase
    provenance: Dict[str, object] = field(default_factory=dict)


def _load(directory: Path) -> Tuple[Dict[str, dict], Dict[str, str], List[str]]:
    data: Dict[str, dict] = {}
    digests: Dict[str, str] = {}
    missing: List[str] = []
    for key, stem in FILES.items():
        path = directory / (stem + ".json")
        if not path.is_file():
            missing.append(stem)
            continue
        raw = path.read_bytes()
        digests[stem] = hashlib.sha256(raw).hexdigest()
        data[key] = json.loads(raw.decode("utf-8"))
    return data, digests, missing


def _get(data: Dict[str, dict], dim: str, key: str) -> Optional[str]:
    """Look the key up directly, then one level down.

    D5 nests everything under "vulnerability_type", so a flat read loses the CWE.
    """
    section = data.get(dim) or {}
    value = section.get(key)
    if value in (None, "", [], {}):
        for nested in section.values():
            if isinstance(nested, dict) and nested.get(key) not in (None, "", [], {}):
                value = nested[key]
                break
    if value in (None, "", [], {}):
        return None
    return str(value)


def adapt(directory: Path) -> LegacyBundle:
    data, digests, missing = _load(directory)
    if not data:
        raise FileNotFoundError("目录下没有七维输入: %s" % directory)

    cve_id = next((_get(data, k, "cve_id") for k in data if _get(data, k, "cve_id")), None)
    component = _get(data, "D3", "component_name") or _get(data, "D3", "name") or "unknown"
    evidence: List[Evidence] = []
    diagnostics: List[str] = []

    def add(identifier: str, kind: EvidenceKind, statement: Optional[str],
            source: str, visible: Visibility, status: VerificationStatus = VerificationStatus.UNKNOWN):
        if not statement:
            return
        evidence.append(Evidence(id=identifier, kind=kind, statement=statement,
                                 source=source, status=status, visible_in=visible))

    # Public, generic surface facts only.
    add("A1", EvidenceKind.INPUT_ASSERTION, _get(data, "D3", "vendor"),
        "D3.vendor", Visibility.PUBLIC)
    add("A2", EvidenceKind.INPUT_ASSERTION, _get(data, "D3", "version_range"),
        "D3.version_range", Visibility.PUBLIC)
    add("A3", EvidenceKind.INPUT_ASSERTION, _get(data, "D4", "entry_point"),
        "D4.entry_point", Visibility.PUBLIC)
    add("A4", EvidenceKind.INPUT_ASSERTION, _get(data, "D4", "required_permissions"),
        "D4.required_permissions", Visibility.PUBLIC)
    add("A5", EvidenceKind.INPUT_ASSERTION, _get(data, "D5", "cwe_id"),
        "D5.cwe_id", Visibility.PUBLIC)
    add("A6", EvidenceKind.INPUT_ASSERTION, _get(data, "D3", "file_format_input"),
        "D3.file_format_input", Visibility.PUBLIC)

    # Everything that spells out the mechanism: retained, never projected.
    for dim, key in sorted(RESTRICTED_PATHS):
        value = _get(data, dim, key)
        if value:
            evidence.append(Evidence(
                id="E-%s-%s" % (dim, key), kind=EvidenceKind.EVALUATION_ONLY,
                statement=value, source="%s.%s" % (dim, key),
                status=VerificationStatus.UNKNOWN, visible_in=Visibility.EVAL))
            diagnostics.append("%s.%s 含触发细节，已降为 EVALUATION_ONLY" % (dim, key))

    affected_tools = _get(data, "D2", "affected_tools")
    toolkit = _get(data, "D2", "cuda_toolkit_version") or _get(data, "D2", "tested_vulnerable_version")

    case = GPUCase(
        schema_version=SCHEMA_VERSION,
        identity=CaseIdentity(case_id=cve_id or ("case:" + directory.name),
                              cve_id=cve_id, title=component,
                              sources=[str(directory)]),
        target=TargetProfile(vendor=_get(data, "D3", "vendor") or "NVIDIA",
                             component=component, platform="linux",
                             execution_tier="userland_toolchain",
                             versions={"affected": _get(data, "D3", "version_range") or "unknown"}),
        entry_surface=EntrySurface(
            medium=_get(data, "D4", "entry_type") or "file",
            interface=_get(data, "D4", "entry_point") or component,
            trust_boundary=_get(data, "D4", "required_permissions") or "unknown"),
        description=VulnerabilityDescription(
            public_summary="%s: %s" % (component, _get(data, "D5", "cwe_name") or "见公告"),
            cwe=_get(data, "D5", "cwe_id"),
            impact=_get(data, "D5", "cvss_severity"),
            root_cause_status=VerificationStatus.UNKNOWN),
        knowledge=ConstraintKnowledge(evidence=evidence, missing=
                                      ["根因描述存在但不可投影"
                                       if _get(data, "D7", "root_cause")
                                       else "根因未公开"]),
        contract=ExperimentContract(goal="生成能触发该崩溃的完整输入",
                                    backend="cuda_container",
                                    allowed_operations=["build_input", "run_tool"],
                                    risk_level="medium"),
        extension=PlatformExtension(name="cuda_toolchain", version="1",
                                    payload={"affected_tools": affected_tools or "",
                                             "cuda_toolkit": toolkit or ""}),
    )
    provenance = {
        "source_directory": str(directory),
        "file_sha256": digests,
        "missing_files": missing,
        "field_states": {"present": sorted(k for k in data),
                         "missing": missing},
        "diagnostics": diagnostics,
        "note": "结构有效不代表漏洞事实已证实；本适配器不补全缺失字段",
    }
    return LegacyBundle(case=case, provenance=provenance)
