# -*- coding: utf-8 -*-
"""Blind projection of the seven-dimension bundle.

The earlier fix only filtered the spec file, while the pipeline still handed the raw
bundle to the security expert: `7_root_cause` carries the faulting address (0x45ada0)
and the exact alignment expression, and `4_attack_surface` names the field. A prompt
built from those measures reading, not generation.

This module is the single place that decides what a blind run may see, and it is
applied before the expert, not after it.
"""

import re
from typing import Any, Dict, Iterable

# Dimensions that may be shown, and the keys within them. Anything absent is dropped.
PUBLIC_KEYS = {
    "affected_component": ("name", "component_name", "type", "vendor",
                           "version_range", "file_format_input",
                           "advisory_url", "technical_report"),
    "cuda_environment": ("cuda_toolkit_version", "fix_version", "affected_tools",
                         "gpu_architecture"),
    # attack_vector / attack_complexity / surface_type are free text extracted from
    # a technical write-up: for 23340 they spell out "sh_size = 1..11", which is the
    # answer. Only the generic surface facts survive.
    "attack_surface": ("subsystem", "entry_type", "entry_point",
                       "required_permissions", "remote_trigger"),
    # vulnerability_type nests free-text fields (subtype) that restate the bug, so
    # only the classification values are projected.
    "vulnerability_type": ("vulnerability_type",),
}

PUBLIC_NESTED = {
    "vulnerability_type": ("cwe_id", "cwe_name", "vulnerability_category",
                           "cvss_score", "cvss_severity", "cvss_vector"),
}

# Anything shaped like a location or an arithmetic derivation is internal analysis.
SCRUBBERS = (
    (re.compile(r"0x[0-9a-fA-F]{4,}"), "<addr>"),
    (re.compile(r"`[^`]{0,120}`"), "<expr>"),
)


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        text = value
        for pattern, replacement in SCRUBBERS:
            text = pattern.sub(replacement, text)
        return text
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def project(dimensions: Dict[str, Any]) -> Dict[str, Any]:
    """Advisory-level view of the bundle, keyed as the expert expects.

    Kept deliberately non-empty: removing everything would make the run blind but
    also unusable, which is a different failure.
    """
    out: Dict[str, Any] = {}
    for name, keys in PUBLIC_KEYS.items():
        section = dimensions.get(name)
        if not isinstance(section, dict):
            continue
        kept = {k: section[k] for k in keys if k in section and section[k]}
        nested_keys = PUBLIC_NESTED.get(name)
        if nested_keys and isinstance(kept.get("vulnerability_type"), dict):
            inner = kept["vulnerability_type"]
            kept["vulnerability_type"] = {k: inner[k] for k in nested_keys if k in inner}
        if kept:
            out[name] = _clean(kept)
    cve_id = dimensions.get("cve_id") or dimensions.get("affected_component", {}).get("cve_id")
    if cve_id:
        out["cve_id"] = cve_id
    out["_blind"] = True
    return out


def forbidden_terms() -> Iterable[str]:
    """Strings that must never survive projection."""
    return ("root_cause", "0x45", "controllable_fields", "exploitation_difficulty",
            "vulnerable_function", "tool_path", "trigger_command",
            "sh_size", "attack_vector", "attack_complexity")


def audit(text: str) -> list:
    """Return any leaked markers found in a rendered prompt."""
    hits = []
    for term in forbidden_terms():
        if term in text:
            hits.append(term)
    if re.search(r"0x[0-9a-fA-F]{4,}", text):
        hits.append("address-like")
    return hits
