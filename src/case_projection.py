# -*- coding: utf-8 -*-
"""Turn a case into what a model is allowed to see.

Visibility is decided per evidence object, not per document. A public write-up can
still contain the full trigger recipe - the 23340 advisory text does - so "public"
is not a licence to paste it into a blind prompt.
"""

import json
from typing import Dict, List

from .case_v2 import GPUCase, Visibility

PUBLIC_ONLY = "PUBLIC_ONLY"
FACT_ASSISTED = "FACT_ASSISTED"


def _allowed(mode: str) -> set:
    if mode == PUBLIC_ONLY:
        return {Visibility.PUBLIC}
    if mode == FACT_ASSISTED:
        return {Visibility.PUBLIC, Visibility.FACT}
    raise ValueError("未知投影模式: %s" % mode)


# Only these fields are rendered. Anything else is dropped by default, including
# fields added later.
PUBLIC_FIELDS = {
    "identity": ("case_id", "cve_id", "title"),
    "target": ("vendor", "component", "platform", "execution_tier", "versions"),
    "entry_surface": ("medium", "interface", "trust_boundary"),
    "description": ("public_summary", "cwe", "impact"),
}
# allowed_operations can name capabilities the blind prompt should not advertise.
CONTRACT_FIELDS = ("goal", "backend", "risk_level")


def _pick(source: dict, keys) -> Dict[str, object]:
    return {key: source[key] for key in keys if source.get(key) not in (None, "", [], {})}


def project(case: GPUCase, mode: str) -> Dict[str, object]:
    allowed = _allowed(mode)
    evidence: List[dict] = []
    for item in case.knowledge.evidence:
        if item.visible_in not in allowed:
            continue
        entry = {"id": item.id, "kind": item.kind.value,
                 "statement": item.statement, "status": item.status.value}
        if item.kind.value == "STATIC_FACT":
            entry["source"] = item.source
            entry["target_identity"] = item.target_identity
        evidence.append(entry)

    projected = {
        "evidence": evidence,
        "schema_version": case.schema_version,
        "mode": mode,
        "identity": _pick(case.identity.model_dump(), PUBLIC_FIELDS["identity"]),
        "target": _pick(case.target.model_dump(), PUBLIC_FIELDS["target"]),
        "entry_surface": _pick(case.entry_surface.model_dump(),
                               PUBLIC_FIELDS["entry_surface"]),
        "description": _pick(case.description.model_dump(),
                             PUBLIC_FIELDS["description"]),
        "contract": _pick(case.contract.model_dump(), CONTRACT_FIELDS),
    }
    if case.extension:
        if allowed == {Visibility.PUBLIC}:
            # The payload names the image, its hash and candidate RVAs; those are
            # facts, so a blind projection gets the platform name only.
            projected["extension"] = {"name": case.extension.name}
        else:
            projected["extension"] = _pick(case.extension.model_dump(),
                                           ("name", "version", "payload"))
    # missing 可能在自由文本里点出关键字段名，只有非盲测模式才带。
    if allowed != {Visibility.PUBLIC}:
        projected["missing"] = list(case.knowledge.missing)
    return projected


def render(case: GPUCase, mode: str) -> str:
    return json.dumps(project(case, mode), ensure_ascii=False, indent=1)
