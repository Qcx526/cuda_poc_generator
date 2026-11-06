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
        "schema_version": case.schema_version,
        "mode": mode,
        "identity": {"case_id": case.identity.case_id, "cve_id": case.identity.cve_id,
                     "title": case.identity.title},
        "target": case.target.model_dump(),
        "entry_surface": case.entry_surface.model_dump(),
        "description": {"public_summary": case.description.public_summary,
                        "cwe": case.description.cwe,
                        "impact": case.description.impact},
        "evidence": evidence,
        "missing": list(case.knowledge.missing),
        "contract": case.contract.model_dump(),
    }
    if case.extension:
        entry = {"name": case.extension.name, "version": case.extension.version}
        if allowed != {Visibility.PUBLIC}:
            # The payload names the image, its hash and candidate RVAs; those are
            # facts, so a blind projection gets the platform name only.
            entry["payload"] = dict(case.extension.payload)
        projected["extension"] = entry
    return projected


def render(case: GPUCase, mode: str) -> str:
    return json.dumps(project(case, mode), ensure_ascii=False, indent=1)
