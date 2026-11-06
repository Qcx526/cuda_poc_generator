# -*- coding: utf-8 -*-
"""The single entry point a generator uses to turn a case into prompt context.

Both platform backends call this and nothing else; that is what keeps the visibility
contract in one place instead of in each generator. Output is deterministic so a run
can be replayed and audited from the hash alone.
"""

import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional

from .case_projection import FACT_ASSISTED, PUBLIC_ONLY, project
from .case_v2 import GPUCase


def load_case(path: Path) -> GPUCase:
    return GPUCase.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))


def build_context(case_path: Path, mode: str,
                  authorized_fact_ids: Optional[List[str]] = None) -> Dict[str, object]:
    """Return the context plus an audit record of what was and was not included.

    ``authorized_fact_ids`` can only narrow what the case already authorised; it can
    never widen it, so a caller cannot opt into a fact the case did not list.
    """
    case = load_case(case_path)
    if authorized_fact_ids is not None:
        narrowed = [i for i in authorized_fact_ids
                    if i in set(case.contract.authorized_fact_ids)]
        case = case.model_copy(update={"contract": case.contract.model_copy(
            update={"authorized_fact_ids": narrowed})})

    payload = project(case, mode)
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    included = [item["id"] for item in payload.get("evidence", [])]
    excluded = [item.id for item in case.knowledge.evidence if item.id not in included]
    return {
        "case_id": case.identity.case_id,
        "platform": case.target.platform,
        "backend": case.contract.backend,
        "mode": mode,
        "context_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "included_evidence": included,
        "excluded_evidence": excluded,
        "payload": payload,
    }


__all__ = ["build_context", "load_case", "PUBLIC_ONLY", "FACT_ASSISTED"]
