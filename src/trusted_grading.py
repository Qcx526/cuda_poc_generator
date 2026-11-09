# -*- coding: utf-8 -*-
"""Grade FILE_INPUT runs from the harness record, not from the candidate's prints.

The observation log used to be the only input to grading, and those lines are written
by the candidate. A trusted record (``iteration_N_trusted.json``) now takes precedence;
when it is absent the verdict is EVIDENCE_MISSING rather than a fallback to claims.

Claims are reconciled with five distinct outcomes, because "0 claims, 0 mismatches"
is not the same as "everything agreed".
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional

CLAIM_FULL = re.compile(r"^\[CPG_RUN\] (\S+?)::([^\s]+) exit=(-?\d+)", re.M)
CLAIM_LEGACY = re.compile(r"^\[CPG_RUN\] (\S+?) exit=(-?\d+)", re.M)
LABEL_LINE = re.compile(r"^\[CPG_LABEL\] (\S+) (BENIGN|MALICIOUS|CONTROL)\s*$", re.M)

MATCHED = "MATCHED"
MISMATCHED = "MISMATCHED"
UNSUPPORTED = "UNSUPPORTED_FORMAT"
NO_CLAIM = "NO_CLAIM"
NO_OBSERVATION = "NO_OBSERVATION"


def parse_claims_detailed(text: str) -> Dict[str, object]:
    """Split claims into supported and unsupported forms, without guessing tools."""
    full = [{"file": m.group(1), "tool": m.group(2), "exit": int(m.group(3))}
            for m in CLAIM_FULL.finditer(text or "")]
    legacy = [{"file": m.group(1), "exit": int(m.group(2))}
              for m in CLAIM_LEGACY.finditer(text or "")]
    # A legacy line has no tool, and the tool cannot be inferred from the filename.
    return {"full": full, "legacy": legacy,
            "unsupported_lines": ["[CPG_RUN] %s exit=%s" % (c["file"], c["exit"])
                                  for c in legacy]}


def reconcile(text: str, trusted_path: Path) -> Dict[str, object]:
    claims = parse_claims_detailed(text)
    observed = {}
    if trusted_path.is_file():
        data = json.loads(trusted_path.read_text(encoding="utf-8"))
        for item in data.get("invocations", []):
            name = item["run_id"].rsplit(":", 1)[-1]
            observed[(item["tool"], name)] = item["exit_code"]

    outcomes = {"matched": [], "mismatched": [], "unsupported": claims["unsupported_lines"],
                "no_claim": not claims["full"] and not claims["legacy"]}
    for claim in claims["full"]:
        key = (claim["tool"], claim["file"])
        if key not in observed:
            outcomes["mismatched"].append({**claim, "observed": None,
                                           "reason": NO_OBSERVATION})
        elif observed[key] == claim["exit"]:
            outcomes["matched"].append({**claim, "observed": observed[key]})
        else:
            outcomes["mismatched"].append({**claim, "observed": observed[key],
                                           "reason": MISMATCHED})
    # Legacy claims never match anything: no tool identity, so no comparison is valid.
    outcomes["legacy_count"] = len(claims["legacy"])
    outcomes["authoritative"] = "trusted" if observed else "none"
    return outcomes


def runs_from_trusted(trusted_path: Path, observation_text: str) -> List[dict]:
    """One run entry per trusted invocation, labelled by what the run declared.

    Labels stay candidate-declared: the harness observes exits, not intent. Each entry
    carries the artifact hash so a label can always be traced back to exact bytes.
    """
    data = json.loads(trusted_path.read_text(encoding="utf-8"))
    labels = {name: role.upper() for name, role in LABEL_LINE.findall(observation_text or "")}
    runs = []
    for item in data.get("invocations", []):
        name = item["run_id"].rsplit(":", 1)[-1]
        run = {"artifact": name, "exit_code": item["exit_code"],
               "tool": item["tool"], "tool_version": item.get("tool_version", ""),
               "sha256": item.get("input_sha256", "")}
        if name in labels:
            run["label"] = labels[name]
            run["label_source"] = "candidate_declared"
        runs.append(run)
    return runs


def trust_status(trusted_path: Path, observation_text: str) -> dict:
    if not trusted_path.is_file():
        return {"level": "EVIDENCE_MISSING",
                "reason": "没有 trusted 记录：判定不得回退到候选打印"}
    data = json.loads(trusted_path.read_text(encoding="utf-8"))
    invocations = data.get("invocations", [])
    if not invocations:
        return {"level": "EVIDENCE_MISSING",
                "reason": "trusted 记录里没有任何工具调用"}
    unknown = [i for i in invocations if i.get("tool_version") in (None, "", "unknown")]
    return {"level": "TRUSTED", "invocations": len(invocations),
            "unknown_tool_version": len(unknown),
            "note": "标签为候选声明，退出码与哈希为 harness 观测"}


__all__ = ["parse_claims_detailed", "reconcile", "runs_from_trusted", "trust_status",
           "MATCHED", "MISMATCHED", "UNSUPPORTED", "NO_CLAIM", "NO_OBSERVATION"]
