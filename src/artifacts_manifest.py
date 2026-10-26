# -*- coding: utf-8 -*-
"""The candidate declares which artifact plays which role.

Name prefixes were doing this job, and they failed in both directions: a sweep
of hundreds of variants produced files the prefixes could not classify, and a
control with a slightly different name was silently counted as a crafted input.

An explicit manifest makes the roles part of the submission instead of a naming
convention: the grader labels from it, exercises only what it names, and a
missing or contradictory manifest is a visible failure rather than a guess.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

MANIFEST_NAME = "artifacts.json"
ROLE_KEYS = {"benign": "BENIGN", "crafted": "MALICIOUS", "controls": "CONTROL"}
MAX_PER_ROLE = 8


class ManifestError(ValueError):
    """The manifest exists but cannot be used as written."""


def load(path_dir: Path) -> Optional[dict]:
    """Read the manifest next to the candidate, or None when absent."""
    path = Path(path_dir) / MANIFEST_NAME
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ManifestError("%s is not valid JSON: %s" % (MANIFEST_NAME, exc))


def entries(manifest: Optional[dict], directory: Path) -> List[Tuple[str, str]]:
    """Flatten a manifest into (file name, role) pairs that exist on disk.

    A named file that is not on disk is dropped rather than invented: a role
    without a file is exactly the "claimed but not produced" case the manifest
    exists to expose.
    """
    if not manifest:
        return []
    root = Path(directory)
    pairs: List[Tuple[str, str]] = []
    for key, role in ROLE_KEYS.items():
        raw = manifest.get(key) or []
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, list):
            raise ManifestError("%s must be a list of file names" % key)
        kept = 0
        for name in raw:
            if not isinstance(name, str) or not name.strip():
                continue
            candidate = root / name.strip()
            if not candidate.is_file():
                continue
            pairs.append((candidate.name, role))
            kept += 1
            if kept >= MAX_PER_ROLE:
                break
    return pairs


def validate(manifest: Optional[dict], pairs: List[Tuple[str, str]]) -> List[str]:
    """Problems a run should be judged on rather than guessed through."""
    if manifest is None:
        return ["no %s: the artifacts were not declared" % MANIFEST_NAME]
    problems = []
    roles = {role for _, role in pairs}
    if "BENIGN" not in roles:
        problems.append("no benign baseline declared")
    if "MALICIOUS" not in roles:
        problems.append("no crafted artifact declared")
    if not problems and len(pairs) > MAX_PER_ROLE * len(ROLE_KEYS):
        problems.append("manifest exceeds the declared artifact budget")
    return problems


def label_lines(pairs: List[Tuple[str, str]]) -> List[str]:
    """The lines the grader already understands, emitted from the manifest."""
    return ["[CPG_LABEL] %s %s" % (name, role) for name, role in pairs]
