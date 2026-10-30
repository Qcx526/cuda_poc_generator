# -*- coding: utf-8 -*-
"""Every crash site ever seen, so "is this new" is a lookup.

Before this existed, each campaign ended with a human reading offsets and deciding
whether they had been seen before. That does not scale past a handful of runs, and
it fails quietly: an old site reported as new looks exactly like a real finding
until someone checks by hand.

The ledger is the check. A site is identified by module + offset bucket, the same
key the campaign uses for deduplication, plus the versions it was measured on.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional

DEFAULT_PATH = "data/mutation/sites.json"


def load(path: str = DEFAULT_PATH) -> Dict[str, dict]:
    target = Path(path)
    if not target.is_file():
        return {}
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save(sites: Dict[str, dict], path: str = DEFAULT_PATH) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(sites, ensure_ascii=False, indent=2,
                                 sort_keys=True), encoding="utf-8")


def record(sites: Dict[str, dict], fingerprint: str, *, cve: str, tool: str,
           source: str, image: str, crashed: bool = True,
           attribution: str = "", trigger: Optional[dict] = None) -> bool:
    """Add a sighting; returns True when the site was not known before.

    A known site still gets the new version appended: a site that crashes on one
    release and not another is how a fixed/unfixed judgement is made later.
    """
    if not fingerprint:
        return False
    entry = sites.get(fingerprint)
    is_new = entry is None
    if entry is None:
        entry = {"fingerprint": fingerprint, "cve": cve, "tool": tool,
                 "first_source": source, "attribution": attribution,
                 "versions": {}, "triggers": []}
        sites[fingerprint] = entry
    entry["versions"][image] = bool(crashed)
    if trigger:
        _add_trigger(entry, trigger)
    return is_new


MAX_TRIGGERS = 5


def _add_trigger(entry: dict, trigger: dict) -> None:
    """Keep the first few distinct recipes for a site.

    Without them, finding out which mutation reached a crash means searching
    hundreds of variant files by hand - and the artifact files themselves are
    usually gone by the time anyone asks. The recipe is the durable part: edits
    are absolute offsets and widths, so it replays against the same seed byte for
    byte without needing the tooling that produced it.
    """
    triggers = entry.setdefault("triggers", [])

    def key_of(item: dict) -> tuple:
        return (item.get("stage", ""),
                item.get("op", ""),
                tuple(sorted((k, str(v)) for k, v in (item.get("params") or {}).items())),
                tuple(sorted(tuple(edit) for edit in item.get("edits") or [])))

    key = key_of(trigger)
    for existing in triggers:
        if key_of(existing) == key:
            return
    if len(triggers) < MAX_TRIGGERS:
        triggers.append(trigger)


def seen(sites: Dict[str, dict], fingerprint: str) -> bool:
    return bool(fingerprint) and fingerprint in sites


def summary(sites: Dict[str, dict]) -> List[str]:
    """One line per site, newest last, for a report."""
    rows = ["| 崩溃点 | 首次来源 | 归属 | 版本表现 |", "|---|---|---|---|"]
    for key in sorted(sites):
        entry = sites[key]
        versions = entry.get("versions") or {}
        shown = "; ".join("%s %s" % (str(image).split(":")[-1].split("-")[0],
                                     "崩" if crashed else "不崩")
                          for image, crashed in sorted(versions.items()))
        rows.append("| `%s` | %s | %s | %s |"
                    % (key, entry.get("first_source", "—"),
                       entry.get("attribution") or entry.get("cve", "—"),
                       shown or "—"))
    return rows


def find(sites: Dict[str, dict], fingerprint: str) -> Optional[dict]:
    return sites.get(fingerprint)
