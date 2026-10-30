# -*- coding: utf-8 -*-
"""Decide what a crash site is: a known CVE, a fixed-but-unpublished defect, or new.

The ledger records where something crashed and on which releases. The catalog
records what each CVE is and which release fixed it. Putting the two together is
mechanical, and doing it by hand is how "we found something" quietly becomes
"we found something we cannot name".

The rule is deliberately conservative. A site only counts as a known CVE when the
component matches *and* the release that stopped crashing is the release that
advisory names. Anything else is reported as unresolved rather than guessed - an
attribution that is wrong is worse than one that is missing, because it ends the
investigation.

  python -m src.attribute            # attribute every ledger site
  python -m src.attribute --site cuobjdump+0x68000 --show
"""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional

from . import site_ledger

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "data" / "cve_catalog.json"

KNOWN = "已披露"
UNPUBLISHED = "已修复但无对应公告"
UNRESOLVED = "同组件，版本区间不一致"
NEW = "无对应公告（候选新发现）"
UNKNOWN = "无法判定（缺版本数据）"


def load_catalog(path: Path = CATALOG) -> Dict[str, dict]:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def module_of(fingerprint: str) -> str:
    return fingerprint.split("+", 1)[0] if "+" in fingerprint else fingerprint


def short(image: str) -> str:
    """A comparable release label.

    The images are named two ways: ``nvidia/cuda:12.4.1-devel-...`` and the
    project's own ``cpg/cuda112-py3:1.0``, where the toolkit version is in the
    repository name and the tag is a build number. Reading the tag alone turns
    11.2 into "1.0", which then matches nothing.
    """
    text = str(image)
    marker = text.split("/")[-1]
    for digits, version in (("cuda112", "11.2"), ("cuda113", "11.3"),
                            ("cuda118", "11.8"), ("cuda120", "12.0"),
                            ("cuda124", "12.4"), ("cuda130", "13.0"),
                            ("cuda131", "13.1")):
        if digits in marker:
            return version
    tail = text.split(":")[-1].split("-")[0]
    return ".".join(tail.split(".")[:2])


def _same_release(left: str, right: str) -> bool:
    """Compare release labels by major.minor; "13.0.0" and "13.0" are the same."""
    def key(value: str):
        parts = [p for p in str(value).replace("-", ".").split(".")[:2]]
        return ".".join(parts)
    return key(left) == key(right)


def attribute(site: str, entry: dict, catalog: Dict[str, dict]) -> dict:
    """Compare one site against the catalog."""
    module = module_of(site)
    versions = entry.get("versions") or {}
    crashed = [short(image) for image, hit in versions.items() if hit]
    clean = [short(image) for image, hit in versions.items() if not hit]

    candidates = [cve for cve, item in catalog.items()
                  if module.lower() in str(item.get("component", "")).lower()]
    if not candidates:
        return {"verdict": NEW, "cve": "", "reason": "目录里没有组件为 %s 的公告" % module,
                "crashed": crashed, "clean": clean}

    resolved = []
    for cve in candidates:
        fixed = str(catalog[cve].get("fixed_in") or "")
        if fixed and clean and any(_same_release(clean_version, fixed)
                                   for clean_version in clean):
            resolved.append(cve)

    if len(resolved) == 1:
        return {"verdict": KNOWN, "cve": resolved[0],
                "reason": "组件相同，且 %s 之后不再崩溃，与该公告的修复版本一致" % clean[0],
                "crashed": crashed, "clean": clean}
    if len(resolved) > 1:
        return {"verdict": UNRESOLVED, "cve": ",".join(resolved),
                "reason": "多个同组件公告的修复版本都吻合，无法唯一确定",
                "crashed": crashed, "clean": clean}
    if not any(catalog[cve].get("fixed_in") for cve in candidates):
        return {"verdict": UNKNOWN, "cve": "",
                "reason": "同组件有 %d 个公告，但目录里都没有修复版本" % len(candidates),
                "crashed": crashed, "clean": clean}
    return {"verdict": UNPUBLISHED, "cve": "",
            "reason": "同组件公告的修复版本与我们观察到的版本区间不一致",
            "crashed": crashed, "clean": clean,
            "candidates": candidates[:6]}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="attribute crash sites to CVEs")
    parser.add_argument("--ledger", default=site_ledger.DEFAULT_PATH)
    parser.add_argument("--site", default="")
    parser.add_argument("--show", action="store_true")
    parser.add_argument("--write", action="store_true", help="store verdicts in the ledger")
    args = parser.parse_args(argv)

    sites = site_ledger.load(args.ledger)
    catalog = load_catalog()
    if not sites:
        print("台账为空")
        return 2

    rows = []
    for site in sorted(sites):
        if args.site and args.site != site:
            continue
        verdict = attribute(site, sites[site], catalog)
        rows.append((site, verdict))
        if args.write:
            sites[site]["attribution"] = (verdict["cve"] or verdict["verdict"])
            sites[site]["attribution_reason"] = verdict["reason"]

    print("| 崩溃点 | 判定 | CVE | 崩在 | 不崩在 | 理由 |")
    print("|---|---|---|---|---|---|")
    for site, verdict in rows:
        print("| `%s` | %s | %s | %s | %s | %s |"
              % (site, verdict["verdict"], verdict["cve"] or "—",
                 "/".join(verdict["crashed"]) or "—",
                 "/".join(verdict["clean"]) or "—", verdict["reason"]))

    if args.show:
        for site, verdict in rows:
            print("\n%s" % site)
            for key, value in verdict.items():
                print("  %-10s %s" % (key, value))

    if args.write:
        site_ledger.save(sites, args.ledger)
        print("\n已写回台账")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
