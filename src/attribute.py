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
UNTESTED = "未跨版本（无法判断是否已修复）"


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


WRITE_CWES = ("CWE-121", "CWE-787", "CWE-122")
READ_CWES = ("CWE-125", "CWE-476", "CWE-457")


def access_of(entry: dict) -> str:
    """'read' / 'write' / '' as recorded with the trigger."""
    for trigger in entry.get("triggers") or []:
        label = str(trigger.get("access") or trigger.get("severity") or "")
        if "write" in label.lower():
            return "write"
        if "read" in label.lower():
            return "read"
    return ""


def _compatible(entry_access: str, cwe: str) -> bool:
    """A read cannot be a write-type defect, and the other way round."""
    if not entry_access or not cwe:
        return True
    if entry_access == "read":
        return cwe not in WRITE_CWES
    if entry_access == "write":
        return cwe not in READ_CWES
    return True


def attribute(site: str, entry: dict, catalog: Dict[str, dict]) -> dict:
    """Compare one site against the catalog."""
    module = module_of(site)
    versions = entry.get("versions") or {}
    crashed = [short(image) for image, hit in versions.items() if hit]
    clean = [short(image) for image, hit in versions.items() if not hit]

    if len(versions) <= 1 or not clean:
        # One release is not a comparison: nothing can be said about whether the
        # defect was fixed, so no advisory can be ruled in or out.
        return {"verdict": UNTESTED, "cve": "",
                "reason": "只测了 %s，没有不崩的版本可比" % ("/".join(crashed) or "—"),
                "crashed": crashed, "clean": clean}

    candidates = [cve for cve, item in catalog.items()
                  if module.lower() in str(item.get("component", "")).lower()]
    access = access_of(entry)
    if access:
        filtered = [cve for cve in candidates
                    if _compatible(access, str(catalog[cve].get("cwe") or ""))]
        if filtered:
            candidates = filtered
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
                "reason": "组件相同，且 %s 之后不再崩溃，与该公告的修复版本一致"
                          % ("/".join(clean) or "—"),
                "crashed": crashed, "clean": clean, "access": access}
    if len(resolved) > 1:
        return {"verdict": UNRESOLVED, "cve": ",".join(resolved),
                "reason": "多个同组件公告的修复版本都吻合，无法唯一确定",
                "crashed": crashed, "clean": clean, "access": access}
    if not any(catalog[cve].get("fixed_in") for cve in candidates):
        return {"verdict": UNKNOWN, "cve": "",
                "reason": "同组件有 %d 个公告，但目录里都没有修复版本" % len(candidates),
                "crashed": crashed, "clean": clean}
    return {"verdict": UNPUBLISHED, "cve": "",
            "reason": "同组件公告的修复版本与我们观察到的版本区间不一致",
            "crashed": crashed, "clean": clean,
            "candidates": candidates[:6]}


def backfill(sites: Dict[str, dict], seed_path: Path, image: str, tool: str,
             workdir: Path) -> int:
    """Replay sites that were recorded before access type was stored.

    Without it an attribution has to consider every advisory for the component,
    including ones whose defect is a write while ours is a read.
    """
    from . import mutation_campaign as campaign
    from .replay import rebuild

    seed = seed_path.read_bytes()
    workdir.mkdir(parents=True, exist_ok=True)
    filled = 0
    for site, entry in sites.items():
        triggers = entry.get("triggers") or []
        if not triggers or any(t.get("access") for t in triggers):
            continue
        trigger = triggers[0]
        try:
            payload = rebuild(seed, trigger)
        except (KeyError, ValueError):
            continue
        variant = campaign.Variant(axis="backfill", field=site, value=0,
                                   offset=0, width=0)
        variant.payload = payload
        variant.path = str(workdir / ("backfill_%s.cubin"
                                      % site.replace("+", "_").replace(".", "_")))
        Path(variant.path).write_bytes(payload)
        try:
            campaign.run([variant], seed, [tool.split()], workdir, image)
        except Exception:  # noqa: BLE001 - a missing image must not stop the pass
            continue
        if variant.access or variant.severity:
            trigger["access"] = variant.access
            trigger["severity"] = variant.severity
            trigger["access_measured_on"] = image
            filled += 1
            print("%-24s access=%s severity=%s" % (site, variant.access, variant.severity))
        else:
            print("%-24s 重放未复现，未记录" % site)
    return filled


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="attribute crash sites to CVEs")
    parser.add_argument("--ledger", default=site_ledger.DEFAULT_PATH)
    parser.add_argument("--site", default="")
    parser.add_argument("--show", action="store_true")
    parser.add_argument("--write", action="store_true", help="store verdicts in the ledger")
    parser.add_argument("--backfill", action="store_true",
                        help="replay sites to record their access type")
    parser.add_argument("--seed", default="")
    parser.add_argument("--image", default="nvidia/cuda:12.4.1-devel-ubuntu22.04")
    parser.add_argument("--tool", default="cuobjdump --dump-elf {artifact}")
    parser.add_argument("--workdir", default="data/mutation/backfill")
    args = parser.parse_args(argv)

    sites = site_ledger.load(args.ledger)
    catalog = load_catalog()
    if not sites:
        print("台账为空")
        return 2

    if args.backfill:
        if not args.seed:
            print("--backfill 需要 --seed")
            return 2
        filled = backfill(sites, Path(args.seed), args.image, args.tool,
                          Path(args.workdir))
        site_ledger.save(sites, args.ledger)
        print("补了 %d 个点的访问类型" % filled)

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
