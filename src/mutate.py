# -*- coding: utf-8 -*-
"""One entry point for mutating a verified PoC, with a report that says what was
tried and what was not.

Every step is deterministic and needs no model: the stages substitute values,
compute values from other fields, and then the framework runs the artifacts. What
the report adds over the individual tools is coverage accounting - which layers
were exercised, which were skipped and why - and a lookup against the site ledger,
so a crash is either new or known without anyone comparing offsets by hand.

  python -m src.mutate --cve CVE-2024-0076 \\
      --seed data/outputs/CVE-2024-0076/poc_x.cubin \\
      --image cpg/cuda112-py3:1.0 \\
      --tool "cuobjdump --dump-elf {artifact}" --workdir data/mutation/run
"""

import argparse
import hashlib
import json
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Optional

from . import elf_fields, site_ledger
from . import mutation_campaign as campaign
from . import mutation_ops

SECTION_TYPES = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
                 9: "REL", 1879048192: "nv.info", 1879048203: "nv.rel.action"}


def _is_site(fingerprint: str) -> bool:
    """A fault site, as opposed to a bare exit code.

    ``exit:137`` means the process was killed - by the OOM killer, or by the wall
    clock. It says nothing about where the parser went wrong and must not enter a
    ledger of fault sites.
    """
    return bool(fingerprint) and not fingerprint.startswith("exit:")


def section_map(seed: bytes) -> List[dict]:
    """Name, type and size of every section, for the report's structure section."""
    table = elf_fields.table(seed)
    shstrndx = table.get("e_shstrndx", {}).get("value", 0)
    name_off = table.get("sec%d.sh_offset" % shstrndx, {}).get("value", 0)
    name_size = table.get("sec%d.sh_size" % shstrndx, {}).get("value", 0)
    blob = seed[name_off:name_off + name_size]
    count = table.get("e_shnum", {}).get("value", 0)
    out = []
    for index in range(count):
        prefix = "sec%d." % index
        if prefix + "sh_size" not in table:
            continue
        raw = table[prefix + "sh_name"]["value"]
        end = blob.find(b"\x00", raw)
        name = blob[raw:end if end >= 0 else len(blob)].decode("ascii", "replace")
        kind = table[prefix + "sh_type"]["value"]
        out.append({"index": index, "name": name or "(unnamed)",
                    "type": SECTION_TYPES.get(kind, str(kind)),
                    "size": table[prefix + "sh_size"]["value"]})
    return out


def _stage_of(variants: List[campaign.Variant]) -> Dict[str, str]:
    return {variant.field + ":" + str(variant.value): variant.axis
            for variant in variants}


def run_stage(name: str, variants: List[campaign.Variant], seed: bytes,
              invocations: List[List[str]], workdir: Path, image: str,
              timeout: int) -> dict:
    """Run one stage in its own directory, then summarise what it produced."""
    stage_dir = workdir / name
    stage_dir.mkdir(parents=True, exist_ok=True)
    baseline = campaign.Variant(axis="seed", field="(unchanged)", value=0,
                               offset=0, width=0)
    if not variants:
        return {"stage": name, "variants": 0, "refused": 0, "crashed": 0,
                "sites": {}, "baseline": "", "variants_detail": []}
    campaign.run([baseline] + variants, seed, invocations, stage_dir, image,
                 timeout=timeout)
    campaign.classify(variants, baseline.fingerprint)
    refused = [v for v in variants
               if v.exit_code not in (None, 0) and not _is_site(v.fingerprint)]
    # A variant that reproduces the seed's own crash has proved nothing about the
    # mutation: the seed already crashed there. Counting it as a crash is what
    # turns a 688-variant run into "666 crashes" and buries the signal.
    same = [v for v in variants
            if _is_site(v.fingerprint) and v.fingerprint == baseline.fingerprint]
    other = [v for v in variants
             if _is_site(v.fingerprint) and v.fingerprint != baseline.fingerprint]
    sites: Dict[str, int] = {}
    triggers: Dict[str, dict] = {}
    seed_sha = hashlib.sha256(seed).hexdigest()[:16]
    for variant in other:
        sites[variant.fingerprint] = sites.get(variant.fingerprint, 0) + 1
        if variant.fingerprint not in triggers:
            edits = variant.edits or [[variant.offset, variant.width, variant.value]]
            triggers[variant.fingerprint] = {
                "stage": name,
                "artifact": Path(variant.path).name,
                "edits": edits,
                "fields": {variant.field: variant.value},
                "seed_sha256": seed_sha,
            }
    return {"stage": name, "variants": len(variants), "refused": len(refused),
            "same": len(same), "crashed": len(other), "sites": sites,
            "triggers": triggers,
            "baseline": baseline.fingerprint, "variants_detail": variants}


def build_report(cve: str, seed_path: Path, seed: bytes, image: str,
                 stages: List[dict], skipped: List[str],
                 new_sites: List[str], known_sites: List[str],
                 ledger: Dict[str, dict]) -> str:
    lines = ["# 变异报告：%s" % cve, "",
             "| 项 | 值 |", "|---|---|",
             "| 种子 | `%s`（%d 字节）|" % (seed_path.name, len(seed)),
             "| 镜像 | `%s` |" % image,
             "| 工具 | %s |" % (stages[0].get("tool") if stages else "—"), "",
             "## 结构", "",
             "| # | 节 | 类型 | 大小 |", "|---|---|---|---|"]
    for item in section_map(seed):
        lines.append("| %d | `%s` | %s | %d |"
                     % (item["index"], item["name"], item["type"], item["size"]))

    lines += ["", "## 覆盖的层面", "",
              "| 层面 | 变体 | 拒绝 | 与种子同处 | 新点位 | 崩溃点 | 新 | 已知 |",
              "|---|---|---|---|---|---|---|---|"]
    for row in stages:
        new = len([site for site in row["sites"] if site in new_sites])
        known = len(row["sites"]) - new
        lines.append("| `%s` | %d | %d | %d | %d | %d | %d | %d |"
                     % (row["stage"], row["variants"], row["refused"],
                        row.get("same", 0), row["crashed"], len(row["sites"]),
                        new, known))
    for name in skipped:
        lines.append("| `%s` | — | — | — | — | — | — | — |" % name)

    if skipped:
        lines += ["", "## 跳过的层面", ""]
        for name in skipped:
            lines.append("- `%s`：%s" % (name, mutation_ops.SKIP_REASON.get(name, "未实现")))

    baseline = stages[0].get("baseline") if stages else ""
    if baseline:
        lines += ["", "种子本身崩在 `%s`；下表不含这一处。" % baseline]
    lines += ["", "## 崩溃点", ""]
    if not new_sites and not known_sites:
        lines += ["没有崩溃。"]
    else:
        lines += ["| 崩溃点 | 判定 | 归属 |", "|---|---|---|"]
        for site in new_sites:
            lines.append("| `%s` | **台账中没有** | 待查重 |" % site)
        for site in known_sites:
            entry = ledger.get(site) or {}
            lines.append("| `%s` | 已知 | %s |"
                         % (site, entry.get("attribution") or entry.get("cve", "—")))

    lines += ["", "## 结论", ""]
    if new_sites:
        lines.append("发现 %d 个台账中没有的崩溃点，需要做跨版本验证与查重。"
                     % len(new_sites))
    elif known_sites:
        lines.append("只打中台账里已有的崩溃点，没有新发现。")
    else:
        lines.append("这一轮没有崩溃。注意结论只覆盖上面列出的层面；"
                     "跳过的层面没有被证伪。")
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="mutate a verified PoC, by layer")
    parser.add_argument("--cve", required=True)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--image", default=campaign.DEFAULT_IMAGE)
    parser.add_argument("--tool", default="")
    parser.add_argument("--stages", default="value,relation")
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--ledger", default=site_ledger.DEFAULT_PATH)
    parser.add_argument("--timeout", type=int, default=1200)
    args = parser.parse_args(argv)

    seed_path = Path(args.seed)
    seed = seed_path.read_bytes()
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    invocations = [args.tool.split()] if args.tool else \
        [["cuobjdump", "--dump-elf", "{artifact}"]]

    requested = [name.strip() for name in args.stages.split(",") if name.strip()]
    built = mutation_ops.build(seed, requested)
    skipped = list(built.skipped)

    # One variant may be produced by two stages; it is attributed to the first,
    # so the per-stage numbers do not double count the same execution.
    by_stage: "OrderedDict[str, list]" = OrderedDict(
        (name, []) for name in mutation_ops.STAGES)
    seen = set()
    for variant in built.variants:
        key = (variant.offset, variant.width, variant.value)
        if key in seen:
            continue
        seen.add(key)
        by_stage.setdefault(variant.axis, []).append(variant)

    ledger = site_ledger.load(args.ledger)
    # Snapshot before running: a site found by the first stage must not be
    # reported as "known" by the second one.
    was_known = dict(ledger)
    rows = []
    new_sites: List[str] = []
    known_sites: List[str] = []
    for name in mutation_ops.STAGES:
        variants = by_stage.get(name) or []
        if name not in requested:
            continue
        if name not in mutation_ops.IMPLEMENTED:
            continue
        row = run_stage(name, variants, seed, invocations, workdir, args.image,
                        args.timeout)
        row["tool"] = " ".join(invocations[0])
        rows.append(row)
        for site in row["sites"]:
            if site in was_known:
                if site not in known_sites:
                    known_sites.append(site)
            elif site not in new_sites:
                new_sites.append(site)
            site_ledger.record(ledger, site, cve=args.cve, tool=row["tool"],
                               source=name, image=args.image,
                               trigger=(row.get("triggers") or {}).get(site))
        print("%-9s 变体 %4d | 拒绝 %3d | 同种子 %4d | 新点位 %3d | 崩溃点 %d"
              % (name, row["variants"], row["refused"], row["same"],
                 row["crashed"], len(row["sites"])), flush=True)

    site_ledger.save(ledger, args.ledger)
    report = build_report(args.cve, seed_path, seed, args.image, rows, skipped,
                          new_sites, known_sites, ledger)
    (workdir / "mutation_report.md").write_text(report, encoding="utf-8")

    print("\n新崩溃点 %d 个，已知 %d 个" % (len(new_sites), len(known_sites)))
    for site in new_sites:
        print("  新: %s" % site)
    print("报告: %s" % (workdir / "mutation_report.md"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
