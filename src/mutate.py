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


def verdict_for(versions: Dict[str, bool], newest: str) -> str:
    """What the version ladder says about one site.

    A site that crashes on an older release and not on the newest is a defect
    someone already fixed. A site that crashes on the newest is the only case
    worth carrying forward as a candidate.
    """
    if not versions:
        return "未跨版本"
    crashing = [image for image, hit in versions.items() if hit]
    if not crashing:
        return "各版本均未崩"
    if newest in crashing:
        return "**最新版仍崩（候选新漏洞）**"
    fixed_from = sorted(str(i).split(":")[-1].split("-")[0] for i in versions
                        if not versions[i])
    return "已修复（%s 起不崩）" % "/".join(fixed_from)


def verify_site(site: str, trigger: Optional[dict], seed: bytes,
                images: List[str], invocations: List[List[str]], workdir: Path,
                timeout: int) -> Dict[str, bool]:
    """Rebuild the artifact from its recipe and run it on each release."""
    from .replay import rebuild

    if not trigger or not trigger.get("edits"):
        return {}
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    artifact = workdir / ("verify_%s.cubin" % site.replace("+", "_").replace(".", "_"))
    artifact.write_bytes(rebuild(seed, trigger))
    measured: Dict[str, bool] = {}
    for image in images:
        variant = campaign.Variant(axis="verify", field=site, value=0,
                                   offset=0, width=0)
        variant.edits = [tuple(edit) for edit in trigger["edits"]]
        variant.path = str(artifact)
        stage_dir = workdir / ("verify_%s" % image.split(":")[-1].split("-")[0])
        stage_dir.mkdir(parents=True, exist_ok=True)
        try:
            campaign.run([variant], seed, invocations, stage_dir, image,
                         timeout=timeout)
        except Exception:  # noqa: BLE001 - a missing image must not kill the run
            measured[image] = False
            continue
        measured[image] = bool(_is_site(variant.fingerprint))
    return measured


def build_report(cve: str, seed_path: Path, seed: bytes, image: str,
                 stages: List[dict], skipped: List[str],
                 new_sites: List[str], known_sites: List[str],
                 ledger: Dict[str, dict],
                 verdicts: Optional[Dict[str, dict]] = None) -> str:
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
        lines += ["| 崩溃点 | 台账 | 版本表现 | 结论 |", "|---|---|---|---|"]
        for site in new_sites:
            info = (verdicts or {}).get(site) or {}
            shown = "; ".join("%s %s" % (str(image).split(":")[-1].split("-")[0],
                                         "崩" if hit else "不崩")
                              for image, hit in (info.get("versions") or {}).items())
            lines.append("| `%s` | 新 | %s | %s |"
                         % (site, shown or "—", info.get("verdict", "待查重")))
        for site in known_sites:
            entry = ledger.get(site) or {}
            info = (verdicts or {}).get(site) or {}
            shown = "; ".join("%s %s" % (str(image).split(":")[-1].split("-")[0],
                                         "崩" if hit else "不崩")
                              for image, hit in (info.get("versions") or {}).items())
            lines.append("| `%s` | 已知 | %s | %s |"
                         % (site, shown or "—",
                            entry.get("attribution") or entry.get("cve", "—")))

    lines += ["", "## 结论", ""]
    verdicts = verdicts or {}
    candidates = [site for site in new_sites
                  if "候选" in (verdicts.get(site) or {}).get("verdict", "")]
    if new_sites and verdicts:
        if candidates:
            lines.append("%d 个新崩溃点里，**%d 个在最新版本上仍然崩溃**：%s。"
                         % (len(new_sites), len(candidates),
                            "、".join("`%s`" % site for site in candidates)))
            lines.append("")
            lines.append("下一步：跨版本区间确认（哪一版开始崩）、登记、查重。")
        else:
            lines.append("%d 个新崩溃点全部在最新版本上不再出现，"
                         "说明它们是已修复的缺陷，不是新漏洞。" % len(new_sites))
            lines.append("")
            lines.append("仍有一步没做：查重——确认它们是否为已披露的 CVE，"
                         "而不是仅仅「已修复但未公开」。")
    elif new_sites:
        lines.append("发现 %d 个台账中没有的崩溃点，但未做跨版本验证——"
                     "无法判断是新缺陷还是已修复。" % len(new_sites))
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
    parser.add_argument("--versions", default="",
                        help="comma-separated images to check each new site on, "
                             "newest last")
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

    verdicts: Dict[str, dict] = {}
    images = [item.strip() for item in args.versions.split(",") if item.strip()]
    if images and new_sites:
        newest = images[-1]
        print("\n跨版本验证 %d 个点 × %d 个镜像" % (len(new_sites), len(images)),
              flush=True)
        for site in new_sites:
            trigger = site_ledger.find(ledger, site) or {}
            trigger = (trigger.get("triggers") or [None])[0]
            measured = verify_site(site, trigger, seed, images, invocations,
                                   workdir / "versions", args.timeout)
            for image, hit in measured.items():
                site_ledger.record(ledger, site, cve=args.cve,
                                   tool=" ".join(invocations[0]),
                                   source="version", image=image, crashed=hit)
            verdict = verdict_for(measured, newest)
            verdicts[site] = {"versions": measured, "verdict": verdict}
            print("  %-24s %s" % (site, verdict), flush=True)

    site_ledger.save(ledger, args.ledger)
    report = build_report(args.cve, seed_path, seed, args.image, rows, skipped,
                          new_sites, known_sites, ledger, verdicts)
    (workdir / "mutation_report.md").write_text(report, encoding="utf-8")

    print("\n新崩溃点 %d 个，已知 %d 个" % (len(new_sites), len(known_sites)))
    for site in new_sites:
        print("  新: %s" % site)
    print("报告: %s" % (workdir / "mutation_report.md"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
