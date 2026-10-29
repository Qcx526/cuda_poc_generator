# -*- coding: utf-8 -*-
"""The same budget spent blindly, so the semantic axes have something to beat.

A method that finds new fault sites proves nothing until someone asks whether
random byte flips would have found them too. This runs exactly that: one byte
changed per variant, same seed, same tools, same container, same number of
variants as the semantic campaign spent.

The comparison that matters is not "who crashed more". Crashing is cheap. It is
how many *distinct* fault sites each approach reached, and how many of those were
new - against the rejections each one paid for.

  python -m src.baseline_control --cve CVE-2024-0076 --count 16
"""

import argparse
import json
import random
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from . import mutation_campaign as campaign

RANDOM = "random"


def random_variants(size: int, count: int, seed: int = 7,
                    skip_first: int = 0x40, until: int = 0) -> List[campaign.Variant]:
    """One changed byte each, drawn uniformly, avoiding the ELF ident block.

    The first 64 bytes are the magic, class and type; flipping those produces
    files the loader rejects outright, which measures nothing about the parser.

    ``until`` bounds the draw to the region a parser actually reads (headers and
    the section table). Uniform draws over a whole file spend most of their budget
    on payload bytes, which no parser decision depends on.
    """
    stop = until if until > skip_first else size
    rng = random.Random(seed)
    variants: List[campaign.Variant] = []
    used = set()
    while len(variants) < count:
        offset = rng.randrange(skip_first, stop)
        if offset in used:
            continue
        used.add(offset)
        variants.append(campaign.Variant(axis=RANDOM, field="byte", value=rng.randrange(256),
                                         offset=offset, width=1))
    return variants


def summarise(variants: Sequence[campaign.Variant], baseline: str) -> Dict[str, object]:
    counts: Dict[str, int] = {}
    sites = set()
    novel = set()
    for variant in variants:
        counts[variant.outcome] = counts.get(variant.outcome, 0) + 1
        if variant.fingerprint:
            sites.add(variant.fingerprint)
            if variant.outcome == campaign.NOVEL:
                novel.add(variant.fingerprint)
    return {"counts": counts,
            "distinct_sites": len(sites),
            "novel_sites": sorted(novel),
            "baseline": baseline}


def compare(semantic: Dict[str, object], blind: Dict[str, object]) -> str:
    lines = ["| 指标 | 语义轴变异 | 随机字节变异 |", "|---|---|---|"]
    for key, label in (("SAME_SITE", "打中同一处"), ("CLEAN", "不崩溃"),
                       ("NOVEL_SITE", "落在新点位"), ("NO_SIGNAL", "工具拒绝/无信号")):
        lines.append("| %s | %d | %d |" % (label,
                                           semantic["counts"].get(key, 0),
                                           blind["counts"].get(key, 0)))
    lines.append("| **独立崩溃点** | **%d** | **%d** |"
                 % (semantic["distinct_sites"], blind["distinct_sites"]))
    lines.append("| **独立新点位** | **%d** | **%d** |"
                 % (len(semantic["novel_sites"]), len(blind["novel_sites"])))
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="blind-mutation control arm")
    parser.add_argument("--cve", required=True)
    parser.add_argument("--spec", default="")
    parser.add_argument("--count", type=int, default=16)
    parser.add_argument("--until", type=int, default=0,
                        help="upper bound for random offsets (0 = whole file)")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--workdir", default="")
    parser.add_argument("--tool", default="",
                        help='single tool to exercise, e.g. "nvdisasm {artifact}"')
    parser.add_argument("--image", default=campaign.DEFAULT_IMAGE)
    parser.add_argument("--seed-artifact", default="",
                        help="path to the seed artifact; overrides mutation.seed")
    args = parser.parse_args(argv)

    spec_path = Path(args.spec) if args.spec else Path("specs") / args.cve / "spec.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    block = spec.get("mutation") or {}
    seed_path = (Path(args.seed_artifact) if args.seed_artifact else
                 Path("data/outputs") / args.cve / str(block.get("seed", "")))
    if not seed_path.is_file():
        print("seed not found: %s" % seed_path)
        return 2

    seed_bytes = seed_path.read_bytes()
    workdir = Path(args.workdir) if args.workdir else Path("data/control") / args.cve
    anchor = spec.get("anchor") or {}
    invocations = ([args.tool.split()] if args.tool else
                   campaign.parse_invocations(anchor.get("invocations"),
                                              anchor.get("invocation")))

    baseline_variant = campaign.Variant(axis="seed", field="(unchanged)",
                                        value=0, offset=0, width=0)
    variants = random_variants(len(seed_bytes), args.count, args.seed,
                               until=args.until)
    raw = campaign.run([baseline_variant] + variants, seed_bytes, invocations,
                       workdir, args.image)
    baseline = baseline_variant.fingerprint
    campaign.classify(variants, baseline)

    blind = summarise(variants, baseline)
    # The semantic arm is re-read from its own report, not re-run: both arms must
    # spend the same budget, and re-running one would double its sample.
    semantic_path = Path("data/mutation") / args.cve.lower() / "variants.json"
    semantic: Dict[str, object] = {"counts": {}, "distinct_sites": 0, "novel_sites": []}
    if semantic_path.is_file():
        rows = json.loads(semantic_path.read_text(encoding="utf-8"))
        rows = [row for row in rows if row.get("axis") != "seed"]
        semantic = summarise([campaign.Variant(**{k: row[k] for k in row if k in
                                                  campaign.Variant.__annotations__})
                              for row in rows], baseline)

    table = compare(semantic, blind)
    text = ("# %s 对照实验：语义轴 vs 随机字节\n\n"
            "种子基线指纹：`%s`\n\n"
            "随机组：单字节改动 %d 处，跳过头 64 字节，seed=%d\n\n%s\n"
            % (args.cve, baseline or "未记录", args.count, args.seed, table))
    (Path(workdir) / "control.md").write_text(text, encoding="utf-8")
    (Path(workdir) / "control.json").write_text(
        json.dumps({"blind": blind, "semantic": semantic, "raw_len": len(raw)},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    print(text)
    print("written to %s" % workdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
