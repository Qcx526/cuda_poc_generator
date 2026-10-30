# -*- coding: utf-8 -*-
"""Two ways to spend the same number of executions, measured against each other.

Arm A is what the pipeline does now: enumerate mutations of the seed, one variant
each, no memory. Arm B keeps a queue: a variant that makes the tool print more than
the seed did is kept and mutated again, so changes accumulate.

The comparison is only meaningful if the arms differ in one thing. Both use the
same mutation vocabulary, the same seed, the same budget in executions, and the
same crash-site objective. Arm B additionally uses output volume as its selection
signal - that is the only difference, and the point being tested.

  python -m src.corpus_lab --seed <cubin> --image <img> --budget 120 --arm both
"""

import argparse
import random
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import elf_fields, site_ledger
from . import mutation_campaign as campaign
from . import mutation_ops

# The mutation vocabulary both arms draw from. Field mutations are named, not
# offset-addressed, so they apply to any parent that has the field.
FIELD_VALUES = (0, 1, 8, 11, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)


def vocabulary(seed: bytes) -> List[Tuple[str, object]]:
    """Everything either arm is allowed to try, in a parent-agnostic form."""
    table = elf_fields.table(seed)
    items: List[Tuple[str, object]] = []
    for name, item in table.items():
        for value in FIELD_VALUES:
            if value < (1 << (8 * item["width"])) and value != item["value"]:
                items.append(("field", (name, value)))
    for op, params in (("truncate", {"at": len(seed) - 1}),
                       ("truncate", {"at": len(seed) // 2}),
                       ("pad", {"bytes": 64}),
                       ("copy_table_to_end", {})):
        items.append(("layout", (op, params)))
    return items


def apply_to(parent: bytes, mutation: Tuple[str, object]) -> Optional[bytes]:
    """One mutation, applied to whatever parent was chosen."""
    kind, payload = mutation
    if kind == "layout":
        op, params = payload
        try:
            out = mutation_ops.rebuild_layout(parent, op, params)
        except (ValueError, KeyError):
            return None
        return out if out and out != parent else None
    name, value = payload
    item = elf_fields.table(parent).get(name)
    if not item:
        return None
    if value >= (1 << (8 * item["width"])) or value == item["value"]:
        return None
    return campaign.apply(parent, item["offset"], item["width"], value)


def measure(samples: List[Tuple[str, bytes]], seed: bytes, image: str,
            workdir: Path, tool: List[str]) -> List[campaign.Variant]:
    """Run a batch of finished artifacts and return them with depth and fault site."""
    if not samples:
        return []
    variants = []
    for label, payload in samples:
        variant = campaign.Variant(axis="lab", field=label, value=0, offset=0,
                                   width=0)
        variant.payload = payload
        variants.append(variant)
    workdir.mkdir(parents=True, exist_ok=True)
    for index, variant in enumerate(variants):
        variant.path = str(workdir / ("%03d_%s.cubin"
                                      % (index, variant.field.replace("/", "_")[:40])))
        Path(variant.path).write_bytes(variant.payload)
    campaign.run(variants, seed, [tool], workdir, image)
    campaign.classify(variants, "")
    return variants


def arm_flat(seed: bytes, image: str, budget: int, workdir: Path, tool: List[str],
             rng: random.Random) -> Dict[str, object]:
    """Current approach: every mutation starts from the seed again."""
    items = vocabulary(seed)
    rng.shuffle(items)
    picked = items[:budget]
    samples = []
    for index, mutation in enumerate(picked):
        payload = apply_to(seed, mutation)
        if payload:
            samples.append(("%03d" % index, payload))
    found = measure(samples, seed, image, workdir, tool)
    return summarize("flat", found, budget)


def arm_queue(seed: bytes, image: str, budget: int, workdir: Path,
              tool: List[str], rng: random.Random,
              prefer_deep: float = 0.7) -> Dict[str, object]:
    """Keep what got deeper, mutate it again.

    A parent is chosen from the queue - the deepest one most of the time, a random
    one otherwise, so the search can still escape a local maximum.
    """
    items = vocabulary(seed)
    queue: List[Tuple[str, bytes, int]] = [("seed", seed, 0)]
    found: List[campaign.Variant] = []
    depth0 = measure([("seed", seed)], seed, image, workdir / "seed", tool)
    base_depth = depth0[0].stdout_bytes if depth0 else 0

    for step in range(budget):
        if rng.random() < prefer_deep:
            parent = max(queue, key=lambda item: item[2])
        else:
            parent = rng.choice(queue)
        mutation = rng.choice(items)
        payload = apply_to(parent[1], mutation)
        if payload is None:
            continue
        label = "%03d" % step
        result = measure([(label, payload)], seed, image,
                         workdir / label, tool)
        if not result:
            continue
        variant = result[0]
        found.append(variant)
        # Enqueue when the file is more than a dead end: the tool printed
        # something. Depth above the seed's own is the stronger signal.
        if variant.stdout_bytes > base_depth:
            queue.append((label, payload, variant.stdout_bytes))
        elif variant.stdout_bytes > 0 and len(queue) < 8:
            queue.append((label, payload, variant.stdout_bytes))
    return summarize("queue", found, budget)


def summarize(name: str, variants: List[campaign.Variant], budget: int) -> Dict[str, object]:
    sites = {v.fingerprint for v in variants
             if v.fingerprint and not v.fingerprint.startswith("exit:")}
    refused = [v for v in variants
               if v.exit_code not in (None, 0) and not v.fingerprint]
    parsed = [v for v in variants if v.exit_code == 0]
    return {"arm": name, "executions": budget, "ran": len(variants),
            "sites": sorted(sites), "site_count": len(sites),
            "refused": len(refused), "parsed": len(parsed),
            "depth_max": max((v.stdout_bytes for v in variants), default=0)}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="flat enumeration vs queue")
    parser.add_argument("--seed", required=True)
    parser.add_argument("--image", default=campaign.DEFAULT_IMAGE)
    parser.add_argument("--tool", default="cuobjdump --dump-elf {artifact}")
    parser.add_argument("--budget", type=int, default=120)
    parser.add_argument("--arm", choices=("flat", "queue", "both"), default="both")
    parser.add_argument("--workdir", default="data/mutation/lab")
    parser.add_argument("--seed-value", type=int, default=17)
    args = parser.parse_args(argv)

    seed = Path(args.seed).read_bytes()
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    tool = args.tool.split()
    rng = random.Random(args.seed_value)

    results = []
    if args.arm in ("flat", "both"):
        results.append(arm_flat(seed, args.image, args.budget,
                                workdir / "flat", tool, rng))
    if args.arm in ("queue", "both"):
        results.append(arm_queue(seed, args.image, args.budget,
                                 workdir / "queue", tool, rng))

    lines = ["# 对照实验：一次性枚举 vs 队列累积", "",
             "| 组 | 执行数 | 实际跑 | 崩溃点 | 每百次执行 | 被拒 | 最深处 |",
             "|---|---|---|---|---|---|---|"]
    for row in results:
        per100 = 100.0 * row["site_count"] / max(1, row["executions"])
        lines.append("| %s | %d | %d | %d | %.2f | %d | %d |"
                     % (row["arm"], row["executions"], row["ran"],
                        row["site_count"], per100, row["refused"],
                        row["depth_max"]))
    for row in results:
        lines.append("")
        lines.append("%s 命中的崩溃点：%s"
                     % (row["arm"], "、".join("`%s`" % s for s in row["sites"]) or "无"))
    text = "\n".join(lines) + "\n"
    (workdir / "comparison.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
