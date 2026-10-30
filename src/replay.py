# -*- coding: utf-8 -*-
"""Rebuild one artifact from the ledger and confirm it still crashes where it did.

A crash site in the ledger is a claim about a file that no longer exists - the
variants live in a work directory that gets cleaned up. The recipe stored beside
the site is what makes the claim checkable later: given the same seed, the edits
are absolute and reproduce the artifact byte for byte.

  python -m src.replay --site cuobjdump+0x68000 --seed <cubin> \\
      --image cpg/cuda112-py3:1.0 --tool "cuobjdump --dump-elf {artifact}"
"""

import argparse
import hashlib
from pathlib import Path
from typing import List, Optional

from . import site_ledger
from . import mutation_campaign as campaign


def find_trigger(sites: dict, fingerprint: str) -> Optional[dict]:
    entry = sites.get(fingerprint)
    if not entry:
        return None
    triggers = entry.get("triggers") or []
    return triggers[0] if triggers else None


def rebuild(seed: bytes, trigger: dict) -> bytes:
    """Apply the stored edits; offsets and widths are absolute, so this is exact."""
    return campaign.apply_many(seed, [tuple(edit) for edit in trigger["edits"]])


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="rebuild a ledger site")
    parser.add_argument("--site", required=True)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--image", default=campaign.DEFAULT_IMAGE)
    parser.add_argument("--tool", default="")
    parser.add_argument("--workdir", default="data/mutation/replay")
    parser.add_argument("--ledger", default=site_ledger.DEFAULT_PATH)
    args = parser.parse_args(argv)

    sites = site_ledger.load(args.ledger)
    trigger = find_trigger(sites, args.site)
    if not trigger:
        print("台账里没有 %s，或它没有记录触发配方" % args.site)
        return 2

    seed = Path(args.seed).read_bytes()
    digest = hashlib.sha256(seed).hexdigest()[:16]
    expected = trigger.get("seed_sha256")
    if expected and expected != digest:
        # Wrong seed means the recipe addresses different bytes.
        print("种子的 sha256 前 16 位是 %s，配方记录的是 %s —— 不是同一份种子"
              % (digest, expected))
        return 3

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    artifact = workdir / ("replay_%s.cubin" % args.site.replace("+", "_"))
    artifact.write_bytes(rebuild(seed, trigger))
    print("重建 %s（%d 字节，%d 处编辑）"
          % (artifact, artifact.stat().st_size, len(trigger["edits"])))

    variant = campaign.Variant(axis="replay", field=args.site, value=0,
                               offset=0, width=0)
    # campaign.run materialises every variant from offset/width/value and would
    # overwrite the file just rebuilt; carrying the edits makes it re-apply the
    # same recipe instead, which is also what a re-run should be.
    variant.edits = [tuple(edit) for edit in trigger["edits"]]
    variant.path = str(artifact)
    invocations = [args.tool.split()] if args.tool else \
        [["cuobjdump", "--dump-elf", "{artifact}"]]
    campaign.run([variant], seed, invocations, workdir, args.image)
    campaign.classify([variant], "")

    print("退出码 %s | 崩溃点 %s" % (variant.exit_code, variant.fingerprint or "无"))
    if variant.fingerprint == args.site:
        print("一致：重建的文件崩在同一处")
        return 0
    print("不一致：台账记录的是 %s" % args.site)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
