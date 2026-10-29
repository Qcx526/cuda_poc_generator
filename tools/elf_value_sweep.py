# -*- coding: utf-8 -*-
"""One-off experiment: substitute dangerous values into every ELF field.

Why this operator and not random bytes: the crash on 11.2 needed sh_size to be
exactly 0xFFFFFFFF. A single flipped byte cannot produce that, which is why 124
single-byte mutations on the fixed release found nothing. Parser bugs are usually
about a value crossing a boundary, so the values worth trying are the boundaries.

Not wired into the pipeline: this is a probe, and a probe that earns its keep gets
promoted afterwards.

  python tools/elf_value_sweep.py --seed <cubin> --image nvidia/cuda:12.4.1-devel-ubuntu22.04 \
      --tool "nvdisasm {artifact}" --workdir data/control/sweep
"""

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import mutation_campaign as campaign  # noqa: E402
from src.elf_fields import fields  # noqa: E402

# Values a parser branches on: zero, one, the window just below the ELF
# alignment of a RELA entry (12), which is the precondition a heap-write bug
# documents, the sign boundary, and the all-ones patterns that turn a length
# into a huge one.
INTERESTING = [0, 1, 2, 8, 11, 0x7FFFFFFF, 0xFFFFFFFF]


def variants_for(data: bytes):
    """One variant per (field, interesting value) that fits the field."""
    length = len(data)
    values = INTERESTING + [length, length + 1, 0xFFFFFFFFFFFFFFFF]
    variants = []
    for name, offset, width in fields(data):
        limit = (1 << (8 * width)) - 1
        for value in values:
            if value > limit:
                continue
            variants.append(campaign.Variant(axis=name, field=name, value=value,
                                             offset=offset, width=width))
    return variants


def summarise(crashes):
    """Group crashes by fault site.

    Forty-four variants that all land in libc+0x183000 are one fact about the
    parser, repeated - not forty-four findings. Counting variants overstates the
    result in a way that is easy to quote by accident.
    """
    groups = {}
    for variant in crashes:
        groups.setdefault(variant.fingerprint, []).append(variant)
    return sorted(groups.items(), key=lambda item: -len(item[1]))


def main() -> int:
    parser = argparse.ArgumentParser(description="dangerous-value sweep over ELF fields")
    parser.add_argument("--seed", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--tool", default="nvdisasm {artifact}")
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--timeout", type=int, default=1200)
    args = parser.parse_args()

    seed = Path(args.seed).read_bytes()
    variants = variants_for(seed)
    baseline = campaign.Variant(axis="seed", field="(unchanged)", value=0,
                                offset=0, width=0)
    workdir = Path(args.workdir)
    campaign.run([baseline] + variants, seed, [args.tool.split()], workdir,
                 args.image, timeout=args.timeout)
    campaign.classify(variants, baseline.fingerprint)

    print("seed fingerprint: %s | variants: %d"
          % (baseline.fingerprint or "(clean)", len(variants)))
    crashes = [v for v in variants if v.outcome == campaign.NOVEL]
    groups = summarise(crashes)
    print("crashes at a new site: %d, at %d distinct site(s)"
          % (len(crashes), len(groups)))
    for site, items in groups:
        fields = sorted({item.field for item in items})
        access = sorted({item.severity for item in items if item.severity})
        sample = Path(items[0].path).name if items[0].path else "-"
        print("  %-26s %2d variant(s) | %-18s | %s"
              % (site, len(items), "/".join(access) or "unknown",
                 ", ".join(fields[:5])))
        print("      e.g. %s" % sample)
    if not crashes:
        print("  none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
