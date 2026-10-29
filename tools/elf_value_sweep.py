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

INTERESTING = [0, 1, 0xFFFFFFFF]


def fields(data: bytes):
    """Every numeric field in the ELF header and every section header."""
    out = []
    if len(data) < 64:
        return out
    out += [("e_shoff", 0x28, 8), ("e_shentsize", 0x3A, 2),
            ("e_shnum", 0x3C, 2), ("e_shstrndx", 0x3E, 2)]
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    entsize = struct.unpack_from("<H", data, 0x3A)[0]
    count = struct.unpack_from("<H", data, 0x3C)[0]
    if not entsize or shoff + entsize * count > len(data):
        return out
    # Fields a parser actually branches on. sh_addr and sh_addralign are left
    # out: they rarely change a decision, and 630 variants is already enough to
    # turn a five-second probe into an hour.
    named = [("sh_type", 4, 4), ("sh_offset", 24, 8), ("sh_size", 32, 8),
             ("sh_link", 40, 4), ("sh_info", 44, 4), ("sh_entsize", 56, 8)]
    for index in range(count):
        base = shoff + index * entsize
        for name, rel, width in named:
            out.append(("sec%d.%s" % (index, name), base + rel, width))
    return out


def variants_for(data: bytes):
    length = len(data)
    values = INTERESTING + [length, length + 1]
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
