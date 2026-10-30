# -*- coding: utf-8 -*-
"""Both arms must spend the same budget and mutate by the same rules."""

import struct

from src import corpus_lab


def _cubin(sections=3) -> bytes:
    entsize, shoff = 64, 64
    shstr = b"\x00.shstrtab\x00.text\x00"
    data = bytearray(shoff + entsize * sections) + bytearray(shstr)
    data[0:4] = b"\x7fELF"
    data[4] = 2
    struct.pack_into("<Q", data, 0x28, shoff)
    struct.pack_into("<H", data, 0x3A, entsize)
    struct.pack_into("<H", data, 0x3C, sections)
    struct.pack_into("<H", data, 0x3E, 1)
    base = shoff + entsize * 2
    struct.pack_into("<I", data, base, 11)
    struct.pack_into("<I", data, base + 4, 1)
    struct.pack_into("<Q", data, base + 24, 64)
    struct.pack_into("<Q", data, base + 32, 32)
    return bytes(data)


def test_both_arms_share_one_vocabulary():
    """The comparison is only meaningful if the mutation rules are identical."""
    seed = _cubin()
    items = corpus_lab.vocabulary(seed)
    kinds = {kind for kind, _ in items}
    assert kinds == {"field", "layout"}
    assert any(payload[0] == "sec2.sh_size" for kind, payload in items
               if kind == "field")


def test_a_field_mutation_applies_to_any_parent():
    seed = _cubin()
    changed = corpus_lab.apply_to(seed, ("field", ("sec2.sh_size", 1)))
    assert changed is not None and changed != seed
    table = __import__("src.elf_fields", fromlist=["table"]).table(changed)
    assert table["sec2.sh_size"]["value"] == 1


def test_a_mutation_that_would_change_nothing_is_dropped():
    seed = _cubin()
    table = __import__("src.elf_fields", fromlist=["table"]).table(seed)
    current = table["sec2.sh_size"]["value"]
    assert corpus_lab.apply_to(seed, ("field", ("sec2.sh_size", current))) is None


def test_a_mutation_naming_a_missing_field_is_dropped():
    assert corpus_lab.apply_to(_cubin(), ("field", ("sec9.sh_size", 0))) is None


def test_an_impossible_layout_is_dropped():
    assert corpus_lab.apply_to(b"", ("layout", ("truncate", {"at": 5}))) is None


def test_the_summary_counts_sites_not_runs():
    from src import mutation_campaign as campaign

    variants = [
        campaign.Variant(axis="lab", field="a", value=0, offset=0, width=0,
                         exit_code=139, fingerprint="cuobjdump+0x67000"),
        campaign.Variant(axis="lab", field="b", value=0, offset=0, width=0,
                         exit_code=139, fingerprint="cuobjdump+0x67000"),
        campaign.Variant(axis="lab", field="c", value=0, offset=0, width=0,
                         exit_code=255),
    ]
    summary = corpus_lab.summarize("flat", variants, budget=10)
    assert summary["site_count"] == 1 and summary["ran"] == 3
    assert summary["refused"] == 1
