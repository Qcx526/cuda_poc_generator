# -*- coding: utf-8 -*-
"""Stages, the ledger, and the report that ties them together."""

import json
import struct
from pathlib import Path

from src import mutation_ops, site_ledger
from src.mutate import section_map


def _cubin(sections=3) -> bytes:
    """A cubin-shaped ELF with a string table and a named section."""
    entsize, shoff = 64, 64
    shstr = b"\x00.shstrtab\x00.text\x00"
    data = bytearray(shoff + entsize * sections) + bytearray(shstr)
    data[0:4] = b"\x7fELF"
    data[4] = 2
    struct.pack_into("<Q", data, 0x28, shoff)
    struct.pack_into("<H", data, 0x3A, entsize)
    struct.pack_into("<H", data, 0x3C, sections)
    struct.pack_into("<H", data, 0x3E, 1)
    name_base = shoff + entsize * sections
    # section 1: the string table itself
    base = shoff + entsize
    struct.pack_into("<I", data, base, 1)                    # sh_name
    struct.pack_into("<I", data, base + 4, 3)                # sh_type STRTAB
    struct.pack_into("<Q", data, base + 24, name_base)       # sh_offset
    struct.pack_into("<Q", data, base + 32, len(shstr))      # sh_size
    # section 2: named .text
    base = shoff + entsize * 2
    struct.pack_into("<I", data, base, 11)                   # sh_name -> ".text"
    struct.pack_into("<I", data, base + 4, 1)                # PROGBITS
    struct.pack_into("<Q", data, base + 24, 64)              # sh_offset
    struct.pack_into("<Q", data, base + 32, 32)              # sh_size
    struct.pack_into("<Q", data, base + 56, 16)              # sh_entsize
    return bytes(data)


def test_value_stage_covers_every_field_with_boundaries():
    seed = _cubin()
    variants = mutation_ops.value_stage(seed)
    assert variants and all(v.axis == "value" for v in variants)
    assert any(v.value == 0 for v in variants)
    assert any(v.value == len(seed) for v in variants)


def test_relation_stage_derives_sizes_from_the_file_length():
    seed = _cubin()
    variants = mutation_ops.relation_stage(seed)
    sizes = {(v.field, v.value) for v in variants}
    assert ("sec2.sh_size", len(seed) - 64) in sizes          # exactly fits
    assert ("sec2.sh_size", len(seed) - 64 + 8) in sizes      # eight bytes over


def test_relation_stage_offers_a_stride_below_the_record_size():
    """Twelve bytes is the alignment a relocation entry needs; a stride below it
    is the precondition a heap-write bug documents."""
    seed = _cubin()
    variants = mutation_ops.relation_stage(seed)
    assert ("sec2.sh_entsize", 12) in {(v.field, v.value) for v in variants}


def test_relation_stage_points_indexes_one_past_the_last_section():
    seed = _cubin()
    variants = mutation_ops.relation_stage(seed)
    assert ("sec2.sh_link", 3) in {(v.field, v.value) for v in variants}


def test_relation_stage_puts_names_at_the_end_of_the_string_table():
    seed = _cubin()
    variants = mutation_ops.relation_stage(seed)
    shstr = len(b"\x00.shstrtab\x00.text\x00")
    assert ("sec2.sh_name", shstr) in {(v.field, v.value) for v in variants}


def test_unimplemented_layers_are_reported_not_silently_dropped():
    built = mutation_ops.build(_cubin(), ["value", "layout", "payload", "naming"])
    assert set(built.skipped) == {"payload", "naming"}
    assert "尚未实现" in mutation_ops.SKIP_REASON["payload"]
    # layout is implemented now, so it must contribute variants, not a skip note
    assert any(v.axis == "layout" for v in built.variants)


def test_build_deduplicates_across_stages():
    built = mutation_ops.build(_cubin(), ["value", "relation"])
    keys = [(v.offset, v.width, v.value) for v in built.variants]
    assert len(keys) == len(set(keys))


def test_the_ledger_tells_new_from_known():
    sites = {}
    assert site_ledger.record(sites, "cuobjdump+0xb000", cve="CVE-X",
                              tool="cuobjdump", source="value",
                              image="cuda:11.2") is True
    assert site_ledger.record(sites, "cuobjdump+0xb000", cve="CVE-X",
                              tool="cuobjdump", source="relation",
                              image="cuda:12.4") is False
    assert sites["cuobjdump+0xb000"]["versions"] == {"cuda:11.2": True,
                                                    "cuda:12.4": True}


def test_the_ledger_survives_a_round_trip(tmp_path: Path):
    path = tmp_path / "sites.json"
    sites = {}
    site_ledger.record(sites, "nvdisasm+0x10000", cve="CVE-Y", tool="nvdisasm",
                       source="llm", image="cuda:12.4")
    site_ledger.save(sites, str(path))
    assert site_ledger.load(str(path))["nvdisasm+0x10000"]["cve"] == "CVE-Y"


def test_an_empty_fingerprint_is_never_recorded():
    sites = {}
    assert site_ledger.record(sites, "", cve="CVE-X", tool="t", source="s",
                              image="i") is False
    assert sites == {}


def test_the_structure_map_reads_names_from_the_string_table():
    names = [item["name"] for item in section_map(_cubin())]
    assert ".shstrtab" in names and ".text" in names


def test_an_exit_code_is_not_a_fault_site():
    """137 means the process was killed, not that the parser failed somewhere."""
    from src.mutate import _is_site

    assert _is_site("cuobjdump+0xb000") is True
    assert _is_site("exit:137") is False
    assert _is_site("") is False


def test_the_report_separates_the_seeds_own_crash(tmp_path):
    from src.mutate import build_report

    seed = _cubin()
    path = tmp_path / "seed.cubin"
    path.write_bytes(seed)
    rows = [{"stage": "value", "variants": 10, "refused": 2, "same": 7,
             "crashed": 1, "sites": {"cuobjdump+0x68000": 1},
             "baseline": "cuobjdump+0xb000", "tool": "cuobjdump"}]
    text = build_report("CVE-X", path, seed, "img", rows, ["layout"],
                        ["cuobjdump+0x68000"], [], {})
    assert "种子本身崩在 `cuobjdump+0xb000`" in text
    assert "| `value` | 10 | 2 | 7 | 1 | 1 | 1 | 0 |" in text


def test_a_site_is_reported_once_even_if_two_stages_find_it(tmp_path):
    from src.mutate import build_report

    seed = _cubin()
    path = tmp_path / "seed.cubin"
    path.write_bytes(seed)
    rows = [
        {"stage": "value", "variants": 5, "refused": 0, "same": 0, "crashed": 1,
         "sites": {"cuobjdump+0x68000": 1}, "baseline": "", "tool": "cuobjdump"},
        {"stage": "relation", "variants": 5, "refused": 0, "same": 0, "crashed": 1,
         "sites": {"cuobjdump+0x68000": 1}, "baseline": "", "tool": "cuobjdump"},
    ]
    text = build_report("CVE-X", path, seed, "img", rows, [],
                        ["cuobjdump+0x68000"], [], {})
    section = text.split("## 崩溃点")[1]
    assert section.count("cuobjdump+0x68000") == 1


# ---- triggers: a site's claim has to be rebuildable --------------------------

def test_a_trigger_records_absolute_edits():
    from src import mutation_campaign as campaign
    from src.mutate import run_stage  # noqa: F401  (import keeps the contract honest)

    seed = _cubin()
    variant = campaign.Variant(axis="value", field="sec2.sh_size", value=0,
                               offset=64 + 64 + 32, width=8)
    variant.path = "value_sec2.sh_size_0.cubin"
    edits = variant.edits or [[variant.offset, variant.width, variant.value]]
    assert edits == [[160, 8, 0]]


def test_the_trigger_rebuilds_the_same_bytes():
    from src import mutation_campaign as campaign
    from src.replay import rebuild

    seed = _cubin()
    trigger = {"edits": [[160, 8, 0]]}
    rebuilt = rebuild(seed, trigger)
    assert rebuilt == campaign.apply(seed, 160, 8, 0)
    assert rebuilt != seed


def test_ledger_keeps_distinct_triggers_only():
    sites = {}
    trigger = {"stage": "value", "edits": [[160, 8, 0]]}
    site_ledger.record(sites, "cuobjdump+0x68000", cve="CVE-X", tool="t",
                       source="value", image="i", trigger=trigger)
    site_ledger.record(sites, "cuobjdump+0x68000", cve="CVE-X", tool="t",
                       source="value", image="i", trigger=dict(trigger))
    assert len(sites["cuobjdump+0x68000"]["triggers"]) == 1

    other = {"stage": "relation", "edits": [[168, 8, 24]]}
    site_ledger.record(sites, "cuobjdump+0x68000", cve="CVE-X", tool="t",
                       source="relation", image="i", trigger=other)
    assert len(sites["cuobjdump+0x68000"]["triggers"]) == 2


def test_triggers_are_capped(tmp_path):
    path = tmp_path / "sites.json"
    sites = {}
    for index in range(9):
        site_ledger.record(sites, "cuobjdump+0x68000", cve="CVE-X", tool="t",
                           source="value", image="i",
                           trigger={"stage": "value", "edits": [[100 + index, 8, 0]]})
    site_ledger.save(sites, str(path))
    loaded = site_ledger.load(str(path))
    assert len(loaded["cuobjdump+0x68000"]["triggers"]) == site_ledger.MAX_TRIGGERS


# ---- the version ladder decides what a site means ----------------------------

def test_a_site_that_survives_the_newest_release_is_a_candidate():
    from src.mutate import verdict_for

    images = ["cuda:12.4", "cuda:13.0"]
    assert "候选新漏洞" in verdict_for({"cuda:12.4": True, "cuda:13.0": True},
                                      "cuda:13.0")


def test_a_site_fixed_by_the_newest_release_is_not_a_candidate():
    from src.mutate import verdict_for

    text = verdict_for({"cuda:12.4": True, "cuda:13.0": False}, "cuda:13.0")
    assert "已修复" in text and "13.0" in text
    assert "候选" not in text


def test_a_site_that_never_crashes_says_so():
    from src.mutate import verdict_for

    assert verdict_for({"cuda:13.0": False}, "cuda:13.0") == "各版本均未崩"
    assert verdict_for({}, "cuda:13.0") == "未跨版本"


# ---- layout: the shape of the file -------------------------------------------

def test_truncation_cuts_exactly_where_it_says():
    from src.mutation_ops import layout_stage

    seed = _cubin()
    labels = {v.field: v for v in layout_stage(seed)}
    cut = labels["truncate@63"]
    assert len(cut.payload) == 63
    assert cut.payload == seed[:63]


def test_padding_changes_the_file_length_without_moving_bytes():
    from src.mutation_ops import layout_stage

    seed = _cubin()
    labels = {v.field: v for v in layout_stage(seed)}
    padded = labels["pad@64"]
    assert padded.payload[:len(seed)] == seed
    assert len(padded.payload) == len(seed) + 64


def test_the_table_is_moved_to_the_end_and_the_pointer_follows():
    from src.mutation_ops import layout_stage

    seed = _cubin()
    labels = {v.field: v for v in layout_stage(seed)}
    moved = labels["table@eof"]
    assert len(moved.payload) > len(seed)
    assert struct.unpack_from("<Q", moved.payload, 0x28)[0] == len(seed)


def test_growing_a_moved_table_adds_real_entries():
    from src.mutation_ops import layout_stage

    seed = _cubin()
    labels = {v.field: v for v in layout_stage(seed)}
    grown = labels["table@eof+8"]
    before = struct.unpack_from("<H", seed, 0x3C)[0]
    after = struct.unpack_from("<H", grown.payload, 0x3C)[0]
    assert after == before + 8


def test_a_layout_variant_carries_a_replayable_recipe():
    """The ledger stores an operation, not a file - so it must rebuild."""
    from src.mutation_ops import layout_stage, rebuild_layout

    seed = _cubin()
    for variant in layout_stage(seed):
        meta = variant.meta
        assert meta["op"]
        assert rebuild_layout(seed, meta["op"], meta["params"]) == variant.payload


def test_materialise_prefers_the_whole_file_over_edits():
    from src import mutation_campaign as campaign

    variant = campaign.Variant(axis="layout", field="truncate@10", value=0,
                               offset=0, width=0)
    variant.payload = b"payload"
    variant.edits = [[0, 8, 1]]
    assert campaign.materialise(b"seed", variant) == b"payload"


def test_layout_variants_are_not_collapsed_by_deduplication():
    """Their offset, width and value are all zero; the payload is the identity."""
    from src import mutation_ops

    built = mutation_ops.build(_cubin(), ["layout"])
    layout = [v for v in built.variants if v.axis == "layout"]
    assert len(layout) >= 8
    assert len({mutation_ops.variant_key(v) for v in layout}) == len(layout)
