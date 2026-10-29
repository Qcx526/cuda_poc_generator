# -*- coding: utf-8 -*-
"""A model proposes; the code applies. Validation is where that separation lives."""

import struct

from src import mutation_campaign as campaign
from src.elf_fields import fields, table
from src.llm_mutation import Proposal, parse_proposals, to_variants, validate


def _elf(sections: int = 2) -> bytes:
    """Minimal ELF64 with a section table of `sections` entries."""
    entsize = 64
    shoff = 64
    data = bytearray(shoff + entsize * sections)
    data[0:4] = b"\x7fELF"
    data[4] = 2
    struct.pack_into("<Q", data, 0x28, shoff)
    struct.pack_into("<H", data, 0x3A, entsize)
    struct.pack_into("<H", data, 0x3C, sections)
    for index in range(sections):
        base = shoff + index * entsize
        struct.pack_into("<I", data, base + 4, 1)     # sh_type
        struct.pack_into("<Q", data, base + 32, 16)   # sh_size
    return bytes(data)


def test_fields_cover_header_and_sections():
    names = [name for name, _, _ in fields(_elf(2))]
    assert "e_shnum" in names and "e_shstrndx" in names
    assert "sec0.sh_size" in names and "sec1.sh_type" in names


def test_a_proposal_against_an_unknown_field_is_rejected():
    accepted, rejected = validate([Proposal("nope", 1)], table(_elf()))
    assert not accepted and rejected[0]["why"] == "unknown field"


def test_a_value_too_wide_for_the_field_is_rejected():
    accepted, rejected = validate([Proposal("e_shnum", 0x1_0000)], table(_elf()))
    assert not accepted and "does not fit" in rejected[0]["why"]


def test_proposing_the_current_value_teaches_nothing():
    accepted, rejected = validate([Proposal("e_shnum", 2)], table(_elf()))
    assert not accepted and rejected[0]["why"] == "value unchanged"


def test_duplicates_collapse_and_the_first_one_survives():
    accepted, rejected = validate(
        [Proposal("e_shnum", 1), Proposal("e_shnum", 1)], table(_elf()))
    assert len(accepted) == 1 and rejected[0]["why"] == "duplicate"


def test_accepted_proposals_become_variants_at_the_right_offset():
    seed = _elf()
    accepted, _ = validate([Proposal("sec1.sh_size", 0xFFFFFFFF)], table(seed))
    variants = to_variants(accepted)
    assert len(variants) == 1
    assert variants[0].offset == 64 + 64 + 32
    assert variants[0].width == 8


def test_the_model_output_is_parsed_leniently():
    payload = {"mutations": [
        {"field": "sec0.sh_size", "value": 0, "reason": "zero length"},
        {"field": "sec0.sh_size", "value": "not a number"},
        {"value": 1},
    ]}
    proposals = parse_proposals(payload)
    assert len(proposals) == 1 and proposals[0].value == 0


# ---- operators: one answer, many mutations -----------------------------------

from src.llm_mutation import Operator, expand, parse_operators  # noqa: E402


def test_scale_expands_over_every_matching_field():
    seed = _elf(3)
    accepted, _ = expand([Operator("scale", "sec*.sh_size", factor=2)],
                         table(seed), len(seed))
    assert len(accepted) == 3
    assert all(item.value == 32 for item in accepted)


def test_set_to_reads_another_field():
    seed = _elf(3)
    accepted, _ = expand([Operator("set_to", "sec0.sh_size", value_from="e_shnum")],
                         table(seed), len(seed))
    assert accepted[0].value == 3


def test_set_to_file_len_needs_no_extra_input():
    seed = _elf(2)
    accepted, _ = expand([Operator("set_to", "sec0.sh_offset", value_from="file_len")],
                         table(seed), len(seed))
    assert accepted[0].value == len(seed)


def test_a_target_matching_nothing_is_reported():
    seed = _elf()
    accepted, rejected = expand([Operator("set", "nope.*", value=1)],
                                table(seed), len(seed))
    assert not accepted and rejected[0]["why"] == "no field matches"


def test_expansion_respects_the_field_width():
    seed = _elf()
    accepted, rejected = expand([Operator("set", "e_shnum", value=0x1_0000)],
                                table(seed), len(seed))
    assert not accepted and "does not fit" in rejected[0]["why"]


def test_one_operator_costs_one_question_not_one_per_field():
    """This is the whole point: 11 sections, one answer."""
    seed = _elf(11)
    accepted, _ = expand([Operator("scale", "sec*.sh_size", factor=2)],
                         table(seed), len(seed))
    assert len(accepted) == 11


def test_operator_output_is_parsed_leniently():
    """An entry without a target is kept, then refused with a reason.

    Dropping it during parsing would hide the model's malformed answer; keeping it
    means the rejection shows up in the run's rejected list, which is the number
    the experiment reports.
    """
    payload = {"operators": [
        {"op": "set", "target": "e_*", "value": 0, "reason": "zero the header"},
        {"op": "set"},
        {"nonsense": True},
    ]}
    operators = parse_operators(payload)
    assert len(operators) == 2
    assert operators[0].target == "e_*" and operators[1].target == ""
    variants, rejected = expand([operators[1]], table(_elf()), 128)
    assert not variants and rejected[0]["why"] == "no field matches"


# ---- tuple: several fields in one artifact -----------------------------------

def test_a_tuple_aligns_fields_by_section():
    """Both fields of section 0, then both of section 1 - not a cross product."""
    seed = _elf(3)
    variants, rejected = expand([Operator(
        "tuple", assign={"sec*.sh_offset": "file_len", "sec*.sh_size": 32})],
        table(seed), len(seed))
    assert len(variants) == 3 and not rejected
    assert all(len(variant.edits) == 2 for variant in variants)
    first = variants[0].edits
    assert first[0][0] == 64 + 0 * 64 + 24     # sec0.sh_offset
    assert first[1][0] == 64 + 0 * 64 + 32     # sec0.sh_size


def test_a_tuple_with_no_change_is_refused():
    seed = _elf(2)
    variants, rejected = expand([Operator(
        "tuple", assign={"sec0.sh_size": 16, "sec0.sh_type": 1})],
        table(seed), len(seed))
    assert not variants
    assert "equals the current one" in rejected[0]["why"]


def test_a_tuple_naming_an_unknown_field_is_refused():
    seed = _elf()
    variants, rejected = expand([Operator(
        "tuple", assign={"sec0.sh_nope": 1, "sec0.sh_size": 0})],
        table(seed), len(seed))
    assert not variants and "unknown field" in rejected[0]["why"]


def test_an_empty_tuple_is_refused():
    variants, rejected = expand([Operator("tuple", assign={})], table(_elf()), 128)
    assert not variants and rejected[0]["why"] == "empty assign"


# ---- refusals feed back into the next round ----------------------------------

def test_a_refusal_carries_the_tool_message(tmp_path):
    from src.llm_mutation import refusals

    variant = campaign.Variant(axis="tuple", field="sec0.sh_offset", value=0,
                               offset=0, width=8, exit_code=255)
    variant.path = str(tmp_path / "x.cubin")
    (tmp_path / ".err.x.cubin").write_text("Error: section 0: invalid sh_offset\n",
                                           encoding="utf-8")
    items = refusals([variant], tmp_path)
    assert len(items) == 1
    assert items[0]["error"].startswith("Error: section 0")
    assert items[0]["exit"] == 255


def test_a_crash_is_not_a_refusal(tmp_path):
    """A crash is the result being sought; sending it back would ask the model to
    undo its one success."""
    from src.llm_mutation import refusals

    variant = campaign.Variant(axis="tuple", field="sec0.sh_size", value=0,
                               offset=0, width=8, exit_code=139,
                               fingerprint="cuobjdump+0x68000")
    variant.path = str(tmp_path / "y.cubin")
    assert refusals([variant], tmp_path) == []


def test_parsed_files_are_not_refusals(tmp_path):
    from src.llm_mutation import refusals

    variant = campaign.Variant(axis="set", field="sec0.sh_size", value=1,
                               offset=0, width=8, exit_code=0)
    variant.path = str(tmp_path / "z.cubin")
    assert refusals([variant], tmp_path) == []


def test_the_feedback_states_what_was_refused_and_why():
    from src.llm_mutation import build_feedback

    text = build_feedback([Operator("tuple", assign={"sec0.sh_size": 0})],
                          [{"fields": "sec0.sh_size", "exit": 255,
                            "error": "invalid sh_offset"}], parsed=1, crashed=0)
    assert "invalid sh_offset" in text
    assert "1 parsed" in text and "1 refused" in text


def test_escalation_asks_for_different_fields_not_smaller_values():
    """Once everything parses, shrinking further proves even less."""
    from src.llm_mutation import build_escalation

    text = build_escalation([Operator("tuple", assign={"sec0.sh_size": 1})], parsed=4)
    assert "parsed cleanly and none crashed" in text
    assert "Change which fields you touch" in text
    assert "sh_link" in text
