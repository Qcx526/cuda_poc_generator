# -*- coding: utf-8 -*-
"""A model proposes; the code applies. Validation is where that separation lives."""

import struct

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
