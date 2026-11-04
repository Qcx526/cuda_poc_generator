# -*- coding: utf-8 -*-
"""Structural labels.

Three samples with known semantics, built from instruction bytes rather than
from a modified driver: a pure relocation, a real control-flow change, and a
call whose target moved while the callee stayed equivalent.
"""

from src import driver_structdiff as sd


def test_a_relocated_function_is_not_a_structural_change():
    """Same instructions, different addresses: the shape sequence is identical."""
    old = sd.analyze(b"\x48\x89\xd8\x75\x02\x31\xc0\xc3", 0x1000)
    new = sd.analyze(b"\x48\x89\xd8\x75\x02\x31\xc0\xc3", 0x9000)
    label, _ = sd.compare(old, new)
    assert label == sd.RELOCATION_ONLY


def test_a_changed_conditional_is_a_structural_change():
    """je becomes jne: same length, different control flow."""
    old = sd.analyze(b"\x48\x85\xc0\x74\x02\x31\xc0\xc3", 0x1000)
    new = sd.analyze(b"\x48\x85\xc0\x75\x02\x31\xc0\xc3", 0x1000)
    label, evidence = sd.compare(old, new)
    assert label == sd.STRUCTURAL_CHANGE
    assert evidence


def test_a_moved_call_target_with_a_mapped_callee_is_not_a_call_change():
    """The callee moved; the caller still calls the same function."""
    old = sd.analyze(b"\xe8\x00\x10\x00\x00\xc3", 0x1000)      # call 0x2005
    new = sd.analyze(b"\xe8\x00\x20\x00\x00\xc3", 0x1000)      # call 0x3005
    assert old.direct_calls and new.direct_calls
    mapping = {old.direct_calls[0]: new.direct_calls[0]}
    label, evidence = sd.compare(old, new, mapping)
    assert label == sd.RELOCATION_ONLY, evidence


def test_an_unmapped_call_target_is_a_call_graph_change():
    old = sd.analyze(b"\xe8\x00\x10\x00\x00\xc3", 0x1000)
    new = sd.analyze(b"\xe8\x00\x20\x00\x00\xc3\x90\x90\xc3", 0x1000)
    label, evidence = sd.compare(old, new, {})
    assert label in (sd.CALL_GRAPH_CHANGE, sd.STRUCTURAL_CHANGE)
    assert evidence


def test_a_size_blowup_is_uncertain_not_structural():
    """A function can keep its RVA while being split; that is not a finding."""
    old = sd.analyze(b"\x48\x89\xd8\xc3", 0x1000)
    new = sd.analyze(b"\x48\x89\xd8\x90\x90\x90\x90\x90\x90\xc3", 0x1000)
    label, evidence = sd.classify(old, new, 4, 11)
    assert label == sd.MATCH_UNCERTAIN
    assert "尺寸比例异常" in evidence[0]


def test_undecodable_bytes_are_not_silently_compared():
    structure = sd.analyze(b"\xff\xff\xff\xff\xff", 0x1000)
    assert structure.undecodable is True
    label, _ = sd.compare(structure, structure)
    assert label == sd.MATCH_UNCERTAIN


def test_immediates_are_kept_but_only_registers_change_the_shape():
    """A different constant is a different program, not a relocation."""
    a = sd.analyze(b"\xb8\x01\x00\x00\x00\xc3", 0x1000)       # mov eax, 1
    b = sd.analyze(b"\xb8\x02\x00\x00\x00\xc3", 0x1000)       # mov eax, 2
    assert a.shape_digest != b.shape_digest
    assert a.reloc_digest == b.reloc_digest
    label, _ = sd.compare(a, b)
    assert label == sd.CONSTANT_CHANGE
    c = sd.analyze(b"\xb9\x01\x00\x00\x00\xc3", 0x1000)       # mov ecx, 1
    assert c.shape_digest != a.shape_digest


def test_a_changed_comparison_constant_is_a_constant_change():
    """cmp eax,1 vs cmp eax,0 changes behaviour while keeping the CFG identical."""
    old = sd.analyze(b"\x83\xf8\x01\x74\x02\x31\xc0\xc3", 0x1000)
    new = sd.analyze(b"\x83\xf8\x00\x74\x02\x31\xc0\xc3", 0x1000)
    label, evidence = sd.compare(old, new)
    assert label == sd.CONSTANT_CHANGE, evidence


def test_a_changed_struct_offset_is_not_a_relocation():
    old = sd.analyze(b"\x8b\x41\x10\xc3", 0x1000)   # mov eax,[rcx+0x10]
    new = sd.analyze(b"\x8b\x41\x20\xc3", 0x1000)   # mov eax,[rcx+0x20]
    label, _ = sd.compare(old, new)
    assert label == sd.CONSTANT_CHANGE


def test_the_same_struct_offset_across_builds_stays_a_relocation():
    old = sd.analyze(b"\x8b\x41\x10\xc3", 0x1000)
    new = sd.analyze(b"\x8b\x41\x10\xc3", 0x9000)
    label, _ = sd.compare(old, new)
    assert label == sd.RELOCATION_ONLY


def test_a_pdata_fragment_is_uncertain_not_changed():
    """0x303b80 in the real driver: .pdata covers 100 bytes, Ghidra body 441."""
    old = sd.analyze(b"\x90" * 100, 0x1000)
    new = sd.analyze(b"\x90" * 144, 0x1000)
    label, evidence = sd.classify(old, new, 100, 144, old_body=441, new_body=441)
    assert label == sd.MATCH_UNCERTAIN
    assert "Ghidra" in evidence[0]
