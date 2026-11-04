# -*- coding: utf-8 -*-
"""Cross-build function matching.

The property under test is not "matching works" but "matching does not overclaim":
identical bytes may be called identical, displaced bytes may be called relocated,
and equal size must never be a match on its own.
"""

from src import driver_match
from src.driver_match import FunctionFeature


def _feature(rva, size, code, image_base=0):
    import hashlib

    return FunctionFeature(rva=rva, size=size,
                           digest=hashlib.sha1(code).hexdigest(),
                           masked_digest=hashlib.sha1(
                               driver_match.mask_displacements(code)).hexdigest())


def test_identical_bytes_are_paired():
    old = [_feature(0x1000, 8, b"\x48\x89\xd8\xc3\x90\x90\x90\x90")]
    new = [_feature(0x2000, 8, b"\x48\x89\xd8\xc3\x90\x90\x90\x90")]
    result = driver_match.match(old, new)
    assert result.pairs[0].status == "identical"
    assert result.pairs[0].matching_features == ["identical_bytes"]


def test_a_moved_call_target_is_relocated_not_identical():
    """The two bodies differ only in the call displacement."""
    old = [_feature(0x1000, 6, b"\xe8\x11\x22\x33\x44\xc3")]
    new = [_feature(0x3000, 6, b"\xe8\x55\x66\x77\x88\xc3")]
    result = driver_match.match(old, new)
    assert result.pairs[0].status == "relocated"
    assert "masked_bytes" in result.pairs[0].matching_features
    assert result.pairs[0].limitations


def test_rip_relative_displacements_are_masked():
    code = b"\x8b\x05\x11\x22\x33\x44\xc3"
    masked = driver_match.mask_displacements(code)
    assert masked[:2] == b"\x8b\x05"
    assert masked[2:6] == b"\x00\x00\x00\x00"
    assert masked[-1] == 0xC3


def test_equal_size_alone_is_never_a_match():
    old = [_feature(0x1000, 5, b"\x48\x01\xd8\xc3\x90")]
    new = [_feature(0x4000, 5, b"\x48\x29\xd8\xc3\x90")]
    result = driver_match.match(old, new)
    assert result.pairs == []
    assert len(result.unmatched_old) == 1
    assert len(result.unmatched_new) == 1


def test_unmatched_functions_are_reported_not_dropped():
    old = [_feature(0x1000, 4, b"\x90\x90\x90\xc3")]
    result = driver_match.match(old, [])
    assert result.totals["unmatched_old"] == 1
    assert result.totals["pairs"] == 0


def test_candidate_changes_carry_a_limitation():
    old = [_feature(0x1000, 4, b"\x90\x90\x90\xc3")]
    result = driver_match.match(old, [])
    items = driver_match.candidate_changes(result)
    assert items and "limitation" in items[0]
