# -*- coding: utf-8 -*-
"""A control only answers a question if it moves the field that question names."""

from src.control_axes import covers_axis, differing_offsets, mechanism_axes, missing_controls

SPEC = {"mutation": {"axes": [
    {"name": "boundary", "field": "sh_size", "offset": 32, "width": 8, "values": [0, 24]},
    {"name": "mechanism", "field": "sh_type", "offset": 4, "width": 4, "values": [1, 4]},
]}}


def test_differences_are_located():
    assert differing_offsets(b"\x00\x01\x02", b"\x00\x09\x02") == {1}


def test_a_size_mismatch_is_not_a_control():
    assert differing_offsets(b"\x00", b"\x00\x00") == set()


def test_a_control_covering_the_axis_counts():
    differences = {4, 5, 6}
    assert covers_axis(differences, {"offset": 4, "width": 4}) is True


def test_a_control_touching_other_fields_does_not_count():
    """Two changes at once cannot attribute either of them."""
    assert covers_axis({4, 32}, {"offset": 4, "width": 4}) is False


def test_missing_mechanism_control_is_named():
    crafted = bytes(range(64))
    only_boundary = bytearray(crafted)
    only_boundary[32:40] = b"\xff" * 8          # restores sh_size only
    missing = missing_controls(SPEC, {"poc": crafted},
                               {"ctrl_size": bytes(only_boundary)})
    assert missing == ["sh_type"]


def test_a_mechanism_control_satisfies_the_requirement():
    crafted = bytes(range(64))
    retyped = bytearray(crafted)
    retyped[4:8] = b"\x01\x00\x00\x00"          # sh_type RELA -> PROGBITS
    assert missing_controls(SPEC, {"poc": crafted}, {"ctrl_type": bytes(retyped)}) == []


def test_a_spec_without_axes_demands_nothing():
    assert mechanism_axes({}) == []
    assert missing_controls({}, {"poc": b"x"}, {"ctrl": b"y"}) == []
