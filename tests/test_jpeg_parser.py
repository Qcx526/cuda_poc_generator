# -*- coding: utf-8 -*-
"""Parser contract tests.

Two kinds of input here, and both are labelled: real files from Pillow's encoder, and
minimal byte streams built by hand to isolate one rule at a time. The hand-built ones
are deliberately not decodable images - they test the walker, not the codec.
"""

import io

import pytest
from PIL import Image

from src.jpeg_adapter import AdapterError, apply_plan, build_control, build_baseline
from src.jpeg_parser import ParserError, parse, summary


def minimal(entropy: bytes, sof_marker: int = 0xC0, dri: int = 0,
            extra: bytes = b"") -> bytes:
    """A structurally valid stream with one component and caller-supplied entropy."""
    sof = struct_sof(sof_marker)
    out = b"\xff\xd8" + extra + sof
    if dri:
        out += b"\xff\xdd\x00\x04" + dri.to_bytes(2, "big")
    out += b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + entropy + b"\xff\xd9"
    return out


def struct_sof(marker: int) -> bytes:
    payload = bytes([8, 0, 8, 0, 8, 1, 1, 0x11, 0])
    return b"\xff" + bytes([marker]) + (len(payload) + 2).to_bytes(2, "big") + payload


def progressive_bytes() -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (32, 32), (9, 8, 7)).save(buffer, format="JPEG", progressive=True)
    return buffer.getvalue()


def test_baseline_single_scan():
    structure = parse(build_baseline(32, 32))
    assert len(structure.sos_positions) == 1
    assert structure.sof["marker"] == 0xC0
    assert structure.dri_count == 0


def test_progressive_is_recognised_as_multiple_scans():
    data = progressive_bytes()
    structure = parse(data, strict=False)
    assert structure.sof["marker"] == 0xC2
    assert len(structure.sos_positions) > 1, "a real progressive file has more than one scan"


def test_multiscan_is_refused_by_adapter():
    with pytest.raises(AdapterError):
        apply_plan(progressive_bytes(), {"operations": [{"op": "set_dri", "interval": 0}]})


def test_ff00_is_stuffing_not_a_marker():
    data = minimal(b"\x12\x34\xff\x00\x56")
    structure = parse(data)
    assert structure.entropy_bytes == 5
    assert len(structure.sos_positions) == 1


def test_restart_markers_stay_inside_the_scan():
    data = minimal(b"\x11\xff\xd0\x22\xff\xd7\x33")
    structure = parse(data)
    assert len(structure.sos_positions) == 1
    assert structure.names()[-1] == "EOI"


def test_illegal_segment_length_is_refused():
    broken = build_baseline(16, 16).replace(b"\xff\xdb\x00\x43", b"\xff\xdb\x00\x01", 1)
    with pytest.raises(ParserError):
        parse(broken)


def test_truncated_file_is_refused():
    data = build_baseline(32, 32)
    with pytest.raises(ParserError):
        parse(data[: len(data) // 2])


def test_duplicate_dri_baseline_is_refused():
    data = minimal(b"\x01", dri=8)
    once = data
    twice = data.replace(b"\xff\xdd\x00\x04\x00\x08",
                         b"\xff\xdd\x00\x04\x00\x08\xff\xdd\x00\x04\x00\x10", 1)
    assert parse(once).dri_count == 1
    assert parse(twice).dri_count == 2
    with pytest.raises(AdapterError):
        apply_plan(twice, {"operations": [{"op": "set_dri", "interval": 0}]})


def test_unknown_marker_is_refused():
    data = minimal(b"\x01", extra=b"\xff\x02\x00\x02")
    with pytest.raises(ParserError):
        parse(data)


def test_app_and_com_pass_through():
    data = minimal(b"\x01", extra=b"\xff\xe5\x00\x04ab\xff\xfe\x00\x03c")
    structure = parse(data)
    names = structure.names()
    assert "APP5" in names and "COM" in names
    plan = {"operations": [{"op": "set_dri", "interval": 0}]}
    crafted, _ = apply_plan(data, plan)
    control, _ = build_control(data, plan)
    assert control == data
    assert crafted != data


def test_arithmetic_coding_is_refused():
    with pytest.raises(ParserError):
        parse(minimal(b"\x01", sof_marker=0xC9))


def test_multi_operation_journal_restores_baseline():
    baseline = build_baseline(32, 32)
    plan = {"operations": [
        {"op": "set_sof_size", "width": 24, "height": 12},
        {"op": "set_component_sampling", "component": 2, "h": 2, "v": 2},
        {"op": "insert_segment", "marker": 0xEE, "hex": "0102"},
        {"op": "set_dri", "interval": 3},
    ]}
    crafted, journal = apply_plan(baseline, plan)
    control, _ = build_control(baseline, plan)
    assert control == baseline
    assert len(journal) == 4
    assert crafted != baseline


def test_summary_never_raises():
    assert summary(b"not a jpeg")["valid"] is False
    assert summary(progressive_bytes())["sos_count"] > 1
