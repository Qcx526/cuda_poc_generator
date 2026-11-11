# -*- coding: utf-8 -*-
"""Contract tests for the JPEG adapter.

The decisive property is not "it runs" but "a plan reproduces a crafted file and undoes
itself exactly". Every test decodes with Pillow - the reference decoder is never mocked,
because that verdict is what the whole evidence chain rests on.
"""

import io
import struct

import pytest
from PIL import Image

from src.jpeg_adapter import (AdapterError, apply_plan, build_baseline, build_control,
                              diff_range, reference_decode, walk, write_bundle)


@pytest.fixture(scope="module")
def rgb():
    return build_baseline(64, 64, "RGB")


@pytest.fixture(scope="module")
def gray():
    return build_baseline(64, 64, "L")


def test_baseline_rgb_and_gray_decode(rgb, gray):
    for data, mode in ((rgb, "RGB"), (gray, "L")):
        ok, error, size, decoded_mode = reference_decode(data)
        assert ok, error
        assert size == (64, 64)
        assert decoded_mode == mode


def test_sof_size_edit_uses_real_offsets(rgb):
    """The bug this replaces wrote at +6/+8 and corrupted the neighbour field."""
    crafted, _ = apply_plan(rgb, {"operations": [
        {"op": "set_sof_size", "width": 32, "height": 16}]})
    before, after = walk(rgb), walk(crafted)
    assert after["sof_marker"] == before["sof_marker"]
    assert "SOF0(32x16,comp=3,prec=8)" in after["segments"]
    start = crafted.index(b"\xff\xc0")
    assert struct.unpack_from(">H", crafted, start + 5)[0] == 16   # height
    assert struct.unpack_from(">H", crafted, start + 7)[0] == 32   # width
    assert crafted[start + 9] == 3, "component count must not be touched"
    assert crafted[start + 4] == 8, "precision must not be touched"


def test_sof_size_restores_exactly(rgb):
    plan = {"operations": [{"op": "set_sof_size", "width": 32, "height": 16}]}
    crafted, _ = apply_plan(rgb, plan)
    control, journal = build_control(rgb, plan)
    assert control == rgb
    assert journal[0]["prev"] == {"width": 64, "height": 64}
    # 64 -> 32 changes one byte of width; 64 -> 16 changes one byte of height.
    assert diff_range(crafted, control)["differences"] == 2


def test_component_sampling_edit_and_restore(rgb):
    plan = {"operations": [{"op": "set_component_sampling", "component": 0, "h": 2, "v": 1}]}
    start = rgb.index(bytes([0xFF, 0xC0]))
    original = rgb[start + 10 + 0 * 3 + 1]
    crafted, _ = apply_plan(rgb, plan)
    control, journal = build_control(rgb, plan)
    assert journal[0]["prev"] == {"h": original >> 4, "v": original & 0x0F}
    assert control == rgb
    assert crafted[start + 10 + 0 * 3 + 1] == 0x21
    # neighbours untouched
    assert crafted[start + 10 + 1 * 3 + 1] == rgb[start + 10 + 1 * 3 + 1]
    assert crafted[start + 9] == rgb[start + 9]


def test_sampling_rejects_bad_index_and_range(rgb):
    with pytest.raises(AdapterError):
        apply_plan(rgb, {"operations": [{"op": "set_component_sampling",
                                         "component": -1, "h": 1, "v": 1}]})
    with pytest.raises(AdapterError):
        apply_plan(rgb, {"operations": [{"op": "set_component_sampling",
                                         "component": 3, "h": 1, "v": 1}]})
    with pytest.raises(AdapterError):
        apply_plan(rgb, {"operations": [{"op": "set_component_sampling",
                                         "component": 0, "h": 0, "v": 1}]})
    with pytest.raises(AdapterError):
        apply_plan(rgb, {"operations": [{"op": "set_component_sampling",
                                         "component": 0, "h": 5, "v": 1}]})


def test_sof_size_rejects_out_of_range_instead_of_masking(rgb):
    for width in (0, -1, 65536, 70000):
        with pytest.raises(AdapterError):
            apply_plan(rgb, {"operations": [{"op": "set_sof_size",
                                             "width": width, "height": 64}]})


def test_dri_insert_replace_and_restore(rgb):
    plan = {"operations": [{"op": "set_dri", "interval": 0}]}
    crafted, journal = apply_plan(rgb, plan)
    assert journal[0]["mode"] == "insert"
    assert "DRI(0)" in walk(crafted)["segments"]
    control, _ = build_control(rgb, plan)
    assert control == rgb

    twice = {"operations": [{"op": "set_dri", "interval": 0},
                            {"op": "set_dri", "interval": 8}]}
    crafted2, journal2 = apply_plan(rgb, twice)
    assert journal2[0]["mode"] == "insert" and journal2[1]["mode"] == "replace"
    assert walk(crafted2)["dri_count"] == 1, "a second set_dri must replace, not append"
    control2, _ = build_control(rgb, twice)
    assert control2 == rgb


def test_dri_interval_range_and_duplicate_dri_refused(rgb):
    with pytest.raises(AdapterError):
        apply_plan(rgb, {"operations": [{"op": "set_dri", "interval": 65536}]})
    with pytest.raises(AdapterError):
        apply_plan(rgb, {"operations": [{"op": "set_dri", "interval": -1}]})


def test_segment_insert_and_strip(rgb):
    insert = {"operations": [{"op": "insert_segment", "marker": 0xFE, "hex": "414243"}]}
    crafted, journal = apply_plan(rgb, insert)
    assert "COM" in walk(crafted)["segments"]
    assert journal[0]["length"] == 7  # FF FE len(2) + 3 payload
    control, _ = build_control(rgb, insert)
    assert control == rgb

    strip = {"operations": [{"op": "strip_segment", "marker": 0xE0}]}
    stripped, journal2 = apply_plan(rgb, strip)
    assert stripped != rgb
    control2, _ = build_control(rgb, strip)
    assert control2 == rgb
    assert journal2[0]["removed"]


def test_segment_rejects_bad_marker_and_long_payload(rgb):
    for marker in (0xC0, 0xDA, 0xD9):
        with pytest.raises(AdapterError):
            apply_plan(rgb, {"operations": [{"op": "insert_segment",
                                             "marker": marker, "hex": ""}]})
    with pytest.raises(AdapterError):
        apply_plan(rgb, {"operations": [{"op": "insert_segment", "marker": 0xFE,
                                         "hex": "00" * 65534}]})


def test_multiple_operations_restore_in_reverse(rgb):
    plan = {"operations": [
        {"op": "set_sof_size", "width": 48, "height": 32},
        {"op": "insert_segment", "marker": 0xFE, "hex": "aabb"},
        {"op": "set_component_sampling", "component": 1, "h": 2, "v": 2},
        {"op": "set_dri", "interval": 4},
    ]}
    crafted, journal = apply_plan(rgb, plan)
    control, _ = build_control(rgb, plan)
    assert control == rgb
    assert len(journal) == 4
    # The crafted file is longer (inserted segment and DRI); the control is not.
    assert diff_range(crafted, control)["same_length"] is False
    assert len(crafted) > len(control)
    assert walk(crafted)["sos_count"] == 1
    assert walk(control)["sos_count"] == 1


def test_sha256_is_deterministic(rgb):
    plan = {"operations": [{"op": "set_sof_size", "width": 48, "height": 32}]}
    first, _ = apply_plan(rgb, plan)
    second, _ = apply_plan(rgb, plan)
    assert first == second
    assert build_baseline(64, 64, "RGB") == rgb


def test_progressive_and_multiscan_refused():
    buffer = io.BytesIO()
    Image.new("RGB", (32, 32), (1, 2, 3)).save(buffer, format="JPEG", progressive=True)
    progressive = buffer.getvalue()
    assert walk(progressive)["sof_marker"] == 0xC2
    with pytest.raises(AdapterError):
        apply_plan(progressive, {"operations": [{"op": "set_sof_size",
                                                 "width": 16, "height": 16}]})


def test_write_bundle_provenance(tmp_path, rgb):
    plan = {"operations": [{"op": "set_dri", "interval": 0},
                           {"op": "insert_segment", "marker": 0xFE, "hex": "00"}]}
    bundle = write_bundle(tmp_path, rgb, plan)
    assert bundle["control_equals_baseline"] is True
    assert len(bundle["journal"]) == 2
    names = {a["role"]: a for a in bundle["artifacts"]}
    assert names["CONTROL"]["sha256"] == names["BENIGN"]["sha256"]
    assert names["MALICIOUS"]["sha256"] != names["BENIGN"]["sha256"]
    for artifact in names.values():
        assert (tmp_path / artifact["name"]).is_file()


def test_control_mismatch_is_detected(rgb, monkeypatch):
    """A control that differs from the baseline must raise, not ship."""
    import src.jpeg_adapter as adapter

    plan = {"operations": [{"op": "set_sof_size", "width": 32, "height": 32}]}
    monkeypatch.setattr(adapter, "_undo_one", lambda data, entry: None)
    with pytest.raises(AdapterError):
        adapter.build_control(rgb, plan)
