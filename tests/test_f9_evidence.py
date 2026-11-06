# -*- coding: utf-8 -*-
"""Facts the F9-R1 correction introduced, checked against the archived JSON."""

import json
from pathlib import Path

import pytest

EVIDENCE = Path("data/driver/f9_evidence.json")
OFFSETS = Path("data/driver/f9_offsets.json")

pytestmark = pytest.mark.skipif(not EVIDENCE.is_file(), reason="f9 evidence 未生成")


def _driver() -> dict:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))["driver"]


def test_both_text_sections_are_reported_separately():
    """Two sections share the name .text; taking the last gave 91 bytes."""
    sections = _driver()["text_sections"]
    sizes = [item["vsize"] for item in sections]
    assert sections[0]["index"] == 0
    assert 13820405 in sizes
    assert 91 in sizes
    assert len(sections) == 2


def test_pdata_is_described_as_records_not_functions():
    driver = _driver()
    assert "pdata_records" in driver
    assert "pdata_entries" not in driver


def test_the_image_never_names_the_ddi():
    """Negative evidence: no symbol search can locate the escape callback."""
    scan = _driver()["ddi_name_scan"]
    assert scan["dxgk_ascii"] == 0
    assert scan["dxgk_utf16"] == 0
    assert scan["dxgkrnl_string"] == 1
    assert "dxgkrnl.sys" not in [d.lower() for d in scan["import_dlls"]]


def test_compiler_confirms_the_initialization_offset():
    payload = json.loads(OFFSETS.read_text(encoding="utf-8"))
    assert payload["offset_DxgkDdiEscape"] == "0x00000110"
    assert payload["sizeof_DRIVER_INITIALIZATION_DATA"] == "0x00000608"
    assert payload["negative_control"]["compiled"] is False
    assert "C2338" in payload["negative_control"]["error"]
