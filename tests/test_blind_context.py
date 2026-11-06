# -*- coding: utf-8 -*-
"""Blind projection of the seven-dimension bundle.

The earlier fix filtered spec.json only; the pipeline still handed the raw bundle to
the expert, and `7_root_cause.json` carries the faulting address and the exact
alignment formula. These tests use the real input files, not fixtures.
"""

import json
from pathlib import Path

import pytest

from src import blind_context as bc

INPUTS = Path("data/inputs/CVE-2025-23340")
pytestmark = pytest.mark.skipif(not INPUTS.is_dir(), reason="inputs not on disk")


def _dimensions() -> dict:
    merged = {}
    for name, key in (("affected_component", "3_affected_component"),
                      ("cuda_environment", "2_cuda_environment"),
                      ("attack_surface", "4_attack_surface"),
                      ("vulnerability_type", "5_vulnerability_type")):
        path = INPUTS / (key + ".json")
        if path.is_file():
            merged[name] = json.loads(path.read_text(encoding="utf-8"))
    merged["root_cause"] = json.loads((INPUTS / "7_root_cause.json").read_text(encoding="utf-8"))
    return merged


def test_the_raw_bundle_really_does_contain_the_answer():
    """Guard the guard: if the input stops carrying a formula, this test tells us."""
    raw = json.dumps(_dimensions(), ensure_ascii=False)
    assert "0x45" in raw or "root_cause" in raw


def test_projection_removes_root_cause_addresses_and_formulas():
    projected = json.dumps(bc.project(_dimensions()), ensure_ascii=False)
    assert "root_cause" not in projected
    assert not bc.audit(projected), bc.audit(projected)
    assert "0x45" not in projected


def test_projection_keeps_the_target_identifiable():
    projected = bc.project(_dimensions())
    text = json.dumps(projected, ensure_ascii=False)
    assert projected["cve_id"] == "CVE-2025-23340"
    assert "nvdisasm" in text or "entry_point" in text
    assert projected["affected_component"]["version_range"]


def test_internal_fields_are_not_projected():
    projected = bc.project(_dimensions())
    flat = json.dumps(projected, ensure_ascii=False)
    for term in ("vulnerable_function", "tool_path", "trigger_command",
                 "controllable_fields", "exploitation_difficulty"):
        assert term not in flat


def test_audit_flags_an_address_when_one_slips_through():
    assert "address-like" in bc.audit("at 0x45ada0 the parser reads")
    assert bc.audit("nvdisasm SHT_RELA handler") == []
