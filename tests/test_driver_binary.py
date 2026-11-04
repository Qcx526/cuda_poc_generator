# -*- coding: utf-8 -*-
"""Static index and context builder.

The driver binary is 120 MB and not in the repository, so the tests that need it
skip when it is absent; the parsing logic itself is exercised against a synthetic
PE built here, so the suite stays runnable on any machine.
"""

import struct
from pathlib import Path

import pytest

from src import driver_context
from src.driver_binary import PEImage, facts_of

DRIVER = Path(r"C:\Windows\System32\DriverStore\FileRepository"
              r"\nv_dispi.inf_amd64_c8bc842500fab35b\nvlddmkm.sys")


def _build_pe(tmp_path: Path) -> Path:
    """A minimal PE32+ with one section, one import and two RUNTIME_FUNCTIONs."""
    data = bytearray(0x400)
    # DOS header -> PE offset
    struct.pack_into("<I", data, 0x3C, 0x80)
    struct.pack_into("<I", data, 0x80, 0x00004550)          # PE\0\0
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B)                # PE32+
    struct.pack_into("<Q", data, opt + 24, 0x140000000)     # ImageBase
    # data directories: import at index 1, exception at index 3
    dirs = opt + 112
    struct.pack_into("<II", data, dirs + 1 * 8, 0x1100, 0x28)
    struct.pack_into("<II", data, dirs + 3 * 8, 0x1080, 24)
    # section table
    sec = opt + 0xF0
    data[sec:sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", data, sec + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, sec + 36, 0x60000020)      # code | execute
    # two functions: 0x1000..0x1050 and 0x1050..0x10a0
    struct.pack_into("<III", data, 0x280, 0x1000, 0x1050, 0)
    struct.pack_into("<III", data, 0x28C, 0x1050, 0x10A0, 0)
    # import descriptor -> name at 0x1180
    struct.pack_into("<IIIII", data, 0x300, 0, 0, 0, 0x1180, 0)
    data[0x380:0x380 + 10] = b"ntoskrnl\x00\x00"
    path = tmp_path / "sample.sys"
    path.write_bytes(bytes(data))
    return path


def test_functions_come_from_the_exception_directory(tmp_path):
    facts = facts_of(_build_pe(tmp_path))
    assert len(facts.functions) == 2
    assert facts.functions[0].rva == 0x1000
    assert facts.functions[1].size == 0x50


def test_lookup_accepts_both_rva_and_virtual_address(tmp_path):
    """Mixing the two is the silent failure this method exists to prevent."""
    facts = facts_of(_build_pe(tmp_path))
    by_rva = facts.function_at(0x1010)
    by_va = facts.function_at(0x140001010)
    assert by_rva is not None and by_va is not None
    assert by_rva.rva == by_va.rva == 0x1000


def test_an_address_between_functions_is_not_attributed(tmp_path):
    facts = facts_of(_build_pe(tmp_path))
    assert facts.function_at(0x2000) is None


def test_imports_and_identity_are_recorded(tmp_path):
    facts = facts_of(_build_pe(tmp_path))
    assert "ntoskrnl" in facts.imports
    assert len(facts.sha256) == 64
    assert facts.image_base == 0x140000000


def test_summary_is_machine_readable(tmp_path):
    summary = facts_of(_build_pe(tmp_path)).summary()
    assert summary["functions"] == 2
    assert summary["provenance"].startswith("pe_headers")


def test_strings_are_reported_with_their_address(tmp_path):
    path = _build_pe(tmp_path)
    image = PEImage(path)
    found = {item["text"]: item["rva"] for item in image.strings(minimum=6)}
    assert "ntoskrnl" in found


@pytest.mark.skipif(not DRIVER.is_file(), reason="driver image not present")
def test_the_real_driver_indexes_without_analysis():
    facts = facts_of(DRIVER)
    assert len(facts.functions) > 70000
    target = facts.function_at(0x1406912f0)
    assert target is not None and target.section == ".text"
    assert facts.pdb.get("path", "").endswith("nvlddmkm.pdb")


def test_context_labels_every_source():
    text = driver_context.build_context(
        {"path": "x", "sha256": "y", "functions": 2, "imports": ["ntoskrnl.exe"]},
        {"rva": "6912f0", "name": "FUN_1406912f0", "size": 4654, "instructions": 900,
         "callers": ["a@1"], "callees": [], "string_refs": [], "decompiled": "int f(){return 0;}"},
        cve="CVE-2026-47571", hypothesis="授权分支在 ctx 归属检查")
    assert "pe_headers" in text
    assert "ghidra_decompiler" in text
    assert "analyst_hypothesis" in text
    assert "UNKNOWN" not in text or "缺失" in text


def test_context_survives_a_missing_function():
    text = driver_context.build_context({"path": "x"}, None, cve="CVE-1")
    assert "pe_headers" in text
    assert "CVE-1" in text


SAMPLE = Path("data/driver/ghidra/smoke_exe/function_1c3c.json")


@pytest.mark.skipif(not SAMPLE.is_file(), reason="no exported sample yet")
def test_exported_facts_have_a_stable_shape():
    """The Python side reads this file; its keys are the contract."""
    import json

    facts = json.loads(SAMPLE.read_text(encoding="utf-8"))
    for key in ("rva", "name", "size", "instructions", "callers", "callees",
                "string_refs", "decompiled", "provenance"):
        assert key in facts
    assert facts["provenance"] == "ghidra_decompiler"
    assert isinstance(facts["callers"], list)
    assert facts["instructions"] > 0


@pytest.mark.skipif(not SAMPLE.is_file(), reason="no exported sample yet")
def test_rva_is_relative_to_the_image_base():
    """A VA here would silently miss the .pdata index, which is RVA based."""
    import json

    facts = json.loads(SAMPLE.read_text(encoding="utf-8"))
    assert int(facts["rva"], 16) < 0x140000000


@pytest.mark.skipif(not SAMPLE.is_file(), reason="no exported sample yet")
def test_context_consumes_exported_facts():
    import json

    facts = json.loads(SAMPLE.read_text(encoding="utf-8"))
    text = driver_context.build_context({"path": "x", "sha256": "y"}, facts, cve="CVE-2026-47571")
    assert "ghidra_decompiler" in text
    assert "反编译" in text


SAMPLE = Path("data/driver/ghidra/smoke_exe/function_1c3c.json")


@pytest.mark.skipif(not SAMPLE.is_file(), reason="no exported sample yet")
def test_exported_facts_have_a_stable_shape():
    """The Python side reads this file; its keys are the contract."""
    import json

    facts = json.loads(SAMPLE.read_text(encoding="utf-8"))
    for key in ("rva", "name", "size", "instructions", "callers", "callees",
                "string_refs", "decompiled", "provenance"):
        assert key in facts
    assert facts["provenance"] == "ghidra_decompiler"
    assert isinstance(facts["callers"], list)
    assert facts["instructions"] > 0


@pytest.mark.skipif(not SAMPLE.is_file(), reason="no exported sample yet")
def test_rva_is_relative_to_the_image_base():
    """A VA here would silently miss the .pdata index, which is RVA based."""
    import json

    facts = json.loads(SAMPLE.read_text(encoding="utf-8"))
    assert int(facts["rva"], 16) < 0x140000000


@pytest.mark.skipif(not SAMPLE.is_file(), reason="no exported sample yet")
def test_context_consumes_exported_facts():
    import json

    facts = json.loads(SAMPLE.read_text(encoding="utf-8"))
    text = driver_context.build_context({"path": "x", "sha256": "y"}, facts, cve="CVE-2026-47571")
    assert "ghidra_decompiler" in text
    assert "反编译" in text
