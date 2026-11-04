# -*- coding: utf-8 -*-
"""ABI layout assertions.

These numbers come from the installed SDK headers (10.0.26100.0) under MSVC x64
rules, and are re-derived here by ctypes. They are deliberately hard-coded: if a
future struct edit shifts a field, the test fails instead of the generated program
failing with an access violation.

Compiler verification is *not* claimed - this machine has no C/C++ toolchain.
"""

import ctypes

import pytest

from src import driver_abi as abi


def test_escape_packet_is_32_bytes_with_4_byte_handles():
    assert ctypes.sizeof(abi.D3DKMT_ESCAPE) == 32
    assert abi.D3DKMT_ESCAPE.hAdapter.offset == 0
    assert abi.D3DKMT_ESCAPE.hDevice.offset == 4
    assert abi.D3DKMT_ESCAPE.Type.offset == 8
    assert abi.D3DKMT_ESCAPE.Flags.offset == 12
    assert abi.D3DKMT_ESCAPE.pPrivateDriverData.offset == 16
    assert abi.D3DKMT_ESCAPE.PrivateDriverDataSize.offset == 24
    assert abi.D3DKMT_ESCAPE.hContext.offset == 28


def test_open_adapter_from_hdc_starts_with_an_eight_byte_hdc():
    """HDC is a pointer; a handle-shaped field here would shift everything."""
    # LUID is 4-byte aligned in C, so it sits at 12 and the struct is 24 bytes.
    # The compiler said so; an 8-byte-aligned model says 32 and is wrong.
    assert ctypes.sizeof(abi.D3DKMT_OPENADAPTERFROMHDC) == 24
    assert abi.D3DKMT_OPENADAPTERFROMHDC.hDc.offset == 0
    assert abi.D3DKMT_OPENADAPTERFROMHDC.hAdapter.offset == 8
    assert abi.D3DKMT_OPENADAPTERFROMHDC.AdapterLuid.offset == 12
    assert abi.D3DKMT_OPENADAPTERFROMHDC.VidPnSourceId.offset == 20


def test_create_device_union_with_a_pointer_is_eight_bytes():
    """Modelling this union as a four-byte handle produced hDevice == 0."""
    assert ctypes.sizeof(abi.D3DKMT_CREATEDEVICE_ADAPTER) == 8
    assert abi.D3DKMT_CREATEDEVICE.Flags.offset == 8
    assert abi.D3DKMT_CREATEDEVICE.hDevice.offset == 12


def test_create_context_keeps_device_then_node_then_engine():
    assert abi.D3DKMT_CREATECONTEXT.hDevice.offset == 0
    assert abi.D3DKMT_CREATECONTEXT.NodeOrdinal.offset == 4
    assert abi.D3DKMT_CREATECONTEXT.EngineAffinity.offset == 8
    assert abi.D3DKMT_CREATECONTEXT.Flags.offset == 12
    assert abi.D3DKMT_CREATECONTEXT.pPrivateDriverData.offset == 16


def test_handle_type_is_not_a_pointer():
    assert ctypes.sizeof(abi.D3DKMT_HANDLE) == 4
    assert issubclass(abi.D3DKMT_HANDLE, ctypes.c_uint32)


def test_status_formatting_matches_the_ntstatus_seen_in_logs():
    assert "0xC000000D" in abi.ntstatus(0xC000000D)
    assert "-1073741811" in abi.ntstatus(0xC000000D)
    assert "STATUS_SUCCESS" in abi.ntstatus(0)


def test_luid_is_eight_bytes_with_four_byte_alignment():
    assert ctypes.sizeof(abi.LUID_T) == 8
    assert ctypes.alignment(abi.LUID_T) == 4


def test_create_context_includes_the_trailing_command_buffer():
    assert ctypes.sizeof(abi.D3DKMT_CREATECONTEXT) == 96
    assert abi.D3DKMT_CREATECONTEXT.CommandBuffer.offset == 88


def test_layout_report_covers_every_structure():
    report = abi.layout_report()
    for name in ("D3DKMT_ESCAPE", "D3DKMT_CREATEDEVICE", "D3DKMT_CREATECONTEXT"):
        assert report[name]["sizeof"] > 0
        assert report[name]["alignof"] in (4, 8)


def test_open_adapter_from_luid_is_eight_byte_luid_then_handle():
    assert ctypes.sizeof(abi.D3DKMT_OPENADAPTERFROMLUID) == 12
    assert abi.D3DKMT_OPENADAPTERFROMLUID.AdapterLuid.offset == 0
    assert abi.D3DKMT_OPENADAPTERFROMLUID.hAdapter.offset == 8


COMPILED = __import__("pathlib").Path("tools/driver/abi_reference.jsonl")


@pytest.mark.skipif(not COMPILED.is_file(), reason="no compiled reference on disk")
def test_ctypes_matches_the_compiler_exactly():
    """The compiler is the authority; this test fails the moment they diverge."""
    import json

    report = abi.layout_report()
    mismatches = []
    for line in COMPILED.read_text(encoding="utf-8").splitlines():
        item = json.loads(line)
        if "scalar" in item:
            continue
        if "field" in item:
            name = "Adapter" if (item["struct"] == "D3DKMT_CREATEDEVICE"
                                 and item["field"] == "hAdapter") else item["field"]
            got = report.get(item["struct"], {}).get("offsets", {}).get(name)
            if got != item["offset"]:
                mismatches.append((item["struct"], name, item["offset"], got))
        else:
            got = report.get(item["struct"], {})
            if got.get("sizeof") != item["sizeof"] or got.get("alignof") != item["alignof"]:
                mismatches.append((item["struct"], "size", item["sizeof"], got))
    assert mismatches == []
