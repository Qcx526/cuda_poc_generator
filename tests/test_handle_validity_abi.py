# -*- coding: utf-8 -*-
"""Offline ABI checks for the handle-validity work.

No driver call happens here: these assert the structure layout against d3dkmthk.h and
that the old "equal to the adapter means invalid" rule is gone.
"""

import ctypes

import pytest

from tools.driver import escape_probe, handle_validity as hv


def test_createdevice_layout_matches_the_header():
    """union{hAdapter,pAdapter}=8, Flags@8, hDevice@12 on x64."""
    struct = hv.D3DKMT_CREATEDEVICE
    assert struct.hAdapter.offset == 0
    assert struct.Flags.offset == 8
    assert struct.hDevice.offset == 12


def test_getdevicestate_begins_with_handle_then_statetype():
    struct = hv.D3DKMT_GETDEVICESTATE
    assert struct.hDevice.offset == 0
    assert struct.StateType.offset == 4
    assert ctypes.sizeof(struct) >= 12


def test_queryadapterinfo_field_order():
    struct = hv.D3DKMT_QUERYADAPTERINFO
    assert struct.hAdapter.offset == 0
    assert struct.Type.offset == 4


def test_documented_constants():
    assert hv.KMTQAITYPE_DRIVERVERSION == 13
    assert hv.D3DKMT_DEVICESTATE_EXECUTION == 1


def test_equality_with_the_adapter_is_not_treated_as_invalid():
    """The old rule zeroed the device when its value equalled the adapter's."""
    assert escape_probe.usable_device(0, 0x40000040) is True
    assert escape_probe.usable_device(0, 0) is False
    assert escape_probe.usable_device(0xC000000D, 0x40000040) is False


def test_a_tool_count_is_not_a_driver_oracle():
    """GetDeviceState answers liveness; it must not be read as 'escape reached'."""
    assert not hasattr(hv, "trigger_count")
