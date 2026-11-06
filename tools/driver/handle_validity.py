# -*- coding: utf-8 -*-
"""Is a device handle actually usable? Ask the documented API, not the numbers.

The earlier probe decided a handle was invalid when its value equalled the adapter's:

    usable = status == 0 and device not in (0, handle)

Nothing in d3dkmthk.h supports that. Two handles may coincide numerically and still be
valid; conversely a distinct value proves nothing. This module asks ``GetDeviceState``
and ``QueryAdapterInfo`` instead, and treats a failure as inconclusive until it has
been compared against a known-good device and a genuinely bogus handle.
"""

import ctypes
from ctypes import POINTER, byref, c_uint32, c_void_p, wintypes

from src.driver_abi import D3DKMT_HANDLE

# d3dkmthk.h: KMTQAITYPE_DRIVERVERSION = 13
KMTQAITYPE_DRIVERVERSION = 13
# d3dkmthk.h: D3DKMT_DEVICESTATE_EXECUTION = 1
D3DKMT_DEVICESTATE_EXECUTION = 1


class D3DKMT_CREATEDEVICE(ctypes.Structure):
    """Mirrors the header: union of hAdapter/pAdapter, Flags, then hDevice."""

    _fields_ = [("hAdapter", D3DKMT_HANDLE),
                ("_pad", c_uint32),
                ("Flags", c_uint32),
                ("hDevice", D3DKMT_HANDLE),
                ("pCommandBuffer", c_void_p),
                ("CommandBufferSize", c_uint32),
                ("pAllocationList", c_void_p),
                ("AllocationListSize", c_uint32),
                ("pPatchLocationList", c_void_p),
                ("PatchLocationListSize", c_uint32)]


class D3DKMT_GETDEVICESTATE(ctypes.Structure):
    _fields_ = [("hDevice", D3DKMT_HANDLE),
                ("StateType", c_uint32),
                ("ExecutionState", c_uint32),
                ("_pad", c_uint32 * 8)]


class D3DKMT_QUERYADAPTERINFO(ctypes.Structure):
    _fields_ = [("hAdapter", D3DKMT_HANDLE),
                ("Type", c_uint32),
                ("pPrivateDriverData", c_void_p),
                ("PrivateDriverDataSize", c_uint32)]


class D3DKMT_DESTROYDEVICE(ctypes.Structure):
    _fields_ = [("hDevice", D3DKMT_HANDLE)]


class D3DKMT_CLOSEADAPTER(ctypes.Structure):
    _fields_ = [("hAdapter", D3DKMT_HANDLE)]


def _gdi32():
    lib = ctypes.WinDLL("gdi32", use_last_error=True)
    lib.D3DKMTCreateDevice.argtypes = [POINTER(D3DKMT_CREATEDEVICE)]
    lib.D3DKMTGetDeviceState.argtypes = [POINTER(D3DKMT_GETDEVICESTATE)]
    lib.D3DKMTQueryAdapterInfo.argtypes = [POINTER(D3DKMT_QUERYADAPTERINFO)]
    lib.D3DKMTDestroyDevice.argtypes = [POINTER(D3DKMT_DESTROYDEVICE)]
    lib.D3DKMTCloseAdapter.argtypes = [POINTER(D3DKMT_CLOSEADAPTER)]
    for name in ("D3DKMTCreateDevice", "D3DKMTGetDeviceState", "D3DKMTQueryAdapterInfo",
                 "D3DKMTDestroyDevice", "D3DKMTCloseAdapter"):
        getattr(lib, name).restype = ctypes.c_int32
    return lib


def adapter_version(lib, adapter: int) -> dict:
    """Documented, read-only probe: a working adapter answers this with 0."""
    buffer = ctypes.create_string_buffer(64)
    request = D3DKMT_QUERYADAPTERINFO(hAdapter=adapter, Type=KMTQAITYPE_DRIVERVERSION,
                                      pPrivateDriverData=ctypes.cast(buffer, c_void_p),
                                      PrivateDriverDataSize=len(buffer))
    status = lib.D3DKMTQueryAdapterInfo(byref(request))
    return {"api": "QueryAdapterInfo(DRIVERVERSION)", "hAdapter": adapter,
            "status": status & 0xFFFFFFFF}


def create_device(lib, adapter: int) -> dict:
    request = D3DKMT_CREATEDEVICE(hAdapter=adapter, Flags=0)
    status = lib.D3DKMTCreateDevice(byref(request))
    return {"api": "CreateDevice", "status": status & 0xFFFFFFFF,
            "hAdapter": adapter, "hDevice": request.hDevice,
            "same_value": request.hDevice == adapter,
            "note": "数值相同不代表无效；这里只记录，不做判定"}


def device_state(lib, device: int, state_type: int = D3DKMT_DEVICESTATE_EXECUTION) -> dict:
    request = D3DKMT_GETDEVICESTATE(hDevice=device, StateType=state_type)
    status = lib.D3DKMTGetDeviceState(byref(request))
    return {"api": "GetDeviceState", "hDevice": device, "StateType": state_type,
            "status": status & 0xFFFFFFFF, "ExecutionState": request.ExecutionState}


def destroy_device(lib, device: int) -> dict:
    status = lib.D3DKMTDestroyDevice(byref(D3DKMT_DESTROYDEVICE(hDevice=device)))
    return {"api": "DestroyDevice", "hDevice": device, "status": status & 0xFFFFFFFF}


def close_adapter(lib, adapter: int) -> dict:
    status = lib.D3DKMTCloseAdapter(byref(D3DKMT_CLOSEADAPTER(hAdapter=adapter)))
    return {"api": "CloseAdapter", "hAdapter": adapter, "status": status & 0xFFFFFFFF}


def run(adapter: int, bogus: int = 0xDEAD) -> dict:
    """Positive control, negative control, and a destroyed handle."""
    lib = _gdi32()
    steps = []

    steps.append(adapter_version(lib, adapter))
    created = create_device(lib, adapter)
    steps.append(created)
    device = created["hDevice"]

    steps.append(device_state(lib, device))                    # known-good
    steps.append(device_state(lib, bogus))                     # never existed
    steps.append(device_state(lib, device, state_type=0))      # invalid StateType

    steps.append(destroy_device(lib, device))
    steps.append(device_state(lib, device))                    # destroyed
    steps.append(close_adapter(lib, adapter))

    by_name = {}
    for step in steps:
        by_name.setdefault(step["api"], []).append(step["status"])
    verdict = {
        "valid_device_status": steps[2]["status"],
        "bogus_handle_status": steps[3]["status"],
        "destroyed_handle_status": steps[6]["status"],
        "discriminates": steps[2]["status"] == 0 and steps[3]["status"] != 0,
        "destroyed_differs_from_valid": steps[6]["status"] != steps[2]["status"],
        "same_value_as_adapter": created["same_value"],
    }
    return {"steps": steps, "statuses": by_name, "verdict": verdict}
