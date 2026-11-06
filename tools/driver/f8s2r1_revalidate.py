# -*- coding: utf-8 -*-
"""Revalidate the corrected ABI against the adapter selected by LUID.

Every earlier JSON was produced with a 44-byte D3DKMT_GETDEVICESTATE while the real
structure is 56 bytes, so those runs cannot be reused. This script records fresh
statuses, the sizes actually used, and the driver identity on two levels: the file on
disk and the module loaded in the kernel.
"""

import ctypes
import hashlib
import json
import platform
import sys
from ctypes import byref, c_uint32, c_void_p, wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.driver_abi import D3DKMT_HANDLE          # noqa: E402
from tools.driver import handle_validity as hv   # noqa: E402

DRIVER_FILE = Path("C:/Windows/System32/DriverStore/FileRepository/"
                   "nv_dispi.inf_amd64_c8bc842500fab35b/nvlddmkm.sys")


class D3DKMT_OPENADAPTERFROMLUID(ctypes.Structure):
    _fields_ = [("Luid", ctypes.c_uint64), ("hAdapter", D3DKMT_HANDLE)]


class D3DKMT_CLOSEADAPTER(ctypes.Structure):
    _fields_ = [("hAdapter", D3DKMT_HANDLE)]


def gdi32():
    lib = ctypes.WinDLL("gdi32", use_last_error=True)
    for name in ("D3DKMTOpenAdapterFromLuid", "D3DKMTCloseAdapter"):
        getattr(lib, name).restype = ctypes.c_int32
    lib.D3DKMTOpenAdapterFromLuid.argtypes = [ctypes.POINTER(D3DKMT_OPENADAPTERFROMLUID)]
    lib.D3DKMTCloseAdapter.argtypes = [ctypes.POINTER(D3DKMT_CLOSEADAPTER)]
    return lib


def open_by_luid(lib, luid_text: str) -> dict:
    high, _, low = luid_text.partition(":")
    request = D3DKMT_OPENADAPTERFROMLUID(
        Luid=(int(high or 0, 16) << 32) | int(low or 0, 16))
    status = lib.D3DKMTOpenAdapterFromLuid(byref(request))
    return {"api": "OpenAdapterFromLuid", "luid": luid_text,
            "status": status & 0xFFFFFFFF, "hAdapter": request.hAdapter}


def close_adapter(lib, adapter: int) -> dict:
    status = lib.D3DKMTCloseAdapter(byref(D3DKMT_CLOSEADAPTER(hAdapter=adapter)))
    return {"api": "CloseAdapter", "hAdapter": adapter, "status": status & 0xFFFFFFFF}


def query_driver_version(lib, adapter: int) -> dict:
    """DRIVERVERSION writes a UINT, so the buffer is exactly four bytes."""
    out = c_uint32(0)
    request = hv.D3DKMT_QUERYADAPTERINFO(
        hAdapter=adapter, Type=hv.KMTQAITYPE_DRIVERVERSION,
        pPrivateDriverData=ctypes.cast(byref(out), c_void_p),
        PrivateDriverDataSize=ctypes.sizeof(out))
    status = lib.D3DKMTQueryAdapterInfo(byref(request))
    return {"api": "QueryAdapterInfo(DRIVERVERSION=13)", "buffer_bytes": ctypes.sizeof(out),
            "status": status & 0xFFFFFFFF, "value": out.value}


def loaded_kernel_module(name: str = "nvlddmkm.sys") -> dict:
    """Where the kernel actually has it loaded, as opposed to what is on disk."""
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.EnumDeviceDrivers.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    psapi.EnumDeviceDrivers.restype = wintypes.BOOL
    psapi.GetDeviceDriverBaseNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR,
                                               wintypes.DWORD]
    psapi.GetDeviceDriverBaseNameW.restype = wintypes.DWORD
    needed = wintypes.DWORD(0)
    psapi.EnumDeviceDrivers(None, 0, byref(needed))
    count = needed.value // ctypes.sizeof(ctypes.c_void_p)
    if not count:
        return {"found": False}
    bases = (ctypes.c_void_p * count)()
    if not psapi.EnumDeviceDrivers(ctypes.cast(bases, ctypes.POINTER(ctypes.c_void_p)),
                                   ctypes.sizeof(bases), byref(needed)):
        return {"found": False}
    buffer = ctypes.create_unicode_buffer(260)
    for base in bases:
        if not psapi.GetDeviceDriverBaseNameW(ctypes.c_void_p(base), buffer, 260):
            continue
        if buffer.value.lower() == name.lower():
            return {"found": True, "base": "0x%x" % int(base or 0), "name": buffer.value}
    return {"found": False, "scanned": count}


def main() -> int:
    baseline = ROOT / "data" / "driver" / "f8s2_baseline.json"
    evidence = json.loads(baseline.read_text(encoding="utf-8"))
    logical = [a for a in evidence["d3d11"]["adapters"] if a.get("vendor") == "0x10de"]
    luid = logical[0]["luid"] if logical else "0:0"

    lib = gdi32()
    steps = []
    opened = open_by_luid(lib, luid)
    steps.append(opened)
    adapter = opened["hAdapter"]

    steps.append(query_driver_version(lib, adapter))

    result = {"luid": luid, "opened": opened["status"]}
    if opened["status"] == 0:
        created = hv.create_device(lib, adapter)
        steps.append(created)
        if created["status"] == 0:
            device = created["hDevice"]
            # Named variables, not negative indices: an off-by-one here silently
            # relabels one status as another, which is exactly the kind of error
            # that turns a failure into a success.
            valid = hv.device_state(lib, device)
            bogus = hv.device_state(lib, 0xDEAD)
            destroy = hv.destroy_device(lib, device)
            destroyed = hv.device_state(lib, device)
            steps.extend([valid, bogus, destroy, destroyed])
            result.update({
                "hDevice": device,
                "same_value_as_adapter": created["same_value"],
                "valid_status": valid["status"],
                "bogus_status": bogus["status"],
                "destroy_status": destroy["status"],
                "destroyed_status": destroyed["status"],
            })
        else:
            result["aborted"] = "CreateDevice failed"
    steps.append(close_adapter(lib, adapter))

    payload = {
        "host": {"platform": platform.platform(), "version": platform.version(),
                 "build": platform.win32_ver()[1]},
        "target_luid": luid,
        "logical_adapters_note": "%d 个 NVIDIA DXGI 条目，属逻辑适配器，不等于 %d 张物理卡"
                                 % (len(logical), len(logical)),
        "abi_sizes": {
            "D3DKMT_HANDLE": ctypes.sizeof(D3DKMT_HANDLE),
            "D3DKMT_CREATEDEVICE": ctypes.sizeof(hv.D3DKMT_CREATEDEVICE),
            "D3DKMT_GETDEVICESTATE": ctypes.sizeof(hv.D3DKMT_GETDEVICESTATE),
            "D3DKMT_QUERYADAPTERINFO": ctypes.sizeof(hv.D3DKMT_QUERYADAPTERINFO),
        },
        "driver": {
            "file": str(DRIVER_FILE),
            "file_sha256": hashlib.sha256(DRIVER_FILE.read_bytes()).hexdigest()
            if DRIVER_FILE.is_file() else None,
            "loaded_module": loaded_kernel_module(),
            "note": "磁盘文件与内核已加载模块是两条身份线索，不能互相替代",
        },
        "steps": steps,
        "result": result,
    }
    target = ROOT / "data" / "driver" / "f8s2r1_revalidation.json"
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({"result": result, "abi": payload["abi_sizes"],
                      "driver": payload["driver"]}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
