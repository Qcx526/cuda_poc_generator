# -*- coding: utf-8 -*-
"""Call a few documented entry points with correct arguments, then bend one.

Stage 1-2 establishes a baseline: if a call does not return NVAPI_OK with sane
arguments, nothing learned from mutating it means anything. Only once the
baseline works does stage 3 change a single field, so a fault has exactly one
possible cause.

Buffer sizes are the driver's business, not ours: a call that fills a struct is
given the size the header declares, and the mutation stage shrinks or grows it
by one field so the rest of the request stays identical.

  python -m tools.probe_nvapi_calls              # baseline only
  python -m tools.probe_nvapi_calls --mutate     # baseline, then one field bent
"""

import argparse
import ctypes
import json
from ctypes import wintypes
from pathlib import Path
from typing import Dict, List, Optional

NVAPI_OK = 0
MAX_PHYSICAL_GPUS = 64
QUERY_INTERFACE = {
    "init": 0x0150E828,
    "unload": 0xD22BDD7E,
    "enum_physical": 0xE5AC921F,
    "full_name": 0xCEEE8E9F,
    "pci_ids": 0x2DDFB66E,
    "thermal": 0xE3640A56,
}

NAME_LEN = 64
THERMAL_SENSORS = 3


class Sensor(ctypes.Structure):
    _fields_ = [("controller", wintypes.UINT),
                ("defaultMinTemp", wintypes.INT),
                ("defaultMaxTemp", wintypes.INT),
                ("currentTemp", wintypes.INT),
                ("target", wintypes.UINT)]


class ThermalSettings(ctypes.Structure):
    _fields_ = [("version", wintypes.UINT),
                ("count", wintypes.UINT),
                ("sensor", Sensor * THERMAL_SENSORS)]


def thermal_version() -> int:
    """NVAPI's struct versioning: size in the low word, version in the high."""
    return ctypes.sizeof(ThermalSettings) | (1 << 16)


def resolve(nvapi, identifier: int):
    query = nvapi.nvapi_QueryInterface
    query.restype = ctypes.c_void_p
    query.argtypes = [ctypes.c_uint]
    return query(identifier)


def enum_physical_gpus(nvapi):
    pointer = resolve(nvapi, QUERY_INTERFACE["enum_physical"])
    if not pointer:
        raise RuntimeError("NvAPI_EnumPhysicalGPUs is not available")
    call = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(wintypes.HANDLE),
                            ctypes.POINTER(wintypes.UINT))(pointer)
    handles = (wintypes.HANDLE * MAX_PHYSICAL_GPUS)()
    count = wintypes.UINT(0)
    status = call(handles, ctypes.byref(count))
    return status, [handles[index] for index in range(count.value)]


def get_full_name(nvapi, handle) -> Dict[str, object]:
    pointer = resolve(nvapi, QUERY_INTERFACE["full_name"])
    if not pointer:
        return {"status": None, "error": "unavailable"}
    call = ctypes.CFUNCTYPE(ctypes.c_int, wintypes.HANDLE,
                            ctypes.c_char_p)(pointer)
    buffer = ctypes.create_string_buffer(NAME_LEN)
    status = call(handle, buffer)
    return {"status": status, "name": buffer.value.decode("ascii", "replace")}


def get_pci_ids(nvapi, handle) -> Dict[str, object]:
    pointer = resolve(nvapi, QUERY_INTERFACE["pci_ids"])
    if not pointer:
        return {"status": None, "error": "unavailable"}
    call = ctypes.CFUNCTYPE(ctypes.c_int, wintypes.HANDLE,
                            ctypes.POINTER(wintypes.UINT),
                            ctypes.POINTER(wintypes.UINT),
                            ctypes.POINTER(wintypes.UINT),
                            ctypes.POINTER(wintypes.UINT))(pointer)
    values = [wintypes.UINT(0) for _ in range(4)]
    status = call(handle, *[ctypes.byref(item) for item in values])
    return {"status": status,
            "device_id": "0x%08x" % values[0].value,
            "subsystem_id": "0x%08x" % values[1].value,
            "revision_id": "0x%08x" % values[2].value,
            "ext_device_id": "0x%08x" % values[3].value}


def get_thermal(nvapi, handle, declared_version: Optional[int] = None) -> Dict[str, object]:
    pointer = resolve(nvapi, QUERY_INTERFACE["thermal"])
    if not pointer:
        return {"status": None, "error": "unavailable"}
    call = ctypes.CFUNCTYPE(ctypes.c_int, wintypes.HANDLE, wintypes.UINT,
                            ctypes.POINTER(ThermalSettings))(pointer)
    settings = ThermalSettings()
    settings.version = thermal_version() if declared_version is None else declared_version
    status = call(handle, 0, ctypes.byref(settings))
    return {"status": status, "count": settings.count,
            "version_declared": "0x%08x" % settings.version,
            "first_temp": settings.sensor[0].currentTemp}


def main() -> int:
    parser = argparse.ArgumentParser(description="call documented NVAPI entries")
    parser.add_argument("--mutate", action="store_true",
                        help="after a clean baseline, bend one field and call again")
    parser.add_argument("--json", default="data/probe/nvapi_calls.json")
    args = parser.parse_args()

    import os
    nvapi = ctypes.WinDLL(os.path.join(os.environ["WINDIR"], "System32",
                                       "nvapi64.dll"))
    init = resolve(nvapi, QUERY_INTERFACE["init"])
    if not init or ctypes.CFUNCTYPE(ctypes.c_int)(init)() != NVAPI_OK:
        print("NVAPI did not initialise")
        return 1

    report: Dict[str, object] = {"baseline": {}, "mutation": None}
    status, handles = enum_physical_gpus(nvapi)
    report["baseline"]["enum_physical_gpus"] = {"status": status,
                                                "count": len(handles)}
    print("EnumPhysicalGPUs      status=%d count=%d" % (status, len(handles)))
    if status != NVAPI_OK or not handles:
        print("no GPU handle; nothing further can be tried")
        return 1

    handle = handles[0]
    for label, function in (("get_full_name", get_full_name),
                            ("get_pci_ids", get_pci_ids)):
        result = function(nvapi, handle)
        report["baseline"][label] = result
        detail = result.get("name") or result.get("device_id") or result.get("error")
        print("%-21s status=%s %s" % (label, result.get("status"), detail))

    thermal = get_thermal(nvapi, handle)
    report["baseline"]["get_thermal"] = thermal
    print("%-21s status=%s count=%s temp=%s"
          % ("get_thermal", thermal.get("status"), thermal.get("count"),
             thermal.get("first_temp")))

    clean = all(entry.get("status") == NVAPI_OK
                for entry in report["baseline"].values())
    print("\nbaseline %s" % ("clean" if clean else "NOT clean - mutation is meaningless"))

    if args.mutate and clean:
        # One field, one change: the struct still declares its real size, but the
        # version word claims a version the driver does not know.
        bent = get_thermal(nvapi, handle, declared_version=thermal_version() | (0xF << 16))
        report["mutation"] = {"what": "thermal version word raised to v15", "result": bent}
        print("mutation (version word)  status=%s count=%s"
              % (bent.get("status"), bent.get("count")))

    target = Path(args.json)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print("written to %s" % target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
