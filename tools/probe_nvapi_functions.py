# -*- coding: utf-8 -*-
"""Which driver functions this nvapi64.dll will hand out, by id.

The DLL exports two symbols and nothing else, so every driver capability sits
behind `nvapi_QueryInterface(id)`: a 32-bit id in, a function pointer out, NULL
when the driver does not know the id. That makes enumeration cheap and safe -
asking for a pointer changes nothing, and no driver code runs.

A NULL is recorded as "unresolved", never as "absent": the tool cannot tell a
driver that lacks the function from an id that this table has wrong. Both look
identical from here, and pretending otherwise would turn a guess into a claim.

  python -m tools.probe_nvapi_functions
  python -m tools.probe_nvapi_functions --call-safe   # also read version strings
"""

import argparse
import ctypes
import json
import struct
from ctypes import wintypes
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Ids widely used by the public nvapi headers. Confidence is noted per entry
# because a wrong id and an unsupported call are indistinguishable at runtime.
KNOWN_FUNCTIONS: List[Tuple[str, str, str]] = [
    ("0x0150E828", "NvAPI_Initialize", "high"),
    ("0xD22BDD7E", "NvAPI_Unload", "high"),
    ("0x6C2D26A8", "NvAPI_GetErrorMessage", "high"),
    ("0x01053FA5", "NvAPI_GetInterfaceVersionString", "high"),
    ("0x2926AAAD", "NvAPI_SYS_GetDriverAndBranchVersion", "high"),
    ("0xE5AC921F", "NvAPI_EnumPhysicalGPUs", "high"),
    ("0xCEEE8E9F", "NvAPI_GPU_GetFullName", "high"),
    ("0x1BE0B8E5", "NvAPI_GPU_GetBusId", "high"),
    ("0x2DDFB66E", "NvAPI_GPU_GetPCIIdentifiers", "high"),
    ("0xE3640A56", "NvAPI_GPU_GetThermalSettings", "medium"),
    ("0xDCB616C3", "NvAPI_EnumNvidiaDisplayHandle", "medium"),
    ("0xE33D8A80", "unverified id (kept as a negative control)", "none"),
]


def pe_exports(path: str) -> List[str]:
    """Named exports, read straight from the PE export directory."""
    with open(path, "rb") as handle:
        data = handle.read()
    if data[:2] != b"MZ":
        raise ValueError("not a PE file: %s" % path)
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("missing PE signature: %s" % path)
    coff = pe + 4
    sections = struct.unpack_from("<H", data, coff + 2)[0]
    optional = coff + 20
    magic = struct.unpack_from("<H", data, optional)[0]
    directories = optional + (112 if magic == 0x20B else 96)
    export_rva = struct.unpack_from("<I", data, directories)[0]
    if not export_rva:
        return []

    table = []
    section_table = optional + struct.unpack_from("<H", data, coff + 16)[0]
    for index in range(sections):
        entry = section_table + index * 40
        # Order matters: VirtualSize then VirtualAddress, not the reverse.
        vsize, virtual, raw_size, raw = struct.unpack_from("<IIII", data, entry + 8)
        table.append((virtual, max(vsize, raw_size), raw))

    def to_file(rva: int) -> Optional[int]:
        for virtual, size, raw in table:
            if virtual <= rva < virtual + size:
                return raw + (rva - virtual)
        return None

    directory = to_file(export_rva)
    if directory is None:
        return []
    count = struct.unpack_from("<I", data, directory + 24)[0]
    names_rva = struct.unpack_from("<I", data, directory + 32)[0]
    names_offset = to_file(names_rva)
    if names_offset is None:
        return []
    names = []
    for index in range(count):
        name_rva = struct.unpack_from("<I", data, names_offset + index * 4)[0]
        offset = to_file(name_rva)
        if offset is None:
            continue
        end = data.index(b"\x00", offset)
        names.append(data[offset:end].decode("ascii", "replace"))
    return names


def resolve(dll, identifier: str):
    """Ask for a function pointer; NULL means the driver did not hand it out."""
    query = dll.nvapi_QueryInterface
    query.restype = ctypes.c_void_p
    query.argtypes = [ctypes.c_uint]
    return query(int(identifier, 16))


def read_version_string(dll) -> Optional[str]:
    """The one call worth making: fills a small char buffer, returns a status."""
    pointer = resolve(dll, "0x01053FA5")
    if not pointer:
        return None
    call = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p)(pointer)
    buffer = ctypes.create_string_buffer(64)
    return buffer.value.decode("ascii", "replace") if call(buffer) == 0 else None


def main() -> int:
    parser = argparse.ArgumentParser(description="enumerate nvapi entry points by id")
    parser.add_argument("--json", default="data/probe/nvapi_functions.json")
    parser.add_argument("--call-safe", action="store_true",
                        help="also read the interface version string")
    args = parser.parse_args()

    import os
    path = os.path.join(os.environ.get("WINDIR", r"C:\Windows"),
                        "System32", "nvapi64.dll")
    exports = pe_exports(path)
    print("nvapi64.dll exports: %d — %s" % (len(exports), ", ".join(exports)))
    print("everything else is behind nvapi_QueryInterface(id)\n")

    dll = ctypes.WinDLL(path)
    init = resolve(dll, "0x0150E828")
    initialised = False
    if init:
        initialised = ctypes.CFUNCTYPE(ctypes.c_int)(init)() == 0

    results: List[Dict[str, object]] = []
    resolved = 0
    for identifier, name, confidence in KNOWN_FUNCTIONS:
        pointer = resolve(dll, identifier)
        results.append({"id": identifier, "name": name, "confidence": confidence,
                        "resolved": bool(pointer)})
        if pointer:
            resolved += 1
        print("  %-12s %-42s %s" % (identifier, name,
                                    "resolved" if pointer else "-"))

    print("\n%d/%d ids resolved (init=%s)"
          % (resolved, len(KNOWN_FUNCTIONS), "ok" if initialised else "failed"))
    print("unresolved means 'not handed out', which is not the same as 'absent': "
          "this table may hold a wrong id")

    report = {"dll": path, "exports": exports, "initialised": initialised,
              "functions": results}
    if args.call_safe:
        report["interface_version"] = read_version_string(dll)
        print("interface version: %s" % report["interface_version"])

    target = Path(args.json)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                      encoding="utf-8")
    print("written to %s" % target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
