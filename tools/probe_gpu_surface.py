# -*- coding: utf-8 -*-
"""What the GPU driver exposes to an unprivileged user, read-only.

Before crafting anything against a kernel driver it is worth knowing which
device objects exist and which of them an ordinary user can even open. This
probe answers that and nothing else: no ioctl is issued, no buffer is sent, so
it cannot fault the driver. Anything it finds is a surface; anything it cannot
open is a wall that no amount of clever input will climb.

  python -m tools.probe_gpu_surface
  python -m tools.probe_gpu_surface --json data/probe/gpu_surface.json
"""

import argparse
import ctypes
import json
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Dict, List

if sys.platform != "win32":
    raise SystemExit("this probe targets Windows; the Linux path uses /dev/nvidia*")

ntdll = ctypes.WinDLL("ntdll")
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

DIRECTORY_QUERY = 0x0001
DIRECTORY_TRAVERSE = 0x0002
STATUS_SUCCESS = 0
STATUS_NO_MORE_ENTRIES = 0x8000001A
STATUS_BUFFER_TOO_SMALL = 0xC0000023
OBJ_CASE_INSENSITIVE = 0x00000040


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", wintypes.USHORT),
                ("MaximumLength", wintypes.USHORT),
                ("Buffer", ctypes.c_void_p)]


class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Length", wintypes.ULONG),
                ("RootDirectory", wintypes.HANDLE),
                ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
                ("Attributes", wintypes.ULONG),
                ("SecurityDescriptor", ctypes.c_void_p),
                ("SecurityQualityOfService", ctypes.c_void_p)]


class DIRECTORY_INFORMATION(ctypes.Structure):
    _fields_ = [("Name", UNICODE_STRING), ("TypeName", UNICODE_STRING)]


def _unicode_string(text: str):
    buffer = ctypes.create_unicode_buffer(text)
    return UNICODE_STRING(len(text) * 2, len(text) * 2 + 2,
                          ctypes.cast(buffer, ctypes.c_void_p)), buffer


def list_device_objects(directory: str = "\\Device") -> List[Dict[str, str]]:
    """Every object directly under \\Device, with its type.

    Read-only enumeration: opening the directory asks for query rights only.
    """
    name, keepalive = _unicode_string(directory)
    attributes = OBJECT_ATTRIBUTES(ctypes.sizeof(OBJECT_ATTRIBUTES), None,
                                   ctypes.pointer(name), OBJ_CASE_INSENSITIVE,
                                   None, None)
    handle = wintypes.HANDLE()
    status = ntdll.NtOpenDirectoryObject(
        ctypes.byref(handle), DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
        ctypes.byref(attributes))
    if status != STATUS_SUCCESS:
        raise OSError("NtOpenDirectoryObject(%s) failed: 0x%08x"
                      % (directory, status & 0xFFFFFFFF))

    entries: List[Dict[str, str]] = []
    context = wintypes.ULONG(0)
    size = 64 * 1024
    buffer = ctypes.create_string_buffer(size)
    restart = True
    while True:
        returned = wintypes.ULONG(0)
        status = ntdll.NtQueryDirectoryObject(
            handle, buffer, size, False, restart, ctypes.byref(context),
            ctypes.byref(returned))
        restart = False
        if status == STATUS_NO_MORE_ENTRIES:
            break
        if status != STATUS_SUCCESS:
            break
        offset = 0
        while offset < returned.value:
            item = DIRECTORY_INFORMATION.from_buffer(buffer, offset)
            if item.Name.Length == 0:
                break
            text = ctypes.wstring_at(item.Name.Buffer, item.Name.Length // 2)
            kind = ""
            if item.TypeName.Length:
                kind = ctypes.wstring_at(item.TypeName.Buffer,
                                         item.TypeName.Length // 2)
            entries.append({"name": text, "type": kind})
            offset += ctypes.sizeof(DIRECTORY_INFORMATION)
    kernel32.CloseHandle(handle)
    return entries


def try_open(path: str) -> Dict[str, object]:
    """Can an ordinary user open this at all? No bytes are sent either way."""
    GENERIC_READ = 0x80000000
    OPEN_EXISTING = 3
    handle = kernel32.CreateFileW(path, GENERIC_READ, 0, None, OPEN_EXISTING,
                                  0, None)
    if handle == wintypes.HANDLE(-1).value:
        err = ctypes.get_last_error()
        return {"path": path, "opened": False, "error": err,
                "meaning": {5: "access denied", 2: "not found",
                            32: "sharing violation"}.get(err, "error %d" % err)}
    kernel32.CloseHandle(handle)
    return {"path": path, "opened": True, "error": 0, "meaning": "opened"}


def nvapi_driver_version():
    """Ask the user-mode NVIDIA API; a documented interface, read-only."""
    try:
        nvapi = ctypes.WinDLL("nvapi64.dll")
    except OSError:
        return None
    try:
        query = nvapi.nvapi_QueryInterface
        query.restype = ctypes.c_void_p
        query.argtypes = [ctypes.c_uint]
        init = query(0x0150E828)
        if not init:
            return None
        init_fn = ctypes.CFUNCTYPE(ctypes.c_int)(init)
        if init_fn() != 0:
            return None
        version_fn_ptr = query(0xE33D8A80)  # NvAPI_GetInterfaceVersionString
        if not version_fn_ptr:
            return "initialised, version string unavailable"
        get_version = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p)(version_fn_ptr)
        buffer = ctypes.create_string_buffer(64)
        if get_version(buffer) == 0:
            return buffer.value.decode("ascii", "replace")
        return "initialised, version query failed"
    except OSError:
        return None


GPU_HINTS = ("nv", "nvidia", "dxg", "display", "gpu", "nvlddmkm")


def interesting(entries: List[Dict[str, str]]) -> List[Dict[str, str]]:
    return [entry for entry in entries
            if any(hint in entry["name"].lower() for hint in GPU_HINTS)]


def main() -> int:
    parser = argparse.ArgumentParser(description="read-only GPU surface probe")
    parser.add_argument("--json", default="data/probe/gpu_surface.json")
    args = parser.parse_args()

    report: Dict[str, object] = {}
    try:
        entries = list_device_objects()
    except OSError as exc:
        print("cannot enumerate \\Device: %s" % exc)
        return 1

    report["device_objects_total"] = len(entries)
    report["gpu_related"] = interesting(entries)
    print("device objects: %d total, %d GPU-related"
          % (len(entries), len(report["gpu_related"])))
    for entry in report["gpu_related"][:20]:
        print("  %-40s %s" % (entry["name"], entry["type"]))

    opens = [try_open("\\\\.\\GLOBALROOT\\Device\\" + entry["name"])
             for entry in report["gpu_related"]]
    report["open_attempts"] = opens
    print("\nopen attempts (read-only, no ioctl sent):")
    for item in opens:
        flag = "OPEN" if item["opened"] else "----"
        print("  [%s] %-40s %s" % (flag, item["path"].split("\\")[-1],
                                   item["meaning"]))

    report["nvapi"] = nvapi_driver_version()
    print("\nnvapi: %s" % (report["nvapi"] or "not available"))

    target = Path(args.json)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                      encoding="utf-8")
    print("\nwritten to %s" % target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
