# -*- coding: utf-8 -*-
"""Does the driver's ioctl channel actually work?

Opening a device object proves the object exists, not that it will carry a
request. This sends a handful of codes that should not exist, which is the
cheapest way to find out: a dispatch layer that does not recognise a code
rejects it before any handler sees the buffer.

That is also why the codes are deliberately outside the driver's device type.
A wrong-type code cannot reach a handler by accident, so a clean rejection is
evidence and a crash here would be a genuine surprise worth knowing about.

  python -m tools.probe_ioctl_channel
  python -m tools.probe_ioctl_channel --device "\\\\.\\DxgKrnl"

Every call is recorded; nothing is repeated and nothing is retried.
"""

import argparse
import ctypes
import json
from ctypes import wintypes
from pathlib import Path

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Device types NVIDIA's driver does not claim; a code carrying one of these has
# no handler to reach. 0x002b is avoided on purpose.
PROBE_CODES = [
    (0x00000000, "code 0"),
    (0xFFFFFFFF, "all bits set"),
    (0x0000E000, "type 0x0000, function 0xe00"),
    (0x77770004, "type 0x7777"),
    (0xFFFF0008, "type 0xffff"),
    (0x00018000, "type 0x0001"),
]

MEANING = {
    0: "HANDLED (unexpected: this code exists)",
    1: "invalid function - dispatch rejected it",
    5: "access denied - needs more rights",
    6: "invalid handle",
    50: "not supported",
    87: "invalid parameter - code may be recognised",
    122: "insufficient buffer - code is recognised",
}


def open_device(path: str, write: bool):
    access = 0x80000000 | (0x40000000 if write else 0)
    handle = kernel32.CreateFileW(path, access, 0, None, 3, 0, None)
    if handle == wintypes.HANDLE(-1).value:
        raise OSError(ctypes.get_last_error(),
                      "CreateFileW failed for %s" % path)
    return handle


def try_code(handle, code: int) -> dict:
    """One call, zeroed input, no output buffer, no retry."""
    in_buffer = ctypes.create_string_buffer(16)
    returned = wintypes.DWORD(0)
    ok = kernel32.DeviceIoControl(
        handle, wintypes.DWORD(code),
        in_buffer, wintypes.DWORD(len(in_buffer)),
        None, wintypes.DWORD(0),
        ctypes.byref(returned), None)
    error = 0 if ok else ctypes.get_last_error()
    return {"code": "0x%08x" % code, "ok": bool(ok), "error": error,
            "meaning": MEANING.get(error, "error %d" % error)}


def main() -> int:
    parser = argparse.ArgumentParser(description="probe the ioctl dispatch channel")
    parser.add_argument("--device", default="\\\\.\\NvAdminDevice")
    parser.add_argument("--write", action="store_true",
                        help="request write access as well (more invasive)")
    parser.add_argument("--json", default="data/probe/ioctl_channel.json")
    args = parser.parse_args()

    handle = open_device(args.device, args.write)
    print("device : %s (%s)" % (args.device, "rw" if args.write else "read"))
    print("codes  : %d, each sent once, no retry\n" % len(PROBE_CODES))

    results = []
    try:
        for code, label in PROBE_CODES:
            result = try_code(handle, code)
            result["label"] = label
            results.append(result)
            print("  %-12s %-24s %s" % (result["code"], label, result["meaning"]))
    finally:
        kernel32.CloseHandle(handle)

    rejected = sum(1 for item in results if item["error"] == 1)
    print("\n%d/%d rejected at dispatch" % (rejected, len(results)))
    if rejected == len(results):
        print("channel is alive and refuses unknown codes - safe to go further")
    elif any(item["ok"] for item in results):
        print("WARNING: a probe code was handled; examine before continuing")

    target = Path(args.json)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"device": args.device, "write": args.write,
                                  "results": results}, ensure_ascii=False, indent=2),
                      encoding="utf-8")
    print("written to %s" % target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
