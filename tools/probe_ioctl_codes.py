# -*- coding: utf-8 -*-
"""Send codes the driver actually defines, one at a time, with empty buffers.

These came out of nvapi64.dll, so unlike the earlier bogus codes they can reach a
handler. The buffer is empty on purpose: a handler that validates its input will
reject a zero-length buffer before it dereferences anything, and the rejection
code alone tells us the function exists and roughly what it wants.

One code per invocation, printed before the call, so that a machine going down
leaves no doubt about which request caused it.

  python -m tools.probe_ioctl_codes --code 0x00320004
  python -m tools.probe_ioctl_codes --code 0x08de0004 --in-size 64
"""

import argparse
import ctypes
import json
import time
from ctypes import wintypes
from pathlib import Path

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

MEANING = {
    0: "HANDLED - the call succeeded",
    1: "invalid function - this device does not dispatch it",
    5: "access denied",
    6: "invalid handle",
    87: "invalid parameter - recognised, buffer rejected",
    122: "insufficient buffer - recognised, wants more data",
    1784: "supplied user buffer invalid",
}


def open_device(path: str):
    GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING = 0x80000000, 0x40000000, 3
    handle = kernel32.CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, None,
                                  OPEN_EXISTING, 0, None)
    if handle == wintypes.HANDLE(-1).value:
        raise OSError(ctypes.get_last_error(), "cannot open %s" % path)
    return handle


def send(handle, code: int, in_size: int, out_size: int) -> dict:
    input_buffer = ctypes.create_string_buffer(max(in_size, 1))
    output_buffer = ctypes.create_string_buffer(max(out_size, 1))
    returned = wintypes.DWORD(0)
    ok = kernel32.DeviceIoControl(
        handle, wintypes.DWORD(code),
        input_buffer if in_size else None, wintypes.DWORD(in_size),
        output_buffer if out_size else None, wintypes.DWORD(out_size),
        ctypes.byref(returned), None)
    error = 0 if ok else ctypes.get_last_error()
    return {"code": "0x%08x" % code, "in_size": in_size, "out_size": out_size,
            "ok": bool(ok), "error": error,
            "returned": returned.value,
            "meaning": MEANING.get(error, "error %d" % error)}


def main() -> int:
    parser = argparse.ArgumentParser(description="send one real ioctl code")
    parser.add_argument("--code", required=True)
    parser.add_argument("--device", default="\\\\.\\NvAdminDevice")
    parser.add_argument("--in-size", type=int, default=0)
    parser.add_argument("--out-size", type=int, default=0)
    parser.add_argument("--json", default="data/probe/ioctl_codes.json")
    args = parser.parse_args()

    code = int(args.code, 16) if args.code.lower().startswith("0x") else int(args.code)
    handle = open_device(args.device)
    print("device %s | code 0x%08x | in=%d out=%d"
          % (args.device, code, args.in_size, args.out_size))
    print("sending (if the machine goes down, this is the request that did it)")
    time.sleep(1)

    result = send(handle, code, args.in_size, args.out_size)
    kernel32.CloseHandle(handle)
    print("  ok=%s error=%d returned=%d  %s"
          % (result["ok"], result["error"], result["returned"], result["meaning"]))

    target = Path(args.json)
    target.parent.mkdir(parents=True, exist_ok=True)
    history = []
    if target.is_file():
        try:
            history = json.loads(target.read_text(encoding="utf-8")).get("attempts", [])
        except ValueError:
            history = []
    history.append(result)
    target.write_text(json.dumps({"attempts": history}, ensure_ascii=False, indent=2),
                      encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
