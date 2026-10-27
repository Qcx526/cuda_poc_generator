# -*- coding: utf-8 -*-
"""Watch nvapi64 call the driver, from inside the process that is doing it.

Static extraction found codes but could not say which device or which call they
belong to, and sending them to NvAdminDevice did nothing. So instead of guessing
where nvapi64 sends its requests, replace its `DeviceIoControl` import entry for
the duration of one call and read the arguments as they go past.

Nothing is sent by us: the arguments are the ones nvapi64 itself chose, after a
documented API call. That is the difference between knowing the codes and
knowing which code belongs to which function.

  python -m tools.hook_deviceioctl
  python -m tools.hook_deviceioctl --call full_name
"""

import argparse
import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path
from typing import Dict, List

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
# Without an explicit restype these return 32-bit ints and the module base gets
# truncated, which is not an error anyone sees until a write lands nowhere.
kernel32.GetModuleHandleW.restype = ctypes.c_void_p
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.VirtualProtect.restype = wintypes.BOOL
kernel32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.VirtualQuery.restype = ctypes.c_size_t

DeviceIoControlProto = ctypes.WINFUNCTYPE(
    wintypes.BOOL, wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p)

PAGE_READWRITE = 0x04


def module_base(name: str) -> int:
    handle = kernel32.GetModuleHandleW(name)
    if not handle:
        raise OSError("module not loaded: %s" % name)
    return handle


def slot_address(base: int, rva: int) -> int:
    return base + rva


def make_protection_writable(address: int, size: int = 8):
    old = wintypes.DWORD(0)
    ok = kernel32.VirtualProtect(ctypes.c_void_p(address), ctypes.c_size_t(size),
                                 PAGE_READWRITE, ctypes.byref(old))
    if not ok:
        raise OSError(ctypes.get_last_error(), "VirtualProtect failed")
    return old.value


def patch_pointer(address: int, value: int) -> None:
    ctypes.cast(ctypes.c_void_p(address), ctypes.POINTER(ctypes.c_void_p))[0] = value


def read_pointer(address: int) -> int:
    return ctypes.cast(ctypes.c_void_p(address),
                       ctypes.POINTER(ctypes.c_void_p))[0] or 0


class Watch:
    """Records one DeviceIoControl call and forwards it unchanged."""

    def __init__(self):
        self.calls: List[Dict[str, object]] = []
        self.original = None
        self.callback = None

    def install(self, slot: int) -> None:
        self.original = read_pointer(slot)
        if not self.original:
            raise OSError("import slot is empty; the module is not bound")

        def forward(handle, code, in_buffer, in_size, out_buffer, out_size,
                    returned, overlapped):
            entry = {"code": "0x%08x" % code, "in_size": int(in_size),
                     "out_size": int(out_size)}
            if in_buffer and in_size:
                entry["in_head"] = ctypes.string_at(in_buffer, min(int(in_size), 32)).hex()
            self.calls.append(entry)
            original = DeviceIoControlProto(self.original)
            return original(handle, code, in_buffer, in_size, out_buffer,
                            out_size, returned, overlapped)

        self.callback = DeviceIoControlProto(forward)
        old = make_protection_writable(slot)
        try:
            patch_pointer(slot, ctypes.cast(self.callback, ctypes.c_void_p).value)
        finally:
            kernel32.VirtualProtect(ctypes.c_void_p(slot), ctypes.c_size_t(8),
                                    old, ctypes.byref(wintypes.DWORD(0)))

    def remove(self, slot: int) -> None:
        if self.original:
            old = make_protection_writable(slot)
            try:
                patch_pointer(slot, self.original)
            finally:
                kernel32.VirtualProtect(ctypes.c_void_p(slot), ctypes.c_size_t(8),
                                        old, ctypes.byref(wintypes.DWORD(0)))


CALLS = {
    "full_name": 0xCEEE8E9F,
    "thermal": 0xE3640A56,
    "pci_ids": 0x2DDFB66E,
}


def run_calls(nvapi, which: str) -> None:
    query = nvapi.nvapi_QueryInterface
    query.restype = ctypes.c_void_p
    query.argtypes = [ctypes.c_uint]
    init = query(0x0150E828)
    if init:
        ctypes.CFUNCTYPE(ctypes.c_int)(init)()
    enum = query(0xE5AC921F)
    handles = (wintypes.HANDLE * 64)()
    count = wintypes.UINT(0)
    ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(wintypes.HANDLE),
                     ctypes.POINTER(wintypes.UINT))(enum)(handles, ctypes.byref(count))
    if not count.value:
        raise RuntimeError("no GPU handle")
    handle = handles[0]

    if which == "full_name":
        buffer = ctypes.create_string_buffer(64)
        ctypes.CFUNCTYPE(ctypes.c_int, wintypes.HANDLE,
                         ctypes.c_char_p)(query(CALLS["full_name"]))(handle, buffer)
        print("full_name ->", buffer.value.decode("ascii", "replace"))
    elif which == "pci_ids":
        values = [wintypes.UINT(0) for _ in range(4)]
        ctypes.CFUNCTYPE(ctypes.c_int, wintypes.HANDLE,
                         ctypes.POINTER(wintypes.UINT), ctypes.POINTER(wintypes.UINT),
                         ctypes.POINTER(wintypes.UINT),
                         ctypes.POINTER(wintypes.UINT))(query(CALLS["pci_ids"]))(
            handle, *[ctypes.byref(item) for item in values])
        print("pci_ids ->", [hex(item.value) for item in values])
    else:
        buffer = ctypes.create_string_buffer(128)
        ctypes.CFUNCTYPE(ctypes.c_int, wintypes.HANDLE, wintypes.UINT,
                         ctypes.c_void_p)(query(CALLS["thermal"]))(handle, 0, buffer)
        print("thermal -> called")


def main() -> int:
    parser = argparse.ArgumentParser(description="watch nvapi64 ioctls from inside")
    parser.add_argument("--call", default="full_name", choices=sorted(CALLS))
    parser.add_argument("--slot-rva", default="0x5ff1e8")
    parser.add_argument("--json", default="data/probe/ioctl_watch.json")
    args = parser.parse_args()

    nvapi = ctypes.WinDLL(os.path.join(os.environ["WINDIR"], "System32",
                                       "nvapi64.dll"))
    base = module_base("nvapi64.dll")
    slot = slot_address(base, int(args.slot_rva, 16))
    print("nvapi64 base 0x%x | import slot 0x%x | call %s"
          % (base, slot, args.call))

    watch = Watch()
    watch.install(slot)
    try:
        run_calls(nvapi, args.call)
    finally:
        watch.remove(slot)

    print("\n%d DeviceIoControl call(s) observed:" % len(watch.calls))
    for entry in watch.calls:
        print("  code=%s in=%d out=%d %s"
              % (entry["code"], entry["in_size"], entry["out_size"],
                 entry.get("in_head", "")))

    target = Path(args.json)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"call": args.call, "calls": watch.calls},
                                 ensure_ascii=False, indent=2), encoding="utf-8")
    print("written to %s" % target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
