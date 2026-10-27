# -*- coding: utf-8 -*-
"""Copy a real escape from the driver's own user-mode component.

Everything built by hand so far was rejected before dispatch, which means some
field of our D3DKMT_ESCAPE is not what the kernel expects - and the header does
not say which. Rather than guess again, load the user-mode driver the same way a
D3D application does, replace its `D3DKMTEscape` import slot, and read the
arguments it passes when the runtime asks it to do something.

The UMD is loaded before the device is created so that the patched slot is the
one it resolves through; a slot patched afterwards would never be called.

  python -m tools.hook_umd_escape
  python -m tools.hook_umd_escape --module nvwgf2umx.dll
"""

import argparse
import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path
from typing import Dict, List

from tools.extract_ioctls import Image, import_slots

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.GetModuleHandleW.restype = ctypes.c_void_p
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.LoadLibraryW.restype = ctypes.c_void_p
kernel32.LoadLibraryW.argtypes = [wintypes.LPCWSTR]
kernel32.VirtualProtect.restype = wintypes.BOOL
kernel32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

EscapeProto = ctypes.WINFUNCTYPE(wintypes.LONG, ctypes.c_void_p)
PAGE_READWRITE = 0x04
D3D_DRIVER_TYPE_HARDWARE = 1
D3D11_SDK_VERSION = 7


class EscapeRequest(ctypes.Structure):
    """The structure as we believe it; the capture will say whether that is right."""
    _fields_ = [("hAdapter", wintypes.UINT),
                ("hDevice", wintypes.UINT),
                ("Flags", wintypes.UINT),
                ("EscapeCode", wintypes.UINT),
                ("pPrivateDriverData", ctypes.c_void_p),
                ("PrivateDriverDataSize", wintypes.UINT),
                ("hContext", wintypes.UINT)]


def patch(address: int, value: int) -> None:
    old = wintypes.DWORD(0)
    kernel32.VirtualProtect(ctypes.c_void_p(address), ctypes.c_size_t(8),
                            PAGE_READWRITE, ctypes.byref(old))
    try:
        ctypes.cast(ctypes.c_void_p(address),
                    ctypes.POINTER(ctypes.c_void_p))[0] = value
    finally:
        kernel32.VirtualProtect(ctypes.c_void_p(address), ctypes.c_size_t(8),
                                old.value, ctypes.byref(wintypes.DWORD(0)))


def read_pointer(address: int) -> int:
    return ctypes.cast(ctypes.c_void_p(address),
                       ctypes.POINTER(ctypes.c_void_p))[0] or 0


class Watch:
    def __init__(self, label: str):
        self.label = label
        self.calls: List[Dict[str, object]] = []
        self.original = 0
        self.callback = None

    def install(self, slot: int) -> None:
        self.original = read_pointer(slot)
        if not self.original:
            raise OSError("slot %#x is empty" % slot)
        forwarder = EscapeProto(self.original)

        def hook(request_pointer):
            try:
                request = ctypes.cast(request_pointer,
                                      ctypes.POINTER(EscapeRequest)).contents
                entry = {"code": "0x%08x" % request.EscapeCode,
                         "flags": request.Flags,
                         "in_size": request.PrivateDriverDataSize,
                         "hAdapter": "0x%x" % request.hAdapter,
                         "hDevice": "0x%x" % request.hDevice,
                         "hContext": "0x%x" % request.hContext}
                if request.pPrivateDriverData and request.PrivateDriverDataSize:
                    head = min(request.PrivateDriverDataSize, 32)
                    entry["data_head"] = ctypes.string_at(
                        request.pPrivateDriverData, head).hex()
                self.calls.append(entry)
            except Exception:  # noqa: BLE001 - never break the caller
                pass
            return forwarder(request_pointer)

        self.callback = EscapeProto(hook)
        patch(slot, ctypes.cast(self.callback, ctypes.c_void_p).value)

    def remove(self, slot: int) -> None:
        if self.original:
            patch(slot, self.original)


def create_device():
    """A hardware D3D11 device: this is what makes the UMD issue escapes."""
    d3d11 = ctypes.WinDLL("d3d11")
    device = ctypes.c_void_p()
    context = ctypes.c_void_p()
    feature = wintypes.UINT(0)
    status = d3d11.D3D11CreateDevice(None, D3D_DRIVER_TYPE_HARDWARE, None, 0,
                                     None, 0, D3D11_SDK_VERSION,
                                     ctypes.byref(device), ctypes.byref(feature),
                                     ctypes.byref(context))
    return status, device, context


def main() -> int:
    parser = argparse.ArgumentParser(description="watch the UMD issue escapes")
    parser.add_argument("--module", default="nvwgf2umx.dll")
    parser.add_argument("--json", default="data/probe/umd_escape.json")
    args = parser.parse_args()

    # The UMD ships beside the driver it belongs to. Taking it from System32 or
    # from the newest DriverStore folder yields a version that is not running.
    from tools.extract_escape_codes import driver_path
    path = Path(driver_path()).parent / args.module
    image = Image(path.read_bytes())
    slots = import_slots(image, "D3DKMTEscape")
    print("%s: %d D3DKMTEscape import slot(s)" % (args.module, len(slots)))
    if not slots:
        print("this module does not import D3DKMTEscape; nothing to watch")
        return 1

    kernel32.LoadLibraryW(str(path))
    base = kernel32.GetModuleHandleW(args.module)
    print("loaded at 0x%x" % base)
    slot = base + (slots[0] - image.image_base)

    watch = Watch(args.module)
    watch.install(slot)
    try:
        status, device, context = create_device()
        print("D3D11CreateDevice status=0x%08x device=%s"
              % (status & 0xFFFFFFFF, bool(device.value)))
    finally:
        watch.remove(slot)

    print("\n%d escape(s) observed from the UMD" % len(watch.calls))
    for entry in watch.calls[:10]:
        print("  code=%s flags=%d size=%d ctx=%s data=%s"
              % (entry["code"], entry["flags"], entry["in_size"],
                 entry["hContext"], entry.get("data_head", "")[:32]))

    target = Path(args.json)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"module": args.module, "calls": watch.calls},
                                 ensure_ascii=False, indent=2), encoding="utf-8")
    print("written to %s" % target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
