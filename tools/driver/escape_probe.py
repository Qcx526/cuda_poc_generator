# -*- coding: utf-8 -*-
"""Issue a D3DKMT escape, the channel the kernel driver calls "kernel-mode escape".

Everything so far went through NVAPI, which is a structured, versioned, heavily
type-checked interface: profile structs, setting structs, each field gated by a
version dword. Escape is the opposite - a handle plus an opaque byte buffer whose
size the caller chooses. That is the shape a fuzzer wants, and it is what
CVE-2026-47571 names.

  python -m tools.driver.escape_probe --cmd 0 --size 16        # benign
  python -m tools.driver.escape_probe --cmd 0 --size 16 --fill 0xFF

The adapter is opened from the display device name, which needs no GPU enumeration
API and works on a machine where NVML refuses to initialise.
"""

import argparse
import ctypes
from ctypes import wintypes
from typing import Optional

gdi32 = ctypes.WinDLL("gdi32")
user32 = ctypes.WinDLL("user32")


class D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME(ctypes.Structure):
    _fields_ = [("DeviceName", wintypes.WCHAR * 32),
                ("hAdapter", wintypes.UINT)]


class D3DKMT_CLOSEADAPTER(ctypes.Structure):
    _fields_ = [("hAdapter", wintypes.UINT)]


class D3DKMT_ESCAPE(ctypes.Structure):
    """Layout matters: the padding after Flags and after the size is real."""
    _fields_ = [("hAdapter", wintypes.UINT),
                ("hDevice", wintypes.UINT),
                ("Flags", wintypes.UINT),
                ("pPrivateDriverData", ctypes.c_void_p),
                ("PrivateDriverDataSize", wintypes.UINT),
                ("hContext", wintypes.UINT)]


def display_name(index: int = 0) -> Optional[str]:
    class DISPLAY_DEVICEW(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD),
                    ("DeviceName", wintypes.WCHAR * 32),
                    ("DeviceString", wintypes.WCHAR * 128),
                    ("StateFlags", wintypes.DWORD),
                    ("DeviceID", wintypes.WCHAR * 128),
                    ("DeviceKey", wintypes.WCHAR * 128)]

    device = DISPLAY_DEVICEW()
    device.cb = ctypes.sizeof(device)
    if not user32.EnumDisplayDevicesW(None, index, ctypes.byref(device), 0):
        return None
    return device.DeviceName


def open_adapter(name: str) -> dict:
    request = D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME()
    request.DeviceName = name
    status = gdi32.D3DKMTOpenAdapterFromGdiDisplayName(ctypes.byref(request))
    return {"status": status, "hAdapter": request.hAdapter}


def close_adapter(handle: int) -> int:
    request = D3DKMT_CLOSEADAPTER(hAdapter=handle)
    return gdi32.D3DKMTCloseAdapter(ctypes.byref(request))


class D3DKMT_CREATEDEVICE(ctypes.Structure):
    """hAdapter in, hDevice out - the union is how the API overloads the field."""
    _fields_ = [("hAdapter", wintypes.UINT),
                ("Flags", wintypes.UINT),
                ("pCreateDevice", ctypes.c_void_p),
                ("Size", wintypes.UINT)]


class D3DKMT_DESTROYDEVICE(ctypes.Structure):
    _fields_ = [("hDevice", wintypes.UINT)]


def create_device(handle: int) -> dict:
    """A device on the adapter.

    NVIDIA's escapes are dispatched per device, not per adapter: with only an
    adapter handle every command comes back STATUS_INVALID_PARAMETER, which looks
    like an unknown command but is a missing device.
    """
    request = D3DKMT_CREATEDEVICE()
    request.hAdapter = handle
    request.Flags = 0
    request.pCreateDevice = None
    request.Size = 0
    status = gdi32.D3DKMTCreateDevice(ctypes.byref(request))
    return {"status": status, "hDevice": request.hAdapter}


def destroy_device(handle: int) -> int:
    return gdi32.D3DKMTDestroyDevice(ctypes.byref(D3DKMT_DESTROYDEVICE(hDevice=handle)))


def escape(handle: int, command: int, size: int, fill: int = 0x00,
           device: int = 0) -> dict:
    """One escape with a buffer we control byte for byte.

    The first dword carries the command; the rest is whatever the caller puts
    there. Real NVIDIA escapes read a header of {cmd, size, ret, flags} and then
    dispatch on cmd, which makes the buffer the input surface.
    """
    buffer = (ctypes.c_ubyte * max(size, 8))()
    ctypes.memset(buffer, fill, len(buffer))
    ctypes.memmove(buffer, ctypes.byref(ctypes.c_uint32(command)), 4)
    ctypes.memmove(ctypes.byref(buffer, 4), ctypes.byref(ctypes.c_uint32(size)), 4)
    request = D3DKMT_ESCAPE()
    request.hAdapter = handle
    request.hDevice = device
    request.Flags = 0
    request.pPrivateDriverData = ctypes.cast(buffer, ctypes.c_void_p)
    request.PrivateDriverDataSize = len(buffer)
    request.hContext = 0
    status = gdi32.D3DKMTEscape(ctypes.byref(request))
    ret = ctypes.c_uint32.from_buffer(buffer, 8).value if len(buffer) >= 12 else None
    return {"status": status, "ret": ret}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="one D3DKMT escape")
    parser.add_argument("--adapter-index", type=int, default=0)
    parser.add_argument("--cmd", type=lambda text: int(text, 0), default=0)
    parser.add_argument("--size", type=int, default=16)
    parser.add_argument("--fill", type=lambda text: int(text, 0), default=0)
    args = parser.parse_args(argv)

    name = display_name(args.adapter_index)
    print("display: %s" % name)
    if not name:
        return 2
    opened = open_adapter(name)
    print("open adapter: status=%(status)s hAdapter=%(hAdapter)s" % opened)
    if opened["status"] != 0 or not opened["hAdapter"]:
        return 3

    made = create_device(opened["hAdapter"])
    print("create device: status=%(status)s hDevice=%(hDevice)s" % made)
    device = made["hDevice"] if made["status"] == 0 else 0
    result = escape(opened["hAdapter"], args.cmd, args.size, args.fill, device)
    print("escape cmd=0x%x size=%d device=%s -> status=%s ret=%s"
          % (args.cmd, args.size, device, result["status"], result["ret"]))
    if device:
        destroy_device(device)
    close_adapter(opened["hAdapter"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
