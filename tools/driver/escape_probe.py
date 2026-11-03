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
    """D3DKMT_ESCAPE in WDK order: Type at 8, Flags at 12.

    An earlier version of this file had no Type member, so the value passed as
    "flags" landed in Type and the real Flags slot stayed zero. Every result
    produced with that layout describes a different call than the one intended.
    """
    _fields_ = [("hAdapter", wintypes.UINT),                 # 0
                ("hDevice", wintypes.UINT),                  # 4
                ("Type", wintypes.UINT),                     # 8
                ("Flags", wintypes.UINT),                    # 12
                ("pPrivateDriverData", ctypes.c_void_p),     # 16
                ("PrivateDriverDataSize", wintypes.UINT),    # 24
                ("hContext", wintypes.UINT)]                 # 28


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
    """The full 64-byte structure, not a four-field abbreviation.

    The first member is a union of ``hAdapter`` and ``pAdapter``; because the
    pointer is 8 bytes on x64, ``Flags`` sits at 8 and the returned ``hDevice``
    at 12. An abbreviated structure both reads the wrong field and hands the API
    a buffer shorter than it was written for.
    """
    _fields_ = [("hAdapter", wintypes.UINT),                  # 0  union low half
                ("Reserved0", wintypes.UINT),                 # 4  union high half
                ("Flags", wintypes.UINT),                     # 8
                ("hDevice", wintypes.UINT),                   # 12  out
                ("pCommandBuffer", ctypes.c_void_p),          # 16
                ("CommandBufferSize", wintypes.UINT),         # 24
                ("pAllocationList", ctypes.c_void_p),         # 32
                ("AllocationListSize", wintypes.UINT),        # 40
                ("pPatchLocationList", ctypes.c_void_p),      # 48
                ("PatchLocationListSize", wintypes.UINT)]     # 56


class D3DKMT_DESTROYDEVICE(ctypes.Structure):
    _fields_ = [("hDevice", wintypes.UINT)]


def create_device(handle: int) -> dict:
    """A device on the adapter; the handle comes back at offset 12.

    NVIDIA's escapes are dispatched per device, not per adapter, so this must
    succeed before any escape means anything. The success flag alone is not
    enough: ``hDevice`` is checked to be non-zero and different from the adapter,
    because a handle equal to the adapter is the signature of reading the wrong
    field.
    """
    request = D3DKMT_CREATEDEVICE()
    request.hAdapter = handle
    request.Flags = 0
    status = gdi32.D3DKMTCreateDevice(ctypes.byref(request))
    device = request.hDevice
    usable = status == 0 and device not in (0, handle)
    return {"status": status, "hDevice": device, "usable": usable}


def destroy_device(handle: int) -> int:
    return gdi32.D3DKMTDestroyDevice(ctypes.byref(D3DKMT_DESTROYDEVICE(hDevice=handle)))


def escape(handle: int, command: int, size: int, fill: int = 0x00,
           device: int = 0, escape_type: int = 0, flags: int = 0) -> dict:
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
    request.Type = escape_type
    request.Flags = flags
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
    print("create device: status=%(status)s hDevice=%(hDevice)s usable=%(usable)s" % made)
    device = made["hDevice"] if made.get("usable") else 0
    result = escape(opened["hAdapter"], args.cmd, args.size, args.fill, device)
    print("escape cmd=0x%x size=%d device=%s -> status=%s ret=%s"
          % (args.cmd, args.size, device, result["status"], result["ret"]))
    if device:
        destroy_device(device)
    close_adapter(opened["hAdapter"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
