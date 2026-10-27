# -*- coding: utf-8 -*-
"""Reach the GPU driver through D3DKMT, the documented graphics interface.

NVAPI turned out to keep its transport private, which makes anything learned
from it vendor-specific. D3DKMT is the Windows graphics stack's own interface:
the same calls reach NVIDIA, AMD and Intel drivers, so a technique built here
carries over instead of dying with one vendor's DLL.

The probe climbs in three stages, each separate, because each one tells you
whether the next is worth trying:

  1. adapter  open an adapter from a display DC - no allocation, no command
  2. device   create a device on that adapter - driver allocates state
  3. escape   send one private escape - the driver runs its own handler

  python -m tools.probe_d3dkmt --stage adapter
  python -m tools.probe_d3dkmt --stage device
"""

import argparse
import ctypes
import json
from ctypes import wintypes
from pathlib import Path

gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)

# Handles are 64-bit: leaving the default restype truncates them, and a truncated
# DC is rejected as an invalid parameter rather than as a wrong handle.
gdi32.CreateDCW.restype = ctypes.c_void_p
gdi32.CreateDCW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                            wintypes.LPCWSTR, ctypes.c_void_p]
gdi32.DeleteDC.restype = wintypes.BOOL
gdi32.DeleteDC.argtypes = [ctypes.c_void_p]

STATUS_SUCCESS = 0


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class OPENADAPTERFROMHDC(ctypes.Structure):
    _fields_ = [("hDc", wintypes.HDC),
                ("hAdapter", wintypes.UINT),
                ("AdapterLuid", LUID),
                ("VidPnSourceId", wintypes.UINT)]


class CREATEDEVICEFLAGS(ctypes.Structure):
    _fields_ = [("Value", wintypes.UINT)]


class CREATEDEVICE(ctypes.Structure):
    """Layout taken from what the driver actually writes, not from a header.

    A zeroed request was sent and the buffer read back: offset 0 kept the adapter
    handle and offset 12 came back holding a new handle that DestroyDevice
    accepted. So Flags occupy offset 8 and hDevice follows at 12 - the union
    reading in the WDK header does not describe this build.
    """
    _fields_ = [("hAdapter", wintypes.UINT),
                ("Reserved0", wintypes.UINT),
                ("Flags", CREATEDEVICEFLAGS),
                ("hDevice", wintypes.UINT),
                ("pCommandBuffer", ctypes.c_void_p),
                ("CommandBufferSize", wintypes.UINT),
                ("pAllocationList", ctypes.c_void_p),
                ("AllocationListSize", wintypes.UINT),
                ("pPatchLocationList", ctypes.c_void_p),
                ("PatchLocationListSize", wintypes.UINT)]


class ESCAPE(ctypes.Structure):
    """Flags precede the escape code: a code read from the wrong offset is an
    invalid parameter, which looks exactly like a driver that rejects the code."""
    _fields_ = [("hAdapter", wintypes.UINT),
                ("hDevice", wintypes.UINT),
                ("Flags", wintypes.UINT),
                ("EscapeCode", wintypes.UINT),
                ("pPrivateDriverData", ctypes.c_void_p),
                ("PrivateDriverDataSize", wintypes.UINT),
                ("hContext", wintypes.UINT)]


class DISPLAY_DEVICEW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD),
                ("DeviceName", wintypes.WCHAR * 32),
                ("DeviceString", wintypes.WCHAR * 128),
                ("StateFlags", wintypes.DWORD),
                ("DeviceID", wintypes.WCHAR * 128),
                ("DeviceKey", wintypes.WCHAR * 128)]


def first_display() -> str:
    """The display whose DC can be opened; 'DISPLAY' alone is not enough."""
    device = DISPLAY_DEVICEW()
    device.cb = ctypes.sizeof(device)
    index = 0
    while user32.EnumDisplayDevicesW(None, index, ctypes.byref(device), 0):
        if device.StateFlags & 0x1:  # DISPLAY_DEVICE_ATTACHED_TO_DESKTOP
            return device.DeviceName
        index += 1
        device.cb = ctypes.sizeof(device)
    raise RuntimeError("no attached display found")


class OPENADAPTERFROMLUID(ctypes.Structure):
    _fields_ = [("AdapterLuid", LUID), ("hAdapter", wintypes.UINT)]


def open_adapter_from_luid(luid) -> int:
    """The route the published PoCs use; also the one that yields a usable handle."""
    request = OPENADAPTERFROMLUID()
    request.AdapterLuid = luid
    status = gdi32.D3DKMTOpenAdapterFromLuid(ctypes.byref(request))
    return status, request.hAdapter


def open_adapter_from_hdc(device_name: str = ""):
    """Open an adapter through a display DC: no window, no D3D runtime."""
    if not device_name:
        device_name = first_display()
    hdc = gdi32.CreateDCW("DISPLAY", device_name, None, None)
    if not hdc:
        raise OSError(ctypes.get_last_error(), "CreateDCW failed")
    request = OPENADAPTERFROMHDC()
    request.hDc = hdc
    status = gdi32.D3DKMTOpenAdapterFromHdc(ctypes.byref(request))
    return status, request, hdc


def create_device(h_adapter: int):
    request = CREATEDEVICE()
    request.hAdapter = h_adapter
    status = gdi32.D3DKMTCreateDevice(ctypes.byref(request))
    return status, request


def device_handle(request) -> int:
    return request.hDevice


class DESTROYDEVICE(ctypes.Structure):
    _fields_ = [("hDevice", wintypes.UINT)]


def destroy_device(h_adapter: int, h_device: int) -> int:
    request = DESTROYDEVICE()
    request.hDevice = h_device
    return gdi32.D3DKMTDestroyDevice(ctypes.byref(request))


def send_escape(h_adapter: int, h_device: int, code: int, payload: bytes):
    buffer = ctypes.create_string_buffer(payload, len(payload))
    request = ESCAPE()
    request.hAdapter = h_adapter
    request.hDevice = h_device
    request.EscapeCode = code
    request.pPrivateDriverData = ctypes.cast(buffer, ctypes.c_void_p)
    request.PrivateDriverDataSize = len(payload)
    status = gdi32.D3DKMTEscape(ctypes.byref(request))
    return status, buffer


def main() -> int:
    parser = argparse.ArgumentParser(description="climb the D3DKMT interface")
    parser.add_argument("--stage", default="adapter",
                        choices=["adapter", "device", "escape"])
    parser.add_argument("--escape-code", default="0x0")
    parser.add_argument("--payload-size", type=int, default=16)
    parser.add_argument("--json", default="data/probe/d3dkmt.json")
    args = parser.parse_args()

    report = {"stage": args.stage}
    # The DC route gives a LUID but its handle is refused by every later call;
    # opening again by that LUID yields one the driver accepts.
    status, request, hdc = open_adapter_from_hdc()
    luid_text = "%08x:%08x" % (request.AdapterLuid.HighPart & 0xFFFFFFFF,
                               request.AdapterLuid.LowPart)
    print("adapter by HDC status=%d handle=0x%x luid=%s"
          % (status, request.hAdapter, luid_text))
    if status != STATUS_SUCCESS:
        print("no adapter; nothing further is possible")
        return 1

    luid_status, h_adapter = open_adapter_from_luid(request.AdapterLuid)
    report["open_adapter"] = {"status": luid_status, "h_adapter": h_adapter,
                              "luid": luid_text,
                              "hdc_handle": request.hAdapter}
    print("adapter by LUID status=%d handle=0x%x" % (luid_status, h_adapter))
    if luid_status != STATUS_SUCCESS or not h_adapter:
        print("adapter handle unusable; stopping here")
        return 1

    if args.stage == "adapter":
        gdi32.DeleteDC(hdc)
        _write(report, args.json)
        return 0

    device_status, device = create_device(h_adapter)
    handle = device_handle(device)
    report["create_device"] = {"status": device_status, "h_device": handle}
    print("create device  status=%d handle=0x%x" % (device_status, handle))
    if device_status != STATUS_SUCCESS or not handle:
        print("device not created; escape would have no target")
        gdi32.DeleteDC(hdc)
        return 1

    if args.stage == "device":
        destroy_device(h_adapter, handle)
        gdi32.DeleteDC(hdc)
        _write(report, args.json)
        return 0

    code = int(args.escape_code, 16) if args.escape_code.lower().startswith("0x") \
        else int(args.escape_code)
    payload = bytes(args.payload_size)
    escape_status, _ = send_escape(h_adapter, handle, code, payload)
    report["escape"] = {"code": "0x%x" % code, "payload_size": args.payload_size,
                        "status": escape_status}
    print("escape         code=0x%x size=%d status=%d"
          % (code, args.payload_size, escape_status))

    destroy_device(h_adapter, handle)
    gdi32.DeleteDC(hdc)
    _write(report, args.json)
    return 0 if escape_status == STATUS_SUCCESS else 1


def _write(report, path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    history = []
    if target.is_file():
        try:
            history = json.loads(target.read_text(encoding="utf-8")).get("history", [])
        except ValueError:
            history = []
    history.append(report)
    target.write_text(json.dumps({"history": history}, ensure_ascii=False, indent=2),
                      encoding="utf-8")
    print("written to %s" % target)


if __name__ == "__main__":
    raise SystemExit(main())
