# -*- coding: utf-8 -*-
"""The one ABI definition every generated PoC is required to reuse.

The bug this replaces was mechanical, not conceptual: generated programs declared
D3DKMT handles as pointers. On x64 that silently makes every following field sit
eight bytes too late, so the driver reads garbage and the process dies with an
access violation before any call is even attributable.

Facts encoded here are taken from the installed Windows SDK headers
(10.0.26100.0) and are not negotiable from the prompt side:

* ``D3DKMT_HANDLE`` is ``UINT`` - four bytes, not a pointer.
* ``D3DKMT_PTR(Type, Name)`` on Windows is plain ``Type Name`` - ``HDC`` is a
  pointer (eight bytes), a handle is not.
* user-mode ``D3DKMT_*`` structures are **not** the kernel ``DXGKARG_*`` ones;
  their field offsets differ and must never be mixed.
* ``NTSTATUS`` is signed 32-bit; ``0xC000000D`` prints as ``-1073741811``.

Layout was computed from the header field order under the MSVC x64 rules and then
re-derived by ctypes. It is *not* compiler-verified: this machine has no C/C++
toolchain, and the report says so rather than implying otherwise.
"""

import ctypes
from ctypes import POINTER, Structure, Union, byref, c_int32, c_uint32, c_void_p, c_wchar_p

NTSTATUS = c_int32
D3DKMT_HANDLE = c_uint32          # UINT, 4 bytes - the whole point of this module
HANDLE = c_void_p
HDC = c_void_p
ULONG = c_uint32


class LUID_T(Structure):
    """A real LUID, not a pointer.

    Modelling this as c_void_p made it eight-byte aligned and pushed every later
    field four bytes too far; the compiled reference caught it (sizeof 24 vs 32).
    """

    _fields_ = [("LowPart", c_uint32), ("HighPart", c_int32)]


class D3DDDI_ESCAPEFLAGS(Union):
    _fields_ = [("Value", c_uint32)]


class D3DKMT_ESCAPE(Structure):
    """User-mode escape packet: handles are 4 bytes, pointers 8."""

    _fields_ = [
        ("hAdapter", D3DKMT_HANDLE),
        ("hDevice", D3DKMT_HANDLE),
        ("Type", c_uint32),
        ("Flags", D3DDDI_ESCAPEFLAGS),
        ("pPrivateDriverData", c_void_p),
        ("PrivateDriverDataSize", c_uint32),
        ("hContext", D3DKMT_HANDLE),
    ]


class D3DKMT_OPENADAPTERFROMHDC(Structure):
    _fields_ = [
        ("hDc", HDC),
        ("hAdapter", D3DKMT_HANDLE),
        ("AdapterLuid", LUID_T),
        ("VidPnSourceId", c_uint32),
    ]


class D3DKMT_OPENADAPTERFROMLUID(Structure):
    _fields_ = [("AdapterLuid", LUID_T), ("hAdapter", D3DKMT_HANDLE)]


class D3DKMT_CREATEDEVICEFLAGS(Union):
    _fields_ = [("Value", c_uint32)]


class D3DKMT_CREATEDEVICE_ADAPTER(Union):
    """The header puts hAdapter and pAdapter in one union.

    The pointer member makes the union eight bytes even though the handle member
    is four, so everything after it shifts - which is why a four-byte modelling
    produced a zero hDevice and an INVALID_PARAMETER on the next call.
    """

    _fields_ = [("hAdapter", D3DKMT_HANDLE), ("pAdapter", c_void_p)]


class D3DKMT_CREATEDEVICE(Structure):
    _fields_ = [
        ("Adapter", D3DKMT_CREATEDEVICE_ADAPTER),
        ("Flags", D3DKMT_CREATEDEVICEFLAGS),
        ("hDevice", D3DKMT_HANDLE),
        ("pCommandBuffer", c_void_p),
        ("CommandBufferSize", c_uint32),
        ("pAllocationList", c_void_p),
        ("AllocationListSize", c_uint32),
        ("pPatchLocationList", c_void_p),
        ("PatchLocationListSize", c_uint32),
    ]


class D3DDDI_CREATECONTEXTFLAGS(Union):
    _fields_ = [("Value", c_uint32)]


class D3DKMT_CREATECONTEXT(Structure):
    _fields_ = [
        ("hDevice", D3DKMT_HANDLE),
        ("NodeOrdinal", c_uint32),
        ("EngineAffinity", c_uint32),
        ("Flags", D3DDDI_CREATECONTEXTFLAGS),
        ("pPrivateDriverData", c_void_p),
        ("PrivateDriverDataSize", c_uint32),
        ("ClientHint", c_uint32),
        ("hContext", D3DKMT_HANDLE),
        ("pCommandBuffer", c_void_p),
        ("CommandBufferSize", c_uint32),
        ("pAllocationList", c_void_p),
        ("AllocationListSize", c_uint32),
        ("pPatchLocationList", c_void_p),
        ("PatchLocationListSize", c_uint32),
        ("CommandBuffer", ctypes.c_uint64),
    ]


class D3DKMT_DESTROYCONTEXT(Structure):
    _fields_ = [("hContext", D3DKMT_HANDLE)]


class D3DKMT_DESTROYDEVICE(Structure):
    _fields_ = [("hDevice", D3DKMT_HANDLE)]


class D3DKMT_CLOSEADAPTER(Structure):
    _fields_ = [("hAdapter", D3DKMT_HANDLE)]


class DISPLAY_DEVICEW(Structure):
    _fields_ = [("cb", c_uint32),
                ("DeviceName", ctypes.c_wchar * 32),
                ("DeviceString", ctypes.c_wchar * 128),
                ("StateFlags", c_uint32),
                ("DeviceID", ctypes.c_wchar * 128),
                ("DeviceKey", ctypes.c_wchar * 128)]


def bind_gdi32():
    """Resolve the D3DKMT entry points once, with exact signatures.

    ``argtypes`` is set because ctypes otherwise truncates pointers on x64, which
    looks like a driver rejection rather than a marshalling bug.
    """
    gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
    specs = {
        "D3DKMTOpenAdapterFromHdc": [POINTER(D3DKMT_OPENADAPTERFROMHDC)],
        "D3DKMTOpenAdapterFromLuid": [POINTER(D3DKMT_OPENADAPTERFROMLUID)],
        "D3DKMTCreateDevice": [POINTER(D3DKMT_CREATEDEVICE)],
        "D3DKMTCreateContext": [POINTER(D3DKMT_CREATECONTEXT)],
        "D3DKMTDestroyContext": [POINTER(D3DKMT_DESTROYCONTEXT)],
        "D3DKMTDestroyDevice": [POINTER(D3DKMT_DESTROYDEVICE)],
        "D3DKMTCloseAdapter": [POINTER(D3DKMT_CLOSEADAPTER)],
        "D3DKMTEscape": [POINTER(D3DKMT_ESCAPE)],
    }
    for name, argtypes in specs.items():
        function = getattr(gdi32, name)
        function.argtypes = argtypes
        function.restype = NTSTATUS
    return gdi32


def bind_user32():
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetDC.argtypes = [c_void_p]
    user32.GetDC.restype = HDC
    user32.ReleaseDC.argtypes = [c_void_p, HDC]
    user32.ReleaseDC.restype = c_int32
    user32.EnumDisplayDevicesW.argtypes = [c_wchar_p, c_uint32,
                                           POINTER(DISPLAY_DEVICEW), c_uint32]
    user32.EnumDisplayDevicesW.restype = c_int32
    return user32


def bind_gdi_dc():
    """A DC for one display, which is what OpenAdapterFromHdc expects.

    A screen DC from GetDC(NULL) is not tied to a single display, and the call
    rejects it with STATUS_INVALID_PARAMETER - a marshalling-looking failure that
    is really a wrong-handle-type failure.
    """
    gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
    gdi32.CreateDCW.argtypes = [c_wchar_p, c_wchar_p, c_wchar_p, c_void_p]
    gdi32.CreateDCW.restype = HDC
    gdi32.DeleteDC.argtypes = [HDC]
    gdi32.DeleteDC.restype = c_int32
    return gdi32


def ntstatus(value: int) -> str:
    """Print an NTSTATUS the way the driver returns it: signed, hex, name."""
    signed = value - (1 << 32) if value > 0x7FFFFFFF else value
    names = {0: "STATUS_SUCCESS", -1073741811: "STATUS_INVALID_PARAMETER",
             -1073741823: "STATUS_UNSUCCESSFUL", -1073741790: "STATUS_ACCESS_DENIED",
             -1073741637: "STATUS_INVALID_DEVICE_REQUEST"}
    return "%s (0x%08X / %d)" % (names.get(signed, "NTSTATUS"), value & 0xFFFFFFFF, signed)


LAYOUT = {
    "D3DKMT_ESCAPE": D3DKMT_ESCAPE,
    "D3DKMT_OPENADAPTERFROMHDC": D3DKMT_OPENADAPTERFROMHDC,
    "D3DKMT_OPENADAPTERFROMLUID": D3DKMT_OPENADAPTERFROMLUID,
    "D3DKMT_CREATEDEVICE": D3DKMT_CREATEDEVICE,
    "D3DKMT_CREATECONTEXT": D3DKMT_CREATECONTEXT,
    "D3DKMT_DESTROYCONTEXT": D3DKMT_DESTROYCONTEXT,
    "DISPLAY_DEVICEW": DISPLAY_DEVICEW,
}


def layout_report() -> dict:
    """sizeof/alignof/offsetof for every structure, computed by ctypes."""
    out = {}
    for name, structure in LAYOUT.items():
        fields = {}
        for field_name, _ in structure._fields_:
            fields[field_name] = getattr(structure, field_name).offset
        out[name] = {"sizeof": ctypes.sizeof(structure),
                     "alignof": ctypes.alignment(structure),
                     "offsets": fields}
    return out


def r0_selftest() -> list:
    """Exercise the public, harmless path and report each step.

    This is the gate both experiment groups must pass: it does not depend on any
    model output, and it never sends a private escape body.
    """
    steps = []
    gdi32 = bind_gdi32()
    user32 = bind_user32()

    device = DISPLAY_DEVICEW()
    device.cb = ctypes.sizeof(DISPLAY_DEVICEW)
    enumerated = user32.EnumDisplayDevicesW(None, 0, byref(device), 0)
    steps.append({"step": "enum_display", "ok": bool(enumerated),
                  "detail": device.DeviceName if enumerated else "no device"})

    name = device.DeviceName if enumerated else None
    gdi = bind_gdi_dc()
    hdc = gdi.CreateDCW("DISPLAY", name, None, None)
    steps.append({"step": "create_dc", "ok": bool(hdc),
                  "detail": "device=%s hdc=0x%x" % (name, hdc or 0)})
    if not hdc:
        return steps

    open_adapter = D3DKMT_OPENADAPTERFROMHDC()
    open_adapter.hDc = hdc
    status = gdi32.D3DKMTOpenAdapterFromHdc(byref(open_adapter))
    steps.append({"step": "open_adapter", "ok": status == 0, "status": ntstatus(status),
                  "hAdapter": open_adapter.hAdapter})
    if status != 0:
        gdi.DeleteDC(hdc)
        return steps

    create_device = D3DKMT_CREATEDEVICE()
    create_device.Adapter.hAdapter = open_adapter.hAdapter
    create_device.Flags.Value = 0
    status = gdi32.D3DKMTCreateDevice(byref(create_device))
    steps.append({"step": "create_device", "ok": status == 0, "status": ntstatus(status),
                  "hDevice": create_device.hDevice})
    if status != 0:
        gdi32.D3DKMTCloseAdapter(byref(D3DKMT_CLOSEADAPTER(open_adapter.hAdapter)))
        gdi.DeleteDC(hdc)
        return steps

    create_context = D3DKMT_CREATECONTEXT()
    create_context.hDevice = create_device.hDevice
    create_context.NodeOrdinal = 0
    create_context.EngineAffinity = 0
    create_context.Flags.Value = 0
    create_context.ClientHint = 0
    status = gdi32.D3DKMTCreateContext(byref(create_context))
    steps.append({"step": "create_context", "ok": status == 0, "status": ntstatus(status),
                  "hContext": create_context.hContext})
    if status == 0:
        destroy = gdi32.D3DKMTDestroyContext(byref(D3DKMT_DESTROYCONTEXT(create_context.hContext)))
        steps.append({"step": "destroy_context", "ok": destroy == 0,
                      "status": ntstatus(destroy)})

    destroyed = gdi32.D3DKMTDestroyDevice(byref(D3DKMT_DESTROYDEVICE(create_device.hDevice)))
    steps.append({"step": "destroy_device", "ok": destroyed == 0, "status": ntstatus(destroyed)})
    gdi32.D3DKMTCloseAdapter(byref(D3DKMT_CLOSEADAPTER(open_adapter.hAdapter)))
    gdi.DeleteDC(hdc)
    return steps


if __name__ == "__main__":
    import json
    import sys

    if "--layout" in sys.argv:
        print(json.dumps(layout_report(), ensure_ascii=False, indent=2))
    else:
        for item in r0_selftest():
            print(json.dumps(item, ensure_ascii=False))
