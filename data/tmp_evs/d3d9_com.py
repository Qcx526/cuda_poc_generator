"""D3D9 device via comtypes: proper vtable, HRESULT instead of a crash."""
import ctypes
from ctypes import POINTER, Structure, c_void_p, c_uint, c_ulong, c_int
from ctypes import wintypes
from comtypes import GUID, HRESULT, COMMETHOD, IUnknown

user32 = ctypes.WinDLL("user32")
d3d9 = ctypes.WinDLL("d3d9")
d3d9.Direct3DCreate9.argtypes = [c_uint]; d3d9.Direct3DCreate9.restype = c_void_p

class PRESENT(Structure):
    _fields_ = [("BackBufferWidth", c_uint), ("BackBufferHeight", c_uint),
                ("BackBufferFormat", c_uint), ("BackBufferCount", c_uint),
                ("MultiSampleType", c_uint), ("MultiSampleQuality", c_ulong),
                ("SwapEffect", c_uint), ("hDeviceWindow", wintypes.HWND),
                ("Windowed", wintypes.BOOL), ("EnableAutoDepthStencil", wintypes.BOOL),
                ("AutoDepthStencilFormat", c_uint), ("Flags", c_ulong),
                ("FullScreen_RefreshRateInHz", c_uint), ("PresentationInterval", c_uint)]

class IDirect3D9(IUnknown):
    _iid_ = GUID("{81BDCBCA-64D4-426d-AE8D-AD0147F4275C}")
    _methods_ = [
        COMMETHOD([], HRESULT, "RegisterSoftwareDevice", (["in"], c_void_p)),
        COMMETHOD([], c_uint, "GetAdapterCount"),
        COMMETHOD([], HRESULT, "GetAdapterIdentifier", (["in"], c_uint), (["in"], c_ulong), (["in"], c_void_p)),
        COMMETHOD([], c_uint, "GetAdapterModeCount", (["in"], c_uint), (["in"], c_uint)),
        COMMETHOD([], HRESULT, "EnumAdapterModes", (["in"], c_uint), (["in"], c_uint), (["in"], c_uint), (["in"], c_void_p)),
        COMMETHOD([], HRESULT, "GetAdapterDisplayMode", (["in"], c_uint), (["in"], c_void_p)),
        COMMETHOD([], HRESULT, "CheckDeviceType", (["in"], c_uint), (["in"], c_uint), (["in"], c_uint), (["in"], c_uint), (["in"], wintypes.BOOL)),
        COMMETHOD([], HRESULT, "CheckDeviceFormat", (["in"], c_uint), (["in"], c_uint), (["in"], c_uint), (["in"], c_ulong), (["in"], c_uint), (["in"], c_uint)),
        COMMETHOD([], HRESULT, "CheckDeviceMultiSampleType", (["in"], c_uint), (["in"], c_uint), (["in"], c_uint), (["in"], wintypes.BOOL), (["in"], c_uint), (["in"], c_void_p)),
        COMMETHOD([], HRESULT, "CheckDepthStencilMatch", (["in"], c_uint), (["in"], c_uint), (["in"], c_uint), (["in"], c_uint), (["in"], c_uint)),
        COMMETHOD([], c_void_p, "GetAdapterMonitor", (["in"], c_uint)),
        COMMETHOD([], HRESULT, "CreateDevice",
                  (["in"], c_uint, "Adapter"), (["in"], c_uint, "DeviceType"),
                  (["in"], c_void_p, "hFocusWindow"), (["in"], c_ulong, "BehaviorFlags"),
                  (["in"], POINTER(PRESENT), "pPresentationParameters"),
                  (["in"], POINTER(c_void_p), "ppReturnedDeviceInterface")),
    ]

hwnd = user32.CreateWindowExW(0, "STATIC", "cpg", 0x00CF0000, 0, 0, 64, 64, None, None, None, None)
d3d = ctypes.cast(d3d9.Direct3DCreate9(32), POINTER(IDirect3D9))
print("adapter count:", d3d.GetAdapterCount())
pp = PRESENT(64, 64, 22, 1, 0, 0, 1, hwnd, 1, 0, 0, 0, 0, 0x80000000)
dev = c_void_p()
try:
    hr = d3d.CreateDevice(0, 1, hwnd, 0x40, ctypes.byref(pp), ctypes.byref(dev))
    print("CreateDevice ok, dev:", hex(dev.value or 0))
except Exception as exc:
    print("CreateDevice failed:", exc)
