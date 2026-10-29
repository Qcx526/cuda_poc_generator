"""Register a real window class, create the window, then CreateDevice."""
import ctypes
from ctypes import POINTER, Structure, c_void_p, c_uint, c_ulong, c_int, WINFUNCTYPE
from ctypes import wintypes
from comtypes import GUID, HRESULT, COMMETHOD, IUnknown

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
d3d9 = ctypes.WinDLL("d3d9")
d3d9.Direct3DCreate9.argtypes = [c_uint]; d3d9.Direct3DCreate9.restype = c_void_p

LRESULT = ctypes.c_ssize_t
WNDPROC = WINFUNCTYPE(LRESULT, wintypes.HWND, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t)

class WNDCLASSEXW(Structure):
    _fields_ = [("cbSize", c_uint), ("style", c_uint), ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", c_int), ("cbWndExtra", c_int), ("hInstance", c_void_p),
                ("hIcon", c_void_p), ("hCursor", c_void_p), ("hbrBackground", c_void_p),
                ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR),
                ("hIconSm", c_void_p)]

@WNDPROC
def _proc(hwnd, msg, wp, lp):
    return user32.DefWindowProcW(hwnd, msg, wp, lp)

wc = WNDCLASSEXW()
wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
wc.style = 0x0020 | 0x0002  # CS_OWNDC | CS_HREDRAW
wc.lpfnWndProc = _proc
wc.hInstance = kernel32.GetModuleHandleW(None)
wc.lpszClassName = "CpgWnd"
print("RegisterClassExW:", user32.RegisterClassExW(ctypes.byref(wc)), "err:", ctypes.get_last_error())
user32.CreateWindowExW.restype = wintypes.HWND
user32.CreateWindowExW.argtypes = [c_ulong, wintypes.LPCWSTR, wintypes.LPCWSTR, c_ulong,
                                   c_int, c_int, c_int, c_int, c_void_p, c_void_p, c_void_p, c_void_p]
hwnd = user32.CreateWindowExW(0, "CpgWnd", "cpg", 0x10CF0000, 0, 0, 64, 64, None, None, wc.hInstance, None)
print("hwnd:", hex(hwnd or 0), "IsWindow:", user32.IsWindow(hwnd), "err:", ctypes.get_last_error())

class PRESENT(Structure):
    _fields_ = [("BackBufferWidth", c_uint), ("BackBufferHeight", c_uint), ("BackBufferFormat", c_uint),
                ("BackBufferCount", c_uint), ("MultiSampleType", c_uint), ("MultiSampleQuality", c_ulong),
                ("SwapEffect", c_uint), ("hDeviceWindow", wintypes.HWND), ("Windowed", wintypes.BOOL),
                ("EnableAutoDepthStencil", wintypes.BOOL), ("AutoDepthStencilFormat", c_uint),
                ("Flags", c_ulong), ("FullScreen_RefreshRateInHz", c_uint), ("PresentationInterval", c_uint)]

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
        COMMETHOD([], HRESULT, "CreateDevice", (["in"], c_uint), (["in"], c_uint), (["in"], wintypes.HWND),
                  (["in"], c_ulong), (["in"], POINTER(PRESENT)), (["in"], POINTER(c_void_p))),
    ]

d3d = ctypes.cast(d3d9.Direct3DCreate9(32), POINTER(IDirect3D9))
for flags in (0x40 | 0x2, 0x20 | 0x2, 0x2):
    pp = PRESENT(64, 64, 22, 1, 0, 0, 1, hwnd, 1, 0, 0, 0, 0, 0x80000000)
    dev = c_void_p()
    try:
        d3d.CreateDevice(0, 1, hwnd, flags, ctypes.byref(pp), ctypes.byref(dev))
        print("CreateDevice ok flags=0x%x dev=%s" % (flags, hex(dev.value or 0)))
        break
    except Exception as exc:
        print("flags=0x%x failed: %s" % (flags, exc))
