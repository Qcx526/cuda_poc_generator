"""D3D9 device with a real hidden window, then create the SINCOS pixel shader."""
import ctypes, sys
from ctypes import wintypes

user32 = ctypes.WinDLL("user32", use_last_error=True)
d3d9 = ctypes.WinDLL("d3d9")
d3dc = ctypes.WinDLL("d3dcompiler_47")

class PRESENT(ctypes.Structure):
    _fields_ = [("BackBufferWidth", wintypes.UINT), ("BackBufferHeight", wintypes.UINT),
                ("BackBufferFormat", wintypes.UINT), ("BackBufferCount", wintypes.UINT),
                ("MultiSampleType", wintypes.UINT), ("MultiSampleQuality", wintypes.DWORD),
                ("SwapEffect", wintypes.UINT), ("hDeviceWindow", wintypes.HWND),
                ("Windowed", wintypes.BOOL), ("EnableAutoDepthStencil", wintypes.BOOL),
                ("AutoDepthStencilFormat", wintypes.UINT), ("Flags", wintypes.DWORD),
                ("FullScreen_RefreshRateInHz", wintypes.UINT),
                ("PresentationInterval", wintypes.UINT)]

d3d9.Direct3DCreate9.argtypes = [wintypes.UINT]; d3d9.Direct3DCreate9.restype = ctypes.c_void_p
d3dc.D3DCompile.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_void_p,
                            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, wintypes.UINT,
                            wintypes.UINT, ctypes.POINTER(ctypes.c_void_p),
                            ctypes.POINTER(ctypes.c_void_p)]
d3dc.D3DCompile.restype = ctypes.c_long
user32.CreateWindowExW.restype = wintypes.HWND
user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                   wintypes.DWORD, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, wintypes.HWND, wintypes.HMENU,
                                   wintypes.HINSTANCE, wintypes.LPVOID]

SRC = b"float4 main(float2 uv : TEXCOORD0) : COLOR { float s,c; sincos(uv.x,s,c); return float4(s,c,0,1); }"

def vcall(obj, index, restype, argtypes, *args):
    table = ctypes.cast(ctypes.cast(obj, ctypes.POINTER(ctypes.c_void_p))[0],
                        ctypes.POINTER(ctypes.c_void_p))
    return ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)(table[index])(obj, *args)

blob, err = ctypes.c_void_p(), ctypes.c_void_p()
hr = d3dc.D3DCompile(SRC, len(SRC), b"s.hlsl", None, None, b"main", b"ps_3_0", 0, 0,
                     ctypes.byref(blob), ctypes.byref(err))
table = ctypes.cast(ctypes.cast(blob, ctypes.POINTER(ctypes.c_void_p))[0], ctypes.POINTER(ctypes.c_void_p))
ptr = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)(table[3])(blob)
size = ctypes.WINFUNCTYPE(ctypes.c_size_t, ctypes.c_void_p)(table[4])(blob)
code = ctypes.string_at(ptr, size)
print("compile ps_3_0 hr:", hex(hr & 0xFFFFFFFF), "bytes:", len(code))

hwnd = user32.CreateWindowExW(0, "STATIC", "cpg", 0x00CF0000, 0, 0, 64, 64, None, None, None, None)
print("hwnd:", hex(hwnd or 0))
d3d = d3d9.Direct3DCreate9(32)
pp = PRESENT(0, 0, 22, 1, 0, 0, 1, hwnd, 1, 0, 0, 0, 0, 0x80000000)
dev = ctypes.c_void_p()
hr = vcall(d3d, 14, ctypes.c_long, [wintypes.UINT, wintypes.UINT, wintypes.HWND, wintypes.DWORD,
                                    ctypes.POINTER(PRESENT), ctypes.POINTER(ctypes.c_void_p)],
           0, 1, hwnd, 0x40, ctypes.byref(pp), ctypes.byref(dev))
print("CreateDevice(HAL) hr:", hex(hr & 0xFFFFFFFF & 0xFFFFFFFF), "dev:", hex(dev.value or 0))
if hr != 0:
    hr2 = vcall(d3d, 14, ctypes.c_long, [wintypes.UINT, wintypes.UINT, wintypes.HWND, wintypes.DWORD,
                                         ctypes.POINTER(PRESENT), ctypes.POINTER(ctypes.c_void_p)],
                0, 4, hwnd, 0x40, ctypes.byref(pp), ctypes.byref(dev))
    print("CreateDevice(NULLREF) hr:", hex(hr2 & 0xFFFFFFFF), "dev:", hex(dev.value or 0))
    hr = hr2
if hr != 0: sys.exit(2)

buf = ctypes.create_string_buffer(code, len(code))
shader = ctypes.c_void_p()
hr = vcall(dev, 106, ctypes.c_long, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
           ctypes.cast(buf, ctypes.c_void_p), ctypes.byref(shader))
print("CreatePixelShader hr:", hex(hr & 0xFFFFFFFF), "shader:", hex(shader.value or 0))
print("RESULT:", "PATH WORKS" if hr == 0 else "rejected")
