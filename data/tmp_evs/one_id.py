import ctypes, struct
from ctypes import c_void_p, c_uint, c_int
dll = ctypes.WinDLL("nvapi64.dll")
qi = dll.nvapi_QueryInterface
qi.argtypes=[c_uint]; qi.restype=c_void_p
ctypes.WINFUNCTYPE(c_int)(qi(0x0150E828))()
buf = ctypes.create_string_buffer(1024)
struct.pack_into("<I", buf, 0, 1024 | (1 << 16))
addr = qi(0x6c2d048c)
print("addr:", hex(addr or 0), flush=True)
fn = ctypes.WINFUNCTYPE(c_int, c_void_p)(addr)
print("status:", fn(ctypes.byref(buf)))
