"""Probe: can we compile a ps_3_0 shader that carries D3DSIO_SINCOS?"""
import ctypes
from ctypes import wintypes

d3dc = ctypes.WinDLL("d3dcompiler_47.dll")
d3dc.D3DCompile.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p,
                            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p,
                            ctypes.c_char_p, wintypes.UINT, wintypes.UINT,
                            ctypes.POINTER(ctypes.c_void_p),
                            ctypes.POINTER(ctypes.c_void_p)]
d3dc.D3DCompile.restype = ctypes.c_long

SRC = b"""
float4 main(float2 uv : TEXCOORD0) : COLOR {
    float s, c;
    sincos(uv.x, s, c);
    return float4(s, c, 0, 1);
}
"""
blob = ctypes.c_void_p(); err = ctypes.c_void_p()
hr = d3dc.D3DCompile(SRC, len(SRC), b"sincos.hlsl", None, None, b"main", b"ps_3_0",
                     0, 0, ctypes.byref(blob), ctypes.byref(err))
print("D3DCompile(ps_3_0) hr=0x%08x" % (hr & 0xFFFFFFFF))
if hr == 0:
    table = ctypes.cast(ctypes.cast(blob, ctypes.POINTER(ctypes.c_void_p))[0],
                        ctypes.POINTER(ctypes.c_void_p))
    proto_ptr = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)
    proto_size = ctypes.WINFUNCTYPE(ctypes.c_size_t, ctypes.c_void_p)
    ptr = proto_ptr(table[3])(blob)
    size = proto_size(table[4])(blob)
    data = ctypes.string_at(ptr, size)
    print("bytecode bytes:", size, "| version token: 0x%08x" % int.from_bytes(data[0:4], "little"))
    tokens = [int.from_bytes(data[i:i+4], "little") for i in range(0, size, 4)]
    opcodes = [(t & 0xFFFF) for t in tokens]
    print("opcode 37 (SINCOS) present:", 37 in opcodes, "| count:", opcodes.count(37))
    print("first 8 opcodes:", [hex(o) for o in opcodes[:8]])
else:
    print("error blob:", ctypes.cast(err, ctypes.c_void_p).value)
