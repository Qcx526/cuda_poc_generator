"""Parse SM3 tokens properly and report where SINCOS sits."""
import ctypes
from ctypes import wintypes

d3dc = ctypes.WinDLL("d3dcompiler_47.dll")
d3dc.D3DCompile.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p,
                            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p,
                            ctypes.c_char_p, wintypes.UINT, wintypes.UINT,
                            ctypes.POINTER(ctypes.c_void_p),
                            ctypes.POINTER(ctypes.c_void_p)]
d3dc.D3DCompile.restype = ctypes.c_long

SRC = b"float4 main(float2 uv : TEXCOORD0) : COLOR { float s,c; sincos(uv.x,s,c); return float4(s,c,0,1); }"
blob = ctypes.c_void_p(); err = ctypes.c_void_p()
hr = d3dc.D3DCompile(SRC, len(SRC), b"s.hlsl", None, None, b"main", b"ps_3_0", 0, 0,
                     ctypes.byref(blob), ctypes.byref(err))
assert hr == 0, hex(hr & 0xFFFFFFFF)
table = ctypes.cast(ctypes.cast(blob, ctypes.POINTER(ctypes.c_void_p))[0], ctypes.POINTER(ctypes.c_void_p))
ptr = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)(table[3])(blob)
size = ctypes.WINFUNCTYPE(ctypes.c_size_t, ctypes.c_void_p)(table[4])(blob)
data = ctypes.string_at(ptr, size)
words = [int.from_bytes(data[i:i+4], "little") for i in range(0, size, 4)]

NAMES = {0xFFFE: "COMMENT", 0x0001: "MOV", 0x0002: "ADD", 0x0003: "SUB", 0x0004: "MAD",
         0x0005: "MUL", 0x0006: "RCP", 0x0007: "RSQ", 0x0008: "DP3", 0x0009: "DP4",
         0x000A: "MIN", 0x000B: "MAX", 0x000C: "SLT", 0x000D: "SGE", 0x000E: "EXP",
         0x000F: "LOG", 0x0010: "LIT", 0x0011: "DST", 0x0012: "LRP", 0x0013: "FRC",
         0x0014: "M4x4", 0x0015: "M4x3", 0x0016: "M3x4", 0x0017: "M3x3", 0x0018: "M3x2",
         0x0019: "CALL", 0x001A: "CALLNZ", 0x001B: "LOOP", 0x001C: "RET", 0x001D: "ENDLOOP",
         0x001E: "LABEL", 0x001F: "DCL", 0x0020: "POW", 0x0021: "CRS", 0x0022: "SGN",
         0x0023: "ABS", 0x0024: "NRM", 0x0025: "SINCOS"}
i = 0
while i < len(words):
    tok = words[i]
    if tok == 0x0000FFFF or tok == 0x0000FFFE:
        op, length = 0xFFFE, (tok >> 16) & 0x7FFF
        i += max(1, length)
        continue
    op, length = tok & 0xFFFF, (tok >> 24) & 0xF
    if op == 0x0000:  # version token
        print("token[%2d] VERSION 0x%08x" % (i, tok)); i += 1; continue
    print("token[%2d] %-7s len=%2d  tokens=%s" % (i, NAMES.get(op, hex(op)), length,
                                                  [hex(w) for w in words[i:i+length]]))
    if op == 0x0025:
        print("        ^ SINCOS at dword offset %d (byte %d)" % (i, i*4))
    i += max(1, length)
