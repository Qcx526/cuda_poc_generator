"""Append one SHT_RELA section to a real cubin and shrink its sh_size."""
import struct, subprocess, sys

def main(sh_size: int, out: str) -> None:
    open("/tmp/k.cu", "w").write("__global__ void k(){}\n")
    subprocess.run(["nvcc", "-cubin", "/tmp/k.cu", "-o", "/tmp/base.cubin"], check=True)
    d = bytearray(open("/tmp/base.cubin", "rb").read())
    e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
    table = bytes(d[e_shoff:e_shoff + e_shentsize * e_shnum])
    data_off = len(d)
    d += b"\x00" * 64                                   # section body
    new_off = len(d)
    d += table + struct.pack("<IIQQQQIIQQ", 0, 4, 0, 0, data_off, sh_size, 0, 0, 24, 0)
    struct.pack_into("<Q", d, 0x28, new_off)            # e_shoff -> new table
    struct.pack_into("<H", d, 0x3C, e_shnum + 1)        # e_shnum
    open(out, "wb").write(d)
    print("built", out, "sections:", e_shnum + 1, "sh_size:", sh_size)

main(int(sys.argv[1], 0), sys.argv[2])
