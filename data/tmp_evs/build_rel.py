"""Build a minimal ET_REL ELF64 with a real .shstrtab and one .rela.text."""
import struct, sys

def build(sh_size: int, out: str) -> None:
    shstr = b"\x00.shstrtab\x00.rela.text\x00"
    name_rela = 1 + len(".shstrtab") + 1
    rela_data = b"\x00" * 64
    ehsize, shentsize = 64, 64
    shstr_off = ehsize
    rela_off = shstr_off + len(shstr)
    data_off = rela_off + len(rela_data)
    shoff = data_off
    shnum = 3
    eh = bytearray(b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8)
    eh += struct.pack("<HHIQQQIHHHHHH", 1, 0xBE, 1, 0, 0, shoff, 0,
                      ehsize, 0, 0, shentsize, shnum, 1)
    sh = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sh += struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    sh += struct.pack("<IIQQQQIIQQ", name_rela, 4, 0, 0, rela_off, sh_size, 0, 0, 8, 24)
    open(out, "wb").write(bytes(eh) + shstr + rela_data + sh)
    print("built", out, "size", shoff + shentsize * shnum, "sh_size", sh_size)

build(int(sys.argv[1]), sys.argv[2])
