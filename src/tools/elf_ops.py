"""ELF64 cubin operations — parse, find, modify, validate sections.

Battle-tested against CUDA 11.2 cubin files on Windows.
Uses only struct from stdlib — no pyelftools or external dependencies.

Standard ELF64 section header format: <IIQQQQIIQQ (64 bytes, 10 fields)
  Field indices: 0=sh_name, 1=sh_type, 2=sh_flags, 3=sh_addr,
                 4=sh_offset, 5=sh_size, 6=sh_link, 7=sh_info,
                 8=sh_addralign, 9=sh_entsize
"""

import os
import struct
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ELF64_SHDR_FMT = "<IIQQQQIIQQ"
ELF64_SHDR_SIZE = 64
SHT_REL = 9
SHT_RELA = 4
SHT_PROGBITS = 1
SHT_SYMTAB = 2

# Offsets within ELF64 header
EHDR_SHOFF = 0x28      # e_shoff
EHDR_SHENTSIZE = 0x3A  # e_shentsize
EHDR_SHNUM = 0x3C      # e_shnum
EHDR_SHSTRNDX = 0x3E   # e_shstrndx


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------

def find_section(data: bytes, name: str) -> Optional[Tuple[int, Tuple]]:
    """Find a section by name. Returns (index, header_tuple) or None."""
    sections = parse_all_sections(data)
    strtab = _read_shstrtab(data)
    for idx, hdr in enumerate(sections):
        n = _section_name(strtab, hdr[0])
        if n == name:
            return idx, hdr
    return None


def find_sections_by_type(data: bytes, section_type: int) -> List[Tuple[int, Tuple]]:
    """Find all sections of a given type. Returns list of (index, header_tuple)."""
    sections = parse_all_sections(data)
    return [(i, h) for i, h in enumerate(sections) if h[1] == section_type]


def replace_section_content(
    data: bytes, section_name: str, new_content: bytes, output_path: Optional[str] = None
) -> bytes:
    """Replace a section's content by appending new data at end-of-file and
    updating the section header. Returns the modified bytes.

    If ``output_path`` is provided, the result is also written to that file.
    Does NOT add new section headers — modifies existing one in-place.
    """
    sections = parse_all_sections(data)
    strtab = _read_shstrtab(data)
    target_idx = None
    for idx, hdr in enumerate(sections):
        if _section_name(strtab, hdr[0]) == section_name:
            target_idx = idx
            break
    if target_idx is None:
        raise ValueError(f"Section '{section_name}' not found")

    working = bytearray(data)
    new_offset = len(working)
    working.extend(new_content)
    _patch_shdr_field(working, target_idx, 4, new_offset)   # sh_offset
    _patch_shdr_field(working, target_idx, 5, len(new_content))  # sh_size

    if output_path is not None:
        with open(output_path, "wb") as f:
            f.write(working)
    return bytes(working)


def append_section(
    data: bytes, name: str, body: bytes, section_type: Optional[int] = None
) -> bytes:
    """Append a new section to an ELF64 cubin.

    The new section header is added to the section header table, `.shstrtab`
    is extended with the new name, and the ELF header is updated to point to
    the new section header table. The modified ELF data is returned as bytes.

    If ``section_type`` is not supplied, it is inferred from the section name:
      * `.rel*`  -> SHT_REL
      * `.rela*` -> SHT_RELA
      * otherwise -> SHT_PROGBITS
    """
    working = bytearray(data)

    e_shoff = struct.unpack_from("<Q", working, EHDR_SHOFF)[0]
    e_shentsize = struct.unpack_from("<H", working, EHDR_SHENTSIZE)[0]
    e_shnum = struct.unpack_from("<H", working, EHDR_SHNUM)[0]
    e_shstrndx = struct.unpack_from("<H", working, EHDR_SHSTRNDX)[0]

    if e_shnum == 0 or e_shstrndx >= e_shnum:
        raise ValueError("Invalid ELF section header info")

    # Parse all existing section headers as mutable lists.
    shdrs: List[List] = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        shdrs.append(list(struct.unpack(ELF64_SHDR_FMT, working[off:off + e_shentsize])))

    # Read .shstrtab and append the new name.
    shstr_hdr = shdrs[e_shstrndx]
    shstr_off = shstr_hdr[4]
    shstr_size = shstr_hdr[5]
    shstrtab = bytearray(working[shstr_off:shstr_off + shstr_size])

    name_bytes = name.encode("utf-8") + b"\x00"
    name_offset = len(shstrtab)
    shstrtab.extend(name_bytes)

    # Infer section type if not provided.
    if section_type is None:
        if name.startswith(".rela"):
            section_type = SHT_RELA
        elif name.startswith(".rel"):
            section_type = SHT_REL
        else:
            section_type = SHT_PROGBITS

    # Append the new section body (aligned to 8 bytes).
    body = body or b""
    padding = (8 - (len(working) % 8)) % 8
    working.extend(b"\x00" * padding)
    new_offset = len(working)
    working.extend(body)
    new_size = len(body)

    # Move .shstrtab to the end of the file with its updated content.
    new_shstr_offset = len(working)
    working.extend(shstrtab)
    shstr_hdr[4] = new_shstr_offset
    shstr_hdr[5] = len(shstrtab)

    # Add the new section header.
    new_shdr = [name_offset, section_type, 0, 0, new_offset, new_size, 0, 0, 8, 0]
    shdrs.append(new_shdr)

    # Write the updated section header table at the end of the file.
    new_e_shoff = len(working)
    for shdr in shdrs:
        working.extend(struct.pack(ELF64_SHDR_FMT, *shdr))

    # Update ELF header.
    struct.pack_into("<Q", working, EHDR_SHOFF, new_e_shoff)
    struct.pack_into("<H", working, EHDR_SHNUM, e_shnum + 1)

    return bytes(working)


def patch_section_field(
    data: bytes, section_idx: int, field_index: int, value: int
) -> bytes:
    """Modify one field of a section header. Returns new bytes (does not write file).

    field_index: 4=sh_offset, 5=sh_size, 6=sh_link, 7=sh_info, etc.
    """
    working = bytearray(data)
    _patch_shdr_field(working, section_idx, field_index, value)
    return bytes(working)


def validate_elf_structure(data: bytes) -> List[str]:
    """Validate ELF structure. Returns list of issues (empty = valid)."""
    issues = []
    if len(data) < 64:
        return ["File too small for ELF64 header"]
    if data[:4] != b"\x7fELF":
        return ["Not an ELF file"]
    try:
        e_shoff = struct.unpack_from("<Q", data, EHDR_SHOFF)[0]
        e_shentsize = struct.unpack_from("<H", data, EHDR_SHENTSIZE)[0]
        e_shnum = struct.unpack_from("<H", data, EHDR_SHNUM)[0]
        e_shstrndx = struct.unpack_from("<H", data, EHDR_SHSTRNDX)[0]
    except struct.error:
        return ["Truncated ELF header"]
    if e_shentsize != 64:
        issues.append(f"Unexpected e_shentsize={e_shentsize}")
    if e_shoff + e_shnum * e_shentsize > len(data):
        issues.append("Section header table extends beyond file")
    if e_shstrndx >= e_shnum:
        issues.append(f"e_shstrndx ({e_shstrndx}) >= e_shnum ({e_shnum})")
    for i in range(min(e_shnum, 100)):
        off = e_shoff + i * e_shentsize
        if off + 64 > len(data):
            issues.append(f"Section {i} header truncated")
            continue
        vals = struct.unpack(ELF64_SHDR_FMT, data[off:off+64])
        if vals[4] + vals[5] > len(data):
            issues.append(
                f"Section {i}: sh_offset({vals[4]}) + sh_size({vals[5]}) exceeds file"
            )
    return issues


def get_section_info(data: bytes) -> List[Dict]:
    """Return a list of dicts describing all sections. Useful for inspection."""
    sections = parse_all_sections(data)
    strtab = _read_shstrtab(data)
    result = []
    for idx, hdr in enumerate(sections):
        result.append({
            "index": idx,
            "name": _section_name(strtab, hdr[0]),
            "type": hdr[1],
            "offset": hdr[4],
            "size": hdr[5],
            "link": hdr[6],
            "info": hdr[7],
        })
    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def parse_all_sections(data: bytes) -> List[Tuple]:
    """Parse all section headers from an ELF64 file. Returns list of 10-tuples."""
    e_shoff = struct.unpack_from("<Q", data, EHDR_SHOFF)[0]
    _, _, _, _, _, e_shentsize, e_shnum, _ = struct.unpack_from("<QIHHHHHH", data, EHDR_SHOFF)
    result = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        result.append(struct.unpack(ELF64_SHDR_FMT, data[off:off+e_shentsize]))
    return result


def _read_shstrtab(data: bytes) -> bytes:
    """Read the section name string table."""
    e_shoff = struct.unpack_from("<Q", data, EHDR_SHOFF)[0]
    _, _, _, _, _, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
        "<QIHHHHHH", data, EHDR_SHOFF
    )
    off = e_shoff + e_shstrndx * e_shentsize
    vals = struct.unpack(ELF64_SHDR_FMT, data[off:off+e_shentsize])
    return data[vals[4]:vals[4]+vals[5]]


def _section_name(strtab: bytes, name_offset: int) -> str:
    """Extract null-terminated section name from shstrtab."""
    end = strtab.find(b"\x00", name_offset)
    if end > name_offset:
        return strtab[name_offset:end].decode("ascii", errors="replace")
    return f"?idx={name_offset}"


def _patch_shdr_field(data: bytearray, section_idx: int, field_index: int, value: int) -> None:
    """Modify one field in a section header in-place."""
    e_shoff = struct.unpack_from("<Q", data, EHDR_SHOFF)[0]
    e_shentsize = struct.unpack_from("<H", data, EHDR_SHENTSIZE)[0]
    hdr_off = e_shoff + section_idx * e_shentsize
    # Fields 0-3 are 4 bytes, 4-9 are 8 bytes
    field_offsets = [0, 4, 8, 16, 24, 32, 40, 44, 48, 56]
    if field_index < 4:
        struct.pack_into("<I", data, hdr_off + field_offsets[field_index], value)
    else:
        struct.pack_into("<Q", data, hdr_off + field_offsets[field_index], value)


def _patch_shdr(data: bytearray, section_idx: int, field_offset: int,
                value: int, width: int = 8) -> None:
    """Low-level: modify bytes at a specific offset within a section header."""
    e_shoff = struct.unpack_from("<Q", data, EHDR_SHOFF)[0]
    e_shentsize = struct.unpack_from("<H", data, EHDR_SHENTSIZE)[0]
    pos = e_shoff + section_idx * e_shentsize + field_offset
    if width == 4:
        struct.pack_into("<I", data, pos, value)
    else:
        struct.pack_into("<Q", data, pos, value)
