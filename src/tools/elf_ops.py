"""Bounded ELF64 little-endian section parsing and explicit byte mutations.

The supported format is the ordinary (non-extended-numbering) ELF64 section
layout from the System V gABI. ELF32 and big-endian files are rejected, not
reinterpreted. This module checks structure, not CUDA semantics or execution.
"""

import struct
from typing import Dict, List, Optional, Tuple

ELF64_SHDR_FMT = "<IIQQQQIIQQ"
ELF64_SHDR_SIZE = struct.calcsize(ELF64_SHDR_FMT)
ELF64_EHDR_SIZE = 64
MAX_SECTION_NAME_BYTES = 4096
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9
SHN_LORESERVE = 0xFF00
SHN_XINDEX = 0xFFFF
SHF_INFO_LINK = 0x40
SHF_LINK_ORDER = 0x80

EHDR_SHOFF = 0x28
EHDR_SHENTSIZE = 0x3A
EHDR_SHNUM = 0x3C
EHDR_SHSTRNDX = 0x3E

# (byte offset, byte width) by field index, as specified by Elf64_Shdr.
SHDR_FIELDS = ((0, 4), (4, 4), (8, 8), (16, 8), (24, 8),
               (32, 8), (40, 4), (44, 4), (48, 8), (56, 8))
_LINK_SECTION_TYPES = {SHT_SYMTAB, SHT_RELA, 5, 6, SHT_REL, 11, 17, 18}


def _uint(value: int, width: int, label: str) -> int:
    if type(value) is not int or value < 0 or value >= 1 << (width * 8):
        raise ValueError(f"{label} must be an unsigned {width * 8}-bit integer")
    return value


def _bytes(data: bytes, label: str = "ELF data") -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError(f"{label} must be bytes or bytearray")
    return bytes(data)


def _in_file(offset: int, size: int, file_size: int) -> bool:
    # Subtraction avoids fixed-width overflow if ported to a native language.
    return offset <= file_size and size <= file_size - offset


def _parse_validated(data: bytes) -> Tuple[List[Tuple], bytes]:
    """Parse the supported structural subset; all reads follow bounds checks."""
    data = _bytes(data)
    if len(data) < ELF64_EHDR_SIZE:
        raise ValueError("File too small for ELF64 header")
    if data[:4] != b"\x7fELF":
        raise ValueError("Not an ELF file")
    if data[4] != 2:
        raise ValueError("Unsupported ELF class: only ELF64 is supported")
    if data[5] != 1:
        raise ValueError("Unsupported ELF byte order: only little-endian is supported")
    if data[6] != 1 or struct.unpack_from("<I", data, 20)[0] != 1:
        raise ValueError("Unsupported ELF version")
    if struct.unpack_from("<H", data, 52)[0] != ELF64_EHDR_SIZE:
        raise ValueError("Invalid ELF64 e_ehsize")

    shoff = struct.unpack_from("<Q", data, EHDR_SHOFF)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, EHDR_SHENTSIZE)
    if shnum == 0 or shnum >= SHN_LORESERVE or shstrndx == SHN_XINDEX:
        raise ValueError("Unsupported sectionless ELF or extended section numbering")
    if shentsize != ELF64_SHDR_SIZE:
        raise ValueError(f"Invalid e_shentsize={shentsize}; ELF64 requires 64")
    if shoff < ELF64_EHDR_SIZE or not _in_file(shoff, shnum * shentsize, len(data)):
        raise ValueError("Section header table lies outside the file or overlaps ELF header")
    if shoff % 8:
        raise ValueError("Section header table is not 8-byte aligned")
    if shstrndx >= shnum:
        raise ValueError("Section name string table index is outside section table")

    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phnum == SHN_XINDEX:
        raise ValueError("Unsupported extended program header numbering")
    reserved = [(0, ELF64_EHDR_SIZE, "ELF header"),
                (shoff, shoff + shnum * shentsize, "section header table")]
    if phnum:
        if phentsize != 56 or phoff < ELF64_EHDR_SIZE or not _in_file(phoff, phnum * phentsize, len(data)):
            raise ValueError("Invalid or truncated ELF64 program header table")
        phend = phoff + phnum * phentsize
        if phoff < shoff + shnum * shentsize and shoff < phend:
            raise ValueError("Program and section header tables overlap")
        reserved.append((phoff, phend, "program header table"))

    sections = [struct.unpack_from(ELF64_SHDR_FMT, data, shoff + i * shentsize)
                for i in range(shnum)]
    if sections[0][1] != SHT_NULL:
        raise ValueError("Section index zero must have type SHT_NULL")
    intervals = []
    for i, hdr in enumerate(sections):
        if hdr[1] == SHT_NULL:
            # gABI leaves inactive header members undefined.
            continue
        offset, size, alignment = hdr[4], hdr[5], hdr[8]
        if alignment and alignment & (alignment - 1):
            raise ValueError(f"Section {i}: sh_addralign must be zero or a power of two")
        if alignment > 1 and hdr[3] % alignment:
            raise ValueError(f"Section {i}: sh_addr violates sh_addralign")
        if hdr[1] != SHT_NOBITS:
            if not _in_file(offset, size, len(data)):
                raise ValueError(f"Section {i}: content range extends beyond file")
            if size:
                end = offset + size
                for start, stop, label in reserved:
                    if offset < stop and start < end:
                        raise ValueError(f"Section {i}: content overlaps {label}")
                intervals.append((offset, end, i))
        if hdr[7] >= shnum and (hdr[1] in {SHT_REL, SHT_RELA} or hdr[2] & SHF_INFO_LINK):
            raise ValueError(f"Section {i}: sh_info section index is outside section table")
        if hdr[6] >= shnum and (hdr[1] in _LINK_SECTION_TYPES or hdr[2] & SHF_LINK_ORDER):
            raise ValueError(f"Section {i}: sh_link section index is outside section table")
        if hdr[9] and size % hdr[9]:
            raise ValueError(f"Section {i}: sh_size is not a multiple of sh_entsize")
    intervals.sort()
    for previous, current in zip(intervals, intervals[1:]):
        if previous[1] > current[0]:
            raise ValueError(f"Section content ranges overlap: {previous[2]} and {current[2]}")

    if shstrndx == 0:
        if any(hdr[0] for hdr in sections if hdr[1] != SHT_NULL):
            raise ValueError("Section names refer to an absent string table")
        return sections, b"\x00"
    str_hdr = sections[shstrndx]
    if str_hdr[1] != SHT_STRTAB:
        raise ValueError("Section name string table is not SHT_STRTAB")
    strtab = data[str_hdr[4]:str_hdr[4] + str_hdr[5]]
    if not strtab or strtab[0] != 0 or strtab[-1] != 0:
        raise ValueError("Section name string table must start and end with NUL")
    for i, hdr in enumerate(sections):
        if hdr[1] != SHT_NULL:
            try:
                _section_name(strtab, hdr[0])
            except ValueError as exc:
                raise ValueError(f"Section {i}: {exc}") from exc
    return sections, strtab


def parse_all_sections(data: bytes) -> List[Tuple]:
    """Return all ELF64 headers; reject unsupported or unsafe input first."""
    return _parse_validated(data)[0]


def validate_elf_structure(data: bytes) -> List[str]:
    """Return [] for supported structure, otherwise explicit diagnostics.

    This is not a CUDA ABI validator, a loader, or a vulnerability oracle.
    Unknown processor-specific section semantics are left opaque.
    """
    try:
        _parse_validated(data)
    except ValueError as exc:
        return [str(exc)]
    return []


def find_section(data: bytes, name: str) -> Optional[Tuple[int, Tuple]]:
    """Find the first named section in a validated ELF64 input."""
    if not isinstance(name, str):
        raise ValueError("Section name must be a string")
    sections, strtab = _parse_validated(data)
    for idx, hdr in enumerate(sections):
        if hdr[1] != SHT_NULL and _section_name(strtab, hdr[0]) == name:
            return idx, hdr
    return None


def find_sections_by_type(data: bytes, section_type: int) -> List[Tuple[int, Tuple]]:
    _uint(section_type, 4, "Section type")
    return [(i, h) for i, h in enumerate(parse_all_sections(data)) if h[1] == section_type]


def get_section_info(data: bytes) -> List[Dict]:
    sections, strtab = _parse_validated(data)
    return [{"index": i, "name": "" if h[1] == SHT_NULL else _section_name(strtab, h[0]),
             "type": h[1], "offset": h[4], "size": h[5], "link": h[6], "info": h[7]}
            for i, h in enumerate(sections)]


def _write_result(data: bytearray, output_path: Optional[str]) -> bytes:
    result = bytes(data)
    _parse_validated(result)
    if output_path is not None:
        with open(output_path, "wb") as stream:
            stream.write(result)
    return result


def _append_aligned(data: bytearray, body: bytes, alignment: int) -> int:
    # Mutators cap padding rather than allocating an attacker-chosen uint64.
    alignment = max(alignment, 1)
    if alignment > 1024 * 1024:
        raise ValueError("Unsupported mutation alignment above 1 MiB")
    data.extend(b"\x00" * ((-len(data)) % alignment))
    offset = len(data)
    data.extend(body)
    return offset


def replace_section_content(data: bytes, section_name: str, new_content: bytes,
                            output_path: Optional[str] = None) -> bytes:
    """Append replacement bytes and update that header in a valid ELF.

    Relocation does not repair program segments or CUDA semantics. No loader
    or external process is invoked. NOBITS and inactive sections have no body.
    """
    sections, strtab = _parse_validated(data)
    if not isinstance(section_name, str):
        raise ValueError("Section name must be a string")
    indexes = [i for i, h in enumerate(sections) if h[1] != SHT_NULL
               and _section_name(strtab, h[0]) == section_name]
    if len(indexes) != 1:
        raise ValueError("Section name must identify exactly one section")
    idx = indexes[0]
    hdr = sections[idx]
    if hdr[1] == SHT_NOBITS:
        raise ValueError("SHT_NOBITS has no file content to replace")
    working = bytearray(data)
    new_offset = _append_aligned(working, _bytes(new_content, "Section content"), hdr[8])
    _write_field(working, idx, 4, new_offset)
    _write_field(working, idx, 5, len(new_content))
    return _write_result(working, output_path)


def append_section(data: bytes, name: str, body: bytes,
                   section_type: Optional[int] = None) -> bytes:
    """Append file-backed section bytes and relocate the section/name tables.

    This preserves structural bounds; type-specific relocation/symbol semantics
    remain the caller's responsibility. It does not make a runnable cubin.
    """
    sections, strtab = _parse_validated(data)
    if not isinstance(name, str) or not name or "\x00" in name:
        raise ValueError("New section name must be a nonempty NUL-free string")
    try:
        name_bytes = name.encode("utf-8") + b"\x00"
    except UnicodeEncodeError as exc:
        raise ValueError("Section name must encode as UTF-8") from exc
    if len(name_bytes) - 1 > MAX_SECTION_NAME_BYTES:
        raise ValueError("Section name exceeds the supported 4096-byte limit")
    if any(_section_name(strtab, h[0]) == name for h in sections if h[1] != SHT_NULL):
        raise ValueError("A section with this name already exists")
    shstrndx = struct.unpack_from("<H", data, EHDR_SHSTRNDX)[0]
    if shstrndx == 0:
        raise ValueError("Appending named sections requires an existing name string table")
    if len(sections) + 1 >= SHN_LORESERVE:
        raise ValueError("Appending would require unsupported extended numbering")
    if section_type is None:
        section_type = SHT_RELA if name.startswith(".rela") else SHT_REL if name.startswith(".rel") else SHT_PROGBITS
    _uint(section_type, 4, "Section type")
    if section_type in {SHT_NULL, SHT_NOBITS}:
        raise ValueError("Appending byte content requires a file-backed section type")
    body = _bytes(body, "Section content")
    name_offset = len(strtab)
    _uint(name_offset, 4, "Section name offset")
    working = bytearray(data)
    new_offset = _append_aligned(working, body, 8)
    new_strtab = strtab + name_bytes
    new_str_offset = _append_aligned(working, new_strtab, 1)
    headers = [list(h) for h in sections]
    headers[shstrndx][4:6] = [new_str_offset, len(new_strtab)]
    headers.append([name_offset, section_type, 0, 0, new_offset, len(body), 0, 0, 8, 0])
    new_table = b"".join(struct.pack(ELF64_SHDR_FMT, *h) for h in headers)
    new_shoff = _append_aligned(working, new_table, 8)
    struct.pack_into("<Q", working, EHDR_SHOFF, new_shoff)
    struct.pack_into("<H", working, EHDR_SHNUM, len(headers))
    return _write_result(working, None)


def _write_field(data: bytearray, section_idx: int, field_index: int, value: int) -> None:
    """Internal write after bounds/type checks; no structural reparse mid-edit."""
    if type(field_index) is not int or not 0 <= field_index < len(SHDR_FIELDS):
        raise ValueError("Section field index must be an integer in [0, 9]")
    shoff = struct.unpack_from("<Q", data, EHDR_SHOFF)[0]
    shnum = struct.unpack_from("<H", data, EHDR_SHNUM)[0]
    if type(section_idx) is not int or not 0 <= section_idx < shnum:
        raise ValueError("Section index is outside section table")
    offset, width = SHDR_FIELDS[field_index]
    _uint(value, width, "Section field value")
    pos = shoff + section_idx * ELF64_SHDR_SIZE + offset
    if not _in_file(pos, width, len(data)):
        raise ValueError("Section field write lies outside the file")
    struct.pack_into("<I" if width == 4 else "<Q", data, pos, value)


def patch_section_field(data: bytes, section_idx: int, field_index: int, value: int) -> bytes:
    """Write one correctly sized field in a validated source ELF.

    Explicit research mutations may produce an invalid result: call
    validate_elf_structure on the returned bytes before inspection, and never
    interpret mutation success as loadability, execution, or CVE verification.
    """
    _parse_validated(data)
    working = bytearray(data)
    _write_field(working, section_idx, field_index, value)
    return bytes(working)


def _patch_shdr_field(data: bytearray, section_idx: int, field_index: int, value: int) -> None:
    """Compatibility mutator with identical validated source/field rules."""
    if not isinstance(data, bytearray):
        raise ValueError("In-place ELF mutation requires bytearray")
    _parse_validated(data)
    _write_field(data, section_idx, field_index, value)


def _patch_shdr(data: bytearray, section_idx: int, field_offset: int,
                value: int, width: int = 8) -> None:
    """Compatibility mutator restricted to a complete declared ELF64 field."""
    if type(field_offset) is not int or type(width) is not int:
        raise ValueError("Field offset and width must be integers")
    try:
        field_index = SHDR_FIELDS.index((field_offset, width))
    except ValueError as exc:
        raise ValueError("Offset/width must identify one complete ELF64 section field") from exc
    _patch_shdr_field(data, section_idx, field_index, value)


def _read_shstrtab(data: bytes) -> bytes:
    return _parse_validated(data)[1]


def _section_name(strtab: bytes, name_offset: int) -> str:
    if type(name_offset) is not int or not 0 <= name_offset < len(strtab):
        raise ValueError("Section name offset is outside string table")
    # Bound scans and decoded output for repeated adversarial name offsets.
    # Oversized names are an unsupported subset, not a repaired ELF variant.
    end = strtab.find(b"\x00", name_offset, name_offset + MAX_SECTION_NAME_BYTES + 1)
    if end < 0:
        raise ValueError("Section name has no NUL terminator within the supported 4096-byte limit")
    return strtab[name_offset:end].decode("utf-8", errors="surrogateescape")
