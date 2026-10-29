# -*- coding: utf-8 -*-
"""The numeric fields of an ELF header and its section table.

Shared by the value sweep (which substitutes every field in turn) and by the
model-guided mutation (which needs to know which fields its proposals may name).
Keeping one implementation means a proposal can never name a field the sweep
could not also reach.
"""

import struct
from typing import List, Tuple

# Fields a parser branches on. sh_addr and sh_addralign are left out: they rarely
# change a decision, and including them multiplies the variant count without
# buying coverage.
SECTION_FIELDS = (
    ("sh_name", 0, 4), ("sh_type", 4, 4), ("sh_offset", 24, 8),
    ("sh_size", 32, 8), ("sh_link", 40, 4), ("sh_info", 44, 4),
    ("sh_entsize", 56, 8),
)


def fields(data: bytes) -> List[Tuple[str, int, int]]:
    """(name, absolute offset, width) for every reachable numeric field."""
    out: List[Tuple[str, int, int]] = []
    if len(data) < 64:
        return out
    out += [("e_shoff", 0x28, 8), ("e_shentsize", 0x3A, 2),
            ("e_shnum", 0x3C, 2), ("e_shstrndx", 0x3E, 2)]
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    entsize = struct.unpack_from("<H", data, 0x3A)[0]
    count = struct.unpack_from("<H", data, 0x3C)[0]
    if not entsize or shoff + entsize * count > len(data):
        return out
    for index in range(count):
        base = shoff + index * entsize
        for name, rel, width in SECTION_FIELDS:
            out.append(("sec%d.%s" % (index, name), base + rel, width))
    return out


def read(data: bytes, offset: int, width: int) -> int:
    raw = data[offset:offset + width]
    if len(raw) != width:
        return -1
    return int.from_bytes(raw, "little")


def table(data: bytes) -> dict:
    """Field name -> {offset, width, value}, for prompts and validation."""
    return {name: {"offset": offset, "width": width,
                   "value": read(data, offset, width)}
            for name, offset, width in fields(data)}
