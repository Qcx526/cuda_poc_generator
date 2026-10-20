# -*- coding: utf-8 -*-
"""Minimal PE export lookup, so observation targets need no symbol server.

The debugger cannot resolve ``module!Export`` without a symbol path. Reading
the export table gives the RVA directly, and ``module+0xRVA`` breakpoints work
regardless of symbols being available.
"""

import struct
from pathlib import Path
from typing import Optional


def export_rva(dll_path: Path, name: str) -> Optional[int]:
    """Return the RVA of an exported symbol, or None when it is not exported."""
    data = Path(dll_path).read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        return None
    coff = pe + 4
    nsections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        export_dir_rva = struct.unpack_from("<I", data, opt + 112)[0]
    else:
        export_dir_rva = struct.unpack_from("<I", data, opt + 96)[0]
    sections = []
    for index in range(nsections):
        offset = opt + opt_size + index * 40
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, offset + 8)
        sections.append((va, vsize, rawptr, rawsize))

    def to_file(rva: int) -> Optional[int]:
        for va, vsize, rawptr, rawsize in sections:
            if va <= rva < va + max(vsize, rawsize):
                return rawptr + (rva - va)
        return None

    directory = to_file(export_dir_rva)
    if directory is None:
        return None
    nnames = struct.unpack_from("<I", data, directory + 24)[0]
    funcs = struct.unpack_from("<I", data, directory + 28)[0]
    names = struct.unpack_from("<I", data, directory + 32)[0]
    ordinals = struct.unpack_from("<I", data, directory + 36)[0]
    names_file = to_file(names)
    ordinals_file = to_file(ordinals)
    funcs_file = to_file(funcs)
    if None in (names_file, ordinals_file, funcs_file):
        return None
    wanted = name.encode("ascii", "ignore")
    for index in range(nnames):
        name_rva = struct.unpack_from("<I", data, names_file + index * 4)[0]
        name_file = to_file(name_rva)
        if name_file is None:
            continue
        end = data.index(b"\0", name_file)
        if data[name_file:end] != wanted:
            continue
        ordinal = struct.unpack_from("<H", data, ordinals_file + index * 2)[0]
        return struct.unpack_from("<I", data, funcs_file + ordinal * 4)[0]
    return None
