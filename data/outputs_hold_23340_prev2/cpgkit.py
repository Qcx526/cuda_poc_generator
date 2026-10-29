# -*- coding: utf-8 -*-
"""Small ELF helpers for a generated candidate.

The failures that waste a run are not exotic: a section is created 32 bytes
long when the header alone is 32 bytes, or a name is never added to the string
table so the loader cannot see the section at all. Hand-rolling the layout each
time is where those mistakes come from, so the candidate gets a small library
that does the bookkeeping and refuses obviously broken states.

Deliberately dependency-free: it runs inside the same hardened container as the
tool, where nothing is installed.

    from cpgkit import Elf
    e = Elf("in.cubin")
    e.append_section(".nv_debug_source", blob)
    e.save("out.cubin")
    require(len(e.section(".nv_debug_source").data) == len(blob), "size mismatch")
"""

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

SHDR = struct.Struct("<IIQQQQIIQQ")
EHDR_SHoff, EHDR_SHeNTSIZE, EHDR_SHNUM, EHDR_SHSTRNDX = 0x28, 0x3A, 0x3C, 0x3E
SHT_NOBITS = 8


class KitError(AssertionError):
    """An invariant the candidate asserted did not hold."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise KitError(message)


@dataclass
class Section:
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int
    data: bytes = b""


class Elf:
    """Read, patch and extend an ELF64 image without external tools."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.image = bytearray(self.path.read_bytes())
        require(self.image[:4] == b"\x7fELF", "not an ELF file: %s" % path)
        require(self.image[4] == 2, "only ELF64 is supported")
        shoff = struct.unpack_from("<Q", self.image, EHDR_SHoff)[0]
        entsize = struct.unpack_from("<H", self.image, EHDR_SHeNTSIZE)[0]
        count = struct.unpack_from("<H", self.image, EHDR_SHNUM)[0]
        strndx = struct.unpack_from("<H", self.image, EHDR_SHSTRNDX)[0]
        require(entsize == SHDR.size, "unexpected section header size %d" % entsize)
        require(shoff and count, "no section header table")
        self.shstrndx = strndx
        self.raw = []
        for i in range(count):
            self.raw.append(list(SHDR.unpack_from(self.image, shoff + i * SHDR.size)))
        names = self._names()
        self.sections: List[Section] = []
        for i, sh in enumerate(self.raw):
            sec = Section(name=names[i], type=sh[1], flags=sh[2], addr=sh[3],
                          offset=sh[4], size=sh[5], link=sh[6], info=sh[7],
                          addralign=sh[8], entsize=sh[9])
            if sec.type != SHT_NOBITS and sec.size:
                sec.data = bytes(self.image[sec.offset:sec.offset + sec.size])
            self.sections.append(sec)

    def _strtab(self) -> bytearray:
        sec = self.sections[self.shstrndx]
        return bytearray(sec.data)

    def _names(self) -> List[str]:
        raw = self.raw
        strtab = bytes(self.image[raw[self.shstrndx][4]:raw[self.shstrndx][4] + raw[self.shstrndx][5]])
        names = []
        for sh in raw:
            end = strtab.find(b"\0", sh[0])
            names.append(strtab[sh[0]:end].decode("utf-8", "replace"))
        return names

    def section(self, name: str) -> Optional[Section]:
        for sec in self.sections:
            if sec.name == name:
                return sec
        return None

    def names(self) -> List[str]:
        return [s.name for s in self.sections]

    def append_section(self, name: str, data: bytes, align: int = 8) -> Section:
        """Add a section, extending the string table so the loader can see it.

        A section that exists in the file but not in the string table is
        invisible to every tool, which looks exactly like "the section is
        missing" - a failure mode worth preventing in code rather than in prose.
        """
        require(self.section(name) is None, "section %s already exists" % name)
        strtab = self._strtab()
        require(strtab.endswith(b"\0") or len(strtab) == 0, "string table is not terminated")

        while len(self.image) % align:
            self.image.append(0)
        data_off = len(self.image)
        self.image += data

        strtab += name.encode() + b"\0"
        while len(self.image) % align:
            self.image.append(0)
        strtab_off = len(self.image)
        self.image += strtab

        self.raw[self.shstrndx][4] = strtab_off
        self.raw[self.shstrndx][5] = len(strtab)
        sec = Section(name=name, type=1, flags=0, addr=0, offset=data_off,
                      size=len(data), link=0, info=0, addralign=align,
                      entsize=0, data=data)
        self.raw.append([len(strtab) - len(name) - 1, sec.type, sec.flags, sec.addr,
                         sec.offset, sec.size, sec.link, sec.info, sec.addralign,
                         sec.entsize])
        self.sections.append(sec)
        return sec

    def save(self, path: str) -> Path:
        """Write the image with a rebuilt section header table."""
        while len(self.image) % 8:
            self.image.append(0)
        shoff = len(self.image)
        for sh in self.raw:
            self.image += SHDR.pack(*sh)
        struct.pack_into("<Q", self.image, EHDR_SHoff, shoff)
        struct.pack_into("<H", self.image, EHDR_SHNUM, len(self.raw))
        out = Path(path)
        out.write_bytes(bytes(self.image))
        return out


def check_section_roundtrip(path: str, name: str, expect_size: int) -> None:
    """Re-read a saved file and assert the section survived as intended."""
    again = Elf(path)
    sec = again.section(name)
    require(sec is not None, "section %s missing after save" % name)
    require(sec.size == expect_size,
            "section %s size %d != expected %d" % (name, sec.size, expect_size))
