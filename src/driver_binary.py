# -*- coding: utf-8 -*-
"""Read-only PE facts for a driver image, with functions addressed by RVA.

The point of this module is to stop handing the model a 120 MB binary and hoping.
It exposes the few things an analyst actually asks for - "what function is at this
RVA", "who calls it", "which strings live where" - so a hypothesis can be phrased
against an address instead of a vague description.

Two deliberate limits:

* No disassembly. Cross-references and decompilation come from Ghidra, which
  already does that better; duplicating it here would create a second, drifting
  source of truth.
* Every fact is tagged with where it came from (``.pdata``, import table, string
  scan), because a guess about a function's purpose is not a fact about it.
"""

import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional

UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Section:
    name: str
    vaddr: int
    vsize: int
    raw_offset: int
    raw_size: int
    flags: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & 0x20000000)

    @property
    def contains(self) -> "tuple[int, int]":
        return (self.vaddr, self.vaddr + max(self.vsize, self.raw_size))


@dataclass(frozen=True)
class Function:
    rva: int
    size: int
    section: str

    @property
    def end(self) -> int:
        return self.rva + self.size


@dataclass
class ImageFacts:
    path: str
    sha256: str
    size: int
    machine: str
    pe32plus: bool
    image_base: int
    build_time: int
    sections: List[Section] = field(default_factory=list)
    functions: List[Function] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    pdb: Dict[str, object] = field(default_factory=dict)

    def function_at(self, rva: int) -> Optional[Function]:
        """The function containing an address, given as RVA or as a full VA.

        Callers usually have a VA from a debugger paste and an RVA from .pdata;
        accepting both avoids the silent "not found" that comes from mixing them.
        """
        if rva >= self.image_base:
            rva -= self.image_base
        low, high = 0, len(self.functions) - 1
        while low <= high:
            mid = (low + high) // 2
            item = self.functions[mid]
            if rva < item.rva:
                high = mid - 1
            elif rva >= item.end:
                low = mid + 1
            else:
                return item
        return None

    def summary(self) -> Dict[str, object]:
        return {
            "path": self.path, "sha256": self.sha256, "size": self.size,
            "machine": self.machine, "pe32plus": self.pe32plus,
            "image_base": "0x%x" % self.image_base,
            "build_time": self.build_time,
            "sections": len(self.sections),
            "functions": len(self.functions),
            "imports": self.imports,
            "exports": self.exports,
            "pdb": self.pdb,
            "provenance": "pe_headers + exception_directory",
        }


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


class PEImage:
    """Parse once, query many times; the file is never written to."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self._parse_headers()
        self._parse_sections()
        self._parse_directories()

    # -- headers ------------------------------------------------------

    def _parse_headers(self) -> None:
        data = self.data
        pe = _u32(data, 0x3C)
        self.machine = _u16(data, pe + 4)
        self.nsections = _u16(data, pe + 6)
        self.timestamp = _u32(data, pe + 8)
        opt_size = _u16(data, pe + 20)
        self.optional_offset = pe + 24
        magic = _u16(data, self.optional_offset)
        self.pe32plus = magic == 0x20B
        base_offset = self.optional_offset + (24 if self.pe32plus else 28)
        self.image_base = struct.unpack_from("<Q" if self.pe32plus else "<I",
                                             data, base_offset)[0]
        self._section_offset = self.optional_offset + opt_size

    def _parse_sections(self) -> None:
        self.sections: List[Section] = []
        for index in range(self.nsections):
            base = self._section_offset + index * 40
            name = self.data[base:base + 8].rstrip(b"\x00").decode("latin-1", "replace")
            vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", self.data, base + 8)
            flags = _u32(self.data, base + 36)
            self.sections.append(Section(name, vaddr, vsize, raw, rsize, flags))

    def _parse_directories(self) -> None:
        dirs = []
        for index in range(16):
            dirs.append(struct.unpack_from("<II", self.data,
                                           self.optional_offset + 112 + index * 8))
        self.directories = dirs

    # -- address helpers ----------------------------------------------

    def offset_of(self, rva: int) -> Optional[int]:
        for section in self.sections:
            start, end = section.contains
            if start <= rva < end:
                delta = rva - start
                if delta >= section.raw_size:
                    return None
                return section.raw_offset + delta
        return None

    def section_of(self, rva: int) -> str:
        for section in self.sections:
            start, end = section.contains
            if start <= rva < end:
                return section.name
        return UNKNOWN

    # -- structured facts ---------------------------------------------

    def functions(self) -> List[Function]:
        """RUNTIME_FUNCTION entries, which is the only trustworthy function list.

        A linear sweep would invent functions inside data; the exception
        directory is what the OS itself uses to unwind, so it is the authority.
        """
        rva, size = self.directories[3]
        offset = self.offset_of(rva) if rva else None
        if offset is None or not size:
            return []
        out = []
        for index in range(size // 12):
            begin, end, _ = struct.unpack_from("<III", self.data, offset + index * 12)
            if end <= begin:
                continue
            out.append(Function(begin, end - begin, self.section_of(begin)))
        out.sort(key=lambda item: item.rva)
        return out

    def imports(self) -> List[str]:
        rva, _ = self.directories[1]
        offset = self.offset_of(rva) if rva else None
        names: List[str] = []
        if offset is None:
            return names
        for index in range(64):
            entry = offset + index * 20
            if entry + 20 > len(self.data) or self.data[entry:entry + 20] == b"\x00" * 20:
                break
            name_rva = _u32(self.data, entry + 12)
            name_offset = self.offset_of(name_rva) if name_rva else None
            if name_offset is None:
                continue
            end = self.data.find(b"\x00", name_offset, name_offset + 256)
            names.append(self.data[name_offset:end].decode("latin-1", "replace"))
        return names

    def exports(self) -> List[str]:
        rva, size = self.directories[0]
        offset = self.offset_of(rva) if rva else None
        if offset is None or not size:
            return []
        count = _u32(self.data, offset + 24)
        names_rva = _u32(self.data, offset + 32)
        names_offset = self.offset_of(names_rva) if names_rva else None
        if names_offset is None:
            return []
        out = []
        for index in range(min(count, 64)):
            entry = self.offset_of(_u32(self.data, names_offset + index * 4))
            if entry is None:
                continue
            end = self.data.find(b"\x00", entry, entry + 256)
            out.append(self.data[entry:end].decode("latin-1", "replace"))
        return out

    def pdb(self) -> Dict[str, object]:
        rva, size = self.directories[6]
        offset = self.offset_of(rva) if rva else None
        if offset is None:
            return {}
        for index in range(size // 28):
            entry = offset + index * 28
            _, _, _, _, kind, length, _, pointer = struct.unpack_from(
                "<IIHHIIII", self.data, entry)
            if kind != 2 or not pointer:
                continue
            blob = self.data[pointer:pointer + length]
            if blob[:4] != b"RSDS":
                continue
            return {"guid": blob[4:20].hex(),
                    "age": struct.unpack_from("<I", blob, 20)[0],
                    "path": blob[24:].split(b"\x00")[0].decode("latin-1", "replace")}
        return {}

    def strings(self, minimum: int = 6, limit: int = 20000) -> Iterator[Dict[str, object]]:
        """Printable ASCII runs with their virtual address.

        This is a scan, not a claim: a string's presence says nothing about who
        reads it. Cross-references come from Ghidra.
        """
        data = self.data
        current: List[int] = []
        produced = 0
        for offset, byte in enumerate(data):
            if 0x20 <= byte < 0x7F:
                current.append(byte)
                continue
            if len(current) >= minimum:
                rva = self._rva_of_offset(offset - len(current))
                if rva is not None:
                    yield {"rva": rva, "text": bytes(current).decode("latin-1"),
                           "provenance": "string_scan"}
                    produced += 1
                    if produced >= limit:
                        return
            current = []

    def _rva_of_offset(self, offset: int) -> Optional[int]:
        for section in self.sections:
            if section.raw_offset <= offset < section.raw_offset + section.raw_size:
                return section.vaddr + (offset - section.raw_offset)
        return None


def facts_of(path: Path) -> ImageFacts:
    image = PEImage(path)
    return ImageFacts(
        path=str(path),
        sha256=hashlib.sha256(image.data).hexdigest(),
        size=len(image.data),
        machine="0x%x" % image.machine,
        pe32plus=image.pe32plus,
        image_base=image.image_base,
        build_time=image.timestamp,
        sections=image.sections,
        functions=image.functions(),
        imports=image.imports(),
        exports=image.exports(),
        pdb=image.pdb(),
    )


def export(facts: ImageFacts, target: Path) -> Path:
    """Write the machine-readable version, without the per-function table."""
    target = Path(target)
    target.write_text(json.dumps(facts.summary(), ensure_ascii=False, indent=2),
                      encoding="utf-8")
    return target
