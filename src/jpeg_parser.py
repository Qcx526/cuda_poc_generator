# -*- coding: utf-8 -*-
"""JPEG marker parser that understands where a scan ends.

The previous walker stopped at the first SOS, so it could not tell a baseline file from
a multi-scan one and happily reported success on structure it had not read. This parser
walks the whole file: inside entropy-coded data `FF 00` is a stuffed byte, `FF D0-D7` is
a restart marker, `FF FF` is fill, and any other `FF xx` ends the scan.

It is a structural reader only. "Parsed" says nothing about whether the entropy stream
decodes; that verdict comes from a real decoder (Pillow) and is recorded separately.
"""

import struct
from dataclasses import dataclass, field
from typing import List, Optional

SOI, EOI, SOS, DRI, DQT, DHT = 0xD8, 0xD9, 0xDA, 0xDD, 0xDB, 0xC4
SOF_BASELINE, SOF_EXTENDED = 0xC0, 0xC1
# Every SOF variant is parsed for diagnostics; only baseline/extended are editable.
SOF_ALL = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}

NAME = {0xD8: "SOI", 0xD9: "EOI", 0xDB: "DQT", 0xC4: "DHT", 0xDA: "SOS",
        0xC0: "SOF0", 0xC1: "SOF1", 0xC2: "SOF2", 0xC3: "SOF3", 0xC5: "SOF5",
        0xC6: "SOF6", 0xC7: "SOF7", 0xC9: "SOF9", 0xCA: "SOF10", 0xCB: "SOF11",
        0xCD: "SOF13", 0xCE: "SOF14", 0xCF: "SOF15", 0xCC: "DAC", 0xDE: "DHP",
        0xDF: "EXP", 0x01: "TEM",
        0xDD: "DRI", 0xE0: "APP0", 0xE1: "APP1", 0xE2: "APP2", 0xE3: "APP3",
        0xE4: "APP4", 0xE5: "APP5", 0xE6: "APP6", 0xE7: "APP7", 0xE8: "APP8",
        0xE9: "APP9", 0xEA: "APP10", 0xEB: "APP11", 0xEC: "APP12", 0xED: "APP13",
        0xEE: "APP14", 0xEF: "APP15", 0xFE: "COM", 0xDD: "DRI", 0xDC: "DNL"}

# Policy table. Every marker the parser meets falls into exactly one class, and the class
# decides whether the file is editable. Silently skipping an unknown marker would mean
# claiming to understand a file whose structure was never read.
SUPPORTED = {SOI, EOI, DQT, DHT, SOF_BASELINE, SOF_EXTENDED, SOS, DRI}
PASSTHROUGH = set(range(0xE0, 0xF0)) | {0xFE}
REFUSED = {
    0xC2: "progressive DCT (SOF2)",
    0xC3: "lossless (SOF3)",
    0xC5: "differential sequential (SOF5)",
    0xC6: "differential progressive (SOF6)",
    0xC7: "differential lossless (SOF7)",
    0xC9: "arithmetic-coded extended sequential (SOF9)",
    0xCA: "arithmetic-coded progressive (SOF10)",
    0xCB: "arithmetic-coded lossless (SOF11)",
    0xCD: "arithmetic-coded differential sequential (SOF13)",
    0xCE: "arithmetic-coded differential progressive (SOF14)",
    0xCF: "arithmetic-coded differential lossless (SOF15)",
    0xCC: "arithmetic coding conditioning (DAC)",
    0xDC: "define number of lines (DNL)",
    0xDE: "hierarchical progression (DHP)",
    0xDF: "expand reference components (EXP)",
    0x01: "temporary private use (TEM)",
}


class ParserError(ValueError):
    """The bytes are not a JPEG this parser can account for."""


@dataclass
class Segment:
    marker: int
    name: str
    offset: int
    length: int          # whole segment length including FF and the two length bytes
    payload_offset: int


@dataclass
class Structure:
    segments: List[Segment] = field(default_factory=list)
    sof: Optional[dict] = None
    sos_positions: List[int] = field(default_factory=list)
    dri_count: int = 0
    dri_values: List[int] = field(default_factory=list)
    entropy_bytes: int = 0
    trailing_after_eoi: int = 0

    def names(self) -> List[str]:
        return [s.name for s in self.segments]


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from(">H", data, offset)[0]


def parse(data: bytes, strict: bool = True) -> Structure:
    """Walk markers and entropy segments. Raises ParserError on anything unaccounted."""
    if len(data) < 4 or data[0] != 0xFF or data[1] != SOI:
        raise ParserError("not a JPEG: missing SOI")

    structure = Structure()
    i = 2
    while i < len(data):
        # Fill bytes may precede a marker; more than one FF is legal.
        if data[i] != 0xFF:
            raise ParserError("expected marker at offset %d, found 0x%02X" % (i, data[i]))
        while i < len(data) and data[i] == 0xFF:
            i += 1
        if i >= len(data):
            raise ParserError("truncated marker at end of file")
        marker = data[i]
        start = i - 1
        i += 1

        if marker == EOI:
            structure.segments.append(Segment(EOI, "EOI", start, 2, i))
            structure.trailing_after_eoi = len(data) - i
            return structure
        if marker in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7):
            raise ParserError("restart marker outside a scan at offset %d" % start)
        if marker == 0x00:
            raise ParserError("stuffed byte outside a scan at offset %d" % start)

        if marker in REFUSED and strict:
            raise ParserError("refused: %s (0x%02X)" % (REFUSED[marker], marker))
        if strict and marker not in SUPPORTED and marker not in PASSTHROUGH:
            raise ParserError("unknown marker 0x%02X at offset %d" % (marker, start))

        if i + 2 > len(data):
            raise ParserError("truncated length field for 0x%02X" % marker)
        length = _u16(data, i)
        if length < 2:
            raise ParserError("illegal segment length %d for 0x%02X" % (length, marker))
        end = i + length
        if end > len(data):
            raise ParserError("truncated segment 0x%02X: needs %d bytes, %d left"
                              % (marker, length, len(data) - i))

        name = NAME.get(marker, "0x%02X" % marker)
        structure.segments.append(Segment(marker, name, start, end - start, i + 2))

        if marker in SOF_ALL:
            if length < 8:
                raise ParserError("SOF too short (%d)" % length)
            components = data[i + 7]
            if components < 1 or length < 8 + components * 3:
                raise ParserError("SOF component table truncated")
            structure.sof = {
                "marker": marker,
                "precision": data[i + 2],
                "height": _u16(data, i + 3),
                "width": _u16(data, i + 5),
                "components": components,
                "comps": [{"id": data[i + 8 + c * 3],
                           "h": data[i + 9 + c * 3] >> 4,
                           "v": data[i + 9 + c * 3] & 0x0F,
                           "quant": data[i + 10 + c * 3]} for c in range(components)],
            }
        elif marker == DRI:
            if length != 4:
                raise ParserError("DRI length must be 4, got %d" % length)
            structure.dri_count += 1
            structure.dri_values.append(_u16(data, i + 2))

        i = end

        if marker == SOS:
            structure.sos_positions.append(start)
            i, consumed = _skip_entropy(data, i)
            structure.entropy_bytes += consumed

    raise ParserError("no EOI: file ends inside a segment")


def _skip_entropy(data: bytes, i: int) -> tuple:
    """Advance past entropy-coded data; return (position of next marker, bytes consumed)."""
    start = i
    while i < len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        if i + 1 >= len(data):
            raise ParserError("truncated escape at end of scan")
        nxt = data[i + 1]
        if nxt == 0x00:          # stuffed byte inside entropy data
            i += 2
            continue
        if 0xD0 <= nxt <= 0xD7:  # restart marker, part of the scan
            i += 2
            continue
        if nxt == 0xFF:          # fill byte before a marker
            i += 1
            continue
        return i, i - start
    raise ParserError("scan runs to end of file without EOI")


def summary(data: bytes) -> dict:
    """Best-effort description for diagnostics; never raises."""
    try:
        structure = parse(data, strict=False)
    except ParserError as exc:
        return {"valid": False, "error": str(exc), "segments": [], "sos_count": 0}
    return {"valid": True, "segments": structure.names(),
            "sos_count": len(structure.sos_positions),
            "dri_count": structure.dri_count, "dri_values": structure.dri_values,
            "sof": structure.sof, "entropy_bytes": structure.entropy_bytes}
