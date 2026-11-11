# -*- coding: utf-8 -*-
"""JPEG input adapter: a plan says what to change, this module decides how.

Design contract
---------------
* A plan is data, not code. The candidate never assembles bytes.
* Every mutation records what it replaced, so the control is produced by undoing the
  plan in reverse rather than by guessing "original" values.
* Anything ambiguous is refused: progressive, arithmetic coding, multi-scan, unknown
  markers and out-of-range values raise instead of being masked or truncated.
* Validation runs two independent readers: the segment walker here and Pillow's decoder.
  "Markers parse" and "the image decodes" are different facts and both are recorded.

SOF layout (ITU-T T.81 B.2.2), offsets from the 0xFF byte:
    0 FF | 1 marker | 2-3 length | 4 precision | 5-6 height | 7-8 width | 9 Nf | ...
The earlier version used 6 and 8, which wrote one byte past each field and corrupted the
neighbouring value - that is the defect this module now guards with a test.
"""

import hashlib
import io
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from PIL import Image

from .jpeg_parser import SOF_BASELINE, SOF_EXTENDED, ParserError, parse

from .jpeg_parser import SOF_BASELINE, SOF_EXTENDED, ParserError, parse

SOF_BASELINE = 0xC0          # only baseline/extended sequential is editable here
SOF_EXTENDED = 0xC1
SOF_ALL = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}

SEGMENT_NAMES = {0xD8: "SOI", 0xD9: "EOI", 0xDB: "DQT", 0xC4: "DHT", 0xDA: "SOS",
                 0xDD: "DRI", 0xE0: "APP0", 0xE1: "APP1", 0xFE: "COM"}
APP_MARKERS = set(range(0xE0, 0xF0))


class AdapterError(ValueError):
    """Fail-closed: the plan or the file is outside what this adapter supports."""


@dataclass
class Artifact:
    role: str
    name: str
    data: bytes
    sha256: str
    segments: List[str] = field(default_factory=list)
    reference_ok: bool = False
    reference_error: str = ""
    size: tuple = (0, 0)
    mode: str = ""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require(condition, message):
    if not condition:
        raise AdapterError(message)


def walk(data: bytes) -> dict:
    """Segment names and SOF fields, from the full-file parser.

    Kept as a thin wrapper because callers already depend on this shape; the parsing
    itself lives in jpeg_parser, which walks past entropy data instead of stopping at
    the first SOS.
    """
    try:
        structure = parse(data, strict=False)
    except ParserError as exc:
        return {"segments": [], "entropy_bytes": 0, "valid": False,
                "sof_marker": None, "sos_count": 0, "dri_count": 0,
                "error": str(exc)}
    segments = []
    for item in structure.segments:
        if item.name in ("SOF0", "SOF1") and structure.sof:
            sof = structure.sof
            segments.append("%s(%dx%d,comp=%d,prec=%d)"
                            % (item.name, sof["width"], sof["height"],
                               sof["components"], sof["precision"]))
        elif item.marker == 0xDD:
            segments.append("DRI(%d)" % structure.dri_values[structure.dri_count - 1]
                            if structure.dri_values else "DRI")
        elif item.marker == 0xDA:
            segments.append("SOS")
        else:
            segments.append(item.name)
    return {"segments": segments, "entropy_bytes": structure.entropy_bytes,
            "valid": True,
            "sof_marker": structure.sof["marker"] if structure.sof else None,
            "sos_count": len(structure.sos_positions),
            "dri_count": structure.dri_count,
            "dri_values": structure.dri_values}


def reference_decode(data: bytes) -> tuple:
    """Independent verdict from a normal JPEG decoder."""
    try:
        image = Image.open(io.BytesIO(data))
        image.load()
        return True, "", image.size, image.mode
    except Exception as exc:  # noqa: BLE001 - any decoder error is the verdict
        return False, "%s: %s" % (type(exc).__name__, exc), (0, 0), ""


def require_editable(data: bytes) -> dict:
    """Refuse anything whose structure this adapter does not fully account for."""
    try:
        structure = parse(data, strict=True)
    except ParserError as exc:
        raise AdapterError(str(exc)) from exc
    _require(structure.sof is not None, "no SOF marker found")
    _require(structure.sof["marker"] in (SOF_BASELINE, SOF_EXTENDED),
             "unsupported SOF type 0x%02X" % structure.sof["marker"])
    _require(len(structure.sos_positions) == 1,
             "multi-scan input (%d scans) is not supported"
             % len(structure.sos_positions))
    # A baseline with two DRI segments has no single value to restore, so editing it
    # could not produce a control that is byte-identical to it.
    _require(structure.dri_count <= 1,
             "baseline already has %d DRI segments" % structure.dri_count)
    return walk(data)


def build_baseline(width: int = 64, height: int = 64, mode: str = "RGB",
                   quality: int = 90, seed: int = 7) -> bytes:
    """A real encoder produces the baseline; nothing is hand-assembled."""
    _require(1 <= width <= 65535 and 1 <= height <= 65535, "size out of range")
    _require(mode in ("RGB", "L"), "unsupported mode %r" % mode)
    if mode == "L":
        pixels = [(x * 3 + y * 5 + seed) % 256 for y in range(height) for x in range(width)]
        image = Image.new("L", (width, height))
    else:
        pixels = [((x * 7 + seed) % 256, (y * 5 + seed) % 256, (x + y) % 256)
                  for y in range(height) for x in range(width)]
        image = Image.new("RGB", (width, height))
    image.putdata(pixels)
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=quality)
    return buffer.getvalue()


def _segment_at(data: bytes, marker: int) -> Optional[tuple]:
    """(start, end) of the first segment with this marker, start pointing at 0xFF."""
    i = 2
    while i + 3 < len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        if data[i + 1] == marker:
            length = struct.unpack_from(">H", data, i + 2)[0]
            return i, i + 2 + length
        if data[i + 1] == 0xDA:
            return None
        length = struct.unpack_from(">H", data, i + 2)[0]
        i += 2 + length
    return None


def _sof_start(data: bytes) -> int:
    for marker in (SOF_BASELINE, SOF_EXTENDED):
        found = _segment_at(data, marker)
        if found:
            return found[0]
    raise AdapterError("no editable SOF segment")


def _apply_one(data: bytearray, op: dict) -> dict:
    """Apply one operation; return the journal entry needed to undo it."""
    kind = op.get("op")

    if kind == "set_sof_size":
        width, height = op.get("width"), op.get("height")
        _require(isinstance(width, int) and isinstance(height, int), "size must be int")
        _require(1 <= width <= 65535, "width out of range: %r" % (width,))
        _require(1 <= height <= 65535, "height out of range: %r" % (height,))
        start = _sof_start(data)
        prev_height = struct.unpack_from(">H", data, start + 5)[0]
        prev_width = struct.unpack_from(">H", data, start + 7)[0]
        struct.pack_into(">H", data, start + 5, height)
        struct.pack_into(">H", data, start + 7, width)
        return {"op": kind, "prev": {"width": prev_width, "height": prev_height}}

    if kind == "set_component_sampling":
        index, h, v = op.get("component"), op.get("h"), op.get("v")
        _require(isinstance(index, int), "component index must be int")
        _require(isinstance(h, int) and isinstance(v, int), "sampling must be int")
        _require(0 <= index, "negative component index: %r" % (index,))
        _require(1 <= h <= 4 and 1 <= v <= 4, "sampling out of range: %dx%d" % (h, v))
        start = _sof_start(data)
        count = data[start + 9]
        _require(index < count, "component index %d out of range (Nf=%d)" % (index, count))
        offset = start + 10 + index * 3 + 1
        prev = data[offset]
        data[offset] = ((h & 0x0F) << 4) | (v & 0x0F)
        return {"op": kind, "index": index, "offset": offset,
                "prev": {"h": prev >> 4, "v": prev & 0x0F}}

    if kind == "set_dri":
        interval = op.get("interval")
        _require(isinstance(interval, int), "interval must be int")
        _require(0 <= interval <= 65535, "interval out of range: %r" % (interval,))
        payload = b"\xff\xdd\x00\x04" + struct.pack(">H", interval)
        found = _segment_at(data, 0xDD)
        if found:
            prev = struct.unpack_from(">H", data, found[0] + 4)[0]
            data[found[0]:found[1]] = payload
            return {"op": kind, "mode": "replace", "prev_interval": prev,
                    "offset": found[0]}
        sos = _segment_at(data, 0xDA)
        position = sos[0] if sos else len(data) - 2
        data[position:position] = payload
        return {"op": kind, "mode": "insert", "prev_interval": None, "offset": position}

    if kind == "insert_segment":
        marker = op.get("marker")
        _require(isinstance(marker, int), "marker must be int")
        _require(marker in APP_MARKERS or marker == 0xFE,
                 "marker 0x%02X is not an insertable APP/COM marker" % marker)
        payload = bytes.fromhex(op.get("hex", ""))
        _require(len(payload) <= 65533, "payload too long: %d bytes" % len(payload))
        block = b"\xff" + bytes([marker]) + struct.pack(">H", len(payload) + 2) + payload
        sos = _segment_at(data, 0xDA)
        position = sos[0] if sos else len(data) - 2
        data[position:position] = block
        return {"op": kind, "offset": position, "length": len(block)}

    if kind == "strip_segment":
        marker = op.get("marker")
        _require(isinstance(marker, int), "marker must be int")
        _require(marker not in (0xD8, 0xD9, 0xDA), "cannot strip SOI/EOI/SOS")
        found = _segment_at(data, marker)
        _require(found is not None, "segment 0x%02X not present" % marker)
        removed = bytes(data[found[0]:found[1]])
        del data[found[0]:found[1]]
        return {"op": kind, "marker": marker, "offset": found[0], "removed": removed.hex()}

    raise AdapterError("unsupported op: %r" % (kind,))


def _undo_one(data: bytearray, entry: dict) -> None:
    """Reverse one journal entry on ``data`` in place."""
    kind = entry["op"]
    if kind == "set_sof_size":
        start = _sof_start(data)
        struct.pack_into(">H", data, start + 5, entry["prev"]["height"])
        struct.pack_into(">H", data, start + 7, entry["prev"]["width"])
    elif kind == "set_component_sampling":
        offset = entry["offset"]
        data[offset] = ((entry["prev"]["h"] & 0x0F) << 4) | (entry["prev"]["v"] & 0x0F)
    elif kind == "set_dri":
        if entry["mode"] == "replace":
            struct.pack_into(">H", data, entry["offset"] + 4, entry["prev_interval"])
        else:
            start = entry["offset"]
            _require(bytes(data[start:start + 2]) == b"\xff\xdd",
                     "DRI undo: expected injected segment at %d" % start)
            del data[start:start + 6]
    elif kind == "insert_segment":
        start, length = entry["offset"], entry["length"]
        _require(data[start] == 0xFF, "insert undo: no marker at %d" % start)
        del data[start:start + length]
    elif kind == "strip_segment":
        data[entry["offset"]:entry["offset"]] = bytes.fromhex(entry["removed"])
    else:
        raise AdapterError("cannot undo %r" % (kind,))


def apply_plan(baseline: bytes, plan: dict) -> tuple:
    """Apply a plan, returning (bytes, journal). Raises on anything unsupported."""
    require_editable(baseline)
    data = bytearray(baseline)
    journal = []
    for op in plan.get("operations", []):
        journal.append(_apply_one(data, op))
    return bytes(data), journal


def build_control(baseline: bytes, plan: dict) -> tuple:
    """Undo the plan in reverse on the crafted bytes.

    The control must reproduce the baseline bit for bit; if it does not, the plan or an
    operation is ambiguous, and this raises instead of shipping a control that differs
    from the baseline in an unexplained way.
    """
    crafted, journal = apply_plan(baseline, plan)
    control = bytearray(crafted)
    for entry in reversed(journal):
        _undo_one(control, entry)
    control = bytes(control)
    _require(control == baseline,
             "control does not reproduce the baseline: %d bytes differ"
             % sum(1 for a, b in zip(control, baseline) if a != b))
    return control, journal


def diff_range(left: bytes, right: bytes) -> dict:
    """Where two artifacts differ, for the record."""
    if len(left) != len(right):
        return {"same_length": False, "left": len(left), "right": len(right)}
    positions = [i for i, (a, b) in enumerate(zip(left, right)) if a != b]
    return {"same_length": True, "differences": len(positions),
            "first": positions[0] if positions else None,
            "last": positions[-1] if positions else None}


def make_artifact(role: str, name: str, data: bytes) -> Artifact:
    ok, error, size, mode = reference_decode(data)
    info = walk(data)
    return Artifact(role=role, name=name, data=data, sha256=sha256(data),
                    segments=info["segments"], reference_ok=ok,
                    reference_error=error, size=size, mode=mode)


def write_bundle(directory: Path, baseline: bytes, plan: dict) -> dict:
    """Materialise baseline, crafted and control with full provenance."""
    directory.mkdir(parents=True, exist_ok=True)
    crafted, journal = apply_plan(baseline, plan)
    control, _ = build_control(baseline, plan)
    items = [("BENIGN", "benign_baseline.jpg", baseline),
             ("MALICIOUS", "poc_plan.jpg", crafted),
             ("CONTROL", "ctrl_restored.jpg", control)]
    artifacts = []
    for role, name, data in items:
        artifact = make_artifact(role, name, data)
        (directory / name).write_bytes(data)
        artifacts.append(artifact)
    (directory / "plan.json").write_text(json.dumps(
        {"plan": plan, "journal": journal,
         "control_equals_baseline": control == baseline,
         "poc_vs_control": diff_range(crafted, control),
         "poc_vs_baseline": diff_range(crafted, baseline)},
        ensure_ascii=False, indent=1), encoding="utf-8")
    # The manifest is the verifiable record; plan.json stays for human reading.
    from .jpeg_bundle import write_manifest
    manifest = write_manifest(directory)
    return {"baseline_sha256": sha256(baseline),
            "manifest_sha256": manifest["manifest_sha256"],
            "journal": journal,
            "control_equals_baseline": control == baseline,
            "poc_vs_control": diff_range(crafted, control),
            "artifacts": [{"role": a.role, "name": a.name, "sha256": a.sha256,
                           "reference_ok": a.reference_ok,
                           "reference_error": a.reference_error,
                           "segments": a.segments, "size": list(a.size), "mode": a.mode}
                          for a in artifacts]}
