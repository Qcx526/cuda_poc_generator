# -*- coding: utf-8 -*-
"""JPEG input adapter: build a legal baseline, then mutate named fields.

The point of the adapter is that a plan describes *what* to change and the tool decides
*how* to lay it out, so a candidate never has to hand-assemble entropy-coded data. That
was the actual failure in F15 round 7: the files carried DHT and SOS but the bit stream
did not decode.

Every mutation is recorded with the original bytes, the mutated bytes and both hashes, so
a result can always be traced back to what changed. Validation runs two independent
readers - the segment walker here and Pillow's own decoder - because "markers parse" and
"image decodes" are different facts.
"""

import hashlib
import io
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from PIL import Image

SOF_MARKERS = {0xC0, 0xC1, 0xC2}
SEGMENT_NAMES = {0xD8: "SOI", 0xD9: "EOI", 0xDB: "DQT", 0xC4: "DHT", 0xDA: "SOS",
                 0xDD: "DRI", 0xE0: "APP0", 0xE1: "APP1", 0xFE: "COM"}


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


def walk(data: bytes) -> dict:
    """Segment list plus SOF fields, without decoding entropy data."""
    info = {"segments": [], "entropy_bytes": 0, "valid": data[:2] == b"\xff\xd8"}
    i = 2
    while i + 3 < len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker == 0xD9:
            info["segments"].append("EOI")
            break
        if marker == 0xDA:
            length = struct.unpack_from(">H", data, i + 2)[0]
            info["segments"].append("SOS(len=%d)" % length)
            info["entropy_bytes"] = max(0, len(data) - (i + 2 + length) - 2)
            break
        length = struct.unpack_from(">H", data, i + 2)[0]
        name = SEGMENT_NAMES.get(marker, "%02X(len=%d)" % (marker, length))
        if marker in SOF_MARKERS:
            name = "SOF%d(%dx%d,comp=%d)" % (marker - 0xC0,
                                             struct.unpack_from(">H", data, i + 7)[0],
                                             struct.unpack_from(">H", data, i + 5)[0],
                                             data[i + 9])
        info["segments"].append(name)
        i += 2 + length
    return info


def reference_decode(data: bytes) -> tuple:
    """Independent verdict: does a normal JPEG decoder accept these bytes?"""
    try:
        image = Image.open(io.BytesIO(data))
        image.load()
        return True, "", image.size, image.mode
    except Exception as exc:  # noqa: BLE001 - any decoder error is the verdict
        return False, "%s: %s" % (type(exc).__name__, exc), (0, 0), ""


def build_baseline(width: int = 64, height: int = 64, mode: str = "RGB",
                   quality: int = 90, seed: int = 7) -> bytes:
    """A real encoder produces the baseline; nothing here is hand-assembled."""
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


def _find_segment(data: bytes, marker: int) -> Optional[tuple]:
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


def apply_plan(baseline: bytes, plan: dict) -> tuple:
    """Apply a named mutation; returns (bytes, notes). Unknown ops are refused."""
    data = bytearray(baseline)
    notes = []
    for op in plan.get("operations", []):
        kind = op.get("op")
        if kind == "set_sof_size":
            found = _find_segment(data, 0xC0)
            if not found:
                return bytes(data), ["no SOF0 to edit"]
            start = found[0]
            struct.pack_into(">H", data, start + 6, int(op["height"]) & 0xFFFF)
            struct.pack_into(">H", data, start + 8, int(op["width"]) & 0xFFFF)
            notes.append("set_sof_size %dx%d" % (op["width"], op["height"]))
        elif kind == "set_component_sampling":
            found = _find_segment(data, 0xC0)
            if not found:
                return bytes(data), ["no SOF0 to edit"]
            start = found[0]
            count = data[start + 9]
            index = int(op["component"])
            if index >= count:
                return bytes(data), ["component index out of range"]
            offset = start + 10 + index * 3 + 1
            data[offset] = ((int(op["h"]) & 0x0F) << 4) | (int(op["v"]) & 0x0F)
            notes.append("set_component_sampling[%d]=%dx%d" % (index, op["h"], op["v"]))
        elif kind == "set_dri":
            interval = int(op["interval"]) & 0xFFFF
            payload = b"\xff\xdd\x00\x04" + struct.pack(">H", interval)
            found = _find_segment(data, 0xDD)
            if found:
                data[found[0]:found[1]] = payload
                notes.append("replace_dri=%d" % interval)
            else:
                sos = _find_segment(data, 0xDA)
                position = sos[0] if sos else len(data) - 2
                data[position:position] = payload
                notes.append("insert_dri=%d" % interval)
        elif kind == "insert_segment":
            marker = int(op["marker"])
            payload = bytes.fromhex(op.get("hex", ""))
            block = b"\xff" + bytes([marker]) + struct.pack(">H", len(payload) + 2) + payload
            sos = _find_segment(data, 0xDA)
            position = sos[0] if sos else len(data) - 2
            data[position:position] = block
            notes.append("insert_segment %02X len=%d" % (marker, len(payload)))
        elif kind == "strip_segment":
            marker = int(op["marker"])
            found = _find_segment(data, marker)
            if not found:
                notes.append("strip_segment %02X: absent" % marker)
            else:
                del data[found[0]:found[1]]
                notes.append("strip_segment %02X" % marker)
        else:
            return bytes(data), ["unsupported op: %s" % kind]
    return bytes(data), notes


def make_artifact(role: str, name: str, data: bytes) -> Artifact:
    ok, error, size, mode = reference_decode(data)
    info = walk(data)
    return Artifact(role=role, name=name, data=data, sha256=sha256(data),
                    segments=info["segments"], reference_ok=ok, reference_error=error,
                    size=size, mode=mode)


def build_control(baseline: bytes, plan: dict) -> bytes:
    """Same envelope as the crafted file, with the mutated field put back."""
    restored = {"operations": [dict(op) for op in plan.get("operations", [])]}
    for op in restored["operations"]:
        if op.get("op") == "set_sof_size":
            image = Image.open(io.BytesIO(baseline))
            op["width"], op["height"] = image.size
        elif op.get("op") == "set_component_sampling":
            op["h"], op["v"] = 1, 1
        elif op.get("op") == "set_dri":
            op["interval"] = 64
    return apply_plan(baseline, restored)[0]


def write_bundle(directory: Path, baseline: bytes, plan: dict) -> dict:
    """Materialise baseline, crafted and control; report every hash."""
    directory.mkdir(parents=True, exist_ok=True)
    crafted, notes = apply_plan(baseline, plan)
    control = build_control(baseline, plan)
    items = [
        ("BENIGN", "benign_baseline.jpg", baseline),
        ("MALICIOUS", "poc_plan.jpg", crafted),
        ("CONTROL", "ctrl_restored.jpg", control),
    ]
    artifacts = []
    for role, name, data in items:
        artifact = make_artifact(role, name, data)
        (directory / name).write_bytes(data)
        artifacts.append(artifact)
    (directory / "plan.json").write_text(
        json.dumps({"plan": plan, "notes": notes}, ensure_ascii=False, indent=1),
        encoding="utf-8")
    return {
        "baseline_sha256": sha256(baseline),
        "notes": notes,
        "artifacts": [{"role": a.role, "name": a.name, "sha256": a.sha256,
                       "reference_ok": a.reference_ok,
                       "reference_error": a.reference_error,
                       "segments": a.segments, "size": list(a.size), "mode": a.mode}
                      for a in artifacts],
    }
