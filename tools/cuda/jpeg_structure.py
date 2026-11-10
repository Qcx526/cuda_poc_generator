# -*- coding: utf-8 -*-
"""Read JPEG structure from the bytes, independently of the candidate.

Everything here follows ITU-T T.81 marker layout: SOF carries precision, height, width
and one record per component (id, h, v, quant table). The derived quantities - component
plane size and the MCU grid - are arithmetic on those fields, computed by the harness so
a candidate's own numbers cannot stand in for them.

This is structure, not nvJPEG behaviour: it says what the file asks the decoder to do.
"""

import hashlib
import json
import struct
from pathlib import Path

SOF_MARKERS = {0xC0, 0xC1, 0xC2}


def parse(path: Path) -> dict:
    data = path.read_bytes()
    out = {"file": path.name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
           "valid_jpeg": data[:2] == b"\xff\xd8", "eoi": data[-2:] == b"\xff\xd9"}
    i, sof = 2, None
    while i + 3 < len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        length = struct.unpack_from(">H", data, i + 2)[0]
        if marker in SOF_MARKERS:
            sof = {"marker": "SOF%d" % (marker - 0xC0), "offset": i,
                   "precision": data[i + 4],
                   "height": struct.unpack_from(">H", data, i + 5)[0],
                   "width": struct.unpack_from(">H", data, i + 7)[0],
                   "components": data[i + 9]}
            comps = []
            base = i + 10
            for c in range(sof["components"]):
                cid = data[base + c * 3]
                hv = data[base + c * 3 + 1]
                comps.append({"id": cid, "h": hv >> 4, "v": hv & 0x0F,
                              "quant": data[base + c * 3 + 2]})
            sof["component_list"] = comps
            break
        i += 2 + length
    out["sof"] = sof
    if sof and sof["component_list"]:
        hmax = max(c["h"] for c in sof["component_list"]) or 0
        vmax = max(c["v"] for c in sof["component_list"]) or 0
        out["derived"] = {
            "hmax": hmax, "vmax": vmax,
            "mcu_cols": (sof["width"] + 8 * hmax - 1) // (8 * hmax) if hmax else None,
            "mcu_rows": (sof["height"] + 8 * vmax - 1) // (8 * vmax) if vmax else None,
            "planes": [{"id": c["id"],
                        "width": -(-sof["width"] * c["h"] // hmax) if hmax else None,
                        "height": -(-sof["height"] * c["v"] // vmax) if vmax else None,
                        "zero_extent": (c["h"] == 0 or c["v"] == 0)}
                       for c in sof["component_list"]],
        }
    return out


def scan(directory: Path) -> list:
    return [parse(p) for p in sorted(directory.glob("*.jpg"))]


def main() -> int:
    import sys
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/driver/f15/run6")
    rows = scan(target)
    print(json.dumps(rows, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
