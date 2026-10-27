# -*- coding: utf-8 -*-
"""Candidate escape codes, read from the driver's own instructions.

The published NVIDIA PoCs all begin the same way: a 32-bit escape code in the
0x1000xxxx range is handed to D3DKMTEscape, and the miniport's DxgkDdiEscape
handler decides what to do with the private data. The codes are not secret but
they are not documented either - they exist only as immediates in nvlddmkm.sys.

This finds them without executing anything. A byte scan is used rather than a
full disassembly because the file is seventy megabytes and a linear sweep at that
size costs minutes; the opcode patterns below are the ones that carry a 32-bit
immediate, so a false positive is a constant that happens to share the prefix and
is filtered out by validation in the caller.

  python -m tools.extract_escape_codes
  python -m tools.extract_escape_codes --min-hits 2 --json data/probe/escape_codes.json
"""

import argparse
import collections
import json
import os
import struct
from pathlib import Path
from typing import Dict, List

ESCAPE_PREFIX = 0x1000


def file_version(path: Path) -> str:
    """Four-part version from the file's resource, or empty when unreadable."""
    import ctypes
    from ctypes import wintypes
    version = ctypes.WinDLL("version")
    size = version.GetFileVersionInfoSizeW(str(path), None)
    if not size:
        return ""
    buffer = ctypes.create_string_buffer(size)
    if not version.GetFileVersionInfoW(str(path), 0, size, buffer):
        return ""
    pointer = ctypes.c_void_p()
    length = wintypes.UINT()
    if not version.VerQueryValueW(buffer, "\\", ctypes.byref(pointer),
                                  ctypes.byref(length)):
        return ""
    # VS_FIXEDFILEINFO: signature, strucVersion, FileVersionMS, FileVersionLS.
    # Reading MS out of slot 1 gives a plausible-looking wrong answer.
    fixed = ctypes.cast(pointer, ctypes.POINTER(wintypes.DWORD * 4)).contents
    return "%d.%d.%d.%d" % (fixed[2] >> 16, fixed[2] & 0xFFFF,
                            fixed[3] >> 16, fixed[3] & 0xFFFF)


def nvidia_version(windows_version: str) -> str:
    """31.0.15.3598 -> 535.98: the driver's own numbering hides in the last digits."""
    parts = windows_version.split(".")
    if len(parts) != 4:
        return ""
    # 31.0.15.3598 -> digits "5" + "3598" = 53598, presented as 535.98.
    digits = "%d%s" % (int(parts[2]) % 10, parts[3].zfill(4))
    return "%s.%s" % (digits[:-2], digits[-2:])


def loaded_driver_version() -> str:
    import subprocess
    try:
        text = subprocess.run(["nvidia-smi", "--query-gpu=driver_version",
                               "--format=csv,noheader"], capture_output=True,
                              text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    return text.strip().splitlines()[0].strip() if text.strip() else ""


def driver_path(want: str = "") -> Path:
    """The driver that is actually loaded, not the newest one on disk.

    The DriverStore keeps every version ever installed; picking by modified time
    analyses whichever was written last, which is neither the running driver nor
    the one the CVE names.
    """
    root = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "DriverStore" / "FileRepository"
    candidates = list(root.rglob("nvlddmkm.sys"))
    if not candidates:
        raise FileNotFoundError("nvlddmkm.sys not found under %s" % root)
    want = want or loaded_driver_version()
    for candidate in candidates:
        if want and nvidia_version(file_version(candidate)) == want:
            return candidate
    raise FileNotFoundError("no nvlddmkm.sys matches driver %s; found %s"
                            % (want, [file_version(item) for item in candidates]))


def scan(data: bytes) -> Dict[int, int]:
    """Count immediates in the vendor escape range, by opcode shape.

    Covered: mov r32, imm32 (B8+r), cmp eax, imm32 (3D), cmp r32, imm32
    (81 /r), and the REX-prefixed forms (41 81 /r, 41 B8+r). Other encodings
    exist; these are the ones a dispatch table is written with.
    """
    hits: collections.Counter = collections.Counter()
    limit = len(data) - 8

    def record(offset: int) -> None:
        value = struct.unpack_from("<I", data, offset)[0]
        if ESCAPE_PREFIX == (value >> 16) & 0xFFFF or \
                0x10000000 <= value <= 0x1000FFFF:
            hits[value] += 1

    for index in range(limit):
        byte = data[index]
        if byte in (0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0x3D):
            record(index + 1)
        elif byte == 0x81 and data[index + 1] in range(0xF8, 0x100):
            record(index + 2)
        elif (byte == 0x41 and data[index + 1] == 0x81
              and data[index + 2] in range(0xF8, 0x100)):
            record(index + 3)
        elif byte == 0x41 and 0xB8 <= data[index + 1] <= 0xBF:
            record(index + 2)
    return dict(hits)


def plausible(code: int) -> bool:
    """Escape codes look like 0x1000 followed by a two-byte function number."""
    return (code >> 16) == 0x1000 and 0 < (code & 0xFFFF) < 0x2000


def summarise(hits: Dict[int, int], min_hits: int = 1) -> List[Dict[str, object]]:
    rows = [{"code": "0x%08x" % code, "value": code, "hits": count}
            for code, count in hits.items()
            if count >= min_hits and plausible(code)]
    return sorted(rows, key=lambda row: (-row["hits"], row["value"]))


def main() -> int:
    parser = argparse.ArgumentParser(description="find escape code candidates")
    parser.add_argument("--driver", default="", help="path to nvlddmkm.sys")
    parser.add_argument("--min-hits", type=int, default=1)
    parser.add_argument("--json", default="data/probe/escape_codes.json")
    args = parser.parse_args()

    path = Path(args.driver) if args.driver else driver_path()
    data = path.read_bytes()
    print("%s (%.1f MB)" % (path, len(data) / 1e6))

    hits = scan(data)
    rows = summarise(hits, args.min_hits)
    print("%d immediate candidates in 0x1000xxxx, %d plausible as escape codes\n"
          % (len(hits), len(rows)))
    for row in rows[:25]:
        print("  %s  hits=%d" % (row["code"], row["hits"]))
    if len(rows) > 25:
        print("  ... %d more" % (len(rows) - 25))

    # The historical codes make a useful check: if they are gone, the driver
    # renumbered its interface and an old PoC cannot be reused as written.
    for known in (0x100008B, 0x100010B):
        state = "present x%d" % hits[known] if known in hits else "absent"
        print("  historical 0x%08x: %s" % (known, state))

    target = Path(args.json)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"driver": str(path), "candidates": rows},
                                 ensure_ascii=False, indent=2), encoding="utf-8")
    print("written to %s" % target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
