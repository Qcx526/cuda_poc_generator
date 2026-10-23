# -*- coding: utf-8 -*-
"""Enumerate and survey the NVAPI surface of nvapi64.dll.

Two modes, both offline-safe by design:

  enumerate  read the dispatch table straight out of the PE image. The table is
             16 bytes per entry - function pointer, then the API id - and ends
             at a null pointer. Nothing is executed, so this cannot crash a
             machine.

  survey     call each id with a *valid* buffer and record the status. Every
             attempt is logged before it runs, so a crash names the id that
             caused it instead of losing the whole run.

The survey deliberately sends a well-formed buffer, never a bad pointer: a bad
pointer to an unknown function can reach the kernel driver and bugcheck the
machine, which is not acceptable on a workstation.
"""

import argparse
import ctypes
import json
import struct
from ctypes import c_void_p, c_uint, c_int
from pathlib import Path
from typing import Dict, List, Optional

ENTRY_SIZE = 16


def _pe_sections(pe: bytes):
    e = struct.unpack_from("<I", pe, 0x3C)[0]
    nsec = struct.unpack_from("<H", pe, e + 6)[0]
    opt = e + 24
    base = struct.unpack_from("<Q", pe, opt + 24)[0]
    out = []
    off = opt + struct.unpack_from("<H", pe, e + 20)[0]
    for i in range(nsec):
        s = off + i * 40
        vs, va, rs, rp = struct.unpack_from("<IIII", pe, s + 8)
        out.append((pe[s:s + 8].rstrip(b"\0").decode(errors="ignore"), va, vs, rp, rs))
    return base, out


def enumerate_ids(dll: Path, table_rva: int) -> List[Dict[str, object]]:
    pe = Path(dll).read_bytes()
    base, sections = _pe_sections(pe)

    def r2o(rva: int) -> Optional[int]:
        for _, va, vs, rp, rs in sections:
            if va <= rva < va + max(vs, rs):
                return rp + (rva - va)
        return None

    off = r2o(table_rva)
    if off is None:
        raise SystemExit("table rva 0x%x is outside every section" % table_rva)
    entries = []
    for i in range(65536):
        fn, ident, _pad = struct.unpack_from("<QII", pe, off + i * ENTRY_SIZE)
        if fn == 0:
            break
        entries.append({"id": ident, "rva": fn - base})
    return entries


def survey(ids: List[int], limit: int, log: Path, start: int = 0) -> int:
    dll = ctypes.WinDLL("nvapi64.dll")
    qi = dll.nvapi_QueryInterface
    qi.argtypes = [c_uint]
    qi.restype = c_void_p
    init = ctypes.WINFUNCTYPE(c_int)(qi(0x0150E828))
    init()

    buffer = ctypes.create_string_buffer(1024)
    struct.pack_into("<I", buffer, 0, 1024 | (1 << 16))
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as fh:
        for n, ident in enumerate(ids[start:start + limit], start=start):
            fh.write(json.dumps({"try": "0x%08x" % ident}) + "\n")
            fh.flush()
            addr = qi(ident)
            if not addr:
                fh.write(json.dumps({"id": "0x%08x" % ident, "status": "null"}) + "\n")
                fh.flush()
                continue
            fn = ctypes.WINFUNCTYPE(c_int, c_void_p)(addr)
            status = fn(ctypes.byref(buffer))
            fh.write(json.dumps({"id": "0x%08x" % ident, "status": status}) + "\n")
            fh.flush()
    return 0


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="NVAPI surface enumeration and survey")
    parser.add_argument("mode", choices=["enumerate", "survey"])
    parser.add_argument("--dll", default=r"C:/Windows/System32/nvapi64.dll")
    parser.add_argument("--table-rva", default="0x60D000")
    parser.add_argument("--ids", default="data/nvapi_ids.json")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--log", default="data/nvapi_survey.jsonl")
    args = parser.parse_args(argv)

    if args.mode == "enumerate":
        entries = enumerate_ids(Path(args.dll), int(args.table_rva, 0))
        Path(args.ids).write_text(json.dumps(entries, indent=1), encoding="utf-8")
        print("enumerated %d ids -> %s" % (len(entries), args.ids))
        return 0

    ids = [int(e["id"]) for e in json.loads(Path(args.ids).read_text(encoding="utf-8"))]
    return survey(ids, args.limit or len(ids), Path(args.log), args.start)


if __name__ == "__main__":
    raise SystemExit(main())
