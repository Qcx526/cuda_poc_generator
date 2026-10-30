# -*- coding: utf-8 -*-
"""Mutate one field at a time inside every calibrated GPU struct.

The earlier calibration only set the version/size dword, so every call was
benign: the driver filled the struct and nothing depended on our input. This walks
the struct instead - one aligned dword at a time, extreme values - because that is
where a driver that trusts a caller-supplied count or index will write somewhere
it should not.

A probe can take the calling process with it: a driver writing through a count we
gave it corrupts our heap, and Python then dies with an unrelated exception. So
every probe is written to a marker before it runs, and results are appended as they
return; a restart knows exactly which probe killed the last run.

  python -m tools.driver.field_sweep --resume
"""

import argparse
import ctypes
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from tools.driver.drs_probe import Nvapi  # noqa: E402

MAP = ROOT / "data" / "driver" / "gpu_map.json"
RESULTS = ROOT / "data" / "driver" / "field-sweep.tsv"
MARKER = ROOT / "data" / "driver" / "field-sweep.armed"
CAP = 1 << 20
VALUES = (0xFFFFFFFF, 0)


def arity(proto: str) -> int:
    depth, count = 0, 1
    for char in proto:
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == "," and depth == 0:
            count += 1
    return count


def targets() -> list:
    import pathlib

    names = json.loads((ROOT / "data" / "nvapi_names.json").read_text(encoding="utf-8"))
    protos = json.loads((ROOT / "data" / "nvapi_protos.json").read_text(encoding="utf-8"))
    calibrated = json.loads(MAP.read_text(encoding="utf-8"))
    by_name = {name: ident for ident, name in names.items()}
    out = []
    for name, info in calibrated.items():
        ident = by_name.get(name)
        proto = protos.get(name, "")
        if not ident or arity(proto) != 2:
            continue          # a wrong arity writes through garbage arguments
        out.append((int(ident, 16), name, info["ver"], info["size"]))
    return out


def done_keys() -> set:
    if not RESULTS.is_file():
        return set()
    keys = set()
    for line in RESULTS.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if parts and parts[0] == "RES":
            keys.add(parts[1])
    return keys


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="field-level probe of GPU structs")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="stop after N probes")
    args = parser.parse_args(argv)

    nv = Nvapi()
    nv.open()
    handles = (ctypes.c_void_p * 64)()
    count = ctypes.c_uint32(0)
    nv._fn(0xE5AC921F, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)])(
        handles, ctypes.byref(count))
    gpu = handles[0]
    if not gpu:
        print("no GPU handle")
        return 2

    done = done_keys() if args.resume else set()
    if args.resume and MARKER.is_file():
        armed = MARKER.read_text(encoding="utf-8").strip()
        if armed and armed not in done:
            with RESULTS.open("a", encoding="utf-8") as handle:
                handle.write("RES\t%s\tDIED\t-\n" % armed)
            done.add(armed)
            print("[!] 上次停在 %s —— 调用把进程带走了" % armed, flush=True)

    probes = runs = 0
    for ident, name, ver, size in targets():
        fn = nv._fn(ident, [ctypes.c_void_p, ctypes.c_void_p])
        if not fn:
            continue
        for offset in range(4, max(size, 8), 4):
            for value in VALUES:
                key = "%s|%d|0x%x" % (name, offset, value)
                if key in done:
                    continue
                if args.limit and probes >= args.limit:
                    print("达到上限 %d" % args.limit)
                    return 0
                MARKER.write_text(key, encoding="utf-8")
                buf = (ctypes.c_ubyte * CAP)()
                ctypes.memmove(buf, ctypes.byref(ctypes.c_uint32(size | (ver << 16))), 4)
                ctypes.memmove(ctypes.byref(buf, offset),
                               ctypes.byref(ctypes.c_uint32(value)), 4)
                probes += 1
                try:
                    rc = fn(gpu, buf)
                except Exception as exc:          # noqa: BLE001 - keep sweeping
                    with RESULTS.open("a", encoding="utf-8") as handle:
                        handle.write("RES\t%s\tEXC:%s\t-\n" % (key, type(exc).__name__))
                    continue
                runs += 1
                over = next((i for i in range(size, 65536) if buf[i]), None)
                with RESULTS.open("a", encoding="utf-8") as handle:
                    handle.write("RES\t%s\t%d\t%s\n" % (key, rc, over))
                if over is not None:
                    print("[!] 越界写 %s -> 偏移 %d (rc=%d)" % (key, over, rc), flush=True)
    print("完成 %d 次探测（%d 次正常返回）" % (probes, runs))
    MARKER.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
