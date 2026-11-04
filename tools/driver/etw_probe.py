# -*- coding: utf-8 -*-
"""Capture DxgKrnl ETW while running a fixed scenario, then count events.

The question this answers is narrow: can ETW tell an escape call apart from
ordinary graphics activity? The provider emits numeric task ids only (no names
in the tracerpt output), so the test is a differential count, not a semantic
decoding.
"""

import argparse
import collections
import csv
import subprocess
import sys
from pathlib import Path

PROVIDER = "{802EC45A-1E99-4B83-9920-87C98277BA9D}"   # Microsoft-Windows-DxgKrnl
SESSION = "cpg_dxg"


def _run(command, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, errors="replace", **kwargs)


def start_trace(etl: Path) -> None:
    etl.parent.mkdir(parents=True, exist_ok=True)
    _run(["logman", "start", SESSION, "-p", PROVIDER, "-o", str(etl), "-ets"])


def stop_trace() -> None:
    _run(["logman", "stop", SESSION, "-ets"])


def scenario(with_escape: bool) -> None:
    """Same object setup either way; the flag adds exactly one escape call."""
    import ctypes

    from src import driver_abi as abi

    if not with_escape:
        for _ in abi.r0_selftest():
            pass
        return

    user32, gdi32 = abi.bind_user32(), abi.bind_gdi32()
    device = abi.DISPLAY_DEVICEW()
    device.cb = ctypes.sizeof(abi.DISPLAY_DEVICEW)
    user32.EnumDisplayDevicesW(None, 0, ctypes.byref(device), 0)
    gdi = abi.bind_gdi_dc()
    hdc = gdi.CreateDCW("DISPLAY", device.DeviceName, None, None)
    opened = abi.D3DKMT_OPENADAPTERFROMHDC()
    opened.hDc = hdc
    if gdi32.D3DKMTOpenAdapterFromHdc(ctypes.byref(opened)) != 0:
        return
    created = abi.D3DKMT_CREATEDEVICE()
    created.Adapter.hAdapter = opened.hAdapter
    if gdi32.D3DKMTCreateDevice(ctypes.byref(created)) != 0:
        return
    context = abi.D3DKMT_CREATECONTEXT()
    context.hDevice = created.hDevice
    gdi32.D3DKMTCreateContext(ctypes.byref(context))

    escape = abi.D3DKMT_ESCAPE()
    escape.hAdapter = opened.hAdapter
    escape.hDevice = created.hDevice
    escape.hContext = context.hContext
    status = gdi32.D3DKMTEscape(ctypes.byref(escape))
    print("escape status = %s" % abi.ntstatus(status))

    gdi32.D3DKMTDestroyContext(ctypes.byref(abi.D3DKMT_DESTROYCONTEXT(context.hContext)))
    gdi32.D3DKMTDestroyDevice(ctypes.byref(abi.D3DKMT_DESTROYDEVICE(created.hDevice)))
    gdi32.D3DKMTCloseAdapter(ctypes.byref(abi.D3DKMT_CLOSEADAPTER(opened.hAdapter)))
    gdi.DeleteDC(hdc)


def summarise(csv_path: Path) -> dict:
    csv.field_size_limit(10 ** 7)
    by_task: collections.Counter = collections.Counter()
    by_pid_task: collections.Counter = collections.Counter()
    total = 0
    with open(csv_path, encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.reader(handle)
        next(reader, None)
        for row in reader:
            if len(row) < 10 or not row[0].startswith("Microsoft-Windows-DxgKrnl"):
                continue
            total += 1
            task, pid = row[7].strip(), row[9].strip()
            by_task[task] += 1
            by_pid_task["%s|%s" % (pid, task)] += 1
    return {"total": total, "by_task": dict(by_task.most_common(40)),
            "by_pid_task": dict(by_pid_task.most_common(60))}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--escape", action="store_true")
    parser.add_argument("--etl", default="data/driver/etw/run.etl")
    parser.add_argument("--csv", default="data/driver/etw/run.csv")
    parser.add_argument("--out", default="data/driver/etw/run_summary.json")
    args = parser.parse_args(argv)

    etl, csv_path = Path(args.etl), Path(args.csv)
    for stale in (etl, csv_path):
        if stale.exists():
            stale.unlink()
    start_trace(etl)
    try:
        scenario(args.escape)
    finally:
        stop_trace()
    if not etl.is_file():
        print("no ETL produced - trace could not start (permissions?)")
        return 2
    _run(["tracerpt", str(etl), "-o", str(csv_path), "-of", "CSV", "-y"])
    if not csv_path.is_file():
        print("tracerpt produced no CSV")
        return 3
    summary = summarise(csv_path)
    summary["escape_call"] = bool(args.escape)
    import json

    Path(args.out).write_text(json.dumps(summary, ensure_ascii=False, indent=1),
                              encoding="utf-8")
    print("events=%d -> %s" % (summary["total"], args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
