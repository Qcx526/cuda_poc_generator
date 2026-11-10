# -*- coding: utf-8 -*-
"""Run nvJPEG inputs through several library versions with the fixed probe.

Every run names the DLL it loads, so the version in the record is the version that
executed. Crash means abnormal termination only: a Windows structured exception
surfaces as an exit code at or above 0xC0000000, not as any non-zero value.
"""

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
F15 = ROOT / "data" / "driver" / "f15"
PROBE = F15 / "nvjpeg_probe.exe"

VERSIONS = {
    "11.4.0": Path(r"C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v11.2/bin/nvjpeg64_11.dll"),
    "12.3.1": Path(r"C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.4/bin/nvjpeg64_12.dll"),
    "13.2.2": Path(r"D:/cuda1341_extract/libnvjpeg/nvjpeg/bin/x64/nvjpeg64_13.dll"),
}

EXCEPTION_FLOOR = 0xC0000000
STAGE_KEYS = ("STAGE2 file_read", "STAGE4 nvjpegGetImageInfo", "STAGE6", "STAGE7")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_crash(code) -> bool:
    return code is not None and (code < 0 or code >= EXCEPTION_FLOOR)


def run(version: str, jpg: Path) -> dict:
    dll = VERSIONS[version]
    env = dict(os.environ)
    env["PATH"] = str(dll.parent) + os.pathsep + env["PATH"]
    proc = subprocess.run([str(PROBE), "--dll", str(dll), "--file", str(jpg)],
                          capture_output=True, text=True, errors="replace",
                          timeout=180, env=env)
    code = proc.returncode
    out = proc.stdout or ""
    stages = {}
    for key in STAGE_KEYS:
        for line in out.splitlines():
            if line.startswith(key):
                stages[key.split()[0]] = line.strip()
    lib = re.search(r"^LIB version=(\S+)", out, re.M)
    phases = re.search(r"^LIB symbol_phases=(\S+)", out, re.M)
    last = re.search(r"^VERDICT last_success_stage=(\S+)", out, re.M)
    return {
        "version": version,
        "dll": str(dll),
        "dll_sha256": sha256(dll),
        "reported_version": lib.group(1) if lib else None,
        "phases": phases.group(1) if phases else None,
        "input": jpg.name,
        "input_sha256": sha256(jpg),
        "exit": code,
        "kind": ("crash" if is_crash(code) else
                 "rejected" if code == 1 else "ok" if code == 0 else "other"),
        "last_stage": last.group(1) if last else None,
        "stages": stages,
        "stdout": out[-3000:],
        "stderr": (proc.stderr or "")[-1000:],
    }


def collect(runs_dir: Path) -> list:
    return sorted(p for p in runs_dir.glob("*.jpg"))


def main() -> int:
    groups = {name: F15 / name for name in ("run1", "run2", "run3", "run4")}
    rows = []
    print("%-6s %-38s %s" % ("run", "file", "  ".join("%-12s" % v for v in VERSIONS)))
    for name, directory in groups.items():
        if not directory.is_dir():
            continue
        for jpg in collect(directory):
            record = {"run": name, "file": jpg.name, "results": {}}
            cells = []
            for version in VERSIONS:
                r = run(version, jpg)
                record["results"][version] = r
                cells.append("%-12s" % ("%s(%s)" % (r["kind"], r["exit"])))
            rows.append(record)
            print("%-6s %-38s %s" % (name, jpg.name, "  ".join(cells)))
    (F15 / "stage_runs.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    print("saved stage_runs.json rows=%d" % len(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
