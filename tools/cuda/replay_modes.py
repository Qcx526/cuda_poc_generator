# -*- coding: utf-8 -*-
"""Replay archived artifacts with the argv candidates actually use.

The stored trusted records ran `cuobjdump <file>`. Candidates run `cuobjdump -elf
<file>`, and for CVE-2025-23346 that difference is the whole result: bare form exits 0,
-elf exits 139. This writes a separate record instead of touching the originals.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.trusted_exec import run_trusted   # noqa: E402

OUT = ROOT / "data" / "driver" / "f14-replay"
CASES = ("CVE-2025-23346", "CVE-2025-23308", "CVE-2025-23338",
         "CVE-2024-0111", "CVE-2024-0124", "CVE-2024-0125")


def newest_dir(cve: str):
    base = ROOT / "data" / "outputs" / cve
    candidates = [base] + sorted(base.glob("_stale_*"))
    best, best_count = None, 0
    for path in candidates:
        if not path.is_dir():
            continue
        count = len(list(path.glob("*.cubin"))) + len(list(path.glob("*.elf")))
        if count > best_count:
            best, best_count = path, count
    return best, best_count


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for cve in CASES:
        directory, count = newest_dir(cve)
        if directory is None or not count:
            print("%-18s 无产物" % cve)
            continue
        run = run_trusted(directory, "cpg/cuda112-py3:1.0")
        crashes = [i for i in run.invocations
                   if i.exit_code is not None and (i.exit_code < 0 or i.exit_code >= 128)]
        (OUT / ("%s.json" % cve)).write_text(json.dumps({
            "directory": str(directory),
            "tool_version": run.tool_version,
            "invocations": [vars(i) for i in run.invocations],
            "note": "按候选实际使用的 argv 重放；原始 trusted.json 未改动",
        }, ensure_ascii=False, indent=1), encoding="utf-8")
        print("%-18s 产物=%d 调用=%d 崩溃=%d %s"
              % (cve, count, len(run.invocations), len(crashes),
                 [(c.run_id.split(":")[1], c.run_id.split(":")[-1], c.exit_code) for c in crashes][:2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
