# -*- coding: utf-8 -*-
"""Re-derive F15 verdicts under the corrected criteria, without touching evidence.

run1/result.json was written by a classifier that counted any non-zero exit as a
crash, so a clean BAD_JPEG rejection was recorded as crafted_crashed=true. The run
records themselves are correct; only the verdict was wrong. This writes a separate
corrected file beside each result and leaves the original byte-identical.
"""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.cuda.f15_nvjpeg import classify, sha256   # noqa: E402

BASE = ROOT / "data" / "driver" / "f15"


def corrected_for(run_dir: Path) -> dict:
    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    runs = result.get("runs", [])
    verdict = classify(runs)
    stages = {}
    for item in runs:
        out = item.get("stdout", "")
        stage = "unknown"
        for marker in ("nvjpegGetImageInfo", "nvjpegDecode"):
            if "%s=" % marker in out:
                stage = marker
                if "%s=BAD_JPEG" % marker in out or "%s=INVALID_PARAMETER" % marker in out:
                    break
        stages[item["file"]] = stage
    return {
        "run": run_dir.name,
        "original_verdict": result.get("verdict"),
        "corrected_verdict": verdict,
        "reached_stage": stages,
        "rule": ("崩溃只认异常终止（负退出码或 Windows 结构化异常）；"
                 "exit=1 是库返回错误状态，记为正常拒绝"),
        "original_sha256": sha256(run_dir / "result.json"),
    }


def main() -> int:
    summary = []
    for run_dir in sorted(BASE.glob("run*")):
        if not (run_dir / "result.json").is_file():
            continue
        corrected = corrected_for(run_dir)
        (run_dir / "result.corrected.json").write_text(
            json.dumps(corrected, ensure_ascii=False, indent=1), encoding="utf-8")
        summary.append(corrected)
        v = corrected["corrected_verdict"]
        print("%-6s crafted_crashed=%-5s differential=%-5s rejected=%s"
              % (run_dir.name, v["crafted_crashed"], v["differential"],
                 ",".join(v["rejected"]) or "-"))
    (BASE / "verdicts.corrected.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
