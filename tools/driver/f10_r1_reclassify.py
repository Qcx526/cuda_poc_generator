# -*- coding: utf-8 -*-
"""Re-read the F10-Step1 runs with the state ladder, without touching the logs.

The summary.json written during the run called arm B's exit=1 an anomaly. That was
wrong, and the original file stays as it is: this script adds a separate record that
says what the same observations mean under the corrected rule.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.exec_evidence import (CANDIDATE_STARTED, GENERATION_COMPLETED,  # noqa: E402
                               INPUT_CREATED, RunRecord, TARGET_TOOL_INVOKED,
                               TARGET_TOOL_RETURNED, ToolInvocation)

OUT = ROOT / "data" / "driver" / "f10step1"
TOOL = "nvdisasm"


def build(arm: str) -> dict:
    log = (OUT / arm / "run.log").read_text(encoding="utf-8", errors="replace")
    code = (OUT / arm / "candidate.py").read_text(encoding="utf-8", errors="replace")
    exits = [int(x) for x in re.findall(r"EXIT=(-?\d+)", log)]
    traceback = "Traceback (most recent call last)" in log

    record = RunRecord(candidate_generated=bool(code.strip()))
    record.candidate_started = "HARNESS=" in log or bool(exits) or traceback
    if exits:
        # The candidate may loop over several inputs; only the last exit survives.
        record.invocations.append(ToolInvocation(
            run_id="%s-recovered" % arm, tool=TOOL, tool_version="CUDA 11.2.2 (2021-02-14)",
            input_sha256="EVIDENCE_MISSING", exit_code=exits[-1], stdout=log))
        record.notes.append("逐次调用未记录：只保留最后一次退出码，输入哈希与 stderr 缺失")
    record.notes.append("input_created 无法确认：候选未打印中间文件")

    return {"arm": arm, "states": record.states(), "highest": record.highest(),
            "candidate_bytes": len(code), "observed_exits": exits,
            "tool_invocations_recorded": len(record.invocations),
            "evidence_status": "EVIDENCE_MISSING",
            "notes": record.notes}


def main() -> int:
    original = json.loads((OUT / "summary.json").read_text(encoding="utf-8"))
    payload = {
        "source": "data/driver/f10step1/summary.json（原始观测，未修改）",
        "reason": "summary 把 exit=1 记为 anomaly=true 与 OBSERVED_ANOMALY；"
                  "按 exec_evidence 的判据，只有信号或超时才算异常终止",
        "original_anomaly_flags": {a["arm"]: a.get("anomaly") for a in original["arms"]},
        "reinterpreted": [build("A"), build("B")],
        "kept_as_is": ["A/run.log", "B/run.log", "A/candidate.py", "B/candidate.py",
                       "summary.json"],
        "missing_evidence": {
            "per_invocation_records": True,
            "input_sha256": True,
            "stderr_of_tool": True,
            "note": "B 组候选内部可能循环多次调用 nvdisasm，仅保留最后一次退出码；"
                    "不得据此补造逐次数据",
        },
    }
    (OUT / "reclassification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    for item in payload["reinterpreted"]:
        print(item["arm"], item["highest"], item["states"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
