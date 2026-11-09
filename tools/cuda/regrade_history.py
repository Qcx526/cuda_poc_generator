# -*- coding: utf-8 -*-
"""Re-grade archived runs with the advisory's own tool, not with whatever crashed.

CVE-2024-53877 is an nvdisasm advisory; a cuobjdump crash is a different tool and does
not support it. The old verdicts stay untouched - this adds a grading block beside
them, so the audit trail shows both what was believed and what the evidence supports.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.cve_grading import grade, parse   # noqa: E402

TOOL_MARKERS = ("nvdisasm", "cuobjdump", "nvlink", "ptxas", "nvprune", "cublas",
                "cufft", "cudnn", "nvidia-smi", "ncu", "nsight")


def advisory_tools(cve: str) -> list:
    spec = ROOT / "specs" / cve / "spec.json"
    if not spec.is_file():
        return []
    data = json.loads(spec.read_text(encoding="utf-8"))
    # 归属以 component 字段为准：advisory 影响的是哪个工具，就只能用哪个工具判。
    component = str(data.get("component", "")).lower()
    for tool in TOOL_MARKERS:
        if tool in component:
            return [tool]
    text = " ".join(str(v) for v in data.values()).lower()
    return [tool for tool in TOOL_MARKERS if tool in text]


def main() -> int:
    roots = [ROOT / "data" / "loop" / name for name in ("f10s2b", "f12b", "f12c")]
    rows = []
    for root in roots:
        if not root.is_dir():
            continue
        for case_dir in sorted(root.glob("CVE-*")):
            if not case_dir.is_dir():
                continue
            cve = case_dir.name
            tools = advisory_tools(cve)
            observations = sorted(case_dir.glob("iteration_*_observation.txt"))
            if not observations:
                continue
            # 用最后一轮观测做分级：迭代的成果体现在最后。
            facts = parse(observations[-1])
            result = grade(facts, tools)
            row = {"batch": root.name, "cve": cve, "advisory_tools": tools,
                   "iteration": observations[-1].name,
                   "levels": result["levels"], "highest": result["highest"],
                   "crashes": facts.crashes,
                   "crashing_tools": facts.crashing_tools,
                   "benign_clean": facts.benign_clean,
                   "control_clean": facts.control_clean,
                   "single_field": facts.single_field_differential,
                   "old_verdict": facts.candidate_verdict}
            rows.append(row)
            print("%-16s tools=%-22s highest=%-24s crash=%d by=%s"
                  % (cve, ",".join(tools) or "-", row["highest"], row["crashes"],
                     ",".join(row["crashing_tools"]) or "-"))
            for observation in observations:
                target = observation.parent / (observation.stem + "_grading.json")
                facts_i = parse(observation)
                target.write_text(json.dumps(
                    {"levels": grade(facts_i, tools)["levels"],
                     "highest": grade(facts_i, tools)["highest"],
                     "advisory_tools": tools,
                     "note": "附加分级；原报告未修改"}, ensure_ascii=False, indent=1),
                    encoding="utf-8")

    out = ROOT / "data" / "driver" / "f12-regrade.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    print("saved:", out, "| cases:", len(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
