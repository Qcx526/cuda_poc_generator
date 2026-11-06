# -*- coding: utf-8 -*-
"""Grade a CUDA run in five separate steps instead of one boolean.

The F7 run exposed why this matters: the framework said SUPPORTED while the generated
harness said NOT_REPRODUCED, because the crash came from `cuobjdump` and the check
looked at `nvdisasm`. Both tools are named by the advisory, so neither statement was
wrong - the single word "SUPPORTED" was.
"""

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

TOOL_EXECUTED = "TOOL_EXECUTED"
CRASH_OBSERVED = "CRASH_OBSERVED"
DIFFERENTIAL_SUPPORTED = "DIFFERENTIAL_SUPPORTED"
CVE_MECHANISM_SUPPORTED = "CVE_MECHANISM_SUPPORTED"
CVE_ATTRIBUTED = "CVE_ATTRIBUTED"

LEVELS = (TOOL_EXECUTED, CRASH_OBSERVED, DIFFERENTIAL_SUPPORTED,
          CVE_MECHANISM_SUPPORTED, CVE_ATTRIBUTED)

CRASH_EXIT = 128          # 139 = SIGSEGV, 134 = SIGABRT


@dataclass
class RunFacts:
    samples: int = 0
    tool_executions: int = 0
    crashes: int = 0
    crashing_tools: List[str] = field(default_factory=list)
    benign_clean: bool = False
    control_clean: bool = False
    single_field_differential: bool = False
    toolkit_version: str = ""
    candidate_verdict: str = ""


def parse(observation: Path) -> RunFacts:
    text = Path(observation).read_text(encoding="utf-8", errors="replace")
    facts = RunFacts()
    facts.samples = len(re.findall(r"^\[CPG_LABEL\]", text, re.M))
    seen_tools = set()
    for match in re.finditer(r"^\[CPG_RUN\] (\S+?)::(\S+) exit=(-?\d+)", text, re.M):
        name, tool, code = match.group(1), match.group(2), int(match.group(3))
        facts.tool_executions += 1
        seen_tools.add(tool)
        if code >= CRASH_EXIT:
            facts.crashes += 1
            if tool not in facts.crashing_tools:
                facts.crashing_tools.append(tool)
    labels = dict(re.findall(r"^\[CPG_LABEL\] (\S+) (BENIGN|MALICIOUS|CONTROL)", text, re.M))
    benign = [n for n, role in labels.items() if role == "BENIGN"]
    control = [n for n, role in labels.items() if role == "CONTROL"]
    facts.benign_clean = _clean(text, benign)
    facts.control_clean = _clean(text, control)
    match = re.search(r"single_field_differential=(True|False)", text)
    facts.single_field_differential = bool(match and match.group(1) == "True")
    # Version identity from the container banner, not from the candidate's own claim.
    banner = re.search(r"^CUDA Version (\d+\.\d+\.\d+)", text, re.M)
    facts.toolkit_version = banner.group(1) if banner else ""
    verdict = re.search(r"^\[CUDA_VERDICT\] (\w+)", text, re.M)
    facts.candidate_verdict = verdict.group(1) if verdict else ""
    return facts


def _clean(text: str, names: List[str]) -> bool:
    for name in names:
        for match in re.finditer(r"^\[CPG_RUN\] %s::\S+ exit=(-?\d+)" % re.escape(name),
                                 text, re.M):
            if int(match.group(1)) >= CRASH_EXIT:
                return False
    return bool(names)


def grade(facts: RunFacts, advisory_tools: List[str]) -> Dict[str, object]:
    reached: List[str] = []
    if facts.tool_executions:
        reached.append(TOOL_EXECUTED)
    if facts.crashes:
        reached.append(CRASH_OBSERVED)
    if facts.crashes and facts.benign_clean and facts.control_clean:
        reached.append(DIFFERENTIAL_SUPPORTED)
    named_tool_crashed = any(tool in advisory_tools for tool in facts.crashing_tools)
    if DIFFERENTIAL_SUPPORTED in reached and named_tool_crashed and facts.single_field_differential:
        reached.append(CVE_MECHANISM_SUPPORTED)
    # Attribution is never granted by the tool: it needs an external source tying the
    # crash to the advisory. This function therefore always stops one level short.
    return {"levels": reached, "highest": reached[-1] if reached else "NONE",
            "facts": facts.__dict__,
            "notes": [] if CVE_ATTRIBUTED not in reached else ["不应自动归属"]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("observation")
    parser.add_argument("--tools", default="nvdisasm,cuobjdump")
    args = parser.parse_args(argv)
    facts = parse(Path(args.observation))
    result = grade(facts, [t.strip() for t in args.tools.split(",") if t.strip()])
    print(json.dumps(result, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


def enrich_report(report_path: Path, observation: Path, tools: List[str]) -> dict:
    """Attach the five-level result to an existing loop report.

    The old verdict is left exactly as written: it was produced by the grader that
    ran at the time, and rewriting history to look stricter is the opposite of an
    audit trail. The grading block is added beside it.
    """
    import json as _json

    report = _json.loads(Path(report_path).read_text(encoding="utf-8"))
    facts = parse(Path(observation))
    result = grade(facts, tools)
    report["grading"] = {"levels": result["levels"], "highest": result["highest"],
                         "facts": facts.__dict__,
                         "note": "old verdict preserved; grading is additive"}
    Path(report_path).write_text(_json.dumps(report, ensure_ascii=False, indent=1),
                                 encoding="utf-8")
    return result


def enrich_report(report_path: Path, observation: Path, tools: List[str]) -> dict:
    """Attach the five-level result to an existing loop report.

    The old verdict is left exactly as written: it was produced by the grader that
    ran at the time, and rewriting history to look stricter is the opposite of an
    audit trail. The grading block is added beside it.
    """
    import json as _json

    report = _json.loads(Path(report_path).read_text(encoding="utf-8"))
    facts = parse(Path(observation))
    result = grade(facts, tools)
    report["grading"] = {"levels": result["levels"], "highest": result["highest"],
                         "facts": facts.__dict__,
                         "note": "old verdict preserved; grading is additive"}
    Path(report_path).write_text(_json.dumps(report, ensure_ascii=False, indent=1),
                                 encoding="utf-8")
    return result
