# -*- coding: utf-8 -*-
"""Final verdicts for F13, computed from trusted records only.

For each case: the advisory's tool, the experiment toolkit version, how many
candidates and inputs there really were, how many tool invocations the harness made,
which of those crashed, and whether the benign and control samples stayed clean.

A crash by cuobjdump never counts for an nvdisasm advisory. A missing trusted record
is EVIDENCE_MISSING, not a pass.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.trusted_grading import LABEL_LINE, trust_status   # noqa: E402

BATCHES = ("f14b", "f13", "f13smoke", "f12c", "f12b", "f10s2b")
CRASH = 128


def identity(cve: str) -> dict:
    spec = ROOT / "specs" / cve / "spec.json"
    if not spec.is_file():
        return {"tool": None, "toolkit": None, "type": None}
    data = json.loads(spec.read_text(encoding="utf-8"))
    return {"tool": data.get("tool"), "toolkit": data.get("experiment_toolkit"),
            "type": data.get("vulnerability_type")}


MECHANISM_DIR = ROOT / "data" / "driver" / "f13-mechanism"


def mechanism_note(cve: str):
    """Root-cause evidence for a specific CVE, if someone actually produced it.

    Files land here only when a run shows the stated mechanism (a UAF detected by a
    sanitizer or by reuse-after-free observation, an OOB write with the exact field,
    and so on). Absence means UNKNOWN, never "probably fine".
    """
    path = MECHANISM_DIR / ("%s.json" % cve)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    return data if data.get("mechanism_evidence") else None


REPLAY_DIR = ROOT / "data" / "driver" / "f14-replay"
# 137 is SIGKILL: the container or the kernel killed it, which says nothing about the
# parser. Only these are parser-level terminations.
PARSER_SIGNALS = {-11, -6, 11, 134, 139}


def is_parser_crash(code) -> bool:
    return code is not None and code in PARSER_SIGNALS


def evaluate(cve_dir: Path, tool: str, use_replay: bool = False) -> dict:
    cve = cve_dir.name
    replay = REPLAY_DIR / ("%s.json" % cve)
    if use_replay and replay.is_file():
        return evaluate_replay(cve, tool, replay)
    case_dir = cve_dir
    trusted_files = sorted(case_dir.glob("iteration_*_trusted.json"))
    scripts = sorted(case_dir.glob("iteration_*_script.py"))
    if not trusted_files:
        return {"status": "EVIDENCE_MISSING",
                "reason": "无 trusted 记录；候选自述不足以判定",
                "candidates": len(scripts), "inputs": 0, "invocations": 0,
                "crashes": 0, "crashing_tools": [], "benign_clean": None,
                "control_clean": None, "differential": False, "mechanism": False}

    inputs, invocations, crashes, crashing_tools = set(), 0, 0, set()
    labels = {}
    versions = {}
    for path in trusted_files:
        data = json.loads(path.read_text(encoding="utf-8"))
        versions.update(data.get("tool_versions") or {})
        observation = path.with_name(path.name.replace("_trusted.json", "_observation.txt"))
        text = observation.read_text(encoding="utf-8", errors="replace") \
            if observation.is_file() else ""
        labels.update({n: r.upper() for n, r in LABEL_LINE.findall(text)})
        for item in data.get("invocations", []):
            invocations += 1
            name = item["run_id"].rsplit(":", 1)[-1]
            if item.get("input_sha256"):
                inputs.add(item["input_sha256"])
            if is_parser_crash(item.get("exit_code")):
                crashes += 1
                crashing_tools.add(item["tool"])

    # cleanliness is judged per label over every invocation touching that artifact
    def clean(role: str) -> bool:
        names = {n for n, r in labels.items() if r == role}
        if not names:
            return False
        for path in trusted_files:
            data = json.loads(path.read_text(encoding="utf-8"))
            for item in data.get("invocations", []):
                name = item["run_id"].rsplit(":", 1)[-1]
                if name in names:
                    if is_parser_crash(item.get("exit_code")):
                        return False
        return True

    # A crash only counts when it can be paired: the crashing artifact must be the
    # one the run declared as the crafted input, and a control of that same artifact
    # must stay clean. An unlabelled probe crashing next to unrelated clean samples is
    # a finding candidate, not a differential.
    def base_of(name: str) -> str:
        """Which field family an artifact belongs to.

        Run names look like "poc_e_shstrndx.cubin" and
        "ctrl_e_shstrndx_restored_0x1.cubin"; the suffix differs, the family does not.
        Two leading tokens are enough to tie a control to the input it restores.
        """
        stem = name
        for prefix in ("poc_", "ctrl_", "sweep_"):
            if stem.startswith(prefix):
                stem = stem[len(prefix):]
                break
        stem = stem.rsplit(".", 1)[0]
        return "_".join(stem.split("_")[:2])

    by_name = {}
    for path in trusted_files:
        for item in json.loads(path.read_text(encoding="utf-8")).get("invocations", []):
            by_name.setdefault(item["run_id"].rsplit(":", 1)[-1], []).append(item)

    labelled_crash, unlabelled_crash = [], []
    for name, items in by_name.items():
        role = labels.get(name)
        crashed = any((i.get("exit_code") or 0) < 0 or (i.get("exit_code") or 0) >= CRASH
                      for i in items)
        if not crashed:
            continue
        (labelled_crash if role == "MALICIOUS" else unlabelled_crash).append(name)

    paired = []
    for name in labelled_crash:
        stem = base_of(name)
        partners = [n for n in by_name
                    if n != name and labels.get(n) == "CONTROL" and base_of(n) == stem]
        partners_clean = [n for n in partners
                          if all(((i.get("exit_code") or 0) < 0 or
                                  (i.get("exit_code") or 0) >= CRASH) is False
                                 for i in by_name[n])]
        if partners_clean:
            paired.append({"crashed": name, "controls": partners_clean})

    benign, control = clean("BENIGN"), clean("CONTROL")
    differential = bool(paired) and benign and control
    # The advisory's own tool crashing on a differential input is the strongest thing
    # a black-box run can show, and it is still not a mechanism: a segfault in
    # nvdisasm says nothing about whether the bug is a UAF, an OOB write or a NULL
    # dereference. Mechanism needs its own evidence, supplied per case.
    target_tool_differential = bool(differential) and tool is not None         and tool in crashing_tools
    mechanism_evidence = mechanism_note(cve) if target_tool_differential else None
    mechanism = bool(mechanism_evidence)
    attributed = bool(mechanism_evidence and mechanism_evidence.get("attribution"))

    levels = []
    if invocations:
        levels.append("TOOL_EXECUTED")
    if crashes:
        levels.append("CRASH_OBSERVED")
    if differential:
        levels.append("DIFFERENTIAL_SUPPORTED")
    if target_tool_differential:
        levels.append("TARGET_TOOL_DIFFERENTIAL_SUPPORTED")
    if mechanism:
        levels.append("CVE_MECHANISM_SUPPORTED")
    if attributed:
        levels.append("CVE_ATTRIBUTED")

    status = levels[-1] if levels else "TOOL_EXECUTED"
    return {"status": status, "levels": levels,
            "candidates": len(scripts), "inputs": len(inputs),
            "invocations": invocations, "crashes": crashes,
            "crashing_tools": sorted(crashing_tools),
            "benign_clean": benign, "control_clean": control,
            "differential": differential,
            "paired_differential": paired,
            "unclassified_findings": sorted(unlabelled_crash),
            "target_tool_differential": target_tool_differential,
            "mechanism": mechanism,
            "mechanism_status": "SUPPORTED" if mechanism else "UNKNOWN",
            "attribution": "ATTRIBUTED" if attributed else "UNATTRIBUTED",
            "tool_versions": versions,
            "note": ("目标工具差分成立；机制需根因级证据，缺失则保持 UNKNOWN"
                     if target_tool_differential and not mechanism
                     else "崩溃工具与 advisory 工具不同则不给目标工具差分")}


def evaluate_replay(cve: str, tool: str, replay: Path) -> dict:
    """Verdict from a mode-aware replay: labels come from filenames, exits from the run."""
    data = json.loads(replay.read_text(encoding="utf-8"))
    items = data.get("invocations", [])
    by_name = {}
    for item in items:
        name = item["run_id"].rsplit(":", 1)[-1]
        by_name.setdefault(name, []).append(item)

    def role(name: str) -> str:
        if name.startswith("poc_"):
            return "MALICIOUS"
        if name.startswith(("ctrl_", "control_")):
            return "CONTROL"
        if name.startswith("benign"):
            return "BENIGN"
        return "UNLABELED"

    def base(name: str) -> str:
        stem = name
        for prefix in ("poc_", "ctrl_", "control_", "sweep_"):
            if stem.startswith(prefix):
                stem = stem[len(prefix):]
                break
        return "_".join(stem.rsplit(".", 1)[0].split("_")[:2])

    crashes = [i for i in items if is_parser_crash(i.get("exit_code"))]
    killed = [i for i in items if i.get("exit_code") == 137]
    crashing_tools = sorted({i["tool"] for i in crashes})

    def clean_for(family: str, exclude: str) -> bool:
        names = [n for n in by_name if n != exclude and role(n) in ("CONTROL", "BENIGN")
                 and (role(n) == "BENIGN" or base(n) == family)]
        if not names:
            return False
        return not any(is_parser_crash(i.get("exit_code"))
                       for n in names for i in by_name[n])

    paired = []
    for name in {i["run_id"].rsplit(":", 1)[-1] for i in crashes}:
        if role(name) != "MALICIOUS":
            continue
        if clean_for(base(name), name):
            paired.append({"crashed": name, "controls": sorted(
                n for n in by_name if base(n) == base(name) and role(n) != "MALICIOUS")})

    target_tool_differential = bool(paired) and tool is not None and tool in crashing_tools
    mechanism = bool(mechanism_note(cve)) and target_tool_differential
    levels = []
    if items:
        levels.append("TOOL_EXECUTED")
    if crashes:
        levels.append("CRASH_OBSERVED")
    if paired:
        levels.append("DIFFERENTIAL_SUPPORTED")
    if target_tool_differential:
        levels.append("TARGET_TOOL_DIFFERENTIAL_SUPPORTED")
    if mechanism:
        levels.append("CVE_MECHANISM_SUPPORTED")
    return {"status": levels[-1] if levels else "TOOL_EXECUTED", "levels": levels,
            "candidates": 1, "inputs": len(by_name), "invocations": len(items),
            "crashes": len(crashes), "killed_137": len(killed),
            "crashing_tools": crashing_tools,
            "benign_clean": clean_for("", ""), "control_clean": bool(paired),
            "differential": bool(paired),
            "paired_differential": paired,
            "unclassified_findings": [],
            "target_tool_differential": target_tool_differential,
            "mechanism": mechanism,
            "mechanism_status": "SUPPORTED" if mechanism else "UNKNOWN",
            "attribution": "UNATTRIBUTED",
            "tool_versions": data.get("tool_versions", {}),
            "source": "f14_replay_modes",
            "note": "按候选 argv 重放；137 记为资源/外部终止，不计解析器崩溃"}


def main() -> int:
    rows = []
    for batch in BATCHES:
        root = ROOT / "data" / "loop" / batch
        if not root.is_dir():
            continue
        for case_dir in sorted(root.glob("CVE-*")):
            if not case_dir.is_dir():
                continue
            cve = case_dir.name
            meta = identity(cve)
            # The mode-aware replay belongs to this round's cases; applying it to
            # older batches would silently restate their numbers.
            result = evaluate(case_dir, meta["tool"], use_replay=(batch == "f13"))
            row = {"batch": batch, "cve": cve, "advisory_tool": meta["tool"],
                   "vulnerability_type": meta["type"],
                   "toolkit": meta["toolkit"], **result}
            rows.append(row)
            print("%-9s %-16s tool=%-10s %-24s inv=%3d crash=%2d by=%s"
                  % (batch, cve, meta["tool"] or "-", result["status"],
                     result["invocations"], result["crashes"],
                     ",".join(result["crashing_tools"]) or "-"))
    out = ROOT / "data" / "driver" / "f13-verdicts.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    print("saved:", out, "| rows:", len(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
