# -*- coding: utf-8 -*-
"""Collapse a four-arm run into the metrics the F6 plan asks for."""

import argparse
import json
from pathlib import Path
from typing import List


def summarise(label: str, base: Path) -> dict:
    rounds: List[dict] = []
    for round_dir in sorted(base.glob("round*")):
        verdict = round_dir / "verdict.json"
        if not verdict.is_file():
            continue
        data = json.loads(verdict.read_text(encoding="utf-8"))
        facts = data.get("facts", {})
        trace = data.get("external", {}).get("trace", [])
        escapes = [step for step in trace if step.get("op") == "escape"]
        triggered = [step for step in escapes if step.get("trigger_at_call")]
        rounds.append({
            "round": round_dir.name,
            "ran": data.get("ran"),
            "level": data.get("verification_level"),
            "oracle": bool(facts.get("oracle_confirmed")),
            "issues": [f for f in ("escape_with_valid_objects", "valid_objects_built")
                       if facts.get(f)],
            "calls": data.get("external", {}).get("calls_made"),
            "escapes": len(escapes),
            "distinct_inputs": len({(s.get("args", {}).get("type"), s.get("args", {}).get("flags"),
                                     s.get("payload_sha256")) for s in escapes}),
            "first_trigger_call": min((s["trigger_at_call"] for s in triggered), default=None),
            "claim": data.get("claimed", {}).get("reached"),
            "claim_matches": data.get("self_report_matches_external"),
            "flaws": data.get("external", {}).get("flaws", []),
        })
    return {"label": label, "rounds": rounds}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", help="e.g. data/driver/mock_runs")
    parser.add_argument("--prefix", default="f6b-")
    args = parser.parse_args(argv)
    root = Path(args.root)
    out = []
    for arm_dir in sorted(root.glob(args.prefix + "*")):
        out.append(summarise(arm_dir.name.replace(args.prefix, ""), arm_dir))
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
