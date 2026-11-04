# -*- coding: utf-8 -*-
"""Summarise an experiment directory into comparable metrics.

One experiment = one multi-round generation process. Its rounds are not
independent samples, so the numbers here describe a process, not a population;
any claim about group differences needs several experiment directories.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Dict, List, Optional


def _load_log(path: Path) -> Dict[str, object]:
    if not path.is_file():
        return {}
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    driver = next((l for l in lines if l.startswith("CPG_DRIVER ")), "")
    claims = next((l for l in lines if l.startswith("CPG_CLAIMS ")), "")
    out: Dict[str, object] = {}
    if driver:
        out["state"] = json.loads(driver[len("CPG_DRIVER "):]).get("state", "?")
    if claims:
        payload = json.loads(claims[len("CPG_CLAIMS "):])
        out["calls"] = len(payload.get("calls") or [])
        statuses = [c.get("status") for c in (payload.get("calls") or [])]
        out["statuses"] = sorted({str(s) for s in statuses})
        out["notes"] = str(payload.get("notes") or "")[:120]
    return out


def summarise(workdir: Path, cve: str) -> Dict[str, object]:
    root = Path(workdir) / cve
    rounds: List[Dict[str, object]] = []
    hashes: List[str] = []
    for index in sorted(root.glob("round*"), key=lambda p: p.name):
        round_dir = index if index.is_dir() else root / index.name
        record: Dict[str, object] = {"round": round_dir.name}
        poc = round_dir / "poc.py"
        if poc.is_file():
            source = poc.read_text(encoding="utf-8", errors="replace")
            digest = hashlib.sha1(source.encode("utf-8")).hexdigest()[:8]
            record.update({"sha": digest, "lines": source.count("\n"),
                           "uses_abi": "driver_abi" in source,
                           "redefines_abi": bool(re.search(r"class D3DKMT_\w+\(", source)),
                           "code_changed": digest not in hashes})
            hashes.append(digest)
        record.update(_load_log(round_dir / "run.log"))
        rounds.append(record)
    executed = [r for r in rounds if r.get("calls")]
    return {
        "workdir": str(workdir),
        "rounds": len(rounds),
        "rounds_with_calls": len(executed),
        "states": [r.get("state") for r in rounds],
        "calls": [r.get("calls", 0) for r in rounds],
        "distinct_statuses": sorted({s for r in rounds for s in r.get("statuses", [])}),
        "code_hashes": hashes,
        "code_changed_between_rounds": sum(1 for r in rounds if r.get("code_changed")),
        "abi_reuse": all(r.get("uses_abi") for r in rounds) if rounds else None,
        "abi_redefined": any(r.get("redefines_abi") for r in rounds),
        "kernel_coverage": "UNAVAILABLE",
        "detail": rounds,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="experiment metrics")
    parser.add_argument("workdir")
    parser.add_argument("--cve", default="CVE-2026-47571")
    args = parser.parse_args(argv)
    print(json.dumps(summarise(Path(args.workdir), args.cve), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
