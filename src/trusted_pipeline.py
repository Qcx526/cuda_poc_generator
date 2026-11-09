# -*- coding: utf-8 -*-
"""Run a FILE_INPUT candidate, then re-execute everything it produced.

Two layers, kept apart on purpose:

* the candidate runs in the hardened container and its stdout is kept as claims;
* the harness then re-runs each artifact with each tool and records what it saw.

A verdict is derived only from the harness layer. A candidate that prints a crash it
never caused produces claims with no observed counterpart, which the comparison marks
as a mismatch instead of a success.
"""

import json
import subprocess
from pathlib import Path
from typing import Optional

from .exec_evidence import RunRecord, ToolInvocation
from .trusted_exec import compare_with_claims, run_trusted, to_report

RUN_SCRIPT = "cd /work && python3 candidate.py; echo HARNESS_RC=$?"


def run_candidate(workdir: Path, image: str, timeout: int = 300) -> dict:
    command = ["docker", "run", "--rm", "--network", "none",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--read-only", "--tmpfs", "/tmp:size=512m",
               "--pids-limit", "256", "--memory", "2g", "--cpus", "1",
               "-v", "%s:/work:rw" % workdir.resolve().as_posix(),
               image, "bash", "-c", RUN_SCRIPT]
    proc = subprocess.run(command, capture_output=True, text=True, errors="replace",
                          timeout=timeout)
    return {"returncode": proc.returncode,
            "stdout": proc.stdout[-40000:], "stderr": proc.stderr[-8000:]}


def execute_with_evidence(workdir: Path, candidate: Path, image: str) -> dict:
    """Full loop: candidate run -> artifact replay -> claim reconciliation."""
    script = workdir / "candidate.py"
    script.write_bytes(candidate.read_bytes())

    run = run_candidate(workdir, image)
    (workdir / "candidate_stdout.txt").write_text(run["stdout"], encoding="utf-8")

    trusted = run_trusted(workdir, image)
    compare_with_claims(trusted, run["stdout"])
    report = to_report(trusted, workdir)
    report["candidate_returncode"] = run["returncode"]
    (workdir / "evidence.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")

    record = RunRecord(candidate_generated=script.stat().st_size > 0,
                       candidate_started=run["returncode"] is not None,
                       inputs_created=[i.run_id.rsplit(":", 1)[-1]
                                       for i in trusted.invocations])
    record.invocations = trusted.invocations
    report["states"] = record.states()
    report["highest"] = record.highest()
    report["verdict_source"] = "harness_replay"
    (workdir / "evidence.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    return report


def summarize(report: dict) -> str:
    crashes = [i for i in report["invocations"] if i["exit_code"] is not None
               and (i["exit_code"] < 0 or i["exit_code"] >= 128)]
    return ("states=%s crash_invocations=%d mismatches=%d"
            % (report["highest"], len(crashes), len(report["mismatches"])))


def _main(argv: Optional[list] = None) -> int:
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2:
        print("usage: python -m src.trusted_pipeline <workdir> <candidate.py> [image]")
        return 2
    workdir = Path(args[0])
    candidate = Path(args[1])
    image = args[2] if len(args) > 2 else "cpg/cuda112-py3:1.0"
    workdir.mkdir(parents=True, exist_ok=True)
    report = execute_with_evidence(workdir, candidate, image)
    print(summarize(report))
    for item in report["invocations"][:8]:
        print("  %-9s %-30s exit=%s" % (item["tool"], item["run_id"].rsplit(":", 1)[-1],
                                        item["exit_code"]))
    for item in report["mismatches"][:4]:
        print("  MISMATCH", item)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
