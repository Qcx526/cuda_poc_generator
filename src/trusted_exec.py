# -*- coding: utf-8 -*-
"""Trusted tool execution for FILE_INPUT candidates.

Until now the only record of what nvdisasm or cuobjdump did came from lines the
candidate printed itself. A candidate can print "[CPG_RUN] poc.cubin::nvdisasm exit=139"
without ever calling the tool, and the grader would believe it.

This module re-runs every artifact the candidate produced, inside the same hardened
container, and records what the harness itself observed. Candidate claims are kept
separately and compared, never merged.
"""

import base64
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .exec_evidence import ToolInvocation

ARTIFACT_SUFFIXES = (".cubin", ".elf", ".bin", ".so")
TOOLS = ("nvdisasm", "cuobjdump")
CLAIM_PATTERN = re.compile(r"^\[CPG_RUN\] (\S+?)::(\S+) exit=(-?\d+)", re.M)

SCRIPT = r"""
set -u
echo "VERSION|$(nvdisasm --version 2>&1 | head -1)"
for f in /work/*.cubin /work/*.elf /work/*.bin /work/*.so; do
  [ -e "$f" ] || continue
  for t in nvdisasm cuobjdump; do
    command -v "$t" >/dev/null 2>&1 || continue
    out=$("$t" "$f" 2>/tmp/err.bin); rc=$?
    echo "REC|$t|$(basename "$f")|$rc|$(printf %s "$out" | base64 -w0)|$(base64 -w0 /tmp/err.bin)"
  done
done
"""


@dataclass
class TrustedRun:
    invocations: List[ToolInvocation] = field(default_factory=list)
    claims: List[dict] = field(default_factory=list)
    mismatches: List[dict] = field(default_factory=list)
    tool_version: str = ""
    raw: str = ""


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect_artifacts(directory: Path) -> List[Path]:
    return sorted(p for p in directory.iterdir()
                  if p.is_file() and p.suffix.lower() in ARTIFACT_SUFFIXES)


def parse_claims(candidate_stdout: str) -> List[dict]:
    return [{"file": m.group(1), "tool": m.group(2), "exit": int(m.group(3))}
            for m in CLAIM_PATTERN.finditer(candidate_stdout)]


def run_trusted(directory: Path, image: str, timeout: int = 180) -> TrustedRun:
    """Re-execute every artifact with each tool, inside the hardened container."""
    artifacts = collect_artifacts(directory)
    if not artifacts:
        return TrustedRun()

    command = ["docker", "run", "--rm", "--network", "none",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--read-only", "--tmpfs", "/tmp:size=512m",
               "--pids-limit", "256", "--memory", "2g", "--cpus", "1",
               "-v", "%s:/work:ro" % directory.resolve().as_posix(),
               image, "bash", "-c", SCRIPT]
    proc = subprocess.run(command, capture_output=True, text=True, errors="replace",
                          timeout=timeout)
    result = TrustedRun(raw=(proc.stdout or "")[-20000:])

    digests = {p.name: sha256_of(p) for p in artifacts}
    for line in (proc.stdout or "").splitlines():
        if line.startswith("VERSION|"):
            result.tool_version = line.split("|", 1)[1].strip()
            continue
        if not line.startswith("REC|"):
            continue
        _, tool, name, code, out_b64, err_b64 = line.split("|", 5)
        exit_code = int(code)
        result.invocations.append(ToolInvocation(
            run_id="%s:%s:%s" % (directory.name, tool, name),
            tool=tool, tool_version=result.tool_version or "unknown",
            input_sha256=digests.get(name, "UNKNOWN"),
            exit_code=exit_code,
            stdout=base64.b64decode(out_b64).decode("utf-8", "replace")[-4000:],
            stderr=base64.b64decode(err_b64).decode("utf-8", "replace")[-2000:],
            signal=exit_code - 128 if exit_code >= 128 else None))
    return result


def compare_with_claims(run: TrustedRun, candidate_stdout: str) -> List[dict]:
    """Any difference between what the candidate said and what we saw is a finding."""
    run.claims = parse_claims(candidate_stdout)
    observed = {}
    for item in run.invocations:
        name = item.run_id.rsplit(":", 1)[-1]
        observed[(item.tool, name)] = item.exit_code
    for claim in run.claims:
        key = (claim["tool"], claim["file"])
        if key in observed and observed[key] != claim["exit"]:
            run.mismatches.append({"tool": claim["tool"], "file": claim["file"],
                                   "claimed": claim["exit"], "observed": observed[key]})
        elif key not in observed:
            run.mismatches.append({"tool": claim["tool"], "file": claim["file"],
                                   "claimed": claim["exit"], "observed": None,
                                   "reason": "候选声称调用，但产物不存在或未被重放"})
    return run.mismatches


def to_report(run: TrustedRun, directory: Path) -> dict:
    return {
        "directory": str(directory),
        "tool_version": run.tool_version,
        "invocations": [vars(item) for item in run.invocations],
        "claims": run.claims,
        "mismatches": run.mismatches,
        "note": "invocations 来自 harness 重放；claims 来自候选自述，两者不合并",
    }


def main(argv: Optional[List[str]] = None) -> int:
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: python -m src.trusted_exec <dir> [image] [candidate_stdout_file]")
        return 2
    directory = Path(args[0])
    image = args[1] if len(args) > 1 else "cpg/cuda112-py3:1.0"
    stdout_file = Path(args[2]) if len(args) > 2 else None
    run = run_trusted(directory, image)
    if stdout_file and stdout_file.is_file():
        compare_with_claims(run, stdout_file.read_text(encoding="utf-8", errors="replace"))
    report = to_report(run, directory)
    target = directory / "trusted_invocations.json"
    target.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print("invocations:", len(run.invocations), "| mismatches:", len(run.mismatches))
    for item in run.invocations[:6]:
        print("  %-9s %-34s exit=%s" % (item.tool, item.run_id.rsplit(":", 1)[-1],
                                        item.exit_code))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
