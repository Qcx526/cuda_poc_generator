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
# Older runs print "[CPG_RUN] file exit=N" without a tool. Requiring "::" meant those
# claims were never parsed, so a candidate could report a crash the harness never saw
# and nothing flagged it. The tool is optional now, and an absent tool matches any.
CLAIM_PATTERN = re.compile(r"^\[CPG_RUN\] (\S+?)(?:::([^\s]+))? exit=(-?\d+)", re.M)

SCRIPT = r"""
set -u
echo "VERSION|$(nvdisasm --version 2>&1 | head -1)"
US=$(printf '')
for f in /work/*.cubin /work/*.elf /work/*.bin /work/*.so; do
  [ -e "$f" ] || continue
  base=$(basename "$f")
  if command -v nvdisasm >/dev/null 2>&1; then
    out=$(nvdisasm "$f" 2>/tmp/e1); rc=$?
    printf 'REC%s%s%s%s%s%s%s%s%s%s%s
' "$US" nvdisasm "$US" "" "$US" "$base" "$US" "$rc" "$US" "$(printf %s "$out" | base64 -w0)" "$US$(base64 -w0 /tmp/e1)"
  fi
  if command -v cuobjdump >/dev/null 2>&1; then
    for m in "" "-elf" "-all" "-sass"; do
      out=$(cuobjdump $m "$f" 2>/tmp/e2); rc=$?
      printf 'REC%s%s%s%s%s%s%s%s%s%s%s%s%s
' "$US" cuobjdump "$US" "$m" "$US" "$base" "$US" "$rc" "$US" "$(printf %s "$out" | base64 -w0)" "$US" "$(base64 -w0 /tmp/e2)"
    done
  fi
done
"""


@dataclass
class TrustedRun:
    invocations: List[ToolInvocation] = field(default_factory=list)
    claims: List[dict] = field(default_factory=list)
    mismatches: List[dict] = field(default_factory=list)
    tool_versions: dict = field(default_factory=dict)
    tool_version: str = ""
    raw: str = ""
    format_ok: dict = field(default_factory=dict)


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect_artifacts(directory: Path, limit: int = 30) -> List[Path]:
    """At most ``limit`` artifacts, crafted/control first.

    A run directory can hold hundreds of sweep files; replaying every one across five
    argv forms exceeds any sane timeout and buries the interesting ones.
    """
    files = [p for p in directory.iterdir()
             if p.is_file() and p.suffix.lower() in ARTIFACT_SUFFIXES]
    priority = {"poc_": 0, "ctrl_": 1, "benign": 2}
    def rank(path: Path) -> tuple:
        for prefix, order in priority.items():
            if path.name.startswith(prefix):
                return (order, path.name)
        return (3, path.name)
    return sorted(files, key=rank)[:limit]


def parse_claims(candidate_stdout: str) -> List[dict]:
    return [{"file": m.group(1), "tool": m.group(2) or "", "exit": int(m.group(3))}
            for m in CLAIM_PATTERN.finditer(candidate_stdout)]


def run_trusted(directory: Path, image: str, timeout: int = 420) -> TrustedRun:
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
    # Format pre-check: a file that is not an ELF never reached the parser, so a tool
    # rejection on it says nothing about the tool. Recorded per artifact, not inferred.
    result.format_ok = {}
    for path in artifacts:
        head = path.read_bytes()[:4]
        result.format_ok[path.name] = head == b"ELF"
    for line in (proc.stdout or "").splitlines():
        if line.startswith("VERSION|"):
            # One version line for the toolchain, not per tool: the payload is the
            # whole "nvdisasm: ..." string and has no second separator.
            result.tool_versions["nvdisasm"] = line.split("|", 1)[1].strip()
            continue
        if not line.startswith("REC"):
            continue
        # Unit separator, not a pipe: base64 and tool paths may contain "|" and a
        # missing field used to shift every following column.
        parts = line.split("")
        if len(parts) < 7:
            continue
        _, tool, mode, name, code, out_b64, err_b64 = parts[:7]
        exit_code = int(code)
        label = "%s%s" % (tool, mode)
        result.invocations.append(ToolInvocation(
            run_id="%s:%s:%s" % (directory.name, label, name),
            tool=tool, tool_version=result.tool_versions.get(tool, "unknown"),
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
    crashed_observed = any(code is not None and (code < 0 or code >= 128)
                           for code in observed.values())
    for claim in run.claims:
        key = (claim["tool"], claim["file"])
        if claim["tool"]:
            if key in observed and observed[key] != claim["exit"]:
                run.mismatches.append({"tool": claim["tool"], "file": claim["file"],
                                       "claimed": claim["exit"], "observed": observed[key]})
            elif key not in observed:
                run.mismatches.append({"tool": claim["tool"], "file": claim["file"],
                                       "claimed": claim["exit"], "observed": None,
                                       "reason": "候选声称调用，但产物不存在或未被重放"})
            continue
        # No tool named: match by artifact only, and treat a claimed crash that never
        # reproduces on any tool as the mismatch it is.
        seen = {code for (tool, name), code in observed.items() if name == claim["file"]}
        if not seen:
            run.mismatches.append({"tool": "", "file": claim["file"],
                                   "claimed": claim["exit"], "observed": None,
                                   "reason": "候选声称调用，但该产物未被重放"})
        elif claim["exit"] < 0 or claim["exit"] >= 128:
            if not any(code is not None and (code < 0 or code >= 128) for code in seen):
                run.mismatches.append({"tool": "", "file": claim["file"],
                                       "claimed": claim["exit"],
                                       "observed": sorted(seen),
                                       "reason": "声称的崩溃在重放中不可复现"})
    return run.mismatches


def to_report(run: TrustedRun, directory: Path) -> dict:
    return {
        "directory": str(directory),
        "tool_versions": run.tool_versions,
        "invocations": [vars(item) for item in run.invocations],
        "claims": run.claims,
        "mismatches": run.mismatches,
        "format_ok": run.format_ok,
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
