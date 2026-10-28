# -*- coding: utf-8 -*-
"""Does the fault still happen on a different toolkit version?

A crash on the version we happen to have proves the input is bad for that build.
It says nothing about whether the vendor still ships the defect, and that is the
difference between a finding worth reporting and one worth filing.

This runs the same artifact under another image and records the answer next to the
original observation. Each version is a separate entry; nothing is overwritten, so
the finding accumulates a history rather than a verdict.

  python -m src.version_check --dir data/findings/novel/<CVE>/<id> \
      --tool "cuobjdump --dump-elf {artifact}" --image nvidia/cuda:12.4.1-devel-ubuntu22.04
"""

import argparse
import json
import subprocess
from pathlib import Path
from typing import Dict, Optional

CRASHCAP = Path(__file__).resolve().parent.parent / "tools" / "driver" / "crashcap.c"


def check(directory: Path, tool: str, image: str,
          timeout: int = 600) -> Dict[str, object]:
    """Run the artifact under another image and describe what happened."""
    directory = Path(directory).resolve()
    meta = json.loads((directory / "finding.json").read_text(encoding="utf-8"))
    artifact = meta.get("artifact", "")
    # The shim has to travel with the artifact: without it the run reports an
    # exit code and nothing about where it died, which is the only thing that
    # makes two versions comparable.
    if CRASHCAP.is_file():
        target = directory / "crashcap.c"
        if not target.is_file() or target.read_bytes() != CRASHCAP.read_bytes():
            target.write_bytes(CRASHCAP.read_bytes())
    command = tool.replace("{artifact}", artifact)

    script = (
        "cd /work && cap='' && "
        "if [ -f ./crashcap.c ] && command -v gcc >/dev/null 2>&1; then "
        "gcc -shared -fPIC -O1 -o /tmp/crashcap.so ./crashcap.c -ldl >/dev/null 2>&1 "
        "&& cap=/tmp/crashcap.so; fi; "
        "rm -f /tmp/cc; CRASHCAP_OUT=/tmp/cc LD_PRELOAD=\"$cap\" %s >/dev/null 2>&1; "
        "rc=$?; echo \"[RC] $rc\"; "
        "if [ -f /tmp/cc ]; then echo \"[SITE]\"; cat /tmp/cc; fi" % command)
    docker = subprocess.run(
        ["docker", "run", "--rm", "--network", "none",
         "-v", "%s:/work:rw" % directory.as_posix(),
         image, "bash", "-c", script],
        capture_output=True, text=True, timeout=timeout,
        encoding="utf-8", errors="replace")
    output = docker.stdout or ""

    code: Optional[int] = None
    site = ""
    for line in output.splitlines():
        if line.startswith("[RC] "):
            code = int(line.split()[1])
        elif "sig=" in line and "module=" in line:
            site = line.strip()

    from . import novel_findings
    crash = novel_findings.parse_crashes("[CPG_RUN] x::t exit=%d\n[CPG_CRASH] x %s\n"
                                         % (code or 0, site)) if site else []
    fingerprint = crash[0].fingerprint if crash else ""
    return {"image": image, "tool": command, "exit_code": code,
            "site": site, "fingerprint": fingerprint,
            "crashed": bool(site)}


def record(directory: Path, result: Dict[str, object]) -> None:
    """Append the version to the finding; keep every run, not just the last."""
    path = Path(directory) / "finding.json"
    meta = json.loads(path.read_text(encoding="utf-8"))
    history = meta.setdefault("versions", [])
    history = [row for row in history if row.get("image") != result["image"]]
    history.append(result)
    meta["versions"] = history
    path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="re-run a finding on another version")
    parser.add_argument("--dir", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args(argv)

    result = check(Path(args.dir), args.tool, args.image)
    record(Path(args.dir), result)
    print("image   : %s" % result["image"])
    print("exit    : %s" % result["exit_code"])
    print("site    : %s" % (result["site"] or "-"))
    print("verdict : %s" % ("still crashes" if result["crashed"] else "no crash"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
