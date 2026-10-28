# -*- coding: utf-8 -*-
"""Look closer at one recorded finding, with tools the scored run does not have.

A fingerprint says "somewhere else"; it does not say what happened there. Valgrind
does: an invalid read at address zero inside strcmp is a missing null check, while
an invalid write into a heap block is a different claim entirely, and the two can
share the same exit code.

The analysis runs in a separate image on purpose. The scored run stays read-only,
offline and free of these tools, so a verdict can never depend on something only
the analyst has installed.

  python -m src.finding_analysis --dir data/findings/novel/<CVE>/<id> \
      --tool "cuobjdump --dump-elf {artifact}"
"""

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

ANALYSIS_IMAGE = "cpg/cuda112-py3:analysis"

_FRAME = re.compile(r"==\d+==\s+by 0x[0-9A-F]+: (\S+)")
_AT = re.compile(r"==\d+==\s+at 0x[0-9A-F]+: (\S+)")
_INVALID = re.compile(r"==\d+== (Invalid (?:read|write) of size \d+)")
_ADDRESS = re.compile(r"==\d+==\s+Address (0x[0-9a-fA-F]+) is (.+)")


def parse(output: str) -> Dict[str, object]:
    """The parts of a memcheck report worth keeping."""
    text = output or ""
    invalid = _INVALID.search(text)
    address = _ADDRESS.search(text)
    frames: List[str] = []
    for match in _AT.finditer(text):
        frames.append(match.group(1))
    for match in _FRAME.finditer(text):
        frames.append(match.group(1))

    verdict = "unknown"
    if invalid:
        kind = invalid.group(1)
        where = frames[0] if frames else ""
        # Anything in the zero page is a null dereference of some form; reading
        # a field at offset four of a null struct is the same bug as reading a
        # null string, and reporting them separately would split one root cause.
        if address and int(address.group(1), 16) < 0x1000:
            verdict = "null-dereference"
        elif "write" in kind:
            verdict = "invalid-write"
        elif where:
            verdict = "invalid-read"
    return {"invalid": invalid.group(1) if invalid else "",
            "address": address.group(1) if address else "",
            "address_note": address.group(2).strip() if address else "",
            "frames": frames[:6],
            "verdict": verdict}


def analyse(directory: Path, tool: str, image: str = ANALYSIS_IMAGE,
            timeout: int = 300) -> Dict[str, object]:
    """Run memcheck on the finding's artifact and record what it reported."""
    directory = Path(directory).resolve()
    meta_path = directory / "finding.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    artifact = meta.get("artifact", "")
    command = tool.replace("{artifact}", artifact)

    docker = ["docker", "run", "--rm", "--network", "none",
              "-v", "%s:/work:rw" % directory.as_posix(),
              image, "bash", "-c",
              "cd /work && valgrind --leak-check=no --error-exitcode=42 "
              "%s >/dev/null 2>/tmp/vg.txt; grep -c . /tmp/vg.txt >/dev/null; "
              "cat /tmp/vg.txt" % command]
    completed = subprocess.run(docker, capture_output=True, text=True,
                               timeout=timeout, encoding="utf-8", errors="replace")
    report = parse(completed.stdout or "")

    (directory / "analysis.txt").write_text(completed.stdout or "", encoding="utf-8")
    meta["valgrind"] = report
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2),
                         encoding="utf-8")
    return report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="analyse a recorded finding")
    parser.add_argument("--dir", required=True)
    parser.add_argument("--tool", required=True,
                        help='command with {artifact}, e.g. "cuobjdump --dump-elf {artifact}"')
    parser.add_argument("--image", default=ANALYSIS_IMAGE)
    args = parser.parse_args(argv)

    report = analyse(Path(args.dir), args.tool, args.image)
    print("verdict : %s" % report["verdict"])
    if report["invalid"]:
        print("invalid : %s at %s %s" % (report["invalid"], report["address"],
                                         report["address_note"]))
    for frame in report["frames"]:
        print("  frame : %s" % frame)
    print("written to %s" % (Path(args.dir) / "analysis.txt"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
