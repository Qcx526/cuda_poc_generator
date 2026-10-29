# -*- coding: utf-8 -*-
"""Run a directory of artifacts in the container and write the observation log.

The same matrix the loop uses, without the model: every artifact is executed in
the frozen image, each run is recorded with its exit code and fault site, and the
result is the log a grader reads. This is what makes the demo checkable by
someone who does not have our API key.

  python -m src.run_artifacts --dir demo/CVE-2024-0076/artifacts \
      --image cpg/cuda112-py3:1.0 --invocation "nvdisasm {artifact}" \
      --invocation "cuobjdump --dump-elf {artifact}"
"""

import argparse
import subprocess
from pathlib import Path
from typing import List, Optional

from .grader_matrix import render_matrix_script

ROLES = (("benign", "BENIGN"), ("ctrl", "CONTROL"),
         ("poc", "MALICIOUS"), ("crafted", "MALICIOUS"))


def role_for(name: str) -> str:
    for prefix, role in ROLES:
        if name.startswith(prefix):
            return role
    return "UNKNOWN"


def run(directory: Path, image: str, invocations: List[List[str]],
        timeout: int = 600) -> str:
    directory = Path(directory).resolve()
    entries = [(path.name, role_for(path.name))
               for path in sorted(directory.glob("*.cubin"))]
    script = render_matrix_script(invocations, entries)
    (directory / "_matrix.sh").write_bytes(script.encode("utf-8"))
    shim = Path(__file__).resolve().parent.parent / "tools" / "driver" / "crashcap.c"
    if shim.is_file():
        (directory / "crashcap.c").write_bytes(shim.read_bytes())

    completed = subprocess.run(
        ["docker", "run", "--rm", "--network", "none",
         "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
         "--read-only", "--tmpfs", "/tmp:size=512m",
         "-v", "%s:/work:rw" % directory.as_posix(),
         image, "bash", "-c", "cd /work && sh ./_matrix.sh"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout)
    return completed.stdout or ""


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="run artifacts, write the log")
    parser.add_argument("--dir", required=True)
    parser.add_argument("--image", default="cpg/cuda112-py3:1.0")
    parser.add_argument("--invocation", action="append", default=[])
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    invocations = [item.split() for item in args.invocation] or \
                  [["nvdisasm", "{artifact}"]]
    text = run(Path(args.dir), args.image, invocations)
    target = Path(args.out) if args.out else Path(args.dir) / "observation.txt"
    target.write_text(text, encoding="utf-8")
    print(text, end="")
    print("written to %s" % target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
