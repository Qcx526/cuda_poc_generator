# -*- coding: utf-8 -*-
"""Corrupt SINCOS operand tokens and watch for an access violation.

The advisory says the bug is reached by "modified and corrupted" shader bytecode,
not by an unusual-but-legal instruction. Legal operand spellings already compile
cleanly, so the input space that matters is the one where the token's fields
disagree with what validation would accept as a whole - the parser keeps the
value, the compiler dereferences it.

Exit codes are the whole signal: 0 means compiled, 1 means the runtime rejected
it, and 0xC0000005 means the read went out of bounds. There is no debugger in the
loop, so a run costs milliseconds instead of seconds.

  python -m tools.driver.sincos_token_fuzz --bytecode data/harness/s2.bin
  python -m tools.driver.sincos_token_fuzz --bytecode data/harness/s1.bin --positions 5 6
"""

import argparse
import collections
import itertools
import os
import struct
import subprocess
from pathlib import Path
from typing import Dict, List, Sequence

ACCESS_VIOLATION = 0xC0000005
CDB = r"D:/Windows Kits/10/Debuggers/x64/cdb.exe"


def load_words(path: Path) -> List[int]:
    data = Path(path).read_bytes()
    return list(struct.unpack("<%dI" % (len(data) // 4), data))


def write_words(path: Path, words: Sequence[int]) -> None:
    Path(path).write_bytes(struct.pack("<%dI" % len(words), *words))


def run(harness: Path, bytecode: Path, scratch: Path, words: Sequence[int],
        timeout: int = 20) -> int:
    write_words(scratch, words)
    try:
        completed = subprocess.run([str(harness), "bytecode", str(scratch)],
                                   capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return -1
    return completed.returncode


def fault_module(harness: Path, bytecode: Path, scratch: Path,
                 words: Sequence[int], cdb: str = CDB) -> str:
    """Which module actually faulted.

    An access violation on its own proves nothing: truncated bytecode makes
    d3d9's validator fault long before the driver sees the shader. Only a fault
    inside nvgpucomp64 is the bug being chased.
    """
    write_words(scratch, words)
    try:
        completed = subprocess.run(
            [cdb, "-c", "sxe av; g; kb; q", str(harness), "bytecode", str(scratch)],
            capture_output=True, text=True, timeout=180,
            encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return ""
    # The faulting frame is the first symbol line after the exception banner.
    # Searching the whole output for "nvgpucomp64" matches the loaded-module
    # list and reports the wrong culprit with complete confidence.
    seen_fault = False
    for line in (completed.stdout or "").splitlines():
        if "Access violation" in line:
            seen_fault = True
            continue
        if not seen_fault:
            continue
        stripped = line.strip()
        if "!" in stripped and not stripped.startswith("*"):
            module = stripped.split("!")[0].split()[-1]
            for token in stripped.split():
                if "!" in token and "+" in token:
                    return token.split("!")[0]
            return module
    return "none"


def sweep(bytecode: Path, harness: Path, positions: Sequence[int],
          indexes: Sequence[int], types: Sequence[int]) -> Dict[str, object]:
    words = load_words(bytecode)
    scratch = Path(bytecode).with_name("_token_sweep.bin")
    stats: collections.Counter = collections.Counter()
    hits: List[Dict[str, object]] = []

    for position in positions:
        if position >= len(words):
            continue
        original = words[position]
        for index, kind in itertools.product(indexes, types):
            token = (original & ~0x7FF) | (index & 0x7FF)
            if kind is not None:
                token = (token & ~0x70000000) | ((kind & 7) << 28)
            mutated = list(words)
            mutated[position] = token
            code = run(harness, bytecode, scratch, mutated)
            stats[code] += 1
            if code == ACCESS_VIOLATION:
                hits.append({"position": position, "index": index, "type": kind,
                             "token": "0x%08x" % token})
    return {"runs": sum(stats.values()),
            "by_code": {"0x%08x" % (code & 0xFFFFFFFF): count
                        for code, count in stats.items()},
            "violations": hits}


def main() -> int:
    parser = argparse.ArgumentParser(description="corrupt SINCOS tokens")
    parser.add_argument("--bytecode", default="data/harness/s2.bin")
    parser.add_argument("--harness", default="data/harness/shader_runner.exe")
    parser.add_argument("--positions", nargs="*", type=int, default=[21, 22, 23])
    parser.add_argument("--indexes", nargs="*", type=int,
                        default=[31, 32, 33, 63, 64, 127, 128, 255, 511, 2047])
    parser.add_argument("--types", nargs="*", type=int, default=[None])
    args = parser.parse_args()

    result = sweep(Path(args.bytecode), Path(os.path.abspath(args.harness)),
                   args.positions, args.indexes, args.types)
    print("runs: %d" % result["runs"])
    for code, count in sorted(result["by_code"].items()):
        print("  %s x%d" % (code, count))
    print("access violations: %d" % len(result["violations"]))
    for hit in result["violations"]:
        print("  position=%d index=%d type=%s token=%s"
              % (hit["position"], hit["index"], hit["type"], hit["token"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
