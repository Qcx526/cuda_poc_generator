# -*- coding: utf-8 -*-
"""Watch what the driver does with a specific byte of the shader program.

The harness pauses before CreatePixelShader and prints where its buffer lives.
A debugger then attaches, sets a data breakpoint on one dword of that buffer,
and the process is released: every hit is a place where the driver read that
field. The stack frame at the hit names the decoder, which is the evidence this
whole line of work has been missing.

    python -m tools.driver.byte_trace --program data/harness/c.bin --offset 28
"""

import argparse
import re
import subprocess
import time
from pathlib import Path
from typing import List, Optional

BUFFER_LINE = re.compile(r"\[BUFFER\]\s+([0-9A-Fa-f]+)\s+size=(\d+)")


def watch(harness: Path, program: Path, offset: int, cdb: Path,
          length: int = 4, settle: float = 4.0, timeout: int = 120,
          second_stage: bool = False) -> List[str]:
    """Return the debugger transcript of every access to buffer+offset."""
    harness = Path(harness).resolve()
    proc = subprocess.Popen([str(harness), "trace", str(Path(program).resolve())],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    try:
        first = ""
        for _ in range(20):
            first = proc.stdout.readline()
            if "[BUFFER]" in first:
                break
        match = BUFFER_LINE.search(first)
        if not match:
            raise SystemExit("harness did not report a buffer address: %r" % first)
        base, size = int(match.group(1), 16), int(match.group(2))
        if offset >= size:
            raise SystemExit("offset %d is beyond the %d-byte program" % (offset, size))

        script = Path(harness).parent / ".byte_trace.cdb"
        stage2 = Path(harness).parent / ".byte_trace.log"
        if second_stage:
            # First watchpoint catches the runtime copying the program; the
            # copy's destination is then watched, because that is the buffer
            # the driver actually parses.
            lines = [
                'ba r%d 0x%x ".printf \\"COPY rcx=%%p rdx=%%p r8=%%p\\\\n\\", '
                '@rcx, @rdx, @r8; ba r%d @rcx \\"kb 6; gc\\"; gc"'
                % (length, base + offset, length),
                "g",
                "q",
            ]
        else:
            lines = ['ba r%d 0x%x "kb 4; r; g"' % (length, base + offset), "g", "q"]
        script.write_text("\n".join(lines) + "\n", encoding="utf-8")

        debugger = subprocess.Popen([str(cdb), "-p", str(proc.pid), "-cf", str(script)],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, errors="replace")
        # The debugger breaks the target on attach; give it time to arm the watch.
        time.sleep(settle)
        try:
            proc.stdin.write("\n")
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        out, _ = debugger.communicate(timeout=timeout)
        return (out or "").splitlines()
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        if proc.poll() is None:
            proc.kill()


def hits(lines: List[str]) -> List[str]:
    """Frames seen at watchpoint hits, deduplicated in order."""
    seen: List[str] = []
    for line in lines:
        if re.search(r"Breakpoint \d+ hit|ba r\d", line) and "!" in line:
            token = line.strip().split()[-1].rstrip(":")
            if "!" in token and token not in seen:
                seen.append(token)
    return seen


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="watch reads of one buffer dword")
    parser.add_argument("--program", required=True)
    parser.add_argument("--offset", type=int, default=28)
    parser.add_argument("--harness", default="data/harness/shader_runner.exe")
    parser.add_argument("--cdb", default=r"D:/Windows Kits/10/Debuggers/x64/cdb.exe")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--second-stage", action="store_true", default=False,
                        help="watch the runtime's copy of the program, not the caller buffer")
    args = parser.parse_args(argv)

    lines = watch(Path(args.harness), Path(args.program), args.offset, Path(args.cdb),
                  timeout=args.timeout, second_stage=args.second_stage)
    for line in lines:
        if "Breakpoint" in line or "!" in line or "Couldn't" in line:
            print(line[:160])
    print("\n=== distinct frames at hits ===")
    for frame in hits(lines) or ["none"]:
        print(frame)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
