# -*- coding: utf-8 -*-
"""cdb-backed tracing: ask the target what it did with an input.

A probe is a stop address plus a small script. The parsed result is deliberately
plain - hit or miss, registers, stack frames - so the same trace can feed a
specification claim, a report, or an LLM prompt without a second parser.
"""

import re
import subprocess
from pathlib import Path
from typing import List, Optional

from src.trace_core import Probe, TraceProvider, TraceResult, register

REGISTER = re.compile(r"\b(rax|rbx|rcx|rdx|rsi|rdi|r8|r9|r10|r11|rip|rsp|rbp)=([0-9a-f`]+)")


class CdbTrace( TraceProvider):
    name = "cdb"

    def __init__(self, cdb: Path, harness: Path, timeout: int = 120) -> None:
        self.cdb = Path(cdb)
        self.harness = Path(harness)
        self.timeout = timeout

    def _script(self, probe: Probe) -> str:
        """Wait for the module, then set the probe.

        A breakpoint set before the module loads resolves against address zero
        and silently fails ("Win32 error 0n299"), which reads as "not reached"
        and would fake a negative result. Waiting for the load event is what
        makes a miss mean a miss.
        """
        return "\n".join(["sxe ld:%s" % probe.module,
                           "g",
                           "bp %s" % probe.expression,
                           "g", "r", "kb 8", "q"]) + "\n"

    def trace(self, program: Path, probe: Probe, timeout: Optional[int] = None) -> TraceResult:
        script = Path(self.harness).parent / ".trace.cdb"
        script.write_text(self._script(probe), encoding="utf-8")
        command = [str(self.cdb), "-cf", str(script),
                   str(self.harness), "bytecode", str(program)]
        try:
            done = subprocess.run(command, capture_output=True, text=True,
                                  errors="replace", timeout=timeout or self.timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            return TraceResult(provider=self.name, hit=False, probe=probe,
                               note="tracer failed: %s" % exc)
        text = (done.stdout or "") + (done.stderr or "")
        return parse(text, probe, self.name)


def parse(text: str, probe: Probe, provider: str = "cdb") -> TraceResult:
    """Extract hit, registers and frames from a cdb transcript."""
    hit = re.search(r"breakpoint\s+\d+\s+hit", text, re.IGNORECASE) is not None
    registers = {m.group(1): m.group(2) for m in REGISTER.finditer(text)}
    frames: List[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if "!" in stripped and re.match(r"^[0-9a-f`]{8,}", stripped):
            token = stripped.split()[-1]
            if "!" in token:
                frames.append(token.rstrip(":"))
    if not hit and "Access violation" in text:
        hit = True  # the probe site faulted, which is also a stop
    note = "hit" if hit else "not hit"
    return TraceResult(provider=provider, hit=hit, probe=probe,
                       registers=registers, frames=frames[:8], note=note)


register(CdbTrace(Path(r"D:/Windows Kits/10/Debuggers/x64/cdb.exe"),
                  Path("data/harness/shader_runner.exe")))
