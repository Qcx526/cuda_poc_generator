# -*- coding: utf-8 -*-
"""Accept-or-reject first, then ask the debugger whether the target block ran.

Running the debugger on every case is slow, so the cheap execution decides
first and the probe is only paid for cases that survive validation. A hit is a
much better signal than a crash: it says the input reached the code the
advisory describes, even when the fault itself is still out of reach.
"""

import re
import subprocess
from pathlib import Path
from typing import Optional

from src.fuzz_core import (ACCEPTED, FAULT, GRAMMAR_ERROR, REACHED, REJECTED,
                           TIMEOUT, Candidate, Outcome)


class ProbeRunner:
    def __init__(self, harness: Path, workdir: Path, cdb: Path, module: str,
                 rva: int, timeout: int = 30, probe_timeout: int = 90) -> None:
        self.harness = Path(harness)
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.cdb = Path(cdb)
        self.module = module
        self.rva = rva
        self.timeout = timeout
        self.probe_timeout = probe_timeout
        self.index = 0
        self.script = self.workdir / ".probe.cdb"
        self.script.write_text("\n".join([
            "sxe ld:%s" % module, "g",
            'bp %s+0x%x "gc"' % (module, rva),
            "g", "q"]) + "\n", encoding="utf-8")

    def __call__(self, candidate: Candidate) -> Outcome:
        self.index += 1
        binary = self.workdir / ("case_%05d.bin" % self.index)
        if candidate.meta.get("format") == "bytes":
            binary.write_bytes(bytes.fromhex(candidate.body))
        else:
            asm = self.workdir / ("case_%05d.asm" % self.index)
            asm.write_text(candidate.body, encoding="utf-8")
            built = subprocess.run([str(self.harness), "assemble", str(asm), str(binary)],
                                   capture_output=True, text=True, errors="replace",
                                   timeout=self.timeout)
            if built.returncode != 0:
                return Outcome(GRAMMAR_ERROR, built.returncode, 0.0, 0,
                               (built.stdout or "")[-120:])

        run = subprocess.run([str(self.harness), "bytecode", str(binary)],
                             capture_output=True, text=True, errors="replace",
                             timeout=self.timeout)
        if run.returncode == 1:
            return Outcome(REJECTED, 1, 0.0, binary.stat().st_size)
        if run.returncode != 0:
            return Outcome(FAULT, run.returncode, 0.0, binary.stat().st_size)

        probe = subprocess.run([str(self.cdb), "-cf", str(self.script),
                                str(self.harness), "bytecode", str(binary)],
                               capture_output=True, text=True, errors="replace",
                               timeout=self.probe_timeout)
        text = (probe.stdout or "") + (probe.stderr or "")
        if re.search(r"Breakpoint \d+ hit", text):
            return Outcome(REACHED, 0, 0.0, binary.stat().st_size,
                           "hit %s+0x%x" % (self.module, self.rva))
        return Outcome(ACCEPTED, 0, 0.0, binary.stat().st_size)


def make(harness: str, workdir: str, cdb: str, module: str, rva: int) -> ProbeRunner:
    return ProbeRunner(Path(harness), Path(workdir), Path(cdb), module, rva)
