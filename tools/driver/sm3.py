# -*- coding: utf-8 -*-
"""Shader-model-3 adapter: a grammar and a runner for :mod:`src.fuzz_core`.

Everything shader-specific lives here. The engine only sees "a program" and
"an outcome", so a second target (a different parser, a different tool) can be
fuzzed by writing one more adapter, not by touching the loop.

The axes are generic on purpose - operand index, declaration count, resource
slot, control flow - rather than "the SINCOS field of CVE-2024-0107". Which
axes and ranges to use comes from the specification's ``search`` block.
"""

import random
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

from src.fuzz_core import (ACCEPTED, FAULT, GRAMMAR_ERROR, REJECTED, TIMEOUT,
                           Candidate, Grammar, Outcome, register)

DEFAULT_PARAMS: Dict[str, object] = {
    "operand_index_max": 127,
    "dest_index_max": 31,
    "defs_choices": [0, 1, 2, 4, 8, 16, 32],
    "repeat_max": 8,
    "resource_slot_max": 15,
    # Loop bounds are where integer handling usually breaks, so the axis uses
    # values on both sides of the 8- and 16-bit edges.
    "loop_counts": [0, 1, 2, 16, 255, 256, 65535],
    "flow_kinds": ["if", "loop", "rep", "if_nested"],
    "axes": ["operand", "defs", "repeat", "resource", "flow"],
    "entry": "sincos",
}


class Sm3Grammar(Grammar):
    """Generates ps_3_0 programs from a few structural axes."""

    name = "sm3"

    def generate(self, rng: random.Random, params: Dict[str, object]) -> Candidate:
        p = dict(DEFAULT_PARAMS)
        p.update(params or {})
        axes: List[str] = list(p["axes"])  # type: ignore[arg-type]
        axis = rng.choice(axes)

        defs = 1
        repeat = 1
        slot = 0
        sampler_kind = "2d"
        flow_kind = ""
        loop_count = 1
        src = "c0.x"
        dest = "r0.xy"

        if axis == "defs":
            defs = rng.choice(p["defs_choices"])  # type: ignore[arg-type]
        elif axis == "operand":
            if rng.random() < 0.5:
                src = "c%d.%s" % (rng.randint(0, int(p["operand_index_max"])),
                                  rng.choice("xyzw"))
            else:
                src = "-r%d.%s" % (rng.randint(0, int(p["dest_index_max"])),
                                   rng.choice("xyzw"))
            dest = "r%d.%s" % (rng.randint(0, int(p["dest_index_max"])),
                               rng.choice(["xy", "x", "y"]))
        elif axis == "repeat":
            repeat = rng.randint(1, int(p["repeat_max"]))
        elif axis == "resource":
            slot = rng.randint(0, int(p["resource_slot_max"]))
            sampler_kind = rng.choice(["2d", "cube", "volume"])
        elif axis == "flow":
            flow_kind = rng.choice(list(p["flow_kinds"]))  # type: ignore[arg-type]
            loop_count = rng.choice(list(p["loop_counts"]))  # type: ignore[arg-type]

        lines: List[str] = ["ps_3_0"]
        if axis == "resource":
            # The assembler rejects a sampler that is not declared, so declare
            # every slot up to the one referenced: the axis is "how many
            # samplers are declared and of which kind", not "illegal operand".
            lines.append("dcl_texcoord0 v0.xy")
            for i in range(slot + 1):
                lines.append("dcl_%s s%d" % (sampler_kind, i))
        for i in range(defs):
            lines.append("def c%d, %.4f, %.4f, %.4f, %.4f"
                         % (i, rng.random(), rng.random(), rng.random(), rng.random()))
        if axis == "resource":
            lines.append("texld r0, v0, s%d" % slot)
            src = "r0.x"
            # SINCOS may not target the register it reads from.
            dest = "r1.%s" % rng.choice(["xy", "x", "y"])
        body = ["sincos %s, %s" % (dest, src)] * repeat
        if flow_kind == "if":
            lines.append("if_gt c0.x, c0.y")
            lines.extend(body)
            lines.append("endif")
        elif flow_kind == "if_nested":
            lines.append("if_gt c0.x, c0.y")
            lines.append("if_ne c0.z, c0.w")
            lines.extend(body)
            lines.append("endif")
            lines.append("endif")
        elif flow_kind in ("loop", "rep"):
            lines.append("defi i0, %d, 1, 0, 0" % loop_count)
            lines.append("loop aL, i0" if flow_kind == "loop" else "rep i0")
            lines.extend(body)
            lines.append("endloop" if flow_kind == "loop" else "endrep")
        else:
            lines.extend(body)
        lines.append("mov oC0, r0")
        return Candidate(body="\n".join(lines) + "\n",
                         meta={"axis": axis, "defs": defs, "repeat": repeat,
                               "resource_slot": slot, "sampler": sampler_kind,
                               "flow": flow_kind, "loop_count": loop_count,
                               "src": src, "dest": dest},
                         name=axis)


register(Sm3Grammar())


class Sm3Runner:
    """Assemble + submit through the C harness, then classify the outcome."""

    def __init__(self, harness: Path, workdir: Path, timeout: int = 20) -> None:
        self.harness = Path(harness)
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.index = 0

    def __call__(self, candidate: Candidate) -> Outcome:
        self.index += 1
        asm = self.workdir / ("case_%05d.asm" % self.index)
        binary = self.workdir / ("case_%05d.bin" % self.index)
        asm.write_text(candidate.body, encoding="utf-8")
        started = time.time()
        try:
            done = subprocess.run([str(self.harness), "assemble", str(asm), str(binary)],
                                  capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return Outcome(kind=TIMEOUT, seconds=self.timeout, detail="harness timeout")
        seconds = round(time.time() - started, 3)
        text = (done.stdout or "") + (done.stderr or "")
        size = binary.stat().st_size if binary.is_file() else 0
        if done.returncode == 0:
            return Outcome(ACCEPTED, done.returncode, seconds, size, text.strip()[-160:])
        if "assemble failed" in text:
            return Outcome(GRAMMAR_ERROR, done.returncode, seconds, size, text.strip()[-160:])
        if "CreatePixelShader" in text:
            return Outcome(REJECTED, done.returncode, seconds, size, text.strip()[-160:])
        return Outcome(FAULT, done.returncode, seconds, size, text.strip()[-160:])


def params_from_spec(spec: Optional[dict]) -> Dict[str, object]:
    """Take the search block out of a specification, if it has one."""
    if not spec:
        return {}
    search = spec.get("search") or {}
    params = dict(DEFAULT_PARAMS)
    params.update(search.get("params") or {})
    return params


def grammar_name_from_spec(spec: Optional[dict]) -> str:
    return ((spec or {}).get("search") or {}).get("grammar", "sm3")
