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
import re
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


class Sm3ByteGrammar(Grammar):
    """Mutate a *valid* program at the dword level.

    The seed already passed the assembler and the validator, so a small number
    of changed words keeps the program acceptable far more often than random
    bytes would - and the changed field is then trusted by the driver despite
    being wrong, which is where compiler bugs live.
    """

    name = "sm3-bytes"

    def __init__(self, seed: Path) -> None:
        self.seed = Path(seed)

    def generate(self, rng: random.Random, params: Dict[str, object]) -> Candidate:
        p = dict(DEFAULT_PARAMS)
        p.update(params or {})
        raw = self.seed.read_bytes()
        words = [int.from_bytes(raw[i:i + 4], "little") for i in range(0, len(raw) - 3, 4)]
        strategy = rng.choice(list(p.get("byte_strategies",
                                         ["flip", "zero", "max", "boundary", "ctab"])))
        if strategy == "ctab":
            # Comments are opaque to the validator but parsed by the driver:
            # the constant table inside them is the classic place where the two
            # disagree about a size or a count.
            span = None
            for i, word in enumerate(words):
                if (word & 0xFFFF) == 0xFFFE:
                    span = (i, i + ((word >> 16) & 0x7FFF))
                    break
            if span is None:
                strategy = "boundary"
            else:
                lo, hi = max(span[0], 4), min(span[1], len(words))
                if hi - lo < 2:
                    strategy = "boundary"
                else:
                    idx = rng.randrange(lo, hi)
                    words[idx] = rng.choice([0, 1, 2, 3, 0x10, 0x1C, 0x20, 0x100,
                                             0xFFFF, 0x10000, 0xFFFFFFFF])
                    body = b"".join(w.to_bytes(4, "little") for w in words).hex()
                    return Candidate(body=body,
                                     meta={"format": "bytes", "axis": "byte",
                                           "strategy": "ctab", "words": [idx],
                                           "count": len(words)},
                                     name="byte")
        flips = max(1, int(p.get("byte_flips", 1)))
        touched = []
        for _ in range(flips):
            # Word 0 is the version token: corrupting it only gets us rejected.
            idx = rng.randrange(1, len(words))
            if strategy == "flip":
                words[idx] ^= 1 << rng.randrange(0, 32)
            elif strategy == "zero":
                words[idx] = 0
            elif strategy == "max":
                words[idx] = 0xFFFFFFFF
            else:
                words[idx] = rng.choice([0, 1, 2, 0xFF, 0x100, 0xFFFF, 0x10000,
                                         0x7FFFFFFF, 0xFFFFFF, 8, 24, 512])
            touched.append(idx)
        body = b"".join(w.to_bytes(4, "little") for w in words).hex()
        return Candidate(body=body,
                         meta={"format": "bytes", "axis": "byte",
                               "strategy": strategy, "words": touched,
                               "count": len(words)},
                         name="byte")


register(Sm3ByteGrammar(Path("data/harness/base.bin")))


class Sm2SincosGrammar(Grammar):
    """Shader-model-2 SINCOS, where the instruction resolves two coefficient
    constants. This is a different compiler path from ps_3_0, and the
    coefficients are the part the driver must look up rather than the validator.

    Axes: which constants hold the input and the two coefficients, and what
    values those constants carry (boundaries are where polynomial evaluation
    tends to misbehave).
    """

    name = "sm2-sincos"
    VALUES = ["0.0", "-0.0", "1.0", "-1.0", "0.5", "1e38", "-1e38",
              "3.4028235e38", "-3.4028235e38", "1e-45", "1234567.0"]

    def generate(self, rng: random.Random, params: Dict[str, object]) -> Candidate:
        p = dict(DEFAULT_PARAMS)
        p.update(params or {})
        coeff_max = int(p.get("coeff_max", 16))
        a = rng.randint(1, coeff_max)
        b = rng.randint(1, coeff_max)
        while b == a:
            b = rng.randint(1, coeff_max)
        defs = {0: rng.choice(self.VALUES), a: rng.choice(self.VALUES),
                b: rng.choice(self.VALUES)}
        stage = str(p.get("stage", "ps"))
        lines = ["vs_2_0"] if stage == "vs" else ["ps_2_0"]
        for idx in sorted(defs):
            v = defs[idx]
            lines.append("def c%d, %s, %s, %s, %s" % (idx, v, v, v, v))
        lines.append("sincos r1.x, c0.x, c%d, c%d" % (a, b))
        if stage == "vs":
            lines.append("mov oPos, c0")
        else:
            lines += ["mov r0, c0", "mov r0.x, r1.x", "mov oC0, r0"]
        return Candidate(body="\n".join(lines) + "\n",
                         meta={"axis": "sm2", "model": "vs_2_0" if stage == "vs" else "ps_2_0",
                               "stage": stage, "input": 0,
                               "coeff_a": a, "coeff_b": b,
                               "values": [defs[0], defs[a], defs[b]]},
                         name="sm2")


register(Sm2SincosGrammar())


class SincosSrcGrammar(Grammar):
    """Every legal spelling of the SINCOS source operand.

    The advisory documents the instruction as
    ``sincos[_sat] destSIN[.mask], destCOS[.mask], [-]src0[_abs][.swizzle]``,
    so negation, absolute value and swizzle are all part of the input space -
    and modifiers are exactly the kind of thing a compiler resolves through a
    table rather than inline.
    """

    name = "sincos-src"
    # SINCOS requires a replicate swizzle, so only single components qualify.
    SWIZZLES = ["x", "y", "z", "w"]

    def generate(self, rng: random.Random, params: Dict[str, object]) -> Candidate:
        p = dict(DEFAULT_PARAMS)
        p.update(params or {})
        stage = str(p.get("stage", "ps"))
        version = "vs_3_0" if stage == "vs" else "ps_3_0"
        idx_max = int(p.get("operand_index_max", 223))
        index = rng.choice([0, 0, 1, 2, 3, 15, 31, 63, 127, 128, 200, idx_max])
        index = min(index, idx_max)
        negate = rng.random() < 0.3
        absolute = rng.random() < 0.3
        swz = rng.choice(self.SWIZZLES)
        mod = ("-" if negate else "") + ("abs" if absolute else "")
        src = "%sc%d%s.%s" % ("-" if negate else "", index,
                              "_abs" if absolute else "", swz)
        dest = "r%d.%s" % (rng.choice([0, 0, 1, 2, 15, 31]), rng.choice(["xy", "x", "y"]))
        lines = [version]
        if stage == "vs":
            lines.append("dcl_position v0")
        lines.append("def c0, 0.5, 0.25, 0.75, 1.0")
        lines.append("sincos %s, %s" % (dest, src))
        lines.append("mov oPos, c0" if stage == "vs" else "mov oC0, r0")
        return Candidate(body="\n".join(lines) + "\n",
                         meta={"axis": "src", "model": version, "stage": stage,
                               "index": index, "mod": mod, "swizzle": swz,
                               "dest": dest},
                         name="src")


register(SincosSrcGrammar())


DRIVER_MODULES = ("nvgpucomp", "nvwgf2um", "nvoglv", "nvd3dum", "nvlddmkm")


def fault_frame(cdb: Path, harness: Path, binary: Path, timeout: int = 90) -> str:
    """Return the first stack frame as "module!symbol+offset" for clustering."""
    if not Path(cdb).is_file():
        return "unknown"
    try:
        done = subprocess.run([str(cdb), "-g", "-G", "-c", "sxe av; g; .lastevent; kb; q",
                               str(harness), "bytecode", str(binary)],
                              capture_output=True, text=True, errors="replace", timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    text = (done.stdout or "") + (done.stderr or "")
    for line in text.splitlines():
        if "!" in line and ("+0x" in line or ":" in line):
            token = line.strip().split()[-1].rstrip(":")
            if "!" in token:
                return token
    return "unknown"


def fault_module(cdb: Path, harness: Path, binary: Path, timeout: int = 90) -> str:
    """Ask a debugger which module faulted.

    A crash is not evidence until it is attributed: a malformed program can
    take down the D3D9 *validator* before any driver code runs, and that says
    nothing about the driver. Only a fault inside an NVIDIA module counts.
    """
    if not Path(cdb).is_file():
        return "unknown"
    script = "sxe av; g; .lastevent; kb; q"
    try:
        done = subprocess.run([str(cdb), "-g", "-G", "-c", script, str(harness),
                               "bytecode", str(binary)],
                              capture_output=True, text=True, errors="replace", timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    text = (done.stdout or "") + (done.stderr or "")
    match = re.search(r"([a-zA-Z0-9_]+)![A-Za-z0-9_:+]+", text)
    if match:
        return match.group(1).lower()
    return "unknown"


class Sm3Runner:
    """Assemble + submit through the C harness, then classify the outcome."""

    def __init__(self, harness: Path, workdir: Path, timeout: int = 20,
                 cdb: str = "", attribute: bool = False) -> None:
        self.harness = Path(harness)
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.index = 0
        self.cdb = cdb
        self.attribute = attribute

    def __call__(self, candidate: Candidate) -> Outcome:
        self.index += 1
        asm = self.workdir / ("case_%05d.asm" % self.index)
        binary = self.workdir / ("case_%05d.bin" % self.index)
        is_bytes = candidate.meta.get("format") == "bytes"
        vertex = candidate.meta.get("stage") == "vs"
        if is_bytes:
            binary.write_bytes(bytes.fromhex(candidate.body))
            command = [str(self.harness), "bytecode", str(binary)]
        else:
            asm.write_text(candidate.body, encoding="utf-8")
            command = [str(self.harness), "assemble", str(asm), str(binary)]
        if vertex:
            command.append("vs")
        started = time.time()
        try:
            done = subprocess.run(command, capture_output=True, text=True, errors="replace",
                                  timeout=self.timeout)
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
        frame = ""
        if self.attribute and self.cdb:
            frame = fault_frame(Path(self.cdb), self.harness, binary)
        module = frame.split("!")[0].lower() if "!" in frame else ""
        attributed = bool(module) and module != "unknown"
        kind = FAULT if (not attributed or
                         any(m in module for m in DRIVER_MODULES)) else "runtime_fault"
        detail = ("frame=%s " % frame if frame else "") + text.strip()[-140:]
        return Outcome(kind, done.returncode, seconds, size, detail)


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
