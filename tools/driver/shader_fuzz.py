# -*- coding: utf-8 -*-
"""Grammar-aware fuzzing for the shader-model-3 path.

Byte-level fuzzing does not work here: the D3D9 validator rejects random
mutations before the driver compiler ever sees them (256 attempts, 0 hits).
So the mutator works on *assembly text* and lets the assembler and the runtime
validator act as a grammar oracle - only well-formed programs reach the driver.

Three ideas borrowed from fuzzing, adapted:

* a seed corpus of valid programs rather than random bytes;
* structure-preserving mutations (operands, declarations, instruction counts,
  boundary values) so most cases stay valid;
* a corpus of "interesting" cases, where interesting means a new
  (outcome, size, duration) bucket - the closest thing to coverage we can get
  from a closed-source driver.

Usage:
  python -m tools.driver.shader_fuzz --iterations 200 --out data/fuzz
"""

import argparse
import json
import random
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HEADER = "ps_3_0\n"
TAIL = "mov oC0, r0\n"


@dataclass
class Case:
    source: str
    mutations: List[str] = field(default_factory=list)


def _def_block(count: int, rng: random.Random) -> str:
    out = []
    for i in range(count):
        out.append("def c%d, %.4f, %.4f, %.4f, %.4f\n"
                   % (i, rng.random(), rng.random(), rng.random(), rng.random()))
    return "".join(out)


def _operand(rng: random.Random, kind: str) -> str:
    """One SINCOS source operand, staying inside what the assembler accepts."""
    if kind == "const":
        base = "c%d.%s" % (rng.choice([0, 0, 0, 1, 2, 3, 7, 15, 31, 63, 127]),
                           rng.choice("xyzw"))
    else:
        base = "r%d.%s" % (rng.choice(list(range(0, 16)) + [30, 31]),
                           rng.choice("xyzw"))
    # SM3 assembly rejects _abs after a swizzle, so only negation is used here.
    return ("-" if rng.random() < 0.25 else "") + base


def generate(seed: int) -> Case:
    rng = random.Random(seed)
    defs = _def_block(rng.choice([0, 1, 1, 2, 4, 8, 16, 32]), rng)
    kind = rng.choice(["const", "const", "temp"])
    src = _operand(rng, kind)
    # The assembler accepts .xy, .x or .y for SINCOS - nothing wider.
    mask = rng.choice(["xy", "xy", "x", "y"])
    dest = "r%d.%s" % (rng.choice([0, 0, 0, 1, 2, 15, 31]), mask)

    body = []
    for _ in range(rng.choice([0, 0, 1, 2, 4])):
        body.append("mov r%d, %s\n" % (rng.randint(0, 3), _operand(rng, "const")))
    repeats = rng.choice([1, 1, 1, 2, 3, 8])
    for i in range(repeats):
        body.append("sincos %s, %s\n" % (dest, src if i == 0 else _operand(rng, kind)))
    for _ in range(rng.choice([0, 0, 1, 3])):
        body.append("add r%d, r%d, %s\n" % (rng.randint(0, 3), rng.randint(0, 3),
                                            _operand(rng, "const")))
    case = Case(source=HEADER + defs + "".join(body) + TAIL)
    case.mutations = ["defs=%d" % defs.count("def "), "src=%s" % src,
                      "mask=%s" % mask, "repeats=%d" % repeats]
    return case


def run_case(harness: Path, workdir: Path, case: Case, index: int,
             timeout: int = 20) -> Dict[str, object]:
    asm = workdir / ("case_%04d.asm" % index)
    binary = workdir / ("case_%04d.bin" % index)
    asm.write_text(case.source, encoding="utf-8")
    started = time.time()
    try:
        completed = subprocess.run([str(harness), "assemble", str(asm), str(binary)],
                                   capture_output=True, text=True, timeout=timeout)
        code, out = completed.returncode, completed.stdout + completed.stderr
    except subprocess.TimeoutExpired:
        return {"index": index, "outcome": "timeout", "rc": None,
                "seconds": timeout, "mutations": case.mutations, "detail": ""}
    seconds = time.time() - started
    if code == 0:
        outcome = "accepted"
    elif code == 1 and "assemble failed" not in out and "CreatePixelShader" in out:
        outcome = "rejected"
    elif code == 1 and "assemble failed" in out:
        outcome = "bad_grammar"
    else:
        outcome = "fault"
    size = binary.stat().st_size if binary.is_file() else 0
    return {"index": index, "outcome": outcome, "rc": code, "seconds": round(seconds, 3),
            "size": size, "mutations": case.mutations,
            "detail": (out.strip().splitlines() or [""])[-1][:160]}


def bucket(result: Dict[str, object]) -> Tuple[str, int, int]:
    """What counts as 'interesting': a new behaviour, not a new input."""
    secs = float(result.get("seconds") or 0)
    return (str(result["outcome"]), int(result.get("size") or 0), int(secs * 4))


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="grammar-aware shader fuzzing")
    parser.add_argument("--harness", default="data/harness/shader_runner.exe")
    parser.add_argument("--out", default="data/fuzz")
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args(argv)

    harness = Path(args.harness).resolve()
    if not harness.is_file():
        raise SystemExit("harness not found: %s" % harness)
    workdir = Path(args.out)
    workdir.mkdir(parents=True, exist_ok=True)

    seen: Dict[Tuple[str, int, int], int] = {}
    corpus: List[Dict[str, object]] = []
    results: List[Dict[str, object]] = []
    for i in range(args.iterations):
        case = generate(args.seed + i)
        result = run_case(harness, workdir, case, i)
        results.append(result)
        key = bucket(result)
        if key not in seen:
            seen[key] = i
            corpus.append(result)
            print("[new] %-10s size=%-4d %.2fs  %s" % (
                result["outcome"], result.get("size", 0), result.get("seconds", 0),
                " ".join(result["mutations"])), flush=True)
        if result["outcome"] == "fault":
            print("[FAULT] case_%04d rc=%s %s" % (i, result["rc"], result["detail"]), flush=True)

    summary = {
        "iterations": args.iterations,
        "outcomes": {k: sum(1 for r in results if r["outcome"] == k)
                     for k in ("accepted", "rejected", "bad_grammar", "fault", "timeout")},
        "corpus_size": len(corpus),
        "faults": [r for r in results if r["outcome"] == "fault"],
    }
    (workdir / "fuzz_summary.json").write_text(
        json.dumps({"summary": summary, "corpus": corpus}, ensure_ascii=False, indent=1),
        encoding="utf-8")
    print("\n=== %d iterations: %s | corpus=%d ===" % (
        args.iterations, summary["outcomes"], len(corpus)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
