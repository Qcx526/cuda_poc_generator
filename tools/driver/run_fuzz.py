# -*- coding: utf-8 -*-
"""Wire a specification into the generic engine and run a campaign.

    python -m tools.driver.run_fuzz --spec specs/CVE-XXXX/spec.json --iterations 400

The specification supplies the axes and ranges (its ``search`` block); this
module supplies only the wiring, so adding a target means adding a grammar,
never editing the loop.
"""

import argparse
import json
from pathlib import Path
from typing import Optional

from src.fuzz_core import fuzz, grammar_for, save
from tools.driver.sm3 import Sm3Runner, grammar_name_from_spec, params_from_spec


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="spec-driven fuzzing campaign")
    parser.add_argument("--spec", default="", help="specification with a search block")
    parser.add_argument("--harness", default="data/harness/shader_runner.exe")
    parser.add_argument("--out", default="data/fuzz")
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args(argv)

    spec = json.loads(Path(args.spec).read_text(encoding="utf-8")) if args.spec else None
    params = params_from_spec(spec)
    grammar = grammar_for(grammar_name_from_spec(spec))
    harness = Path(args.harness).resolve()
    if not harness.is_file():
        raise SystemExit("harness not found: %s" % harness)

    out = Path(args.out)
    runner = Sm3Runner(harness, out)

    def on_new(outcome, candidate):
        print("[new] %-13s axis=%-9s %s" % (outcome.kind, candidate.meta.get("axis"),
                                            candidate.meta), flush=True)

    def on_fault(outcome, candidate):
        print("[FAULT] rc=%s %s" % (outcome.rc, candidate.meta), flush=True)
        (out / "fault_latest.asm").write_text(candidate.body, encoding="utf-8")

    summary = fuzz(grammar=grammar, params=params, runner=runner,
                   iterations=args.iterations, seed=args.seed,
                   on_new=on_new, on_fault=on_fault)
    save(out / "fuzz_summary.json", summary,
         {"spec": args.spec, "params": params, "grammar": grammar.name})
    print("\n=== %d cases: %s | corpus=%d | faults=%d ===" % (
        summary.iterations, summary.outcomes, summary.corpus, len(summary.faults)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
