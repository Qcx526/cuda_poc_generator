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
from typing import Dict, List, Optional

from src.fuzz_core import fuzz, grammar_for, save
from tools.driver.sm3 import Sm3Runner, grammar_name_from_spec, params_from_spec


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="spec-driven fuzzing campaign")
    parser.add_argument("--spec", default="", help="specification with a search block")
    parser.add_argument("--harness", default="data/harness/shader_runner.exe")
    parser.add_argument("--out", default="data/fuzz")
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--cdb", default="", help="debugger used to attribute faults")
    parser.add_argument("--probe-rva", default="",
                        help="use a debugger probe at module+rva as the fitness signal")
    parser.add_argument("--module", default="nvgpucomp64")
    parser.add_argument("--attribute", action="store_true", default=False,
                        help="run a fault under the debugger to name the module")
    parser.add_argument("--grammar", default="", help="override the spec's grammar")
    parser.add_argument("--set", action="append", default=[],
                        help="override a search param, e.g. --set byte_flips=2")
    args = parser.parse_args(argv)

    spec = json.loads(Path(args.spec).read_text(encoding="utf-8")) if args.spec else None
    params = params_from_spec(spec)
    for item in args.set:
        key, _, value = item.partition("=")
        try:
            params[key] = json.loads(value)
        except json.JSONDecodeError:
            params[key] = value
    grammar = grammar_for(args.grammar or grammar_name_from_spec(spec))
    harness = Path(args.harness).resolve()
    if not harness.is_file():
        raise SystemExit("harness not found: %s" % harness)

    out = Path(args.out)
    if args.probe_rva:
        from tools.driver.probe_runner import ProbeRunner
        runner = ProbeRunner(harness, out, Path(args.cdb), args.module,
                             int(args.probe_rva, 0))
    else:
        runner = Sm3Runner(harness, out, cdb=args.cdb, attribute=args.attribute)

    def on_new(outcome, candidate):
        print("[new] %-13s axis=%-9s %s" % (outcome.kind, candidate.meta.get("axis"),
                                            candidate.meta), flush=True)

    trace: List[Dict[str, object]] = []
    trace_file = out / "fuzz_trace.jsonl"

    def on_case(index, outcome, candidate):
        trace.append({"i": index, "kind": outcome.kind, "size": outcome.size,
                      "seconds": outcome.seconds, "meta": candidate.meta,
                      "detail": outcome.detail})
        # Persist as we go: an interrupted campaign must not lose the cases it
        # already ran, including any fault it already found.
        if (index + 1) % 100 == 0:
            trace_file.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in trace),
                                  encoding="utf-8")

    def on_fault(outcome, candidate):
        print("[FAULT] rc=%s %s" % (outcome.rc, candidate.meta), flush=True)
        (out / "fault_latest.asm").write_text(candidate.body, encoding="utf-8")

    summary = fuzz(grammar=grammar, params=params, runner=runner,
                   iterations=args.iterations, seed=args.seed,
                   on_new=on_new, on_fault=on_fault, on_case=on_case)
    trace_file.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in trace),
                          encoding="utf-8")
    save(out / "fuzz_summary.json", summary,
         {"spec": args.spec, "params": params, "grammar": grammar.name})
    print("\n=== %d cases: %s | corpus=%d | faults=%d ===" % (
        summary.iterations, summary.outcomes, summary.corpus, len(summary.faults)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
