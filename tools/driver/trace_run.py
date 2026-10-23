# -*- coding: utf-8 -*-
"""Trace one program at one probe and optionally write the finding back.

    python -m tools.driver.trace_run --spec specs/CVE-XXXX/spec.json \\
        --program data/harness/c.bin --module nvgpucomp64 --rva 0xab3890 \\
        --statement "the out-of-bounds helper is not on the plain SINCOS path" --write

The point is not to print a stack: it is to turn dynamic evidence into a
specification claim the generator can read, so the next attempt starts from
what the target actually did.
"""

import argparse
import json
from pathlib import Path
from typing import Optional

import tools.driver.cdb_trace  # noqa: F401 - registers the provider
from src.trace_core import Probe, claims_from_trace, merge_claims, provider_for


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="trace a program at one probe")
    parser.add_argument("--program", required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--rva", default="")
    parser.add_argument("--symbol", default="")
    parser.add_argument("--provider", default="cdb")
    parser.add_argument("--statement", default="")
    parser.add_argument("--claim-key", default="")
    parser.add_argument("--spec", default="")
    parser.add_argument("--write", action="store_true", default=False)
    parser.add_argument("--timeout", type=int, default=150)
    args = parser.parse_args(argv)

    probe = Probe(args.module,
                  rva=int(args.rva, 0) if args.rva else 0,
                  symbol=args.symbol or None)
    result = provider_for(args.provider).trace(Path(args.program), probe,
                                               timeout=args.timeout)
    print(json.dumps(result.as_dict(), ensure_ascii=False, indent=1))

    if args.write:
        if not (args.spec and args.statement and args.claim_key):
            raise SystemExit("--write needs --spec, --statement and --claim-key")
        claim = claims_from_trace(result, args.statement)
        note = ("probe %s: %s" % (probe.expression, "hit" if result.hit else "never hit"))
        merge_claims(Path(args.spec), {args.claim_key: claim}, history_note=note)
        print("written to %s" % args.spec)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
