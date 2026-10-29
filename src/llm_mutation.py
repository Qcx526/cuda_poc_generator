# -*- coding: utf-8 -*-
"""The model proposes mutations; this module performs them.

Value substitution finds what a boundary break looks like. It cannot find a
mutation that only means something in combination - point one section at another
that has no names, or make a size and an offset disagree in a specific way. Those
are choices about intent, and intent is what a model is good at.

What a model is not good at is writing bytes at the right place. So it does not:
it names a field and a value, this module checks the field exists, fits its width,
and does not duplicate an existing proposal, then applies it exactly. Proposals
that fail validation are counted and reported rather than silently dropped - the
invalid rate is the price of model involvement and belongs in the result.

The proposal list is written next to the run. A run can be replayed from it with
--from-proposals and no model call, which is what makes the result checkable.

  python -m src.llm_mutation --cve CVE-2024-0076 \\
      --seed data/outputs/CVE-2024-0076/benign.cubin \\
      --image nvidia/cuda:12.4.1-devel-ubuntu22.04 \\
      --tool "cuobjdump --dump-elf {artifact}" --count 60 --workdir data/mutation/llm
"""

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import elf_fields
from . import mutation_campaign as campaign

SYSTEM = """You are a vulnerability researcher testing a binary format parser.
You propose mutations, one field at a time, that are likely to make the parser
crash or crash somewhere new.

Rules:
- Name fields using exactly the names in the provided table.
- A value must fit the field's width in bytes.
- Do not propose the value the field already holds.
- Prefer mutations that are self-consistent: a length that still points at real
  data, an index that still names an existing entry, a type that changes which
  code path runs. A file the parser rejects immediately teaches nothing.
- Return JSON only: {"mutations": [{"field": "...", "value": 0, "reason": "..."}]}
"""


@dataclass
class Proposal:
    field: str
    value: int
    reason: str = ""


@dataclass
class Accepted:
    proposal: Proposal
    offset: int
    width: int


def build_prompt(cve_id: str, spec: dict, table: dict, crash_note: str,
                 count: int) -> str:
    oracle = spec.get("oracle") or {}
    rows = ["| field | offset | width | current |", "|---|---|---|---|"]
    for name, item in table.items():
        rows.append("| %s | %d | %d | %d (0x%x) |"
                    % (name, item["offset"], item["width"],
                       item["value"], item["value"]))
    return "\n".join([
        "Target: %s" % spec.get("component", ""),
        "Advisory: %s" % oracle.get("advisory", ""),
        "Affected: %s" % oracle.get("affected", ""),
        "Documented effect: %s" % oracle.get("expected_effect", ""),
        "Documented precondition: %s" % oracle.get("condition", ""),
        "",
        "Already observed: %s" % (crash_note or "nothing yet"),
        "",
        "Fields:",
        "",
    ] + rows + [
        "",
        "Propose at most %d mutations for %s." % (count, cve_id),
        "Explain in the reason what parser decision the value is meant to change.",
    ])


def validate(proposals: List[Proposal], table: dict) -> Tuple[List[Accepted], List[dict]]:
    """Keep the proposals that can be applied exactly as written."""
    accepted: List[Accepted] = []
    rejected: List[dict] = []
    seen = set()
    for proposal in proposals:
        item = table.get(proposal.field)
        if item is None:
            rejected.append({"proposal": proposal.__dict__, "why": "unknown field"})
            continue
        limit = 1 << (8 * item["width"])
        if not 0 <= proposal.value < limit:
            rejected.append({"proposal": proposal.__dict__,
                             "why": "does not fit %d byte(s)" % item["width"]})
            continue
        if proposal.value == item["value"]:
            rejected.append({"proposal": proposal.__dict__,
                             "why": "value unchanged"})
            continue
        key = (proposal.field, proposal.value)
        if key in seen:
            rejected.append({"proposal": proposal.__dict__, "why": "duplicate"})
            continue
        seen.add(key)
        accepted.append(Accepted(proposal, item["offset"], item["width"]))
    return accepted, rejected


def to_variants(items: List[Accepted]) -> List[campaign.Variant]:
    return [campaign.Variant(axis="llm", field=item.proposal.field,
                             value=item.proposal.value, offset=item.offset,
                             width=item.width)
            for item in items]


def parse_proposals(payload: dict) -> List[Proposal]:
    out = []
    for row in payload.get("mutations") or []:
        try:
            out.append(Proposal(field=str(row["field"]),
                                value=int(row["value"]),
                                reason=str(row.get("reason", ""))[:160]))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def ask_model(cve_id: str, spec: dict, table: dict, crash_note: str,
              count: int) -> List[Proposal]:
    from .config_loader import ConfigLoader
    from .llm_client import LLMClient

    client = LLMClient(ConfigLoader())
    payload = client.structured_generate(
        system_prompt=SYSTEM,
        user_prompt=build_prompt(cve_id, spec, table, crash_note, count),
        temperature=0.0)
    return parse_proposals(payload)


def run(cve_id: str, spec: dict, seed: bytes, proposals: List[Proposal],
        invocations: List[List[str]], workdir: Path, image: str,
        timeout: int = 1200) -> dict:
    table = elf_fields.table(seed)
    accepted, rejected = validate(proposals, table)
    variants = to_variants(accepted)
    baseline = campaign.Variant(axis="seed", field="(unchanged)", value=0,
                                offset=0, width=0)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "proposals.json").write_text(json.dumps(
        {"cve_id": cve_id, "proposed": [p.__dict__ for p in proposals],
         "accepted": len(accepted), "rejected": rejected},
        ensure_ascii=False, indent=2), encoding="utf-8")

    if variants:
        campaign.run([baseline] + variants, seed, invocations, workdir,
                     image, timeout=timeout)
        campaign.classify(variants, baseline.fingerprint)

    crashes = [v for v in variants if v.outcome == campaign.NOVEL]
    sites: Dict[str, int] = {}
    for variant in crashes:
        sites[variant.fingerprint] = sites.get(variant.fingerprint, 0) + 1
    return {"proposed": len(proposals), "accepted": len(accepted),
            "rejected": len(rejected), "variants": len(variants),
            "crashes": len(crashes), "sites": sites,
            "seed_fingerprint": baseline.fingerprint,
            "reasons": {v.field: (v.severity or "unknown") for v in variants}}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="model-guided field mutation")
    parser.add_argument("--cve", required=True)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--image", default=campaign.DEFAULT_IMAGE)
    parser.add_argument("--tool", default="")
    parser.add_argument("--count", type=int, default=40)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--from-proposals", default="",
                        help="replay a saved proposal list without calling the model")
    parser.add_argument("--crash-note", default="")
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    spec = json.loads((root / "specs" / args.cve / "spec.json").read_text(encoding="utf-8"))
    seed = Path(args.seed).read_bytes()

    if args.from_proposals:
        payload = json.loads(Path(args.from_proposals).read_text(encoding="utf-8"))
        proposals = [Proposal(**row) for row in payload.get("proposed", [])]
    else:
        proposals = ask_model(args.cve, spec, elf_fields.table(seed),
                              args.crash_note, args.count)

    invocations = [args.tool.split()] if args.tool else \
        [[part.replace("{artifact}", "{artifact}") for part in
          (spec.get("anchor", {}).get("invocation") or ["cuobjdump", "--dump-elf", "{artifact}"])]]
    summary = run(args.cve, spec, seed, proposals, invocations,
                  Path(args.workdir), args.image)

    print("proposed %d | accepted %d | rejected %d"
          % (summary["proposed"], summary["accepted"], summary["rejected"]))
    print("seed fingerprint: %s | variants: %d"
          % (summary["seed_fingerprint"] or "(clean)", summary["variants"]))
    print("crashes: %d at %d distinct site(s)"
          % (summary["crashes"], len(summary["sites"])))
    for site, count in sorted(summary["sites"].items(), key=lambda kv: -kv[1]):
        print("  %-26s %d variant(s)" % (site, count))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
