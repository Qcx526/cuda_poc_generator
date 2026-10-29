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
You design mutation operators that are likely to make the parser crash, or crash
somewhere new. An operator applies to a set of fields, not a single one; the
harness expands it.

Available operator kinds:
  {"op": "set", "target": "<glob>", "value": <int>}
  {"op": "scale", "target": "<glob>", "factor": <int>}
  {"op": "set_to", "target": "<glob>", "value_from": "<source>"}

target is a glob over field names: "sec*.sh_size", "e_*", "sec0.*", "*".
value_from is one of: "file_len", "file_len_plus_1", "section_table_end",
"e_shnum", "e_shoff", "zero".

Rules:
- If an idea applies to every section, write ONE operator with a glob such as
  "sec*.sh_size". Enumerating sec3, sec4, sec5 ... spends your whole budget on a
  single idea and is rejected as redundant by the harness.
- Each operator should match more than one field. Name a single field only when
  the idea is genuinely field-specific (usually a header field).
- The values listed under "already tried" have been substituted into every field
  and taught nothing new. Propose something outside that set: a value derived from
  the file's own structure, a scaled value, an off-by-one, or a combination that
  only makes sense together.
- A value must fit the target field's width; the harness rejects the rest.
- Prefer operators that stay self-consistent: a stride that lands on real data, an
  index that still names an existing entry, a type that changes which code path
  runs. A file the parser rejects immediately teaches nothing.
- Return JSON only: {"operators": [{"op": ..., "target": ..., "reason": "..."}]}
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
        "Already tried, every field: %s"
        % ", ".join(str(v) for v in elf_fields.COMMON_VALUES),
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


@dataclass
class Operator:
    op: str
    target: str
    value: int = 0
    factor: int = 0
    value_from: str = ""
    reason: str = ""


SOURCES = ("file_len", "file_len_plus_1", "section_table_end",
           "e_shnum", "e_shoff", "zero")


def _source_value(name: str, table: dict, length: int) -> Optional[int]:
    if name == "file_len":
        return length
    if name == "file_len_plus_1":
        return length + 1
    if name == "section_table_end":
        entry = table.get("e_shoff")
        stride = table.get("e_shentsize")
        count = table.get("e_shnum")
        if not (entry and stride and count):
            return None
        return entry["value"] + stride["value"] * count["value"]
    if name == "zero":
        return 0
    item = table.get(name)
    return item["value"] if item else None


def expand(operators: List[Operator], table: dict, length: int,
           per_operator: int = 40) -> Tuple[List[Accepted], List[dict]]:
    """Turn operators into concrete mutations, one per matching field.

    This is the point of operators: one model answer covers every section, so the
    cost of asking does not grow with the size of the file.
    """
    import fnmatch

    accepted: List[Accepted] = []
    rejected: List[dict] = []
    seen = set()
    for operator in operators:
        matched = [name for name in table if fnmatch.fnmatch(name, operator.target)]
        if not matched:
            rejected.append({"operator": operator.__dict__, "why": "no field matches"})
            continue
        taken = 0
        for name in matched:
            item = table[name]
            current = item["value"]
            if operator.op == "set":
                value = operator.value
            elif operator.op == "scale":
                value = current * operator.factor
            elif operator.op == "set_to":
                value = _source_value(operator.value_from, table, length)
                if value is None:
                    rejected.append({"operator": operator.__dict__,
                                     "why": "unknown source %s" % operator.value_from})
                    break
            else:
                rejected.append({"operator": operator.__dict__,
                                 "why": "unknown op %s" % operator.op})
                break
            limit = 1 << (8 * item["width"])
            if not 0 <= value < limit:
                rejected.append({"operator": operator.__dict__, "field": name,
                                 "why": "%d does not fit %d byte(s)"
                                        % (value, item["width"])})
                continue
            if value == current:
                rejected.append({"operator": operator.__dict__, "field": name,
                                 "why": "value unchanged"})
                continue
            key = (name, value)
            if key in seen:
                continue
            seen.add(key)
            accepted.append(Accepted(Proposal(name, value, operator.reason),
                                     item["offset"], item["width"]))
            taken += 1
            if taken >= per_operator:
                break
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


def parse_operators(payload: dict) -> List[Operator]:
    out = []
    for row in payload.get("operators") or []:
        try:
            out.append(Operator(op=str(row["op"]), target=str(row["target"]),
                                value=int(row.get("value", 0)),
                                factor=int(row.get("factor", 0)),
                                value_from=str(row.get("value_from", "")),
                                reason=str(row.get("reason", ""))[:160]))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def ask_operators(cve_id: str, spec: dict, table: dict, crash_note: str,
                  count: int) -> List[Operator]:
    from .config_loader import ConfigLoader
    from .llm_client import LLMClient

    client = LLMClient(ConfigLoader())
    payload = client.structured_generate(
        system_prompt=SYSTEM,
        user_prompt=build_prompt(cve_id, spec, table, crash_note, count),
        temperature=0.0)
    return parse_operators(payload)


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
    return execute(cve_id, seed, accepted, rejected, invocations, workdir,
                   image, timeout, proposed=len(proposals))


def execute(cve_id: str, seed: bytes, accepted: List[Accepted],
            rejected: List[dict], invocations: List[List[str]], workdir: Path,
            image: str, timeout: int = 1200, proposed: int = 0) -> dict:
    variants = to_variants(accepted)
    baseline = campaign.Variant(axis="seed", field="(unchanged)", value=0,
                                offset=0, width=0)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "proposals.json").write_text(json.dumps(
        {"cve_id": cve_id, "proposed": proposed,
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
    return {"proposed": proposed, "accepted": len(accepted),
            "rejected": len(rejected), "variants": len(variants),
            "crashes": len(crashes), "sites": sites,
            "seed_fingerprint": baseline.fingerprint,
            "reasons": {v.field: (v.severity or "unknown") for v in variants}}


def invocations_for(spec: dict, args) -> List[List[str]]:
    if args.tool:
        return [args.tool.split()]
    anchor = spec.get("anchor") or {}
    single = anchor.get("invocation") or ["cuobjdump", "--dump-elf", "{artifact}"]
    return [list(single)]


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
    parser.add_argument("--mode", choices=("operators", "instances"),
                        default="operators",
                        help="operators: one answer covers every matching field")
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    spec = json.loads((root / "specs" / args.cve / "spec.json").read_text(encoding="utf-8"))
    seed = Path(args.seed).read_bytes()

    table = elf_fields.table(seed)
    if args.from_proposals:
        payload = json.loads(Path(args.from_proposals).read_text(encoding="utf-8"))
        proposals = [Proposal(**row) for row in payload.get("proposed", [])]
        accepted, rejected = validate(proposals, table)
        summary = execute(args.cve, seed, accepted, rejected, invocations_for(spec, args),
                          Path(args.workdir), args.image, proposed=len(proposals))
    elif args.mode == "instances":
        proposals = ask_model(args.cve, spec, table, args.crash_note, args.count)
        accepted, rejected = validate(proposals, table)
        summary = execute(args.cve, seed, accepted, rejected, invocations_for(spec, args),
                          Path(args.workdir), args.image, proposed=len(proposals))
    else:
        operators = ask_operators(args.cve, spec, table, args.crash_note, args.count)
        accepted, rejected = expand(operators, table, len(seed))
        Path(args.workdir).mkdir(parents=True, exist_ok=True)
        (Path(args.workdir) / "operators.json").write_text(json.dumps(
            {"cve_id": args.cve, "operators": [o.__dict__ for o in operators]},
            ensure_ascii=False, indent=2), encoding="utf-8")
        summary = execute(args.cve, seed, accepted, rejected, invocations_for(spec, args),
                          Path(args.workdir), args.image, proposed=len(operators))
        print("operators: %d | variants per operator: %.1f"
              % (len(operators), summary["variants"] / max(1, len(operators))))

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
