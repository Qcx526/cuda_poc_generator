"""Offline-only P3-A source review, pinned evidence and deterministic reports."""

import argparse
import json
from pathlib import Path

from .models.lifecycle import canonical_sha256
from .models.oracle import OraclePlan
from .oracle import evaluate_oracle
from .oracle_catalog import COARSE_UPPER, load_reviewed_claim, smoke_review_plan
from .oracle_evidence import EvidenceCorpus, load_p2c_evidence, _strict_json
from .oracle_report import rebuild_oracle_report, save_oracle_report
from .report_locale import save_localized_oracle_report, render_oracle_zh


def _read_plan(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1048576:
        raise ValueError("plan must be a bounded regular JSON file")
    return OraclePlan.model_validate(_strict_json(path.read_bytes()))


def main(argv=None):
    from .report_locale import configure_utf8_stdio
    configure_utf8_stdio()
    parser = argparse.ArgumentParser(description="P3-A offline Oracle; no process, model or CVE execution")
    commands = parser.add_subparsers(dest="command", required=True)
    catalog = commands.add_parser("claim", help="read reviewed public-source assertions plus original P1-A hashes")
    catalog.add_argument("--cve", required=True, choices=sorted(COARSE_UPPER))
    prepare = commands.add_parser("prepare-smoke-review", help="draft a conservative plan; does not approve it")
    prepare.add_argument("--cve", required=True, choices=sorted(COARSE_UPPER))
    prepare.add_argument("--evidence", required=True)
    prepare.add_argument("--manifest-sha256", required=True)
    prepare.add_argument("--plan-output", required=True)
    evaluate = commands.add_parser("evaluate", help="evaluate operator-pinned plan against pinned original P2-C evidence")
    evaluate.add_argument("--plan", required=True)
    evaluate.add_argument("--trusted-plan-sha256", required=True)
    evaluate.add_argument("--evidence", required=True)
    evaluate.add_argument("--manifest-sha256", required=True)
    evaluate.add_argument("--report-dir", required=True)
    rebuild = commands.add_parser("rebuild-report", help="verify a saved report bundle and regenerate Markdown offline")
    rebuild.add_argument("--report-dir", required=True)
    synthetic = commands.add_parser("synthetic", help="explicitly SYNTHETIC rule demonstration, never a real CVE")
    synthetic.add_argument("--case", required=True)
    synthetic.add_argument("--trusted-plan-sha256", required=True)
    synthetic.add_argument("--report-dir", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "claim":
            print(load_reviewed_claim(args.cve).model_dump_json(indent=2))
            return 0
        if args.command == "rebuild-report":
            rebuild_oracle_report(args.report_dir)  # frozen v1 integrity first
            folder=Path(args.report_dir)
            plan=_read_plan(folder/"plan.json")
            from .models.oracle import OracleResult, VulnerabilityClaim
            result=OracleResult.model_validate(_strict_json((folder/"result.json").read_bytes()))
            claim=VulnerabilityClaim.model_validate(_strict_json((folder/"claim.json").read_bytes())) if (folder/"claim.json").exists() else None
            print(render_oracle_zh(plan,result,claim),end="")
            return 0
        if args.command == "synthetic":
            case_path = Path(args.case)
            if case_path.is_symlink() or not case_path.is_file() or case_path.stat().st_size > 1048576:
                raise ValueError("synthetic case must be a bounded regular file")
            case = _strict_json(case_path.read_bytes())
            if case.get("label") != "SYNTHETIC" or set(case) != {"label", "scenario", "plan", "artifacts", "binding"}:
                raise ValueError("explicit SYNTHETIC case contract required")
            plan = OraclePlan.model_validate(case["plan"])
            if plan.domain != "SYNTHETIC":
                raise ValueError("synthetic CLI cannot create objective evidence")
            corpus = EvidenceCorpus.from_synthetic(label="SYNTHETIC", binding=case["binding"],
                artifacts={name: raw.encode("utf-8") for name, raw in case["artifacts"].items()})
            result = evaluate_oracle(plan, corpus, trusted_plan_sha256=args.trusted_plan_sha256)
            save_oracle_report(args.report_dir, plan, result)
            save_localized_oracle_report(str(args.report_dir)+".zh-CN",plan,result)
            print(result.model_dump_json(indent=2))
            return 2 if result.condition_status == "CONFLICT" else 0
        corpus = load_p2c_evidence(args.evidence, expected_manifest_sha256=args.manifest_sha256)
        if args.command == "prepare-smoke-review":
            plan = smoke_review_plan(load_reviewed_claim(args.cve), corpus)
            with Path(args.plan_output).open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(plan.model_dump_json(indent=2) + "\n")
            print(json.dumps({"status": "DRAFT_NOT_AUTHORIZED", "plan_sha256": canonical_sha256(plan),
                              "real_cve_verification": "NOT_VERIFIED"}))
            return 0
        plan = _read_plan(args.plan)
        result = evaluate_oracle(plan, corpus, trusted_plan_sha256=args.trusted_plan_sha256)
        save_oracle_report(args.report_dir, plan, result, load_reviewed_claim(plan.cve_id))
        save_localized_oracle_report(str(args.report_dir)+".zh-CN",plan,result,load_reviewed_claim(plan.cve_id))
        print(json.dumps({"eligibility": result.eligibility.status, "condition_status": result.condition_status,
                          "verdict": result.verdict, "real_cve_verification": result.real_cve_verification}))
        # An exit code expresses evaluation/report completion, never CVE success.
        return 2 if result.condition_status == "CONFLICT" else 0
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.exit(2, "Offline Oracle rejected input: " + str(exc) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
