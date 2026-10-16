"""Offline catalog/CLI compatibility, plus optional reread of historical real evidence."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from src.models.lifecycle import canonical_sha256
from src.oracle import evaluate_oracle
from src.oracle_catalog import COARSE_UPPER, ROOT, load_reviewed_claim, smoke_review_plan
from src.oracle_evidence import load_p2c_evidence
from src.oracle_report import rebuild_oracle_report, save_oracle_report


@pytest.mark.parametrize("cve_id", sorted(COARSE_UPPER))
def test_six_claims_reuse_seven_original_input_hashes(cve_id):
    claim = load_reviewed_claim(cve_id)
    refs = {a.source_file: a.source_sha256 for a in claim.input_assertions}
    assert len(refs) == 7
    for path, sha in refs.items():
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == sha
    assert claim.fact_status != "UNREVIEWED"
    assert all(a.verification == "UNVERIFIED" for a in claim.input_assertions)
    assert claim.unknowns
    assert all(s.support == "DOCUMENTED" for s in claim.sources)


def test_public_cwe_conflict_is_not_silently_resolved():
    claim = load_reviewed_claim("CVE-2022-21821")
    assert set(claim.cwe) == {"CWE-190", "CWE-1285"}
    assert claim.fact_status == "CONFLICT"


def test_unreviewed_cve_is_rejected():
    with pytest.raises(ValueError, match="no reviewed"):
        load_reviewed_claim("CVE-2099-0001")


def test_known_toolkit_cannot_exclude_cve_when_target_parser_version_is_unknown(tmp_path):
    from tests.test_oracle_evidence import mock_context, load_mock
    context, pin = mock_context(tmp_path)
    corpus = load_mock(tmp_path, context, pin)
    # This mock has an OBSERVED Toolkit12.8 but no bound nvdisasm version banner.
    # Treating nvcc/Toolkit as this parser version would falsely rule out 0124.
    claim = load_reviewed_claim("CVE-2024-0124")
    plan = smoke_review_plan(claim, corpus)
    result = evaluate_oracle(plan, corpus, trusted_plan_sha256=canonical_sha256(plan))
    assert result.eligibility.status == "UNKNOWN"
    assert result.conditions[0].status == "UNKNOWN"
    assert result.real_cve_verification == "NOT_VERIFIED"


@pytest.mark.parametrize("command", [["--help"], ["claim", "--help"], ["evaluate", "--help"],
                                    ["prepare-smoke-review", "--help"], ["rebuild-report", "--help"]])
def test_oracle_cli_help_remains_offline(command):
    result = subprocess.run([sys.executable, "-m", "src.oracle_cli", *command], cwd=ROOT,
                            capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert b"--help" in result.stdout


def test_oracle_cli_claim_contains_assertions_not_verification():
    result = subprocess.run([sys.executable, "-m", "src.oracle_cli", "claim", "--cve", "CVE-2025-23339"],
                            cwd=ROOT, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    claim = json.loads(result.stdout)
    assert claim["fact_status"] == "DOCUMENTED_NOT_REPRODUCED"
    assert claim["input_assertions"][0]["verification"] == "UNVERIFIED"


@pytest.mark.parametrize("scenario,verdict", [("positive", "VERIFIED"), ("negative", "NOT_VERIFIED"),
                                           ("unknown", "UNKNOWN"), ("partial", "SUPPORTED")])
def test_frozen_synthetic_examples_recompute_from_original_fixture_bytes(scenario, verdict):
    from src.models.oracle import OraclePlan, OracleResult
    from src.oracle_evidence import EvidenceCorpus
    from src.oracle_report import render_oracle_report
    root = ROOT / "docs" / "examples" / "p3_a"
    case = json.loads((root / ("synthetic_" + scenario + "_input.json")).read_bytes())
    assert case["label"] == "SYNTHETIC"
    plan = OraclePlan.model_validate(case["plan"])
    corpus = EvidenceCorpus.from_synthetic(label="SYNTHETIC", binding=case["binding"],
        artifacts={name: raw.encode() for name, raw in case["artifacts"].items()})
    result = evaluate_oracle(plan, corpus, trusted_plan_sha256=canonical_sha256(plan))
    expected = OracleResult.model_validate_json((root / ("synthetic_" + scenario + "_output.json")).read_bytes())
    assert result == expected
    assert result.verdict == verdict and result.real_cve_verification == "NOT_VERIFIED"
    assert render_oracle_report(plan, result).encode() == (root / ("synthetic_" + scenario + "_report.md")).read_bytes()


def test_synthetic_example_cli_and_offline_rebuild(tmp_path):
    root = ROOT / "docs" / "examples" / "p3_a"
    case = json.loads((root / "synthetic_positive_input.json").read_bytes())
    plan_pin = canonical_sha256(case["plan"])
    folder = tmp_path / "synthetic-output"
    result = subprocess.run([sys.executable, "-m", "src.oracle_cli", "synthetic", "--case",
        str(root / "synthetic_positive_input.json"), "--trusted-plan-sha256", plan_pin,
        "--report-dir", str(folder)], cwd=ROOT, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["domain"] == "SYNTHETIC" and output["real_cve_verification"] == "NOT_VERIFIED"
    assert rebuild_oracle_report(folder) == (folder / "report.md").read_text(encoding="utf-8")


@pytest.mark.skipif(not (os.environ.get("P3A_P2C_EVIDENCE_DIR") and os.environ.get("P3A_P2C_MANIFEST_SHA256")),
                    reason="requires independently pinned historical harmless P2-C evidence; never launches tools")
def test_real_historical_smoke_six_cve_oracles_not_verified_and_rebuild(tmp_path):
    corpus = load_p2c_evidence(os.environ["P3A_P2C_EVIDENCE_DIR"],
                              expected_manifest_sha256=os.environ["P3A_P2C_MANIFEST_SHA256"])
    assert corpus.binding["tool_versions"]["nvcc"]["build"] == "12.8.93"
    assert corpus.binding["tool_versions"]["cuobjdump"]["build"] == "12.8.90"
    assert corpus.binding["tool_versions"]["nvdisasm"]["build"] == "12.8.90"
    assert corpus.qualified
    for cve_id in sorted(COARSE_UPPER):
        claim = load_reviewed_claim(cve_id)
        plan = smoke_review_plan(claim, corpus)
        result = evaluate_oracle(plan, corpus, trusted_plan_sha256=canonical_sha256(plan))
        assert result.verdict == "NOT_VERIFIED"
        assert result.real_cve_verification == "NOT_VERIFIED"
        assert result.condition_status != "CONFLICT", result
        assert result.eligibility.status == ("UNKNOWN" if "2025" in cve_id else "INELIGIBLE")
        folder = save_oracle_report(tmp_path / cve_id, plan, result, claim)
        assert rebuild_oracle_report(folder).encode() == (folder / "report.md").read_bytes()
        assert result.observed_context["driver_release"]["value"]
        # Markdown is readable presentation only, never an objective field.
        with pytest.raises(ValueError):
            corpus.resolve("report.md", "0" * 64, "/verdict")
