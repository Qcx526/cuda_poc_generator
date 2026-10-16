"""SYNTHETIC offline report checks. No tool, network or CVE execution."""

import hashlib
from html import unescape
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.models.lifecycle import canonical_sha256
from src.models.oracle import (ConditionEvaluation, CVEEligibility, EvidenceReference,
                               EvidenceRequirement, OraclePlan, OracleResult, SourceDocument,
                               TriggerCondition, VulnerabilityClaim)
from src import oracle_report as reports


def report_inputs(*, observed="12.8.90", target="CVE-2099-9999"):
    reference = EvidenceReference(
        reference_id="synthetic-evidence", domain="SYNTHETIC", cve_id=target,
        request_id="1" * 32, run_id="2" * 32,
        artifact_file="synthetic_process.json", artifact_sha256="3" * 64,
        json_pointer="/tools/cuobjdump/version", original_source="SYNTHETIC fixture only",
        platform_environment_id="sha256:" + "4" * 64, platform_probe_id="synthetic-probe",
        snapshot_sha256="5" * 64, candidate_sha256="6" * 64, tool_role="cuobjdump",
        tool_sha256="7" * 64, collection_method="SYNTHETIC test collector",
        scope="SYNTHETIC", evidence_type="PLATFORM",
    )
    condition = TriggerCondition(
        condition_id="synthetic-version", category="ENVIRONMENT", predicate_type="EQUALS",
        subject="SYNTHETIC cuobjdump version", expected_value="12.8.90", expected_relation="EQUALS",
        applicability="APPLICABLE", required=True,
        requirement=EvidenceRequirement(
            evidence_type="PLATFORM", evidence_source="SYNTHETIC", method="SYNTHETIC_FACT",
            scope="SYNTHETIC", reference_ids=[reference.reference_id]),
        provenance=["synthetic-source"],
    )
    plan = OraclePlan(
        oracle_id="synthetic-report-only-v1", cve_id=target, domain="SYNTHETIC",
        standard_id="SYNTHETIC_ALL_REQUIRED_V1", verification_standard="All synthetic required conditions",
        review_reference="SYNTHETIC unit test policy", bindings={"platform": "SYNTHETIC WSL fixture"},
        conditions=[condition], references=[reference], source_ids=["synthetic-source"],
    )
    result = OracleResult(
        oracle_id=plan.oracle_id, cve_id=target, domain="SYNTHETIC", plan_sha256=canonical_sha256(plan),
        eligibility=CVEEligibility(cve_id=target, status="ELIGIBLE", reasons=["SYNTHETIC version match"]),
        conditions=[ConditionEvaluation(condition_id=condition.condition_id, status="SATISFIED",
                                        reason="SYNTHETIC equality", reference_ids=[reference.reference_id],
                                        observed_values=[observed])],
        condition_status="SATISFIED", verdict="VERIFIED",
        reasons=["All required synthetic rule conditions satisfied"],
        limitations=["SYNTHETIC proof only; no real CVE reproduction"],
    )
    claim = VulnerabilityClaim(
        cve_id=target, cwe=["CWE-125"], vulnerability_type="SYNTHETIC test class",
        affected_component="SYNTHETIC component", affected_version_ranges=["SYNTHETIC version range"],
        version_scheme="UNKNOWN", entry="SYNTHETIC entry", controlled_input="SYNTHETIC input",
        prerequisites=["SYNTHETIC only"], trigger_mechanism="SYNTHETIC mechanism",
        expected_objective_behavior="SYNTHETIC behavior", fixed_versions=[],
        sources=[SourceDocument(source_id="synthetic-source", kind="SYNTHETIC", url="synthetic://fixture",
                                retrieved_at="2026-10-16", support="ASSERTED", locator="/synthetic")],
        unknowns=["No real affected component or root-cause evidence"], fact_status="UNREVIEWED",
    )
    return plan, result, claim


def replace_plan(plan, result, **values):
    revised = OraclePlan.model_validate({**plan.model_dump(mode="python"), **values})
    result = OracleResult.model_validate({**result.model_dump(mode="python"),
                                         "plan_sha256": canonical_sha256(revised)})
    return revised, result


def test_render_is_deterministic_bound_and_nonmutating():
    plan, result, claim = report_inputs()
    before = [item.model_dump(mode="python") for item in (plan, result, claim)]
    report = reports.render_oracle_report(plan, result, claim)
    assert report == reports.render_oracle_report(plan, result, claim)
    assert before == [item.model_dump(mode="python") for item in (plan, result, claim)]
    displayed = unescape(report)
    for text in ["SYNTHETIC", "NOT_VERIFIED", "12.8.90", "synthetic_process.json",
                 "3" * 64, "7" * 64, "/tools/cuobjdump/version", "synthetic-probe"]:
        assert text in displayed
    assert "proves only the synthetic Oracle rules" in report
    assert "not a signature" in report


def test_observed_context_versions_keep_exact_source_references():
    plan, result, _ = report_inputs()
    context = {"driver_release": {"value": "SYNTHETIC 999.1", "artifact_file": "platform_snapshot.json",
                                  "artifact_sha256": "a" * 64, "json_pointer": "/driver_release"},
               "tool_versions": {"cuobjdump": "SYNTHETIC 12.8.90"}}
    modified = result.model_copy(update={"observed_context": context})
    report = unescape(reports.render_oracle_report(plan, modified))
    for text in ["SYNTHETIC 999.1", "platform_snapshot.json", "a" * 64, "/driver_release"]:
        assert text in report


def test_report_escapes_markdown_html_controls_and_bidi():
    unsafe = '<script>bad</script>\n|x|`code`\u202e**VERIFIED**'
    plan, result, claim = report_inputs(observed=unsafe)
    report = reports.render_oracle_report(plan, result, claim)
    assert unsafe not in report
    assert "<script>" not in report
    assert "\u202e" not in report
    assert "&#60;script&#62;" in report
    assert "&#92;n" in report
    assert "&#124;x&#124;" in report
    assert "&#96;code&#96;" in report
    assert "&#92;u202e" in report


@pytest.mark.parametrize("change", [
    {"plan_sha256": "0" * 64}, {"cve_id": "CVE-2099-9998"},
    {"oracle_id": "some-other-oracle"}, {"domain": "OBJECTIVE", "verdict": "NOT_VERIFIED"},
    {"conditions": []},
])
def test_render_rejects_result_association_changes(change):
    plan, result, claim = report_inputs()
    modified = result.model_copy(update=change)
    with pytest.raises((ValueError, ValidationError)):
        reports.render_oracle_report(plan, modified, claim)


def test_duplicate_condition_evaluations_rejected():
    plan, result, _ = report_inputs()
    modified = result.model_copy(update={"conditions": result.conditions * 2})
    with pytest.raises(ValueError, match="condition IDs"):
        reports.render_oracle_report(plan, modified)


def test_unbound_result_evidence_rejected():
    plan, result, _ = report_inputs()
    evaluation = result.conditions[0].model_copy(update={"reference_ids": ["unbound"]})
    with pytest.raises(ValueError, match="unbound evidence"):
        reports.render_oracle_report(plan, result.model_copy(update={"conditions": [evaluation]}))


def test_eligibility_target_mismatch_rejected():
    plan, result, _ = report_inputs()
    wrong = result.eligibility.model_copy(update={"cve_id": "CVE-2099-9998"})
    with pytest.raises(ValueError, match="eligibility target"):
        reports.render_oracle_report(plan, result.model_copy(update={"eligibility": wrong}))


def test_claim_target_and_source_mismatch_rejected():
    plan, result, claim = report_inputs()
    with pytest.raises(ValueError, match="claim target"):
        reports.render_oracle_report(plan, result, claim.model_copy(update={"cve_id": "CVE-2099-9998"}))
    source = claim.sources[0].model_copy(update={"source_id": "different-source"})
    with pytest.raises(ValueError, match="sources are absent"):
        reports.render_oracle_report(plan, result, claim.model_copy(update={"sources": [source]}))


def test_explicit_claim_digest_checked():
    plan, result, claim = report_inputs()
    plan, result = replace_plan(plan, result, bindings={"claim_sha256": canonical_sha256(claim)})
    assert "SYNTHETIC" in reports.render_oracle_report(plan, result, claim)
    changed = claim.model_copy(update={"unknowns": ["Different unknown"]})
    with pytest.raises(ValueError, match="claim digest"):
        reports.render_oracle_report(plan, result, changed)


def test_verified_cannot_hide_unknown_necessary_condition():
    plan, result, _ = report_inputs()
    evaluation = result.conditions[0].model_copy(update={"status": "UNKNOWN"})
    with pytest.raises(ValueError, match="all necessary"):
        reports.render_oracle_report(plan, result.model_copy(update={"conditions": [evaluation]}))


@pytest.mark.parametrize("with_claim", [False, True])
def test_bundle_roundtrip_offline(tmp_path, with_claim):
    plan, result, claim = report_inputs()
    claim = claim if with_claim else None
    folder = reports.save_oracle_report(tmp_path / "new-run", plan, result, claim)
    assert reports.rebuild_oracle_report(folder) == reports.render_oracle_report(plan, result, claim)
    manifest = json.loads((folder / "oracle_manifest.json").read_text(encoding="utf-8"))
    for item in manifest["artifacts"]:
        raw = (folder / item["filename"]).read_bytes()
        assert len(raw) == item["size_bytes"]
        assert hashlib.sha256(raw).hexdigest() == item["sha256"]
    assert manifest["integrity_scope"] == "UNSIGNED_LOCAL_BYTE_INDEX"


def test_existing_directory_is_not_overwritten(tmp_path):
    plan, result, claim = report_inputs()
    folder = reports.save_oracle_report(tmp_path / "old", plan, result, claim)
    original = {path.name: path.read_bytes() for path in folder.iterdir()}
    with pytest.raises(FileExistsError):
        reports.save_oracle_report(folder, plan, result, claim)
    assert original == {path.name: path.read_bytes() for path in folder.iterdir()}


@pytest.mark.parametrize("filename", ["plan.json", "result.json", "claim.json", "report.md"])
def test_artifact_tampering_rejected(tmp_path, filename):
    plan, result, claim = report_inputs()
    folder = reports.save_oracle_report(tmp_path / "run", plan, result, claim)
    path = folder / filename
    path.write_bytes(path.read_bytes() + b"tampered")
    with pytest.raises(ValueError, match="hash/length"):
        reports.rebuild_oracle_report(folder)


def test_edited_report_rejected_even_if_manifest_digest_was_updated(tmp_path):
    plan, result, claim = report_inputs()
    folder = reports.save_oracle_report(tmp_path / "run", plan, result, claim)
    report = folder / "report.md"
    raw = report.read_bytes().replace(b"NOT_VERIFIED", b"VERIFIED")
    report.write_bytes(raw)
    manifest_path = folder / "oracle_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for item in manifest["artifacts"]:
        if item["filename"] == "report.md":
            item.update(size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="deterministic Oracle rendering"):
        reports.rebuild_oracle_report(folder)


@pytest.mark.parametrize("mode", ["extra-file", "missing-file", "duplicate-key", "wrong-target"])
def test_bundle_structural_confusion_rejected(tmp_path, mode):
    plan, result, claim = report_inputs()
    folder = reports.save_oracle_report(tmp_path / "run", plan, result, claim)
    manifest = folder / "oracle_manifest.json"
    if mode == "extra-file":
        (folder / "other.json").write_text("{}", encoding="utf-8")
    elif mode == "missing-file":
        (folder / "report.md").unlink()
    elif mode == "duplicate-key":
        raw = manifest.read_text(encoding="utf-8")
        manifest.write_text('{"domain":"SYNTHETIC",' + raw[1:], encoding="utf-8")
    else:
        value = json.loads(manifest.read_text(encoding="utf-8"))
        value["cve_id"] = "CVE-2099-9998"
        manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError):
        reports.rebuild_oracle_report(folder)


def test_path_traversal_rejected(tmp_path):
    plan, result, claim = report_inputs()
    with pytest.raises(ValueError, match="traversal"):
        reports.save_oracle_report(tmp_path / "child" / ".." / "run", plan, result, claim)


def make_symlink(link, target, *, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip("Host does not permit creating the test symlink: " + str(exc))


def test_symlink_ancestor_rejected(tmp_path):
    plan, result, claim = report_inputs()
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "linked"
    make_symlink(link, real, directory=True)
    with pytest.raises(ValueError, match="symlink/reparse"):
        reports.save_oracle_report(link / "run", plan, result, claim)


def test_symlink_artifact_rejected(tmp_path):
    plan, result, claim = report_inputs()
    folder = reports.save_oracle_report(tmp_path / "run", plan, result, claim)
    result_path = folder / "result.json"
    external = tmp_path / "external-result.json"
    external.write_bytes(result_path.read_bytes())
    result_path.unlink()
    make_symlink(result_path, external)
    with pytest.raises(ValueError, match="symlink/reparse"):
        reports.rebuild_oracle_report(folder)


def test_bounded_read_rejected(tmp_path, monkeypatch):
    plan, result, claim = report_inputs()
    folder = reports.save_oracle_report(tmp_path / "run", plan, result, claim)
    monkeypatch.setattr(reports, "MAX_JSON_BYTES", 1)
    with pytest.raises(ValueError, match="bounded regular"):
        reports.rebuild_oracle_report(folder)


def test_partial_write_cannot_publish_complete_manifest(tmp_path, monkeypatch):
    plan, result, claim = report_inputs()
    original = reports._exclusive_write

    def fail(path, raw):
        if Path(path).name == "result.json":
            raise OSError("SYNTHETIC disk full")
        original(path, raw)

    monkeypatch.setattr(reports, "_exclusive_write", fail)
    folder = tmp_path / "partial"
    with pytest.raises(OSError, match="disk full"):
        reports.save_oracle_report(folder, plan, result, claim)
    assert folder.exists()
    assert not (folder / "oracle_manifest.json").exists()
    with pytest.raises(OSError):
        reports.rebuild_oracle_report(folder)
