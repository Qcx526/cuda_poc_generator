"""SYNTHETIC offline Oracle rules. No real CVE or candidate is executed."""

from copy import deepcopy
import hashlib
import json

import pytest
from pydantic import ValidationError

from src.models.lifecycle import canonical_sha256
from src.models.oracle import (EvidenceReference, OraclePlan, OracleResult, SourceDocument,
                               TriggerCondition, VulnerabilityClaim, version_tuple)
from src.oracle import evaluate_oracle
from src.oracle_evidence import EvidenceCorpus


SYNTHETIC_CVE = "CVE-2099-0001"
SOURCE_ID = "synthetic-reviewed-test-rule-v1"


def synthetic_case():
    """Return explicitly SYNTHETIC plan/corpus; VERIFIED proves this test rule only."""
    binding = {
        "request_id": "a" * 32,
        "run_id": "b" * 32,
        "platform_environment_id": "sha256:" + "d" * 64,
        "platform_probe_id": "synthetic-probe-v1",
        "snapshot_sha256": "f" * 64,
        "candidate_sha256": "e" * 64,
        "tool_sha256": {"fixture": "c" * 64},
    }
    document = {
        "environment": {"version": "12.8.90"},
        "identity": {"candidate_sha256": binding["candidate_sha256"]},
        "entry": {"path": "SYNTHETIC_REVIEWED_ENTRY"},
        "anomaly": {"kind": "SYNTHETIC_BOUND_MEMORY_WRITE", "crashed": False,
                    "exit_code": 0, "sanitizer": "SYNTHETIC_SANITIZER_ERROR"},
        "root_cause": {"binding": "SYNTHETIC_ROOT_CAUSE_BOUND"},
        "fixed_version": {"difference_observed": True, "root_cause_bound": False},
        "scalars": {"integer": 1, "boolean": True, "float": 1.0, "string": "1"},
    }
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    corpus = EvidenceCorpus.from_synthetic(artifacts={"fixture.json": raw}, binding=binding,
                                           label="SYNTHETIC")
    definitions = [
        ("environment", "ENVIRONMENT", "PLATFORM", "/environment/version", "12.8.90"),
        ("identity", "IDENTITY", "IDENTITY", "/identity/candidate_sha256", binding["candidate_sha256"]),
        ("entry", "ENTRY_BEHAVIOR", "PROCESS", "/entry/path", "SYNTHETIC_REVIEWED_ENTRY"),
        ("anomaly", "ANOMALY", "PROCESS", "/anomaly/kind", "SYNTHETIC_BOUND_MEMORY_WRITE"),
        ("root_cause", "ROOT_CAUSE", "ROOT_CAUSE", "/root_cause/binding", "SYNTHETIC_ROOT_CAUSE_BOUND"),
    ]
    references, conditions = [], []
    for condition_id, category, evidence_type, pointer, expected in definitions:
        reference_id = condition_id + "-evidence"
        references.append({
            "reference_id": reference_id, "domain": "SYNTHETIC", "cve_id": SYNTHETIC_CVE,
            **{key: value for key, value in binding.items() if key != "tool_sha256"},
            "artifact_file": "fixture.json", "artifact_sha256": hashlib.sha256(raw).hexdigest(),
            "json_pointer": pointer, "original_source": "SYNTHETIC_FIXTURE",
            "tool_role": "fixture", "tool_sha256": binding["tool_sha256"]["fixture"],
            "collection_method": "p3a-synthetic-1.0", "scope": "SYNTHETIC",
            "evidence_type": evidence_type,
        })
        conditions.append({
            "condition_id": condition_id, "category": category, "predicate_type": "EQUALS",
            "subject": "synthetic." + condition_id, "expected_value": expected,
            "expected_relation": "EQUALS", "applicability": "APPLICABLE", "required": True,
            "requirement": {"evidence_type": evidence_type, "evidence_source": "SYNTHETIC",
                            "method": "SYNTHETIC_FACT", "scope": "SYNTHETIC",
                            "reference_ids": [reference_id]},
            "provenance": [SOURCE_ID],
        })
    plan = OraclePlan.model_validate({
        "oracle_id": "SYNTHETIC-five-category-oracle-v1", "cve_id": SYNTHETIC_CVE,
        "domain": "SYNTHETIC", "standard_id": "SYNTHETIC_ALL_REQUIRED_V1",
        "verification_standard": "SYNTHETIC: every necessary category must have bound exact-field evidence.",
        "review_reference": "SYNTHETIC_TEST_REVIEW_ONLY", "bindings": binding,
        "conditions": conditions, "references": references, "source_ids": [SOURCE_ID],
    })
    return plan, corpus


def _evaluate(plan, corpus, pin=True):
    return evaluate_oracle(plan, corpus, trusted_plan_sha256=canonical_sha256(plan) if pin else None)


def _plan_data(plan):
    return plan.model_dump(mode="python")


def _change_condition(plan, condition_id, **updates):
    data = _plan_data(plan)
    condition = next(x for x in data["conditions"] if x["condition_id"] == condition_id)
    condition.update(updates)
    return OraclePlan.model_validate(data)


def _change_reference(plan, reference_id, **updates):
    data = _plan_data(plan)
    reference = next(x for x in data["references"] if x["reference_id"] == reference_id)
    reference.update(updates)
    return OraclePlan.model_validate(data)


def _replace_document(plan, corpus, document):
    """A newly captured synthetic fixture with updated pins, not hidden log tampering."""
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    other = EvidenceCorpus.from_synthetic(artifacts={"fixture.json": raw}, binding=corpus.binding,
                                          label="SYNTHETIC")
    data = _plan_data(plan)
    for reference in data["references"]:
        reference["artifact_sha256"] = hashlib.sha256(raw).hexdigest()
    return OraclePlan.model_validate(data), other


def _evaluation(result, condition_id):
    return next(x for x in result.conditions if x.condition_id == condition_id)


def test_all_necessary_synthetic_conditions_prove_rules_not_real_cve():
    plan, corpus = synthetic_case()
    result = _evaluate(plan, corpus)
    assert result.domain == "SYNTHETIC"
    assert result.verdict == "VERIFIED"
    assert result.condition_status == "SATISFIED"
    assert result.eligibility.status == "ELIGIBLE"
    assert result.eligibility.execution_authorized is False
    assert result.real_cve_verification == "NOT_VERIFIED"
    assert len(result.conditions) == 5
    assert all(x.status == "SATISFIED" for x in result.conditions)
    assert "SYNTHETIC" in result.reasons[0]
    assert OracleResult.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize("condition_id", ["environment", "identity", "entry", "anomaly", "root_cause"])
def test_missing_necessary_evidence_cannot_verify(condition_id):
    plan, corpus = synthetic_case()
    condition = next(x for x in plan.conditions if x.condition_id == condition_id)
    requirement = condition.requirement.model_dump(mode="python")
    requirement["reference_ids"] = []
    result = _evaluate(_change_condition(plan, condition_id, requirement=requirement), corpus)
    assert _evaluation(result, condition_id).status == "UNKNOWN"
    assert result.verdict != "VERIFIED"
    assert result.real_cve_verification == "NOT_VERIFIED"


def test_wrong_target_cve_is_identity_conflict():
    plan, corpus = synthetic_case()
    data = _plan_data(plan)
    data["cve_id"] = "CVE-2099-0002"
    result = _evaluate(OraclePlan.model_validate(data), corpus)
    assert result.condition_status == "CONFLICT"
    assert result.verdict == "UNKNOWN"


def _numeric_plan(plan):
    data = _plan_data(plan)
    condition = data["conditions"][0]
    condition.update(predicate_type="NUMERIC_RANGE", expected_relation="GTE_LT", expected_value=None,
                     minimum_inclusive="12.8.0", maximum_exclusive="13.0.0")
    condition["requirement"]["method"] = "NUMERIC_VERSION"
    return OraclePlan.model_validate(data)


@pytest.mark.parametrize("version,expected", [("12.8.0", "SATISFIED"), ("12.8.90", "SATISFIED"),
                                                ("13.0.0", "NOT_SATISFIED"), ("12.7.99", "NOT_SATISFIED")])
def test_numeric_component_range_uses_actual_fixture_and_exclusive_upper_bound(version, expected):
    plan, corpus = synthetic_case()
    document = json.loads(corpus.artifacts["fixture.json"])
    document["environment"]["version"] = version
    plan, corpus = _replace_document(_numeric_plan(plan), corpus, document)
    result = _evaluate(plan, corpus)
    assert _evaluation(result, "environment").status == expected
    if expected == "NOT_SATISFIED":
        assert result.eligibility.status == "INELIGIBLE"
        assert result.verdict == "NOT_VERIFIED"
        assert "not a failed CVE reproduction" in result.reasons[0]


@pytest.mark.parametrize("value", ["12.6U1", "unknown", "", 12.8, True, None, "12.8; arbitrary"])
def test_non_numeric_observed_version_fails_closed(value):
    plan, corpus = synthetic_case()
    document = json.loads(corpus.artifacts["fixture.json"])
    document["environment"]["version"] = value
    plan, corpus = _replace_document(_numeric_plan(plan), corpus, document)
    result = _evaluate(plan, corpus)
    assert result.verdict == "UNKNOWN"
    assert _evaluation(result, "environment").status == "CONFLICT"


@pytest.mark.parametrize("field,replacement", [
    ("request_id", "1" * 32), ("run_id", "2" * 32),
    ("platform_environment_id", "sha256:" + "3" * 64),
    ("platform_probe_id", "another-probe"), ("snapshot_sha256", "4" * 64),
    ("candidate_sha256", "5" * 64),
])
def test_cross_run_platform_input_and_snapshot_conflicts_are_blocked(field, replacement):
    plan, corpus = synthetic_case()
    data = _plan_data(plan)
    data["bindings"][field] = replacement
    result = _evaluate(OraclePlan.model_validate(data), corpus)
    assert result.verdict == "UNKNOWN"
    assert result.condition_status == "CONFLICT"
    assert all(x.status == "CONFLICT" for x in result.conditions)


@pytest.mark.parametrize("field,replacement", [
    ("request_id", "1" * 32), ("run_id", "2" * 32),
    ("platform_environment_id", "sha256:" + "3" * 64),
    ("platform_probe_id", "another-probe"), ("snapshot_sha256", "4" * 64),
    ("candidate_sha256", "5" * 64), ("tool_sha256", "6" * 64),
    ("tool_role", "different-tool"), ("cve_id", "CVE-2099-0002"),
])
def test_reference_identity_conflicts_are_blocked(field, replacement):
    plan, corpus = synthetic_case()
    plan = _change_reference(plan, "root_cause-evidence", **{field: replacement})
    result = _evaluate(plan, corpus)
    assert _evaluation(result, "root_cause").status == "CONFLICT"
    assert result.verdict == "UNKNOWN"


def test_plan_tool_binding_change_is_conflict():
    plan, corpus = synthetic_case()
    data = _plan_data(plan)
    data["bindings"]["tool_sha256"]["fixture"] = "9" * 64
    result = _evaluate(OraclePlan.model_validate(data), corpus)
    assert result.condition_status == "CONFLICT"
    assert result.verdict == "UNKNOWN"


@pytest.mark.parametrize("replacement", [None, {}, [], "fixture", {"fixture": True},
                                         {"fixture": "c" * 64, "unreviewed": "9" * 64}])
def test_missing_malformed_or_extra_plan_tool_binding_is_conflict(replacement):
    plan, corpus = synthetic_case()
    data = _plan_data(plan)
    data["bindings"]["tool_sha256"] = replacement
    result = _evaluate(OraclePlan.model_validate(data), corpus)
    assert result.condition_status == "CONFLICT"
    assert result.verdict == "UNKNOWN"


@pytest.mark.parametrize("field,replacement", [
    ("original_source", "REPLACEMENT_LLM_SUMMARY"),
    ("collection_method", "unreviewed-collector"),
    ("artifact_sha256", "7" * 64),
    ("artifact_file", "replacement.json"),
    ("scope", "CVE_TRIGGER"),
    ("evidence_type", "PROCESS"),
    ("domain", "OBJECTIVE"),
])
def test_replaced_source_method_scope_type_or_artifact_is_not_qualified(field, replacement):
    plan, corpus = synthetic_case()
    plan = _change_reference(plan, "root_cause-evidence", **{field: replacement})
    result = _evaluate(plan, corpus)
    assert _evaluation(result, "root_cause").status == "CONFLICT"
    assert result.verdict == "UNKNOWN"


@pytest.mark.parametrize("pointer,expected", [("/anomaly/crashed", False), ("/anomaly/exit_code", 0),
                                                ("/anomaly/sanitizer", "SYNTHETIC_SANITIZER_ERROR")])
def test_crash_exit_zero_or_sanitizer_observation_cannot_replace_root_cause(pointer, expected):
    plan, corpus = synthetic_case()
    plan = _change_reference(plan, "anomaly-evidence", json_pointer=pointer)
    plan = _change_condition(plan, "anomaly", expected_value=expected)
    missing = plan.conditions[-1].requirement.model_dump(mode="python")
    missing["reference_ids"] = []
    plan = _change_condition(plan, "root_cause", requirement=missing)
    result = _evaluate(plan, corpus)
    assert _evaluation(result, "anomaly").status == "SATISFIED"
    assert _evaluation(result, "root_cause").status == "UNKNOWN"
    assert result.verdict == "SUPPORTED"
    assert result.real_cve_verification == "NOT_VERIFIED"


def test_actual_crash_observation_without_root_binding_is_only_supported():
    plan, corpus = synthetic_case()
    document = json.loads(corpus.artifacts["fixture.json"])
    document["anomaly"].update(crashed=True, exit_code=-11)
    plan, corpus = _replace_document(plan, corpus, document)
    plan = _change_reference(plan, "anomaly-evidence", json_pointer="/anomaly/crashed")
    plan = _change_condition(plan, "anomaly", expected_value=True)
    plan = _change_condition(plan, "root_cause", predicate_type="UNIMPLEMENTED", expected_relation="UNKNOWN")
    result = _evaluate(plan, corpus)
    assert result.verdict == "SUPPORTED"
    assert result.condition_status == "UNKNOWN"
    assert result.real_cve_verification == "NOT_VERIFIED"


def test_contradictory_necessary_predicates_cannot_hide_under_different_ids():
    plan, corpus = synthetic_case()
    data = _plan_data(plan)
    duplicate = deepcopy(data["conditions"][-1])
    duplicate.update(condition_id="contradictory_root", expected_value="SYNTHETIC_DIFFERENT_ROOT")
    data["conditions"].append(duplicate)
    result = _evaluate(OraclePlan.model_validate(data), corpus)
    assert _evaluation(result, "root_cause").status == "CONFLICT"
    assert _evaluation(result, "contradictory_root").status == "CONFLICT"
    assert result.verdict == "UNKNOWN"


def test_conflicting_optional_evidence_also_fails_closed():
    plan, corpus = synthetic_case()
    data = _plan_data(plan)
    optional = deepcopy(data["conditions"][-1])
    optional.update(condition_id="optional_root", subject="synthetic.optional_root", required=False)
    optional["requirement"]["reference_ids"] = ["optional-evidence"]
    reference = deepcopy(data["references"][-1])
    reference.update(reference_id="optional-evidence", original_source="REPLACEMENT")
    data["conditions"].append(optional)
    data["references"].append(reference)
    result = _evaluate(OraclePlan.model_validate(data), corpus)
    assert _evaluation(result, "optional_root").status == "CONFLICT"
    assert result.verdict == "UNKNOWN"
    assert result.condition_status == "CONFLICT"


def test_fixed_build_difference_without_root_cause_binding_is_insufficient():
    plan, corpus = synthetic_case()
    plan = _change_reference(plan, "anomaly-evidence", json_pointer="/fixed_version/difference_observed")
    plan = _change_condition(plan, "anomaly", expected_value=True)
    plan = _change_reference(plan, "root_cause-evidence", json_pointer="/fixed_version/root_cause_bound",
                             evidence_type="DIFFERENTIAL")
    requirement = plan.conditions[-1].requirement.model_dump(mode="python")
    requirement["evidence_type"] = "DIFFERENTIAL"
    plan = _change_condition(plan, "root_cause", expected_value=True, requirement=requirement)
    result = _evaluate(plan, corpus)
    assert _evaluation(result, "anomaly").status == "SATISFIED"
    assert _evaluation(result, "root_cause").status == "NOT_SATISFIED"
    assert result.verdict == "NOT_VERIFIED"


@pytest.mark.parametrize("applicability", ["UNKNOWN", "NOT_APPLICABLE"])
def test_required_nonapplicable_condition_is_never_waived(applicability):
    plan, corpus = synthetic_case()
    result = _evaluate(_change_condition(plan, "root_cause", applicability=applicability), corpus)
    assert _evaluation(result, "root_cause").status == "UNKNOWN"
    assert result.verdict != "VERIFIED"


@pytest.mark.parametrize("pin", [None, "0" * 64])
def test_untrusted_or_missing_plan_pin_fails_closed(pin):
    plan, corpus = synthetic_case()
    result = evaluate_oracle(plan, corpus, trusted_plan_sha256=pin)
    assert result.verdict == "UNKNOWN"
    assert result.condition_status == "CONFLICT"


def test_changed_reviewed_plan_cannot_reuse_old_pin():
    plan, corpus = synthetic_case()
    original_pin = canonical_sha256(plan)
    changed = _change_condition(plan, "root_cause", required=False)
    result = evaluate_oracle(changed, corpus, trusted_plan_sha256=original_pin)
    assert result.verdict == "UNKNOWN"
    assert result.condition_status == "CONFLICT"


def test_unimplemented_required_method_is_not_success():
    plan, corpus = synthetic_case()
    requirement = plan.conditions[-1].requirement.model_dump(mode="python")
    requirement["method"] = "UNIMPLEMENTED"
    result = _evaluate(_change_condition(plan, "root_cause", requirement=requirement), corpus)
    assert _evaluation(result, "root_cause").status == "UNKNOWN"
    assert result.verdict != "VERIFIED"


@pytest.mark.parametrize("expected,observed_pointer", [(1, "/scalars/boolean"), (True, "/scalars/integer"),
                                                        (1, "/scalars/float"), (1, "/scalars/string")])
def test_typed_equality_does_not_coerce_bool_integer_float_or_string(expected, observed_pointer):
    plan, corpus = synthetic_case()
    plan = _change_reference(plan, "root_cause-evidence", json_pointer=observed_pointer)
    result = _evaluate(_change_condition(plan, "root_cause", expected_value=expected), corpus)
    assert _evaluation(result, "root_cause").status == "NOT_SATISFIED"
    assert result.verdict == "NOT_VERIFIED"


def test_reference_observations_disagreeing_for_same_predicate_are_conflict():
    plan, corpus = synthetic_case()
    data = _plan_data(plan)
    second = deepcopy(data["references"][-1])
    second.update(reference_id="different-root-observation", json_pointer="/entry/path")
    data["references"].append(second)
    data["conditions"][-1]["requirement"]["reference_ids"].append(second["reference_id"])
    result = _evaluate(OraclePlan.model_validate(data), corpus)
    assert _evaluation(result, "root_cause").status == "CONFLICT"
    assert result.verdict == "UNKNOWN"


def test_valid_first_reference_cannot_hide_invalid_later_source():
    plan, corpus = synthetic_case()
    data = _plan_data(plan)
    second = deepcopy(data["references"][-1])
    second.update(reference_id="replaced-later-source", artifact_sha256="8" * 64)
    data["references"].append(second)
    data["conditions"][-1]["requirement"]["reference_ids"].append(second["reference_id"])
    result = _evaluate(OraclePlan.model_validate(data), corpus)
    root = _evaluation(result, "root_cause")
    assert root.reference_ids == ["root_cause-evidence"]
    assert root.observed_values == ["SYNTHETIC_ROOT_CAUSE_BOUND"]
    assert root.status == "CONFLICT"
    assert result.condition_status == "CONFLICT"
    assert result.verdict == "UNKNOWN"


def test_omitted_necessary_category_cannot_create_verified():
    plan, corpus = synthetic_case()
    data = _plan_data(plan)
    data["conditions"] = data["conditions"][:-1]
    result = _evaluate(OraclePlan.model_validate(data), corpus)
    assert result.condition_status == "SATISFIED"
    assert result.verdict == "SUPPORTED"
    assert any("ROOT_CAUSE" in x for x in result.reasons)


def test_no_environment_prerequisite_leaves_eligibility_unknown():
    plan, corpus = synthetic_case()
    data = _plan_data(plan)
    data["conditions"] = data["conditions"][1:]
    result = _evaluate(OraclePlan.model_validate(data), corpus)
    assert result.eligibility.status == "UNKNOWN"
    assert result.verdict == "UNKNOWN"


def test_incomplete_capture_does_not_verify_any_required_condition():
    plan, corpus = synthetic_case()
    from dataclasses import replace
    incomplete = replace(corpus, qualified=False, diagnostics=("SYNTHETIC_CAPTURE_INCOMPLETE",))
    result = _evaluate(plan, incomplete)
    assert all(x.status == "UNKNOWN" for x in result.conditions)
    assert result.verdict == "UNKNOWN"


def test_necessary_capture_quality_cannot_be_waived_to_manufacture_verified():
    from dataclasses import replace
    plan, corpus = synthetic_case()
    incomplete = replace(corpus, qualified=False, diagnostics=("SYNTHETIC_CAPTURE_INCOMPLETE",))
    data = _plan_data(plan)
    for condition in data["conditions"]:
        condition["requirement"]["completeness_required"] = False
    result = _evaluate(OraclePlan.model_validate(data), incomplete)
    assert result.verdict != "VERIFIED"
    assert all(x.status != "SATISFIED" for x in result.conditions)


@pytest.mark.parametrize("field,value", [("required", "true"), ("required", 1),
                                         ("expected_value", []), ("expected_value", {}),
                                         ("expected_value", None), ("expected_value", "   ")])
def test_invalid_condition_types_and_empty_values_are_rejected(field, value):
    plan, _ = synthetic_case()
    data = plan.conditions[-1].model_dump(mode="python")
    data[field] = value
    with pytest.raises(ValidationError):
        TriggerCondition.model_validate(data)


@pytest.mark.parametrize("level", ["plan", "condition", "requirement", "reference"])
def test_unknown_contract_fields_are_rejected(level):
    plan, _ = synthetic_case()
    data = _plan_data(plan)
    target = {"plan": data, "condition": data["conditions"][0],
              "requirement": data["conditions"][0]["requirement"],
              "reference": data["references"][0]}[level]
    target["llm_verified"] = True
    with pytest.raises(ValidationError):
        OraclePlan.model_validate(data)


@pytest.mark.parametrize("mutation", ["required", "completeness", "reference_hash"])
def test_model_copy_cannot_launder_invalid_nested_types(mutation):
    plan, corpus = synthetic_case()
    if mutation == "required":
        condition = plan.conditions[-1].model_copy(update={"required": "true"})
        changed = plan.model_copy(update={"conditions": [*plan.conditions[:-1], condition]})
    elif mutation == "completeness":
        requirement = plan.conditions[-1].requirement.model_copy(update={"completeness_required": 1})
        condition = plan.conditions[-1].model_copy(update={"requirement": requirement})
        changed = plan.model_copy(update={"conditions": [*plan.conditions[:-1], condition]})
    else:
        reference = plan.references[-1].model_copy(update={"artifact_sha256": 123})
        changed = plan.model_copy(update={"references": [*plan.references[:-1], reference]})
    with pytest.warns(UserWarning, match="Pydantic serializer warnings"), pytest.raises(ValidationError):
        evaluate_oracle(changed, corpus, trusted_plan_sha256=canonical_sha256(plan))


def test_duplicate_or_unbound_ids_and_provenance_are_rejected():
    plan, _ = synthetic_case()
    mutations = []
    duplicate_condition = _plan_data(plan)
    duplicate_condition["conditions"].append(deepcopy(duplicate_condition["conditions"][0]))
    mutations.append(duplicate_condition)
    duplicate_reference = _plan_data(plan)
    duplicate_reference["references"].append(deepcopy(duplicate_reference["references"][0]))
    mutations.append(duplicate_reference)
    bad_source = _plan_data(plan)
    bad_source["conditions"][0]["provenance"] = ["LLM_UNREVIEWED_SOURCE"]
    mutations.append(bad_source)
    missing_reference = _plan_data(plan)
    missing_reference["conditions"][0]["requirement"]["reference_ids"] = ["unbound-reference"]
    mutations.append(missing_reference)
    for data in mutations:
        with pytest.raises(ValidationError):
            OraclePlan.model_validate(data)


@pytest.mark.parametrize("lower,upper", [("12.6U1", "13.0"), ("13.0", "12.8"),
                                         ("12.8", "12.8.0.0"), (None, "13.0")])
def test_unsupported_or_empty_version_ranges_are_rejected(lower, upper):
    plan, _ = synthetic_case()
    data = _plan_data(_numeric_plan(plan))
    data["conditions"][0].update(minimum_inclusive=lower, maximum_exclusive=upper)
    with pytest.raises(ValidationError):
        OraclePlan.model_validate(data)


def _claim_data(kind="LLM_REASONING", support="ASSERTED"):
    return {
        "cve_id": SYNTHETIC_CVE, "cwe": ["CWE-122"], "vulnerability_type": "SYNTHETIC_ONLY",
        "affected_component": "SYNTHETIC_FIXTURE", "affected_version_ranges": ["SYNTHETIC_RANGE"],
        "version_scheme": "UNKNOWN", "entry": "SYNTHETIC_ENTRY", "controlled_input": "SYNTHETIC_INPUT",
        "prerequisites": [], "trigger_mechanism": "SYNTHETIC_UNVERIFIED_ASSERTION",
        "expected_objective_behavior": "SYNTHETIC_UNVERIFIED_BEHAVIOR", "fixed_versions": [],
        "sources": [{"source_id": "llm-source", "kind": kind, "url": "synthetic://untrusted-assertion",
                     "retrieved_at": "2026-10-16", "support": support, "locator": "/synthetic/claim"}],
        "unknowns": ["SYNTHETIC: no objective experiment"], "fact_status": "UNREVIEWED",
    }


@pytest.mark.parametrize("kind", ["LLM_REASONING", "USER_ASSERTION", "SYNTHETIC"])
def test_llm_user_and_synthetic_claims_cannot_establish_documented_cve_fact(kind):
    data = _claim_data(kind, "DOCUMENTED")
    data["fact_status"] = "DOCUMENTED_NOT_REPRODUCED"
    with pytest.raises(ValidationError):
        VulnerabilityClaim.model_validate(data)
    data["fact_status"] = "UNREVIEWED"
    claim = VulnerabilityClaim.model_validate(data)
    assert claim.fact_status == "UNREVIEWED"


def test_no_objective_verified_standard_can_be_asserted_by_json():
    plan, _ = synthetic_case()
    data = _plan_data(plan)
    data["domain"] = "OBJECTIVE"
    with pytest.raises(ValidationError):
        OraclePlan.model_validate(data)
    result = _evaluate(*synthetic_case()).model_dump(mode="python")
    result["domain"] = "OBJECTIVE"
    with pytest.raises(ValidationError):
        OracleResult.model_validate(result)


def test_verdict_and_real_cve_status_are_distinct_contract_fields():
    result = _evaluate(*synthetic_case()).model_dump(mode="python")
    result["real_cve_verification"] = "VERIFIED"
    with pytest.raises(ValidationError):
        OracleResult.model_validate(result)


def test_version_tuple_padding_is_explicit_and_never_parses_vendor_update_labels():
    assert version_tuple("12.8") == version_tuple("12.8.0.0")
    assert version_tuple("12.8.90") < version_tuple("13.0")
    for value in ("12.6U1", "CUDA 12.8", "12", "12.8.1.2.3", True):
        with pytest.raises(ValueError):
            version_tuple(value)


def test_model_reference_rejects_markdown_and_unbound_fragment_metadata():
    plan, _ = synthetic_case()
    data = plan.references[0].model_dump(mode="python")
    data["artifact_file"] = "report.md"
    with pytest.raises(ValidationError):
        EvidenceReference.model_validate(data)
    data["artifact_file"] = "fixture.json"
    data["json_pointer"] = "LLM says a CVE was verified"
    with pytest.raises(ValidationError):
        EvidenceReference.model_validate(data)


def test_source_document_disallows_fabricated_support_and_bad_hash():
    source = _claim_data()["sources"][0]
    source["support"] = "VERIFIED_BY_LLM"
    with pytest.raises(ValidationError):
        SourceDocument.model_validate(source)
    source["support"] = "ASSERTED"
    source["content_sha256"] = "not-a-sha256"
    with pytest.raises(ValidationError):
        SourceDocument.model_validate(source)
