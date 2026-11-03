# -*- coding: utf-8 -*-
"""Driver outcome classification and analysis coercion.

The classifier decides what the next round should do, so a wrong state is not a
cosmetic problem: calling a failed Win32 call a "driver rejection" sends the model
to rewrite parameter values when the call never reached the driver.
"""

import json

from src import driver_outcome as outcome
from src.driver_analyst import DriverAnalysis, _as_bool


def _line(payload: dict) -> str:
    return "noise\nCPG_RESULT " + json.dumps(payload, ensure_ascii=False)


def test_a_bugcheck_outranks_anything_the_candidate_printed():
    result = outcome.classify(
        returncode=0, output=_line({"stage": "escape", "status": 0, "reached": True}),
        bugcheck={"code": "0x0000007e"})
    assert result.state == outcome.KERNEL_BUGCHECK


def test_timeout_is_reported_before_parsing_output():
    result = outcome.classify(returncode=None, output="", timed_out=True)
    assert result.state == outcome.TIMEOUT


def test_a_win32_null_return_is_a_call_failure_not_a_driver_rejection():
    """CreateDCW returning NULL says nothing about the driver."""
    result = outcome.classify(returncode=0, output=_line(
        {"stage": "open", "status": -1, "reached": False,
         "calls": [{"api": "CreateDCW", "status": -1}]}))
    assert result.state == outcome.API_CALL_FAILED
    assert "CreateDCW" in result.reason


def test_access_denied_stays_unattributed():
    """The layer is unknown, so the reason must not name Nvidia or Windows."""
    result = outcome.classify(returncode=0, output=_line(
        {"stage": "escape", "status": -1073741790, "reached": False, "calls": []}))
    assert result.state == outcome.API_REJECTED
    assert "层级未定" in result.reason


def test_missing_result_line_is_not_silently_treated_as_success():
    result = outcome.classify(returncode=0, output="nothing useful here")
    assert result.state == outcome.TARGET_NOT_REACHED


def test_a_faulting_candidate_is_distinguished_from_a_clean_negative():
    result = outcome.classify(returncode=-1073741819, output="")
    assert result.state == outcome.USERMODE_FAULT


def test_a_contradicted_reached_claim_is_not_reached():
    """Saying "reached" while the same call returned an error is a claim, not arrival."""
    result = outcome.classify(returncode=0, output=_line(
        {"stage": "escape", "status": -1073741811, "reached": True,
         "calls": [{"api": "D3DKMTEscape", "status": -1073741811}]}))
    assert result.state == outcome.INPUT_REJECTED


def test_a_claim_alone_never_stands():
    """A candidate saying "reached" with a clean status is still just a claim."""
    result = outcome.classify(returncode=0, output=_line(
        {"stage": "escape", "status": 0, "reached": True}))
    assert result.state == outcome.TARGET_NOT_REACHED
    assert "外部命中" in result.reason


def test_a_candidates_own_evidence_is_not_evidence():
    """`evidence` inside CPG_RESULT is written by the candidate, not an observer."""
    result = outcome.classify(returncode=0, output=_line(
        {"stage": "target", "status": 0xC000000D, "reached": True,
         "evidence": {"probe": "nvgpucomp64+0x12A3560"}}))
    assert result.state == outcome.TARGET_NOT_REACHED


def test_an_external_hit_is_what_promotes_to_reached():
    result = outcome.classify(
        returncode=0,
        output=_line({"stage": "escape", "status": 0xC000000D, "reached": False}),
        external_evidence=[{"producer": "cdb_trace", "hit": True,
                            "where": "nvlddmkm+0x1406912f0"}])
    assert result.state == outcome.TARGET_REACHED
    assert "cdb_trace" in result.reason


def test_every_state_carries_a_next_move():
    for state in outcome.ALL_STATES:
        assert outcome.NEXT_MOVE[state]


def test_analysis_accepts_the_shapes_models_actually_produce():
    """Prose where a bool was asked for must not discard a finished analysis."""
    payload = {
        "vulnerability_primitive": {"kind": "authz"},
        "affected_component": "nvlddmkm",
        "candidate_entry_points": {"name": "escape", "api": "D3DKMTEscape"},
        "required_api_sequence": "CreateDevice -> Escape",
        "object_lifecycle": ["create", "escape", "destroy"],
        "input_structure_hypotheses": {
            "name": "h", "layout": "unknown",
            "fields": "unknown", "known_abi": "结构体偏移为 known，其余 unknown"},
        "trigger_constraints": [
            {"field": "Flags", "values": "0 或 1", "rationale": "位域", "source": "official"}],
        "candidate_mutation_axes": ["flags"],
        "expected_runtime_behavior": {"not_a_crash": "status 差异"},
        "next_experiment": {"goal": "差分"},
    }
    parsed = DriverAnalysis.model_validate(payload)
    assert parsed.candidate_entry_points[0].api == "D3DKMTEscape"
    assert parsed.trigger_constraints[0].values == ["0 或 1"]
    assert isinstance(parsed.expected_runtime_behavior, str)
    assert json.loads(parsed.expected_runtime_behavior)["not_a_crash"] == "status 差异"


def test_bool_coercion_prefers_explicit_unknown():
    assert _as_bool(True) is True
    assert _as_bool("unknown") is False
    assert _as_bool("known except offset 32") is True


def test_a_windows_exception_code_is_a_usermode_fault():
    """Windows returns 0xC0000005 as an unsigned code, not a negative one."""
    result = outcome.classify(returncode=0xC0000005, output="")
    assert result.state == outcome.USERMODE_FAULT
