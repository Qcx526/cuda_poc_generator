# -*- coding: utf-8 -*-
"""The execution ladder: only a signal or a timeout counts as abnormal."""

from src.exec_evidence import (CANDIDATE_STARTED, GENERATION_COMPLETED,
                               OBSERVED_ABNORMAL_TERMINATION, RunRecord,
                               TARGET_TOOL_INVOKED, TARGET_TOOL_RETURNED,
                               ToolInvocation, VULNERABILITY_VERIFIED)


def _record(exit_code):
    record = RunRecord(candidate_generated=True, candidate_started=True,
                       inputs_created=["a.bin"])
    record.invocations.append(ToolInvocation(run_id="r1", tool="nvdisasm",
                                             tool_version="11.2.2",
                                             input_sha256="0" * 64,
                                             exit_code=exit_code))
    return record


def test_exit_one_is_a_rejection_not_an_anomaly():
    states = _record(1).states()
    assert TARGET_TOOL_RETURNED in states
    assert OBSERVED_ABNORMAL_TERMINATION not in states


def test_signal_exit_is_an_anomaly():
    assert OBSERVED_ABNORMAL_TERMINATION in _record(139).states()


def test_timeout_is_an_anomaly():
    invocation = ToolInvocation(run_id="r", tool="nvdisasm", tool_version="1",
                                input_sha256="0" * 64, timed_out=True)
    assert invocation.abnormal is True


def test_verification_is_never_self_granted():
    states = _record(139).states()
    assert VULNERABILITY_VERIFIED not in states
    record = _record(139)
    record.verified_with_differential = True
    assert VULNERABILITY_VERIFIED in record.states()


def test_ladder_stops_at_the_last_supported_state():
    assert _record(None).highest() == TARGET_TOOL_INVOKED
    assert _record(1).highest() == TARGET_TOOL_RETURNED


def test_generated_only():
    assert RunRecord(candidate_generated=True).highest() == GENERATION_COMPLETED
    assert RunRecord(candidate_generated=True, candidate_started=True).highest() == \
        CANDIDATE_STARTED
