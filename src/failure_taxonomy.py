# -*- coding: utf-8 -*-
"""Failure taxonomy for the PoC synthesis loop.

The loop is only general if failures are classified into a small, CVE-agnostic
set of diagnoses, each carrying an actionable directive for the next
generation attempt. A reason string such as "no crash" is useless to the
model; "the instrumented target function was never executed" tells it to
reconsider the entry conditions rather than mutate bytes.

Diagnosis is deterministic: same evidence, same code, same directive. That
keeps the loop auditable and makes the retry budget explainable.
"""

import re
from dataclasses import dataclass
from typing import List, Optional

# Codes are stable identifiers used in reports and tests.
SYNTAX_ERROR = "SYNTAX_ERROR"
LINT_VIOLATION = "LINT_VIOLATION"
EXECUTOR_FAILURE = "EXECUTOR_FAILURE"
STAGE_ERROR = "STAGE_ERROR"
PATH_NOT_REACHED = "PATH_NOT_REACHED"
PRECONDITION_VIOLATED = "PRECONDITION_VIOLATED"
FALSE_POSITIVE = "FALSE_POSITIVE"
INCONCLUSIVE = "INCONCLUSIVE"
NO_EFFECT = "NO_EFFECT"
HARNESS_STEP_FAILED = "HARNESS_STEP_FAILED"
LABEL_CONFLICT = "LABEL_CONFLICT"
NO_OBSERVATION = "NO_OBSERVATION"
UNCLASSIFIED = "UNCLASSIFIED"

_LINT_IDS = ("version-classifier-unknown-major", "driver-probe-without-context",
             "legacy-token-search-on-modern-profile", "elf-layout-built-by-hand",
             "project-import-in-poc", "py38-incompatible-syntax",
             "missing-run-lines",
             "missing-artifact-manifest")

_DIRECTIVES = {
    SYNTAX_ERROR: (
        "The candidate does not parse. Fix the syntax error and keep the rest "
        "of the strategy unchanged."),
    LINT_VIOLATION: (
        "A domain invariant is violated. Correct exactly what the lint names; "
        "do not restructure unrelated parts of the PoC."),
    EXECUTOR_FAILURE: (
        "The isolated executor failed before producing observations. Fix the "
        "harness invocation or timeouts, not the trigger logic."),
    STAGE_ERROR: (
        "A pipeline stage raised. Fix the immediate error and retry; if it "
        "recurs, the strategy itself is not implementable as specified."),
    PATH_NOT_REACHED: (
        "The instrumented target function was never executed: the input never "
        "reached the vulnerable code path. Identify the entry conditions "
        "(API sequence, file format, instruction/profile, version gate) that "
        "the parser requires, then rebuild the input so it reaches them. Do "
        "not mutate bytes blindly."),
    PRECONDITION_VIOLATED: (
        "The target rejected the call before reaching the vulnerable path "
        "(for example CUDA_ERROR_NOT_INITIALIZED, or a version outside the "
        "affected range). Establish the required environment state first, "
        "then issue the same trigger."),
    FALSE_POSITIVE: (
        "The one-variable controls crashed too, so the observed crash is not "
        "attributable to your trigger. Redesign so that exactly one variable "
        "differs between the trigger and its controls, or choose a different "
        "mechanism. More mutations will only reproduce the same false "
        "positive."),
    INCONCLUSIVE: (
        "There is no clean baseline, so the observation cannot be interpreted. "
        "Add a benign input that must not crash before changing the trigger."),
    NO_OBSERVATION: (
        "The candidate ran but produced no [CPG_RUN] lines, so nothing could be "
        "graded. Make it execute the artifacts it creates and emit the contract "
        "lines; a PoC that reports nothing is not a weaker PoC, it is an "
        "unusable one."),
    LABEL_CONFLICT: (
        "The candidate declared a role for an artifact that contradicts the "
        "name it already carries (a file named benign declared MALICIOUS, for "
        "example). Declare roles consistently: the harness refuses to relabel "
        "a recognisable baseline, because that would manufacture evidence."),
    HARNESS_STEP_FAILED: (
        "The candidate aborted at its own step before producing any artifact "
        "run. The detail names the precondition that failed (a compiler flag, "
        "a missing input, a version gate). Fix that step, not the trigger "
        "logic: no trigger was ever exercised."),
    NO_EFFECT: (
        "No observable effect occurred. Verify the input actually reaches the "
        "parser and that the mutated field is one the parser consumes; print "
        "intermediate state to prove the path was taken."),
    UNCLASSIFIED: (
        "The failure does not match a known pattern. Add instrumentation that "
        "distinguishes 'did not reach', 'reached but no effect' and 'effect "
        "suppressed' before changing the trigger."),
}

# Which diagnoses justify another generation attempt.
_RETRYABLE = {
    SYNTAX_ERROR, LINT_VIOLATION, EXECUTOR_FAILURE, STAGE_ERROR,
    PATH_NOT_REACHED, PRECONDITION_VIOLATED, INCONCLUSIVE, NO_EFFECT,
    HARNESS_STEP_FAILED, LABEL_CONFLICT, NO_OBSERVATION,
}
# FALSE_POSITIVE is deliberately retryable only with a redesign, which the
# directive states explicitly; the controller still bounds the attempts.
_RETRYABLE.add(FALSE_POSITIVE)


@dataclass(frozen=True)
class Diagnosis:
    """Machine-readable failure plus the directive handed to the model."""

    code: str
    evidence: str
    directive: str
    retryable: bool = True


def diagnose(*, verdict: Optional[str], reasons: List[str],
             stage_error: Optional[str] = None,
             reached: Optional[bool] = None) -> Optional[Diagnosis]:
    """Classify one iteration's outcome; returns None when it succeeded.

    ``reached`` is the strongest signal: when instrumentation says the target
    function never ran, no amount of trigger tuning will help, so it
    outranks every textual reason.
    """
    if verdict == "SUPPORTED":
        return None

    if stage_error:
        match = re.search("|".join(re.escape(x) for x in _LINT_IDS), stage_error)
        if match:
            return Diagnosis(LINT_VIOLATION, stage_error, _DIRECTIVES[LINT_VIOLATION])
        if "SyntaxError" in stage_error:
            return Diagnosis(SYNTAX_ERROR, stage_error, _DIRECTIVES[SYNTAX_ERROR])
        if re.search(r"\brc=\d+", stage_error):
            return Diagnosis(EXECUTOR_FAILURE, stage_error, _DIRECTIVES[EXECUTOR_FAILURE])
        return Diagnosis(STAGE_ERROR, stage_error, _DIRECTIVES[STAGE_ERROR])

    if reached is False:
        return Diagnosis(PATH_NOT_REACHED, "target function never executed",
                         _DIRECTIVES[PATH_NOT_REACHED])

    joined = " ".join(reasons)
    if "全部崩溃" in joined:
        return Diagnosis(FALSE_POSITIVE, joined, _DIRECTIVES[FALSE_POSITIVE])
    if "不具区分力" in joined or "缺少良性基线" in joined:
        return Diagnosis(INCONCLUSIVE, joined, _DIRECTIVES[INCONCLUSIVE])
    if "未观察到任何样本退出码" in joined:
        return Diagnosis(NO_OBSERVATION, joined, _DIRECTIVES[NO_OBSERVATION])
    if "标签冲突" in joined:
        return Diagnosis(LABEL_CONFLICT, joined, _DIRECTIVES[LABEL_CONFLICT])
    if "步骤失败" in joined or "STEP_FAILED" in joined or "[CUDA_STEP:" in joined:
        return Diagnosis(HARNESS_STEP_FAILED, joined, _DIRECTIVES[HARNESS_STEP_FAILED])
    if "NOT_INITIALIZED" in joined or "前提" in joined:
        return Diagnosis(PRECONDITION_VIOLATED, joined,
                         _DIRECTIVES[PRECONDITION_VIOLATED])
    if "未产生崩溃" in joined:
        return Diagnosis(NO_EFFECT, joined, _DIRECTIVES[NO_EFFECT])
    return Diagnosis(UNCLASSIFIED, joined, _DIRECTIVES[UNCLASSIFIED],
                     retryable=False)


def is_retryable(diagnosis: Optional[Diagnosis]) -> bool:
    """Whether the controller should spend another iteration."""
    return diagnosis is not None and diagnosis.retryable
