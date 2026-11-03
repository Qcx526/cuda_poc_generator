# -*- coding: utf-8 -*-
"""Turn one run's evidence into the context that must change the next program.

"next_move: fix the call" is advice; it does not change code. What changes code is
knowing *which* call failed, with *which* arguments, returning *what*, plus an
explicit statement of what the previous attempt assumed. That is this module's
job: build that block from the execution record, and fingerprint the failing call
so an identical retry can be told apart from an attempted fix.

Unknown stays UNKNOWN. A fabricated argument list would be worse than a missing
one: the model would "fix" something that never happened.
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

UNKNOWN = "UNKNOWN"

# Calls whose text we can fingerprint reliably inside generated Python.
_CALL_PATTERN = r"{api}\s*\(([^)]*)\)"


@dataclass
class FeedbackContext:
    """The twelve fields the next round is allowed to treat as fact."""

    previous_outcome: str = UNKNOWN
    failed_api: str = UNKNOWN
    failed_call_arguments: str = UNKNOWN
    returned_value: str = UNKNOWN
    win32_error: str = UNKNOWN
    ntstatus: str = UNKNOWN
    failure_context: str = UNKNOWN
    previous_hypothesis: str = UNKNOWN
    recommended_change: str = UNKNOWN
    forbidden_unchanged_action: str = UNKNOWN
    expected_next_observation: str = UNKNOWN
    fingerprint: str = UNKNOWN
    history: List[Dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "previous_outcome": self.previous_outcome,
            "failed_api": self.failed_api,
            "failed_call_arguments": self.failed_call_arguments,
            "returned_value": self.returned_value,
            "win32_error": self.win32_error,
            "ntstatus": self.ntstatus,
            "failure_context": self.failure_context,
            "previous_hypothesis": self.previous_hypothesis,
            "recommended_change": self.recommended_change,
            "forbidden_unchanged_action": self.forbidden_unchanged_action,
            "expected_next_observation": self.expected_next_observation,
            "fingerprint": self.fingerprint,
            "history": self.history,
        }


def _result_of(payload: Optional[dict]) -> dict:
    detail = (payload or {}).get("detail") or {}
    return detail.get("result") or {}


def first_failing_call(payload: Optional[dict]) -> dict:
    """The call that stopped the run, not the first call it made."""
    result = _result_of(payload)
    calls = result.get("calls") or []
    for call in calls:
        status = call.get("status")
        if status not in (0, None):
            return call
    return calls[-1] if calls else {}


def call_arguments(source: str, api: str) -> str:
    """The literal arguments at the call site, or UNKNOWN when they are dynamic."""
    if not source or api in (UNKNOWN, ""):
        return UNKNOWN
    match = re.search(_CALL_PATTERN.format(api=re.escape(api)), source)
    if not match:
        return UNKNOWN
    return " ".join(match.group(1).split())


def fingerprint(api: str, arguments: str, returned: object,
                environment: str = "") -> str:
    """A stable id for "this exact call failed this way here".

    Arguments and return value are included on purpose: retrying the same call
    with a different argument is a legitimate next step, and must not be flagged
    as a repeat.
    """
    raw = "|".join([str(api), str(arguments), str(returned), str(environment)])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def build(payload: Optional[dict], source: str = "",
          previous_source: str = "",
          history: Optional[List[Dict[str, str]]] = None,
          environment: str = "") -> FeedbackContext:
    """Assemble the block from the record; never invent a missing field."""
    payload = payload or {}
    result = _result_of(payload)
    call = first_failing_call(payload)
    api = str(call.get("api") or UNKNOWN)
    arguments = call_arguments(previous_source or source, api) if api != UNKNOWN else UNKNOWN
    returned = call.get("status")
    returned_text = UNKNOWN if returned is None else str(returned)

    win32 = UNKNOWN
    ntstatus = UNKNOWN
    if isinstance(returned, int):
        if returned in (-1, 0xFFFFFFFF):
            win32 = "NULL/-1（Win32 失败）"
        elif returned & 0xFFFF0000 == 0xC0000000:
            ntstatus = "0x%08X" % (returned & 0xFFFFFFFF)

    context = str(payload.get("reason") or result.get("notes") or UNKNOWN)
    state = str(payload.get("state") or UNKNOWN)
    return FeedbackContext(
        previous_outcome=state,
        failed_api=api,
        failed_call_arguments=arguments,
        returned_value=returned_text,
        win32_error=win32,
        ntstatus=ntstatus,
        failure_context=context,
        previous_hypothesis=str(result.get("stage") or UNKNOWN),
        recommended_change=str(payload.get("next_move") or UNKNOWN),
        forbidden_unchanged_action=(
            "不得在参数、前序调用或调用路径上完全相同地重试 %s" % api
            if api != UNKNOWN else UNKNOWN),
        expected_next_observation=(
            "%s 返回成功（0/NULL 以外的有效句柄或 NTSTATUS_SUCCESS）" % api
            if api != UNKNOWN else UNKNOWN),
        fingerprint=fingerprint(api, arguments, returned_text, environment),
        history=list(history or []),
    )


def is_repeat(previous: FeedbackContext, current_source: str,
              environment: str = "") -> bool:
    """True when the new code calls the same API the same way with the same result.

    Only the *call* is compared; comments, variable names and formatting are
    irrelevant, so a cosmetic edit cannot pass as progress.
    """
    if previous.failed_api in (UNKNOWN, ""):
        return False
    arguments = call_arguments(current_source, previous.failed_api)
    if arguments == UNKNOWN:
        return False
    current = fingerprint(previous.failed_api, arguments,
                          previous.returned_value, environment)
    return current == previous.fingerprint
