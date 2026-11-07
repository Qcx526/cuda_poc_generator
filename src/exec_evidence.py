# -*- coding: utf-8 -*-
"""Execution states, decided by observation rather than by what a candidate prints.

A candidate that prints "EXIT=139" proves nothing; only the harness sees the real
process. Each state below has a single, checkable entry condition, and a later state
is never inferred from an earlier one.
"""

from dataclasses import dataclass, field
from typing import List, Optional

GENERATION_COMPLETED = "GENERATION_COMPLETED"
CANDIDATE_STARTED = "CANDIDATE_STARTED"
INPUT_CREATED = "INPUT_CREATED"
TARGET_TOOL_INVOKED = "TARGET_TOOL_INVOKED"
TARGET_TOOL_RETURNED = "TARGET_TOOL_RETURNED"
OBSERVED_ABNORMAL_TERMINATION = "OBSERVED_ABNORMAL_TERMINATION"
VULNERABILITY_VERIFIED = "VULNERABILITY_VERIFIED"

ORDER = (GENERATION_COMPLETED, CANDIDATE_STARTED, INPUT_CREATED,
         TARGET_TOOL_INVOKED, TARGET_TOOL_RETURNED,
         OBSERVED_ABNORMAL_TERMINATION, VULNERABILITY_VERIFIED)


@dataclass
class ToolInvocation:
    """One real subprocess call, as the harness saw it."""

    run_id: str
    tool: str
    tool_version: str
    input_sha256: str
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    signal: Optional[int] = None

    @property
    def abnormal(self) -> bool:
        """A crash or a timeout, never a plain rejection."""
        if self.timed_out or self.signal:
            return True
        return self.exit_code is not None and (self.exit_code < 0 or self.exit_code >= 128)


@dataclass
class RunRecord:
    candidate_generated: bool = False
    candidate_started: bool = False
    inputs_created: List[str] = field(default_factory=list)
    invocations: List[ToolInvocation] = field(default_factory=list)
    verified_with_differential: bool = False
    notes: List[str] = field(default_factory=list)

    def states(self) -> List[str]:
        reached = []
        if self.candidate_generated:
            reached.append(GENERATION_COMPLETED)
        if self.candidate_started:
            reached.append(CANDIDATE_STARTED)
        if self.inputs_created:
            reached.append(INPUT_CREATED)
        if self.invocations:
            reached.append(TARGET_TOOL_INVOKED)
        if any(item.exit_code is not None for item in self.invocations):
            reached.append(TARGET_TOOL_RETURNED)
        if any(item.abnormal for item in self.invocations):
            reached.append(OBSERVED_ABNORMAL_TERMINATION)
        # Verification is never granted by this module: it needs a differential the
        # caller had to establish independently.
        if self.verified_with_differential:
            reached.append(VULNERABILITY_VERIFIED)
        return reached

    def highest(self) -> str:
        states = self.states()
        return states[-1] if states else "NOTHING"
