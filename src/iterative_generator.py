# -*- coding: utf-8 -*-
"""Iterative candidate generation driven by failure diagnoses.

This is the loop's "try again, but differently" component. It is deliberately
CVE-agnostic: it knows how to carry a previous candidate and a directive into
the next prompt, and how to reject a candidate at the static gate, nothing
about CUDA.

Two feedback channels:

- static: syntax or domain-lint failure inside one generation round;
- dynamic: the previous iteration's :class:`Diagnosis` directive, passed in by
  the loop controller after execution and grading.
"""

from typing import Callable, List, Optional

from pydantic import BaseModel, ConfigDict


class GenerationOutcome(BaseModel):
    """Result of one generation round, including why it gave up."""

    model_config = ConfigDict(strict=True, frozen=True)

    code: Optional[str] = None
    error: Optional[str] = None
    attempts: int
    transcript: List[str]  # one line per attempt, for the audit trail


def clean_code(raw: str) -> str:
    """Strip markdown fences and leading prose from a model response."""
    text = raw.strip()
    if "```" in text:
        parts = text.split("```")
        # The body sits between the first and second fence.
        if len(parts) >= 3:
            body = parts[1]
            if body.startswith("python"):
                body = body[len("python"):]
            text = body.strip("\n")
    return text.strip() + "\n"


class IterativeCandidateGenerator:
    """Generate a candidate, retrying on static failure and prior diagnosis."""

    def __init__(self, llm: object, system_prompt: str, base_prompt: str,
                 validator: Callable[[str], "tuple[bool, str]"],
                 max_attempts: int = 3) -> None:
        self.llm = llm
        self.system_prompt = system_prompt
        self.base_prompt = base_prompt
        self.validator = validator
        self.max_attempts = max_attempts

    def _messages(self, previous_code: Optional[str],
                  diagnosis_directive: Optional[str],
                  correction: Optional[str]) -> List[dict]:
        prompt = self.base_prompt
        if previous_code:
            prompt += (
                "\n\n[PREVIOUS CANDIDATE — superseded]\n"
                "The code below was executed and rejected. Keep whatever parts "
                "are still correct, but change what the failure requires.\n"
                "```python\n%s\n```\n" % previous_code)
        if diagnosis_directive:
            prompt += ("\n\n[FAILURE DIAGNOSIS — act on this]\n"
                       "%s\n" % diagnosis_directive)
        if correction:
            prompt += ("\n\n[STATIC CHECK FAILED]\n%s\n"
                       "Return the complete corrected script.\n" % correction)
        return [{"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt}]

    def generate(self, previous_code: Optional[str] = None,
                 diagnosis_directive: Optional[str] = None) -> GenerationOutcome:
        transcript: List[str] = []
        correction: Optional[str] = None
        for attempt in range(1, self.max_attempts + 1):
            raw = self.llm.chat(
                self._messages(previous_code, diagnosis_directive, correction),
                temperature=0.1)
            code = clean_code(raw)
            ok, error = self.validator(code)
            if ok:
                transcript.append("attempt %d: accepted" % attempt)
                return GenerationOutcome(code=code, attempts=attempt,
                                         transcript=transcript)
            transcript.append("attempt %d: rejected — %s" % (attempt, error[:160]))
            correction = error
        return GenerationOutcome(error=transcript[-1], attempts=self.max_attempts,
                                 transcript=transcript)
