# -*- coding: utf-8 -*-
"""Tests for the failure taxonomy and iterative generator."""

import unittest

from src.failure_taxonomy import (EXECUTOR_FAILURE, FALSE_POSITIVE,
                                  INCONCLUSIVE, LINT_VIOLATION, NO_EFFECT,
                                  PATH_NOT_REACHED, PRECONDITION_VIOLATED,
                                  SYNTAX_ERROR, UNCLASSIFIED, diagnose,
                                  is_retryable)
from src.iterative_generator import IterativeCandidateGenerator, clean_code
from src.loop_report import render_loop_report
from src.closed_loop import (IterationRecord, LoopConfig, LoopResult,
                             LoopState, TargetTier)


class TestDiagnose(unittest.TestCase):
    def test_success_is_not_a_failure(self):
        self.assertIsNone(diagnose(verdict="SUPPORTED", reasons=["ok"]))

    def test_lint_stage_error_maps_to_lint_violation(self):
        d = diagnose(verdict=None, reasons=[],
                     stage_error="driver-probe-without-context — no cuInit")
        self.assertEqual(d.code, LINT_VIOLATION)
        self.assertIn("lint", d.directive)

    def test_syntax_and_executor_are_distinguished(self):
        self.assertEqual(diagnose(verdict=None, reasons=[],
                                  stage_error="SyntaxError at line 4").code,
                         SYNTAX_ERROR)
        self.assertEqual(diagnose(verdict=None, reasons=[],
                                  stage_error="executor rc=137").code,
                         EXECUTOR_FAILURE)

    def test_unreached_target_outranks_text_reasons(self):
        d = diagnose(verdict="UNKNOWN", reasons=["未产生崩溃"], reached=False)
        self.assertEqual(d.code, PATH_NOT_REACHED)

    def test_all_controls_crashing_is_a_false_positive(self):
        d = diagnose(verdict="UNKNOWN", reasons=["机制对照 5/5 全部崩溃"])
        self.assertEqual(d.code, FALSE_POSITIVE)
        self.assertIn("one variable", d.directive)

    def test_missing_baseline_is_inconclusive(self):
        d = diagnose(verdict="UNKNOWN", reasons=["缺少良性基线"])
        self.assertEqual(d.code, INCONCLUSIVE)

    def test_not_initialized_is_a_precondition_failure(self):
        d = diagnose(verdict="NOT_VERIFIED",
                     reasons=["受控样本未产生崩溃（所有步骤均报告 OK）",
                              "probe returned NOT_INITIALIZED"])
        self.assertEqual(d.code, PRECONDITION_VIOLATED)

    def test_no_effect_is_classified(self):
        d = diagnose(verdict="NOT_VERIFIED", reasons=["受控样本未产生崩溃"])
        self.assertEqual(d.code, NO_EFFECT)

    def test_harness_step_failure_is_retryable(self):
        d = diagnose(verdict="NOT_VERIFIED",
                     reasons=["步骤失败：[CUDA_STEP:S02] — FAIL | lacks debug"])
        self.assertEqual(d.code, "HARNESS_STEP_FAILED")
        self.assertTrue(is_retryable(d))

    def test_missing_observation_is_retryable(self):
        # A candidate that prints no [CPG_RUN] lines cannot be graded, but that
        # is a fixable contract violation, not an unclassifiable dead end.
        d = diagnose(verdict="NOT_VERIFIED",
                     reasons=["未观察到任何样本退出码；输入可能未到达解析器"])
        self.assertEqual(d.code, "NO_OBSERVATION")
        self.assertTrue(is_retryable(d))


    def test_driver_tier_refuses_to_fake_a_container_run(self):
        from src.closed_loop import docker_matrix_stage
        stage = docker_matrix_stage(LoopConfig(cve_id="CVE-X",
                                               tier=TargetTier.DRIVER_USERLAND), [])
        state = stage(LoopState(iteration=1, candidate_file="x.py"))
        self.assertIn("PLATFORM_UNAVAILABLE", state.stage_error)

    def test_platform_gap_is_not_reported_as_a_candidate_defect(self):
        from src.closed_loop import ClosedLoopController
        from src.reproduction import ReproductionResult
        controller = ClosedLoopController(
            LoopConfig(cve_id="CVE-X"), {"generate": lambda s: s},
            lambda s: ReproductionResult(verdict="NOT_VERIFIED", reasons=[]))
        result = controller._stage_failure([], 1, "execute",
                                           "PLATFORM_UNAVAILABLE: needs cdb")
        self.assertEqual(result.trace[-1].diagnosis_code, "PLATFORM_UNAVAILABLE")
        self.assertEqual(result.status, "ERROR")

    def test_unknown_reason_is_not_retryable(self):
        d = diagnose(verdict="NOT_VERIFIED", reasons=["something odd"])
        self.assertEqual(d.code, UNCLASSIFIED)
        self.assertFalse(is_retryable(d))


class FakeLLM:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def chat(self, messages, temperature=None):
        self.calls.append(messages)
        return self.replies.pop(0)


BAD = "def run_single_probe(v):\n    lib.cuModuleLoadData(v)\n"
GOOD = "def ok():\n    return 0\n"


class TestIterativeGenerator(unittest.TestCase):
    def test_retries_until_static_check_passes(self):
        llm = FakeLLM([BAD, GOOD])
        gen = IterativeCandidateGenerator(
            llm, "sys", "base", lambda code: (code == GOOD, "lint says no"))
        outcome = gen.generate()
        self.assertEqual(outcome.attempts, 2)
        self.assertEqual(outcome.code, GOOD)
        self.assertIn("rejected", outcome.transcript[0])

    def test_exhausts_attempts_with_the_last_error(self):
        llm = FakeLLM([BAD, BAD])
        gen = IterativeCandidateGenerator(
            llm, "sys", "base", lambda code: (False, "lint says no"),
            max_attempts=2)
        outcome = gen.generate()
        self.assertIsNone(outcome.code)
        self.assertEqual(outcome.attempts, 2)
        self.assertIn("lint says no", outcome.error)

    def test_previous_code_and_directive_reach_the_prompt(self):
        llm = FakeLLM([GOOD])
        gen = IterativeCandidateGenerator(llm, "sys", "base",
                                          lambda code: (True, ""))
        gen.generate(previous_code="OLD_CODE", diagnosis_directive="FIX_THIS")
        prompt = llm.calls[0][1]["content"]
        self.assertIn("OLD_CODE", prompt)
        self.assertIn("FIX_THIS", prompt)

    def test_clean_code_strips_fences(self):
        self.assertEqual(clean_code("```python\nx = 1\n```"), "x = 1\n")


class TestLoopReport(unittest.TestCase):
    def test_report_renders_trace_and_boundary(self):
        result = LoopResult(
            cve_id="CVE-2025-23340", status="EXHAUSTED", iterations_used=2,
            final_verdict="UNKNOWN",
            reasons=["机制对照 5/5 全部崩溃"],
            trace=[IterationRecord(iteration=1, verdict="UNKNOWN",
                                   diagnosis_code="FALSE_POSITIVE",
                                   directive="redesign controls")])
        text = render_loop_report(result)
        self.assertIn("CVE-2025-23340", text)
        self.assertIn("FALSE_POSITIVE", text)
        self.assertIn("不等于 CVE 级 `VERIFIED`", text)


if __name__ == "__main__":
    unittest.main()
