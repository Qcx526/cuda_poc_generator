# -*- coding: utf-8 -*-
"""Closed-loop controller tests: tier gating, stop conditions, feedback."""

import unittest

from src.closed_loop import (ClosedLoopController, LoopConfig, LoopState,
                             TargetTier)
from src.reproduction import ReproductionResult


def _result(verdict: str, reasons) -> ReproductionResult:
    return ReproductionResult(
        verdict=verdict, reasons=list(reasons), failed_steps=[],
        malicious_runs=1, malicious_crashes=1 if verdict == "SUPPORTED" else 0,
        benign_runs=1, benign_crashes=0)


def _stages(log, generate=None, execute=None):
    return {
        "generate": generate or (lambda s: LoopState(iteration=s.iteration,
                                                     candidate_file="poc.py")),
        "execute": execute or (lambda s: LoopState(
            iteration=s.iteration, candidate_file=s.candidate_file)),
    }


class TestTierGate(unittest.TestCase):
    def test_kernel_target_blocked_without_explicit_allowance(self):
        cfg = LoopConfig(cve_id="CVE-2024-0091", tier=TargetTier.DRIVER_KERNEL,
                         allow_kernel=False)
        controller = ClosedLoopController(cfg, _stages([]), lambda s: _result("UNKNOWN", ["x"]))
        result = controller.run()
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.iterations_used, 0)

    def test_kernel_target_with_allowance_runs_but_stage_refuses(self):
        cfg = LoopConfig(cve_id="CVE-2024-0091", tier=TargetTier.DRIVER_KERNEL,
                         allow_kernel=True)
        controller = ClosedLoopController(
            cfg,
            _stages([], execute=lambda s: (_ for _ in ()).throw(
                RuntimeError("kernel tier allows a single probe per iteration"))),
            lambda s: _result("UNKNOWN", ["x"]))
        result = controller.run()
        self.assertEqual(result.status, "ERROR")
        self.assertIn("single probe", result.reasons[0])

    def test_toolchain_tier_runs_unattended(self):
        cfg = LoopConfig(cve_id="CVE-2025-23339")
        controller = ClosedLoopController(cfg, _stages([]),
                                          lambda s: _result("SUPPORTED", ["ok"]))
        self.assertIsNone(controller.preflight())


class TestStopConditions(unittest.TestCase):
    def test_supported_stops_on_first_iteration(self):
        cfg = LoopConfig(cve_id="CVE-X", max_iterations=3)
        controller = ClosedLoopController(cfg, _stages([]),
                                          lambda s: _result("SUPPORTED", ["ok"]))
        result = controller.run()
        self.assertEqual((result.status, result.iterations_used), ("SUPPORTED", 1))

    def test_attributable_unknown_feeds_back_until_budget_exhausted(self):
        cfg = LoopConfig(cve_id="CVE-X", max_iterations=3)
        controller = ClosedLoopController(
            cfg, _stages([]),
            lambda s: _result("UNKNOWN", ["机制对照 1/1 全部崩溃"]))
        result = controller.run()
        self.assertEqual(result.status, "EXHAUSTED")
        self.assertEqual(result.iterations_used, 3)

    def test_non_attributable_not_verified_stops_early(self):
        cfg = LoopConfig(cve_id="CVE-X", max_iterations=3)
        controller = ClosedLoopController(
            cfg, _stages([]),
            lambda s: _result("NOT_VERIFIED", ["unrelated", "noise"]))
        result = controller.run()
        self.assertEqual((result.status, result.iterations_used),
                         ("EXHAUSTED", 1))

    def test_stage_failure_is_recorded_with_its_name(self):
        cfg = LoopConfig(cve_id="CVE-X", max_iterations=2)

        def broken(state: LoopState) -> LoopState:
            raise ValueError("docker daemon down")

        controller = ClosedLoopController(cfg, _stages([], execute=broken),
                                          lambda s: _result("UNKNOWN", ["x"]))
        result = controller.run()
        self.assertEqual(result.status, "ERROR")
        self.assertIn("stage execute failed", result.reasons[0])

    def test_grader_receives_each_iteration_state(self):
        cfg = LoopConfig(cve_id="CVE-X", max_iterations=2)
        seen = []

        def grader(state: LoopState) -> ReproductionResult:
            seen.append((state.iteration, state.candidate_file))
            return _result("UNKNOWN", ["不具区分力"])

        ClosedLoopController(cfg, _stages([]), grader).run()
        self.assertEqual(seen, [(1, "poc.py"), (2, "poc.py")])


if __name__ == "__main__":
    unittest.main()
