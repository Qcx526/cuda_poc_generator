# -*- coding: utf-8 -*-
"""Tracing stays target-agnostic and only executed evidence becomes a claim."""

import unittest
from pathlib import Path

from src.trace_core import (Probe, TraceResult, claims_from_trace, provider_for,
                            register, run, summarise)


class FakeProvider:
    name = "fake"

    def __init__(self, hit):
        self.hit = hit

    def trace(self, program, probe, timeout=120):
        return TraceResult(provider=self.name, hit=self.hit, probe=probe,
                           registers={"rdx": "0x41414141"} if self.hit else {})


class TestTrace(unittest.TestCase):
    def test_probe_expression_supports_symbols_and_offsets(self):
        self.assertEqual(Probe("m", rva=0x10).expression, "m+0x10")
        self.assertEqual(Probe("m", symbol="m!f").expression, "m!f")

    def test_miss_is_recorded_as_absence_not_as_evidence(self):
        register(FakeProvider(False))
        result = run(provider=provider_for("fake"), program=Path("x"), probe=Probe("m", rva=4))
        claim = claims_from_trace(result, "the helper is on the path")
        self.assertIn("never hit", claim["value"])
        self.assertEqual(claim["verified_by"], "execution")

    def test_hit_carries_the_registers(self):
        register(FakeProvider(True))
        result = run(provider=provider_for("fake"), program=Path("x"), probe=Probe("m", rva=4))
        claim = claims_from_trace(result, "the helper is on the path")
        self.assertIn("rdx=0x41414141", claim["value"])

    def test_summary_counts_hits(self):
        results = [TraceResult("fake", True), TraceResult("fake", False)]
        self.assertIn("1/2", summarise(results))


if __name__ == "__main__":
    unittest.main()
