# -*- coding: utf-8 -*-
"""The engine is target-agnostic: a fake grammar and runner must suffice."""

import random
import unittest

from src.fuzz_core import (ACCEPTED, FAULT, Candidate, Outcome, fuzz, grammar_for,
                           register)


class FakeGrammar:
    name = "fake"

    def generate(self, rng: random.Random, params):
        return Candidate(body="case-%d" % rng.randint(0, 10), meta={"axis": "x"})


class TestEngine(unittest.TestCase):
    def test_counts_outcomes_and_keeps_one_case_per_bucket(self):
        register(FakeGrammar())
        calls = []

        def runner(candidate):
            calls.append(candidate.body)
            return Outcome(ACCEPTED, 0, 0.01, size=len(candidate.body))

        summary = fuzz(grammar=grammar_for("fake"), params={}, runner=runner,
                       iterations=20, seed=3)
        self.assertEqual(summary.iterations, 20)
        self.assertEqual(summary.outcomes[ACCEPTED], 20)
        self.assertEqual(summary.corpus, 1)      # one behaviour, one bucket
        self.assertEqual(len(calls), 20)

    def test_a_fault_is_captured_with_its_input(self):
        register(FakeGrammar())

        def runner(candidate):
            if candidate.body.endswith("3"):
                return Outcome(FAULT, -1073741819, 0.02, detail="0xC0000005")
            return Outcome(ACCEPTED, 0, 0.01)

        summary = fuzz(grammar=grammar_for("fake"), params={}, runner=runner,
                       iterations=30, seed=1)
        self.assertGreaterEqual(len(summary.faults), 1)
        self.assertIn("body", summary.faults[0])

    def test_unknown_grammar_is_named_not_silently_defaulted(self):
        with self.assertRaises(KeyError):
            grammar_for("does-not-exist")


if __name__ == "__main__":
    unittest.main()
