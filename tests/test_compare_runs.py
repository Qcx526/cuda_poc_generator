# -*- coding: utf-8 -*-
"""Ablation comparison: direction of change per CVE plus totals."""

import unittest

from tools.compare_runs import compare

BEFORE = {
    "CVE-A": {"cve_id": "CVE-A", "successes": 1, "attempts": 3, "diagnosis": "FALSE_POSITIVE"},
    "CVE-B": {"cve_id": "CVE-B", "successes": 2, "attempts": 3, "diagnosis": ""},
}
AFTER = {
    "CVE-A": {"cve_id": "CVE-A", "successes": 3, "attempts": 3, "diagnosis": ""},
    "CVE-B": {"cve_id": "CVE-B", "successes": 1, "attempts": 3, "diagnosis": "NO_EFFECT"},
}


class TestCompare(unittest.TestCase):
    def test_reports_direction_per_cve(self):
        text = compare(BEFORE, AFTER)
        self.assertIn("↑ 67%", text)   # 1/3 -> 3/3
        self.assertIn("↓ -33%", text)  # 2/3 -> 1/3
        self.assertIn("提升 1 个 CVE，退化 1 个 CVE", text)

    def test_totals_are_recomputed_from_both_runs(self):
        text = compare(BEFORE, AFTER)
        self.assertIn("A：success = 3/6 = 50%", text)
        self.assertIn("B：success = 4/6 = 67%", text)
        self.assertIn("+16.7 个百分点", text)

    def test_a_cve_missing_from_one_side_does_not_crash(self):
        text = compare({"CVE-C": {"cve_id": "CVE-C", "successes": 0, "attempts": 1}}, {})
        self.assertIn("CVE-C", text)


if __name__ == "__main__":
    unittest.main()
