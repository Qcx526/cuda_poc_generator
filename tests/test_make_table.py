# -*- coding: utf-8 -*-
"""Table rendering: success@k joins the specification's quality facts."""

import unittest
from pathlib import Path

from tools.make_table import build_table, summarise

ROWS = [
    {"cve_id": "CVE-2025-23339", "status": "SUPPORTED", "iterations": 1,
     "diagnosis": "", "attempts": 3, "successes": 2, "seconds": 300},
    {"cve_id": "CVE-9999-0001", "status": "EXHAUSTED", "iterations": 2,
     "diagnosis": "NO_EFFECT", "attempts": 3, "successes": 0, "seconds": 600},
]


class TestTable(unittest.TestCase):
    def test_rows_carry_spec_facts_and_success_rate(self):
        table = build_table(ROWS, Path("."))
        self.assertIn("CVE-2025-23339", table)
        self.assertIn("2/3", table)
        self.assertIn("100%", table)          # 23339 has a 100%-coverage spec
        self.assertIn("无规格", table)         # the placeholder has none

    def test_summary_counts_solved_cves_and_diagnoses(self):
        text = summarise(ROWS)
        self.assertIn("至少一次成功：1（50%）", text)
        self.assertIn("success@3：2/6 = 33%", text)
        self.assertIn("NO_EFFECT", text)


if __name__ == "__main__":
    unittest.main()
