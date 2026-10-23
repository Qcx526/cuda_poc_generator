# -*- coding: utf-8 -*-
"""The evidence pack reports rates over runs, never a bare verdict."""

import json
import tempfile
import unittest
from pathlib import Path

from tools.evidence_pack import build, wilson

ROWS = [
    {"cve_id": "CVE-A", "successes": 4, "attempts": 5, "iterations": 1,
     "diagnosis": "", "status": "SUPPORTED"},
    {"cve_id": "CVE-B", "successes": 0, "attempts": 5, "iterations": 2,
     "diagnosis": "NO_EFFECT", "status": "EXHAUSTED"},
]


class TestPack(unittest.TestCase):
    def test_interval_widens_as_the_sample_shrinks(self):
        narrow_lo, narrow_hi = wilson(40, 50)
        wide_lo, wide_hi = wilson(4, 5)
        self.assertGreater(wide_hi - wide_lo, narrow_hi - narrow_lo)

    def test_pack_reports_success_over_attempts(self):
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            (workdir / "batch_summary.json").write_text(json.dumps(ROWS), encoding="utf-8")
            text = build(workdir, Path("."))
        self.assertIn("4/5", text)
        self.assertIn("0/5", text)
        self.assertIn("success = 40%", text)
        self.assertIn("NO_EFFECT", text)
        self.assertIn("至少一次成功的 CVE：1 / 2", text)

    def test_empty_workdir_is_refused_not_guessed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                build(Path(tmp), Path("."))


if __name__ == "__main__":
    unittest.main()
