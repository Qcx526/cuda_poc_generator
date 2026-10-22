# -*- coding: utf-8 -*-
"""Batch runner tests: classification, ordering, summary arithmetic."""

import json
import tempfile
import unittest
from pathlib import Path

from src.batch_loop import BatchRow, classify, render_summary, run_batch, write_summary


class TestClassify(unittest.TestCase):
    def test_only_binary_utilities_are_selected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = {
                "CVE-A": "NVIDIA CUDA cuobjdump (CUDA Binary Utilities)",
                "CVE-B": "NVIDIA nvdisasm (CUDA Binary Utilities)",
                "CVE-C": "NVIDIA GPU Display Driver kernel mode",
                "CVE-D": "nvJPEG GPU JPEG library",
            }
            for cve, text in cases.items():
                directory = root / cve
                directory.mkdir()
                (directory / "3_affected_component.json").write_text(
                    json.dumps({"component_name": text}), encoding="utf-8")
            self.assertEqual(classify(root), ["CVE-A", "CVE-B"])


class TestBatchRun(unittest.TestCase):
    def test_rows_are_produced_in_order_and_reported(self):
        seen = []

        def fake_runner(cve, iterations, workdir, root, python, image, index=0):
            seen.append(cve)
            return BatchRow(cve_id=cve, status="SUPPORTED", iterations=1,
                            verdict="SUPPORTED", seconds=1.0)

        with tempfile.TemporaryDirectory() as tmp:
            rows = run_batch(["CVE-1", "CVE-2"], iterations=1, workdir=Path(tmp),
                             project_root=Path("."), python_exe="python",
                             image="img", runner=fake_runner,
                             progress=lambda row: seen.append("done:" + row.cve_id))
        self.assertEqual(rows[0].cve_id, "CVE-1")
        self.assertEqual(seen, ["CVE-1", "done:CVE-1", "CVE-2", "done:CVE-2"])


    def test_repeat_counts_successes_over_independent_runs(self):
        outcomes = iter(["CRASHED", "SUPPORTED", "CRASHED"])

        def fake_runner(cve, iterations, workdir, root, python, image, index=0):
            return BatchRow(cve_id=cve, status=next(outcomes), seconds=1.0)

        with tempfile.TemporaryDirectory() as tmp:
            rows = run_batch(["CVE-1"], iterations=1, workdir=Path(tmp),
                             project_root=Path("."), python_exe="python", image="img",
                             repeat=3, runner=fake_runner)
        self.assertEqual(rows[0].attempts, 3)
        self.assertEqual(rows[0].successes, 1)
        self.assertEqual(rows[0].status, "SUPPORTED")
        self.assertEqual(rows[0].success_at_k, "1/3")
        self.assertIn("success@3", render_summary(rows))

    def test_summary_counts_convergence(self):
        rows = [BatchRow("CVE-1", "SUPPORTED", 1, "SUPPORTED", seconds=1),
                BatchRow("CVE-2", "SUPPORTED", 2, "SUPPORTED", seconds=2),
                BatchRow("CVE-3", "EXHAUSTED", 2, "NOT_VERIFIED",
                         "HARNESS_STEP_FAILED", 3)]
        text = render_summary(rows)
        self.assertIn("`SUPPORTED`：2（一轮收敛 1）", text)
        self.assertIn("其余：1", text)

    def test_summary_files_are_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_summary([BatchRow("CVE-1", "SUPPORTED", 1, "SUPPORTED")],
                                 Path(tmp))
            self.assertTrue(path.is_file())
            self.assertTrue((Path(tmp) / "batch_summary.json").is_file())


if __name__ == "__main__":
    unittest.main()
