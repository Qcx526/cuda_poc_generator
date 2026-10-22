# -*- coding: utf-8 -*-
"""EVS tests: typing, legacy import, coverage routing, prompt rendering."""

import json
import tempfile
import unittest
from pathlib import Path

from src.spec_model import (Claim, FieldLayout, VulnSpec, from_legacy, load)


def _native() -> VulnSpec:
    spec = VulnSpec(cve_id="CVE-X", component="cuobjdump", cwe="CWE-125")
    spec.anchor.binary = "cuobjdump"
    spec.anchor.invocation = ["cuobjdump", "{artifact}"]
    spec.anchor.baseline_recipe = "nvcc -cubin x.cu"
    spec.anchor.versions.min = "11.0"
    spec.anchor.versions.fixed_in = "13.0"
    spec.parser.entry_function = "parse"
    spec.parser.loop_pseudocode = "while(true){}"
    spec.parser.consumed_fields = [FieldLayout(name="size", offset=8, size=4,
                                               bound_check="none")]
    spec.observable.value = "SIGSEGV"
    spec.oracle.field = "size"
    spec.oracle.condition = "no bound check"
    return spec


class TestSpecModel(unittest.TestCase):
    def test_complete_spec_routes_to_direct_mutation(self):
        spec = _native()
        self.assertAlmostEqual(spec.operational_coverage(), 1.0)
        self.assertEqual(spec.strategy, "MUTATE_DIRECT")

    def test_empty_spec_starts_with_reconnaissance(self):
        self.assertEqual(VulnSpec(cve_id="CVE-Y").strategy, "RECON_FIRST")

    def test_missing_field_layout_blocks_direct_mutation(self):
        # Coverage can stay high from the anchor alone, but without knowing
        # which fields the parser consumes there is nothing to aim at.
        spec = _native()
        spec.parser.consumed_fields = []
        self.assertNotEqual(spec.strategy, "MUTATE_DIRECT")

    def test_unchecked_fields_are_the_mutation_targets(self):
        spec = _native()
        spec.parser.consumed_fields.append(
            FieldLayout(name="index", offset=12, size=4, bound_check="range"))
        unchecked = [f.name for f in spec.parser.unchecked_fields()]
        self.assertEqual(unchecked, ["size"])

    def test_brief_lists_gaps_and_refuted_hypotheses(self):
        spec = _native()
        spec.anchor.baseline_recipe = ""
        spec.history.refuted = ["magic alone does not crash"]
        brief = spec.prompt_brief()
        self.assertIn("[EVS] CVE-X", brief)
        self.assertIn("already refuted", brief)
        self.assertIn("baseline_recipe", brief)
        self.assertIn("field size", brief)

    def test_claim_provenance_decides_operational_status(self):
        self.assertFalse(Claim(value="x", verified_by="advisory").is_operational)
        self.assertTrue(Claim(value="x", verified_by="reverse_engineering").is_operational)

    def test_save_and_load_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _native().save(Path(tmp) / "spec.json")
            self.assertEqual(load(path).cve_id, "CVE-X")

    def test_legacy_import_is_advisory_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "CVE-LEGACY"
            d.mkdir()
            (d / "3_affected_component.json").write_text(json.dumps({
                "affected_component": {"name": "cuobjdump",
                                       "version_range": "< 13.0",
                                       "file_format_input": "cubin",
                                       "vulnerable_function": "parse"}}),
                encoding="utf-8")
            (d / "7_root_cause.json").write_text(json.dumps({
                "root_cause": {"function": "parse",
                               "vulnerable_code_summary": "while(true)"}}),
                encoding="utf-8")
            spec = from_legacy(d)
            self.assertEqual(spec.origin, "legacy")
            self.assertEqual(spec.parser.entry_function, "parse")
            self.assertEqual(spec.parser.consumed_fields, [])
            self.assertLess(spec.operational_coverage(), 0.6)
            self.assertTrue(all(c.verified_by == "advisory"
                                for c in spec.claims.values()))


class TestWriteBack(unittest.TestCase):
    def test_run_history_is_appended_to_the_spec(self):
        from src.closed_loop import IterationRecord, LoopResult
        from src.loop_runner import record_history

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "specs" / "CVE-X"
            directory.mkdir(parents=True)
            VulnSpec(cve_id="CVE-X").save(directory / "spec.json")
            result = LoopResult(
                cve_id="CVE-X", status="EXHAUSTED", iterations_used=2,
                final_verdict="NOT_VERIFIED",
                trace=[IterationRecord(iteration=1, verdict="NOT_VERIFIED",
                                       diagnosis_code="NO_EFFECT"),
                       IterationRecord(iteration=2, verdict="SUPPORTED")])
            record_history(result, root)
            reloaded = load(directory / "spec.json")
            self.assertEqual(len(reloaded.history.attempts), 2)
            self.assertEqual(reloaded.history.attempts[0].diagnosis, "NO_EFFECT")

    def test_missing_spec_is_silently_skipped(self):
        from src.closed_loop import LoopResult
        from src.loop_runner import record_history
        with tempfile.TemporaryDirectory() as tmp:
            record_history(LoopResult(cve_id="CVE-NONE", status="ERROR",
                                      iterations_used=0), Path(tmp))

    def test_crashing_malicious_artifact_becomes_positive_knowledge(self):
        # What crashed once should be reused, not rediscovered.
        from src.closed_loop import IterationRecord, LoopResult
        from src.loop_runner import record_history

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "specs" / "CVE-X"
            directory.mkdir(parents=True)
            VulnSpec(cve_id="CVE-X").save(directory / "spec.json")
            workdir = root / "run"
            workdir.mkdir()
            (workdir / "iteration_1_observation.txt").write_text(
                "[CPG_LABEL] benign.cubin BENIGN\n[CPG_RUN] benign.cubin exit=0\n"
                "[CPG_LABEL] mallory.cubin MALICIOUS\n[CPG_RUN] mallory.cubin exit=-11\n",
                encoding="utf-8")
            result = LoopResult(cve_id="CVE-X", status="SUPPORTED",
                                iterations_used=1, final_verdict="SUPPORTED",
                                trace=[IterationRecord(iteration=1,
                                                       verdict="SUPPORTED")])
            record_history(result, root, workdir=workdir)
            reloaded = load(directory / "spec.json")
        self.assertEqual(reloaded.history.observed, ["mallory.cubin exit=-11"])
        self.assertIn("observed to crash", reloaded.prompt_brief())

    def test_a_benign_crash_is_not_recorded_as_a_win(self):
        from src.closed_loop import IterationRecord, LoopResult
        from src.loop_runner import record_history

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "specs" / "CVE-Y"
            directory.mkdir(parents=True)
            VulnSpec(cve_id="CVE-Y").save(directory / "spec.json")
            workdir = root / "run"
            workdir.mkdir()
            (workdir / "iteration_1_observation.txt").write_text(
                "[CPG_RUN] benign.cubin exit=-11\n", encoding="utf-8")
            record_history(LoopResult(cve_id="CVE-Y", status="EXHAUSTED",
                                      iterations_used=1), root, workdir=workdir)
            self.assertEqual(load(directory / "spec.json").history.observed, [])


if __name__ == "__main__":
    unittest.main()
