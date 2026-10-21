# -*- coding: utf-8 -*-
"""Input sufficiency scoring: both shapes score alike, gaps are reported."""

import json
import tempfile
import unittest
from pathlib import Path

from src.input_sufficiency import assess, assess_all, missing_note

RICH_COMPONENT = {
    "version_range": "< 13.0", "vulnerable_function": "parse_abbrev",
    "file_format_input": "cubin", "attack_entry_point": "cuobjdump --dump-elf",
}
RICH_ROOT = {"file": "cuobjdump", "function": "parse_abbrev",
             "line": 42, "vulnerable_code_summary": "while(true) decode_leb128()"}


def _write(directory: Path, component: dict, root: dict) -> None:
    (directory / "3_affected_component.json").write_text(
        json.dumps(component), encoding="utf-8")
    (directory / "7_root_cause.json").write_text(json.dumps(root), encoding="utf-8")


class TestAssess(unittest.TestCase):
    def test_complete_wrapped_input_scores_full(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "CVE-A"
            d.mkdir()
            _write(d, {"cve_id": "CVE-A", "affected_component": RICH_COMPONENT},
                   {"cve_id": "CVE-A", "root_cause": RICH_ROOT})
            result = assess(d)
            self.assertEqual(result.score, result.maximum)
            self.assertEqual(result.band, "RICH")
            self.assertEqual(result.missing, [])

    def test_flat_shape_scores_the_same_as_wrapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrapped, flat = Path(tmp) / "w", Path(tmp) / "f"
            wrapped.mkdir(); flat.mkdir()
            _write(wrapped, {"affected_component": RICH_COMPONENT}, {"root_cause": RICH_ROOT})
            _write(flat, dict(RICH_COMPONENT), dict(RICH_ROOT))
            self.assertEqual(assess(wrapped).score, assess(flat).score)

    def test_thin_input_lists_what_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "CVE-B"
            d.mkdir()
            _write(d, {"version_range": "< 12.0"}, {"line": "N/A"})
            result = assess(d)
            self.assertEqual(result.band, "THIN")
            self.assertIn("3.vulnerable_function", result.missing)
            self.assertIn("7.vulnerable_code_summary", result.missing)
            self.assertIn("missing", missing_note(result))

    def test_complete_input_needs_no_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "CVE-C"
            d.mkdir()
            _write(d, RICH_COMPONENT, RICH_ROOT)
            self.assertIsNone(missing_note(assess(d)))

    def test_missing_files_score_zero_rather_than_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "CVE-D"
            d.mkdir()
            result = assess(d)
            self.assertEqual(result.score, 0)
            self.assertEqual(len(result.missing), 8)

    def test_operational_blocks_enable_direct_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "CVE-E"
            d.mkdir()
            _write(d, RICH_COMPONENT, RICH_ROOT)
            root = {"root_cause": dict(RICH_ROOT)}
            root["root_cause"]["parser_model"] = {
                "entry_function": {"name": "parse", "rva": "0x1"},
                "consumed_fields": [{"name": "size", "offset": 8}],
                "loop_pseudocode": "while(true){}",
            }
            (d / "7_root_cause.json").write_text(json.dumps(root), encoding="utf-8")
            comp = {"affected_component": dict(RICH_COMPONENT)}
            comp["affected_component"]["executable_anchor"] = {
                "baseline_recipe": "nvcc -cubin x.cu",
                "affected_versions": {"min": "11.0", "fixed_in": "13.0"},
                "input_format": {"kind": "cubin"},
            }
            (d / "3_affected_component.json").write_text(json.dumps(comp), encoding="utf-8")
            (d / "4_attack_surface.json").write_text(json.dumps({
                "attack_surface": {"observable_signal": {"type": "exit_signal"},
                                   "invocation": {"binary": "cuobjdump"}},
            }), encoding="utf-8")
            result = assess(d)
            self.assertEqual(result.operational_score, result.operational_maximum)
            self.assertEqual(result.strategy, "MUTATE_DIRECT")

    def test_descriptive_only_input_probes_before_mutating(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "CVE-F"
            d.mkdir()
            _write(d, RICH_COMPONENT, RICH_ROOT)
            result = assess(d)
            self.assertEqual(result.operational_score, 0)
            self.assertEqual(result.strategy, "PROBE_THEN_MUTATE")

    def test_thin_input_starts_with_reconnaissance(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "CVE-G"
            d.mkdir()
            _write(d, {"version_range": "< 12.0"}, {})
            self.assertEqual(assess(d).strategy, "RECON_FIRST")


if __name__ == "__main__":
    unittest.main()
