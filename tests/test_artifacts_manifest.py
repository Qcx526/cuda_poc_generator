# -*- coding: utf-8 -*-
"""Roles come from the submission, not from a filename convention."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src import artifacts_manifest as manifest_mod


class TestManifest(unittest.TestCase):
    def _write(self, root: Path, payload) -> None:
        (root / "benign.cubin").write_bytes(b"\x7fELF")
        (root / "poc.cubin").write_bytes(b"\x7fELF")
        (root / "ctrl.cubin").write_bytes(b"\x7fELF")
        text = payload if isinstance(payload, str) else json.dumps(payload)
        (root / manifest_mod.MANIFEST_NAME).write_text(text, encoding="utf-8")

    def test_roles_come_from_the_manifest(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(root, {"benign": ["benign.cubin"], "crafted": ["poc.cubin"],
                               "controls": ["ctrl.cubin"]})
            pairs = manifest_mod.entries(manifest_mod.load(root), root)
            self.assertEqual(dict(pairs),
                             {"benign.cubin": "BENIGN", "poc.cubin": "MALICIOUS",
                              "ctrl.cubin": "CONTROL"})
            self.assertEqual(manifest_mod.validate(manifest_mod.load(root), pairs), [])

    def test_a_declared_file_that_does_not_exist_is_dropped(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(root, {"benign": ["benign.cubin"], "crafted": ["ghost.cubin"]})
            pairs = manifest_mod.entries(manifest_mod.load(root), root)
            self.assertNotIn("ghost.cubin", dict(pairs))
            self.assertTrue(manifest_mod.validate(manifest_mod.load(root), pairs))

    def test_missing_manifest_is_a_problem_not_a_guess(self):
        with TemporaryDirectory() as tmp:
            self.assertIsNone(manifest_mod.load(Path(tmp)))
            self.assertTrue(manifest_mod.validate(None, []))

    def test_invalid_json_raises_instead_of_passing_silently(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write(root, "{not json")
            with self.assertRaises(manifest_mod.ManifestError):
                manifest_mod.load(root)

    def test_label_lines_use_the_format_the_grader_reads(self):
        lines = manifest_mod.label_lines([("poc.cubin", "MALICIOUS")])
        self.assertEqual(lines, ["[CPG_LABEL] poc.cubin MALICIOUS"])


if __name__ == "__main__":
    unittest.main()
