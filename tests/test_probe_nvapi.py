# -*- coding: utf-8 -*-
"""Enumeration must read the real export table, not a remembered list."""

import os
import unittest
from pathlib import Path

from tools.probe_nvapi_functions import KNOWN_FUNCTIONS, pe_exports


class TestExports(unittest.TestCase):
    def test_a_system_dll_exports_what_it_should(self):
        names = pe_exports(os.path.join(os.environ["WINDIR"], "System32", "kernel32.dll"))
        self.assertGreater(len(names), 100)
        self.assertIn("GetProcAddress", names)

    def test_nvapi_exports_exactly_two_symbols(self):
        names = pe_exports(os.path.join(os.environ["WINDIR"], "System32", "nvapi64.dll"))
        self.assertEqual(sorted(names),
                         ["nvapi_Direct_GetMethod", "nvapi_QueryInterface"])

    def test_a_non_pe_file_is_rejected(self):
        with self.assertRaises(ValueError):
            pe_exports(str(Path(__file__)))


class TestTable(unittest.TestCase):
    def test_ids_are_unique_and_well_formed(self):
        ids = [entry[0] for entry in KNOWN_FUNCTIONS]
        self.assertEqual(len(ids), len(set(ids)))
        for identifier in ids:
            self.assertRegex(identifier, r"^0x[0-9A-F]{8}$")

    def test_confidence_is_declared_for_every_entry(self):
        for identifier, name, confidence in KNOWN_FUNCTIONS:
            self.assertIn(confidence, {"high", "medium", "low", "none"},
                          "%s has no honest confidence" % name)


if __name__ == "__main__":
    unittest.main()
