# -*- coding: utf-8 -*-
"""The scanner must find immediates by shape, and only in the vendor range."""

import struct
import unittest

from tools.extract_escape_codes import plausible, scan, summarise


class TestScan(unittest.TestCase):
    def test_mov_eax_immediate_is_found(self):
        data = b"\xB8" + struct.pack("<I", 0x10001002) + b"\x90" * 4
        self.assertEqual(scan(data).get(0x10001002), 1)

    def test_cmp_with_rex_prefix_is_found(self):
        # The unprefixed form matches the same bytes, so the count can be two;
        # what matters is that the value is found at all.
        data = b"\x41\x81\xF8" + struct.pack("<I", 0x10000801) + b"\x90" * 4
        self.assertGreaterEqual(scan(data).get(0x10000801, 0), 1)

    def test_values_outside_the_range_are_ignored(self):
        data = b"\xB8" + struct.pack("<I", 0x00401000) + b"\x90" * 4
        self.assertEqual(scan(data), {})

    def test_plausibility_rejects_prefixed_noise(self):
        self.assertTrue(plausible(0x10000801))
        self.assertFalse(plausible(0x1000BAFF))   # too large a function number
        self.assertFalse(plausible(0x20000001))   # wrong prefix

    def test_summary_is_ordered_by_how_often_a_code_appears(self):
        rows = summarise({0x10000001: 2, 0x10000002: 9})
        self.assertEqual([row["value"] for row in rows], [0x10000002, 0x10000001])


if __name__ == "__main__":
    unittest.main()


class TestDriverSelection(unittest.TestCase):
    def test_windows_version_maps_to_the_nvidia_number(self):
        from tools.extract_escape_codes import nvidia_version

        self.assertEqual(nvidia_version("31.0.15.3598"), "535.98")
        self.assertEqual(nvidia_version("32.0.15.6094"), "560.94")
        self.assertEqual(nvidia_version("27.21.14.6089"), "460.89")

    def test_the_loaded_driver_is_selected_not_the_newest(self):
        """The DriverStore keeps every version; mtime picks the wrong one."""
        from tools.extract_escape_codes import (driver_path, file_version,
                                                loaded_driver_version,
                                                nvidia_version)

        want = loaded_driver_version()
        if not want:
            self.skipTest("the loaded driver version is not readable here")
        path = driver_path()
        self.assertEqual(nvidia_version(file_version(path)), want)
