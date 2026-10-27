# -*- coding: utf-8 -*-
"""The extractor must read what the binary does, not what a header says."""

import os
import unittest

from tools.extract_ioctls import Image, decode, import_slots


class TestDecode(unittest.TestCase):
    def test_a_ctl_code_splits_into_its_parts(self):
        parts = decode(0x0026480C)
        self.assertEqual(parts["device_type"], 0x26)
        self.assertEqual(parts["function"], 0x203)
        self.assertEqual(parts["method"], "BUFFERED")
        self.assertEqual(parts["access"], 1)

    def test_method_comes_from_the_low_two_bits(self):
        for method, expected in ((0, "BUFFERED"), (1, "IN_DIRECT"),
                                 (2, "OUT_DIRECT"), (3, "NEITHER")):
            self.assertEqual(decode(0x00260000 | method)["method"], expected)


class TestImports(unittest.TestCase):
    def test_the_import_directory_is_read_at_the_descriptor(self):
        """A wrong descriptor offset reports 'imports nothing' very convincingly."""
        path = os.path.join(os.environ["WINDIR"], "System32", "nvapi64.dll")
        with open(path, "rb") as handle:
            image = Image(handle.read())
        slots = import_slots(image, "DeviceIoControl")
        self.assertEqual(len(slots), 1)


if __name__ == "__main__":
    unittest.main()
