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
    """The parser is checked against whatever nvapi64.dll is installed.

    That file changes with every driver update, so the assertion cannot be a fixed
    count: 610.47 does not import DeviceIoControl at all, while 551.61 did, and a
    test that pins the number fails for a reason that has nothing to do with the
    parser. What is invariant is the relationship - if the name appears in the
    import table, the parser finds it at the right address.
    """

    def _imports_device_io_control(self, image) -> bool:
        return b"DeviceIoControl\x00" in image.data

    def test_the_import_directory_is_read_at_the_descriptor(self):
        """A wrong descriptor offset reports 'imports nothing' very convincingly."""
        path = os.path.join(os.environ["WINDIR"], "System32", "nvapi64.dll")
        with open(path, "rb") as handle:
            image = Image(handle.read())
        if not self._imports_device_io_control(image):
            self.skipTest("installed nvapi64.dll does not import DeviceIoControl")
        slots = import_slots(image, "DeviceIoControl")
        self.assertGreaterEqual(len(slots), 1)

    def test_some_imports_are_found_at_all(self):
        """The parser must not silently return nothing for a real PE."""
        path = os.path.join(os.environ["WINDIR"], "System32", "nvapi64.dll")
        with open(path, "rb") as handle:
            image = Image(handle.read())
        self.assertTrue(import_slots(image, "LoadLibraryA")
                        or import_slots(image, "GetProcAddress")
                        or import_slots(image, "DeviceIoControl"),
                        "no known import resolved - the directory walk is broken")


if __name__ == "__main__":
    unittest.main()
