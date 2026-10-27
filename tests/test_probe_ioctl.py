# -*- coding: utf-8 -*-
"""The dispatch probe must stay inside codes that cannot reach a handler."""

import unittest

from tools.probe_ioctl_channel import PROBE_CODES, MEANING


class TestProbeCodes(unittest.TestCase):
    def test_no_probe_code_claims_the_nvidia_device_type(self):
        """0x002b is the driver's own type; a code carrying it could reach a handler."""
        for code, label in PROBE_CODES:
            self.assertNotEqual((code >> 16) & 0xFFFF, 0x002B,
                                "%s (%s) uses the driver's device type" % (label, hex(code)))

    def test_each_code_is_sent_once(self):
        codes = [code for code, _ in PROBE_CODES]
        self.assertEqual(len(codes), len(set(codes)))

    def test_rejections_and_successes_read_differently(self):
        self.assertIn("invalid function", MEANING[1])
        self.assertIn("HANDLED", MEANING[0])


if __name__ == "__main__":
    unittest.main()


class TestHookPrimitives(unittest.TestCase):
    def test_patching_and_reading_back_a_pointer(self):
        import ctypes
        from tools.hook_deviceioctl import patch_pointer, read_pointer

        cell = (ctypes.c_void_p * 1)()
        address = ctypes.addressof(cell)
        self.assertEqual(read_pointer(address), 0)
        patch_pointer(address, 0x1234)
        self.assertEqual(read_pointer(address), 0x1234)

    def test_the_watch_starts_empty(self):
        from tools.hook_deviceioctl import Watch
        self.assertEqual(Watch().calls, [])
