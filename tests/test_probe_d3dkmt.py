# -*- coding: utf-8 -*-
"""D3DKMT structs are positional; a wrong size is an invalid parameter, not an error."""

import ctypes
import unittest

from tools.probe_d3dkmt import CREATEDEVICE, ESCAPE, OPENADAPTERFROMHDC


class TestLayout(unittest.TestCase):
    def test_open_adapter_from_hdc_is_24_bytes(self):
        self.assertEqual(ctypes.sizeof(OPENADAPTERFROMHDC), 24)
        self.assertEqual(OPENADAPTERFROMHDC.hAdapter.offset, 8)

    def test_escape_starts_with_two_handles_then_a_code(self):
        self.assertEqual(ESCAPE.hAdapter.offset, 0)
        self.assertEqual(ESCAPE.hDevice.offset, 4)
        self.assertEqual(ESCAPE.EscapeCode.offset, 8)

    def test_created_device_puts_the_returned_handle_first(self):
        """hAdapter in, hDevice out, in the same four bytes."""
        self.assertEqual(CREATEDEVICE.hAdapter.offset, 0)


if __name__ == "__main__":
    unittest.main()
