# -*- coding: utf-8 -*-
"""D3DKMT structs are positional; a wrong size is an invalid parameter, not an error.

These assertions cover every field the API writes back. An earlier version
asserted only the first member of CREATEDEVICE, so an abbreviated 24-byte
structure passed the suite while reading the wrong field.
"""

import ctypes
import unittest

from tools.probe_d3dkmt import CREATEDEVICE, ESCAPE, OPENADAPTERFROMHDC
from tools.driver import escape_probe as probe


class TestProbeLayout(unittest.TestCase):
    def test_open_adapter_from_hdc_is_24_bytes(self):
        self.assertEqual(ctypes.sizeof(OPENADAPTERFROMHDC), 24)
        self.assertEqual(OPENADAPTERFROMHDC.hDc.offset, 0)
        self.assertEqual(OPENADAPTERFROMHDC.hAdapter.offset, 8)
        self.assertEqual(OPENADAPTERFROMHDC.AdapterLuid.offset, 12)
        self.assertEqual(OPENADAPTERFROMHDC.VidPnSourceId.offset, 20)

    def test_escape_type_precedes_flags(self):
        """WDK order is Type at 8 and Flags at 12; the reverse is a silent misuse."""
        self.assertEqual(ctypes.sizeof(ESCAPE), 32)
        self.assertEqual(ESCAPE.hAdapter.offset, 0)
        self.assertEqual(ESCAPE.hDevice.offset, 4)
        self.assertEqual(ESCAPE.Type.offset, 8)
        self.assertEqual(ESCAPE.Flags.offset, 12)
        self.assertEqual(ESCAPE.pPrivateDriverData.offset, 16)
        self.assertEqual(ESCAPE.PrivateDriverDataSize.offset, 24)
        self.assertEqual(ESCAPE.hContext.offset, 28)

    def test_created_device_is_the_full_64_bytes(self):
        self.assertEqual(ctypes.sizeof(CREATEDEVICE), 64)
        self.assertEqual(CREATEDEVICE.hAdapter.offset, 0)
        self.assertEqual(CREATEDEVICE.Flags.offset, 8)
        self.assertEqual(CREATEDEVICE.hDevice.offset, 12)
        self.assertEqual(CREATEDEVICE.pCommandBuffer.offset, 16)
        self.assertEqual(CREATEDEVICE.PatchLocationListSize.offset, 56)


class TestEscapeProbeLayout(unittest.TestCase):
    """The probe that produces new results must match the same WDK layout."""

    def test_escape_has_type_at_8(self):
        self.assertEqual(ctypes.sizeof(probe.D3DKMT_ESCAPE), 32)
        self.assertEqual(probe.D3DKMT_ESCAPE.Type.offset, 8)
        self.assertEqual(probe.D3DKMT_ESCAPE.Flags.offset, 12)

    def test_created_device_is_not_abbreviated(self):
        self.assertEqual(ctypes.sizeof(probe.D3DKMT_CREATEDEVICE), 64)
        self.assertEqual(probe.D3DKMT_CREATEDEVICE.Flags.offset, 8)
        self.assertEqual(probe.D3DKMT_CREATEDEVICE.hDevice.offset, 12)

    def test_create_device_records_equality_without_judging_it(self):
        """Equality is an observation, not a verdict.

        The earlier version treated hDevice == hAdapter as proof of a misread
        field. d3dkmthk.h does not say that, and GetDeviceState returns success
        for such a handle, so the probe now records the coincidence and leaves
        validity to a documented query.
        """

        class FakeGdi:
            @staticmethod
            def D3DKMTCreateDevice(ref):
                request = ref._obj
                request.hDevice = request.hAdapter
                return 0

        original = probe.gdi32
        probe.gdi32 = FakeGdi
        try:
            result = probe.create_device(0x40000000)
        finally:
            probe.gdi32 = original

        self.assertEqual(result["status"], 0)
        self.assertTrue(result["same_value_as_adapter"])
        self.assertTrue(result["usable"], "equal value alone does not invalidate a handle")


if __name__ == "__main__":
    unittest.main()
