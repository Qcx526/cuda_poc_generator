# -*- coding: utf-8 -*-
"""Struct layouts must match the header, or every later result is noise."""

import ctypes
import unittest

from tools.probe_nvapi_calls import (NAME_LEN, THERMAL_SENSORS, ThermalSettings,
                                     thermal_version)


class TestLayout(unittest.TestCase):
    def test_the_version_word_encodes_size_and_version(self):
        version = thermal_version()
        self.assertEqual(version & 0xFFFF, ctypes.sizeof(ThermalSettings))
        self.assertEqual(version >> 16, 1)

    def test_sensor_array_has_three_slots(self):
        self.assertEqual(THERMAL_SENSORS, 3)
        self.assertEqual(len(ThermalSettings().sensor), 3)

    def test_a_sensor_is_twenty_bytes(self):
        from tools.probe_nvapi_calls import Sensor
        self.assertEqual(ctypes.sizeof(Sensor), 20)

    def test_the_name_buffer_is_the_declared_size(self):
        self.assertEqual(NAME_LEN, 64)


if __name__ == "__main__":
    unittest.main()
