# -*- coding: utf-8 -*-
"""The surface probe must be read-only and selective."""

import unittest

from tools.probe_gpu_surface import interesting


class TestFiltering(unittest.TestCase):
    def test_gpu_objects_are_kept(self):
        entries = [{"name": "NvAdminDevice", "type": "Device"},
                   {"name": "DxgKrnl", "type": "Device"},
                   {"name": "gpuenergydrv", "type": "Device"},
                   {"name": "Null", "type": "Device"},
                   {"name": "ConDrv", "type": "Device"}]
        kept = [item["name"] for item in interesting(entries)]
        self.assertEqual(kept, ["NvAdminDevice", "DxgKrnl", "gpuenergydrv"])

    def test_unrelated_devices_are_dropped(self):
        entries = [{"name": "HarddiskVolume3", "type": "Device"},
                   {"name": "Beep", "type": "Device"}]
        self.assertEqual(interesting(entries), [])


if __name__ == "__main__":
    unittest.main()
