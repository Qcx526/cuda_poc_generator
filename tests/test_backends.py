# -*- coding: utf-8 -*-
"""Backend selection: profiles map to capabilities, gaps are named not faked."""

import os
import tempfile
import unittest
from pathlib import Path

from src.backends import (BackendRegistry, ContainerBackend, ExecutionObservation,
                          TargetProfile, WindowsNativeBackend)


class TestTargetProfile(unittest.TestCase):
    def test_tiers_map_to_platform_and_privilege(self):
        self.assertEqual(TargetProfile.for_tier("userland_toolchain"),
                         TargetProfile(platform="linux", privilege="user",
                                       medium="file", device="none"))
        driver = TargetProfile.for_tier("driver_userland")
        self.assertEqual((driver.platform, driver.privilege, driver.device),
                         ("windows", "user", "gpu"))
        kernel = TargetProfile.for_tier("driver_kernel")
        self.assertEqual(kernel.privilege, "kernel")


class TestRegistry(unittest.TestCase):
    def test_kernel_profile_has_no_backend_on_purpose(self):
        registry = BackendRegistry()
        profile = TargetProfile.for_tier("driver_kernel")
        self.assertIsNone(registry.select(profile))
        self.assertIn("NEEDS_BACKEND", registry.describe(profile))

    def test_windows_userland_selects_the_native_backend(self):
        registry = BackendRegistry([WindowsNativeBackend(), ContainerBackend()])
        chosen = registry.select(TargetProfile.for_tier("driver_userland"))
        if os.name == "nt":
            self.assertIsNotNone(chosen)
            self.assertEqual(chosen.name, "windows_native")
        else:
            self.assertIsNone(chosen)

    def test_linux_file_profile_never_selects_a_windows_backend(self):
        registry = BackendRegistry([WindowsNativeBackend()])
        self.assertIsNone(registry.select(TargetProfile.for_tier("userland_toolchain")))


class TestObservation(unittest.TestCase):
    def test_crash_is_recognised_from_the_exit_code_alone(self):
        self.assertTrue(ExecutionObservation(backend="x", exit_code=-11).crashed)
        self.assertFalse(ExecutionObservation(backend="x", exit_code=0).crashed)
        self.assertFalse(ExecutionObservation(backend="x").crashed)


class TestDriverStageGate(unittest.TestCase):
    def test_without_opt_in_a_driver_probe_is_refused_not_run(self):
        from src.closed_loop import LoopConfig, LoopState, TargetTier, docker_matrix_stage
        with tempfile.TemporaryDirectory() as tmp:
            stage = docker_matrix_stage(
                LoopConfig(cve_id="CVE-X", tier=TargetTier.DRIVER_USERLAND,
                           samples_dir=tmp), [])
            state = stage(LoopState(iteration=1, candidate_file=str(Path(tmp) / "p.py")))
        self.assertTrue(state.stage_error.startswith(("NEEDS_BACKEND",
                                                      "PLATFORM_UNAVAILABLE")))
        self.assertIsNone(state.reached)


if __name__ == "__main__":
    unittest.main()
