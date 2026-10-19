"""Offline target-environment classification; no process is launched."""

import unittest
from pathlib import Path

from pydantic import ValidationError

from src.target_profile import (
    TargetEnvironmentProfile,
    classify_target,
    profile_from_input_dir,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INPUTS = PROJECT_ROOT / "data" / "inputs"


def dimensions(**overrides):
    """Minimal well-formed dimensions with one explicit override target."""
    base = {
        "os_environment": {"cve_id": "CVE-2099-0001", "operating_systems": ["Linux (x86_64)"]},
        "cuda_environment": {"cve_id": "CVE-2099-0001", "affected_tools": ["cuobjdump"],
                             "gpu_architecture": "N/A（纯 CPU 工具）",
                             "cuda_driver_version": "Not required"},
        "affected_component": {"cve_id": "CVE-2099-0001", "name": "cuobjdump — parser",
                               "type": "命令行工具", "file_format_input": "ELF / cubin"},
        "attack_surface": {"cve_id": "CVE-2099-0001", "entry_type": "本地文件输入",
                           "entry_point": "cuobjdump --dump-elf <file>"},
        "vulnerability_type": {"cve_id": "CVE-2099-0001"},
        "impact_controllability": {"cve_id": "CVE-2099-0001"},
        "root_cause": {"cve_id": "CVE-2099-0001"},
    }
    for key, value in overrides.items():
        base[key] = {**base.get(key, {}), **value}
    return base


class TestRepositoryCves(unittest.TestCase):
    def test_every_repository_input_is_classifiable_and_valid(self):
        cves = sorted(p.name for p in INPUTS.iterdir() if p.is_dir())
        self.assertEqual(len(cves), 23)
        counts = {}
        for name in cves:
            profile = profile_from_input_dir(str(INPUTS / name))
            self.assertEqual(profile.cve_id, name)
            self.assertTrue(profile.tools or profile.environment_class == "UNKNOWN", name)
            self.assertTrue(profile.reasons, name)
            counts[profile.environment_class] = counts.get(profile.environment_class, 0) + 1
        # Three isolation tiers cover the corpus; driver targets stay manual.
        self.assertEqual(counts, {"USERLAND_TOOL": 16, "DRIVER": 4,
                                  "GPU_LIBRARY": 2, "NETWORK_SERVICE": 1})

    def test_toolchain_cves_are_cpu_containers(self):
        for name in sorted(p.name for p in INPUTS.iterdir() if p.is_dir()):
            profile = profile_from_input_dir(str(INPUTS / name))
            if profile.environment_class != "USERLAND_TOOL":
                continue
            self.assertFalse(profile.requires_gpu, name)
            self.assertEqual(profile.isolation_tier, "CONTAINER_CPU", name)
            self.assertEqual(profile.automation_tier, "FULL_AUTO", name)

    def test_cpu_tool_is_never_promoted_to_gpu_by_the_cuda_label(self):
        # "CUDA Toolkit" appears in the component label of CPU tools; it must
        # not be read as a GPU dependency.
        profile = profile_from_input_dir(str(INPUTS / "CVE-2025-23339"))
        self.assertFalse(profile.requires_gpu)
        self.assertEqual(profile.isolation_tier, "CONTAINER_CPU")


class TestClassificationRules(unittest.TestCase):
    def test_driver_component_needs_a_dedicated_host(self):
        profile = classify_target(dimensions(
            affected_component={"name": "NVIDIA GPU Display Driver", "type": "内核显示驱动"},
            cuda_environment={"gpu_architecture": "sm_75"},
        ))
        self.assertEqual(profile.environment_class, "DRIVER")
        self.assertEqual(profile.isolation_tier, "DEDICATED_HOST")
        self.assertEqual(profile.automation_tier, "MANUAL_ONLY")
        self.assertTrue(profile.requires_gpu)

    def test_negated_driver_wording_is_not_a_driver_target(self):
        # Inputs routinely write "非驱动" to rule the driver class out.
        profile = classify_target(dimensions(
            affected_component={"name": "Triton Inference Server",
                                "type": "推理服务（HTTP/gRPC 服务端），非命令行工具、非驱动"},
            attack_surface={"entry_type": "网络请求", "entry_point": "https://host:8000/v2/models"},
            cuda_environment={"gpu_architecture": "与本 CVE 无关", "affected_tools": ["triton"]},
        ))
        self.assertEqual(profile.environment_class, "NETWORK_SERVICE")
        self.assertEqual(profile.automation_tier, "SUPERVISED")

    def test_gpu_library_with_na_architecture_still_requires_a_device(self):
        profile = classify_target(dimensions(
            affected_component={"name": "CV-CUDA", "type": "Python 库（长驻进程内使用）"},
            cuda_environment={"gpu_architecture": "N/A（缺陷在 Python API 层）",
                              "affected_tools": ["CV-CUDA"]},
            attack_surface={"entry_type": "API 调用", "entry_point": "python api"},
        ))
        self.assertEqual(profile.environment_class, "GPU_LIBRARY")
        self.assertTrue(profile.requires_gpu)
        self.assertEqual(profile.automation_tier, "GPU_WATCHDOG")

    def test_component_name_is_not_split_on_ascii_hyphen(self):
        profile = classify_target(dimensions(
            affected_component={"name": "CV-CUDA — image codec", "type": "Python 库"},
        ))
        self.assertIn("CV-CUDA", profile.tools)
        self.assertNotIn("CV", profile.tools)

    def test_undeclared_target_is_not_granted_automation(self):
        profile = classify_target({
            "affected_component": {"cve_id": "CVE-2099-0002"},
            "cuda_environment": {},
            "attack_surface": {},
        })
        self.assertEqual(profile.environment_class, "UNKNOWN")
        self.assertEqual(profile.automation_tier, "NOT_ALLOWED")
        self.assertEqual(profile.isolation_tier, "UNCLASSIFIED")

    def test_missing_cve_identifier_is_rejected(self):
        with self.assertRaises(ValueError):
            classify_target({"affected_component": {}, "cuda_environment": {}})

    def test_profile_rejects_extra_fields_and_unknown_class(self):
        payload = {
            "cve_id": "CVE-2099-0001", "environment_class": "USERLAND_TOOL",
            "requires_gpu": False, "tools": ["cuobjdump"], "input_kind": "FILE",
            "needs_network": False, "isolation_tier": "CONTAINER_CPU",
            "automation_tier": "FULL_AUTO", "reasons": ["test"], "extra": 1,
        }
        with self.assertRaises(ValidationError):
            TargetEnvironmentProfile.model_validate(payload)
        payload.pop("extra")
        payload["environment_class"] = "SOMETHING_ELSE"
        with self.assertRaises(ValidationError):
            TargetEnvironmentProfile.model_validate(payload)

    def test_classification_is_deterministic_and_pure(self):
        first = classify_target(dimensions())
        second = classify_target(dimensions())
        self.assertEqual(first.model_dump(), second.model_dump())
        self.assertEqual(first.profile_schema_version, "1.0")


if __name__ == "__main__":
    unittest.main()
