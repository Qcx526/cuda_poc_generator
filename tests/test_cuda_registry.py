"""Pure CUDA registry/ELF tests: synthetic bytes are NEVER sent to native tools."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from src import cuda_registry as registry
from src.models.platform import PlatformSnapshot, seal_snapshot
from src.models.tool_result import ToolIdentity
from src.tools.elf_ops import append_section
from tests.test_elf_tools import fixture, change_header, change_section
from tests.test_platform_probe import packet


def synthetic_cuda_elf(*, kernel=True, body=b"SYNTHETIC NONEXECUTABLE GPU TEXT"):
    """Legal structural fixture, not actual CUDA code or a real compiler output."""
    data = change_header(change_header(fixture(), 18, "<H", 190), 16, "<H", 2)
    return append_section(data, registry.CUDA_SMOKE_KERNEL_SECTION, body) if kernel else data


def synthetic_tools():
    return {role: ToolIdentity(requested_executable="/tools/" + name, resolved_path="/tools/" + name,
                                status="OBSERVED", file_sha256="a" * 64,
                                source="synthetic offline identity; no tool is launched")
            for role, name in (("nvcc", "nvcc"), ("cuobjdump", "cuobjdump"),
                               ("nvdisasm", "nvdisasm"), ("host_compiler", "g++"),
                               ("guard_python", "python3.10"))}


class TestCudaRegistry(unittest.TestCase):
    def setUp(self):
        self.snapshot = PlatformSnapshot.model_validate(packet(gpu=b"0, Fixture GPU A, 7.5, 555.42\n")["snapshot"])
        selected = patch("src.tools.compile.current_platform_type", return_value="wsl")
        selected.start()
        self.addCleanup(selected.stop)

    def choose(self, arch=None, snapshot=None, nvcc="/tools/nvcc"):
        return registry.select_cuda_arch(arch, self.snapshot if snapshot is None else snapshot,
                                         expected_nvcc_path=nvcc)

    def test_source_registry_matches_reviewed_fixture_bytes(self):
        action = registry.get_cuda_smoke_action()
        self.assertEqual(action.fixture_id, "p2c-cuda-smoke-v1")
        self.assertEqual(Path(action.relative_path).read_bytes(), action.source)
        self.assertEqual(hashlib.sha256(action.source).hexdigest(), action.sha256)
        self.assertTrue(action.source.endswith(b"\n"))
        self.assertIn(b'extern "C" __global__ void cuda_poc_safe_smoke() {}', action.source)
        for token in (b"main(", b"<<<", b"cudaMalloc", b"cudaLaunch", b"#include", b"asm("):
            self.assertNotIn(token, action.source)
        with self.assertRaises(FrozenInstanceError):
            action.source = b"unreviewed source"

    def test_arch_none_derives_only_from_observed_compute_capability(self):
        self.assertEqual(self.choose(), "sm_75")
        self.assertEqual(self.choose("sm_75"), "sm_75")

    def test_explicit_arch_must_match_gpu_even_when_nvcc_supports_it(self):
        with self.assertRaisesRegex(ValueError, "observed target GPU"):
            self.choose("sm_86")

    def test_arch_requires_observed_gpu_and_all_capabilities(self):
        for snapshot in (packet(gpu=b"")["snapshot"], packet(missing=("nvidia-smi",))["snapshot"],
                         packet(unsupported_cap=True)["snapshot"]):
            with self.subTest(snapshot=snapshot["gpu_devices"]["status"]), self.assertRaises(ValueError):
                self.choose("sm_75", snapshot=snapshot)

    def test_multiple_gpu_architectures_require_explicit_observed_selection(self):
        snapshot = packet()["snapshot"]
        with self.assertRaisesRegex(ValueError, "multiple GPU architectures"):
            self.choose(snapshot=snapshot)
        self.assertEqual(self.choose("sm_86", snapshot=snapshot), "sm_86")

    def test_missing_tool_and_failed_version_have_no_default_arch(self):
        for snapshot in (packet(missing=("nvcc",))["snapshot"], packet(failures=("nvcc_version",))["snapshot"]):
            with self.subTest(snapshot=snapshot["nvcc_version"]["status"]), self.assertRaises(ValueError):
                self.choose("sm_75", snapshot=snapshot)

    def test_arch_missing_from_observed_nvcc_supported_list_is_rejected(self):
        snapshot = packet(gpu=b"0, Fixture GPU A, 8.0, 555.42\n")["snapshot"]
        with self.assertRaisesRegex(ValueError, "observed nvcc supported"):
            self.choose("sm_80", snapshot=snapshot)

    def test_foreign_tool_path_or_backend_cannot_inherit_snapshot_capabilities(self):
        with self.assertRaises(ValueError):
            self.choose(nvcc="/different/nvcc")
        raw = self.snapshot.model_dump(mode="python")
        raw["execution_backend"] = "local"
        with self.assertRaises(ValueError):
            self.choose(snapshot=seal_snapshot(raw))

    def test_malicious_arch_and_windows_tool_paths_are_rejected(self):
        for arch in ("sm_75; whoami", "sm_75 --run", "native", "all", "compute_75", "", None):
            if arch is None:
                continue
            with self.subTest(arch=arch), self.assertRaises(ValueError):
                self.choose(arch)
        for path in (r"C:\CUDA\nvcc.exe", "relative/nvcc", "/tools/../nvcc", "/tools/nvcc\n--run"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.choose(nvcc=path)

    def test_exact_fixed_compile_argv_has_no_extra_option_channel(self):
        argv = registry.build_cuda_step_argv("compile", synthetic_tools(), "sm_75", "/private/job")
        self.assertEqual(argv, ["/tools/nvcc", "--cubin", "--gpu-architecture=sm_75", "--std=c++14",
                                "--compiler-bindir=/tools/g++", "--output-file", "/private/job/out/safe_smoke.cubin",
                                "/private/job/safe_smoke.cu"])
        self.assertNotIn("--run", argv)
        self.assertNotIn("--options-file", argv)

    def test_version_commands_and_native_inspection_commands_are_fixed(self):
        tools = synthetic_tools()
        for role in ("nvcc", "cuobjdump", "nvdisasm"):
            self.assertEqual(registry.build_cuda_step_argv(role + "_version", tools, None, "/job"),
                             ["/tools/" + role, "--version"])
        self.assertEqual(registry.build_cuda_step_argv("cuobjdump", tools, "sm_75", "/job"),
                         ["/tools/cuobjdump", "--dump-elf", "/job/out/safe_smoke.cubin"])
        self.assertEqual(registry.build_cuda_step_argv("nvdisasm", tools, "sm_75", "/job"),
                         ["/tools/nvdisasm", "--no-dataflow", "/job/out/safe_smoke.cubin"])

    def test_unknown_step_and_tool_role_fail_closed(self):
        for step in ("execute", "nvcc --run", "SHELL", ""):
            with self.subTest(step=step), self.assertRaises(ValueError):
                registry.build_cuda_step_argv(step, synthetic_tools(), "sm_75", "/job")
        tools = synthetic_tools()
        tools["untrusted"] = tools["nvcc"]
        with self.assertRaises(ValueError):
            registry.build_cuda_step_argv("compile", tools, "sm_75", "/job")

    def test_unknown_replaced_or_mislabelled_tool_identity_is_rejected(self):
        for mutation in ("unknown", "basename", "boolhash"):
            tools = synthetic_tools()
            identity = tools["nvcc"].model_dump(mode="python")
            if mutation == "unknown":
                identity.update(status="UNKNOWN", file_sha256=None)
            elif mutation == "basename":
                identity["resolved_path"] = "/tools/other"
            else:
                identity["file_sha256"] = True
            tools["nvcc"] = identity
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                registry.build_cuda_step_argv("compile", tools, "sm_75", "/job")

    def test_workspace_path_is_target_posix_and_canonical(self):
        for path in (r"C:\job", "relative", "/job/../other", "/job//other", "//server/share", "/job\nnext"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                registry.build_cuda_step_argv("compile", synthetic_tools(), "sm_75", path)


class TestCudaSmokeElf(unittest.TestCase):
    def test_supported_synthetic_elf_observation_is_explicitly_not_execution(self):
        data = synthetic_cuda_elf()
        result = registry.validate_smoke_cubin_bytes(data)
        self.assertEqual(result["e_machine"], 190)
        self.assertEqual(result["e_type"], 2)
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["kernel_section"], ".text.cuda_poc_safe_smoke")
        self.assertEqual(result["candidate_execution_status"], "NOT_EXECUTED")
        self.assertEqual(result["verification_status"], "NOT_VERIFIED")

    def test_hash_replacement_is_rejected_before_native_inspection(self):
        data = synthetic_cuda_elf()
        self.assertEqual(registry.validate_smoke_cubin_bytes(data, expected_sha256=hashlib.sha256(data).hexdigest())["size_bytes"], len(data))
        for digest in ("0" * 64, "not-a-hash", True):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                registry.validate_smoke_cubin_bytes(data, expected_sha256=digest)

    def test_machine_type_and_fixed_kernel_text_are_required(self):
        for data in (fixture(), change_header(synthetic_cuda_elf(), 18, "<H", 62),
                     change_header(synthetic_cuda_elf(), 16, "<H", 1),
                     synthetic_cuda_elf(kernel=False), synthetic_cuda_elf(body=b"")):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                registry.validate_smoke_cubin_bytes(data)

    def test_unsupported_elf_variants_and_truncated_tables_are_rejected(self):
        base = synthetic_cuda_elf()
        elf32, big_endian = bytearray(base), bytearray(base)
        elf32[4], big_endian[5] = 1, 2
        for data in (bytes(elf32), bytes(big_endian), base[:63], base[:-1], b"not an ELF" * 12,
                     change_header(base, 0x3C, "<H", 0), change_header(base, 0x3E, "<H", 0xFFFF)):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                registry.validate_smoke_cubin_bytes(data)

    def test_section_payload_out_of_bounds_is_rejected_without_native_tools(self):
        data = change_section(synthetic_cuda_elf(), 2, 24, "<Q", 0xFFFFFFFFFFFF)
        with self.assertRaisesRegex(ValueError, "content range"):
            registry.validate_smoke_cubin_bytes(data)

    def test_file_read_checks_missing_size_and_real_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder).resolve() / "safe_smoke.cubin"
            with self.assertRaisesRegex(ValueError, "missing"):
                registry.observe_smoke_cubin(path)
            path.write_bytes(synthetic_cuda_elf())
            observed = registry.observe_smoke_cubin(path)
            self.assertEqual(observed["size_bytes"], path.stat().st_size)
            with self.assertRaisesRegex(ValueError, "file-size limit"):
                registry.observe_smoke_cubin(path, max_cubin_bytes=64)
            path.write_bytes(b"replacement")
            with self.assertRaises(ValueError):
                registry.observe_smoke_cubin(path, expected_sha256=observed["sha256"])

    def test_invalid_byte_limits_and_nonbytes_inputs_are_rejected(self):
        for limit in (True, 0, 63, 268435457):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                registry.validate_smoke_cubin_bytes(synthetic_cuda_elf(), max_cubin_bytes=limit)
        for data in ("ELF", bytearray(synthetic_cuda_elf())):
            with self.subTest(type=type(data)), self.assertRaises(ValueError):
                registry.validate_smoke_cubin_bytes(data)


if __name__ == "__main__":
    unittest.main()
