"""Offline CUDA adapters: fake tool records and legal, nonexecuted ELF bytes."""

import base64
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from src.models.platform import seal_snapshot
from src.models.tool_result import digest_argv, seal_tool_result
from src.tools import compile as compiler
from src.tools import inspect as inspection
from src.tools import env as environment
from src.tools.process import classify_returncode, current_platform_type
from tests.test_platform_probe import packet
from tests.test_elf_tools import fixture, change_header, change_section


def legal_cuda_elf(*, relocation=False, misleading_rel=False):
    """Fixed legal ELF research fixture with synthetic EM_CUDA; never runnable."""
    data = change_header(fixture(), 18, "<H", 190)
    if not relocation:
        data = change_section(data, 6, 4, "<I", 1)
    if misleading_rel:
        data = data.replace(b".text\0", b".RELx\0")
    return data


def mock_result(argv, *, returncode=0, stdout=b"", stderr=b"", timed_out=False, truncated=False,
                started=True, **kwargs):
    platform_type = current_platform_type()
    status, signal, exception = classify_returncode(returncode, platform_type,
                                                   timed_out=timed_out, truncated=truncated, started=started)
    return seal_tool_result({"run_id": "a" * 32, "argv": list(argv), "cwd": str(Path.cwd()),
                            "target_environment": "local", "platform_type": platform_type,
                            "start_status": "STARTED" if started else "START_FAILED",
                            "end_status": status, "returncode": returncode,
                            "linux_signal": signal, "windows_exception_code": exception,
                            "timed_out": timed_out, "truncated": truncated,
                            "started_at": "2026-10-14T00:00:00+00:00",
                            "finished_at": "2026-10-14T00:00:01+00:00", "duration_seconds": 1.0,
                            "resource_limits": {"timeout_seconds": 10.0, "max_output_bytes": 4096,
                                                "termination_scope": "WINDOWS_DIRECT_CHILD" if platform_type == "windows" else "POSIX_PROCESS_GROUP",
                                                "memory_bytes": None, "cpu_seconds": None,
                                                "memory_limit_status": "NOT_ENFORCED", "cpu_limit_status": "NOT_ENFORCED"},
                            "stdout_b64": base64.b64encode(stdout).decode(),
                            "stderr_b64": base64.b64encode(stderr).decode(),
                            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                            "command_identity": {"source": "synthetic offline fixture", "argv_sha256": digest_argv(list(argv))},
                            "tool_identity": {"requested_executable": argv[0], "resolved_path": None,
                                              "status": "UNKNOWN", "file_sha256": None,
                                              "source": "mock tool, not a measured executable"},
                            "diagnostics": [], "evidence_directory": "synthetic-not-a-real-record"})


class TestCompileValidation(unittest.TestCase):
    def test_arch_is_explicit_without_a_platform(self):
        with self.assertRaises(ValueError):
            compiler.resolve_compile_arch(None)
        self.assertEqual(compiler.resolve_compile_arch("sm_90a"), "sm_90a")

    def test_malicious_and_invalid_architecture(self):
        for arch in ("sm_75;whoami", "sm_75 && dir", "compute_75", "75", "", "sm_0", "sm_75\n", 75):
            with self.subTest(arch=arch), self.assertRaises(ValueError):
                compiler.resolve_compile_arch(arch)

    def test_flag_allowlist_preserves_simple_legacy_flags(self):
        self.assertEqual(compiler.validate_compile_flags("-G -lineinfo -O2 --std=c++17"),
                         ["-G", "-lineinfo", "-O2", "--std=c++17"])
        self.assertEqual(compiler.validate_compile_flags(["--maxrregcount=255"]), ["--maxrregcount=255"])

    def test_malicious_or_external_compiler_options_are_rejected(self):
        for flags in ("-G; whoami", "-G && dir", "@args.txt", "-o evil.cubin", "-ccbin other.exe",
                      "--compiler-options=-fplugin=evil.so", "-Iprivate", "--maxrregcount=256",
                      "--options-file=evil.txt", "-Xptxas=-v", ["-G", "\n"], 9):
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                compiler.validate_compile_flags(flags)

    def test_cross_os_paths_are_rejected(self):
        foreign = "/tmp/kernel.cu" if os.name == "nt" else "C:\\private\\kernel.cu"
        with self.assertRaises(ValueError):
            compiler._local_path(foreign)

    def test_snapshot_arch_requires_single_observed_supported_target(self):
        snapshot = packet(gpu=b"0, Synthetic GPU, 7.5, 555.42\n")["snapshot"]
        with patch.object(compiler, "current_platform_type", return_value="wsl"):
            self.assertEqual(compiler.resolve_compile_arch(None, snapshot), "sm_75")
            with self.assertRaises(ValueError):
                compiler.resolve_compile_arch(None, packet()["snapshot"])
            with self.assertRaises(ValueError):
                compiler.resolve_compile_arch("sm_90", snapshot)
        with patch.object(compiler, "current_platform_type", return_value="linux"), self.assertRaises(ValueError):
            compiler.resolve_compile_arch("sm_75", snapshot)
        unknown = deepcopy(snapshot)
        unknown["supported_architectures"] = {"status": "UNKNOWN", "value": None, "source_ids": [], "method": "not available"}
        with self.assertRaises(ValueError):
            compiler.resolve_compile_arch("sm_75", seal_snapshot(unknown))


class TestCompileAdapters(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.source = self.directory / "safe source.cu"
        self.source.write_text("extern \"C\" __global__ void harmless() {}", encoding="utf-8")
        self.output = self.directory / "safe output.cubin"

    @staticmethod
    def successful_tool(argv, **kwargs):
        Path(argv[argv.index("-o") + 1]).write_bytes(legal_cuda_elf())
        return mock_result(argv, stdout=b"compiler output\x00", stderr=b"warning only\xff")

    def test_success_uses_argv_and_keeps_valid_source_output(self):
        with patch.object(compiler, "find_cuda_tool", return_value="mock nvcc.exe"), \
                patch.object(compiler, "run_tool", side_effect=self.successful_tool) as run:
            result = compiler.compile_cubin_result(str(self.source), str(self.output), "sm_75", "-G -lineinfo", use_msvc=False)
        self.assertTrue(result.ok)
        self.assertTrue(self.source.exists())
        self.assertEqual(self.output.read_bytes(), legal_cuda_elf())
        self.assertEqual(result.tool_result.stderr_bytes(), b"warning only\xff")
        self.assertEqual(result.candidate_execution_status, "NOT_EXECUTED")
        self.assertEqual(result.verification_status, "NOT_VERIFIED")
        self.assertEqual(run.call_args.args[0][1:4], ["-G", "-lineinfo", "-arch=sm_75"])
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertFalse(list(self.directory.glob(".cuda_compile_*")))

    def test_nonzero_exit_and_invalid_output_cannot_be_compile_success(self):
        for runner, status in ((lambda argv, **kw: mock_result(argv, returncode=2), "NOT_COMPILED"),
                               (lambda argv, **kw: mock_result(argv), "INVALID_COMPILER_OUTPUT")):
            with self.subTest(status=status), patch.object(compiler, "find_cuda_tool", return_value="nvcc"), \
                    patch.object(compiler, "run_tool", side_effect=runner):
                result = compiler.compile_cubin_result(str(self.source), str(self.output), "sm_75", use_msvc=False)
            self.assertFalse(result.ok)
            self.assertEqual(result.artifact_status, status)
            self.assertEqual(result.verification_status, "NOT_VERIFIED")
            self.assertFalse(self.output.exists())

    def test_missing_compiler_and_timeout_retain_status(self):
        for runner, expected in ((lambda argv, **kw: mock_result(argv, returncode=None, started=False), "START_FAILED"),
                                 (lambda argv, **kw: mock_result(argv, returncode=1, timed_out=True), "TIMED_OUT")):
            with self.subTest(expected=expected), patch.object(compiler, "find_cuda_tool", side_effect=FileNotFoundError), \
                    patch.object(compiler, "run_tool", side_effect=runner):
                with self.assertRaises(compiler.CompileError) as failure:
                    compiler.compile_cubin(str(self.source), str(self.output), "sm_75", use_msvc=False)
            self.assertEqual(failure.exception.result.tool_result.end_status, expected)
            self.assertFalse(self.output.exists())

    def test_existing_output_is_never_overwritten_implicitly(self):
        self.output.write_bytes(b"user file")
        with patch.object(compiler, "run_tool") as run, self.assertRaises(ValueError):
            compiler.compile_cubin(str(self.source), str(self.output), "sm_75", use_msvc=False)
        run.assert_not_called()
        self.assertEqual(self.output.read_bytes(), b"user file")

    def test_snapshot_capabilities_cannot_bind_another_compiler(self):
        snapshot = packet(gpu=b"0, Synthetic GPU, 7.5, 555.42\n")["snapshot"]
        with patch.object(compiler, "current_platform_type", return_value="wsl"), \
                patch.object(compiler, "_local_path", side_effect=lambda value, **kw: Path(value).resolve()), \
                patch.object(compiler, "find_cuda_tool", return_value="another-nvcc"), \
                patch.object(compiler, "run_tool") as run, self.assertRaisesRegex(ValueError, "differs"):
            compiler.compile_cubin_result(str(self.source), str(self.output), snapshot=snapshot, use_msvc=False)
        run.assert_not_called()

    def test_concurrent_publication_failure_preserves_other_output(self):
        def concurrent(argv, **kwargs):
            result = self.successful_tool(argv, **kwargs)
            self.output.write_bytes(b"another task's output")
            return result
        with patch.object(compiler, "find_cuda_tool", return_value="nvcc"), patch.object(compiler, "run_tool", side_effect=concurrent):
            result = compiler.compile_cubin_result(str(self.source), str(self.output), "sm_75", use_msvc=False)
        self.assertEqual(result.artifact_status, "ARTIFACT_PUBLICATION_FAILED")
        self.assertEqual(self.output.read_bytes(), b"another task's output")

    def test_successful_kernel_sources_are_unique_and_retained(self):
        with patch.object(compiler, "find_cuda_tool", return_value="nvcc"), patch.object(compiler, "run_tool", side_effect=self.successful_tool):
            first = compiler.compile_kernel_source("__global__ void harmless() {}", "sm_75", work_dir=str(self.directory), use_msvc=False)
            second = compiler.compile_kernel_source("__global__ void harmless() {}", "sm_75", work_dir=str(self.directory), use_msvc=False)
        self.assertNotEqual(first, second)
        self.assertTrue(all(Path(path).is_file() for path in first + second))

    def test_default_temporary_source_is_retained_for_returned_path(self):
        with patch.object(compiler, "find_cuda_tool", return_value="nvcc"), patch.object(compiler, "run_tool", side_effect=self.successful_tool):
            output, source = compiler.compile_kernel_source("__global__ void harmless() {}", "sm_75", use_msvc=False)
        self.addCleanup(compiler.shutil.rmtree, Path(source).parent)
        self.assertTrue(Path(source).is_file())
        self.assertTrue(Path(output).is_file())

    def test_failed_kernel_source_cleans_only_its_own_task_directory(self):
        keep = self.directory / "_kernel.cu"
        keep.write_text("user owned")
        with patch.object(compiler, "find_cuda_tool", return_value="nvcc"), \
                patch.object(compiler, "run_tool", side_effect=lambda argv, **kw: mock_result(argv, returncode=1)):
            with self.assertRaises(compiler.CompileError):
                compiler.compile_kernel_source("__global__ void harmless() {}", "sm_75", work_dir=str(self.directory), use_msvc=False)
        self.assertEqual(keep.read_text(), "user owned")
        self.assertFalse(list(self.directory.glob("cuda_kernel_*")))

    def test_output_is_not_accepted_by_magic_alone_or_wrong_machine(self):
        def invalid(argv, **kwargs):
            output = Path(argv[argv.index("-o") + 1])
            output.write_bytes(b"\x7fELF")
            return mock_result(argv)
        with patch.object(compiler, "find_cuda_tool", return_value="nvcc"), patch.object(compiler, "run_tool", side_effect=invalid):
            result = compiler.compile_cubin_result(str(self.source), str(self.output), "sm_75", use_msvc=False)
        self.assertEqual(result.artifact_status, "INVALID_COMPILER_OUTPUT")
        non_cuda = bytearray(legal_cuda_elf())
        struct.pack_into("<H", non_cuda, 18, 62)
        self.output.write_bytes(non_cuda)
        with self.assertRaises(ValueError):
            compiler._validate_cubin(self.output)

    def test_cubin_file_size_limit_is_separate_from_stdout_limit(self):
        with patch.object(compiler, "find_cuda_tool", return_value="nvcc"), \
                patch.object(compiler, "run_tool", side_effect=self.successful_tool):
            result = compiler.compile_cubin_result(str(self.source), str(self.output), "sm_75",
                                                  use_msvc=False, max_cubin_bytes=64)
        self.assertEqual(result.tool_result.end_status, "NORMAL_EXIT")
        self.assertEqual(result.artifact_status, "INVALID_COMPILER_OUTPUT")
        self.assertFalse(self.output.exists())

    def test_cleanup_failure_preserves_process_status_and_evidence(self):
        with patch.object(compiler, "find_cuda_tool", return_value="nvcc"), \
                patch.object(compiler, "run_tool", side_effect=lambda argv, **kw: mock_result(argv, returncode=2)), \
                patch.object(compiler.shutil, "rmtree", side_effect=OSError("synthetic cleanup failure")):
            result = compiler.compile_cubin_result(str(self.source), str(self.output), "sm_75", use_msvc=False)
            with self.assertRaises(compiler.CompileError) as error:
                compiler.compile_kernel_source("__global__ void harmless() {}", "sm_75", work_dir=str(self.directory), use_msvc=False)
        self.assertEqual(result.tool_result.end_status, "NONZERO_EXIT")
        self.assertEqual(result.tool_result.evidence_directory, "synthetic-not-a-real-record")
        self.assertTrue(any("CLEANUP_FAILED" in item for item in result.diagnostics))
        self.assertEqual(error.exception.result.tool_result.end_status, "NONZERO_EXIT")
        self.assertTrue(any("CLEANUP_FAILED" in item for item in error.exception.result.diagnostics))


class TestInspectAdapters(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "safe.cubin"
        self.path.write_bytes(legal_cuda_elf())

    def test_normal_exit_with_stderr_is_success(self):
        with patch.object(inspection, "find_cuda_tool", return_value="nvdisasm"), \
                patch.object(inspection, "run_tool", side_effect=lambda argv, **kw: mock_result(argv, stderr=b"warning")):
            self.assertEqual(inspection.nvdisasm_run(str(self.path)), (True, "", "warning", 0))

    def test_malformed_binary_is_rejected_without_external_inspector(self):
        self.path.write_bytes(b"\x7fELF malformed")
        with patch.object(inspection, "run_tool") as run:
            with self.assertRaises(ValueError):
                inspection.nvdisasm_result(str(self.path))
            with self.assertRaises(ValueError):
                inspection.cuobjdump_result(str(self.path))
            legacy = inspection.cuobjdump_elf(str(self.path))
            self.assertFalse(legacy["ok"])
            self.assertEqual(legacy["error"], "INPUT_REJECTED")
            self.assertIsNone(legacy["tool_result"])
        run.assert_not_called()

    def test_nonzero_timeout_start_failure_output_limit_are_not_success(self):
        cases = ({"returncode": 2}, {"returncode": 1, "timed_out": True},
                 {"returncode": None, "started": False}, {"returncode": 0, "truncated": True})
        for options in cases:
            with self.subTest(options=options), patch.object(inspection, "find_cuda_tool", return_value="nvdisasm"), \
                    patch.object(inspection, "run_tool", side_effect=lambda argv, **kw: mock_result(argv, stdout=b"partial", **options)):
                success, out, _, _ = inspection.nvdisasm_run(str(self.path))
                record = inspection.nvdisasm_result(str(self.path))
            self.assertFalse(success)
            self.assertEqual(out, "partial")
            self.assertEqual(record.verification_status, "NOT_VERIFIED")

    def test_cuobjdump_retains_failed_raw_bytes_but_no_fake_sections(self):
        with patch.object(inspection, "find_cuda_tool", return_value="cuobjdump"), \
                patch.object(inspection, "run_tool", side_effect=lambda argv, **kw: mock_result(argv, returncode=1, stdout=b".section .text\n")):
            result = inspection.cuobjdump_elf(str(self.path))
        self.assertFalse(result["ok"])
        self.assertEqual(result["raw"], ".section .text\n")
        self.assertEqual(result["sections"], [])
        self.assertEqual(result["tool_result"]["end_status"], "NONZERO_EXIT")

    def test_relocation_presence_is_not_a_text_heuristic(self):
        self.path.write_bytes(legal_cuda_elf(misleading_rel=True))
        with patch.object(inspection, "run_tool") as run:
            self.assertFalse(inspection.nvdisasm_has_relocation_sections(str(self.path)))
        run.assert_not_called()
        self.path.write_bytes(legal_cuda_elf(relocation=True))
        self.assertTrue(inspection.nvdisasm_has_relocation_sections(str(self.path)))
        self.path.write_bytes(b"\x7fELF malformed")
        with self.assertRaises(ValueError):
            inspection.nvdisasm_has_relocation_sections(str(self.path))

    def test_access_violation_exact_windows_status_only(self):
        self.assertTrue(inspection.is_access_violation(0xC0000005, platform_type="windows"))
        self.assertTrue(inspection.is_access_violation(-1073741819, platform_type="windows"))
        for status in (-11, -1001, 0xC0000374, 0x1C0000005, 2):
            self.assertFalse(inspection.is_access_violation(status, platform_type="windows"))
        self.assertFalse(inspection.is_access_violation(-11, platform_type="linux"))
        self.assertFalse(inspection.is_access_violation(0xC0000005, platform_type="wsl"))


class TestPreparedMsvcEnvironment(unittest.TestCase):
    def test_malicious_toolset_never_calls_a_shell(self):
        with patch.object(environment.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                environment.setup_msvc_env("14.29 & whoami")
        run.assert_not_called()

    def test_unprepared_windows_environment_is_explicit_failure(self):
        with patch.object(environment.os, "name", "nt"), patch.dict(environment.os.environ, {}, clear=True), \
                patch.object(environment.shutil, "which", return_value=None), patch.object(environment.subprocess, "run") as run:
            self.assertEqual(environment.setup_msvc_env(), {})
            with self.assertRaises(ValueError):
                compiler.prepare_msvc_environment({})
        run.assert_not_called()

    def test_prepared_environment_and_requested_toolset_are_checked(self):
        prepared = {"PATH": "compiler path", "INCLUDE": "sdk include", "LIB": "sdk libs", "VCToolsVersion": "14.29.30133"}
        with patch.object(environment.os, "name", "nt"), patch.dict(environment.os.environ, prepared, clear=True), \
                patch.object(environment.shutil, "which", return_value="cl.exe"):
            self.assertEqual(environment.setup_msvc_env("14.29"), dict(environment.os.environ))
            self.assertEqual(environment.setup_msvc_env("14.40"), {})
            self.assertEqual(compiler.prepare_msvc_environment(prepared), prepared)


if __name__ == "__main__":
    unittest.main()
