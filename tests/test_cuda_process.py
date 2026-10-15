"""Mock and harmless native process tests; no CUDA compiler is run here.

Native runner tests deliberately map the synthetic tool roles to the installed
GNU true ELF program. They prove lifecycle behavior, never CUDA compatibility.
The separate explicitly authorized real CUDA smoke provides that evidence.
"""

from copy import deepcopy
import ctypes
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

from src.cuda_guard import CUDA_GUARD_SOURCE
from src.cuda_process import (CudaTraceError, NativeCudaTracer, _NativePlan,
                              _actual_image, run_registered_cuda_tool)
from src.models.execution import CudaResourceLimits, ExecutionResourceLimits
from src.models.tool_result import ToolIdentity
from src.tools.process import canonical_target_environment, measure_tool_identity


LINUX = os.name == "posix" and sys.platform.startswith("linux")


def synthetic_tools():
    return {role: ToolIdentity(requested_executable="/tools/" + role,
                               resolved_path="/tools/" + role, status="OBSERVED",
                               file_sha256="a" * 64, source="synthetic identity; no executable was run")
            for role in ("nvcc", "cuobjdump", "nvdisasm", "host_compiler", "guard_python")}


class TestCudaRunnerBoundaries(unittest.TestCase):
    def setUp(self):
        self.limits = CudaResourceLimits(wall_time_seconds=5.0, cpu_seconds=2,
                                       memory_bytes=2147483648, max_output_bytes=4096)
        self.args = {"tools": synthetic_tools(), "arch": "sm_75", "workspace": "/private/task/work",
                     "limits": self.limits, "target_environment": "wsl:synthetic",
                     "request_id": "a" * 32, "run_id": "b" * 32, "nonce": "c" * 32}

    def test_unknown_steps_and_arbitrary_argv_are_not_accepted(self):
        with patch("src.lifecycle_process.subprocess.Popen") as launch:
            for step in ("EXECUTE_CANDIDATE", "sh -c anything", "../../nvcc", ""):
                with self.assertRaises(ValueError):
                    run_registered_cuda_tool(step, **self.args)
            with self.assertRaises(TypeError):
                run_registered_cuda_tool("compile", argv=["shell"], **self.args)
            launch.assert_not_called()

    def test_tool_roles_and_measured_identity_are_required(self):
        with patch("src.lifecycle_process.subprocess.Popen") as launch:
            missing = deepcopy(self.args)
            missing["tools"].pop("host_compiler")
            with self.assertRaises(ValueError):
                run_registered_cuda_tool("compile", **missing)
            unknown = deepcopy(self.args)
            unknown["tools"]["nvcc"] = unknown["tools"]["nvcc"].model_copy(update={"status": "UNKNOWN", "file_sha256": None})
            with self.assertRaises(ValueError):
                run_registered_cuda_tool("compile", **unknown)
            launch.assert_not_called()

    def test_cuda_limits_do_not_widen_old_fixture_profile(self):
        self.assertEqual(self.limits.memory_bytes, 2147483648)
        with self.assertRaises(ValueError):
            ExecutionResourceLimits.model_validate(self.limits.model_dump(mode="python"))
        for field, value in (("wall_time_seconds", 121.0), ("cpu_seconds", 61), ("memory_bytes", 8589934593)):
            invalid = self.limits.model_dump(mode="python")
            invalid[field] = value
            with self.assertRaises(ValueError):
                CudaResourceLimits.model_validate(invalid)

    def test_guard_is_syntax_valid_and_uses_fd_exec_and_ptrace(self):
        compile(CUDA_GUARD_SOURCE, "fixed CUDA resource guard", "exec")
        self.assertIn(b"os.execve(tool_fd", CUDA_GUARD_SOURCE)
        self.assertIn(b"libc.ptrace(0", CUDA_GUARD_SOURCE)
        self.assertNotIn(b"shell=True", CUDA_GUARD_SOURCE)

    @unittest.skipIf(LINUX, "Linux exercises supported native code")
    def test_windows_cannot_launch_linux_tools_directly(self):
        with patch("src.lifecycle_process.subprocess.Popen") as launch:
            with self.assertRaises(CudaTraceError) as raised:
                run_registered_cuda_tool("nvcc_version", **self.args)
            self.assertEqual(raised.exception.execution_state, "UNSUPPORTED")
            launch.assert_not_called()


@unittest.skipUnless(LINUX, "requires Linux ptrace, /proc and native ELF true fixture")
class TestHarmlessNativeCudaRunner(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)
        self.workspace.chmod(0o700)
        self.native = measure_tool_identity("/usr/bin/true")
        self.python = measure_tool_identity(sys.executable)
        self.tools = {role: self.native for role in ("nvcc", "cuobjdump", "nvdisasm", "host_compiler")}
        self.tools["guard_python"] = self.python
        # Only the lifecycle of the harmless installed `true` image is under
        # test. The real registry's CUDA basename/argv checks are independently
        # covered; do not relax them to make this synthetic mapping acceptable.
        selected = patch("src.cuda_registry.build_cuda_step_argv",
                         side_effect=lambda step, tools, arch, workspace: [self.native.resolved_path, "--version"])
        selected.start()
        self.addCleanup(selected.stop)
        self.limits = CudaResourceLimits(wall_time_seconds=5.0, cpu_seconds=2,
                                       memory_bytes=2147483648, max_output_bytes=4096)

    def execute(self, step="nvcc_version", **kwargs):
        return run_registered_cuda_tool(step, tools=kwargs.pop("tools", self.tools), arch="sm_75",
            workspace=self.workspace, limits=kwargs.pop("limits", self.limits),
            target_environment=canonical_target_environment(), request_id=uuid.uuid4().hex,
            run_id=uuid.uuid4().hex, nonce=uuid.uuid4().hex, **kwargs)

    def test_native_exec_identity_is_measured_at_kernel_stop(self):
        events = []

        def observed(kind, details):
            events.append((kind, details))
            if kind == "TOOL_EXEC_READY":
                self.assertEqual(_actual_image(details["pid"]).file_sha256, self.native.file_sha256)

        result = self.execute(on_event=observed)
        self.assertEqual(result.state, "COMPLETED", result.process.diagnostics)
        self.assertTrue(result.process.action_started)
        self.assertEqual(result.process.process_schema_version, "1.1")
        self.assertEqual(result.process.argv, [self.native.resolved_path, "--version"])
        self.assertEqual(result.process.actual_tool_identity.file_sha256, self.native.file_sha256)
        self.assertEqual(result.process.launcher_tool_identity.file_sha256, self.python.file_sha256)
        self.assertIn("-I", result.process.launcher_argv)
        self.assertEqual(result.process.resources.status, "ENFORCED")
        self.assertEqual(result.process.resources.memory_bytes, 2147483648)
        self.assertEqual(result.process.cleanup.status, "CONFIRMED")
        names = [name for name, _ in events]
        self.assertLess(names.index("RESOURCE_READY"), names.index("TOOL_EXEC_READY"))
        self.assertLess(names.index("TOOL_EXEC_READY"), names.index("RUNNING"))

    def test_all_three_version_roles_use_native_controlled_runner(self):
        for step in ("nvcc_version", "cuobjdump_version", "nvdisasm_version"):
            with self.subTest(step=step):
                result = self.execute(step)
                self.assertEqual(result.state, "COMPLETED", result.process.diagnostics)
                self.assertEqual(result.process.cleanup.status, "CONFIRMED")

    def test_actual_native_identity_failure_does_not_resume_tool(self):
        unknown = self.native.model_copy(update={"file_sha256": "f" * 64})
        with patch("src.cuda_process._actual_image", return_value=unknown):
            result = self.execute()
        self.assertEqual(result.state, "REJECTED", result.process.diagnostics)
        self.assertFalse(result.process.action_started)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.process.cleanup.status, "CONFIRMED")

    def test_native_exec_journal_failure_blocks_resume(self):
        def observed(kind, details):
            if kind == "TOOL_EXEC_READY":
                raise OSError("synthetic full evidence device")

        result = self.execute(on_event=observed)
        self.assertEqual(result.state, "CAPTURE_FAILED", result.process.diagnostics)
        self.assertFalse(result.process.action_started)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.process.cleanup.status, "CONFIRMED")

    def test_ptrace_options_unsupported_never_runs_native_program(self):
        original = NativeCudaTracer._ptrace

        def unsupported(tracer, operation, pid, data=0):
            if operation == 0x4200:
                raise CudaTraceError("synthetic unsupported EXITKILL", state="UNSUPPORTED")
            return original(tracer, operation, pid, data)

        with patch.object(NativeCudaTracer, "_ptrace", new=unsupported):
            result = self.execute()
        self.assertEqual(result.state, "UNSUPPORTED", result.process.diagnostics)
        self.assertFalse(result.process.action_started)
        self.assertEqual(result.process.cleanup.status, "CONFIRMED")

    def test_compile_source_change_and_output_conflict_never_launch(self):
        from src.cuda_registry import CUDA_SMOKE_SOURCE
        (self.workspace / "out").mkdir(mode=0o700)
        source = self.workspace / "safe_smoke.cu"
        source.write_bytes(CUDA_SMOKE_SOURCE + b"// changed\n")
        with patch("src.lifecycle_process.subprocess.Popen") as launch:
            with self.assertRaises(CudaTraceError):
                self.execute("compile")
            source.write_bytes(CUDA_SMOKE_SOURCE)
            (self.workspace / "out" / "safe_smoke.cubin").write_bytes(b"existing user data")
            with self.assertRaises(CudaTraceError):
                self.execute("compile")
            self.assertEqual((self.workspace / "out" / "safe_smoke.cubin").read_bytes(), b"existing user data")
            launch.assert_not_called()

    def test_inspection_needs_bound_compile_artifact_hash(self):
        with patch("src.lifecycle_process.subprocess.Popen") as launch:
            for step in ("cuobjdump", "nvdisasm"):
                with self.assertRaises(CudaTraceError):
                    self.execute(step)
            launch.assert_not_called()

    def test_parent_environment_flags_are_not_inherited(self):
        captured = []
        original = os.execve
        # Guard source receives only this adapter's minimal environment. Inspect
        # the typed plan before the shared engine; do not patch a native process.
        with patch.dict(os.environ, {"NVCC_PREPEND_FLAGS": "untrusted", "LD_PRELOAD": "/unknown", "CXX": "unknown"}):
            from src import lifecycle_process
            engine = lifecycle_process._run_controlled_action

            def inspect_plan(*args, **kwargs):
                captured.append(kwargs["native_plan"].environment)
                return engine(*args, **kwargs)

            with patch("src.lifecycle_process._run_controlled_action", side_effect=inspect_plan):
                result = self.execute()
        self.assertEqual(result.state, "COMPLETED", result.process.diagnostics)
        self.assertNotIn("NVCC_PREPEND_FLAGS", captured[0])
        self.assertNotIn("LD_PRELOAD", captured[0])
        self.assertNotIn("CXX", captured[0])
        self.assertNotIn("PYTHONPATH", captured[0])

    def fixed_native(self, executable, arguments, *, wall=2.0, output=4096):
        """Use only these fixed installed harmless GNU test utilities."""
        identity = measure_tool_identity(executable)
        tools = {role: identity for role in ("nvcc", "cuobjdump", "nvdisasm", "host_compiler")}
        tools["guard_python"] = self.python
        limits = CudaResourceLimits(wall_time_seconds=wall, cpu_seconds=2,
            memory_bytes=2147483648, max_output_bytes=output)
        with patch("src.cuda_registry.build_cuda_step_argv", return_value=[identity.resolved_path, *arguments]):
            return self.execute(tools=tools, limits=limits)

    def test_fixed_native_nonzero_preserves_exit_and_recovery(self):
        result = self.fixed_native("/usr/bin/false", [])
        self.assertEqual(result.state, "NONZERO_EXIT", result.process.diagnostics)
        self.assertEqual(result.process.returncode, 1)
        self.assertEqual(result.process.cleanup.status, "CONFIRMED")

    def test_fixed_native_sleep_timeout_is_reaped(self):
        result = self.fixed_native("/usr/bin/sleep", ["5"], wall=0.2)
        self.assertEqual(result.state, "TIMED_OUT", result.process.diagnostics)
        self.assertTrue(result.process.timed_out)
        self.assertEqual(result.process.cleanup.status, "CONFIRMED")

    def test_fixed_native_output_cap_preserves_prefix(self):
        result = self.fixed_native("/usr/bin/yes", [], output=128)
        self.assertEqual(result.state, "RESOURCE_LIMIT", result.process.diagnostics)
        self.assertTrue(result.process.truncated)
        self.assertLessEqual(result.process.stdout_size_bytes + result.process.stderr_size_bytes, 128)
        self.assertEqual(result.process.cleanup.status, "CONFIRMED")


@unittest.skipUnless(LINUX, "requires Linux wait status and ptrace signal constants")
class TestNativeTraceStatus(unittest.TestCase):
    def test_stopped_wait_is_not_treated_as_exit(self):
        tools = synthetic_tools()
        plan = _NativePlan(step_id="nvcc_version", argv=["/tools/nvcc", "--version"], tools=tools,
                           allowed_images={"/tools/nvcc": "a" * 64}, environment={})
        limits = CudaResourceLimits(wall_time_seconds=5.0, cpu_seconds=2, memory_bytes=2147483648, max_output_bytes=4096)
        with patch("src.cuda_process.ctypes.CDLL"):
            tracer = NativeCudaTracer(plan, limits, lambda kind, **details: True)
        tracer.attach_created_child(100)
        tracer._record = Mock(return_value=tools["nvcc"])
        tracer._ptrace = Mock()
        stopped = (signal.SIGTRAP << 8) | 0x7f
        usage = Mock(ru_utime=0.0, ru_stime=0.0)
        with patch("src.cuda_process.os.wait4", create=True,
                   side_effect=[(100, stopped, usage), (0, 0, usage)]):
            result = tracer.poll()
        self.assertEqual(result[0], 0)
        self.assertTrue(tracer.native_started)
        self.assertIn(100, tracer.known)
        self.assertIsNone(tracer.main_exit)

    def test_actual_exit_retains_exit_status(self):
        tools = synthetic_tools()
        plan = _NativePlan(step_id="nvcc_version", argv=["/tools/nvcc"], tools=tools,
                           allowed_images={}, environment={})
        limits = CudaResourceLimits(wall_time_seconds=5.0, cpu_seconds=2, memory_bytes=2147483648, max_output_bytes=4096)
        with patch("src.cuda_process.ctypes.CDLL"):
            tracer = NativeCudaTracer(plan, limits, lambda kind, **details: True)
        tracer.attach_created_child(100)
        usage = Mock(ru_utime=0.1, ru_stime=0.0)
        with patch("src.cuda_process.os.wait4", create=True, return_value=(100, 7 << 8, usage)):
            result = tracer.poll()
        self.assertEqual(os.waitstatus_to_exitcode(result[1]), 7)
        self.assertFalse(tracer.known)
