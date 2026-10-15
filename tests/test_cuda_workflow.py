"""Offline CUDA orchestration; subprocess adapters are always mocked."""

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src import cuda_smoke_worker as worker
from src.cuda_registry import (CUDA_SMOKE_SOURCE, CUDA_SMOKE_RELATIVE_PATH, build_cuda_step_argv,
                                observe_smoke_cubin)
from src.models.execution import CudaToolchainScope
from src.models.execution import OperatorAuthorization
from src.models.lifecycle import CudaProcessObservation
from src.models.platform import PlatformSnapshot, seal_snapshot
from src.models.tool_result import ToolIdentity
from tests.test_cuda_contracts import (synthetic_cuda_context, synthetic_cuda_scope,
                                       synthetic_version_record)
from tests.test_cuda_registry import synthetic_cuda_elf, synthetic_tools
from tests.test_platform_probe import packet


STEPS = ("nvcc_version", "cuobjdump_version", "nvdisasm_version", "compile", "cuobjdump", "nvdisasm")


def synthetic_process(request, step_id, *, state="COMPLETED", stdout=None):
    """Fabricated kernel/process metadata; no script or native file is run."""
    role = "nvcc" if step_id == "compile" else step_id.removesuffix("_version")
    identity = request.cuda_toolchain.tools[role]
    raw = request.cuda_toolchain.version_records[role].stdout_bytes() if stdout is None else stdout
    empty = __import__("hashlib").sha256(b"").hexdigest()
    stamp = datetime.now(timezone.utc).isoformat()
    return CudaProcessObservation(
        started=True, action_started=True, argv=build_cuda_step_argv(step_id, request.cuda_toolchain.tools, "sm_75", "/workspace"),
        cwd=request.cwd, target_environment=request.binding.target_environment, tool_identity=identity,
        actual_tool_identity=identity, launcher_tool_identity=request.cuda_toolchain.tools["guard_python"],
        launcher_argv=[request.cuda_toolchain.tools["guard_python"].resolved_path, "-I", "-c", "SYNTHETIC_NOT_EXECUTED"],
        pid=10001, pgid=10001, session_id=10001, start_ticks=5000, uid=1000, gid=1000, worker_pid=100,
        started_at=stamp, finished_at=stamp, duration_seconds=0.0,
        returncode=7 if state == "NONZERO_EXIT" else -9 if state in {"TIMED_OUT", "RESOURCE_LIMIT"} else 0,
        linux_signal=9 if state in {"TIMED_OUT", "RESOURCE_LIMIT"} else None,
        timed_out=state == "TIMED_OUT", cancelled=False, truncated=state == "RESOURCE_LIMIT",
        capture_failed=False, resource_limit_reason="SYNTHETIC output cap" if state == "RESOURCE_LIMIT" else None,
        stdout_b64=__import__("base64").b64encode(raw).decode("ascii"), stderr_b64="",
        stdout_sha256=__import__("hashlib").sha256(raw).hexdigest(), stderr_sha256=empty,
        stdout_size_bytes=len(raw), stderr_size_bytes=0, resource_limits=request.resource_limits,
        resources={"status": "ENFORCED", "wall_watchdog": True, "output_cap": True, "process_group": True,
                   "cpu_seconds": request.resource_limits.cpu_seconds, "memory_bytes": request.resource_limits.memory_bytes,
                   "verification_source": "SYNTHETIC offline resource observations"},
        cleanup={"status": "CONFIRMED", "termination_method": "SIGKILL" if state in {"TIMED_OUT", "RESOURCE_LIMIT"} else "NONE",
                 "parent_reaped": True, "group_absent": True, "descendants_absent": True,
                 "checked_at": stamp, "source": "SYNTHETIC offline cleanup observations"},
        diagnostics=["SYNTHETIC process; no native tool was started"])


class TestCudaVersions(unittest.TestCase):
    def setUp(self):
        selected = patch.object(worker, "canonical_target_environment", return_value="wsl:Ubuntu-22.04")
        selected.start()
        self.addCleanup(selected.stop)
        self.scope = synthetic_cuda_scope()
        self.snapshot = PlatformSnapshot.model_validate(packet()["snapshot"])

    def test_supported_complete_twelve_eight_family_is_accepted(self):
        worker.validate_cuda_versions(self.scope, self.snapshot)

    def test_unsupported_or_unparseable_actual_tool_version_is_rejected(self):
        for text in ("13.0", "12.80", "11.8", "unknown"):
            data = self.scope.model_dump(mode="python")
            data["version_records"]["nvdisasm"] = synthetic_version_record("nvdisasm", version=text)
            scope = CudaToolchainScope.model_validate(data)
            with self.subTest(version=text), self.assertRaises(ValueError):
                worker.validate_cuda_versions(scope, self.snapshot)

    def test_toolkit_version_substring_is_not_twelve_eight_compatibility(self):
        for text in ("112.8", "12.80", "12.8-unreviewed"):
            value = self.snapshot.model_dump(mode="python")
            value["cuda_toolkit_version"]["value"] = text
            with self.subTest(text=text), self.assertRaises(ValueError):
                worker.validate_cuda_versions(self.scope, seal_snapshot(value))

    def test_version_record_from_another_target_cannot_be_reused(self):
        with patch.object(worker, "canonical_target_environment", return_value="wsl:Other"):
            with self.assertRaises(ValueError):
                worker.validate_cuda_versions(self.scope, self.snapshot)


class TestCudaDescription(unittest.TestCase):
    def describe(self, *, missing_nvcc=False, missing_inspector=False, failed_version=False, replaced_source=False):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        path = root / CUDA_SMOKE_RELATIVE_PATH
        path.parent.mkdir(parents=True)
        path.write_bytes(b"replacement" if replaced_source else CUDA_SMOKE_SOURCE)
        snapshot = PlatformSnapshot.model_validate(packet(gpu=b"0, Fixture GPU A, 7.5, 555.42\n",
                                                           missing=("nvcc",) if missing_nvcc else ())["snapshot"])
        identities = synthetic_tools()
        observed = {}

        def measure(path, **kwargs):
            role = "guard_python" if str(path) == sys.executable else "host_compiler" if str(path).endswith("g++") else PurePosixPath(str(path)).name
            base = identities[role].model_dump(mode="python")
            base.update(requested_executable=str(path), source=kwargs["source"])
            if missing_inspector and role == "nvdisasm":
                base.update(status="UNKNOWN", file_sha256=None)
            result = ToolIdentity.model_validate(base)
            observed[role] = result
            return result

        def version(argv, **kwargs):
            role = PurePosixPath(argv[0]).name
            tool = observed[role].model_copy(update={"source": kwargs.get("tool_source", "default mismatched identity source")})
            return synthetic_version_record(role, tools={**identities, role: tool},
                                              returncode=7 if failed_version and role == "cuobjdump" else 0)

        with patch.object(worker, "_snapshot", return_value=snapshot), \
                patch.object(worker, "canonical_target_environment", return_value="wsl:Ubuntu-22.04"), \
                patch.object(worker, "target_boot_id", return_value="00000000-0000-0000-0000-000000000001"), \
                patch.object(worker, "Path", PurePosixPath), \
                patch.object(worker, "measure_tool_identity", side_effect=measure), \
                patch.object(worker.shutil, "which", return_value="/tools/g++"), \
                patch.object(worker, "run_tool", side_effect=version) as query, \
                patch("src.tools.compile.current_platform_type", return_value="wsl"), \
                patch.object(worker, "resource_capabilities", return_value={
                    "status": "OBSERVED", "mechanisms": ["WALL_WATCHDOG", "OUTPUT_CAP", "POSIX_PROCESS_GROUP", "RLIMIT_CPU", "RLIMIT_AS"],
                    "source": "SYNTHETIC capabilities"}):
            result = worker.describe_cuda_smoke(root, root / "native")
        return result, query.call_args_list

    def test_complete_description_retains_exact_version_tool_identity_sources(self):
        result, calls = self.describe()
        self.assertEqual(result["status"], "DESCRIBED", result["diagnostics"])
        self.assertEqual(len(calls), 3)
        for call in calls:
            self.assertEqual(call.args[0][1:], ["--version"])
            self.assertNotIn("--cubin", call.args[0])

    def test_missing_nvcc_or_inspector_never_reports_described(self):
        for kwargs in ({"missing_nvcc": True}, {"missing_inspector": True}):
            result, calls = self.describe(**kwargs)
            with self.subTest(kwargs=kwargs):
                self.assertEqual(result["status"], "UNSUPPORTED")
                self.assertIsNone(result["scope"])
                self.assertEqual(calls, [])

    def test_nonzero_version_query_is_not_an_accepted_toolchain(self):
        result, _ = self.describe(failed_version=True)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["scope"])

    def test_replaced_registered_source_stops_before_any_native_query(self):
        result, calls = self.describe(replaced_source=True)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(calls, [])


class TestCudaWorkflow(unittest.TestCase):
    def execute(self, *, failure_step=None, failure_state="NONZERO_EXIT", artifact="valid", source="valid",
                conflict=False, replace_before_inspect=False, expired=False, changed_version=False):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        workspace = root / "workspace"
        workspace.mkdir()
        (workspace / "out").mkdir()
        path = workspace / "safe_smoke.cu"
        if source != "missing":
            path.write_bytes(CUDA_SMOKE_SOURCE if source == "valid" else b"unreviewed replacement")
        cubin = workspace / "out/safe_smoke.cubin"
        if conflict:
            cubin.write_bytes(b"existing user file; never overwrite")
        folder = root / ("f" * 32)
        folder.mkdir()
        request, authorization, _, snapshot, _ = synthetic_cuda_context()
        if expired:
            raw = authorization.model_dump(mode="python")
            raw.update(not_before="2000-01-01T00:00:00+00:00", expires_at="2001-01-01T00:00:00+00:00")
            raw["cuda_toolchain"].update(snapshot_started_monotonic_ns=0, observed_monotonic_ns=0)
            raw.update(not_before_monotonic_ns=0, expires_monotonic_ns=1)
            authorization = OperatorAuthorization.model_validate(raw)

        def run(step_id, **kwargs):
            state = failure_state if step_id == failure_step else "COMPLETED"
            if step_id == "compile" and state == "COMPLETED" and artifact != "missing":
                cubin.write_bytes(synthetic_cuda_elf() if artifact == "valid" else b"malformed compiler output")
            stdout = b"Synthetic nvcc release 13.0\n" if changed_version and step_id == "nvcc_version" else None
            return SimpleNamespace(state=state, process=synthetic_process(request, step_id, state=state, stdout=stdout))

        def observe(path, **kwargs):
            measured = observe_smoke_cubin(path, **kwargs)
            if replace_before_inspect and kwargs.get("expected_sha256") is None:
                path.write_bytes(path.read_bytes() + b"replacement suffix")
            return measured

        def save(path, value):
            path.write_text(json.dumps(value), encoding="utf-8")

        with patch.object(worker, "Path", side_effect=lambda value: workspace if str(value) == request.cwd else Path(value)), \
                patch("src.execution_preflight.target_boot_id", return_value=request.cuda_toolchain.target_boot_id), \
                patch("src.cuda_process.run_registered_cuda_tool", side_effect=run) as adapter, \
                patch.object(worker, "observe_smoke_cubin", side_effect=observe):
            result = worker.run_cuda_workflow(request, authorization, snapshot, folder,
                                               nonce="e" * 32, on_event=lambda *_: None, save_json=save)
        return result, [call.args[0] for call in adapter.call_args_list], workspace

    def test_original_six_step_chain_remains_compatible_with_mock_tools(self):
        result, calls, _ = self.execute()
        self.assertEqual(result.state, "COMPLETED")
        self.assertEqual(calls, list(STEPS))
        self.assertIsNotNone(result.smoke.artifact)
        self.assertEqual(result.smoke.kernel_execution_status, "NOT_EXECUTED")
        self.assertEqual(result.smoke.verification_status, "NOT_VERIFIED")

    def test_expired_authorization_stops_before_all_tool_steps(self):
        result, calls, _ = self.execute(expired=True)
        self.assertEqual(result.state, "REJECTED")
        self.assertEqual(calls, [])
        self.assertEqual(result.smoke.steps, [])

    def test_compile_nonzero_timeout_or_truncation_stops_inspection(self):
        for state in ("NONZERO_EXIT", "TIMED_OUT", "RESOURCE_LIMIT"):
            result, calls, _ = self.execute(failure_step="compile", failure_state=state)
            with self.subTest(state=state):
                self.assertEqual(result.state, state)
                self.assertEqual(calls, list(STEPS[:4]))
                self.assertIsNone(result.smoke.artifact)

    def test_failed_version_or_inspector_keeps_the_actual_terminal_state(self):
        for step in ("nvcc_version", "cuobjdump", "nvdisasm"):
            result, calls, _ = self.execute(failure_step=step)
            with self.subTest(step=step):
                self.assertEqual(result.state, "NONZERO_EXIT")
                self.assertEqual(calls[-1], step)
                self.assertEqual(len(calls), STEPS.index(step) + 1)

    def test_zero_compiler_exit_without_legal_output_is_not_success(self):
        for artifact in ("missing", "malformed"):
            result, calls, _ = self.execute(artifact=artifact)
            with self.subTest(artifact=artifact):
                self.assertEqual(result.state, "UNKNOWN")
                self.assertEqual(calls, list(STEPS[:4]))
                self.assertIsNone(result.smoke.artifact)

    def test_registered_source_replacement_is_blocked_before_first_step(self):
        result, calls, _ = self.execute(source="replaced")
        self.assertEqual(result.state, "REJECTED")
        self.assertEqual(calls, [])

    def test_existing_cubin_is_not_overwritten_or_sent_to_native_tools(self):
        result, calls, workspace = self.execute(conflict=True)
        self.assertEqual(result.state, "UNKNOWN")
        self.assertEqual(calls, list(STEPS[:3]))
        self.assertEqual((workspace / "out/safe_smoke.cubin").read_bytes(), b"existing user file; never overwrite")

    def test_changed_artifact_hash_is_blocked_before_native_inspection(self):
        result, calls, _ = self.execute(replace_before_inspect=True)
        self.assertEqual(result.state, "UNKNOWN")
        self.assertEqual(calls, list(STEPS[:4]))
        self.assertIn("COMPILED_ARTIFACT_CHANGED_OR_MISSING", result.diagnostics)

    def test_missing_source_has_a_failure_outcome_and_does_not_launch(self):
        result, calls, _ = self.execute(source="missing")
        self.assertIn(result.state, {"REJECTED", "UNKNOWN"})
        self.assertEqual(calls, [])

    def test_changed_actual_version_query_cannot_reach_compilation(self):
        result, calls, _ = self.execute(changed_version=True)
        self.assertNotEqual(result.state, "COMPLETED")
        self.assertNotIn("compile", calls)


if __name__ == "__main__":
    unittest.main()
