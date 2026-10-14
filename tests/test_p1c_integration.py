"""Offline ordering regressions; a failed platform never reaches network setup."""

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests.test_baseline import OfflineTestCase, PROJECT_ROOT
from tests.test_platform_probe import packet
from src.models.execution_binding import bind_candidate_to_tool
from src.models.tool_result import digest_argv, seal_tool_result


class TestPlatformPreflight(OfflineTestCase):
    def check_failure(self, *, backend="local", invalid=False):
        cfg = self.config()
        snapshot = packet(backend="local")["snapshot"]
        if invalid:
            snapshot["environment_id"] = "sha256:" + "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            cfg.config["paths"]["outputs_dir"] = directory
            from src import platform_probe
            with patch.object(self.pipeline_module, "ConfigLoader", return_value=cfg), \
                    patch.object(self.pipeline_module, "LLMClient") as provider, \
                    patch.object(self.pipeline_module.CudaDataLoader, "build_or_load_knowledge_base") as rag, \
                    patch.object(self.pipeline_module.CudaPipeline, "_query_rag") as query, \
                    patch.object(self.pipeline_module.CudaPipeline, "_query_web_search") as web, \
                    patch.object(self.pipeline_module, "probe_environment",
                                 **({"return_value": snapshot} if invalid else {"side_effect": RuntimeError("offline platform failure")})), \
                    patch.object(platform_probe, "run_platform_probe", return_value={
                        "snapshot": None, "diagnostics": [], "run_directory": "fixture-record",
                        "transport": {"launcher_returncode": 1, "worker_reported_exit_code": None},
                    }), redirect_stdout(StringIO()):
                pipeline = self.pipeline_module.CudaPipeline()
                with self.assertRaises((ValueError, RuntimeError)):
                    pipeline.run(str(PROJECT_ROOT / "data/inputs/CVE-2024-0124"), target_backend=backend)
            for mock in (provider, rag, query, web):
                mock.assert_not_called()
            report = json.loads((Path(directory) / "CVE-2024-0124/cuda_run_v1.json").read_bytes())
            self.assertEqual(report["status"], "CONTEXT_ERROR")
            self.assertEqual(report["analysis_status"], "NOT_ANALYZED")
            self.assertEqual(report["candidate"]["generation"], "NOT_GENERATED")
            self.assertEqual(report["execution"], "NOT_EXECUTED")
            self.assertEqual(report["verification"], "NOT_VERIFIED")

    def test_local_failure_precedes_providers_rag_and_web(self):
        self.check_failure()

    def test_invalid_snapshot_precedes_providers_rag_and_web(self):
        self.check_failure(invalid=True)

    def test_wsl_failure_precedes_providers_rag_and_web(self):
        self.check_failure(backend="wsl")

    def test_unknown_backend_precedes_providers_rag_and_web(self):
        self.check_failure(backend="invalid")

    def test_domain_signatures_require_explicit_compile_architecture(self):
        signatures = self.library_module.CudaLibrary().get_signatures_text()
        self.assertIn("nvcc_compile(source_path: str, output_path: str, arch: str)", signatures)
        self.assertNotIn("arch: str = 'sm_75'", signatures)


def synthetic_tool_record():
    """Entirely synthetic offline fixture; no file/process observations are claimed."""
    empty_hash = hashlib.sha256(b"").hexdigest()
    argv = ["/tools/nvcc", "--version"]
    return seal_tool_result({
        "run_id": "a" * 32, "argv": argv, "cwd": "/synthetic",
        "target_environment": "wsl:Ubuntu-22.04", "platform_type": "wsl",
        "start_status": "STARTED", "end_status": "NORMAL_EXIT", "returncode": 0,
        "timed_out": False, "truncated": False, "capture_failed": False,
        "started_at": "2026-10-14T00:00:00+00:00", "finished_at": "2026-10-14T00:00:01+00:00",
        "duration_seconds": 1.0,
        "resource_limits": {"timeout_seconds": 3.0, "max_output_bytes": 4096,
                            "termination_scope": "POSIX_PROCESS_GROUP"},
        "stdout_b64": "", "stderr_b64": "", "stdout_sha256": empty_hash, "stderr_sha256": empty_hash,
        "command_identity": {"source": "synthetic fixture", "argv_sha256": digest_argv(argv)},
        "tool_identity": {"requested_executable": argv[0], "resolved_path": argv[0],
                          "status": "OBSERVED", "file_sha256": "b" * 64, "source": "synthetic fixture"},
        "diagnostics": [], "evidence_directory": "/synthetic/not-a-real-record",
    })


class TestCandidateToolBinding(OfflineTestCase):
    def bind(self, source=b"print('not executed')\n", snapshot=None, tool=None, **changes):
        platform = snapshot if snapshot is not None else packet()["snapshot"]
        record = tool if tool is not None else synthetic_tool_record()
        options = {"expected_probe_id": "fixture-id", "expected_tool_record_id": record.record_id}
        options.update(changes)
        return bind_candidate_to_tool(source, platform, record, **options)

    def test_exact_candidate_hash_and_record_references_no_launch(self):
        source = b"raise RuntimeError('must never run')\r\n"
        with patch("subprocess.Popen", side_effect=AssertionError("binding must not launch")):
            binding = self.bind(source)
        self.assertEqual(binding.candidate_sha256, hashlib.sha256(source).hexdigest())
        self.assertEqual(binding.platform_probe_id, "fixture-id")
        self.assertEqual(binding.tool_file_sha256, "b" * 64)

    def test_wrong_expected_probe_or_tool_record_rejected(self):
        for options in ({"expected_probe_id": "old"}, {"expected_tool_record_id": "sha256:" + "0" * 64}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.bind(**options)

    def test_foreign_tool_environment_rejected(self):
        record = synthetic_tool_record().model_dump(mode="json")
        record["target_environment"] = "local"
        with self.assertRaises(ValueError):
            self.bind(tool=seal_tool_result(record))

    def test_unknown_tool_identity_rejected(self):
        record = synthetic_tool_record().model_dump(mode="json")
        record["tool_identity"].update(status="UNKNOWN", resolved_path=None, file_sha256=None)
        with self.assertRaises(ValueError):
            self.bind(tool=seal_tool_result(record))

    def test_corrupted_platform_content_and_empty_candidate_rejected(self):
        snapshot = deepcopy(packet()["snapshot"])
        snapshot["environment_id"] = "sha256:" + "0" * 64
        with self.assertRaises(ValueError):
            self.bind(snapshot=snapshot)
        with self.assertRaises(ValueError):
            self.bind(source=b"")


class TestSharedPrivateArtifacts(unittest.TestCase):
    def test_probe_default_uses_os_appropriate_private_storage(self):
        from src.platform_probe import default_probe_output_root
        expected = (PROJECT_ROOT / "data/outputs/platform_probes" if os.name == "nt" else
                    Path.home() / ".local/state/cuda-poc-generator/platform_probes")
        self.assertEqual(default_probe_output_root(), expected)

    @unittest.skipIf(os.name == "nt", "POSIX filesystem mode enforcement applies only to Linux")
    def test_chmod_without_actual_mode_enforcement_rejected(self):
        from src.probe_artifacts import protect_directory
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "new"
            with patch.object(Path, "stat", return_value=SimpleNamespace(st_mode=0o777)):
                with self.assertRaisesRegex(OSError, "native Linux filesystem"):
                    protect_directory(folder)
