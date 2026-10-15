"""Offline platform fixtures; only synthetic Python children execute in runner tests."""

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from src import platform_worker as worker
from src.models.platform import PlatformSnapshot, seal_snapshot
from src.platform_identity import compute_environment_id
from src.probe_process import run_bounded
from src import wsl_bridge as bridge
from src import platform_probe as service
from src.probe_artifacts import render_report, write_probe_artifacts
from src.env_probe import format_for_prompt, _probe_nvcc_archs
from tests.test_baseline import OfflineTestCase, PROJECT_ROOT, ANALYSIS, SAFE_CODE


def record(command_id, argv, out=b"", err=b"", rc=0, status="COMPLETED", environment="wsl:Ubuntu-22.04"):
    result = {"command_id": command_id, "argv": argv, "environment": environment,
              "timeout_seconds": 3, "max_output_bytes": 32768, "status": status, "returncode": rc,
              "started_at": "2026-10-14T00:00:00+00:00", "finished_at": "2026-10-14T00:00:01+00:00",
              "duration_seconds": 1.0, "timed_out": status == "TIMED_OUT", "truncated": status == "OUTPUT_LIMIT"}
    for key, data in (("stdout", out), ("stderr", err)):
        result[key + "_b64"] = base64.b64encode(data).decode("ascii")
        result[key + "_sha256"] = hashlib.sha256(data).hexdigest()
    return result


def packet(*, probe_id="fixture-id", nonce="fixture-nonce", backend="wsl", gpu=b"0, Fixture GPU A, 7.5, 555.42\n1, Fixture GPU B, 8.6, 555.42\n", missing=(), failures=(), unsupported_cap=False, umd=False):
    def runner(argv, **kw):
        name = kw["command_id"]
        text = {
            "gpu_query": gpu, "gpu_query_fallback": b"0, Fixture GPU A, 555.42\n",
            "smi_banner": b"CUDA UMD Version: 13.4\n" if umd else b"CUDA Version: 12.4\n",
            "nvcc_version": b"Cuda compilation tools, release 12.8, V12.8.93\n",
            "nvcc_gpu_code": b"sm_75\nsm_86\n", "nvcc_gpu_arch": b"compute_75\ncompute_86\n",
            "sanitizer_version": b"Version 2025.1.0.0\n", "gcc_version": b"gcc (Ubuntu) 11.4.0\n",
            "gxx_version": b"g++ (Ubuntu) 11.4.0\n", "msvc_version": b"Version 19.29.30133\n",
        }.get(name, b"")
        rc = 2 if name == "msvc_version" else 0
        if name in failures or (unsupported_cap and name == "gpu_query"):
            rc, text = 1, b""
        return record(name, argv, text, rc=rc, environment=kw["environment"])
    request = {"probe_id": probe_id, "nonce": nonce, "execution_backend": backend,
               "environment_label": "wsl:Ubuntu-22.04" if backend == "wsl" else "local"}
    with patch.dict(worker.os.environ, {"WSL_DISTRO_NAME": "Ubuntu-22.04"}), \
            patch.object(worker, "_find_tool", side_effect=lambda name: None if name in missing else "/tools/" + name), \
            patch.object(worker.platform, "system", return_value="Linux"), \
            patch.object(worker.platform, "release", return_value="6.6-microsoft-standard-WSL2"), \
            patch.object(worker.platform, "machine", return_value="x86_64"), \
            patch.object(worker.Path, "read_bytes", return_value=b'PRETTY_NAME="Fixture Linux"\nVERSION_ID="22.04"\n'), \
            patch.object(worker.platform, "python_version", return_value="3.10.12"):
        return worker.probe_platform(request, runner=runner)


class TestSnapshot(unittest.TestCase):
    def test_configured_and_unchecked_states_remain_explicit(self):
        snapshot = packet()["snapshot"]
        snapshot["gpu_devices"] = worker.field("CONFIGURED", [], [], "explicit empty fixture configuration")
        snapshot["nvcc_version"] = worker.field("NOT_CHECKED", method="not queried")
        model = seal_snapshot(snapshot)
        self.assertEqual(model.gpu_devices.status, "CONFIGURED")
        self.assertEqual(model.nvcc_version.status, "NOT_CHECKED")
        self.assertIn("NOT_CHECKED", format_for_prompt(model.model_dump(mode="json")))

    def test_real_fixture_contract_and_multi_gpu(self):
        snap = PlatformSnapshot.model_validate(packet()["snapshot"])
        devices = snap.gpu_devices.value
        self.assertEqual([d["sm_arch"]["value"] for d in devices], ["sm_75", "sm_86"])
        self.assertTrue(all(d["sm_arch"]["status"] == "INFERRED" for d in devices))
        self.assertEqual(snap.cuda_driver_api_version.status, "NOT_CHECKED")
        self.assertEqual(snap.driver_release.value, "555.42")
        self.assertEqual(snap.cuda_toolkit_version.value, "12.8")

    def test_no_gpu_is_observed_empty_not_unknown(self):
        snapshot = packet(gpu=b"")["snapshot"]
        self.assertEqual(snapshot["gpu_devices"]["status"], "OBSERVED")
        self.assertEqual(snapshot["gpu_devices"]["value"], [])
        self.assertNotIn("sm_75", format_for_prompt(snapshot).split("gpu_devices:")[1].splitlines()[0])

    def test_missing_smi_gpu_unknown(self):
        snapshot = packet(missing=("nvidia-smi",))["snapshot"]
        self.assertEqual(snapshot["gpu_devices"]["status"], "UNKNOWN")
        self.assertIsNone(snapshot["gpu_devices"]["value"])
        PlatformSnapshot.model_validate(snapshot)

    def test_failed_gpu_query_stays_failed(self):
        snapshot = packet(failures=("gpu_query", "gpu_query_fallback"))["snapshot"]
        self.assertEqual(snapshot["gpu_devices"]["status"], "FAILED")
        self.assertIsNone(snapshot["gpu_devices"]["value"])

    def test_unsupported_capability_never_inferred_from_name(self):
        snapshot = packet(unsupported_cap=True)["snapshot"]
        self.assertIsNone(snapshot["gpu_devices"]["value"][0]["sm_arch"]["value"])
        self.assertEqual(snapshot["gpu_devices"]["value"][0]["compute_capability"]["status"], "UNKNOWN")

    def test_missing_nvcc_has_no_historical_arch_list(self):
        snapshot = packet(missing=("nvcc",))["snapshot"]
        self.assertEqual(snapshot["supported_architectures"]["status"], "UNKNOWN")
        self.assertIsNone(snapshot["supported_architectures"]["value"])
        self.assertIsNone(_probe_nvcc_archs(""))

    def test_failed_tool_version_is_not_observed(self):
        snapshot = packet(failures=("nvcc_version", "sanitizer_version"))["snapshot"]
        self.assertEqual(snapshot["nvcc_version"]["status"], "FAILED")
        self.assertEqual(snapshot["compute_sanitizer_version"]["status"], "FAILED")
        self.assertEqual(snapshot["probe_status"], "PARTIAL")

    def test_umd_label_not_forged_as_compatibility_or_api(self):
        snapshot = packet(umd=True)["snapshot"]
        self.assertEqual(snapshot["driver_reported_cuda_version"]["status"], "UNKNOWN")
        self.assertEqual(snapshot["metadata"]["reported_cuda_umd_version"]["value"], "13.4")
        self.assertIsNone(snapshot["cuda_driver_api_version"]["value"])

    def test_identity_excludes_run_time_ids_methods_and_paths(self):
        first = packet()["snapshot"]
        second = deepcopy(first)
        second["metadata"].update(probe_id="different", nonce="different", started_at="different", temporary_path="/tmp/other")
        second["nvcc_path"]["value"] = "/temporary/other/nvcc"
        second["provenance"]["python_stdlib"]["method"] = "other method description"
        self.assertEqual(compute_environment_id(first), compute_environment_id(second))
        second["nvcc_version"]["value"] = "13.0"
        self.assertNotEqual(compute_environment_id(first), compute_environment_id(second))

    def test_corrupt_identity_is_rejected_not_repaired(self):
        snapshot = packet()["snapshot"]
        snapshot["environment_id"] = "sha256:" + "0" * 64
        with self.assertRaises(ValueError):
            PlatformSnapshot.model_validate(snapshot)

    def test_observed_requires_provenance_and_nonnull(self):
        for change in ({"source_ids": []}, {"source_ids": ["invented"]}, {"value": None}):
            snapshot = packet()["snapshot"]
            snapshot["nvcc_version"].update(change)
            with self.assertRaises(ValueError):
                seal_snapshot(snapshot)

    def test_unknown_cannot_carry_default_arch_value(self):
        snapshot = packet()["snapshot"]
        snapshot["supported_architectures"].update(status="UNKNOWN", value=["sm_75"])
        with self.assertRaises(ValueError):
            seal_snapshot(snapshot)

    def test_windows_tool_path_cannot_be_linux_snapshot(self):
        snapshot = packet()["snapshot"]
        snapshot["nvcc_path"]["value"] = "C:\\CUDA\\nvcc.exe"
        with self.assertRaises(ValueError):
            seal_snapshot(snapshot)

    def test_foreign_provenance_and_invalid_metadata_observation_rejected(self):
        for change in ("environment", "umd"):
            snapshot = packet()["snapshot"]
            if change == "environment":
                snapshot["provenance"]["nvcc_version"]["environment"] = "windows"
            else:
                snapshot["metadata"]["reported_cuda_umd_version"] = {"value": "13.4"}
            with self.subTest(change=change), self.assertRaises(ValueError):
                seal_snapshot(snapshot)

    def test_worker_never_compiles_smoke_or_queries_uuid(self):
        fixture = packet()
        for item in fixture["commands"]:
            self.assertNotIn("-cubin", item["argv"])
            self.assertNotIn("-arch=sm_75", item["argv"])
            self.assertFalse(any("uuid" in arg for arg in item["argv"]))
        self.assertEqual(fixture["snapshot"]["metadata"]["smoke_test"], "NOT_RUN")

    def test_localized_compiler_banner_and_ambiguous_build(self):
        self.assertEqual(worker._compiler_version("MSVC 版本 19.29.30159 for x64", "cl"), "19.29.30159")
        self.assertIsNone(worker._compiler_version("19.29.30159 versus 19.30.30000", "cl"))


class TestBoundedRunner(unittest.TestCase):
    def test_exact_bytes_both_streams_and_exitcode(self):
        r = run_bounded([sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'raw\\r\\n');sys.stderr.buffer.write(b'err\\x00');sys.exit(7)"], timeout_seconds=5)
        self.assertEqual(r["returncode"], 7)
        self.assertEqual(base64.b64decode(r["stdout_b64"]), b"raw\r\n")
        self.assertEqual(base64.b64decode(r["stderr_b64"]), b"err\0")

    def test_timeout_is_bounded(self):
        r = run_bounded([sys.executable, "-c", "import time;time.sleep(5)"], timeout_seconds=0.1)
        self.assertEqual(r["status"], "TIMED_OUT")
        self.assertTrue(r["timed_out"])

    def test_output_limit_rejects_not_trusts_truncated_json(self):
        r = run_bounded([sys.executable, "-c", "import sys;sys.stdout.write('x'*100000)"], timeout_seconds=5, max_output_bytes=100)
        self.assertEqual(r["status"], "OUTPUT_LIMIT")
        self.assertTrue(r["truncated"])
        self.assertLessEqual(len(base64.b64decode(r["stdout_b64"])) + len(base64.b64decode(r["stderr_b64"])), 100)

    def test_missing_command_is_start_failed(self):
        r = run_bounded(["cuda-poc-readonly-fixture-does-not-exist"], timeout_seconds=1)
        self.assertEqual(r["status"], "START_FAILED")
        self.assertIsNone(r["returncode"])


class TestBridge(unittest.TestCase):
    def test_list_failure_is_recorded_without_dispatch(self):
        for status, code in (("TIMED_OUT", None), ("OUTPUT_LIMIT", -1), ("COMPLETED", 2)):
            with self.subTest(status=status):
                listing = record("wsl_distro_list", ["wsl.exe"], rc=code, status=status)
                with patch.object(bridge.shutil, "which", return_value="wsl.exe"), \
                        patch.object(bridge, "run_bounded", return_value=listing) as call:
                    result = bridge.probe_wsl(probe_id="p", nonce="n")
                self.assertEqual(call.call_count, 1)
                self.assertEqual(result["status"], "FAILED")

    def test_duplicate_envelope_and_wrong_backend_rejected(self):
        p = packet(probe_id="p", nonce="n")
        for raw in (b'{"nonce":"old","nonce":"n"}', json.dumps(p).encode()):
            with self.assertRaises(ValueError):
                bridge.parse_packet(raw, probe_id="p", nonce="n", backend="local")

    def collect(self, mode="success"):
        def runner(argv, **kwargs):
            if "--list" in argv:
                return record("wsl_distro_list", argv, "Ubuntu-22.04\r\n".encode("utf-16-le"), environment="windows_dispatcher")
            raw = json.dumps(packet(probe_id="probe", nonce="nonce" if mode != "stale" else "old")).encode()
            if mode == "invalid": raw = b"{broken"
            status = {"timeout": "TIMED_OUT", "large": "OUTPUT_LIMIT"}.get(mode, "COMPLETED")
            rc = 5 if mode == "nonzero" else 0
            return record("wsl_worker", argv, raw, rc=rc, status=status, environment="windows_dispatcher")
        with patch.object(bridge.shutil, "which", return_value="wsl.exe"), \
                patch.object(bridge, "run_bounded", side_effect=runner) as calls:
            result = bridge.probe_wsl(probe_id="probe", nonce="nonce")
        return result, calls

    def test_valid_transport_keeps_two_exit_states_and_argv(self):
        r, calls = self.collect()
        self.assertIsNotNone(r["snapshot"])
        self.assertEqual(r["transport"], {"launcher_returncode": 0, "worker_reported_exit_code": 0})
        argv = calls.call_args.args[0]
        self.assertIn("--exec", argv)
        self.assertNotIn("bash", argv)
        self.assertNotIn("-c", argv)
        self.assertEqual(argv[-3:], ["/home/pocdev/.venvs/cuda-poc-generator/bin/python", "-I", "-"])

    def test_missing_wsl(self):
        with patch.object(bridge.shutil, "which", return_value=None):
            self.assertEqual(bridge.probe_wsl(probe_id="p", nonce="n")["diagnostics"][0]["code"], "WSL_UNAVAILABLE")

    def test_missing_distribution(self):
        listing = record("list", ["wsl"], b"OtherDistro\n")
        with patch.object(bridge.shutil, "which", return_value="wsl.exe"), patch.object(bridge, "run_bounded", return_value=listing) as call:
            result = bridge.probe_wsl(probe_id="p", nonce="n")
        self.assertEqual(result["diagnostics"][0]["code"], "WSL_DISTRO_NOT_FOUND")
        self.assertEqual(call.call_count, 1)

    def test_failure_modes_never_reuse_snapshot(self):
        for mode in ("timeout", "large", "nonzero", "invalid", "stale"):
            with self.subTest(mode=mode):
                result, _ = self.collect(mode)
                self.assertEqual(result["status"], "FAILED")
                self.assertIsNone(result["snapshot"])
                self.assertIsNone(result["transport"]["worker_reported_exit_code"])

    def test_windows_python_or_command_injection_rejected(self):
        for kwargs in ({"linux_python": "C:\\repo\\.venv\\Scripts\\python.exe"}, {"linux_python": "/bin/bash"},
                       {"distro": "-execute"}, {"distro": "Ubuntu; touch evil"}, {"user": "pocdev\ncmd"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                bridge.probe_wsl(probe_id="p", nonce="n", **kwargs)

    def test_corrupt_raw_command_evidence_is_rejected(self):
        p = packet(probe_id="p", nonce="n")
        p["commands"][0]["stdout_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            bridge.parse_packet(json.dumps(p).encode(), probe_id="p", nonce="n", backend="wsl")

    def test_malformed_command_metadata_is_rejected(self):
        for changes in ({"argv": [None]}, {"timeout_seconds": True}, {"max_output_bytes": 1},
                        {"duration_seconds": -1}, {"started_at": "yesterday"}, {"returncode": None}):
            p = packet(probe_id="p", nonce="n")
            p["commands"][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                bridge.parse_packet(json.dumps(p).encode(), probe_id="p", nonce="n", backend="wsl")

    def test_invalid_service_options_do_not_start_host_queries(self):
        for options in ({"backend": "wsl", "linux_python": "C:\\python.exe"},
                        {"timeout_seconds": float("nan")}, {"max_output_bytes": False}):
            with self.subTest(options=options), patch.object(service, "_collect_local") as host, self.assertRaises(ValueError):
                service.run_platform_probe(**options)
            host.assert_not_called()


class TestArtifacts(unittest.TestCase):
    def test_failed_probe_generates_diagnostics_without_old_snapshot(self):
        result = {"probe_id": "failed", "status": "FAILED", "snapshot": None, "host_snapshot": None,
                  "commands": [], "diagnostics": [{"code": "WSL_UNAVAILABLE", "field": "bridge", "message": "No worker response."}],
                  "stdout_b64": "", "stderr_b64": "", "transport": {"launcher_returncode": None, "worker_reported_exit_code": None}}
        with tempfile.TemporaryDirectory() as directory:
            path = write_probe_artifacts(directory, result)
            self.assertIsNone(json.loads((path / "platform_snapshot.json").read_text()))
            self.assertIn("FAILED", (path / "probe_report.md").read_text())
            self.assertIn("WSL_UNAVAILABLE", (path / "probe_report.md").read_text())


class TestLegacyEnvironmentHelpers(unittest.TestCase):
    def test_gpu_missing_never_returns_an_architecture(self):
        from src.tools import env
        with patch.object(env.shutil, "which", return_value=None):
            self.assertIsNone(env.get_gpu_compute_capability())

    def test_driver_library_unavailable_never_fabricates_api_version(self):
        from src.tools import env
        import ctypes
        library = "WinDLL" if os.name == "nt" else "CDLL"
        with patch.object(ctypes, library, side_effect=OSError("offline missing library")), \
                patch.object(env.subprocess, "check_output", side_effect=AssertionError("driver release must not be used")):
            self.assertIsNone(env.get_cuda_driver_version())

    def test_missing_toolkit_returns_unknown(self):
        from src.tools import env
        with patch.object(env, "find_cuda_tool", side_effect=FileNotFoundError):
            self.assertEqual(env.get_cuda_toolkit_version(), "unknown")

class TestAdditionalArtifacts(unittest.TestCase):
    def test_reader_requires_probe_identity_and_rejects_old_snapshot(self):
        fixture = packet()["snapshot"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            self.assertEqual(service.read_snapshot(path, expected_probe_id="fixture-id").environment_id, fixture["environment_id"])
            with self.assertRaises(ValueError):
                service.read_snapshot(path, expected_probe_id="new-run")

    def test_private_files_exact_raw_and_deterministic_redacted_report(self):
        snap = packet()["snapshot"]
        result = {"probe_id": "fixture", "status": "PARTIAL", "snapshot": snap, "host_snapshot": None,
                  "commands": packet()["commands"], "diagnostics": snap["diagnostics"],
                  "stdout_b64": base64.b64encode(b"raw\r\n").decode(), "stderr_b64": "",
                  "transport": {"launcher_returncode": 0, "worker_reported_exit_code": 0}}
        with tempfile.TemporaryDirectory() as directory:
            path = write_probe_artifacts(directory, result)
            self.assertEqual((path / "probe_stdout.log").read_bytes(), b"raw\r\n")
            report_text = (path / "probe_report.md").read_text(encoding="utf-8")
            self.assertEqual(report_text, render_report(result))
            self.assertNotIn("/tools/nvcc", report_text)
            self.assertIn("NOT_VERIFIED", report_text)
            self.assertIn("No validated current snapshot", report_text)
            self.assertEqual(json.loads((path / "probe_result.json").read_text())["access_control"]["status"], "APPLIED")
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)


class TestPipelineTarget(OfflineTestCase):
    def test_explicit_wsl_uses_target_only_without_local_paths(self):
        from src.llm_client import StructuredResponse
        fake = self.fake_llm()
        fake.structured_generate.return_value = StructuredResponse(deepcopy(ANALYSIS), json.dumps(ANALYSIS))
        snap = packet()["snapshot"]
        cfg = self.config()
        cfg.config["rag"]["enabled"] = False
        with tempfile.TemporaryDirectory() as directory:
            cfg.config["paths"]["outputs_dir"] = directory
            with patch.object(self.pipeline_module, "ConfigLoader", return_value=cfg), \
                    patch.object(self.pipeline_module, "LLMClient", return_value=fake), \
                    patch.object(self.pipeline_module, "probe_environment", side_effect=AssertionError("local target must not be used")), \
                    patch.object(service, "run_platform_probe", return_value={"snapshot": snap, "status": "PARTIAL", "diagnostics": []}) as probe, \
                    patch.object(self.pipeline_module.CudaDataLoader, "build_or_load_knowledge_base"), \
                    patch.object(self.pipeline_module.CudaPipeline, "_query_web_search", return_value=""):
                r = self.pipeline_module.CudaPipeline().run(input_dir=str(PROJECT_ROOT / "data/inputs/CVE-2024-0124"), target_backend="wsl")
            self.assertEqual(r["candidate"]["execution"], "NOT_EXECUTED")
            self.assertEqual(r["candidate"]["verification"], "NOT_VERIFIED")
            self.assertEqual(probe.call_args.kwargs["backend"], "wsl")
            prompt = fake.chat.call_args.kwargs["messages"][1]["content"]
            self.assertIn("TARGET PLATFORM SNAPSHOT", prompt)
            self.assertNotIn("C:\\\\", prompt)

    def test_failed_wsl_blocks_generation_no_stale_default(self):
        cfg = self.config()
        fake = self.fake_llm()
        with tempfile.TemporaryDirectory() as directory:
            cfg.config["paths"]["outputs_dir"] = directory
            with patch.object(self.pipeline_module, "ConfigLoader", return_value=cfg), \
                    patch.object(self.pipeline_module, "LLMClient", return_value=fake), \
                    patch.object(service, "run_platform_probe", return_value={"snapshot": None, "status": "FAILED", "diagnostics": []}), \
                    patch.object(self.pipeline_module.CudaDataLoader, "build_or_load_knowledge_base"), \
                    patch.object(self.pipeline_module.CudaPipeline, "_query_web_search", return_value=""):
                with self.assertRaises(RuntimeError):
                    self.pipeline_module.CudaPipeline().run(input_dir=str(PROJECT_ROOT / "data/inputs/CVE-2024-0124"), target_backend="wsl")
            fake.chat.assert_not_called()
            fake.structured_generate.assert_not_called()

    def test_legacy_context_is_not_observed_default_arch(self):
        text = format_for_prompt({"gpu": {"gpu_count": 0}, "toolchain": {}})
        self.assertIn("NOT_CHECKED", text)
        self.assertNotIn("sm_75", text)

    def test_target_view_preserves_source_and_nonpath_analysis(self):
        value = {"step": "Use C:\\CUDA\\bin\\nvcc.exe or \\\\server\\share\\nvcc.exe only after checking version", "id": "S01"}
        original = deepcopy(value)
        view = self.pipeline_module.CudaPipeline._target_view(value, {"platform_type": "wsl"})
        self.assertEqual(value, original)
        self.assertNotIn("C:\\", view["step"])
        self.assertNotIn("\\\\server", view["step"])
        self.assertIn("after checking version", view["step"])
        self.assertEqual(view["id"], "S01")


if __name__ == "__main__":
    unittest.main()
