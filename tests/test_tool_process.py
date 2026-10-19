"""Offline process observations: only harmless synthetic Python children run."""

import base64
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from pydantic import ValidationError

from src.models.tool_result import ToolResult, compute_record_id, digest_argv, seal_tool_result
from src.tool_artifacts import ToolEvidenceError, prepare_tool_directory, read_tool_evidence, write_tool_evidence
from src.tools.process import classify_returncode, current_platform_type, run_tool


class ToolProcessTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_python(self, source, **kwargs):
        return run_tool([sys.executable, "-I", "-c", source], artifact_root=self.root, **kwargs)


class TestToolProcess(ToolProcessTestCase):
    def test_exact_binary_output_and_persisted_hashes(self):
        result = self.run_python("import os; os.write(1,b'\\x00\\xff\\r\\n'); os.write(2,b'warning\\x80')")
        self.assertEqual(result.end_status, "NORMAL_EXIT")
        self.assertEqual(result.stdout_bytes(), b"\0\xff\r\n")
        self.assertEqual(result.stderr_bytes(), b"warning\x80")
        self.assertEqual(result.stdout_sha256, hashlib.sha256(result.stdout_bytes()).hexdigest())
        self.assertEqual(read_tool_evidence(result.evidence_directory), result)
        self.assertEqual(result.tool_identity.status, "OBSERVED")
        self.assertEqual(result.candidate_execution_status, "NOT_EXECUTED")
        self.assertEqual(result.verification_status, "NOT_VERIFIED")

    def test_nonzero_exit_is_not_signal_or_verification(self):
        result = self.run_python("import sys; print('partial output'); sys.exit(7)")
        self.assertEqual(result.end_status, "NONZERO_EXIT")
        self.assertEqual(result.returncode, 7)
        self.assertFalse(result.ok)
        self.assertIsNone(result.linux_signal)
        self.assertIsNone(result.windows_exception_code)
        self.assertEqual(result.verification_status, "NOT_VERIFIED")
        self.assertEqual(read_tool_evidence(result.evidence_directory).returncode, 7)

    def test_start_failure_still_has_evidence(self):
        result = run_tool([str(self.root / "definitely-no-tool")], artifact_root=self.root)
        self.assertEqual(result.end_status, "START_FAILED")
        self.assertEqual(result.start_status, "START_FAILED")
        self.assertIsNone(result.returncode)
        self.assertEqual(result.tool_identity.status, "UNKNOWN")
        self.assertEqual(read_tool_evidence(result.evidence_directory), result)

    def test_failed_tool_discovery_never_launches_an_existing_fallback(self):
        with patch("src.tools.process.subprocess.Popen", side_effect=AssertionError("no fallback executable may launch")):
            result = self.run_python("not executed", _startup_error=FileNotFoundError("synthetic tool discovery failure"))
        self.assertEqual(result.end_status, "START_FAILED")
        self.assertIsNone(result.returncode)
        self.assertEqual(result.tool_identity.status, "UNKNOWN")
        self.assertEqual(result.stdout_bytes(), b"")
        self.assertEqual(read_tool_evidence(result.evidence_directory), result)

    def test_invalid_working_directory_is_start_failure(self):
        result = self.run_python("print('never started')", cwd=self.root / "missing")
        self.assertEqual(result.end_status, "START_FAILED")
        self.assertEqual(result.stdout_bytes(), b"")

    def test_timeout_records_raw_prefix(self):
        # The budget must exceed interpreter startup on the host under test;
        # a shorter one kills the child before it can emit the prefix and would
        # assert a host-speed property rather than prefix retention.
        result = self.run_python("import os,time; os.write(1,b'before-timeout'); time.sleep(10)", timeout_seconds=2.0)
        self.assertEqual(result.end_status, "TIMED_OUT")
        self.assertTrue(result.timed_out)
        self.assertEqual(result.stdout_bytes(), b"before-timeout")
        self.assertLess(result.duration_seconds, 4)
        self.assertEqual(read_tool_evidence(result.evidence_directory), result)

    def test_aggregate_output_limit_has_retained_byte_digest(self):
        result = self.run_python("import os; os.write(1,b'a'*10000); os.write(2,b'b'*10000)", max_output_bytes=128)
        self.assertEqual(result.end_status, "OUTPUT_LIMIT")
        self.assertTrue(result.truncated)
        self.assertEqual(len(result.stdout_bytes()) + len(result.stderr_bytes()), 128)
        manifest = json.loads((Path(result.evidence_directory) / "evidence_manifest.json").read_text())
        self.assertFalse(manifest["capture_complete"])
        self.assertEqual(read_tool_evidence(result.evidence_directory), result)

    def test_unique_runs_never_overwrite(self):
        first = self.run_python("print('first')")
        second = self.run_python("print('second')")
        self.assertNotEqual(first.run_id, second.run_id)
        self.assertNotEqual(first.evidence_directory, second.evidence_directory)
        self.assertEqual(read_tool_evidence(first.evidence_directory).stdout_bytes().strip(), b"first")

    def test_explicit_cwd_and_arguments_are_literal(self):
        folder = self.root / "folder with spaces"
        folder.mkdir()
        literal = "x; $(echo unsafe) & | < >"
        result = run_tool([sys.executable, "-I", "-c", "import os,sys; print(os.getcwd()); print(sys.argv[1])", literal],
                          cwd=folder, artifact_root=self.root)
        text = result.stdout_bytes().decode()
        self.assertIn(str(folder.resolve()), text)
        self.assertIn(literal, text)
        self.assertEqual(result.argv[-1], literal)

    def test_input_bytes_preserved_for_identity(self):
        payload = b"\0\xffliteral\n"
        result = self.run_python("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())", input_bytes=payload)
        self.assertEqual(result.stdout_bytes(), payload)
        self.assertEqual(result.stdin_sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(result.stdin_size_bytes, len(payload))

    def test_local_runner_cannot_dispatch_or_relabel_platform(self):
        foreign = "linux" if current_platform_type() == "windows" else "windows"
        with self.assertRaises(ValueError):
            self.run_python("print('must not run')", platform_type=foreign)
        with self.assertRaises(ValueError):
            self.run_python("print('must not run')", target_environment=foreign)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_foreign_absolute_cwd_is_rejected_before_launch(self):
        foreign_cwd = "/home/pocdev/project" if os.name == "nt" else "C:\\private\\project"
        with self.assertRaises(ValueError):
            self.run_python("print('must not run')", cwd=foreign_cwd)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_runner_parameters_never_start(self):
        bad = [({"timeout_seconds": 0}), ({"timeout_seconds": float("nan")}),
               ({"timeout_seconds": "bad"}), ({"env": ["not a mapping"]}),
               ({"max_output_bytes": True}), ({"max_output_bytes": 0}),
               ({"command_source": " "}), ({"input_bytes": "not bytes"})]
        for kwargs in bad:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.run_python("print('must not run')", **kwargs)
        with self.assertRaises(ValueError):
            run_tool("unsafe string command", artifact_root=self.root)
        with self.assertRaises(ValueError):
            run_tool([sys.executable, "\0"], artifact_root=self.root)
        with self.assertRaises(ValueError):
            run_tool({"fake": "mapping"}, artifact_root=self.root)
        self.assertEqual(list(self.root.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "real POSIX signal test executes only in Linux/WSL")
    def test_real_harmless_child_signal(self):
        result = self.run_python("import os,signal; os.kill(os.getpid(),signal.SIGTERM)")
        self.assertEqual(result.end_status, "SIGNAL_TERMINATED")
        self.assertEqual(result.returncode, -signal.SIGTERM)
        self.assertEqual(result.linux_signal, signal.SIGTERM)
        self.assertEqual(result.verification_status, "NOT_VERIFIED")

    def test_capture_error_has_distinct_failure(self):
        class FailedPipe(io.BytesIO):
            def read1(self, count=-1):
                raise OSError("synthetic capture failure")

        class Process:
            pid = 99999999
            stdout = FailedPipe()
            stderr = io.BytesIO()
            stdin = None

            def poll(self):
                return 0

            def wait(self, timeout=None):
                return 0

            def kill(self):
                pass

        with patch("src.tools.process.subprocess.Popen", return_value=Process()), \
                patch("src.tools.process.os.killpg", create=True):
            result = self.run_python("not executed")
        self.assertEqual(result.end_status, "CAPTURE_FAILED")
        self.assertFalse(result.ok)

    def test_wait_timeout_expired_keeps_partial_raw_and_timeout_status(self):
        class Process:
            pid = 99999999
            stdout = io.BytesIO(b"original partial output\r\n")
            stderr = io.BytesIO(b"original diagnostic")
            stdin = None
            waited = False

            def poll(self):
                return 0

            def wait(self, timeout=None):
                if not self.waited:
                    self.waited = True
                    raise subprocess.TimeoutExpired("synthetic wait", timeout)
                return 0

            def kill(self):
                pass

        with patch("src.tools.process.subprocess.Popen", return_value=Process()), \
                patch("src.tools.process.os.killpg", create=True):
            result = self.run_python("not executed")
        self.assertEqual(result.end_status, "TIMED_OUT")
        self.assertTrue(result.timed_out)
        self.assertEqual(result.stdout_bytes(), b"original partial output\r\n")
        self.assertEqual(result.stderr_bytes(), b"original diagnostic")
        self.assertFalse(result.ok)
        self.assertEqual(read_tool_evidence(result.evidence_directory), result)


class TestReturncodeSemantics(unittest.TestCase):
    def test_linux_signal_is_not_windows_exception(self):
        self.assertEqual(classify_returncode(-11, "linux"), ("SIGNAL_TERMINATED", 11, None))
        self.assertEqual(classify_returncode(-15, "wsl"), ("SIGNAL_TERMINATED", 15, None))

    def test_signed_and_unsigned_windows_exception(self):
        expected = ("WINDOWS_EXCEPTION", None, 0xc0000005)
        self.assertEqual(classify_returncode(-1073741819, "windows"), expected)
        self.assertEqual(classify_returncode(0xc0000005, "windows"), expected)
        self.assertEqual(classify_returncode(0xc000001d, "windows"), ("WINDOWS_EXCEPTION", None, 0xc000001d))

    def test_nonzero_and_timeout_not_reclassified_as_success(self):
        self.assertEqual(classify_returncode(2, "windows"), ("NONZERO_EXIT", None, None))
        self.assertEqual(classify_returncode(1, "linux"), ("NONZERO_EXIT", None, None))
        self.assertEqual(classify_returncode(-9, "linux", timed_out=True), ("TIMED_OUT", 9, None))
        self.assertEqual(classify_returncode(0, "windows", truncated=True), ("OUTPUT_LIMIT", None, None))
        self.assertEqual(classify_returncode(None, "linux", started=False), ("START_FAILED", None, None))

    def test_unknown_high_windows_exit_is_not_exception(self):
        self.assertEqual(classify_returncode(0xffffffff, "windows"), ("NONZERO_EXIT", None, None))
        self.assertEqual(classify_returncode(-1, "windows"), ("NONZERO_EXIT", None, None))
        self.assertEqual(classify_returncode(0xf1234567, "windows"), ("NONZERO_EXIT", None, None))


class TestToolEvidence(ToolProcessTestCase):
    def synthetic_record(self, platform_type):
        """Convert a harmless fixture result to an explicitly synthetic OS record."""
        value = self.run_python("print('synthetic fixture')").model_dump(mode="json")
        value["platform_type"] = platform_type
        value["cwd"] = "C:\\fixture" if platform_type == "windows" else "/fixture"
        executable = "C:\\fixture\\python.exe" if platform_type == "windows" else "/fixture/python"
        value["tool_identity"]["resolved_path"] = executable
        value["argv"][0] = executable
        value["command_identity"]["argv_sha256"] = digest_argv(value["argv"])
        value["resource_limits"]["termination_scope"] = "WINDOWS_DIRECT_CHILD" if platform_type == "windows" else "POSIX_PROCESS_GROUP"
        value["record_id"] = compute_record_id(value)
        ToolResult.model_validate(value)
        return value

    def test_model_rejects_forged_output_and_identity(self):
        result = self.run_python("print('fixture')")
        bad = result.model_dump(mode="json")
        bad["stdout_b64"] = base64.b64encode(b"forged").decode()
        with self.assertRaises(ValidationError):
            ToolResult.model_validate(bad)
        bad = result.model_dump(mode="json")
        bad["argv"][-1] = "other source"
        with self.assertRaises(ValidationError):
            ToolResult.model_validate(bad)

    def test_new_result_sealing_normalizes_legal_defaults_and_numbers(self):
        value = self.run_python("print('fixture')").model_dump(mode="json")
        value["resource_limits"] = {"timeout_seconds": 3, "max_output_bytes": 4096,
                                    "termination_scope": value["resource_limits"]["termination_scope"]}
        value["duration_seconds"] = 1
        del value["capture_failed"]
        result = seal_tool_result(value)
        self.assertEqual(result.resource_limits.timeout_seconds, 3.0)
        self.assertEqual(result.duration_seconds, 1.0)
        self.assertEqual(result.resource_limits.memory_limit_status, "NOT_ENFORCED")
        self.assertEqual(ToolResult.model_validate(result.model_dump(mode="json")), result)

    def test_model_rejects_success_with_timeout_even_resealed(self):
        result = self.run_python("print('fixture')")
        bad = result.model_dump(mode="json")
        bad["timed_out"] = True
        bad["record_id"] = compute_record_id(bad)
        with self.assertRaises(ValidationError):
            ToolResult.model_validate(bad)

    def test_model_rejects_unknown_executable_digest(self):
        result = self.run_python("print('fixture')")
        bad = deepcopy(result.model_dump(mode="json"))
        bad["tool_identity"]["status"] = "UNKNOWN"
        bad["record_id"] = compute_record_id(bad)
        with self.assertRaises(ValidationError):
            ToolResult.model_validate(bad)

    def test_model_rejects_relative_or_foreign_platform_paths(self):
        result = self.run_python("print('fixture')")
        for path in ("relative-path", "/home/pocdev" if os.name == "nt" else "C:\\private\\project"):
            bad = deepcopy(result.model_dump(mode="json"))
            bad["cwd"] = path
            bad["record_id"] = compute_record_id(bad)
            with self.subTest(path=path), self.assertRaises(ValidationError):
                ToolResult.model_validate(bad)

    def test_model_rejects_omitted_signal_or_exception_even_resealed(self):
        for platform_type, returncode in (("linux", -11), ("windows", 0xc0000005)):
            bad = self.synthetic_record(platform_type)
            bad["returncode"] = returncode
            bad["end_status"] = "NONZERO_EXIT"
            bad["record_id"] = compute_record_id(bad)
            with self.subTest(platform_type=platform_type), self.assertRaises(ValidationError):
                ToolResult.model_validate(bad)

    def test_model_enforces_timeout_output_capture_precedence(self):
        for changes in ({"returncode": -11, "linux_signal": 11, "end_status": "SIGNAL_TERMINATED", "timed_out": True},
                        {"returncode": -11, "linux_signal": 11, "end_status": "SIGNAL_TERMINATED", "truncated": True},
                        {"end_status": "NORMAL_EXIT", "capture_failed": True}):
            bad = self.synthetic_record("linux")
            bad.update(changes)
            bad["record_id"] = compute_record_id(bad)
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                ToolResult.model_validate(bad)

    def test_model_rejects_wrong_process_termination_scope(self):
        bad = self.synthetic_record("windows")
        bad["resource_limits"]["termination_scope"] = "POSIX_PROCESS_GROUP"
        bad["record_id"] = compute_record_id(bad)
        with self.assertRaises(ValidationError):
            ToolResult.model_validate(bad)

    def test_timeout_incomplete_capture_is_not_manifest_complete(self):
        value = self.synthetic_record("windows")
        value.update({"end_status": "TIMED_OUT", "timed_out": True, "capture_failed": True})
        value["run_id"] = "e" * 32
        folder, protection = prepare_tool_directory(self.root, value["run_id"])
        value["evidence_directory"] = str(folder)
        value["record_id"] = compute_record_id(value)
        result = ToolResult.model_validate(value)
        manifest = write_tool_evidence(folder, result, protection)
        self.assertFalse(manifest["capture_complete"])
        self.assertEqual(read_tool_evidence(folder).end_status, "TIMED_OUT")

    def test_reader_rejects_changed_raw_output(self):
        result = self.run_python("print('fixture')")
        (Path(result.evidence_directory) / "stdout.bin").write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            read_tool_evidence(result.evidence_directory)

    def test_storage_failure_exposes_actual_result_without_fake_success(self):
        result = self.run_python("print('retained bytes')")
        with patch("src.tool_artifacts.Path.open", side_effect=OSError("synthetic disk full")):
            with self.assertRaises(ToolEvidenceError) as caught:
                write_tool_evidence(Path(result.evidence_directory), result,
                                    {"status": "APPLIED", "method": "fixture protection"})
        self.assertEqual(caught.exception.tool_result.stdout_bytes(), result.stdout_bytes())
        self.assertEqual(caught.exception.tool_result.verification_status, "NOT_VERIFIED")

    def test_reader_rejects_manifest_path_escape(self):
        result = self.run_python("print('fixture')")
        file = Path(result.evidence_directory) / "evidence_manifest.json"
        manifest = json.loads(file.read_text())
        manifest["artifacts"]["../stdout.bin"] = manifest["artifacts"].pop("stdout.bin")
        file.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            read_tool_evidence(result.evidence_directory)

    def test_reader_binds_expected_run_and_content_identity(self):
        result = self.run_python("print('fixture')")
        self.assertEqual(read_tool_evidence(result.evidence_directory, expected_run_id=result.run_id,
                                           expected_record_id=result.record_id), result)
        with self.assertRaises(ValueError):
            read_tool_evidence(result.evidence_directory, expected_run_id="0" * 32)
        with self.assertRaises(ValueError):
            read_tool_evidence(result.evidence_directory, expected_record_id="sha256:" + "0" * 64)

    def test_reader_rejects_duplicate_manifest_keys(self):
        result = self.run_python("print('fixture')")
        file = Path(result.evidence_directory) / "evidence_manifest.json"
        file.write_bytes(b'{"schema_version":"1.0",' + file.read_bytes()[1:])
        with self.assertRaises(ValueError):
            read_tool_evidence(result.evidence_directory)

    def test_reader_rejects_false_manifest_verification(self):
        result = self.run_python("print('fixture')")
        file = Path(result.evidence_directory) / "evidence_manifest.json"
        manifest = json.loads(file.read_text())
        manifest["verification_status"] = "VERIFIED"
        file.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            read_tool_evidence(result.evidence_directory)

    def test_access_control_is_recorded_and_posix_permissions_apply(self):
        result = self.run_python("print('fixture')")
        folder = Path(result.evidence_directory)
        manifest = json.loads((folder / "evidence_manifest.json").read_text())
        self.assertEqual(manifest["access_control"]["status"], "APPLIED")
        if os.name != "nt":
            self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
            for file in folder.iterdir():
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)

    @unittest.skipIf(os.name == "nt", "POSIX filesystem permission verification")
    def test_ineffective_directory_permissions_fail_before_process(self):
        with patch("src.tool_artifacts.protect_directory", return_value={"status": "APPLIED", "method": "synthetic unsupported filesystem"}), \
                patch("src.tool_artifacts.Path.stat") as stat, \
                patch("src.tools.process.subprocess.Popen") as launch:
            stat.return_value.st_mode = 0o777
            with self.assertRaisesRegex(OSError, "native Linux filesystem"):
                self.run_python("must not run")
            launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
