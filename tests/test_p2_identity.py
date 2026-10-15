"""P2 fail-closed tool identities; only a fixed harmless Python child runs."""

import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.tool_artifacts import read_tool_evidence
from src.tools.process import (canonical_target_environment, current_platform_type,
                               measure_tool_identity, run_tool)


class TestP2ToolIdentity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def harmless_python(self, **kwargs):
        return run_tool([sys.executable, "-I", "-c", "print('fixed harmless identity fixture')"],
                        artifact_root=self.root, **kwargs)

    def assert_blocked(self, result, diagnostic):
        self.assertEqual(result.start_status, "START_FAILED")
        self.assertEqual(result.end_status, "START_FAILED")
        self.assertIsNone(result.returncode)
        self.assertEqual(result.stdout_bytes(), b"")
        self.assertEqual(result.stderr_bytes(), b"")
        self.assertEqual(result.candidate_execution_status, "NOT_EXECUTED")
        self.assertEqual(result.verification_status, "NOT_VERIFIED")
        self.assertIn(diagnostic, [item.code for item in result.diagnostics])
        self.assertEqual(read_tool_evidence(result.evidence_directory), result)

    def test_missing_file_never_launches(self):
        with patch("src.tools.process.subprocess.Popen") as launch:
            result = run_tool([str(self.root / "no-tool")], artifact_root=self.root)
        launch.assert_not_called()
        self.assertEqual(result.tool_identity.status, "UNKNOWN")
        self.assert_blocked(result, "TOOL_IDENTITY_UNKNOWN")

    def test_failed_path_lookup_never_retries_popen(self):
        with patch("src.tools.process.subprocess.Popen") as launch:
            result = run_tool(["definitely-not-a-tool"], env={"PATH": ""}, artifact_root=self.root)
        launch.assert_not_called()
        self.assertEqual(result.tool_identity.status, "UNKNOWN")
        self.assert_blocked(result, "TOOL_IDENTITY_UNKNOWN")

    def test_hash_read_failure_never_launches_resolved_file(self):
        with patch("src.tools.process.open", side_effect=PermissionError("fixed synthetic unreadable executable"), create=True), \
                patch("src.tools.process.subprocess.Popen") as launch:
            result = self.harmless_python()
        launch.assert_not_called()
        self.assertIsNotNone(result.tool_identity.resolved_path)
        self.assertEqual(result.tool_identity.status, "UNKNOWN")
        self.assertIsNone(result.tool_identity.file_sha256)
        self.assert_blocked(result, "TOOL_IDENTITY_UNKNOWN")

    def test_failed_measurement_api_preserves_unknown(self):
        with patch("src.tools.process.open", side_effect=PermissionError("fixed synthetic hash read failure"), create=True), \
                patch("src.tools.process.subprocess.Popen") as launch:
            identity = measure_tool_identity(sys.executable)
        launch.assert_not_called()
        self.assertEqual(identity.status, "UNKNOWN")
        self.assertIsNone(identity.file_sha256)

    def test_missing_measurement_api_preserves_unknown(self):
        identity = measure_tool_identity(str(self.root / "missing"))
        self.assertEqual(identity.status, "UNKNOWN")
        self.assertIsNone(identity.resolved_path)

    def test_file_changed_while_hashing_has_no_usable_identity(self):
        file = self.root / "never-executed-measurement-file"
        file.write_bytes(b"fixed harmless initial bytes")
        original_open = open

        class ChangingReader:
            def __init__(self, stream):
                self.stream = stream
                self.changed = False

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.stream.close()

            def fileno(self):
                return self.stream.fileno()

            def read(self, count):
                data = self.stream.read(count)
                if not self.changed:
                    self.changed = True
                    file.write_bytes(b"fixed harmless replacement bytes of another size")
                return data

        def changing_open(path, *args, **kwargs):
            return ChangingReader(original_open(path, *args, **kwargs))

        with patch("src.tools.process.open", side_effect=changing_open, create=True), \
                patch("src.tools.process.subprocess.Popen") as launch:
            identity = measure_tool_identity(str(file))
        launch.assert_not_called()
        self.assertEqual(identity.status, "UNKNOWN")
        self.assertIsNone(identity.file_sha256)

    def test_empty_allowlist_denies_measurable_tool(self):
        with patch("src.tools.process.subprocess.Popen") as launch:
            result = self.harmless_python(allowed_tool_identities={})
        launch.assert_not_called()
        self.assertEqual(result.tool_identity.status, "OBSERVED")
        self.assert_blocked(result, "TOOL_IDENTITY_NOT_ALLOWED")

    def test_hash_mismatch_denies_measurable_tool(self):
        identity = measure_tool_identity(sys.executable)
        with patch("src.tools.process.subprocess.Popen") as launch:
            result = self.harmless_python(allowed_tool_identities={identity.resolved_path: "0" * 64})
        launch.assert_not_called()
        self.assert_blocked(result, "TOOL_IDENTITY_NOT_ALLOWED")

    def test_other_path_is_not_an_allowlist_match(self):
        identity = measure_tool_identity(sys.executable)
        other_path = self.root / "other-executable"
        other_path.write_bytes(b"fixed harmless file, never executed")
        with patch("src.tools.process.subprocess.Popen") as launch:
            result = self.harmless_python(allowed_tool_identities={str(other_path): identity.file_sha256})
        launch.assert_not_called()
        self.assert_blocked(result, "TOOL_IDENTITY_NOT_ALLOWED")

    def test_valid_allowlist_runs_only_harmless_fixture_and_records_identity(self):
        identity = measure_tool_identity(sys.executable)
        result = self.harmless_python(allowed_tool_identities={identity.resolved_path: identity.file_sha256})
        self.assertEqual(result.end_status, "NORMAL_EXIT")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.tool_identity.file_sha256, identity.file_sha256)
        self.assertEqual(result.tool_identity.resolved_path, identity.resolved_path)
        self.assertEqual(result.stdout_bytes(), b"fixed harmless identity fixture\r\n" if os.name == "nt" else b"fixed harmless identity fixture\n")
        self.assertEqual(result.target_environment, canonical_target_environment())
        self.assertEqual(read_tool_evidence(result.evidence_directory), result)

    def test_replacement_between_measurement_and_launch_is_denied(self):
        from src.tools import process

        file = self.root / "never-executed-file"
        initial = b"fixed harmless initial bytes"
        file.write_bytes(initial)
        original_measure = process._tool_identity
        calls = 0

        def substitute(executable, cwd, env, source):
            nonlocal calls
            calls += 1
            if calls == 2:
                file.write_bytes(b"fixed harmless replacement bytes")
            return original_measure(executable, cwd, env, source)

        with patch("src.tools.process._tool_identity", side_effect=substitute), \
                patch("src.tools.process.subprocess.Popen") as launch:
            result = run_tool([str(file)], artifact_root=self.root,
                              allowed_tool_identities={str(file): hashlib.sha256(initial).hexdigest()})
        self.assertEqual(calls, 2)
        launch.assert_not_called()
        self.assert_blocked(result, "TOOL_IDENTITY_CHANGED")

    def test_second_measurement_failure_is_denied(self):
        from src.tools import process

        original_measure = process._tool_identity
        calls = 0

        def fail_second_measurement(executable, cwd, env, source):
            nonlocal calls
            calls += 1
            identity = original_measure(executable, cwd, env, source)
            if calls == 2:
                identity.update(status="UNKNOWN", file_sha256=None)
            return identity

        with patch("src.tools.process._tool_identity", side_effect=fail_second_measurement), \
                patch("src.tools.process.subprocess.Popen") as launch:
            result = self.harmless_python()
        launch.assert_not_called()
        self.assert_blocked(result, "TOOL_IDENTITY_CHANGED")

    def test_bad_allowlist_is_rejected_before_evidence_or_launch(self):
        foreign_path = "/tools/python" if os.name == "nt" else "C:\\tools\\python.exe"
        bad = (["not a mapping"], {"relative-tool": "a" * 64},
               {str(self.root / "tool"): "uppercase-or-invalid"}, {foreign_path: "a" * 64})
        for value in bad:
            with self.subTest(value=value), patch("src.tools.process.subprocess.Popen") as launch:
                with self.assertRaises(ValueError):
                    self.harmless_python(allowed_tool_identities=value)
                launch.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])


class TestP2WSLTargetIdentity(unittest.TestCase):
    def test_wsl_label_uses_observed_distribution(self):
        with patch("src.tools.process.current_platform_type", return_value="wsl"), \
                patch.dict(os.environ, {"WSL_DISTRO_NAME": "Ubuntu-22.04"}):
            self.assertEqual(canonical_target_environment(), "wsl:Ubuntu-22.04")

    def test_wsl_label_retains_existing_supported_space_in_distro_name(self):
        with patch("src.tools.process.current_platform_type", return_value="wsl"), \
                patch.dict(os.environ, {"WSL_DISTRO_NAME": "Ubuntu Research"}):
            self.assertEqual(canonical_target_environment(), "wsl:Ubuntu Research")

    def test_wsl_label_rejects_missing_or_malformed_distribution(self):
        for value in (None, "", " bad distro", "Ubuntu/../other", "Ubuntu\n", "-Ubuntu"):
            with self.subTest(value=value), patch("src.tools.process.current_platform_type", return_value="wsl"), \
                    patch.dict(os.environ, {}, clear=True):
                if value is not None:
                    os.environ["WSL_DISTRO_NAME"] = value
                with self.assertRaises(ValueError):
                    canonical_target_environment()

    def test_foreign_wsl_distro_is_rejected_before_launch(self):
        with patch("src.tools.process.current_platform_type", return_value="wsl"), \
                patch.dict(os.environ, {"WSL_DISTRO_NAME": "Ubuntu-22.04"}), \
                patch("src.tools.process.subprocess.Popen") as launch:
            with self.assertRaisesRegex(ValueError, "foreign target"):
                run_tool([sys.executable], target_environment="wsl:Different-Distro")
        launch.assert_not_called()

    def test_missing_wsl_identity_is_rejected_before_launch(self):
        with patch("src.tools.process.current_platform_type", return_value="wsl"), \
                patch.dict(os.environ, {}, clear=True), \
                patch("src.tools.process.subprocess.Popen") as launch:
            with self.assertRaisesRegex(ValueError, "WSL_DISTRO_NAME"):
                run_tool([sys.executable], target_environment="wsl:Ubuntu-22.04")
        launch.assert_not_called()

    def test_canonical_label_cannot_relabel_local_platform(self):
        actual = current_platform_type()
        foreign = "linux" if actual == "windows" else "windows"
        with self.assertRaises(ValueError):
            canonical_target_environment(foreign)


if __name__ == "__main__":
    unittest.main()
