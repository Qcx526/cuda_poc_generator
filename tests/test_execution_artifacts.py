"""Synthetic evidence/authorization regressions; no WSL or candidate dispatch."""

import base64
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.execution_artifacts import read_execution_evidence, write_execution_evidence
from src.fixture_smoke import main, run_authorized_fixture_check
from src.models.execution import OperatorAuthorization, PreflightPolicy
from src.models.tool_result import digest_bytes, seal_tool_result
from src.execution_worker import contract_digest
from tests.test_execution_bridge import execution_packet, fixture_authority
from tests.test_p1c_integration import synthetic_tool_record


def synthetic_authority(packet, request):
    """Exact synthetic records originally hashed into the synthetic worker packet."""
    return fixture_authority(request, packet["target_snapshot"])


def synthetic_bridge_result():
    packet, request = execution_packet()
    authorization, policy = synthetic_authority(packet, request)
    packet["authorization_sha256"] = contract_digest(OperatorAuthorization, authorization)
    packet["policy_sha256"] = contract_digest(PreflightPolicy, policy)
    raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    transport = synthetic_tool_record().model_dump(mode="json")
    transport.update(stdout_b64=base64.b64encode(raw).decode("ascii"), stdout_sha256=digest_bytes(raw))
    transport["resource_limits"]["max_output_bytes"] = 1048576
    return {"packet": packet, "transport": seal_tool_result(transport).model_dump(mode="json")}, request


class TestExecutionEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def save(self):
        result, request = synthetic_bridge_result()
        authorization, policy = synthetic_authority(result["packet"], request)
        return write_execution_evidence(self.root, result, request=request,
                                        authorization=authorization, policy=policy), request

    def test_roundtrip_preserves_original_bytes_and_request(self):
        folder, request = self.save()
        read = read_execution_evidence(folder, expected_request_id=request.request_id)
        self.assertEqual(read["request"], request)
        self.assertEqual(read["packet"]["status"], "FIXTURE_COMPLETED")
        self.assertEqual(read["manifest"]["verification_status"], "NOT_VERIFIED")
        self.assertEqual(read["manifest"]["candidate_execution_status"], "NOT_EXECUTED")
        self.assertTrue((folder / "stdout.bin").read_bytes())
        self.assertIn("fixed harmless fixture", (folder / "report.md").read_text())

    def test_target_log_changes_are_rejected(self):
        folder, _ = self.save()
        (folder / "stdout.bin").write_bytes(b"changed synthetic fixture log")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            read_execution_evidence(folder)

    def test_report_changes_are_rejected(self):
        folder, _ = self.save()
        (folder / "report.md").write_text("fabricated success", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "report mismatch"):
            read_execution_evidence(folder)

    def test_independently_expected_request_cannot_change(self):
        folder, _ = self.save()
        with self.assertRaisesRegex(ValueError, "request mismatch"):
            read_execution_evidence(folder, expected_request_id="f" * 32)

    def test_packet_cannot_be_added_after_transport(self):
        result, request = synthetic_bridge_result()
        result["packet"]["diagnostics"].append("invented diagnosis")
        with self.assertRaisesRegex(ValueError, "raw transport"):
            write_execution_evidence(self.root, result, request=request)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_wrong_request_cannot_relabel_evidence(self):
        result, request = synthetic_bridge_result()
        bad = request.model_dump(mode="python")
        bad["request_id"] = "f" * 32
        with self.assertRaises(ValueError):
            write_execution_evidence(self.root, result, request=bad)

    def test_manifest_cannot_read_outside_evidence_directory(self):
        folder, _ = self.save()
        manifest = json.loads((folder / "manifest.json").read_bytes())
        manifest["artifacts"]["../private.txt"] = {"size_bytes": 0, "sha256": digest_bytes(b"")}
        (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "manifest"):
            read_execution_evidence(folder)

    def test_missing_request_cannot_claim_completed_fixture(self):
        result, _ = synthetic_bridge_result()
        with self.assertRaises(ValueError):
            write_execution_evidence(self.root, result)


class TestOperatorFixtureEntryPoint(unittest.TestCase):
    def test_authorization_flag_required_before_readonly_dispatch(self):
        for authorization in (False, None, 1, "true"):
            with self.subTest(authorization=authorization), patch("src.fixture_smoke.describe_fixed_fixture_wsl") as dispatch:
                with self.assertRaisesRegex(ValueError, "explicit operator"):
                    run_authorized_fixture_check(authorize_fixed_fixture=authorization,
                        authorization_reference="synthetic-approval", operator_id="synthetic-operator",
                        linux_project_root="/workspace")
                dispatch.assert_not_called()

    def test_claimed_reference_does_not_replace_operator_flag(self):
        with patch("src.fixture_smoke.describe_fixed_fixture_wsl") as dispatch:
            status = main(["--authorization-reference", "llm-claims-authorized", "--operator-id", "operator",
                           "--linux-project-root", "/workspace"])
        self.assertEqual(status, 1)
        dispatch.assert_not_called()

    def test_cli_accepts_no_argv_or_candidate_override(self):
        with patch("src.fixture_smoke.describe_fixed_fixture_wsl") as dispatch, self.assertRaises(SystemExit) as error:
            main(["--authorize-fixed-fixture", "--authorization-reference", "approval", "--operator-id", "operator",
                  "--linux-project-root", "/workspace", "--argv", "arbitrary"])
        self.assertEqual(error.exception.code, 2)
        dispatch.assert_not_called()
