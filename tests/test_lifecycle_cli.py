"""Operator entry-point and clock-domain regression; no WSL dispatch."""

from datetime import timedelta
from contextlib import redirect_stderr
from io import StringIO
import unittest
from unittest.mock import patch

from src.lifecycle_cli import build_operator_context, run_authorized_action, main
from src.models.execution import aware_time
from tests.test_lifecycle_models import synthetic_context
from tests.test_lifecycle_models import synthetic_record
from src.lifecycle_artifacts import EvidenceWriteError


class TestLifecycleOperatorEntry(unittest.TestCase):
    def test_target_observation_is_the_authorization_clock_without_relaxing_expiry(self):
        _, _, policy, snapshot, tool = synthetic_context()
        description = {"target_snapshot": snapshot, "tool_result": tool.model_dump(mode="python"),
                       "cwd": "/workspace", "resource_support": policy.resource_support.model_dump(mode="python")}
        request, grant, trusted, _, _ = build_operator_context(description, "p2b-normal-v1",
            operator_id="synthetic-operator", authorization_reference="synthetic-approval")
        self.assertEqual(aware_time(grant.not_before), aware_time(tool.finished_at))
        self.assertEqual(aware_time(grant.expires_at) - aware_time(grant.not_before), timedelta(minutes=5))
        self.assertEqual(trusted.max_snapshot_age_seconds, 300)
        self.assertEqual(request.request_schema_version, "1.1")
        self.assertEqual(set(request.expected_artifacts), {"stdout.bin", "stderr.bin", "process_result.json"})

    def test_authorization_flag_cannot_be_supplied_by_a_truthy_value(self):
        for flag in (False, None, 1, "true"):
            with self.subTest(flag=flag), patch("src.lifecycle_cli.describe_fixed_fixture_wsl") as dispatch:
                with self.assertRaisesRegex(ValueError, "explicit operator"):
                    run_authorized_action(authorize_fixed_actions=flag, action_id="p2b-normal-v1",
                        authorization_reference="approval", operator_id="operator", linux_project_root="/workspace")
                dispatch.assert_not_called()

    def test_unknown_action_or_invalid_operator_never_starts_readiness(self):
        for action, operator in (("EXECUTE_CANDIDATE", "operator"), ("p2b-normal-v1", "\noperator")):
            with self.subTest(action=action), patch("src.lifecycle_cli.describe_fixed_fixture_wsl") as dispatch:
                with self.assertRaises(ValueError):
                    run_authorized_action(authorize_fixed_actions=True, action_id=action,
                        authorization_reference="approval", operator_id=operator, linux_project_root="/workspace")
                dispatch.assert_not_called()

    def test_cli_does_not_accept_arbitrary_source_or_argv(self):
        with patch("src.lifecycle_cli.describe_fixed_fixture_wsl") as dispatch, self.assertRaises(SystemExit) as error:
            main(["--authorize-fixed-actions", "--action", "p2b-normal-v1", "--authorization-reference", "approval",
                  "--operator-id", "operator", "--linux-project-root", "/workspace", "--argv", "unknown"])
        self.assertEqual(error.exception.code, 2)
        dispatch.assert_not_called()

    def test_unwritable_evidence_has_deterministic_in_memory_failure_report(self):
        output = StringIO()
        error = EvidenceWriteError("synthetic disk write failure", record=synthetic_record())
        with patch("src.lifecycle_cli.run_authorized_action", side_effect=error), redirect_stderr(output):
            code = main(["--authorize-fixed-actions", "--action", "p2b-normal-v1", "--authorization-reference", "approval",
                         "--operator-id", "operator", "--linux-project-root", "/workspace"])
        self.assertEqual(code, 1)
        self.assertIn("# P2-B evidence persistence failure", output.getvalue())
        self.assertIn("Status: UNKNOWN", output.getvalue())
        self.assertIn("Storage: INCOMPLETE", output.getvalue())
        self.assertIn("CVE verification: NOT_VERIFIED", output.getvalue())
