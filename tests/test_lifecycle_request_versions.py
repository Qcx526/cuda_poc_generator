"""Offline cross-worker protocol routing; all target/tool observations are mocks."""

from pathlib import PurePosixPath
import unittest
from unittest.mock import patch

from src import execution_worker as readiness_worker
from src import lifecycle_worker
from src.models.execution import ExecutionRequest, PreflightResult
from src.models.platform import PlatformSnapshot
from tests.test_execution_bridge import fixed_request, fixture_authority
from tests import test_lifecycle_worker_audit as worker_audit


class SyntheticReadinessPath(PurePosixPath):
    """Provide the exact registered POSIX path without touching a WSL file."""

    def resolve(self, *, strict):
        return self

    def is_file(self):
        return str(self) == "/workspace/" + readiness_worker.FIXTURE_RELATIVE_PATH

    def is_symlink(self):
        return False

    def read_bytes(self):
        if not self.is_file():
            raise FileNotFoundError(str(self))
        return readiness_worker.FIXTURE_SOURCE


def rejected_after_routing(request_id):
    return PreflightResult(request_id=request_id, status="REJECTED",
                           diagnostics=[{"code": "SYNTHETIC_PREFLIGHT_REACHED", "message": "No process is launched."}],
                           checked_at="2026-10-15T12:00:00+00:00")


class TestWorkerRequestVersions(unittest.TestCase):
    def readiness(self, schema_version):
        req, snapshot, tool = fixed_request()
        grant, policy = fixture_authority(req, snapshot)
        changed = req.model_dump(mode="python")
        changed.update(request_schema_version=schema_version,
                       expected_artifacts=["stdout.bin", "stderr.bin",
                                           "tool_result.json" if schema_version == "1.0" else "process_result.json"])
        request = ExecutionRequest.model_validate(changed)
        # Every other registry condition is identical to the matching-version
        # control. Removing the version guard would reach the sentinel preflight.
        self.assertEqual(request.fixture_id, readiness_worker.FIXTURE_ID)
        self.assertEqual(request.candidate_sha256, readiness_worker.FIXTURE_SHA256)
        self.assertEqual(request.candidate_path, "/workspace/" + readiness_worker.FIXTURE_RELATIVE_PATH)
        self.assertEqual(request.cwd, "/workspace")
        self.assertEqual(policy.scope_root, "/workspace")
        self.assertEqual(policy.fixture_hashes, {readiness_worker.FIXTURE_ID: readiness_worker.FIXTURE_SHA256})
        payload = {"operation": "FIXED_FIXTURE", "nonce": "e" * 32,
                   "request": request.model_dump(mode="json"), "authorization": grant.model_dump(mode="json"),
                   "policy": policy.model_dump(mode="json"), "snapshot": snapshot,
                   "tool_record": tool.model_dump(mode="json")}
        with patch.object(readiness_worker, "current_platform_type", return_value="wsl"), \
                patch.object(readiness_worker, "canonical_target_environment", return_value="wsl:Ubuntu-22.04"), \
                patch.object(readiness_worker, "Path", return_value=SyntheticReadinessPath("/workspace")), \
                patch.object(readiness_worker, "_snapshot", return_value=PlatformSnapshot.model_validate(snapshot)), \
                patch.object(readiness_worker, "measure_tool_identity", return_value=request.tool_identity), \
                patch.object(readiness_worker, "resource_capabilities", return_value=policy.resource_support.model_dump(mode="json")), \
                patch.object(readiness_worker, "preflight_execution", return_value=rejected_after_routing(request.request_id)) as preflight, \
                patch.object(readiness_worker, "run_tool") as launch:
            result = readiness_worker.handle_worker(payload, project_root="synthetic-posix-project")
        launch.assert_not_called()
        return result, preflight.call_count

    def lifecycle(self, schema_version):
        harness = worker_audit.TestWorkerAudit("test_missing_authorization_rejected_without_runner")
        harness.setUp()
        try:
            payload = harness.payload
            payload["request"].update(request_schema_version=schema_version,
                                       expected_artifacts=["stdout.bin", "stderr.bin",
                                                           "tool_result.json" if schema_version == "1.0" else "process_result.json"])
            ExecutionRequest.model_validate(payload["request"])
            with patch.object(lifecycle_worker, "preflight_execution",
                              return_value=rejected_after_routing(payload["request_id"])) as preflight:
                result = harness.execute(payload)
            harness.launch.assert_not_called()
            return result, preflight.call_count
        finally:
            harness.doCleanups()

    def test_p2a_version_one_point_zero_reaches_preflight_without_launch(self):
        result, calls = self.readiness("1.0")
        self.assertEqual(calls, 1)
        self.assertEqual(result["preflight"]["diagnostics"][0]["code"], "SYNTHETIC_PREFLIGHT_REACHED")

    def test_p2a_rejects_lifecycle_version_before_preflight_without_launch(self):
        result, calls = self.readiness("1.1")
        self.assertEqual(calls, 0)
        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(result["diagnostics"], ["FIXED_REGISTRY_SCOPE_MISMATCH"])
        self.assertIsNone(result["tool_result"])

    def test_p2b_version_one_point_one_reaches_preflight_without_launch(self):
        result, calls = self.lifecycle("1.1")
        self.assertEqual(calls, 1)
        self.assertEqual(result["record"]["diagnostics"], ["SYNTHETIC_PREFLIGHT_REACHED"])

    def test_p2b_rejects_tool_result_version_before_preflight_without_launch(self):
        result, calls = self.lifecycle("1.0")
        self.assertEqual(calls, 0)
        self.assertEqual(result["record"]["status"], "UNSUPPORTED")
        self.assertEqual(result["record"]["diagnostics"], ["REGISTERED_ACTION_SCOPE_REQUIRED"])
        self.assertEqual(result["record"]["fixture_execution_status"], "NOT_STARTED")


if __name__ == "__main__":
    unittest.main()
