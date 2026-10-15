"""Local boot-clock observations are never a cross-host time reconstruction."""

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from src.execution_preflight import authorization_active, preflight_execution
from src.models.execution import ExecutionRequest, PreflightPolicy
from src.models.lifecycle import ExecutionRecord
from src.models.tool_result import ToolIdentity
from src.cuda_registry import CUDA_SMOKE_SOURCE
from tests.test_cuda_contracts import synthetic_cuda_context
from tests.test_lifecycle_artifacts import synthetic_lifecycle_context


class TestObservedClockOrder(unittest.TestCase):
    def clock_record(self):
        data = synthetic_lifecycle_context(status="UNKNOWN")[0]["record"].model_dump(mode="python")
        data.update(execution_schema_version="1.1", started_monotonic_ns=100, finished_monotonic_ns=200,
                    started_at="2026-10-15T10:00:10+00:00", finished_at="2026-10-15T10:00:00+00:00")
        for event, stamp, mono in zip(data["events"], (data["started_at"], data["finished_at"]), (100, 200)):
            event.update(observed_at=stamp, monotonic_ns=mono)
        return data

    def test_true_utc_regression_is_preserved_with_observed_local_order(self):
        data = self.clock_record()
        record = ExecutionRecord.model_validate(data)
        self.assertEqual(record.finished_at, data["finished_at"])
        self.assertEqual(record.started_at, data["started_at"])
        self.assertLess(record.started_monotonic_ns, record.finished_monotonic_ns)

    def test_regression_without_complete_monotonic_proof_is_rejected(self):
        for change in ("missing", "reversed", "wrong_bound"):
            data = self.clock_record()
            if change == "missing":
                del data["events"][1]["monotonic_ns"]
            elif change == "reversed":
                data["events"][1]["monotonic_ns"] = 99
            else:
                data["finished_monotonic_ns"] = 300
            with self.subTest(change=change), self.assertRaises(ValueError):
                ExecutionRecord.model_validate(data)

    def test_legacy_records_cannot_acquire_different_time_semantics(self):
        data = self.clock_record()
        data["execution_schema_version"] = "1.0"
        with self.assertRaises(ValueError):
            ExecutionRecord.model_validate(data)

    def test_cuda_authorization_requires_same_real_boot_and_bounded_clock(self):
        _, grant, _, _, _ = synthetic_cuda_context()
        with patch("src.execution_preflight.target_boot_id", return_value=grant.cuda_toolchain.target_boot_id), \
                patch("src.execution_preflight.time.monotonic_ns", return_value=grant.not_before_monotonic_ns + 1):
            self.assertTrue(authorization_active(grant, now=datetime(2000, 1, 1, tzinfo=timezone.utc)))
        with patch("src.execution_preflight.target_boot_id", return_value="00000000-0000-0000-0000-000000000002"):
            self.assertFalse(authorization_active(grant))
        for observed in (grant.not_before_monotonic_ns - 1, grant.expires_monotonic_ns):
            with patch("src.execution_preflight.target_boot_id", return_value=grant.cuda_toolchain.target_boot_id), \
                    patch("src.execution_preflight.time.monotonic_ns", return_value=observed):
                self.assertFalse(authorization_active(grant))


@unittest.skipUnless(os.name == "posix", "target filesystem checks require Linux paths; Windows uses mock/bridge regressions")
class TestCudaPreflightBinding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "safe_smoke.cu").write_bytes(CUDA_SMOKE_SOURCE)
        req, self.auth, policy, self.snapshot, self.tool = synthetic_cuda_context()
        data = req.model_dump(mode="python")
        data.update(candidate_path=str(self.root / "safe_smoke.cu"), cwd=str(self.root))
        self.req = ExecutionRequest.model_validate(data)
        policy_data = policy.model_dump(mode="python")
        policy_data["scope_root"] = str(self.root)
        self.policy = PreflightPolicy.model_validate(policy_data)

    def check(self, *, auth=True, changed_tool=None, stale=False):
        def measured(path, **kwargs):
            expected = next(item for item in self.req.cuda_toolchain.tools.values() if item.resolved_path == path)
            if path == changed_tool:
                return expected.model_copy(update={"file_sha256": "f" * 64})
            return expected
        clock = self.req.cuda_toolchain.observed_monotonic_ns + (2000000000 if stale else 1)
        policy = self.policy
        if stale:
            policy = PreflightPolicy.model_validate({**policy.model_dump(mode="python"), "max_snapshot_age_seconds": 1})
        with patch("src.tools.process.measure_tool_identity", side_effect=measured), \
                patch("src.execution_preflight.target_boot_id", return_value=self.req.cuda_toolchain.target_boot_id), \
                patch("src.execution_preflight.time.monotonic_ns", return_value=clock):
            return preflight_execution(self.req, self.snapshot, self.tool, self.auth if auth else None, policy,
                now=datetime(2000, 1, 1, tzinfo=timezone.utc), observed_platform_type="wsl",
                observed_target_environment=self.req.binding.target_environment)

    def test_valid_exact_scope_is_ready_despite_unreliable_wall_clock(self):
        self.assertEqual(self.check().status, "READY")

    def test_unapproved_source_and_missing_authorization_are_rejected(self):
        self.assertEqual(self.check(auth=False).status, "REJECTED")
        (self.root / "safe_smoke.cu").write_bytes(b"unapproved replacement")
        self.assertEqual(self.check().status, "REJECTED")

    def test_inspector_replacement_is_blocked_before_dispatch(self):
        result = self.check(changed_tool=self.req.cuda_toolchain.tools["nvdisasm"].resolved_path)
        self.assertEqual(result.status, "REJECTED")
        self.assertEqual(result.diagnostics[0].code, "CUDA_TOOL_IDENTITY_MISMATCH")

    def test_expired_snapshot_uses_same_boot_monotonic_observation(self):
        result = self.check(stale=True)
        self.assertEqual(result.status, "REJECTED")
        self.assertEqual(result.diagnostics[0].code, "PLATFORM_SNAPSHOT_STALE")


if __name__ == "__main__":
    unittest.main()
