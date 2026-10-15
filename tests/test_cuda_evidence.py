"""Fabricated CUDA records/bundles for offline association and report tests."""

import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from src.cuda_registry import CUDA_SMOKE_SOURCE
from src.lifecycle_artifacts import (write_execution_evidence, read_execution_evidence, rebuild_execution_report)
from src.models.execution import request_sha256, snapshot_sha256
from src.models.lifecycle import ExecutionRecord, canonical_sha256
from src.models.tool_result import seal_tool_result
from src.native_evidence import export_native_evidence
from tests.test_cuda_contracts import synthetic_cuda_context
from tests.test_cuda_registry import synthetic_cuda_elf
from tests.test_cuda_workflow import synthetic_process, STEPS
from tests.test_p1c_integration import synthetic_tool_record


def json_bytes(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def transport_for(packet, run_id):
    original = synthetic_tool_record().model_dump(mode="json")
    raw = json_bytes(packet)
    original.update(run_id=run_id, stdout_b64=base64.b64encode(raw).decode(), stdout_sha256=hashlib.sha256(raw).hexdigest())
    original["resource_limits"]["max_output_bytes"] = 1048576
    return seal_tool_result(original)


def synthetic_cuda_evidence(folder):
    req, auth, policy, snapshot, tool = synthetic_cuda_context()
    start = datetime.now(timezone.utc).isoformat()
    processes = [synthetic_process(req, step) for step in STEPS]
    end = datetime.now(timezone.utc).isoformat()
    mono = req.cuda_toolchain.observed_monotonic_ns + 1
    states = ["CREATED", "AUTHORIZED", "PREFLIGHT_READY", "STARTING", "RUNNING", "COMPLETED"]
    cubin = synthetic_cuda_elf()
    record = ExecutionRecord(execution_schema_version="1.1", request_id=req.request_id, run_id="e" * 32,
        request_sha256=request_sha256(req), authorization_sha256=canonical_sha256(auth),
        policy_sha256=canonical_sha256(policy), snapshot_sha256=snapshot_sha256(snapshot),
        candidate_sha256=req.candidate_sha256, platform_environment_id=req.platform_environment_id,
        platform_probe_id=req.platform_probe_id, target_environment=req.binding.target_environment,
        tool_record_id=tool.record_id, tool_identity=processes[-1].tool_identity,
        authorization_reference=auth.authorization_reference, operator_id=auth.operator_id, action_id=req.fixture_id,
        status="COMPLETED", events=[{"sequence": i, "state": state, "observed_at": end if i == 5 else start,
            "monotonic_ns": mono + i, "source": "SYNTHETIC offline observation", "reason": "SYNTHETIC " + state}
            for i, state in enumerate(states)], process=processes[-1], worker_pid=processes[-1].worker_pid,
        started_at=start, finished_at=end, started_monotonic_ns=mono, finished_monotonic_ns=mono + 5,
        diagnostics=["SYNTHETIC example only; no tool, GPU or CVE ran"], fixture_execution_status="STARTED",
        evidence_files=["stdout.bin", "stderr.bin", "process_result.json", "lifecycle.json"],
        cuda_smoke={"source_sha256": req.candidate_sha256, "arch": req.cuda_toolchain.arch,
            "tool_versions": req.cuda_toolchain.version_records,
            "steps": [{"step_id": step, "state": "COMPLETED", "process": process} for step, process in zip(STEPS, processes)],
            "artifact": {"size_bytes": len(cubin), "sha256": hashlib.sha256(cubin).hexdigest()}})
    values = {"request.json": req, "authorization.json": auth, "policy.json": policy,
              "snapshot.json": snapshot, "tool_record.json": tool, "execution_record.json": record}
    for name, model in values.items():
        (folder / name).write_bytes(json_bytes(model.model_dump(mode="json")))
    (folder / "lease.json").write_bytes(json_bytes({"request_id": record.request_id, "run_id": record.run_id,
        "target_environment": record.target_environment, "worker": {"pid": record.worker_pid},
        "boot_id": req.cuda_toolchain.target_boot_id}))
    (folder / "preflight.json").write_bytes(json_bytes({"preflight_schema_version": "1.0", "request_id": record.request_id,
        "status": "READY", "diagnostics": [], "checked_at": start,
        "measured_candidate_sha256": record.candidate_sha256, "measured_tool_sha256": req.tool_identity.file_sha256,
        "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}))
    (folder / "worker_events.jsonl").write_bytes(b"")
    (folder / "stdout.bin").write_bytes(processes[-1].stdout_bytes())
    (folder / "stderr.bin").write_bytes(processes[-1].stderr_bytes())
    (folder / "work/out").mkdir(parents=True)
    (folder / "work/safe_smoke.cu").write_bytes(CUDA_SMOKE_SOURCE)
    (folder / "work/out/safe_smoke.cubin").write_bytes(cubin)
    for step in record.cuda_smoke.steps:
        target = folder / "steps" / step.step_id
        target.mkdir(parents=True)
        (target / "stdout.bin").write_bytes(step.process.stdout_bytes())
        (target / "stderr.bin").write_bytes(step.process.stderr_bytes())
        (target / "process_result.json").write_bytes(json_bytes(step.process.model_dump(mode="json")))
    bundle = export_native_evidence(folder, record)
    packet = {"schema_version": "1.0", "operation": "EXECUTE", "nonce": "a" * 32,
        "request_id": record.request_id, "run_id": record.run_id, "worker_exit_code": 0,
        "target_environment": record.target_environment,
        "worker_identity": {"pid": record.worker_pid, "ppid": 1, "pgid": record.worker_pid, "session_id": record.worker_pid,
            "start_ticks": 100, "uid": 1000, "gid": 1000, "state": "R"},
        "record": record.model_dump(mode="json"), "recovery": None, "worker_events": [], "diagnostics": [],
        "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED",
        "native_evidence": bundle.model_dump(mode="json")}
    recovery = deepcopy(packet)
    recovery.update(operation="STATUS", nonce="b" * 32,
        worker_identity={"pid": 200, "ppid": 1, "pgid": 200, "session_id": 200, "start_ticks": 101,
            "uid": 1000, "gid": 1000, "state": "R"},
        recovery={"request_id": record.request_id, "run_id": record.run_id, "checked_at": end,
            "checked_monotonic_ns": mono + 6, "target_boot_id": req.cuda_toolchain.target_boot_id,
            "status": "CONFIRMED", "worker_alive": False, "group_empty": True,
            "identity_match": True, "observer_pid": 200, "observer_uid": 1000, "diagnostics": []})
    result = {"record": record, "transport": transport_for(packet, "1" * 32), "worker_packet": packet,
              "recovery_transport": transport_for(recovery, "2" * 32), "recovery_packet": recovery}
    context = {"request": req, "authorization": auth, "policy": policy, "snapshot": snapshot, "binding_tool_result": tool}
    return result, context


class TestCudaCrossEnvironmentEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.native = self.root / "native"
        self.native.mkdir()
        self.result, self.context = synthetic_cuda_evidence(self.native)

    def save(self):
        return write_execution_evidence(self.root / "windows", self.result, **self.context)

    def update_recovery(self):
        self.result["recovery_transport"] = transport_for(self.result["recovery_packet"], "2" * 32)

    def test_exact_native_bundle_report_and_all_tool_steps_round_trip(self):
        folder = self.save()
        checked = read_execution_evidence(folder)
        self.assertEqual(checked["manifest"].native_evidence.status, "VERIFIED")
        self.assertEqual(checked["manifest"].collector_version, "p2c-1.1")
        report = rebuild_execution_report(folder)
        self.assertEqual(report, (folder / "report.md").read_text(encoding="utf-8"))
        for field in ("Actual native argv", "ppid", "start_ticks", "Native original-file verification: VERIFIED",
                      "Initial dispatch actual argv", "NOT_VERIFIED", "actual cwd"):
            self.assertIn(field, report)
        self.assertEqual((folder / "native_work_out_safe_smoke.cubin").read_bytes(), synthetic_cuda_elf())
        for step in STEPS:
            self.assertTrue((folder / ("native_steps_" + step + "_stdout.bin")).is_file())

    def test_inaccessible_linux_recheck_cannot_claim_verified_even_with_primary(self):
        del self.result["recovery_packet"]["native_evidence"]
        self.update_recovery()
        checked = read_execution_evidence(self.save())
        self.assertEqual(checked["manifest"].native_evidence.status, "UNAVAILABLE")
        self.assertEqual(checked["manifest"].effective_status, "COMPLETED")
        self.assertFalse(checked["manifest"].capture_complete)

    def test_failed_linux_raw_recheck_is_separate_from_execution_completion(self):
        del self.result["recovery_packet"]["native_evidence"]
        self.result["recovery_packet"]["diagnostics"] = ["NATIVE_EVIDENCE_RECHECK_FAILED"]
        self.update_recovery()
        checked = read_execution_evidence(self.save())
        self.assertEqual(checked["manifest"].native_evidence.status, "FAILED")
        self.assertEqual(checked["record"].status, "COMPLETED")
        self.assertFalse(checked["manifest"].capture_complete)

    def test_windows_native_copy_tamper_or_removal_is_rejected(self):
        folder = self.save()
        path = folder / "native_work_out_safe_smoke.cubin"
        path.write_bytes(b"replacement")
        with self.assertRaises(ValueError):
            read_execution_evidence(folder)
        path.unlink()
        with self.assertRaises(ValueError):
            read_execution_evidence(folder)

    def test_wrong_target_boot_or_request_run_is_rejected(self):
        for field in ("target_boot_id", "run_id"):
            changed = deepcopy(self.result["recovery_packet"])
            changed["recovery"][field] = "00000000-0000-0000-0000-000000000099" if field == "target_boot_id" else "f" * 32
            result = {**self.result, "recovery_packet": changed, "recovery_transport": transport_for(changed, "2" * 32)}
            with self.subTest(field=field), self.assertRaises(ValueError):
                write_execution_evidence(self.root / field, result, **self.context)

    def test_missing_cleanup_remains_unknown_even_when_native_files_are_verified(self):
        self.result["recovery_packet"]["recovery"].update(status="UNKNOWN", worker_alive=True, group_empty=None)
        self.update_recovery()
        checked = read_execution_evidence(self.save())
        self.assertEqual(checked["manifest"].effective_status, "UNKNOWN")
        self.assertEqual(checked["manifest"].native_evidence.status, "VERIFIED")


if __name__ == "__main__":
    unittest.main()
