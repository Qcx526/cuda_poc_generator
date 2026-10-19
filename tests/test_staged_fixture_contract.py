"""Synthetic, non-executing admission checks for the fixed received file."""

import hashlib
import json

import pytest

from src import staged_fixture_worker as worker
from src.staged_fixture import evaluate_staged_fixture_archive, render_staged_fixture_report
from src.candidate_adapter import CandidateTransferReceipt
from src.models.lifecycle import LifecycleEvent, RemoteRecoveryCheck, canonical_sha256
from src.models.staged_fixture import (StagedFixtureDescription, StagedFixtureRecord,
    StagedSourceIdentity)
from src.models.tool_result import ToolIdentity
from src.registered_actions import get_registered_action
from src.staged_fixture import build_staged_fixture_context
from tests.test_platform_probe import packet


TRANSFER = "a" * 32
BOOT = "11111111-1111-1111-1111-111111111111"
SOURCE = f"/home/pocdev/.local/state/cuda-poc-generator/candidate_transfers/{TRANSFER}/candidate.py"
NATIVE_ROOT = "/home/pocdev/.local/state/cuda-poc-generator/staged_fixture_tasks"
SUPPORT = {"status": "OBSERVED", "mechanisms": ["WALL_WATCHDOG", "OUTPUT_CAP",
    "POSIX_PROCESS_GROUP", "RLIMIT_CPU", "RLIMIT_AS"], "source": "SYNTHETIC offline test"}


def context():
    action = get_registered_action("p2b-normal-v1")
    receipt = CandidateTransferReceipt(status="STAGED_AND_VERIFIED", request_id="c" * 32,
        transfer_id=TRANSFER, action_id=action.fixture_id, source_sha256=action.sha256,
        source_bytes=len(action.source), target_environment="wsl:Ubuntu-22.04",
        receiver_pid=100, receiver_ppid=99, receiver_uid=1000, receiver_gid=1000,
        receiver_start_ticks=1, staged_relative_path="candidate.py", staged_path=SOURCE,
        candidate_execution_status="NOT_EXECUTED", verification_status="NOT_VERIFIED")
    receipt_raw = (json.dumps(receipt.model_dump(mode="json"), ensure_ascii=False,
        sort_keys=True, indent=2) + "\n").encode("utf-8")
    receipt_sha = hashlib.sha256(receipt_raw).hexdigest()
    source = StagedSourceIdentity(device=10, inode=20, uid=1000, gid=1000,
        mode=0o600, nlink=1, size_bytes=len(action.source), mtime_ns=10, ctime_ns=10,
        source_path=SOURCE, source_sha256=action.sha256, receipt_sha256=receipt_sha,
        transfer_id=TRANSFER, transfer_request_id=receipt.request_id)
    tool = ToolIdentity(requested_executable="/usr/bin/python3", resolved_path="/usr/bin/python3.10",
        status="OBSERVED", file_sha256="d" * 64, source="SYNTHETIC offline test")
    desc = StagedFixtureDescription(description_id="e" * 32, status="DESCRIBED",
        target_environment=receipt.target_environment, snapshot=packet()["snapshot"],
        native_task_root=NATIVE_ROOT, receipt=receipt, source_identity=source,
        tool_identity=tool, target_boot_id=BOOT, observed_monotonic_ns=100,
        resource_support=SUPPORT, diagnostics=[])
    request, grant, policy = build_staged_fixture_context(desc, authorize_fixed_fixture=True,
        operator_id="synthetic-reviewer", authorization_reference="SYNTHETIC-ONLY",
        request_id="f" * 32, run_id="1" * 32)
    return request, grant, policy, desc


def observed(monkeypatch, request, desc, *, source=None, tool=None, boot=BOOT, now=200, support=SUPPORT):
    monkeypatch.setattr(worker, "_protected_root", lambda: NATIVE_ROOT)
    monkeypatch.setattr(worker, "canonical_target_environment", lambda: request.target_environment)
    monkeypatch.setattr(worker, "target_boot_id", lambda: boot)
    monkeypatch.setattr(worker.time, "monotonic_ns", lambda: now)
    monkeypatch.setattr(worker, "measure_tool_identity", lambda *args, **kwargs: tool or request.tool_identity)
    monkeypatch.setattr(worker, "resource_capabilities", lambda *args: support)
    monkeypatch.setattr(worker, "inspect_staged_fixture",
        lambda receipt, sha: source or desc.source_identity.model_dump(mode="json"))


def test_complete_synthetic_admission_and_missing_authorization(monkeypatch):
    request, grant, policy, desc = context()
    same_image_fresh_measurement = ToolIdentity.model_validate({
        **request.tool_identity.model_dump(mode="json"),
        "source": "fresh preflight observation"})
    observed(monkeypatch, request, desc, tool=same_image_fresh_measurement)
    assert worker.preflight_staged_fixture(request, grant, policy, desc)["status"] == "READY"
    missing = worker.preflight_staged_fixture(request, None, policy, desc)
    assert missing["status"] == "REJECTED"
    assert "OPERATOR_AUTHORIZATION_MISSING" in missing["diagnostics"]


def test_same_bytes_replaced_inode_cannot_pass_admission(monkeypatch):
    request, grant, policy, desc = context()
    changed = {**request.source_identity.model_dump(mode="json"), "inode": 21}
    observed(monkeypatch, request, desc, source=changed)
    result = worker.preflight_staged_fixture(request, grant, policy, desc)
    assert result["status"] == "REJECTED"
    assert "STAGED_RECEIPT_OR_INODE_CHANGED" in result["diagnostics"]


def test_boot_change_expiry_and_tool_replacement_are_rejected(monkeypatch):
    request, grant, policy, desc = context()
    observed(monkeypatch, request, desc, boot="22222222-2222-2222-2222-222222222222")
    assert "TARGET_BOOT_OR_DESCRIPTION_EXPIRED" in worker.preflight_staged_fixture(
        request, grant, policy, desc)["diagnostics"]
    observed(monkeypatch, request, desc, now=300000000101)
    assert "TARGET_BOOT_OR_DESCRIPTION_EXPIRED" in worker.preflight_staged_fixture(
        request, grant, policy, desc)["diagnostics"]
    replacement = ToolIdentity.model_validate({**request.tool_identity.model_dump(mode="json"),
        "file_sha256": "0" * 64})
    observed(monkeypatch, request, desc, tool=replacement)
    assert "PYTHON_EXECUTABLE_IDENTITY_CHANGED" in worker.preflight_staged_fixture(
        request, grant, policy, desc)["diagnostics"]


def test_resource_capability_failure_cannot_be_claimed_observed(monkeypatch):
    request, grant, policy, desc = context()
    observed(monkeypatch, request, desc,
        support={"status": "UNSUPPORTED", "mechanisms": [], "source": "SYNTHETIC unavailable"})
    result = worker.preflight_staged_fixture(request, grant, policy, desc)
    assert result["status"] == "REJECTED"
    assert "RESOURCE_LIMITS_UNSUPPORTED" in result["diagnostics"]


def test_process_tool_provenance_may_change_but_binary_identity_may_not():
    from tests.test_lifecycle_artifacts import synthetic_lifecycle_context

    request, grant, policy, desc = context()
    legacy, _ = synthetic_lifecycle_context(status="NONZERO_EXIT")
    process = legacy["record"].process.model_dump(mode="json")
    process.update(worker_pid=100, target_environment=request.target_environment,
        tool_identity={**request.tool_identity.model_dump(mode="json"),
            "source": "fresh child executable measurement"})
    observation = {"events": [{"event": "STAGED_SOURCE_READY", "details": {
        **request.source_identity.model_dump(mode="json"), "request_id": request.request_id,
        "run_id": request.run_id, "pid": process["pid"]}}]}
    states = ("CREATED", "AUTHORIZED", "PREFLIGHT_READY", "STARTING", "RUNNING", "NONZERO_EXIT")
    fields = dict(request_id=request.request_id, run_id=request.run_id,
        transfer_id=request.transfer_id, receipt_sha256=request.receipt_sha256,
        source_identity=request.source_identity, request_sha256=canonical_sha256(request),
        authorization_sha256=canonical_sha256(grant), policy_sha256=canonical_sha256(policy),
        description_sha256=canonical_sha256(desc), snapshot_sha256=request.snapshot_sha256,
        platform_environment_id=request.platform_environment_id,
        platform_probe_id=request.platform_probe_id, target_environment=request.target_environment,
        tool_identity=request.tool_identity, worker_identity={"pid": 100},
        status="NONZERO_EXIT", events=[LifecycleEvent(sequence=index, state=state,
            observed_at="2026-01-01T00:00:00+00:00", source="SYNTHETIC", reason=state,
            monotonic_ns=index) for index, state in enumerate(states)],
        process=process, staged_observation=observation, artifacts={}, diagnostics=[],
        fixed_source_execution_status="EXECUTED")
    assert StagedFixtureRecord.model_validate(fields).process.tool_identity.source == (
        "fresh child executable measurement")
    altered = {**process, "tool_identity": {**process["tool_identity"], "file_sha256": "0" * 64}}
    with pytest.raises(ValueError, match="executable path or SHA-256"):
        StagedFixtureRecord.model_validate({**fields, "process": altered})


def _json_file(path, value):
    path.write_bytes((json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"))


def _synthetic_rejected_archive(root):
    request, grant, policy, desc = context()
    record = StagedFixtureRecord(request_id=request.request_id, run_id=request.run_id,
        transfer_id=request.transfer_id, receipt_sha256=request.receipt_sha256,
        source_identity=request.source_identity, request_sha256=canonical_sha256(request),
        authorization_sha256=canonical_sha256(grant), policy_sha256=canonical_sha256(policy),
        description_sha256=canonical_sha256(desc), snapshot_sha256=request.snapshot_sha256,
        platform_environment_id=request.platform_environment_id,
        platform_probe_id=request.platform_probe_id, target_environment=request.target_environment,
        tool_identity=request.tool_identity, worker_identity={"pid": 100}, status="REJECTED",
        events=[LifecycleEvent(sequence=0, state="CREATED", observed_at="2026-01-01T00:00:00+00:00",
            source="SYNTHETIC", reason="request received", monotonic_ns=100),
            LifecycleEvent(sequence=1, state="REJECTED", observed_at="2026-01-01T00:00:01+00:00",
            source="SYNTHETIC", reason="admission rejected", monotonic_ns=101)],
        process=None, staged_observation=None, artifacts={}, diagnostics=["SYNTHETIC_REJECTION"],
        fixed_source_execution_status="NOT_EXECUTED")
    recovery = RemoteRecoveryCheck(request_id=request.request_id, run_id=request.run_id,
        status="CONFIRMED", worker_alive=False, group_empty=True, identity_match=True,
        checked_at="2026-01-01T00:00:02+00:00", observer_pid=101, observer_uid=1000, diagnostics=[])
    root.mkdir()
    for name, value in (("request", request), ("authorization", grant),
                        ("policy", policy), ("description", desc)):
        _json_file(root / (name + ".json"), value.model_dump(mode="json"))
    _json_file(root / "execute.json", {"packet": {"record": record.model_dump(mode="json")}})
    _json_file(root / "status.json", {"packet": {"record": record.model_dump(mode="json"),
        "recovery": recovery.model_dump(mode="json")}})
    action = get_registered_action("p2b-normal-v1")
    (root / "source.bin").write_bytes(action.source)
    _json_file(root / "transfer_receipt.json", desc.receipt.model_dump(mode="json"))
    result = {"request_id": request.request_id, "run_id": request.run_id,
        "transfer_id": request.transfer_id, "source_sha256": action.sha256,
        "target_environment": request.target_environment,
        "tool_sha256": request.tool_identity.file_sha256,
        "authorization_reference": grant.authorization_reference,
        "status": "REJECTED", "cleanup_status": "CONFIRMED",
        "fixed_source_execution_status": "NOT_EXECUTED",
        "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED",
        "diagnostics": ["SYNTHETIC_REJECTION"]}
    files = {path.name: {"size_bytes": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in root.iterdir() if path.is_file()}
    manifest = {"schema_version": "staged-harmless-1.0", "request_id": request.request_id,
        "run_id": request.run_id, "transfer_id": request.transfer_id,
        "record_sha256": canonical_sha256(record), "status": "REJECTED",
        "cleanup_status": "CONFIRMED", "files": files,
        "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    _json_file(root / "evidence_manifest.json", manifest)
    result["manifest_sha256"] = hashlib.sha256((root / "evidence_manifest.json").read_bytes()).hexdigest()
    _json_file(root / "controller_result.json", result)
    (root / "report.zh-CN.md").write_bytes(render_staged_fixture_report(result, record, recovery).encode("utf-8"))
    return result, record, recovery


def test_offline_report_cannot_forge_cleanup_or_fixed_file_execution(tmp_path):
    root = tmp_path / "synthetic"
    result, record, recovery = _synthetic_rejected_archive(root)
    assert evaluate_staged_fixture_archive(root)["status"] == "REJECTED"
    for changed in ({"cleanup_status": "FAILED"}, {"fixed_source_execution_status": "EXECUTED"}):
        altered = {**result, **changed}
        _json_file(root / "controller_result.json", altered)
        (root / "report.zh-CN.md").write_bytes(
            render_staged_fixture_report(altered, record, recovery).encode("utf-8"))
        try:
            evaluate_staged_fixture_archive(root)
        except ValueError:
            pass
        else:
            raise AssertionError("self-consistent but false execution conclusion was accepted")


def test_execute_and_status_records_must_match_even_after_manifest_reseal(tmp_path):
    root = tmp_path / "synthetic"
    result, record, recovery = _synthetic_rejected_archive(root)
    status = json.loads((root / "status.json").read_bytes())
    status["packet"]["record"]["diagnostics"] = ["SYNTHETIC_ALTERNATE_RECORD"]
    _json_file(root / "status.json", status)
    manifest = json.loads((root / "evidence_manifest.json").read_bytes())
    changed = (root / "status.json").read_bytes()
    manifest["files"]["status.json"] = {"size_bytes": len(changed),
        "sha256": hashlib.sha256(changed).hexdigest()}
    _json_file(root / "evidence_manifest.json", manifest)
    result["manifest_sha256"] = hashlib.sha256((root / "evidence_manifest.json").read_bytes()).hexdigest()
    _json_file(root / "controller_result.json", result)
    (root / "report.zh-CN.md").write_bytes(render_staged_fixture_report(result, record, recovery).encode("utf-8"))
    try:
        evaluate_staged_fixture_archive(root)
    except ValueError as exc:
        assert "different" in str(exc)
    else:
        raise AssertionError("different worker records were silently merged")
