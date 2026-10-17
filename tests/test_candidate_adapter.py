import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.candidate_adapter import (CandidateArtifact, CandidateAdmission, assess_candidate_admission,
                                  load_generation_candidate, render_candidate_admission)
from src.cuda_smoke_worker import CudaSmokeDescription
from src.models.lifecycle import canonical_sha256


def _candidate():
    source = b"print('registered review only')\n"
    run_id = "a" * 32
    record = {"schema_version": "1.0", "cve_id": "CVE-2025-23339", "run_id": run_id,
        "execution": "NOT_EXECUTED", "verification": "NOT_VERIFIED",
        "candidate": {"run_id": run_id, "generation": "GENERATED", "static": "STATIC_VALID",
            "execution": "NOT_EXECUTED", "verification": "NOT_VERIFIED", "source_file": "cuda_poc_v1.py",
            "sha256": hashlib.sha256(source).hexdigest(), "correction_attempts": 0, "errors": [],
            "check_method": "python_ast_struct_name_heuristics"}}
    return run_id, source, record


@pytest.mark.parametrize("use_default_root", [False, True])
def test_generation_candidate_loader_binds_real_archived_run_hashes(tmp_path, monkeypatch, use_default_root):
    from src import candidate_adapter as adapter
    run_id, source, record = _candidate()
    root = tmp_path / "data" / "outputs" if use_default_root else tmp_path / "outputs"
    monkeypatch.setattr(adapter, "ARTIFACT_PROJECT_ROOT", tmp_path)
    folder = root / "CVE-2025-23339" / "runs" / run_id
    folder.mkdir(parents=True)
    (folder / "artifact_manifest.json").write_bytes(b"fixed manifest bytes")
    manifest = SimpleNamespace(evidence_domain="GENERATED_CANDIDATE_RESEARCH")
    monkeypatch.setattr(adapter, "read_review_run", lambda *a, **k: (manifest, {
        "analysis/generation_run.json": json.dumps(record).encode(), "poc/cuda_poc_v1.py": source}))
    result = load_generation_candidate("CVE-2025-23339", run_id,
        output_root=None if use_default_root else root)
    assert result.source_sha256 == hashlib.sha256(source).hexdigest()
    assert result.generation_record_sha256 == canonical_sha256(record)
    assert result.generation_manifest_sha256 == hashlib.sha256(b"fixed manifest bytes").hexdigest()
    assert result.generation_run_id == run_id


def test_candidate_loader_rejects_generation_status_or_cve_run_conflict(tmp_path, monkeypatch):
    from src import candidate_adapter as adapter
    run_id, source, record = _candidate()
    root = tmp_path / "outputs"
    folder = root / "CVE-2025-23339" / "runs" / run_id
    folder.mkdir(parents=True)
    (folder / "artifact_manifest.json").write_bytes(b"manifest")
    record["run_id"] = "b" * 32
    manifest = SimpleNamespace(evidence_domain="GENERATED_CANDIDATE_RESEARCH")
    monkeypatch.setattr(adapter, "read_review_run", lambda *a, **k: (manifest, {
        "analysis/generation_run.json": json.dumps(record).encode(), "poc/cuda_poc_v1.py": source}))
    with pytest.raises(ValueError, match="CVE/run"):
        load_generation_candidate("CVE-2025-23339", run_id, output_root=root)


def test_candidate_preflight_never_grants_execution_without_candidate_policy():
    run_id, source, _ = _candidate()
    candidate = CandidateArtifact(cve_id="CVE-2025-23339", generation_run_id=run_id,
        generation_manifest_sha256="1" * 64, generation_record_sha256="2" * 64,
        source_sha256=hashlib.sha256(source).hexdigest(), source_bytes=len(source), static_status="STATIC_VALID")
    description = CudaSmokeDescription(description_schema_version="1.0", status="UNKNOWN", snapshot=None, scope=None,
        native_task_root="/tmp/tasks", source_sha256="3" * 64,
        resource_support={"status": "UNKNOWN", "mechanisms": [], "source": "synthetic unit test"}, diagnostics=[])
    result = assess_candidate_admission(candidate, description)
    assert result.candidate_identity_status == "VERIFIED"
    assert result.target_identity_status == "UNKNOWN"
    assert result.execution_admission == "UNSUPPORTED"
    assert result.candidate_execution_status == "NOT_EXECUTED"
    assert result.verification_status == "NOT_VERIFIED"
    assert "固定 fixture 的授权" in render_candidate_admission(result)


def test_candidate_model_rejects_fake_execution_admission():
    run_id, source, _ = _candidate()
    candidate = CandidateArtifact(cve_id="CVE-2025-23339", generation_run_id=run_id,
        generation_manifest_sha256="1" * 64, generation_record_sha256="2" * 64,
        source_sha256=hashlib.sha256(source).hexdigest(), source_bytes=len(source), static_status="STATIC_INVALID")
    with pytest.raises(ValueError):
        CandidateAdmission(preflight_id="c" * 32, observed_at="2026-10-17T00:00:00+00:00", candidate=candidate,
            target_environment=None, platform_environment_id=None, platform_probe_id=None,
            target_tool_profile=None, target_tool_path=None, target_tool_sha256=None, target_tool_version=None,
            candidate_identity_status="VERIFIED", target_identity_status="NOT_CHECKED",
            execution_admission="READY", candidate_execution_status="EXECUTED",
            verification_status="NOT_VERIFIED", diagnostics=[],)


@pytest.mark.parametrize("mismatch", [None, "remote_home", "task_suffix", "tool_sha256"])
def test_windows_candidate_assessment_binds_remote_sidecar_identity(monkeypatch, mismatch):
    """SYNTHETIC identity records; no native tools or network requests."""
    import base64
    from src import cuda_smoke_worker
    from src.cuda_smoke_worker import CUOBJDUMP_12_8_55_1_SHA256
    from src.models.platform import PlatformSnapshot
    from src.models.execution import CudaToolchainScope
    from src.models.tool_result import digest_argv, seal_tool_result
    from tests.test_cuda_contracts import synthetic_cuda_scope
    from tests.test_platform_probe import packet

    run_id, source, _ = _candidate()
    candidate = CandidateArtifact(cve_id="CVE-2025-23339", generation_run_id=run_id,
        generation_manifest_sha256="1" * 64, generation_record_sha256="2" * 64,
        source_sha256=hashlib.sha256(source).hexdigest(), source_bytes=len(source), static_status="STATIC_VALID")
    scope = synthetic_cuda_scope()
    tool = scope.tools["cuobjdump"].model_copy(update={
        "requested_executable": "/home/pocdev/.local/share/cuda-poc-generator/toolchains/cuobjdump-12.8.55/root/usr/local/cuda-12.8/bin/cuobjdump",
        "resolved_path": "/home/pocdev/.local/share/cuda-poc-generator/toolchains/cuobjdump-12.8.55/root/usr/local/cuda-12.8/bin/cuobjdump",
        "file_sha256": "f" * 64 if mismatch == "tool_sha256" else CUOBJDUMP_12_8_55_1_SHA256})
    raw = b"SYNTHETIC Cuda compilation tools, release 12.8, V12.8.55\nBuild cuda_12.8.r12.8/compiler.35351055_0\n"
    version = scope.version_records["cuobjdump"].model_dump(mode="python")
    argv = [tool.resolved_path, "--version"]
    version.update(argv=argv, tool_identity=tool.model_dump(mode="python"),
        stdout_b64=base64.b64encode(raw).decode("ascii"), stdout_sha256=hashlib.sha256(raw).hexdigest())
    version["command_identity"]["argv_sha256"] = digest_argv(argv)
    scope_data = scope.model_dump(mode="python")
    scope_data["tools"]["cuobjdump"] = tool
    scope_data["version_records"]["cuobjdump"] = seal_tool_result(version)
    scope = CudaToolchainScope.model_validate(scope_data)
    root = "/home/pocdev/.local/state/cuda-poc-generator/lifecycle_tasks"
    if mismatch == "remote_home": root = root.replace("/home/pocdev/", "/home/other/")
    if mismatch == "task_suffix": root = root.replace("lifecycle_tasks", "other_tasks")
    description = CudaSmokeDescription(description_schema_version="1.1", tool_profile="cuobjdump-12.8.55-1",
        status="DESCRIBED", snapshot=PlatformSnapshot.model_validate(packet()["snapshot"]), scope=scope,
        native_task_root=root, source_sha256="3" * 64,
        resource_support={"status": "UNKNOWN", "mechanisms": [], "source": "SYNTHETIC identity-only test"}, diagnostics=[])
    monkeypatch.setattr(cuda_smoke_worker, "_sidecar_cuobjdump_path",
        lambda: (_ for _ in ()).throw(AssertionError("Windows HOME cannot identify a WSL binary")))
    result = assess_candidate_admission(candidate, description)
    assert result.target_identity_status == ("VERIFIED" if mismatch is None else "FAILED")
    assert result.execution_admission == "UNSUPPORTED"
    assert result.candidate_execution_status == "NOT_EXECUTED"
    assert result.verification_status == "NOT_VERIFIED"


def test_wsl_transfer_worker_stages_only_exact_registered_source(tmp_path, monkeypatch):
    import base64
    from src import candidate_transfer_worker as worker
    from src.registered_actions import get_registered_action

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(worker.Path, "home", lambda: home)
    monkeypatch.setattr(worker, "current_platform_type", lambda: "wsl")
    monkeypatch.setattr(worker, "canonical_target_environment", lambda: "wsl:Ubuntu-22.04")
    monkeypatch.setattr(worker.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(worker.os, "getgid", lambda: 1000, raising=False)
    monkeypatch.setattr(worker, "_start_ticks", lambda: 12345)
    action = get_registered_action("p2b-normal-v1")
    result = worker.receive_registered_candidate({"schema_version": "1.0", "operation": "STAGE_REGISTERED_HARMLESS",
        "request_id": "d" * 32, "transfer_id": "e" * 32, "action_id": action.fixture_id,
        "source_b64": base64.b64encode(action.source).decode(), "source_sha256": action.sha256})
    staged = Path(result["staged_path"])
    assert result["status"] == "STAGED_AND_VERIFIED"
    assert staged.read_bytes() == action.source
    assert hashlib.sha256(staged.read_bytes()).hexdigest() == action.sha256
    assert result["candidate_execution_status"] == "NOT_EXECUTED"


def test_wsl_transfer_worker_rejects_unregistered_or_replaced_source(monkeypatch):
    import base64
    from src import candidate_transfer_worker as worker
    from src.registered_actions import get_registered_action

    monkeypatch.setattr(worker, "current_platform_type", lambda: "wsl")
    action = get_registered_action("p2b-normal-v1")
    payload = {"schema_version": "1.0", "operation": "STAGE_REGISTERED_HARMLESS",
        "request_id": "d" * 32, "transfer_id": "e" * 32, "action_id": action.fixture_id,
        "source_b64": base64.b64encode(action.source + b"# changed").decode(),
        "source_sha256": hashlib.sha256(action.source + b"# changed").hexdigest()}
    with pytest.raises(ValueError, match="immutable harmless"):
        worker.receive_registered_candidate(payload)
    payload["action_id"] = "unknown-action"
    with pytest.raises(ValueError, match="unregistered harmless"):
        worker.receive_registered_candidate(payload)
