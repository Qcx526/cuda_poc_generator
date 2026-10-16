"""Explicit Windows operator entry point: fixed CUDA compile/inspect, no launch."""

import argparse
from datetime import timedelta
import json
from pathlib import PurePosixPath
import sys
import uuid

from .cuda_registry import CUDA_SMOKE_ID, CUDA_SMOKE_SHA256, CUDA_SMOKE_SOURCE
from .cuda_smoke_worker import CudaSmokeDescription
from .execution_worker import contract_digest
from .lifecycle_artifacts import (write_execution_evidence, read_execution_evidence, EvidenceWriteError)
from .lifecycle_bridge import describe_cuda_smoke_wsl, run_task_wsl, LifecycleDispatchError
from .lifecycle_cli import persist_task_handle
from .models.execution import (CudaResourceLimits, ExecutionRequest, OperatorAuthorization,
                               PreflightPolicy, snapshot_sha256, aware_time)
from .models.execution_binding import bind_candidate_to_tool


def build_cuda_operator_context(description, *, run_id, operator_id, authorization_reference, arch=None):
    description = CudaSmokeDescription.model_validate(description)
    if description.status != "DESCRIBED" or description.scope is None or description.snapshot is None:
        raise ValueError("fixed CUDA description did not establish a supported measured toolchain")
    scope, snapshot = description.scope, description.snapshot
    if arch is not None and arch != scope.arch:
        raise ValueError("explicit architecture differs from this target's observed and validated CUDA architecture")
    if not isinstance(run_id, str) or len(run_id) != 32 or any(c not in "0123456789abcdef" for c in run_id):
        raise ValueError("run ID must be 32 lowercase hexadecimal digits")
    workspace = str(PurePosixPath(description.native_task_root) / run_id / "work")
    tool = scope.version_records["nvcc"]
    binding = bind_candidate_to_tool(CUDA_SMOKE_SOURCE, snapshot, tool,
        expected_probe_id=snapshot.metadata["probe_id"], expected_tool_record_id=tool.record_id)
    # Each of six declared tool steps has this bounded profile. No GPU/VRAM or
    # aggregate process-tree CPU budget is implied by per-process RLIMITs.
    limits = CudaResourceLimits(wall_time_seconds=30.0, cpu_seconds=15,
                                memory_bytes=4294967296, max_output_bytes=131072)
    req = ExecutionRequest(request_schema_version="1.2", request_id=uuid.uuid4().hex,
        candidate_sha256=CUDA_SMOKE_SHA256, platform_environment_id=snapshot.environment_id,
        platform_probe_id=snapshot.metadata["probe_id"], execution_backend="wsl",
        authorized_action="SAFE_CUDA_SMOKE", authorization_reference=authorization_reference,
        tool_role="nvcc", tool_identity=scope.tools["nvcc"], binding=binding, resource_limits=limits,
        cuda_toolchain=scope, expected_artifacts=["stdout.bin", "stderr.bin", "process_result.json"],
        candidate_path=str(PurePosixPath(workspace) / "safe_smoke.cu"), cwd=workspace,
        input_files=[], fixture_id=CUDA_SMOKE_ID)
    now = aware_time(tool.finished_at)
    grant = OperatorAuthorization(authorization_schema_version="1.1", request_id=req.request_id,
        authorization_reference=authorization_reference, operator_id=operator_id, issuer_kind="operator",
        candidate_sha256=req.candidate_sha256, platform_environment_id=req.platform_environment_id,
        platform_probe_id=req.platform_probe_id, authorized_action=req.authorized_action,
        tool_resolved_path=req.tool_identity.resolved_path, tool_file_sha256=req.tool_identity.file_sha256,
        resource_limits=limits, cuda_toolchain=scope, fixture_id=req.fixture_id,
        authorization_clock="TARGET_BOOT_MONOTONIC", not_before_monotonic_ns=scope.observed_monotonic_ns,
        expires_monotonic_ns=scope.observed_monotonic_ns + 300000000000,
        not_before=now.isoformat(), expires_at=(now + timedelta(minutes=5)).isoformat())
    policy = PreflightPolicy(policy_schema_version="1.1", expected_environment_id=snapshot.environment_id,
        expected_probe_id=req.platform_probe_id, expected_snapshot_sha256=snapshot_sha256(snapshot),
        expected_target_environment=binding.target_environment, execution_backend="wsl",
        allowed_operator_ids=[operator_id], allowed_authorization_references=[authorization_reference],
        scope_root=workspace, allowed_tools={item.resolved_path: item.file_sha256 for item in scope.tools.values()},
        fixture_hashes={CUDA_SMOKE_ID: CUDA_SMOKE_SHA256}, resource_support=description.resource_support,
        max_resource_limits=limits, cuda_toolchain=scope)
    return req, grant, policy, snapshot, tool


def run_safe_cuda_smoke(*, authorize_safe_cuda_smoke, authorization_reference, operator_id,
                        linux_project_root, backend="wsl", distro="Ubuntu-22.04", user="pocdev",
                        linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python", arch=None, output_root=None):
    if authorize_safe_cuda_smoke is not True:
        raise ValueError("explicit operator authorization for the fixed safe CUDA smoke is required")
    if backend != "wsl":
        raise ValueError("only the fixed Windows-to-WSL CUDA smoke backend is supported")
    for value in (authorization_reference, operator_id):
        if not isinstance(value, str) or not value.strip() or len(value) > 128 or any(c in value for c in "\0\n\r"):
            raise ValueError("operator and authorization reference must be nonblank single-line identifiers")
    options = {"distro": distro, "user": user, "linux_python": linux_python, "linux_project_root": linux_project_root}
    transport, packet, diagnostics = describe_cuda_smoke_wsl(**options)
    from .lifecycle_artifacts import write_cuda_readiness_evidence
    readiness = write_cuda_readiness_evidence(output_root, transport, packet, diagnostics)
    from .report_locale import write_execution_view_from_archive
    readiness_view = write_execution_view_from_archive(readiness)
    description = None if packet is None else packet.get("cuda_description")
    if description is None or description["status"] != "DESCRIBED":
        return {"effective_state": "UNKNOWN" if description is None else description["status"],
            "readiness_report": str(readiness_view / "report.zh-CN.md"), "report_locale": "zh-CN", "candidate_execution_status": "NOT_EXECUTED",
            "verification_status": "NOT_VERIFIED"}
    run_id = uuid.uuid4().hex
    req, grant, policy, snapshot, tool = build_cuda_operator_context(description, run_id=run_id,
        operator_id=operator_id, authorization_reference=authorization_reference, arch=arch)
    control = None
    def retain_handle(handle):
        nonlocal control
        control = persist_task_handle(handle, output_root)
    result = run_task_wsl(req, grant, policy, snapshot, tool, run_id=run_id, on_task_created=retain_handle, **options)
    folder = write_execution_evidence(output_root, result, request=req, authorization=grant,
        policy=policy, snapshot=snapshot, binding_tool_result=tool)
    checked = read_execution_evidence(folder, expected_request_id=req.request_id, expected_run_id=run_id)
    manifest = checked["manifest"]
    view = write_execution_view_from_archive(folder,source_domain="RECORDED_EXECUTION")
    return {"request_id": req.request_id, "run_id": run_id, "action_id": CUDA_SMOKE_ID,
        "remote_state": checked["record"].status, "effective_state": manifest.effective_status,
        "cleanup_confirmation": manifest.cleanup_confirmation,
        "native_evidence": manifest.native_evidence.status,
        "evidence_directory": str(folder), "report": str(view / "report.zh-CN.md"), "report_locale": "zh-CN",
        "control_handle_file": str(control), "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}


def main(argv=None):
    from .report_locale import configure_utf8_stdio, failure_with_legacy_zh
    configure_utf8_stdio()
    parser = argparse.ArgumentParser(description="Explicitly authorized fixed CUDA compile/inspect in WSL; never launches a kernel or PoC")
    parser.add_argument("--authorize-safe-cuda-smoke", action="store_true")
    parser.add_argument("--backend", choices=["wsl"], default="wsl")
    parser.add_argument("--authorization-reference", required=True)
    parser.add_argument("--operator-id", required=True)
    parser.add_argument("--linux-project-root", required=True)
    parser.add_argument("--distro", default="Ubuntu-22.04")
    parser.add_argument("--wsl-user", default="pocdev")
    parser.add_argument("--linux-python", default="/home/pocdev/.venvs/cuda-poc-generator/bin/python")
    parser.add_argument("--arch", default=None, help="Optional explicit target; must equal observed GPU/nvcc target")
    parser.add_argument("--output-root", default=None)
    args = parser.parse_args(argv)
    try:
        result = run_safe_cuda_smoke(authorize_safe_cuda_smoke=args.authorize_safe_cuda_smoke,
            authorization_reference=args.authorization_reference, operator_id=args.operator_id,
            linux_project_root=args.linux_project_root, backend=args.backend, distro=args.distro,
            user=args.wsl_user, linux_python=args.linux_python, arch=args.arch, output_root=args.output_root)
    except LifecycleDispatchError as exc:
        print(failure_with_legacy_zh(exc.report,exc.record), file=sys.stderr)
        return 1
    except EvidenceWriteError as exc:
        record = exc.record
        legacy=("CUDA smoke evidence storage INCOMPLETE; no persisted success is claimed."
              + (" Remote recorded status: " + record.status if record is not None else "")
              + " Candidate NOT_EXECUTED; CVE NOT_VERIFIED.")
        print(failure_with_legacy_zh(legacy,record),file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(failure_with_legacy_zh(type(exc).__name__+": "+str(exc)), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["effective_state"] == "COMPLETED" and result.get("native_evidence") == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
