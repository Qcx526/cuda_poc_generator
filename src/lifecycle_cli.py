"""Explicit operator entry point for fixed harmless lifecycle checks."""

import argparse
from datetime import timedelta
import json
from pathlib import Path, PurePosixPath
import os
import sys
import uuid

from .execution_artifacts import write_execution_evidence as write_readiness_evidence
from .execution_bridge import describe_fixed_fixture_wsl
from .lifecycle_artifacts import write_execution_evidence, read_execution_evidence, EvidenceWriteError
from .lifecycle_bridge import run_task_wsl, LifecycleDispatchError
from .models.execution import (ExecutionRequest, ExecutionResourceLimits, OperatorAuthorization,
                               PreflightPolicy, snapshot_sha256, aware_time)
from .models.execution_binding import bind_candidate_to_tool
from .models.platform import PlatformSnapshot
from .models.tool_result import ToolResult
from .registered_actions import REGISTERED_ACTIONS, get_registered_action
from .probe_artifacts import protect_directory


def build_operator_context(description, action_id, *, operator_id, authorization_reference, cancellation_test=False):
    """Trusted CLI configuration; never populate operator inputs with model output."""
    action = get_registered_action(action_id)
    snapshot = PlatformSnapshot.model_validate(description["target_snapshot"])
    tool = ToolResult.model_validate(description["tool_result"])
    binding = bind_candidate_to_tool(action.source, snapshot, tool,
                                     expected_probe_id=snapshot.metadata["probe_id"], expected_tool_record_id=tool.record_id)
    wall = 0.8 if action_id in {"p2b-timeout-v1", "p2b-child-cleanup-v1"} else 5.0
    if cancellation_test:
        wall = 5.0
    limits = ExecutionResourceLimits(wall_time_seconds=wall, cpu_seconds=1 if action_id == "p2b-cpu-limit-v1" else 2,
                                     memory_bytes=268435456, max_output_bytes=4096)
    req = ExecutionRequest(request_schema_version="1.1", request_id=uuid.uuid4().hex, candidate_sha256=action.sha256,
        platform_environment_id=snapshot.environment_id, platform_probe_id=snapshot.metadata["probe_id"],
        execution_backend="wsl", authorized_action="FIXED_FIXTURE_CHECK", authorization_reference=authorization_reference,
        tool_role="fixture_python", tool_identity=tool.tool_identity, binding=binding, resource_limits=limits,
        expected_artifacts=["stdout.bin", "stderr.bin", "process_result.json"],
        candidate_path=str(PurePosixPath(description["cwd"]) / action.relative_path), cwd=description["cwd"],
        input_files=[], fixture_id=action.fixture_id)
    # Authorization is evaluated against the target clock. Anchor the operator's
    # window to the exact retained WSL observation, not a guessed host clock
    # offset; preflight and both gates keep their strict time comparisons.
    now = aware_time(tool.finished_at)
    grant = OperatorAuthorization(request_id=req.request_id, authorization_reference=authorization_reference,
        operator_id=operator_id, issuer_kind="operator", candidate_sha256=req.candidate_sha256,
        platform_environment_id=req.platform_environment_id, platform_probe_id=req.platform_probe_id,
        authorized_action=req.authorized_action, tool_resolved_path=tool.tool_identity.resolved_path,
        tool_file_sha256=tool.tool_identity.file_sha256, resource_limits=limits, fixture_id=req.fixture_id,
        not_before=now.isoformat(), expires_at=(now + timedelta(minutes=5)).isoformat())
    policy = PreflightPolicy(expected_environment_id=snapshot.environment_id, expected_probe_id=req.platform_probe_id,
        expected_snapshot_sha256=snapshot_sha256(snapshot), expected_target_environment=binding.target_environment,
        execution_backend="wsl", allowed_operator_ids=[operator_id], allowed_authorization_references=[authorization_reference],
        scope_root=req.cwd, allowed_tools={tool.tool_identity.resolved_path: tool.tool_identity.file_sha256},
        fixture_hashes={action.fixture_id: action.sha256}, resource_support=description["resource_support"], max_resource_limits=limits)
    return req, grant, policy, snapshot, tool


def persist_task_handle(handle, output_root=None):
    """Protect a scoped operator capability without printing its token."""
    from .lifecycle_artifacts import default_lifecycle_output_root
    root = Path(output_root) if output_root is not None else default_lifecycle_output_root()
    folder = root / "controls" / handle.run_id
    protect_directory(folder)
    control_file = folder / "operator_handle.json"
    fd = os.open(control_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write((json.dumps(handle.model_dump(mode="json"), sort_keys=True) + "\n").encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())
    if os.name != "nt":
        control_file.chmod(0o600)
    return control_file


def run_authorized_action(*, authorize_fixed_actions, action_id, authorization_reference, operator_id,
                          linux_project_root, distro="Ubuntu-22.04", user="pocdev",
                          linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python",
                          cancel_after_seconds=None, output_root=None):
    if authorize_fixed_actions is not True:
        raise ValueError("explicit operator authorization for registered harmless actions is required")
    for value in (authorization_reference, operator_id):
        if not isinstance(value, str) or not value.strip() or len(value) > 128 or any(c in value for c in "\0\n\r"):
            raise ValueError("operator and authorization reference must be nonblank single-line identifiers")
    get_registered_action(action_id)
    options = {"distro": distro, "user": user, "linux_python": linux_python, "linux_project_root": linux_project_root}
    described = describe_fixed_fixture_wsl(**options)
    readiness = write_readiness_evidence(None, described)
    from .report_locale import write_execution_view_from_archive
    readiness_view = write_execution_view_from_archive(readiness)
    if described["packet"] is None or described["packet"]["status"] != "DESCRIBED":
        return {"effective_state": "UNKNOWN", "readiness_report": str(readiness_view / "report.zh-CN.md"), "report_locale": "zh-CN",
                "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    req, grant, policy, snapshot, tool = build_operator_context(described["packet"], action_id,
        operator_id=operator_id, authorization_reference=authorization_reference, cancellation_test=cancel_after_seconds is not None)
    control_file = None
    def retain_handle(handle):
        nonlocal control_file
        control_file = persist_task_handle(handle, output_root)
    result = run_task_wsl(req, grant, policy, snapshot, tool, cancel_after_seconds=cancel_after_seconds,
                          on_task_created=retain_handle, **options)
    folder = write_execution_evidence(output_root, result, request=req, authorization=grant, policy=policy,
                                       snapshot=snapshot, binding_tool_result=tool)
    checked = read_execution_evidence(folder, expected_request_id=req.request_id, expected_run_id=result["record"]["run_id"])
    manifest = checked["manifest"]
    view = write_execution_view_from_archive(folder,source_domain="RECORDED_EXECUTION")
    return {"request_id": req.request_id, "run_id": result["record"]["run_id"], "action_id": action_id,
            "remote_state": result["record"]["status"], "effective_state": manifest.effective_status,
            "cleanup_confirmation": manifest.cleanup_confirmation, "evidence_directory": str(folder),
            "report": str(view / "report.zh-CN.md"), "report_locale": "zh-CN",
            "control_handle_file": str(control_file),
            "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}


def main(argv=None):
    from .report_locale import configure_utf8_stdio, failure_with_legacy_zh
    configure_utf8_stdio()
    parser = argparse.ArgumentParser(description="Authorized registered harmless Windows-to-WSL lifecycle check; no candidate execution")
    parser.add_argument("--authorize-fixed-actions", action="store_true")
    parser.add_argument("--action", required=True, choices=tuple(REGISTERED_ACTIONS))
    parser.add_argument("--authorization-reference", required=True)
    parser.add_argument("--operator-id", required=True)
    parser.add_argument("--linux-project-root", required=True)
    parser.add_argument("--distro", default="Ubuntu-22.04")
    parser.add_argument("--wsl-user", default="pocdev")
    parser.add_argument("--linux-python", default="/home/pocdev/.venvs/cuda-poc-generator/bin/python")
    parser.add_argument("--cancel-after", type=float, default=None)
    parser.add_argument("--output-root", default=None)
    args = parser.parse_args(argv)
    try:
        result = run_authorized_action(authorize_fixed_actions=args.authorize_fixed_actions, action_id=args.action,
            authorization_reference=args.authorization_reference, operator_id=args.operator_id,
            linux_project_root=args.linux_project_root, distro=args.distro, user=args.wsl_user,
            linux_python=args.linux_python, cancel_after_seconds=args.cancel_after, output_root=args.output_root)
    except LifecycleDispatchError as exc:
        # If the storage device is unavailable, keep a deterministic in-memory
        # report on stderr instead of inventing an on-disk evidence success.
        print(failure_with_legacy_zh(exc.report,exc.record), file=sys.stderr)
        return 1
    except EvidenceWriteError as exc:
        observed = exc.record
        legacy=("# P2-B evidence persistence failure\n\nStatus: UNKNOWN\nStorage: INCOMPLETE\n"
              + ("Request: " + observed.request_id + "\nRun: " + observed.run_id
                 + "\nRemote recorded status: " + observed.status + "\n" if observed is not None else "")
              + "\nThe evidence manifest could not be committed. No persisted evidence success is claimed."
              + "\nCandidate execution: NOT_EXECUTED. CVE verification: NOT_VERIFIED.\n")
        print(failure_with_legacy_zh(legacy,observed),file=sys.stderr)
        return 1
    except (ValueError, OSError) as exc:
        print(failure_with_legacy_zh(type(exc).__name__+": "+str(exc)), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["effective_state"] == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
