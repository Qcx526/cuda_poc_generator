"""Operator-only P2-A communication check, restricted to one harmless fixture."""

import argparse
from datetime import datetime, timedelta, timezone
import json
import sys
import uuid

from .execution_artifacts import write_execution_evidence
from .execution_bridge import describe_fixed_fixture_wsl, execute_fixed_fixture_wsl
from .execution_worker import FIXTURE_ID, FIXTURE_SHA256, FIXTURE_SOURCE
from .models.execution import (ExecutionRequest, OperatorAuthorization, PreflightPolicy, snapshot_sha256,
                               ExecutionResourceLimits)
from .models.execution_binding import bind_candidate_to_tool
from .models.platform import PlatformSnapshot
from .models.tool_result import ToolResult


def run_authorized_fixture_check(*, authorize_fixed_fixture, authorization_reference,
                                operator_id, linux_project_root, distro="Ubuntu-22.04",
                                user="pocdev", linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python",
                                output_root=None):
    """Trusted operator boundary; never call with model-supplied authorization.

    This function intentionally accepts no request JSON, candidate path or argv.
    The explicit operator invocation creates a short-lived, exact-scope grant.
    Library callers with their own policy can use the separate strict contracts.
    """
    if authorize_fixed_fixture is not True:
        raise ValueError("explicit operator authorization for the fixed harmless fixture is required")
    if any(not isinstance(value, str) or not value.strip() or "\0" in value or len(value) > 128
           for value in (authorization_reference, operator_id)):
        raise ValueError("provide a nonblank operator ID and authorization reference (at most 128 characters)")
    bridge_options = {"distro": distro, "user": user, "linux_python": linux_python,
                      "linux_project_root": linux_project_root}
    described = describe_fixed_fixture_wsl(**bridge_options)
    describe_folder = write_execution_evidence(output_root, described)
    packet = described["packet"]
    if packet is None or packet["status"] != "DESCRIBED":
        return {"status": "UNKNOWN", "request_id": None, "describe_evidence": str(describe_folder),
                "execution_evidence": None, "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    snapshot = PlatformSnapshot.model_validate(packet["target_snapshot"])
    observation = ToolResult.model_validate(packet["tool_result"])
    binding = bind_candidate_to_tool(FIXTURE_SOURCE, snapshot, observation,
                                     expected_probe_id=snapshot.metadata["probe_id"],
                                     expected_tool_record_id=observation.record_id)
    limits = ExecutionResourceLimits(wall_time_seconds=10.0, cpu_seconds=2,
                                     memory_bytes=268435456, max_output_bytes=4096)
    request = ExecutionRequest(
        request_id=uuid.uuid4().hex, candidate_sha256=FIXTURE_SHA256,
        platform_environment_id=snapshot.environment_id, platform_probe_id=snapshot.metadata["probe_id"],
        execution_backend="wsl", authorized_action="FIXED_FIXTURE_CHECK",
        authorization_reference=authorization_reference, tool_role="fixture_python",
        tool_identity=observation.tool_identity, binding=binding, resource_limits=limits,
        expected_artifacts=["stdout.bin", "stderr.bin", "tool_result.json"],
        candidate_path=packet["fixture_path"], cwd=packet["cwd"], input_files=[], fixture_id=FIXTURE_ID)
    now = datetime.now(timezone.utc)
    grant = OperatorAuthorization(
        request_id=request.request_id, authorization_reference=authorization_reference,
        operator_id=operator_id, issuer_kind="operator", candidate_sha256=request.candidate_sha256,
        platform_environment_id=request.platform_environment_id, platform_probe_id=request.platform_probe_id,
        authorized_action=request.authorized_action, tool_resolved_path=observation.tool_identity.resolved_path,
        tool_file_sha256=observation.tool_identity.file_sha256, resource_limits=limits, fixture_id=FIXTURE_ID,
        not_before=now.isoformat(), expires_at=(now + timedelta(minutes=5)).isoformat())
    # This configuration is constructed in the operator entry point, independently
    # of all generated analysis. The target recomputes actual resource support.
    policy = PreflightPolicy(
        expected_environment_id=snapshot.environment_id, expected_probe_id=request.platform_probe_id,
        expected_snapshot_sha256=snapshot_sha256(snapshot),
        expected_target_environment=binding.target_environment, execution_backend="wsl",
        allowed_operator_ids=[operator_id], allowed_authorization_references=[authorization_reference],
        scope_root=packet["cwd"], allowed_tools={observation.tool_identity.resolved_path: observation.tool_identity.file_sha256},
        fixture_hashes={FIXTURE_ID: FIXTURE_SHA256}, max_snapshot_age_seconds=300,
        resource_support=packet["resource_support"],
        max_resource_limits=limits)
    executed = execute_fixed_fixture_wsl(request, grant, snapshot, observation, policy, **bridge_options)
    # Operator grant and policy are private records, never repository content.
    execute_folder = write_execution_evidence(output_root, executed, request=request,
                                             authorization=grant, policy=policy)
    return {"status": executed["packet"]["status"] if executed["packet"] is not None else "UNKNOWN",
            "request_id": request.request_id, "describe_evidence": str(describe_folder),
            "execution_evidence": str(execute_folder), "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Explicitly authorized fixed harmless Windows-to-WSL fixture check; no candidate execution")
    parser.add_argument("--authorize-fixed-fixture", action="store_true", help="operator explicitly authorizes only the registered harmless fixture")
    parser.add_argument("--authorization-reference", required=True)
    parser.add_argument("--operator-id", required=True)
    parser.add_argument("--linux-project-root", required=True, help="explicit trusted Linux checkout path")
    parser.add_argument("--distro", default="Ubuntu-22.04")
    parser.add_argument("--wsl-user", default="pocdev")
    parser.add_argument("--linux-python", default="/home/pocdev/.venvs/cuda-poc-generator/bin/python")
    parser.add_argument("--output-root", default=None)
    args = parser.parse_args(argv)
    try:
        result = run_authorized_fixture_check(
            authorize_fixed_fixture=args.authorize_fixed_fixture, authorization_reference=args.authorization_reference,
            operator_id=args.operator_id, linux_project_root=args.linux_project_root, distro=args.distro,
            user=args.wsl_user, linux_python=args.linux_python, output_root=args.output_root)
    except (ValueError, OSError) as exc:
        print("P2-A fixture check failed: " + str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] == "FIXTURE_COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
