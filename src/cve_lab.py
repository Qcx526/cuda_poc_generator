"""Windows CVE intake and separately authorized fixed harmless integration checks."""

import argparse
import json
import os
from pathlib import Path
import sys
import uuid

from .candidate_adapter import (assess_candidate_admission, load_generation_candidate,
                                render_candidate_admission)


def _write_new(path: Path, raw: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def preflight_candidate(*, cve_id, generation_run_id, linux_project_root, outputs_root="data/outputs",
                        distro="Ubuntu-22.04", user="pocdev",
                        linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python"):
    """Bind a real archived candidate to an observed target; never transfer or execute it."""
    if os.name != "nt":
        raise ValueError("candidate preflight dispatch is Windows-only; use the WSL venv only for offline verification")
    if cve_id != "CVE-2025-23339":
        raise ValueError("the current host-parser target profile is registered only for CVE-2025-23339")
    candidate = load_generation_candidate(cve_id, generation_run_id, output_root=outputs_root)
    preflight_id = uuid.uuid4().hex
    output = Path(outputs_root) / "candidate_preflights" / preflight_id
    output.mkdir(parents=True, exist_ok=False)
    transport_root = output / "transports"
    from .lifecycle_bridge import describe_cuda_smoke_wsl
    transport, packet, diagnostics = describe_cuda_smoke_wsl(
        distro=distro, user=user, linux_python=linux_python,
        linux_project_root=linux_project_root, artifact_root=transport_root,
        tool_profile="cuobjdump-12.8.55-1")
    description = None if packet is None else packet.get("cuda_description")
    report = assess_candidate_admission(candidate, description, preflight_id=preflight_id)
    if diagnostics:
        report_data = report.model_dump(mode="json")
        report_data["diagnostics"] = report_data["diagnostics"] + diagnostics
        from .candidate_adapter import CandidateAdmission
        report = CandidateAdmission.model_validate(report_data)
    if description is not None:
        _write_new(output / "target_description.json",
            (json.dumps(description, ensure_ascii=False, sort_keys=True,
                        indent=2, allow_nan=False) + "\n").encode("utf-8"))
    _write_new(output / "candidate_admission.json",
        (json.dumps(report.model_dump(mode="json"), ensure_ascii=False, sort_keys=True,
                    indent=2, allow_nan=False) + "\n").encode("utf-8"))
    _write_new(output / "report.zh-CN.md", render_candidate_admission(report).encode("utf-8"))
    return report, output


def main(argv=None):
    from .report_locale import configure_utf8_stdio
    configure_utf8_stdio()
    parser = argparse.ArgumentParser(description="CVE 归档预检与单独授权的固定无害 WSL 测试")
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser("preflight", help="verify current archived generation run and observe WSL target")
    preflight.add_argument("--cve", required=True)
    preflight.add_argument("--run-id", required=True, help="generation run ID, not a later execution run ID")
    preflight.add_argument("--linux-project-root", required=True)
    preflight.add_argument("--outputs-root", default="data/outputs")
    preflight.add_argument("--distro", default="Ubuntu-22.04")
    preflight.add_argument("--wsl-user", default="pocdev")
    preflight.add_argument("--linux-python", default="/home/pocdev/.venvs/cuda-poc-generator/bin/python")
    execute = commands.add_parser("execute", help="仅运行已审核固定无害接收文件；不运行 LLM PoC")
    execute.add_argument("--mode", choices=["fixed-staged-normal"], required=True)
    execute.add_argument("--authorize-fixed-fixture", action="store_true")
    execute.add_argument("--operator-id", required=True)
    execute.add_argument("--authorization-reference", required=True)
    execute.add_argument("--linux-project-root", required=True)
    execute.add_argument("--outputs-root", default="data/outputs/p3d_r3_staged_fixture")
    execute.add_argument("--distro", default="Ubuntu-22.04")
    execute.add_argument("--wsl-user", default="pocdev")
    execute.add_argument("--linux-python", default="/home/pocdev/.venvs/cuda-poc-generator/bin/python")
    evaluate = commands.add_parser("evaluate", help="离线核验固定无害执行原件并重建中文结论")
    evaluate.add_argument("--archive", required=True, help="本轮固定无害执行证据目录")
    args = parser.parse_args(argv)
    try:
        if args.command == "execute":
            from .staged_fixture import run_staged_fixture_wsl
            result = run_staged_fixture_wsl(authorize_fixed_fixture=args.authorize_fixed_fixture,
                operator_id=args.operator_id, authorization_reference=args.authorization_reference,
                linux_project_root=args.linux_project_root, output_root=args.outputs_root,
                distro=args.distro, user=args.wsl_user, linux_python=args.linux_python)
            fields = ("request_id", "run_id", "transfer_id", "status", "cleanup_status",
                "fixed_source_execution_status", "candidate_execution_status", "verification_status",
                "source_sha256", "manifest_sha256", "evidence_dir", "report_path", "diagnostics")
            print(json.dumps({name: result.get(name) for name in fields}, ensure_ascii=False, default=str))
            return 0 if result.get("status") == "COMPLETED" else 2
        if args.command == "evaluate":
            from .staged_fixture import evaluate_staged_fixture_archive
            result = evaluate_staged_fixture_archive(args.archive)
            fields = ("integrity_status", "status", "request_id", "run_id",
                "manifest_sha256", "report_sha256")
            print(json.dumps({name: result.get(name) for name in fields}, ensure_ascii=False, default=str))
            return 0 if result.get("integrity_status") == "VERIFIED" else 2
        result, output = preflight_candidate(cve_id=args.cve, generation_run_id=args.run_id,
                linux_project_root=args.linux_project_root, outputs_root=args.outputs_root,
                distro=args.distro, user=args.wsl_user, linux_python=args.linux_python)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("候选预检失败：" + type(exc).__name__ + "：" + str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"preflight_id": result.preflight_id, "report": str(output / "report.zh-CN.md"),
                      "candidate_execution_status": result.candidate_execution_status,
                      "verification_status": result.verification_status,
                      "execution_admission": result.execution_admission,
                      "target_identity_status": result.target_identity_status}, ensure_ascii=False))
    return 0 if result.target_identity_status == "VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
