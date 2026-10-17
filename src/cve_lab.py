"""Windows entry points for read-only candidate admission and fixed safe target smoke."""

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
    parser = argparse.ArgumentParser(description="CVE lab: fail-closed candidate preflight; no candidate execution")
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser("preflight", help="verify current archived generation run and observe WSL target")
    preflight.add_argument("--cve", required=True)
    preflight.add_argument("--run-id", required=True, help="generation run ID, not a later execution run ID")
    preflight.add_argument("--linux-project-root", required=True)
    preflight.add_argument("--outputs-root", default="data/outputs")
    preflight.add_argument("--distro", default="Ubuntu-22.04")
    preflight.add_argument("--wsl-user", default="pocdev")
    preflight.add_argument("--linux-python", default="/home/pocdev/.venvs/cuda-poc-generator/bin/python")
    args = parser.parse_args(argv)
    try:
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
