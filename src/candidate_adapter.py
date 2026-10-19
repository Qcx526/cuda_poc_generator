"""Fail-closed candidate identity intake; arbitrary PoC code is never started here."""

from datetime import datetime, timezone
import base64
import hashlib
import json
import os
import re
import uuid
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from .artifact_packaging import ROOT as ARTIFACT_PROJECT_ROOT, read_review_run
from .cuda_smoke_worker import CudaSmokeDescription, registered_sidecar_cuobjdump_identity_matches
from .models.generation import CandidateResult
from .models.lifecycle import LifecycleContract


class CandidateArtifact(LifecycleContract):
    artifact_schema_version: Literal["1.0"] = "1.0"
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    generation_run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    generation_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    generation_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_relative_path: Literal["poc/cuda_poc_v1.py"] = "poc/cuda_poc_v1.py"
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_bytes: int = Field(gt=0, le=1048576)
    static_status: Literal["NOT_CHECKED", "STATIC_VALID", "STATIC_INVALID"]


class CandidateAdmission(LifecycleContract):
    admission_schema_version: Literal["1.0"] = "1.0"
    report_locale: Literal["zh-CN"] = "zh-CN"
    preflight_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    observed_at: str
    candidate: CandidateArtifact
    target_environment: str | None
    platform_environment_id: str | None
    platform_probe_id: str | None
    target_tool_profile: str | None
    target_tool_path: str | None
    target_tool_sha256: str | None
    target_tool_version: str | None = Field(default=None, max_length=4096)
    candidate_identity_status: Literal["VERIFIED", "FAILED", "UNKNOWN"]
    target_identity_status: Literal["VERIFIED", "FAILED", "UNKNOWN", "NOT_CHECKED"]
    execution_admission: Literal["UNSUPPORTED"] = "UNSUPPORTED"
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    verification_status: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    diagnostics: list[str] = Field(max_length=32)

    @model_validator(mode="after")
    def fail_closed(self):
        if self.target_identity_status == "VERIFIED":
            if not all((self.target_environment, self.platform_environment_id, self.platform_probe_id,
                        self.target_tool_profile, self.target_tool_path, self.target_tool_sha256,
                        self.target_tool_version)):
                raise ValueError("verified target identity must include platform, tool and build")
        elif any((self.target_tool_path, self.target_tool_sha256, self.target_tool_version)):
            raise ValueError("unverified target cannot carry measured tool identity fields")
        if self.execution_admission != "UNSUPPORTED" or self.candidate_execution_status != "NOT_EXECUTED":
            raise ValueError("this adapter is identity-only and cannot grant arbitrary candidate execution")
        return self


def load_generation_candidate(cve_id: str, generation_run_id: str, *, output_root=None) -> CandidateArtifact:
    """Read the current immutable generation archive; never fall back to flat v1 files."""
    archive_root = Path(output_root) if output_root else ARTIFACT_PROJECT_ROOT / "data" / "outputs"
    manifest, content = read_review_run(cve_id, generation_run_id, output_root=archive_root)
    if manifest.evidence_domain != "GENERATED_CANDIDATE_RESEARCH":
        raise ValueError("指定 run 是资料审查产物，不是本轮候选生成记录")
    record_raw = content.get("analysis/generation_run.json")
    source = content.get("poc/cuda_poc_v1.py")
    if record_raw is None or source is None:
        raise ValueError("指定生成轮次没有真实保存的候选源码")
    record = json.loads(record_raw)
    if record.get("cve_id") != cve_id or record.get("run_id") != generation_run_id:
        raise ValueError("候选生成记录与请求 CVE/run 不一致")
    candidate = CandidateResult.model_validate(record.get("candidate"))
    source_digest = hashlib.sha256(source).hexdigest()
    if (candidate.run_id != generation_run_id or candidate.generation != "GENERATED"
            or candidate.sha256 != source_digest or record.get("execution") != "NOT_EXECUTED"
            or record.get("verification") != "NOT_VERIFIED"):
        raise ValueError("当前生成记录与本轮候选原始字节或状态不一致")
    if len(source) > 1048576:
        raise ValueError("候选超过接收上限")
    generation_manifest_sha = hashlib.sha256(
        archive_root.joinpath(cve_id, "runs", generation_run_id, "artifact_manifest.json").read_bytes()).hexdigest()
    from .models.lifecycle import canonical_sha256
    return CandidateArtifact(cve_id=cve_id, generation_run_id=generation_run_id,
        generation_manifest_sha256=generation_manifest_sha, generation_record_sha256=canonical_sha256(record),
        source_sha256=source_digest, source_bytes=len(source), static_status=candidate.static)


def assess_candidate_admission(candidate: CandidateArtifact, description, *, preflight_id=None) -> CandidateAdmission:
    """Bind a generated source to a measured WSL target while denying execution."""
    candidate = CandidateArtifact.model_validate(candidate.model_dump(mode="python") if isinstance(candidate, CandidateArtifact) else candidate)
    diagnostics = ["ARBITRARY_CANDIDATE_EXECUTION_UNSUPPORTED",
                   "固定 fixture 的授权和隔离不能授予未知 LLM 代码执行权"]
    target_environment = platform_id = probe_id = profile = tool_path = tool_sha = tool_version = None
    target_status = "NOT_CHECKED"
    if description is not None:
        desc = CudaSmokeDescription.model_validate(description.model_dump(mode="python") if isinstance(description, CudaSmokeDescription) else description)
        if desc.status != "DESCRIBED" or desc.snapshot is None or desc.scope is None:
            target_status = "UNKNOWN"
            diagnostics.append("WSL_TARGET_OR_TOOLCHAIN_DESCRIPTION_INCOMPLETE")
        else:
            target_environment = desc.snapshot.metadata.get("environment_label")
            platform_id = desc.snapshot.environment_id
            probe_id = desc.snapshot.metadata.get("probe_id")
            profile = desc.tool_profile
            tool = desc.scope.tools["cuobjdump"]
            target_text = (desc.scope.version_records["cuobjdump"].stdout_bytes()
                           + desc.scope.version_records["cuobjdump"].stderr_bytes()).decode("utf-8", errors="replace")
            target_status = "VERIFIED"
            tool_path, tool_sha, tool_version = tool.resolved_path, tool.file_sha256, target_text.strip()
            if (desc.snapshot.platform_type != "wsl" or desc.snapshot.execution_backend != "wsl"
                    or profile != "cuobjdump-12.8.55-1" or "V12.8.55" not in target_text
                    or "Build cuda_12.8.r12.8/compiler.35351055_0" not in target_text
                    or not registered_sidecar_cuobjdump_identity_matches(tool, target_text,
                        target_task_root=desc.native_task_root)):
                target_status = "FAILED"
                diagnostics.append("TARGET_CUOBJDUMP_IS_NOT_THE_REGISTERED_12_8_55_BUILD")
            if not all((target_environment, probe_id)):
                target_status = "UNKNOWN"
                diagnostics.append("WSL_PLATFORM_IDENTITY_INCOMPLETE")
    return CandidateAdmission(preflight_id=preflight_id or uuid.uuid4().hex,
        observed_at=datetime.now(timezone.utc).isoformat(), candidate=candidate,
        target_environment=target_environment, platform_environment_id=platform_id, platform_probe_id=probe_id,
        target_tool_profile=profile, target_tool_path=tool_path if target_status == "VERIFIED" else None,
        target_tool_sha256=tool_sha if target_status == "VERIFIED" else None,
        target_tool_version=tool_version if target_status == "VERIFIED" else None,
        candidate_identity_status="VERIFIED", target_identity_status=target_status,
        diagnostics=diagnostics)


def render_candidate_admission(report: CandidateAdmission) -> str:
    report = CandidateAdmission.model_validate(report.model_dump(mode="python") if isinstance(report, CandidateAdmission) else report)
    def cell(value):
        return str(value if value is not None else "未检查").replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    lines = ["# 候选执行准入预检报告", "", "报告语言：zh-CN。", "",
        "本报告只核对已归档生成候选与 WSL 目标身份，不启动候选。", "",
        "| 项目 | 本轮观测 |", "|---|---|",
        f"| preflight_id | {report.preflight_id} |",
        f"| CVE / 生成 run | {report.candidate.cve_id} / {report.candidate.generation_run_id} |",
        f"| 生成 manifest SHA-256 | {report.candidate.generation_manifest_sha256} |",
        f"| 源码 SHA-256 / 字节数 | {report.candidate.source_sha256} / {report.candidate.source_bytes} |",
        f"| 静态检查 | {report.candidate.static_status}（不代表可执行） |",
        f"| WSL 目标 / 平台 ID / probe | {cell(report.target_environment)} / {cell(report.platform_environment_id)} / {cell(report.platform_probe_id)} |",
        f"| cuobjdump 档案 / 路径 / SHA-256 | {cell(report.target_tool_profile)} / {cell(report.target_tool_path)} / {cell(report.target_tool_sha256)} |",
        f"| 工具版本原始输出 | {cell(report.target_tool_version)} |",
        f"| 候选身份 / 目标身份 / 执行准入 | {report.candidate_identity_status} / {report.target_identity_status} / {report.execution_admission} |",
        f"| 候选执行 / CVE 验证 | {report.candidate_execution_status} / {report.verification_status} |", "",
        "## 阻断原因", ""]
    lines.extend("- " + cell(code) for code in report.diagnostics)
    lines += ["", "当前 WSL bubblewrap 与资源合同仅覆盖已审核固定 fixture，尚未认证适用于任意模型生成 Python、native 或 GPU 程序。",
        "候选源码已绑定生成 CVE、run、manifest 和字节哈希；此身份核验不会创建候选执行授权。",
        "系统 cuobjdump 工具 smoke 使用独立固定输入，不属于本轮候选，也不能作为指定 CVE 验证证据。", ""]
    return "\n".join(lines)


class CandidateTransferReceipt(LifecycleContract):
    schema_version: Literal["1.0"] = "1.0"
    status: Literal["STAGED_AND_VERIFIED"]
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    transfer_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    action_id: Literal["p2b-normal-v1"]
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_bytes: int = Field(gt=0, le=1048576)
    target_environment: str = Field(min_length=1)
    receiver_pid: int = Field(gt=0)
    receiver_ppid: int = Field(ge=0)
    receiver_uid: int = Field(ge=0)
    receiver_gid: int = Field(ge=0)
    receiver_start_ticks: int = Field(gt=0)
    staged_relative_path: Literal["candidate.py"]
    staged_path: str = Field(min_length=1)
    candidate_execution_status: Literal["NOT_EXECUTED"]
    verification_status: Literal["NOT_VERIFIED"]


def _write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def transfer_registered_candidate_wsl(*, action_id, linux_project_root, output_root="data/outputs/candidate_transfers",
        distro="Ubuntu-22.04", user="pocdev", linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python"):
    """Transfer and stage only the exact fixed normal-exit fixture; this never executes it."""
    if os.name != "nt":
        raise ValueError("candidate transfer adapter is Windows-only")
    from .registered_actions import get_registered_action
    from .tools.process import measure_tool_identity, run_tool
    from .wsl_bridge import validate_wsl_options
    from .execution_bridge import _linux_root, build_execution_worker_source

    if action_id != "p2b-normal-v1":
        raise ValueError("only the reviewed p2b-normal-v1 transfer is supported in this phase")
    action = get_registered_action(action_id)
    validate_wsl_options(distro, linux_python, user)
    project_root = _linux_root(linux_project_root)
    request_id, transfer_id = uuid.uuid4().hex, uuid.uuid4().hex
    payload = {"schema_version": "1.0", "operation": "STAGE_REGISTERED_HARMLESS",
        "request_id": request_id, "transfer_id": transfer_id, "action_id": action_id,
        "source_b64": base64.b64encode(action.source).decode("ascii"), "source_sha256": action.sha256}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    bootstrap = build_execution_worker_source(payload, linux_project_root=project_root,
                                               worker_entrypoint="candidate_transfer")
    launcher = measure_tool_identity("wsl.exe", source="Windows fixed candidate transfer WSL launcher")
    if launcher.status != "OBSERVED":
        raise ValueError("Windows WSL launcher identity is unavailable; fixed transfer cannot start")
    result = run_tool([launcher.resolved_path, "--distribution", distro, "--user", user,
                       "--exec", linux_python, "-I", "-"], timeout_seconds=30, max_output_bytes=65536,
                      input_bytes=bootstrap, command_source="fixed registered harmless candidate byte transfer only",
                      allowed_tool_identities={launcher.resolved_path: launcher.file_sha256},
                      artifact_root=Path(output_root) / "transports")
    if not result.ok or result.truncated or result.capture_failed:
        raise RuntimeError("WSL candidate staging transport did not complete with bounded full capture")
    def pairs(items):
        data = {}
        for key, value in items:
            if key in data:
                raise ValueError("duplicate WSL candidate transfer response key")
            data[key] = value
        return data
    response = json.loads(result.stdout_bytes(), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite transfer JSON")))
    receipt = CandidateTransferReceipt.model_validate(response)
    if (receipt.request_id, receipt.transfer_id, receipt.action_id, receipt.source_sha256, receipt.source_bytes) != (
            request_id, transfer_id, action_id, action.sha256, len(action.source)):
        raise ValueError("WSL transfer receipt does not bind the exact Windows source and task")
    if receipt.target_environment != "wsl:" + distro:
        raise ValueError("WSL candidate transfer receipt target is different from the selected distribution")
    folder = Path(output_root) / transfer_id
    folder.mkdir(parents=True, exist_ok=False)
    files = {"source.bin": action.source, "worker_response.bin": result.stdout_bytes(),
        "worker_stderr.bin": result.stderr_bytes(),
        "transfer_request.json": (encoded + "\n").encode("utf-8"),
        "transfer_receipt.json": (json.dumps(receipt.model_dump(mode="json"), ensure_ascii=False,
            sort_keys=True, indent=2) + "\n").encode("utf-8"),
        "windows_transport_result.json": (json.dumps(result.model_dump(mode="json"), ensure_ascii=False,
            sort_keys=True, indent=2) + "\n").encode("utf-8")}
    for name, raw in files.items():
        _write_new(folder / name, raw)
    manifest = {"schema_version": "1.0", "request_id": request_id, "transfer_id": transfer_id,
        "action_id": action_id, "source_sha256": action.sha256,
        "files": {name: {"size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                  for name, raw in sorted(files.items())},
        "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    manifest_raw = (json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    _write_new(folder / "manifest.json", manifest_raw)
    return {"receipt": receipt, "directory": str(folder), "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "source_sha256": action.sha256, "raw_transport": result}


def render_fixed_candidate_chain(*, receipt, execution, source_sha256, transfer_manifest_sha256):
    """Render the harmless chain while keeping legacy PoC execution state independent."""
    process = execution.get("process") or {}
    text = (process.get("stdout_b64") or "")
    try:
        stdout = base64.b64decode(text, validate=True).decode("utf-8", errors="replace")
    except Exception:
        stdout = "原始 stdout 不能在该投影视图中显示；请依据原始证据核验。"
    return "\n".join([
        "# Windows 到 WSL 固定无害候选链路报告", "", "报告语言：zh-CN。", "",
        "本记录测试的是注册表中的固定正常退出程序，不是 LLM 生成候选，也没有 CVE 目标。", "",
        f"| 请求 / 传输 ID | {receipt.request_id} / {receipt.transfer_id} |",
        f"| 注册动作 / 源码 SHA-256 | {receipt.action_id} / {source_sha256} |",
        f"| Windows→WSL 接收路径 | {receipt.target_environment}：`{receipt.staged_path}` |",
        f"| WSL 接收 PID / UID | {receipt.receiver_pid} / {receipt.receiver_uid} |",
        f"| 接收字节数 / 复核 | {receipt.source_bytes} / STAGED_AND_VERIFIED |",
        f"| 传输 manifest SHA-256 | {transfer_manifest_sha256} |",
        f"| 独立执行 run / 动作 | {execution.get('run_id')} / {execution.get('action_id')} |",
        f"| 远端执行状态 / PID / 退出码 / signal | {execution.get('remote_status')} / {process.get('pid')} / {process.get('returncode')} / {process.get('linux_signal')} |",
        f"| 进程回收 | {execution.get('cleanup_confirmation')} |",
        f"| 原始 stdout SHA-256 | {process.get('stdout_sha256')} |", "",
        "## 结论", "",
        "WSL 接收端重新核对传入字节与固定注册表 SHA-256 后，独立执行 run 使用同一注册动作完成受限正常退出。",
        "此固定动作的授权不能扩展到 `cuda_poc_v1.py` 或任意模型代码。",
        "本报告的固定动作是实际运行的 harmless fixture；项目候选执行状态仍为 NOT_EXECUTED，CVE 验证为 NOT_VERIFIED。",
        f"原始 stdout 的解码显示仅供阅读：`{stdout.strip()}`；原始字节保存在独立执行证据目录。", ""])


class CandidateExecutionAdapter:
    """Candidate intake plus one fixed harmless integration route; no generic PoC dispatch."""

    @staticmethod
    def inspect_generation_run(cve_id, generation_run_id, *, output_root=None):
        return load_generation_candidate(cve_id, generation_run_id, output_root=output_root)

    @staticmethod
    def assess_generated_candidate(candidate, target_description):
        return assess_candidate_admission(candidate, target_description)

    @staticmethod
    def run_registered_harmless_smoke(*, authorize_fixed_candidate=False, action_id="p2b-normal-v1",
            authorization_reference, operator_id, linux_project_root, output_root="data/outputs/p3d_r2_candidate_bridge",
            distro="Ubuntu-22.04", user="pocdev", linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python"):
        if authorize_fixed_candidate is not True:
            raise ValueError("explicit operator authorization for the fixed harmless candidate smoke is required")
        from .lifecycle_cli import run_authorized_action
        transfer = transfer_registered_candidate_wsl(action_id=action_id, linux_project_root=linux_project_root,
            output_root=Path(output_root) / "transfers", distro=distro, user=user, linux_python=linux_python)
        receipt = transfer["receipt"]
        execution = run_authorized_action(authorize_fixed_actions=True, action_id=action_id,
            authorization_reference=authorization_reference, operator_id=operator_id,
            linux_project_root=linux_project_root, distro=distro, user=user, linux_python=linux_python,
            output_root=Path(output_root) / "executions")
        execution_folder = Path(execution["evidence_directory"])
        execution_record = json.loads((execution_folder / "execution_record.json").read_text(encoding="utf-8"))
        process = execution_record.get("process") or {}
        if (execution_record.get("action_id") != receipt.action_id
                or execution_record.get("candidate_sha256") != receipt.source_sha256
                or not process.get("action_started") or process.get("cleanup", {}).get("status") != "CONFIRMED"):
            raise ValueError("fixed execution run does not match the staged harmless candidate source")
        link = {"schema_version": "1.0", "transfer_id": receipt.transfer_id, "transfer_request_id": receipt.request_id,
            "transfer_manifest_sha256": transfer["manifest_sha256"], "action_id": receipt.action_id,
            "source_sha256": receipt.source_sha256, "execution_request_id": execution["request_id"],
            "execution_run_id": execution["run_id"], "execution_evidence_directory": str(execution_folder),
            "execution_status": execution["remote_state"], "cleanup_confirmation": execution["cleanup_confirmation"],
            "process": process, "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
        chain_id = uuid.uuid4().hex
        chain_folder = Path(output_root) / "chains" / chain_id
        chain_folder.mkdir(parents=True, exist_ok=False)
        link_raw = (json.dumps(link, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        link_path = chain_folder / "execution_link.json"
        _write_new(link_path, link_raw)
        report_raw = render_fixed_candidate_chain(receipt=receipt,
            execution={**execution, "remote_status": execution["remote_state"], "process": process},
            source_sha256=receipt.source_sha256, transfer_manifest_sha256=transfer["manifest_sha256"]).encode("utf-8")
        report_path = chain_folder / "report.zh-CN.md"
        _write_new(report_path, report_raw)
        chain_manifest = {"schema_version": "1.0", "chain_id": chain_id, "transfer_id": receipt.transfer_id,
            "transfer_manifest_sha256": transfer["manifest_sha256"],
            "execution_request_id": execution["request_id"], "execution_run_id": execution["run_id"],
            "action_id": receipt.action_id, "source_sha256": receipt.source_sha256,
            "files": {name: {"size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                      for name, raw in sorted({"execution_link.json": link_raw, "report.zh-CN.md": report_raw}.items())},
            "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
        manifest_raw = (json.dumps(chain_manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        _write_new(chain_folder / "manifest.json", manifest_raw)
        return {"chain_id": chain_id, "chain_directory": str(chain_folder), "transfer_id": receipt.transfer_id,
            "transfer_directory": transfer["directory"],
            "execution_request_id": execution["request_id"], "execution_run_id": execution["run_id"],
            "execution_evidence_directory": str(execution_folder), "execution_status": execution["remote_state"],
            "cleanup_confirmation": execution["cleanup_confirmation"], "source_sha256": receipt.source_sha256,
            "report": str(report_path), "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
