"""Windows controller for the exact received P2-B harmless normal fixture.

No caller can supply source code or argv.  The separately operated authorization
is limited to the already reviewed source and a fresh, measured WSL destination.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
from typing import Literal

from pydantic import Field, model_validator

from .artifact_packaging import _read, _regular_path, _write_new
from .candidate_adapter import CandidateTransferReceipt, transfer_registered_candidate_wsl
from .execution_bridge import _linux_root, build_execution_worker_source
from .lifecycle_bridge import TaskHandle, WorkerIdentity
from .models.execution import ExecutionResourceLimits
from .models.lifecycle import LifecycleContract, RemoteRecoveryCheck, canonical_sha256
from .models.staged_fixture import (StagedFixtureAuthorization, StagedFixtureDescription,
    StagedFixturePolicy, StagedFixtureRecord, StagedFixtureRequest, validate_staged_binding)
from .models.tool_result import ToolResult
from .probe_artifacts import protect_directory
from .registered_actions import get_registered_action
from .tool_artifacts import ToolEvidenceError
from .tools.process import measure_tool_identity, run_tool
from .wsl_bridge import validate_wsl_options


class StagedFixturePacket(LifecycleContract):
    schema_version: Literal["1.0"]
    operation: Literal["DESCRIBE", "EXECUTE", "STATUS", "CANCEL"]
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    target_environment: str
    worker_identity: WorkerIdentity
    status: str
    description: StagedFixtureDescription | None
    record: StagedFixtureRecord | None
    recovery: RemoteRecoveryCheck | None
    raw_files: dict[str, str]
    diagnostics: list[str]

    @model_validator(mode="after")
    def identities(self):
        if self.description is not None and (self.operation != "DESCRIBE" or self.record is not None
                or self.description.target_environment != self.target_environment
                or self.status != self.description.status):
            raise ValueError("description disagrees with operation or target")
        if self.record is not None:
            if (self.record.request_id, self.record.run_id, self.record.target_environment) != (
                    self.request_id, self.run_id, self.target_environment):
                raise ValueError("record belongs to a different request, run or WSL target")
            if self.operation == "EXECUTE" and (self.record.worker_identity != self.worker_identity.model_dump(mode="json")
                    or self.status != self.record.status):
                raise ValueError("execution record differs from responding worker")
        elif self.raw_files:
            raise ValueError("raw files require their corresponding fixed staged record")
        if self.recovery is not None and (self.operation not in {"STATUS", "CANCEL"}
                or (self.recovery.request_id, self.recovery.run_id) != (self.request_id, self.run_id)
                or (self.recovery.observer_pid, self.recovery.observer_uid) != (
                    self.worker_identity.pid, self.worker_identity.uid)
                or self.status != self.recovery.status):
            raise ValueError("independent recovery observer identity conflict")
        return self


def _json(value):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _strict_json(raw):
    if type(raw) is not bytes or len(raw) > 16777216:
        raise ValueError("fixed staged protocol result has invalid byte length")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate fixed staged protocol field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite protocol number")))


def parse_staged_packet(raw, *, operation, nonce, request_id, run_id, target_environment,
                        request=None, authorization=None, policy=None, description=None):
    packet = StagedFixturePacket.model_validate(_strict_json(raw))
    if (packet.operation, packet.nonce, packet.request_id, packet.run_id, packet.target_environment) != (
            operation, nonce, request_id, run_id, target_environment):
        raise ValueError("fixed staged response changed operation, nonce, request, run or target")
    if packet.record is not None:
        if request is None or policy is None or description is None:
            raise ValueError("execution record requires independently retained contracts")
        validate_staged_binding(packet.record, request, authorization, policy, description)
        if set(packet.raw_files) != set(packet.record.artifacts):
            raise ValueError("raw fixed staged evidence set differs from record")
        for name, artifact in packet.record.artifacts.items():
            raw_file = base64.b64decode(packet.raw_files[name], validate=True)
            if len(raw_file) != artifact.size_bytes or hashlib.sha256(raw_file).hexdigest() != artifact.sha256:
                raise ValueError("raw fixed staged evidence differs from measured bytes")
    return packet


def _handle(linux_project_root, distro, user, linux_python):
    validate_wsl_options(distro, linux_python, user)
    return TaskHandle(request_id=uuid.uuid4().hex, run_id=uuid.uuid4().hex,
        control_token=uuid.uuid4().hex + uuid.uuid4().hex, distro=distro, user=user,
        linux_python=linux_python, linux_project_root=_linux_root(linux_project_root))


def _envelope(operation, handle, *, receipt=None, receipt_sha256=None,
              request=None, authorization=None, policy=None, description=None):
    return {"schema_version": "1.0", "operation": operation, "nonce": uuid.uuid4().hex,
        "request_id": handle.request_id, "run_id": handle.run_id, "control_token": handle.control_token,
        "receipt": None if receipt is None else receipt.model_dump(mode="json"),
        "receipt_sha256": receipt_sha256,
        "request": None if request is None else request.model_dump(mode="json"),
        "authorization": None if authorization is None else authorization.model_dump(mode="json"),
        "policy": None if policy is None else policy.model_dump(mode="json"),
        "description": None if description is None else description.model_dump(mode="json")}


def _transport(payload, handle, *, artifact_root, request=None, authorization=None, policy=None, description=None):
    if os.name != "nt":
        raise ValueError("fixed staged transfer controller must be started by Windows Python")
    launcher = measure_tool_identity("wsl.exe", source="fixed staged Windows launcher byte identity")
    if launcher.status != "OBSERVED":
        raise ValueError("Windows WSL launcher identity is unavailable; fixed task cannot start")
    bootstrap = build_execution_worker_source(payload, linux_project_root=handle.linux_project_root,
        worker_entrypoint="staged_fixture")
    diagnostics = []
    try:
        result = run_tool([launcher.resolved_path, "--distribution", handle.distro,
            "--user", handle.user, "--exec", handle.linux_python, "-I", "-"],
            timeout_seconds=90 if payload["operation"] == "EXECUTE" else 60 if payload["operation"] == "DESCRIBE" else 30,
            max_output_bytes=16777216, input_bytes=bootstrap, artifact_root=artifact_root,
            allowed_tool_identities={launcher.resolved_path: launcher.file_sha256},
            command_source="reviewed fixed staged harmless " + payload["operation"])
    except ToolEvidenceError as exc:
        if exc.tool_result is None:
            raise
        result = ToolResult.model_validate(exc.tool_result.model_dump(mode="python"))
        diagnostics.append("WINDOWS_TRANSPORT_EVIDENCE_WRITE_FAILED")
    packet = None
    if result.ok and not result.truncated and not result.capture_failed:
        try:
            packet = parse_staged_packet(result.stdout_bytes(), operation=payload["operation"],
                nonce=payload["nonce"], request_id=handle.request_id, run_id=handle.run_id,
                target_environment="wsl:" + handle.distro,
                request=request, authorization=authorization, policy=policy, description=description)
        except (ValueError, TypeError, KeyError) as exc:
            diagnostics.append("STAGED_PROTOCOL_REJECTED:" + type(exc).__name__ + ":" + str(exc))
    else:
        diagnostics.append("WINDOWS_WSL_LAUNCHER_" + result.end_status)
    return result, packet, diagnostics


def build_staged_fixture_context(description, *, authorize_fixed_fixture=False, operator_id,
                                 authorization_reference, request_id=None, run_id=None,
                                 resource_limits=None):
    if authorize_fixed_fixture is not True:
        raise ValueError("固定无害文件执行需要独立操作员授权")
    for value, maximum in ((operator_id, 128), (authorization_reference, 256)):
        if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(
                character in value for character in "\0\r\n"):
            raise ValueError("操作员和授权编号必须是受限长度的非空单行标识")
    desc = StagedFixtureDescription.model_validate(description)
    if desc.status != "DESCRIBED" or desc.snapshot is None or desc.source_identity is None or desc.tool_identity is None:
        raise ValueError("目标描述未完整实测，不能授权执行")
    limits = ExecutionResourceLimits.model_validate(resource_limits or dict(
        wall_time_seconds=10.0, cpu_seconds=2, memory_bytes=268435456, max_output_bytes=65536))
    req = StagedFixtureRequest(request_id=request_id or uuid.uuid4().hex, run_id=run_id or uuid.uuid4().hex,
        transfer_id=desc.receipt.transfer_id, transfer_request_id=desc.receipt.request_id,
        receipt_sha256=desc.source_identity.receipt_sha256, source_identity=desc.source_identity,
        description_sha256=canonical_sha256(desc), platform_environment_id=desc.snapshot.environment_id,
        platform_probe_id=desc.snapshot.metadata["probe_id"], snapshot_sha256=canonical_sha256(desc.snapshot),
        target_environment=desc.target_environment, target_boot_id=desc.target_boot_id,
        observed_monotonic_ns=desc.observed_monotonic_ns, tool_identity=desc.tool_identity,
        resource_limits=limits, authorization_reference=authorization_reference)
    auth = StagedFixtureAuthorization(request_id=req.request_id, run_id=req.run_id,
        transfer_id=req.transfer_id, receipt_sha256=req.receipt_sha256,
        source_sha256=req.source_identity.source_sha256, request_sha256=canonical_sha256(req),
        operator_id=operator_id, authorization_reference=authorization_reference,
        issuer_kind="operator", target_boot_id=desc.target_boot_id,
        not_before_monotonic_ns=desc.observed_monotonic_ns,
        expires_monotonic_ns=desc.observed_monotonic_ns + 300000000000)
    policy = StagedFixturePolicy(request_sha256=canonical_sha256(req),
        description_sha256=canonical_sha256(desc), allowed_operator_ids=[operator_id],
        allowed_authorization_references=[authorization_reference],
        allowed_tool_path=desc.tool_identity.resolved_path,
        allowed_tool_sha256=desc.tool_identity.file_sha256,
        native_task_root=desc.native_task_root, transfer_id=req.transfer_id,
        receipt_sha256=req.receipt_sha256, source_sha256=req.source_identity.source_sha256,
        resource_limits=limits)
    return req, auth, policy


def render_staged_fixture_report(result, record=None, recovery=None):
    """Deterministic UTF-8 Chinese projection; never an LLM scientific claim."""
    result = dict(result)
    state = result["status"]
    process = None if record is None else record.process
    reason = "已核对收到的固定文件、授权、资源约束、真实退出和独立回收。" if state == "COMPLETED" else (
        "未取得完整的远端执行与回收证据；保留失败或未知状态。")
    if state == "REJECTED":
        reason = "前置身份或授权检查拒绝，本轮没有放行固定文件。"
    lines = ["# Windows→WSL 固定无害文件执行报告", "", "报告语言：zh-CN。", "",
        "本报告仅对应已审核的 p2b-normal-v1 CPU fixture，不属于任何 CVE 漏洞复现。", "",
        "| 项目 | 观测值 |", "|---|---|",
        f"| request_id / run_id | {result['request_id']} / {result['run_id']} |",
        f"| 传输 ID / 接收文件 SHA-256 | {result.get('transfer_id') or '未取得'} / {result.get('source_sha256') or '未取得'} |",
        f"| 目标环境 / 工具 SHA-256 | {result.get('target_environment') or '未取得'} / {result.get('tool_sha256') or '未取得'} |",
        f"| 操作员授权引用 | {result.get('authorization_reference') or '未取得'} |",
        f"| 执行状态 / 独立回收 | {state} / {result.get('cleanup_status') or 'UNKNOWN'} |",
        f"| 实际 PID / 退出码 / Linux signal | {None if process is None else process.pid} / {None if process is None else process.returncode} / {None if process is None else process.linux_signal} |",
        f"| 超时 / 截断 / 采集失败 | {None if process is None else process.timed_out} / {None if process is None else process.truncated} / {None if process is None else process.capture_failed} |",
        f"| 固定文件实际执行 / PoC 候选执行 / 漏洞验证 | {result.get('fixed_source_execution_status', 'NOT_EXECUTED')} / NOT_EXECUTED / NOT_VERIFIED |",
        f"| 本地证据清单 SHA-256 | {result.get('manifest_sha256') or '未取得'} |", "",
        "## 判定和缺失证据", "", reason,
        "", "原始 stdout/stderr 保持字节原貌；若有执行进程，清单逐项列出其 SHA-256 与字节数。", "",
        "普通退出码 0 只能说明固定无害任务结束，不能证明目标 CVE。",
        "未知 LLM 代码未执行，真实 PoC 候选执行状态为 NOT_EXECUTED；目标漏洞验证状态为 NOT_VERIFIED。", ""]
    for item in result.get("diagnostics", []):
        lines.insert(-1, "诊断：" + str(item).replace("\n", " ").replace("\r", " "))
    return "\n".join(lines)


def run_staged_fixture_wsl(*, authorize_fixed_fixture=False, operator_id,
                           authorization_reference, linux_project_root,
                           distro="Ubuntu-22.04", user="pocdev",
                           linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python",
                           output_root="data/outputs/fixed_staged_fixture",
                           transfer_output_root="data/outputs/candidate_transfers", resource_limits=None):
    """Transfer, independently authorize, execute exact received bytes, then recheck."""
    if authorize_fixed_fixture is not True:
        raise ValueError("固定无害文件执行未获明确授权")
    if os.name != "nt":
        raise ValueError("Windows→WSL fixed staged task requires Windows Python")
    handle = _handle(linux_project_root, distro, user, linux_python)
    root = _regular_path(output_root)
    if any(re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", part, re.IGNORECASE) for part in root.parts):
        raise ValueError("固定无害任务不得归档到真实 CVE 目录")
    session = root / handle.run_id
    protection = protect_directory(session)
    _write_new(session / "task_handle.private.json", _json(handle))
    _write_new(session / "access_control.json", _json(protection))
    diagnostics = []
    observations = {}
    transfer = desc = req = auth = policy = None
    record = recovery = None
    status = "UNKNOWN"
    receipt_sha = None

    def observe(operation):
        payload = _envelope(operation, handle,
            receipt=None if operation != "DESCRIBE" else transfer["receipt"],
            receipt_sha256=None if operation != "DESCRIBE" else receipt_sha,
            request=req if operation == "EXECUTE" else None,
            authorization=auth if operation == "EXECUTE" else None,
            policy=policy if operation == "EXECUTE" else None,
            description=desc if operation == "EXECUTE" else None)
        try:
            transport, packet, notes = _transport(payload, handle, artifact_root=session / "transports",
                request=req, authorization=auth, policy=policy, description=desc)
        except (OSError, ValueError) as exc:
            transport, packet, notes = None, None, ["WSL_OBSERVER_FAILURE:" + type(exc).__name__ + ":" + str(exc)]
        observation = {"transport": None if transport is None else transport.model_dump(mode="json"),
            "packet": None if packet is None else packet.model_dump(mode="json"), "diagnostics": notes}
        observations[operation] = observation
        diagnostics.extend(notes)
        _write_new(session / (operation.lower() + ".json"), _json(observation))
        return packet

    try:
        transfer = transfer_registered_candidate_wsl(action_id="p2b-normal-v1",
            linux_project_root=linux_project_root, output_root=transfer_output_root,
            distro=distro, user=user, linux_python=linux_python)
        transfer_root = _regular_path(transfer["directory"])
        receipt_raw = _read(transfer_root / "transfer_receipt.json", 65536)
        source_raw = _read(transfer_root / "source.bin", 1048576)
        if (hashlib.sha256(source_raw).hexdigest() != get_registered_action("p2b-normal-v1").sha256
                or _strict_json(receipt_raw) != transfer["receipt"].model_dump(mode="json")):
            raise ValueError("fixed transfer retained source or receipt differs from exact registry bytes")
        receipt_sha = hashlib.sha256(receipt_raw).hexdigest()
        _write_new(session / "transfer_receipt.json", receipt_raw)
        _write_new(session / "source.bin", source_raw)
        _write_new(session / "transfer_pin.json", _json({"transfer_id": transfer["receipt"].transfer_id,
            "transfer_manifest_sha256": transfer["manifest_sha256"], "receipt_sha256": receipt_sha,
            "source_sha256": hashlib.sha256(source_raw).hexdigest()}))
        described = observe("DESCRIBE")
        if described is None or described.description is None:
            diagnostics.append("STAGED_DESCRIPTION_MISSING")
        else:
            desc = described.description
            if desc.status != "DESCRIBED" or desc.source_identity is None or desc.source_identity.receipt_sha256 != receipt_sha:
                status = desc.status
                diagnostics.extend(desc.diagnostics)
            else:
                req, auth, policy = build_staged_fixture_context(desc, authorize_fixed_fixture=True,
                    operator_id=operator_id, authorization_reference=authorization_reference,
                    request_id=handle.request_id, run_id=handle.run_id, resource_limits=resource_limits)
                for name, value in (("description", desc), ("request", req),
                                    ("authorization", auth), ("policy", policy)):
                    _write_new(session / (name + ".json"), _json(value))
                executed = observe("EXECUTE")
                if executed is None:
                    observe("CANCEL")
                recovered = observe("STATUS")
                packet = executed if executed is not None and executed.record is not None else recovered
                record = None if packet is None else packet.record
                recovery = None if recovered is None else recovered.recovery
                if record is not None:
                    if recovery is None:
                        status = "UNKNOWN"
                        diagnostics.append("INDEPENDENT_WSL_CLEANUP_MISSING")
                    elif recovery.status == "FAILED":
                        status = "CLEANUP_FAILED"
                    elif recovery.status == "UNKNOWN":
                        status = "UNKNOWN"
                    else:
                        status = record.status
                    raw_files = {name: base64.b64decode(value, validate=True)
                                 for name, value in packet.raw_files.items()}
                    evidence_dir = session / "raw"
                    evidence_dir.mkdir(mode=0o700, exist_ok=False)
                    for name, value in raw_files.items():
                        _write_new(evidence_dir / name, value)
                else:
                    diagnostics.append("WSL_EXECUTION_RECORD_MISSING")
    except (OSError, ValueError, KeyError) as exc:
        diagnostics.append("FIXED_STAGED_CONTROLLER_ERROR:" + type(exc).__name__ + ":" + str(exc))
    files = {}
    for path in sorted(session.iterdir()):
        if path.is_file() and path.name not in {"task_handle.private.json"}:
            raw = _read(path, 16777216)
            files[path.name] = {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}
    raw_dir = session / "raw"
    if raw_dir.exists():
        for path in sorted(raw_dir.iterdir()):
            raw = _read(path, 4194304)
            files["raw/" + path.name] = {"sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}
    manifest = {"schema_version": "staged-harmless-1.0", "request_id": handle.request_id,
        "run_id": handle.run_id, "transfer_id": None if transfer is None else transfer["receipt"].transfer_id,
        "record_sha256": None if record is None else canonical_sha256(record),
        "status": status, "cleanup_status": None if recovery is None else recovery.status,
        "files": files, "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    manifest_raw = _json(manifest)
    _write_new(session / "evidence_manifest.json", manifest_raw)
    manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
    result = {"schema_version": "staged-harmless-controller-1.0", "report_locale": "zh-CN",
        "cve_id": None, "request_id": handle.request_id, "run_id": handle.run_id,
        "transfer_id": None if transfer is None else transfer["receipt"].transfer_id,
        "source_sha256": None if req is None else req.source_identity.source_sha256,
        "target_environment": None if req is None else req.target_environment,
        "tool_sha256": None if req is None else req.tool_identity.file_sha256,
        "authorization_reference": None if auth is None else auth.authorization_reference,
        "status": status, "cleanup_status": None if recovery is None else recovery.status,
        "fixed_source_execution_status": "NOT_EXECUTED" if record is None else record.fixed_source_execution_status,
        "manifest_sha256": manifest_sha, "evidence_dir": str(session), "diagnostics": diagnostics,
        "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    _write_new(session / "controller_result.json", _json(result))
    report = render_staged_fixture_report(result, record, recovery)
    _write_new(session / "report.zh-CN.md", report.encode("utf-8"))
    result["report_path"] = str(session / "report.zh-CN.md")
    result["record"] = None if record is None else record.model_dump(mode="json")
    result["recovery"] = None if recovery is None else recovery.model_dump(mode="json")
    return result


def evaluate_staged_fixture_archive(path):
    """Reopen local raw files and rebuild the Chinese report byte for byte."""
    root = _regular_path(path)
    manifest_raw = _read(root / "evidence_manifest.json", 1048576)
    manifest = _strict_json(manifest_raw)
    result = _strict_json(_read(root / "controller_result.json", 1048576))
    if (manifest.get("schema_version") != "staged-harmless-1.0"
            or result.get("manifest_sha256") != hashlib.sha256(manifest_raw).hexdigest()
            or (manifest.get("request_id"), manifest.get("run_id"), manifest.get("status")) != (
                result.get("request_id"), result.get("run_id"), result.get("status"))):
        raise ValueError("fixed staged manifest and controller identity conflict")
    for name, item in manifest["files"].items():
        if (not isinstance(name, str) or name.startswith("/") or "\\" in name
                or ".." in Path(name).parts or len(Path(name).parts) > 2):
            raise ValueError("unsafe fixed staged artifact path")
        raw = _read(root / name, 16777216)
        if len(raw) != item["size_bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("fixed staged raw artifact was removed or modified")
    record = recovery = None
    execute_record = status_record = None
    execution_path = root / "execute.json"
    if execution_path.exists():
        executed = _strict_json(_read(execution_path, 16777216))
        packet = executed.get("packet")
        if packet is not None and packet.get("record") is not None:
            execute_record = StagedFixtureRecord.model_validate(packet["record"])
    status_path = root / "status.json"
    if status_path.exists():
        observed = _strict_json(_read(status_path, 16777216))
        packet = observed.get("packet")
        if packet is not None and packet.get("recovery") is not None:
            recovery = RemoteRecoveryCheck.model_validate(packet["recovery"])
            if packet.get("record") is not None:
                status_record = StagedFixtureRecord.model_validate(packet["record"])
    if (execute_record is not None and status_record is not None
            and canonical_sha256(execute_record) != canonical_sha256(status_record)):
        raise ValueError("EXECUTE and STATUS returned different fixed staged records")
    record = execute_record or status_record
    if record is not None:
        req = StagedFixtureRequest.model_validate(_strict_json(_read(root / "request.json")))
        auth_raw = _strict_json(_read(root / "authorization.json"))
        auth = None if auth_raw is None else StagedFixtureAuthorization.model_validate(auth_raw)
        policy = StagedFixturePolicy.model_validate(_strict_json(_read(root / "policy.json")))
        desc = StagedFixtureDescription.model_validate(_strict_json(_read(root / "description.json")))
        validate_staged_binding(record, req, auth, policy, desc)
        if (record.request_id, record.run_id) != (result["request_id"], result["run_id"]):
            raise ValueError("archived record belongs to another run")
        raw_source = _read(root / "source.bin", 1048576)
        receipt_raw = _read(root / "transfer_receipt.json", 65536)
        receipt = CandidateTransferReceipt.model_validate(_strict_json(receipt_raw))
        if (hashlib.sha256(raw_source).hexdigest() != req.source_identity.source_sha256
                or hashlib.sha256(receipt_raw).hexdigest() != req.receipt_sha256
                or receipt != desc.receipt):
            raise ValueError("archived transfer bytes differ from execution request")
        if manifest.get("record_sha256") != canonical_sha256(record):
            raise ValueError("record digest in evidence manifest changed")
        for name, artifact in record.artifacts.items():
            raw = _read(root / "raw" / name, 4194304)
            if len(raw) != artifact.size_bytes or hashlib.sha256(raw).hexdigest() != artifact.sha256:
                raise ValueError("execution raw file differs from worker artifact")
        if recovery is None or (recovery.request_id, recovery.run_id) != (record.request_id, record.run_id):
            raise ValueError("independent cleanup observation missing or crossed runs")
        effective = ("UNKNOWN" if recovery.status == "UNKNOWN" else
            "CLEANUP_FAILED" if recovery.status == "FAILED" else record.status)
        if (result.get("status") != effective or manifest.get("status") != effective
                or result.get("cleanup_status") != recovery.status
                or manifest.get("cleanup_status") != recovery.status
                or result.get("transfer_id") != record.transfer_id
                or manifest.get("transfer_id") != record.transfer_id
                or result.get("source_sha256") != record.source_identity.source_sha256
                or result.get("target_environment") != record.target_environment
                or result.get("tool_sha256") != record.tool_identity.file_sha256
                or result.get("authorization_reference") != (
                    None if auth is None else auth.authorization_reference)
                or result.get("fixed_source_execution_status") != record.fixed_source_execution_status
                or result.get("candidate_execution_status") != "NOT_EXECUTED"
                or result.get("verification_status") != "NOT_VERIFIED"):
            raise ValueError("controller conclusion disagrees with execution and independent cleanup evidence")
    elif (result.get("status") in {"COMPLETED", "NONZERO_EXIT", "TIMED_OUT", "CANCELLED", "RESOURCE_LIMIT"}
            or result.get("fixed_source_execution_status") != "NOT_EXECUTED"
            or result.get("candidate_execution_status") != "NOT_EXECUTED"
            or result.get("verification_status") != "NOT_VERIFIED"
            or manifest.get("record_sha256") is not None):
        raise ValueError("missing execution record cannot support the reported result")
    rebuilt = render_staged_fixture_report(result, record, recovery).encode("utf-8")
    if _read(root / "report.zh-CN.md", 1048576) != rebuilt:
        raise ValueError("Chinese fixed staged report cannot be reconstructed byte for byte")
    return {"integrity_status": "VERIFIED" if record is not None else "INCOMPLETE",
        "status": result["status"], "request_id": result["request_id"], "run_id": result["run_id"],
        "record": None if record is None else record.model_dump(mode="json"),
        "manifest_sha256": result["manifest_sha256"],
        "report_sha256": hashlib.sha256(rebuilt).hexdigest()}
