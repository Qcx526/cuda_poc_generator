"""Trusted Windows controller for two reviewed no-CVE Memcheck fixtures.

The public dispatcher accepts an explicit operator authorization, never argv,
candidate source, a shell command, or an LLM-produced authorization object.
Each transport and independent cleanup observation is retained separately.
"""

import base64
import json
import os
from pathlib import Path
import re
import uuid
from typing import Literal

from pydantic import Field, model_validator

from .artifact_packaging import _regular_path, _strict_json, _write_new
from .execution_bridge import _linux_root, build_execution_worker_source
from .lifecycle_bridge import TaskHandle, WorkerIdentity
from .memcheck_evidence import (parse_memcheck_evidence, read_memcheck_evidence,
                                 save_memcheck_evidence)
from .memcheck_registry import fixed_source, get_memcheck_task
from .models.lifecycle import LifecycleContract, RemoteRecoveryCheck, canonical_sha256
from .models.memcheck import (MemcheckAuthorization, MemcheckDescription, MemcheckExecutionRecord,
                               MemcheckPolicy, MemcheckRequest, MemcheckResourceLimits,
                               validate_memcheck_binding)
from .models.tool_result import ToolResult, digest_bytes
from .probe_artifacts import protect_directory
from .tool_artifacts import ToolEvidenceError
from .tools.process import measure_tool_identity, run_tool
from .wsl_bridge import validate_wsl_options


class MemcheckPacket(LifecycleContract):
    schema_version: Literal["1.0"]
    operation: Literal["DESCRIBE", "EXECUTE", "STATUS", "CANCEL"]
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    target_environment: str
    worker_identity: WorkerIdentity
    status: str
    description: MemcheckDescription | None
    record: MemcheckExecutionRecord | None
    recovery: RemoteRecoveryCheck | None
    raw_files: dict[str, str]
    diagnostics: list[str]

    @model_validator(mode="after")
    def identities(self):
        if self.description is not None and (self.operation != "DESCRIBE" or self.record is not None
                or self.description.target_environment != self.target_environment or self.status != self.description.status):
            raise ValueError("诊断描述的操作或目标环境冲突")
        if self.record is not None:
            if (self.record.request_id, self.record.run_id, self.record.target_environment) != (
                    self.request_id, self.run_id, self.target_environment):
                raise ValueError("诊断执行记录发生跨请求、run 或平台混淆")
            if self.operation == "EXECUTE" and self.record.worker_identity != self.worker_identity.model_dump(mode="json"):
                raise ValueError("执行记录的 worker 身份与实际通信端不同")
            if self.operation == "EXECUTE" and self.status != self.record.status:
                raise ValueError("通信状态与原始执行记录状态不同")
        elif self.raw_files:
            raise ValueError("没有执行记录不能传送伪造的原始文件")
        if self.recovery is not None and (self.operation not in {"STATUS", "CANCEL"}
                or (self.recovery.request_id, self.recovery.run_id) != (self.request_id, self.run_id)
                or (self.recovery.observer_pid, self.recovery.observer_uid) != (
                    self.worker_identity.pid, self.worker_identity.uid)):
            raise ValueError("独立回收记录与实际控制进程或任务不同")
        if self.recovery is not None and self.status != self.recovery.status:
            raise ValueError("回收通信状态与独立观察不同")
        return self


def _json(value):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _windows_host():
    return os.name == "nt"


def _collector_sha256():
    return digest_bytes(Path(__file__).with_name("memcheck_sandbox.py").read_bytes())


def _operator_scope(operator_id, authorization_reference):
    for value, maximum in ((operator_id, 128), (authorization_reference, 256)):
        if (not isinstance(value, str) or not value.strip() or len(value) > maximum
                or any(char in value for char in "\0\r\n")):
            raise ValueError("操作者身份与授权引用必须是受限长度的非空单行标识")


def parse_memcheck_packet(raw, *, operation, nonce, request_id, run_id, target_environment,
                          expected_request=None, authorization=None, policy=None):
    """Strict, duplicate-safe packet decoding, independently bound to host intent."""
    if type(raw) is not bytes or len(raw) > 16777216:
        raise ValueError("Memcheck 通信结果长度不合法")
    packet = MemcheckPacket.model_validate(_strict_json(raw))
    if (packet.operation, packet.nonce, packet.request_id, packet.run_id, packet.target_environment) != (
            operation, nonce, request_id, run_id, target_environment):
        raise ValueError("Memcheck 通信的操作、nonce、request/run 或目标身份不一致")
    if packet.description is not None and packet.description.collector_sha256 != _collector_sha256():
        raise ValueError("WSL 采集器源码身份与当前受信 Windows checkout 不一致")
    if packet.record is not None:
        if expected_request is None or authorization is None or policy is None:
            raise ValueError("执行记录需要独立提供原始请求、授权与策略")
        validate_memcheck_binding(packet.record, expected_request, authorization, policy)
        if set(packet.raw_files) != set(packet.record.artifacts):
            raise ValueError("传送原始文件集合与执行端记录不一致")
        for name, item in packet.record.artifacts.items():
            data = base64.b64decode(packet.raw_files[name], validate=True)
            if len(data) != item.size_bytes or digest_bytes(data) != item.sha256:
                raise ValueError("传送原始文件与采集端 SHA-256 不同")
    return packet


def _envelope(operation, handle, *, request=None, authorization=None, policy=None, description=None):
    return {"schema_version": "1.0", "operation": operation, "nonce": uuid.uuid4().hex,
        "request_id": handle.request_id, "run_id": handle.run_id, "control_token": handle.control_token,
        "request": None if request is None else request.model_dump(mode="json"),
        "authorization": None if authorization is None else authorization.model_dump(mode="json"),
        "policy": None if policy is None else policy.model_dump(mode="json"),
        "description": None if description is None else description.model_dump(mode="json")}


def _transport(payload, handle, *, artifact_root, request=None, authorization=None, policy=None):
    validate_wsl_options(handle.distro, handle.linux_python, handle.user)
    root = _linux_root(handle.linux_project_root)
    if not _windows_host():
        raise ValueError("固定 Memcheck 自动调度必须从 Windows Python 发起")
    launcher = measure_tool_identity("wsl.exe", source="fixed Memcheck Windows launcher byte measurement")
    source = build_execution_worker_source(payload, linux_project_root=root, worker_entrypoint="memcheck")
    diagnostics = []
    try:
        transport = run_tool([launcher.resolved_path or "wsl.exe", "--distribution", handle.distro,
            "--user", handle.user, "--exec", handle.linux_python, "-I", "-"],
            timeout_seconds=150 if payload["operation"] == "EXECUTE" else 90 if payload["operation"] == "DESCRIBE" else 30,
            max_output_bytes=16777216, input_bytes=source, artifact_root=artifact_root,
            allowed_tool_identities={} if launcher.status != "OBSERVED" else {launcher.resolved_path: launcher.file_sha256},
            command_source="registered fixed Memcheck " + payload["operation"] + "; no candidate dispatch")
    except ToolEvidenceError as exc:
        if exc.tool_result is None:
            raise
        transport = ToolResult.model_validate(exc.tool_result.model_dump(mode="python"))
        diagnostics.append("WINDOWS_TRANSPORT_EVIDENCE_WRITE_FAILED")
    packet = None
    if transport.ok:
        try:
            packet = parse_memcheck_packet(transport.stdout_bytes(), operation=payload["operation"],
                nonce=payload["nonce"], request_id=handle.request_id, run_id=handle.run_id,
                target_environment="wsl:" + handle.distro, expected_request=request,
                authorization=authorization, policy=policy)
        except (ValueError, TypeError, KeyError) as exc:
            diagnostics.append("MEMCHECK_PROTOCOL_REJECTED:" + type(exc).__name__ + ":" + str(exc))
    else:
        diagnostics.append("WINDOWS_WSL_LAUNCHER_" + transport.end_status)
    return transport, packet, diagnostics


def _new_handle(*, distro, user, linux_python, linux_project_root, request_id=None, run_id=None):
    validate_wsl_options(distro, linux_python, user)
    root = _linux_root(linux_project_root)
    return TaskHandle(request_id=request_id or uuid.uuid4().hex, run_id=run_id or uuid.uuid4().hex,
        control_token=uuid.uuid4().hex + uuid.uuid4().hex, distro=distro, user=user,
        linux_python=linux_python, linux_project_root=root)


def describe_fixed_memcheck_wsl(*, linux_project_root, distro="Ubuntu-22.04", user="pocdev",
        linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python", artifact_root=None):
    """Read-only measured tool/platform description; grants no execution authority."""
    handle = _new_handle(distro=distro, user=user, linux_python=linux_python, linux_project_root=linux_project_root)
    return _transport(_envelope("DESCRIBE", handle), handle, artifact_root=artifact_root)


def build_fixed_memcheck_context(description, task_id, *, authorize_fixed_memcheck=False, operator_id,
        authorization_reference, request_id=None, run_id=None, resource_limits=None):
    """Trusted operator boundary: never invoke from untrusted LLM request text."""
    if authorize_fixed_memcheck is not True:
        raise ValueError("固定无害 Memcheck 诊断需要操作者明确授权")
    _operator_scope(operator_id, authorization_reference)
    task = get_memcheck_task(task_id)
    fixed_source(task_id)
    desc = MemcheckDescription.model_validate(description)
    if desc.status != "DESCRIBED" or desc.snapshot is None:
        raise ValueError("工具和平台身份尚未取得完整实测，不能授权执行")
    if desc.collector_sha256 != _collector_sha256():
        raise ValueError("采集器身份与受信源码不同")
    if desc.snapshot.execution_backend != "wsl" or desc.snapshot.metadata.get("environment_label") != desc.target_environment:
        raise ValueError("平台快照与 WSL 描述目标不一致")
    request = MemcheckRequest(request_id=request_id or uuid.uuid4().hex, run_id=run_id or uuid.uuid4().hex,
        task_id=task_id, source_sha256=task.source_sha256, description_sha256=canonical_sha256(desc),
        collector_sha256=desc.collector_sha256, platform_environment_id=desc.snapshot.environment_id,
        platform_probe_id=desc.snapshot.metadata["probe_id"], snapshot_sha256=canonical_sha256(desc.snapshot),
        target_environment=desc.target_environment, target_boot_id=desc.target_boot_id,
        observed_monotonic_ns=desc.observed_monotonic_ns, tools=desc.tools, helper_images=desc.helper_images,
        resource_limits=MemcheckResourceLimits.model_validate(resource_limits or {}),
        authorization_reference=authorization_reference)
    auth = MemcheckAuthorization(request_id=request.request_id, run_id=request.run_id, task_id=task_id,
        request_sha256=canonical_sha256(request), operator_id=operator_id,
        authorization_reference=authorization_reference, issuer_kind="operator", target_boot_id=desc.target_boot_id,
        not_before_monotonic_ns=desc.observed_monotonic_ns,
        expires_monotonic_ns=desc.observed_monotonic_ns + 300000000000)
    allowed = dict(desc.helper_images)
    for identity in desc.tools.values():
        if identity.resolved_path in allowed and allowed[identity.resolved_path] != identity.file_sha256:
            raise ValueError("同一执行路径对应冲突的工具 SHA-256")
        allowed[identity.resolved_path] = identity.file_sha256
    policy = MemcheckPolicy(request_sha256=canonical_sha256(request), description_sha256=request.description_sha256,
        allowed_operator_ids=[operator_id], allowed_authorization_references=[authorization_reference],
        allowed_images=allowed, native_task_root=desc.native_task_root, resource_limits=request.resource_limits)
    return request, auth, policy


def run_fixed_memcheck_wsl(task_id, *, authorize_fixed_memcheck=False, operator_id,
        authorization_reference, linux_project_root, distro="Ubuntu-22.04", user="pocdev",
        linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python",
        output_root="data/outputs/fixed_memcheck", resource_limits=None):
    """Describe, authorize, preflight, execute, independently recover and reparse.

    This API has exactly two registry tasks and cannot accept candidate content.
    A launcher failure always triggers scoped cancellation and a fresh STATUS.
    """
    if authorize_fixed_memcheck is not True:
        raise ValueError("固定无害 Memcheck 诊断需要操作者明确授权")
    get_memcheck_task(task_id)
    fixed_source(task_id)
    _operator_scope(operator_id, authorization_reference)
    handle = _new_handle(distro=distro, user=user, linux_python=linux_python, linux_project_root=linux_project_root)
    output = _regular_path(output_root)
    if any(re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", part, re.IGNORECASE) for part in output.parts):
        raise ValueError("固定无害诊断不能归入真实 CVE 目录")
    session = output / "controller" / handle.run_id
    protection = protect_directory(session)
    _write_new(session / "task_handle.private.json", _json(handle))
    _write_new(session / "access_control.json", _json(protection))
    observations, diagnostics = {}, []
    request = auth = policy = description = None

    def observe(operation):
        payload = _envelope(operation, handle, request=request if operation == "EXECUTE" else None,
            authorization=auth if operation == "EXECUTE" else None, policy=policy if operation == "EXECUTE" else None,
            description=description if operation == "EXECUTE" else None)
        try:
            transport, packet, notes = _transport(payload, handle, artifact_root=session / "transports",
                request=request, authorization=auth, policy=policy)
        except (OSError, ValueError) as exc:
            transport, packet, notes = None, None, ["CONTROLLER_OBSERVER_FAILED:" + type(exc).__name__ + ":" + str(exc)]
        observations[operation] = {"transport": None if transport is None else transport.model_dump(mode="json"),
            "packet": None if packet is None else packet.model_dump(mode="json"), "diagnostics": notes}
        diagnostics.extend(notes)
        _write_new(session / (operation.lower() + ".json"), _json(observations[operation]))
        return packet

    described = observe("DESCRIBE")
    state = "UNKNOWN"
    evidence_folder = manifest_sha256 = record_sha256 = None
    parse_status, cleanup_confirmation = "NOT_CHECKED", "UNKNOWN"
    if described is not None and described.description is not None:
        description = described.description
        if description.status != "DESCRIBED":
            state = description.status
            diagnostics.extend(description.diagnostics)
        else:
            request, auth, policy = build_fixed_memcheck_context(description, task_id,
                authorize_fixed_memcheck=True, operator_id=operator_id, authorization_reference=authorization_reference,
                request_id=handle.request_id, run_id=handle.run_id, resource_limits=resource_limits)
            for name, value in (("description", description), ("request", request), ("authorization", auth), ("policy", policy)):
                _write_new(session / (name + ".json"), _json(value))
            executed = observe("EXECUTE")
            if executed is None:
                observe("CANCEL")
            recovered = observe("STATUS")
            packet = executed if executed is not None and executed.record is not None else recovered
            record = None if packet is None else packet.record
            if record is not None:
                record_sha256 = canonical_sha256(record)
                _write_new(session / "record_pin.json", _json({"request_id": handle.request_id,
                    "run_id": handle.run_id, "record_sha256": record_sha256}))
                if recovered is not None and recovered.recovery is not None:
                    cleanup_confirmation = recovered.recovery.status
                    state = record.status if recovered.recovery.status == "CONFIRMED" else (
                        "CLEANUP_FAILED" if recovered.recovery.status == "FAILED" else "UNKNOWN")
                try:
                    raw = {name: base64.b64decode(value, validate=True) for name, value in packet.raw_files.items()}
                    parsed = parse_memcheck_evidence(record, request, auth, policy, raw, expected_record_sha256=record_sha256)
                    parse_status = parsed.parse_status
                    folder, manifest_sha256 = save_memcheck_evidence(parsed, raw, output_root=output)
                    evidence_folder = str(folder)
                    independently_read = read_memcheck_evidence(folder, expected_manifest_sha256=manifest_sha256)
                    if canonical_sha256(independently_read) != canonical_sha256(parsed):
                        raise ValueError("独立重新解析与采集后解析对象不同")
                    _write_new(session / "evidence_pin.json", _json({"run_id": handle.run_id,
                        "manifest_sha256": manifest_sha256, "record_sha256": record_sha256,
                        "evidence_directory": evidence_folder, "independent_reparse": "PASS"}))
                except (OSError, ValueError) as exc:
                    state = "CAPTURE_FAILED" if state != "CLEANUP_FAILED" else state
                    diagnostics.append("EVIDENCE_INDEPENDENT_CHECK_FAILED:" + type(exc).__name__ + ":" + str(exc))
    result = {"schema_version": "memcheck-controller-1.0", "report_locale": "zh-CN", "cve_id": None,
        "request_id": handle.request_id, "run_id": handle.run_id, "task_id": task_id,
        "effective_state": state, "record_sha256": record_sha256, "manifest_sha256": manifest_sha256,
        "parse_status":parse_status,"cleanup_confirmation":cleanup_confirmation,
        "evidence_directory": evidence_folder, "controller_directory": str(session), "diagnostics": diagnostics,
        "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    _write_new(session / "controller_result.json", _json(result))
    report = ("# Windows→WSL 固定无害 Memcheck 调度报告\n\n"
        + "报告语言：zh-CN。\n\n任务：" + task_id + "。request_id：" + handle.request_id + "；run_id：" + handle.run_id
        + "。\n\n最终调度状态：" + state + "。独立诊断目录：" + str(evidence_folder)
        + "。\n\n执行记录 SHA-256：" + str(record_sha256) + "；诊断清单 SHA-256：" + str(manifest_sha256)
        + "。\n\n只有独立 STATUS 确认回收后才采用远端执行状态。通信失败不能证明远端进程已终止。"
        + "\n\n诊断信息：" + ("；".join(diagnostics) or "没有额外通信错误；具体诊断结果见证据目录内的中文报告。")
        + "\n\n本任务仅运行固定无害 CPU fixture，没有真实 CVE 目标。候选执行状态为 NOT_EXECUTED，漏洞验证状态始终 NOT_VERIFIED。\n")
    _write_new(session / "controller_report.zh-CN.md", report.encode("utf-8"))
    result["report_path"] = str(session / "controller_report.zh-CN.md")
    return result
