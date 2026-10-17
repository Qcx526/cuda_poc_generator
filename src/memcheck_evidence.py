"""Offline, byte-bound evidence for the fixed no-CVE Memcheck collector.

This module never starts a process.  A record digest must be pinned by the
caller, and recorded authorization and policy must bind before original bytes
can be interpreted.  Historical imported/Synthetic models remain unchanged.
"""

import base64
from html import escape
import json
import os
import re
import stat
from types import SimpleNamespace
from typing import Literal

from pydantic import Field

from .artifact_packaging import MAX_FILE, MAX_TOTAL, _read, _regular_path, _strict_json, _write_new
from .host_diagnostic_tasks import diagnostic_reason_zh
from .host_parser_evidence import _InvalidXML, _parse
from .models.artifact_package import safe_member
from .models.host_parser import HostArtifactIdentity, HostMemoryObservation, HostRawArtifact
from .models.lifecycle import LifecycleContract, canonical_sha256
from .models.memcheck import (MemcheckAuthorization, MemcheckExecutionRecord, MemcheckPolicy,
                              MemcheckRequest, validate_memcheck_binding)
from .models.tool_result import ToolIdentity, digest_bytes
from .probe_artifacts import protect_directory


class MemcheckEvidence(LifecycleContract):
    evidence_schema_version: Literal["memcheck-1.0"] = "memcheck-1.0"
    parser_version: Literal["p3b-memcheck-xml4-parser-1.0"] = "p3b-memcheck-xml4-parser-1.0"
    report_locale: Literal["zh-CN"] = "zh-CN"
    cve_id: None = None
    record: MemcheckExecutionRecord
    request: MemcheckRequest
    authorization: MemcheckAuthorization
    policy: MemcheckPolicy
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_artifacts: list[HostRawArtifact] = Field(max_length=3)
    parse_status: Literal["PARSED", "REJECTED"]
    diagnostic_codes: list[str]
    observations: list[HostMemoryObservation]
    qualified_for_cve_verification: Literal[False] = False
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    real_cve_verification: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"


_STREAMS = ("memcheck.xml", "memcheck.stdout.bin", "memcheck.stderr.bin")


def _cell(value):
    return escape(str(value), quote=True).replace("`", "&#96;").replace("|", "&#124;").replace(
        "\r", "&#13;").replace("\n", "&#10;")


def _json(value):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _generic_directory(path):
    folder = _regular_path(path)
    if any(re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", part, re.IGNORECASE) for part in folder.parts):
        raise ValueError("固定无害诊断必须独立保存，不得归入真实 CVE 实验目录")
    return folder


def _binding(record, request, authorization, policy, expected_record_sha256):
    record, request, authorization, policy = validate_memcheck_binding(record, request, authorization, policy)
    if canonical_sha256(record) != expected_record_sha256:
        raise ValueError("固定诊断执行记录与独立固定的 SHA-256 不同")
    if (policy.description_sha256 != request.description_sha256 or policy.resource_limits != request.resource_limits
            or authorization.target_boot_id != request.target_boot_id):
        raise ValueError("诊断策略、资源限制或授权 boot 身份与请求不同")
    images = {tool.resolved_path: tool.file_sha256 for tool in request.tools.values()}
    for path, digest in request.helper_images.items():
        if path in images and images[path] != digest:
            raise ValueError("辅助程序与工具允许列表中的身份冲突")
        images[path] = digest
    if policy.allowed_images != images:
        raise ValueError("独立策略未精确绑定工具及辅助程序允许列表")
    for step in record.steps:
        p = step.process
        if (p.target_environment != request.target_environment or p.tool_identity != request.tools["bwrap"]
                or not p.argv or p.argv[0] != request.tools["bwrap"].resolved_path
                or p.inner_linux_signal != (-p.inner_returncode if p.inner_returncode is not None and p.inner_returncode < 0 else None)):
            raise ValueError("步骤目标、实际外层工具或内层 signal 与固定请求不同")
    return record, request, authorization, policy


def _derive(record, request, raw_files):
    """Reuse the frozen XML grammar with a read-only inner-process adapter."""
    artifacts = []
    for name in _STREAMS:
        if name not in raw_files:
            continue
        identity = record.artifacts[name]
        artifacts.append(HostRawArtifact(identity=HostArtifactIdentity(artifact_file=name,
            original_path="/out/" + name, sha256=identity.sha256, size_bytes=identity.size_bytes),
            raw_b64=base64.b64encode(raw_files[name]).decode("ascii")))
    codes, observations = [], []
    if len(record.steps) != 2:
        return artifacts, "REJECTED", ["MEMCHECK_STEP_NOT_RECORDED"], observations
    step = record.steps[-1]
    process = step.process
    if (set(_STREAMS) - set(raw_files) or not process.action_started or process.inner_pid is None
            or process.inner_returncode is None or process.inner_result is None
            or process.truncated or process.capture_failed or process.timed_out or process.cancelled
            or process.cleanup.status != "CONFIRMED" or process.resources.status != "ENFORCED"
            or process.inner_result.get("all_tracees_reaped") is not True
            or process.inner_result.get("remaining_pids") != [] or process.inner_result.get("error") is not None):
        return artifacts, "REJECTED", ["CAPTURE_OR_CLEANUP_INCOMPLETE"], observations
    # The outer process is bubblewrap.  Never relabel its PID or argv as
    # Valgrind: the adapter uses only execution-end observed inner fields.
    xml_identity = next(item.identity for item in artifacts if item.identity.artifact_file == "memcheck.xml")
    adapter = SimpleNamespace(diagnostic_artifact=xml_identity, observed_pid=process.inner_pid,
        target_argv=process.inner_argv[4:], process=SimpleNamespace(argv=process.inner_argv))
    try:
        observations = _parse(raw_files["memcheck.xml"], adapter)
        codes.append("STRUCTURED_MEMORY_OBSERVATIONS_ONLY")
        if not observations:
            codes.append("NO_STRUCTURED_MEMORY_ERROR_OBSERVED")
        if process.inner_linux_signal is not None:
            codes.append("LINUX_SIGNAL_IS_NOT_CVE_PROOF")
        return artifacts, "PARSED", codes, observations
    except _InvalidXML as exc:
        return artifacts, "REJECTED", [str(exc)], []


def _json_original(raw_files, name):
    if name not in raw_files:
        raise ValueError("缺少执行投影对应的原始文件：" + name)
    return _strict_json(raw_files[name])


def _verify_process_originals(record, request, authorization, policy, raw_files):
    limits = {key: [getattr(request.resource_limits, key)] * 2 for key in (
        "cpu_seconds", "memory_bytes", "max_file_bytes", "max_open_files", "core_bytes")}
    for step in record.steps:
        p, prefix = step.process, step.step_id
        if _json_original(raw_files, prefix + ".process_result.json") != p.model_dump(mode="json"):
            raise ValueError("进程结果投影与执行端原始 JSON 不同")
        if _json_original(raw_files, prefix + ".argv.json") != p.argv:
            raise ValueError("bubblewrap argv 投影与原始 JSON 不同")
        config = _json_original(raw_files, prefix + ".config.json")
        if (type(config) is not dict or config.get("schema_version") != "1.0"
                or (config.get("request_id"), config.get("run_id"), config.get("step_id"), config.get("task_id"),
                    config.get("source_sha256"), config.get("tools"), config.get("allowed_images"), config.get("limits")) !=
                   (request.request_id, request.run_id, prefix, request.task_id, request.source_sha256,
                    {key: value.model_dump(mode="json") for key, value in request.tools.items()},
                    policy.allowed_images, request.resource_limits.model_dump(mode="json"))):
            raise ValueError("原始 sandbox 配置与固定请求或独立策略不同")
        nonce = config.get("nonce")
        if type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{32}", nonce):
            raise ValueError("原始 sandbox nonce 无效")
        expected_executable = None if prefix == "compile" else record.executable_sha256
        if config.get("executable_sha256") != expected_executable:
            raise ValueError("原始 sandbox 配置的执行文件身份不同")
        if p.ready_observation is not None:
            ready = _json_original(raw_files, prefix + ".ready.json")
            if ready != p.ready_observation:
                raise ValueError("ready 投影与原始 JSON 不同")
            if (ready.get("request_id"), ready.get("run_id"), ready.get("step_id"), ready.get("nonce"),
                    ready.get("source_sha256"), ready.get("argv"), ready.get("limits")) != (
                    request.request_id, request.run_id, prefix, nonce, request.source_sha256, p.inner_argv, limits):
                raise ValueError("ready 记录未绑定固定任务或实际资源限制")
            if type(ready.get("pid")) is not int or ready["pid"] <= 0:
                raise ValueError("ready 原件中的 guard PID 无效")
            if ready.get("guard_python_image") != {"path": request.tools["guard_python"].resolved_path,
                    "sha256": request.tools["guard_python"].file_sha256}:
                raise ValueError("ready 中实测 Python 图像与固定采集器工具身份不同")
            boundaries, namespaces, outer = ready.get("boundaries"), ready.get("namespaces"), config.get("outer_namespaces")
            names = {"user", "mnt", "net", "pid", "ipc", "uts"}
            required = {"private_" + name for name in names} | {"host_paths_absent", "gpu_devices_absent", "no_new_privs", "source_readonly"}
            if prefix == "memcheck": required.add("target_readonly")
            if (type(boundaries) is not dict or not required <= set(boundaries)
                    or any(type(value) is not bool or not value for value in boundaries.values())
                    or type(namespaces) is not dict or set(namespaces) != names
                    or type(outer) is not dict or set(outer) != names
                    or any(type(namespaces[name]) is not str or not namespaces[name] or namespaces[name] == outer[name] for name in names)):
                raise ValueError("原始 ready 未确认所需文件、网络及进程命名空间边界")
        elif prefix + ".ready.json" in raw_files:
            raise ValueError("保存了 ready 原件却缺少对应进程投影")
        host_name = prefix + ".host_identity.json"
        if p.host_observation is not None:
            host = _json_original(raw_files, host_name)
            if host != p.host_observation or type(host) is not dict or set(host) != {"bwrap_identity", "bwrap_image", "guard_identity"}:
                raise ValueError("宿主侧独立进程观测投影与原始记录不同")
            image = ToolIdentity.model_validate(host["bwrap_image"])
            bwrap = request.tools["bwrap"]
            if image.status != "OBSERVED" or (image.resolved_path, image.file_sha256) != (bwrap.resolved_path, bwrap.file_sha256):
                raise ValueError("宿主 /proc 实测 bubblewrap 图像与允许的二进制不同")
            native, guard = host["bwrap_identity"], host["guard_identity"]
            if (type(native) is not dict or type(guard) is not dict
                    or any(native.get(key) != getattr(p, key) for key in ("pid", "pgid", "session_id", "start_ticks", "uid", "gid"))):
                raise ValueError("宿主侧 bubblewrap 进程身份与原始执行观察不同")
            if (p.ready_observation is None or any(type(guard.get(key)) is not int or guard[key] <= 0 for key in ("pid", "pgid", "session_id", "start_ticks"))
                    or guard["pgid"] != p.pgid or guard["session_id"] != p.session_id
                    or guard["start_ticks"] != p.ready_observation.get("start_ticks")):
                raise ValueError("宿主侧 guard 与 namespace ready 的进程启动身份不同")
        elif p.action_started or host_name in raw_files:
            raise ValueError("目标启动缺少宿主侧独立工具/进程身份原始观察")
        if p.inner_result is not None:
            result = _json_original(raw_files, prefix + ".result.json")
            if result != p.inner_result:
                raise ValueError("result 投影与原始 JSON 不同")
            if (result.get("request_id"), result.get("run_id"), result.get("step_id"), result.get("nonce"),
                    result.get("source_sha256"), result.get("executable_sha256"), result.get("argv"),
                    result.get("child_pid"), result.get("returncode"), result.get("linux_signal")) != (
                    request.request_id, request.run_id, prefix, nonce, request.source_sha256, expected_executable,
                    p.inner_argv, p.inner_pid, p.inner_returncode, p.inner_linux_signal):
                raise ValueError("result 原件与任务、输入、执行文件或实际退出状态不同")
            if p.ready_observation is None or result.get("guard_pid") != p.ready_observation.get("pid"):
                raise ValueError("result 与 ready guard 进程身份不同")
            if (type(result.get("child_pid")) is not int or result["child_pid"] <= 0
                    or result.get("returncode") is not None and type(result["returncode"]) is not int
                    or result.get("linux_signal") is not None and type(result["linux_signal"]) is not int):
                raise ValueError("result 原件中的实际 PID 或退出状态类型无效")
        elif prefix + ".result.json" in raw_files:
            raise ValueError("保存了 result 原件却缺少对应进程投影")
        trace_name = prefix + ".trace.jsonl"
        if trace_name in raw_files:
            lines = raw_files[trace_name].splitlines()
            if len(lines) > 512 or any(not line.strip() for line in lines):
                raise ValueError("原始 trace JSONL 记录数量或行格式无效")
            events = [_strict_json(line) for line in lines]
        else:
            events = []
        if events != p.trace_events:
            raise ValueError("内核跟踪投影与原始 trace JSONL 不同")
        # A timeout may leave an original trace but no final result.json.  Its
        # first native EXEC can be checked as a trace identity without filling
        # the record's deliberately UNKNOWN inner_pid/exit fields.
        trace_root = p.inner_pid
        if trace_root is None:
            trace_root = next((event.get("pid") for event in events
                if type(event) is dict and event.get("event") == "EXEC"), None)
        active = {trace_root} if type(trace_root) is int and trace_root > 0 else set()
        main_exec, main_reaped, previous_time = False, False, None
        for event in events:
            if type(event) is not dict or event.get("event") not in {"EXEC", "CHILD_STOP", "FORK", "REAPED"}:
                raise ValueError("不支持的内核跟踪事件")
            pid, when = event.get("pid"), event.get("monotonic_ns")
            if (type(pid) is not int or pid <= 0 or pid not in active or type(when) is not int or when < 0
                    or previous_time is not None and when < previous_time):
                raise ValueError("内核跟踪 PID、事件顺序或时钟无效")
            previous_time = when
            if event["event"] in {"EXEC", "CHILD_STOP"}:
                if (type(event.get("image_path")) is not str or event["image_path"] not in policy.allowed_images
                        or policy.allowed_images[event["image_path"]] != event.get("image_sha256")
                        or event.get("limits") != limits or type(event.get("argv")) is not list
                        or not event["argv"] or any(type(value) is not str or "\0" in value for value in event["argv"])
                        or type(event.get("identity")) is not dict or event["identity"].get("pid") != pid):
                    raise ValueError("内核执行图像、argv、PID 或资源限制不在授权范围")
                if any(type(value) is not list or len(value) != 2 or any(type(bound) is not int for bound in value)
                        for value in event["limits"].values()):
                    raise ValueError("内核资源限制原始字段类型无效")
                if pid == trace_root and not main_exec:
                    if event["event"] != "EXEC" or event["argv"] != p.inner_argv:
                        raise ValueError("首次实际目标执行参数与固定 argv 不同")
                    if not authorization.not_before_monotonic_ns <= when <= authorization.expires_monotonic_ns:
                        raise ValueError("实际目标启动时刻不在独立授权期限内")
                    main_exec = True
            elif event["event"] == "FORK":
                child = event.get("child_pid")
                if type(child) is not int or child <= 0 or child in active or len(active) >= request.resource_limits.max_tracees:
                    raise ValueError("后代进程身份重复或超过固定上限")
                active.add(child)
            else:
                code = event.get("returncode")
                if type(code) is not int:
                    raise ValueError("回收事件缺少客观退出码")
                if pid == trace_root:
                    if p.inner_result is not None and code != p.inner_returncode:
                        raise ValueError("主目标回收退出码与执行结果不同")
                    main_reaped = True
                active.remove(pid)
        if p.action_started and not main_exec:
            raise ValueError("声称目标启动但缺少对应内核 EXEC 观测")
        if p.inner_result is not None and p.inner_result.get("all_tracees_reaped") is True:
            if not main_reaped or active or p.inner_result.get("remaining_pids") != []:
                raise ValueError("声称全部回收但内核跟踪仍有未回收进程")


def _verify_raw_files(record, request, authorization, policy, raw_files):
    if type(raw_files) is not dict or set(raw_files) != set(record.artifacts):
        raise ValueError("原始文件集合与执行记录不一致；缺失和多余文件均不接受")
    if sum(len(value) for value in raw_files.values() if isinstance(value, bytes)) > MAX_TOTAL:
        raise ValueError("原始证据总长度超出离线读取上限")
    for name, identity in record.artifacts.items():
        safe_member(name)
        raw = raw_files[name]
        if type(raw) is not bytes or len(raw) > MAX_FILE:
            raise ValueError("原始证据必须是长度受限的 bytes")
        if len(raw) != identity.size_bytes or digest_bytes(raw) != identity.sha256:
            raise ValueError("原始证据长度或 SHA-256 与执行端记录不同：" + name)
    if record.steps and "fixture.c" not in raw_files:
        raise ValueError("有编译步骤却缺少原始固定 C 源码")
    if record.steps and ("sandbox_guard.py" not in raw_files
            or digest_bytes(raw_files["sandbox_guard.py"]) != request.collector_sha256):
        raise ValueError("采集器原始源码缺失或与独立请求固定的 SHA-256 不同")
    if record.steps and record.steps[0].status == "COMPLETED" and "fixture.bin" not in raw_files:
        raise ValueError("编译完成却缺少已绑定构建产物")
    if "fixture.c" in raw_files and digest_bytes(raw_files["fixture.c"]) != request.source_sha256:
        raise ValueError("保存的 C 源码与冻结任务身份不同")
    if "fixture.bin" in raw_files and digest_bytes(raw_files["fixture.bin"]) != record.executable_sha256:
        raise ValueError("保存的构建产物与实际执行目标身份不同")
    for step in record.steps:
        for stream in ("stdout", "stderr"):
            name = step.step_id + "." + stream + ".bin"
            if name not in raw_files or raw_files[name] != getattr(step.process, stream + "_bytes")():
                raise ValueError("原始标准流与执行端进程记录不同：" + name)
    _verify_process_originals(record, request, authorization, policy, raw_files)


def parse_memcheck_evidence(record, request, authorization, policy, raw_files, *, expected_record_sha256):
    """Validate separately pinned collection identities, then parse original XML.

    A matching digest establishes content consistency, not host authenticity.
    Trust still depends on the separately supplied operator policy and genuine
    execution-end record.  No imported record receives a REAL_CAPTURE label.
    """
    record, request, authorization, policy = _binding(record, request, authorization, policy, expected_record_sha256)
    _verify_raw_files(record, request, authorization, policy, raw_files)
    artifacts, status, codes, observations = _derive(record, request, raw_files)
    return MemcheckEvidence(record=record, request=request, authorization=authorization, policy=policy,
        record_sha256=expected_record_sha256, raw_artifacts=artifacts,
        parse_status=status, diagnostic_codes=codes, observations=observations)


def reassess_memcheck_evidence(evidence, *, expected_record_sha256):
    """Reparse embedded original XML/streams without any process execution."""
    evidence = MemcheckEvidence.model_validate(evidence)
    record, request, auth, policy = _binding(evidence.record, evidence.request, evidence.authorization,
        evidence.policy, expected_record_sha256)
    raw = {}
    for item in evidence.raw_artifacts:
        name = item.identity.artifact_file
        if name in raw or name not in _STREAMS or name not in record.artifacts:
            raise ValueError("原始诊断流身份重复或未被执行记录绑定")
        reference = record.artifacts[name]
        if item.identity.sha256 != reference.sha256 or item.identity.size_bytes != reference.size_bytes:
            raise ValueError("原始诊断流与独立执行记录摘要不同")
        raw[name] = item.raw_bytes()
    artifacts, status, codes, observations = _derive(record, request, raw)
    rebuilt = MemcheckEvidence(record=record, request=request, authorization=auth, policy=policy,
        record_sha256=expected_record_sha256, raw_artifacts=artifacts, parse_status=status,
        diagnostic_codes=codes, observations=observations)
    if canonical_sha256(evidence) != canonical_sha256(rebuilt):
        raise ValueError("派生诊断字段与原始 XML 独立重新解析不同")
    return rebuilt


def render_memcheck_report(evidence):
    """Deterministic zh-CN rendering; this view cannot upgrade any status."""
    evidence = MemcheckEvidence.model_validate(evidence)
    evidence = reassess_memcheck_evidence(evidence, expected_record_sha256=evidence.record_sha256)
    record, req, auth = evidence.record, evidence.request, evidence.authorization
    rows = ["# 固定无害 CPU Memcheck 诊断报告", "", "报告语言：zh-CN；渲染版本：p3d-fixed-memcheck-report-1.0。", "",
        "本报告来自固定诊断执行记录及其原始字节的离线解析；没有真实 CVE 目标，不是漏洞复现报告。",
        "候选执行状态：NOT_EXECUTED；真实 CVE 验证状态：NOT_VERIFIED。", "", "## 实验摘要与授权", "",
        "| 项目 | 记录 |", "|---|---|",
        f"| request_id / run_id | {record.request_id} / {record.run_id} |",
        f"| 固定任务 | {_cell(record.task_id)} |",
        f"| 执行状态 / 解析状态 | {record.status} / {evidence.parse_status} |",
        f"| 操作者 / 授权来源 | {_cell(auth.operator_id)} / {auth.issuer_kind} |",
        f"| 授权引用 | {_cell(auth.authorization_reference)} |",
        f"| 执行记录 SHA-256 | {evidence.record_sha256} |",
        f"| 请求 / 授权 / 策略 SHA-256 | {record.request_sha256} / {record.authorization_sha256} / {record.policy_sha256} |",
        f"| 目标环境 / 平台身份 | {_cell(record.target_environment)} / {_cell(record.platform_environment_id)} |",
        f"| 平台 probe / 快照 SHA-256 | {_cell(record.platform_probe_id)} / {record.snapshot_sha256} |",
        f"| 源码 / 构建产物 SHA-256 | {record.source_sha256} / {_cell(record.executable_sha256)} |", "",
        "## 实际工具身份", "", "| 角色 | 可执行文件 | SHA-256 |", "|---|---|---|"]
    for role, identity in sorted(req.tools.items()):
        rows.append(f"| {_cell(role)} | {_cell(identity.resolved_path)} | {identity.file_sha256} |")
    rows += ["", "## 编译、诊断进程及回收", ""]
    if not record.steps:
        rows.append("执行记录没有启动步骤；不虚构 PID、标准流或 XML。")
    for step in record.steps:
        p = step.process
        rows += [f"### {'固定源码编译' if step.step_id == 'compile' else 'Valgrind Memcheck'}", "",
            "| 项目 | 记录 |", "|---|---|", f"| 步骤状态 | {step.status} |",
            f"| 外层 argv | {_cell(json.dumps(p.argv, ensure_ascii=False))} |",
            f"| 固定内层 argv | {_cell(json.dumps(p.inner_argv, ensure_ascii=False))} |",
            f"| 外层 PID / PGID / session | {_cell(p.pid)} / {_cell(p.pgid)} / {_cell(p.session_id)} |",
            f"| 命名空间内目标 PID | {_cell(p.inner_pid)} |",
            f"| 外层退出码 / signal | {_cell(p.returncode)} / {_cell(p.linux_signal)} |",
            f"| 内层退出码 / signal | {_cell(p.inner_returncode)} / {_cell(p.inner_linux_signal)} |",
            f"| 启动 / 结束时间 | {_cell(p.started_at)} / {_cell(p.finished_at)} |",
            f"| 时长（秒） | {p.duration_seconds} |",
            f"| 超时 / 取消 / 截断 / 采集失败 | {p.timed_out} / {p.cancelled} / {p.truncated} / {p.capture_failed} |",
            f"| 回收状态 / 终止方式 | {p.cleanup.status} / {p.cleanup.termination_method} |",
            f"| 父进程回收 / 进程组消失 / 后代消失 | {p.cleanup.parent_reaped} / {p.cleanup.group_absent} / {p.cleanup.descendants_absent} |",
            f"| 剩余 PID | {_cell(p.cleanup.remaining_pids)} |",
            f"| 资源实施状态 / 来源 | {p.resources.status} / {_cell(p.resources.verification_source)} |",
            f"| Wall watchdog / 输出限制 / 进程组 | {p.resources.wall_watchdog} / {p.resources.output_cap} / {p.resources.process_group} |",
            f"| CPU 秒数 / 地址空间字节 | {_cell(p.resources.cpu_seconds)} / {_cell(p.resources.memory_bytes)} |",
            f"| 网络隔离 / cgroup v2 | {p.resources.network_isolation} / {p.resources.cgroup_v2_status} |",
            f"| cgroup 说明 | {_cell(p.resources.cgroup_v2_detail)} |",
            f"| 内核跟踪事件数 | {len(p.trace_events)} |", ""]
        if p.host_observation is not None:
            image = p.host_observation["bwrap_image"]
            guard = p.host_observation["guard_identity"]
            rows += ["| 宿主侧独立身份观测 | 记录 |", "|---|---|",
                f"| /proc 实测外层图像 | {_cell(image['resolved_path'])} / {_cell(image['file_sha256'])} |",
                f"| 宿主侧 guard PID / start_ticks | {_cell(guard['pid'])} / {_cell(guard['start_ticks'])} |",
                f"| namespace 内 Python 实际图像 | {_cell(p.ready_observation['guard_python_image'])} |", ""]
    rows += ["CPU 与地址空间限制是每进程 RLIMIT；不声称是任务级 cgroup 总量限制。RLIMIT_AS 不是物理内存或 GPU VRAM 配额。",
        "固定 fixture 的隔离和授权不能用于任意候选或真实 CVE 输入。", "", "## 原始文件及完整性", "",
        "| 文件 | 字节数 | SHA-256 |", "|---|---:|---|"]
    for name, artifact in sorted(record.artifacts.items()):
        rows.append(f"| {_cell(name)} | {artifact.size_bytes} | {artifact.sha256} |")
    rows += ["", "原始 XML、stdout、stderr 保留采集字节；报告不翻译或改写日志。SHA-256 验证内容一致性，不是来源签名。",
        "", "## XML 解析与客观观测", ""]
    if not evidence.observations:
        rows.append("没有可报告的合格结构化内存错误；若解析被拒绝，不能据此判断程序没有内存错误。")
    for item in evidence.observations:
        rows += [f"- XML 类型：{_cell(item.source_kind)}；分类：{item.classification}；访问方向：{item.access_type}。",
            f"  原始节点：{_cell(item.kind_locator.xml_node)}；文件 SHA-256：{item.kind_locator.artifact_sha256}。",
            "  堆/栈区域、访问大小、故障地址、生命周期及 CVE 根因保持 UNKNOWN；不从自然语言诊断描述补造。"]
        for frame in item.frames:
            rows.append("  栈帧节点：" + _cell(frame.locator.xml_node) + "；指令指针：" + _cell(frame.instruction_pointer)
                + "；函数：" + _cell(frame.function) + "；文件/行：" + _cell(frame.file) + "/" + _cell(frame.line) + "。")
    rows += ["", "## 状态原因与缺失条件", ""]
    special = {"MEMCHECK_STEP_NOT_RECORDED": "没有 Memcheck 执行步骤，尚无可解析的真实诊断。",
        "NO_STRUCTURED_MEMORY_ERROR_OBSERVED": "完整 XML 中没有结构化内存错误；这不能证明任意程序安全或目标漏洞不存在。",
        "LINUX_SIGNAL_IS_NOT_CVE_PROOF": "观测到 Linux signal；进程终止不等于指定 CVE 已验证。"}
    rows.extend("- " + special.get(code, diagnostic_reason_zh(code)) + "（" + _cell(code) + "）" for code in evidence.diagnostic_codes)
    rows.extend("- 执行端诊断标识：" + _cell(code) for code in record.diagnostics)
    rows += ["", "本轮只验证诊断后端对固定无害 CPU fixture 的观测能力；没有真实 CVE 输入、受影响/修复版本对照或专项根因绑定。",
        "未执行生成的 PoC；没有目标 CVE 漏洞验证证据；结论始终为 NOT_VERIFIED。", "", "## 离线重建与独立复核", "",
        "报告重建从保存的结构化对象和嵌入原始三流重新解析，结果应逐字节一致。独立复核另行固定 manifest SHA-256，",
        "重新打开全部原始文件，核验执行/请求/授权/策略绑定及每个文件长度、SHA-256，再运行既有 XML v4 解析器。",
        "两种操作均不启动程序，不创造新的执行事实，也不把未认证导入改名为真实采集。", ""]
    return "\n".join(rows)


def save_memcheck_evidence(evidence, raw_files, *, output_root="data/outputs/fixed_memcheck"):
    """Create a new independent run archive; never overwrite or make a ZIP."""
    evidence = MemcheckEvidence.model_validate(evidence)
    rebuilt = parse_memcheck_evidence(evidence.record, evidence.request, evidence.authorization, evidence.policy,
        raw_files, expected_record_sha256=evidence.record_sha256)
    if canonical_sha256(rebuilt) != canonical_sha256(evidence):
        raise ValueError("保存前重新解析结果与传入对象不同")
    folder = _generic_directory(output_root) / evidence.record.run_id
    folder.parent.mkdir(parents=True, exist_ok=True)
    protect_directory(folder)
    (folder / "raw").mkdir(mode=0o700)
    content = {"record.json": _json(evidence.record), "request.json": _json(evidence.request),
        "authorization.json": _json(evidence.authorization), "policy.json": _json(evidence.policy),
        "parsed.json": _json(evidence), "report.zh-CN.md": render_memcheck_report(evidence).encode("utf-8")}
    content.update({"raw/" + name: raw for name, raw in raw_files.items()})
    if any(len(raw) > MAX_FILE for raw in content.values()) or sum(map(len, content.values())) > MAX_TOTAL:
        raise ValueError("序列化诊断档案超过离线读取上限；归档未完成")
    manifest = {"manifest_schema_version": "memcheck-1.0", "report_locale": "zh-CN", "cve_id": None,
        "request_id": evidence.record.request_id, "run_id": evidence.record.run_id,
        "record_sha256": evidence.record_sha256,
        "files": {name: {"sha256": digest_bytes(raw), "size_bytes": len(raw)} for name, raw in sorted(content.items())}}
    for name, raw in content.items():
        _write_private_new(folder / name, raw)
    encoded = _json(manifest)
    _write_private_new(folder / "manifest.json", encoded)
    return folder, digest_bytes(encoded)


def _write_private_new(path, raw):
    _write_new(path, raw)
    if os.name != "nt":
        path.chmod(0o600)
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise OSError("诊断原始证据文件的 0600 权限未能实施")


def read_memcheck_evidence(directory, *, expected_manifest_sha256):
    """Verify all retained original bytes and independently reparse XML offline."""
    folder = _generic_directory(directory)
    manifest_bytes = _read(folder / "manifest.json")
    if digest_bytes(manifest_bytes) != expected_manifest_sha256:
        raise ValueError("诊断清单与独立固定的 SHA-256 不同")
    manifest = _strict_json(manifest_bytes)
    expected_keys = {"manifest_schema_version", "report_locale", "cve_id", "request_id", "run_id", "record_sha256", "files"}
    if (type(manifest) is not dict or set(manifest) != expected_keys or manifest["manifest_schema_version"] != "memcheck-1.0"
            or manifest["report_locale"] != "zh-CN" or manifest["cve_id"] is not None or type(manifest["files"]) is not dict):
        raise ValueError("诊断清单格式不受支持")
    content = {}
    for name, identity in manifest["files"].items():
        safe_member(name)
        if (type(identity) is not dict or set(identity) != {"sha256", "size_bytes"}
                or type(identity["size_bytes"]) is not int or not 0 <= identity["size_bytes"] <= MAX_FILE):
            raise ValueError("诊断清单文件身份格式不合法")
        raw = _read(folder / name)
        if len(raw) != identity["size_bytes"] or digest_bytes(raw) != identity["sha256"]:
            raise ValueError("诊断原始文件缺失或被修改：" + name)
        content[name] = raw
        if sum(map(len, content.values())) > MAX_TOTAL:
            raise ValueError("诊断档案超过总长度上限")
    if sum(map(len, content.values())) > MAX_TOTAL:
        raise ValueError("诊断档案超过总长度上限")
    mandatory = {"record.json", "request.json", "authorization.json", "policy.json", "parsed.json", "report.zh-CN.md"}
    if not mandatory <= set(content):
        raise ValueError("诊断档案缺少必需结构化对象或报告")
    record = MemcheckExecutionRecord.model_validate(_strict_json(content["record.json"]))
    if (folder.name != record.run_id or manifest["request_id"] != record.request_id
            or manifest["run_id"] != record.run_id or manifest["record_sha256"] != canonical_sha256(record)):
        raise ValueError("诊断目录、清单与执行记录发生跨 run 混淆")
    expected_files = mandatory | {"raw/" + name for name in record.artifacts}
    if set(content) != expected_files:
        raise ValueError("诊断档案包含未绑定文件或缺少原始文件")
    for path in folder.rglob("*"):
        _regular_path(path)
        if not (stat.S_ISDIR(path.lstat().st_mode) or stat.S_ISREG(path.lstat().st_mode)):
            raise ValueError("诊断档案包含不受支持的特殊文件")
    actual = {path.relative_to(folder).as_posix() for path in folder.rglob("*") if path.is_file()}
    if actual != expected_files | {"manifest.json"}:
        raise ValueError("诊断目录含清单外文件")
    rebuilt = parse_memcheck_evidence(record,
        MemcheckRequest.model_validate(_strict_json(content["request.json"])),
        MemcheckAuthorization.model_validate(_strict_json(content["authorization.json"])),
        MemcheckPolicy.model_validate(_strict_json(content["policy.json"])),
        {name: content["raw/" + name] for name in record.artifacts}, expected_record_sha256=manifest["record_sha256"])
    saved = MemcheckEvidence.model_validate(_strict_json(content["parsed.json"]))
    if canonical_sha256(saved) != canonical_sha256(rebuilt):
        raise ValueError("派生诊断对象与原始文件独立重新解析不同")
    if content["report.zh-CN.md"] != render_memcheck_report(rebuilt).encode("utf-8"):
        raise ValueError("中文诊断报告无法逐字节重建")
    return rebuilt
