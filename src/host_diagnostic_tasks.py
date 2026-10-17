"""Fixed CPU diagnostic preparation, offline parsing and explicit fixed dispatch.

Historical preparation/import contracts keep their meanings. The separate
run-fixed command uses the versioned P3-D authorization and runtime resource gate.
"""

import argparse
import base64
from dataclasses import dataclass
from html import escape
from pathlib import Path
import re
import stat
from types import MappingProxyType
import uuid

from .artifact_packaging import MAX_FILE, MAX_TOTAL, _read, _regular_path, _strict_json, _write_new
from .host_diagnostics_probe import read_host_diagnostics_archive
from .host_parser_evidence import _InvalidXML, _parse
from .models.harmless_diagnostic import (DiagnosticPreparation, HarmlessDiagnosticCollection,
                                        HarmlessDiagnosticEvidence)
from .models.host_parser import HostRawArtifact
from .models.lifecycle import canonical_sha256
from .models.tool_result import digest_bytes
from .report_locale import configure_utf8_stdio


@dataclass(frozen=True)
class DiagnosticTask:
    task_id: str
    source_file: str
    source_sha256: str
    intended_observation: str


DIAGNOSTIC_TASKS = MappingProxyType({
    "p3c-normal-v1": DiagnosticTask("p3c-normal-v1", "normal.c", "430cb14334f368538ab36462b8956ab42b9727d7b0a10663c0196f4b8445e107", "NO_EXPECTED_ERROR"),
    "p3c-invalid-read-v1": DiagnosticTask("p3c-invalid-read-v1", "invalid_read.c", "ee94debc4196dfdca03988288ebfc62e58bc7f4aaaa14977d8644bc5ed745d1c", "INVALID_READ"),
    "p3c-invalid-write-v1": DiagnosticTask("p3c-invalid-write-v1", "invalid_write.c", "d69b5329039d1548c977ee3e86e8a895e9b79e10585a1bc09ca08817cd56ef7c", "INVALID_WRITE"),
    "p3c-freed-read-v1": DiagnosticTask("p3c-freed-read-v1", "freed_read.c", "7dd07a5103c6308e83e01728a1f0c15bed903ba58dc1490a4c29cc8380e57e05", "INVALID_READ_LIFETIME_UNKNOWN"),
})
FIXTURE_ROOT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "host_diagnostics"
_BLOCKERS = ["OPERATOR_AUTHORIZATION_MISSING", "ISOLATION_NOT_CONFIRMED",
             "MEMCHECK_RESOURCE_PROFILE_UNVALIDATED", "P2_DIAGNOSTIC_ACTION_UNREGISTERED"]
_REASONS = {
    "OPERATOR_AUTHORIZATION_MISSING": "未收到操作者对这些固定 CPU 诊断任务的独立执行授权。",
    "ISOLATION_NOT_CONFIRMED": "没有确认适用于受控异常程序的文件、网络、权限隔离及回收边界。",
    "MEMCHECK_RESOURCE_PROFILE_UNVALIDATED": "现有 P2 资源机制可复用，但 Memcheck 的地址空间需求及限制实施尚未实测；不降低原有约束。",
    "P2_DIAGNOSTIC_ACTION_UNREGISTERED": "P2 执行注册表尚未接入此新动作；普通 fixture 或 CUDA smoke 授权不授权 Memcheck。",
    "VALGRIND_IDENTITY_UNKNOWN": "固定探测路径未发现可测量的 Valgrind，不能假定已安装，也未自动安装。",
    "VALGRIND_VERSION_UNCONFIRMED": "Valgrind 版本查询失败、身份变化或输出不完整，不能认定工具可用。",
    "PROBE_TARGET_UNKNOWN": "未获得合格目标响应，不用其他平台观测代替。",
}
_PARSE_REASONS = {
    "STRUCTURED_MEMORY_OBSERVATIONS_ONLY": "完整 XML v4 的结构化字段已解析；只支持对应访问观测，不证明 CVE。",
    "CAPTURE_OR_CLEANUP_INCOMPLETE": "启动、完整采集、输出限制、超时或回收确认不满足要求，拒绝推断。",
    "XML_SIZE_LIMIT": "XML 原始字节超过解析上限。",
    "XML_UTF8_REQUIRED": "XML 编码不是严格 UTF-8。",
    "XML_DTD_OR_ENTITY_FORBIDDEN": "XML 包含禁止的 DTD、实体或 NUL。",
    "XML_MALFORMED_OR_TRUNCATED": "XML 损坏、未闭合或被截断。",
    "XML_UNSUPPORTED_ROOT": "XML 根节点不符合已支持的 Valgrind 格式。",
    "XML_STRUCTURE_LIMIT": "XML 嵌套深度或节点数量超出受控上限。",
    "XML_UNSUPPORTED_NODE_PROFILE": "XML 使用未支持的命名空间、属性或节点名称。",
    "XML_UNSUPPORTED_PROTOCOL": "只支持 Memcheck XML 协议 4；不会将其他协议改标后接纳。",
    "XML_PROCESS_ID_CONFLICT": "XML 中的 PID 与绑定进程观察不一致。",
    "XML_MISSING_FINISHED": "缺少唯一完整的 FINISHED 结束记录，不能视作完整诊断。",
    "XML_UNSUPPORTED_PROCESS_STATE": "XML 包含未知进程状态，拒绝猜测。",
    "XML_DUPLICATE_FINISHED": "XML 中出现重复结束记录，拒绝歧义。",
    "XML_TOOL_OR_INPUT_IDENTITY_CONFLICT": "XML 实际目标或诊断工具 argv 与采集记录不同。",
    "XML_ERROR_LIMIT": "XML 错误记录数量超过上限。",
    "XML_FRAME_LIMIT": "XML 调用栈帧数量超过上限。",
    "XML_INVALID_FRAME_LINE": "调用栈行号不是受支持的非负整数。",
    "XML_INVALID_INSTRUCTION_POINTER": "栈帧指令地址格式不合法，不编造地址。",
    "XML_INVALID_OR_DUPLICATE_ERROR_ID": "错误身份无效或重复。",
    "XML_DUPLICATE_XWHAT": "错误描述结构重复，拒绝歧义。",
    "XML_INVALID_ARGUMENT": "XML 参数节点缺失内容或存在未支持结构。",
    "XML_ARGUMENT_LIMIT": "XML 参数向量超过限制。",
}


def _cell(value):
    return escape(str(value), quote=True).replace("`", "&#96;").replace("|", "&#124;").replace("\r", "&#13;").replace("\n", "&#10;")


def diagnostic_reason_zh(code):
    if code.startswith(("XML_REQUIRED_OR_DUPLICATE_", "XML_INVALID_SCALAR_NODE:")):
        return "XML 必需节点缺失、重复或标量内容不合法，拒绝猜测。"
    return _PARSE_REASONS.get(code, "该格式或身份检查未满足；没有扩大解析支持范围，也没有推断缺失观测。")


def get_diagnostic_task(task_id):
    if not isinstance(task_id, str) or task_id not in DIAGNOSTIC_TASKS:
        raise ValueError("只允许已审核固定 CPU 诊断任务，拒绝自定义源码、shell 或 argv")
    return DIAGNOSTIC_TASKS[task_id]


def diagnostic_source(task_id):
    task = get_diagnostic_task(task_id)
    raw = _read(FIXTURE_ROOT / task.source_file)
    if digest_bytes(raw) != task.source_sha256:
        raise ValueError("固定诊断源文件与注册表 SHA-256 不同，拒绝准备")
    return raw


def prepare_diagnostic(*, task_id, probe_directory, expected_probe_sha256, request_id=None, run_id=None):
    """Read verified capability bytes and make a blocked preparation, never run."""
    task = get_diagnostic_task(task_id)
    diagnostic_source(task_id)
    probe = read_host_diagnostics_archive(probe_directory)
    if probe.record_sha256 != expected_probe_sha256:
        raise ValueError("能力探测记录与操作者固定的摘要不同")
    valgrind = next((x for x in probe.tools if x.tool_id == "valgrind"), None)
    blockers = list(_BLOCKERS)
    if probe.target is None:
        blockers.append("PROBE_TARGET_UNKNOWN")
    if valgrind is None or valgrind.identity.status != "OBSERVED":
        blockers.append("VALGRIND_IDENTITY_UNKNOWN")
    elif valgrind.version_status != "OBSERVED":
        blockers.append("VALGRIND_VERSION_UNCONFIRMED")
    return DiagnosticPreparation(task_id=task_id, source_sha256=task.source_sha256,
        request_id=request_id or uuid.uuid4().hex, run_id=run_id or uuid.uuid4().hex,
        probe_id=probe.probe_id, probe_record_sha256=probe.record_sha256,
        requested_environment=probe.requested_environment,
        diagnostic_tool=valgrind.identity if valgrind else None, tool_version=valgrind.version if valgrind else None,
        requested_limits={"wall_time_seconds": 30.0, "cpu_seconds": 10, "memory_bytes": 1073741824,
                          "max_output_bytes": 1048576}, blockers=blockers)


def render_preparation_report(record):
    record = DiagnosticPreparation.model_validate(record.model_dump(mode="python"))
    lines = ["# 固定无害主机诊断准备报告", "", "报告语言：zh-CN。", "",
        "这是准备与阻断报告，不是执行报告；未执行固定诊断程序或生成候选。", "",
        f"- request_id / run_id：`{record.request_id}` / `{record.run_id}`",
        f"- 固定任务：`{record.task_id}`；源文件 SHA-256：`{record.source_sha256}`",
        f"- 探测记录：`{record.probe_id}`；内容 SHA-256：`{record.probe_record_sha256}`",
        f"- 目标环境：{_cell(record.requested_environment)}",
        f"- 工具身份：{_cell(record.diagnostic_tool.model_dump(mode='json') if record.diagnostic_tool else None)}",
        f"- 观测到的工具版本：{_cell(record.tool_version)}", "",
        "## 执行准入与缺失条件", "", "状态：REJECTED；真实诊断：NOT_CHECKED；P2 专项动作与资源配置：UNSUPPORTED。", ""]
    lines.extend("- " + _REASONS.get(code, "该必要前置条件未满足。") + "（" + _cell(code) + "）" for code in record.blockers)
    lines += ["", "## 证据、限制与复核", "",
        "本轮没有启动诊断进程，因此没有 PID、Memcheck XML、stdout/stderr 或回收结果；不生成占位日志。",
        "版本查询不证明 XML v4 兼容性或内存诊断效果。新协议格式必须明确拒绝，不能通过替换版本号接纳。",
        "要求的资源限制仅是待审核计划，未实施；RLIMIT_AS 不代表 GPU VRAM 配额。",
        "原能力探测日志保留在其独立通用档案，重建本报告不会重新探测或运行任何程序。",
        "无害诊断不绑定任何 CVE；没有专项根因或差分证据。候选：NOT_EXECUTED；真实漏洞：NOT_VERIFIED。", ""]
    return "\n".join(lines)


def _json(value):
    import json
    return (json.dumps(value.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _generic_root(output_root):
    root = _regular_path(output_root)
    if any(re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", part, re.IGNORECASE) for part in root.resolve().parts):
        raise ValueError("无害诊断没有 CVE 绑定，必须在通用诊断目录独立归档")
    return root


def save_preparation(record, *, output_root="data/outputs/host_diagnostic_preparations"):
    record = DiagnosticPreparation.model_validate(record.model_dump(mode="python"))
    folder = _generic_root(output_root) / record.run_id
    folder.parent.mkdir(parents=True, exist_ok=True)
    folder.mkdir(exist_ok=False)
    _write_new(folder / "preparation.json", _json(record))
    _write_new(folder / "report.zh-CN.md", render_preparation_report(record).encode("utf-8"))
    return folder


def rebuild_preparation(directory, *, expected_preparation_sha256):
    folder = _generic_root(directory)
    raw = _read(folder / "preparation.json")
    if digest_bytes(raw) != expected_preparation_sha256:
        raise ValueError("准备记录原始字节摘要不同")
    record = DiagnosticPreparation.model_validate(_strict_json(raw))
    if folder.name != record.run_id:
        raise ValueError("准备目录与 run 身份不一致")
    text = render_preparation_report(record)
    if _read(folder / "report.zh-CN.md") != text.encode("utf-8"):
        raise ValueError("中文准备报告与结构化状态不一致")
    return text


def parse_harmless_diagnostic(collection, *, diagnostic_bytes, stdout_bytes, stderr_bytes, expected_collection_sha256):
    """Reuse P3-B XML v4 checks without inventing a CVE-specific collection.

    UNVERIFIED_IMPORT means imported original bytes, NOT authenticated real
    collection. No caller can claim REAL_CAPTURE or execution authorization.
    """
    collection = HarmlessDiagnosticCollection.model_validate(collection.model_dump(mode="python") if hasattr(collection, "model_dump") else collection)
    task = get_diagnostic_task(collection.task_id)
    if task.source_sha256 != collection.source_sha256:
        raise ValueError("诊断源文件与固定任务身份不一致")
    pin = canonical_sha256(collection)
    if pin != expected_collection_sha256:
        raise ValueError("独立固定的采集记录摘要不同")
    raw_artifacts = []
    for name, raw in (("diagnostic", diagnostic_bytes), ("stdout", stdout_bytes), ("stderr", stderr_bytes)):
        if type(raw) is not bytes:
            raise ValueError("原始诊断数据必须是字节，不接受摘要或翻译文本")
        raw_artifacts.append(HostRawArtifact(identity=getattr(collection, name + "_artifact"),
            raw_b64=base64.b64encode(raw).decode("ascii")))
    if stdout_bytes != collection.process.stdout_bytes() or stderr_bytes != collection.process.stderr_bytes():
        raise ValueError("流字节与绑定进程不同")
    observations, codes = [], []
    if (not collection.capture_complete or collection.cleanup_status != "CONFIRMED"
            or collection.process.truncated or collection.process.capture_failed or collection.process.timed_out
            or collection.process.start_status != "STARTED"):
        status = "REJECTED"
        codes.append("CAPTURE_OR_CLEANUP_INCOMPLETE")
    else:
        try:
            observations = _parse(diagnostic_bytes, collection)
            status = "PARSED"
            codes.append("STRUCTURED_MEMORY_OBSERVATIONS_ONLY")
        except _InvalidXML as exc:
            status = "REJECTED"
            codes.append(str(exc))
    return HarmlessDiagnosticEvidence(collection=collection, collection_sha256=pin, raw_artifacts=raw_artifacts,
        parse_status=status, diagnostic_codes=codes, observations=observations)


def reassess_harmless_diagnostic(evidence, *, expected_collection_sha256):
    evidence = HarmlessDiagnosticEvidence.model_validate(evidence.model_dump(mode="python") if hasattr(evidence, "model_dump") else evidence)
    raw = {x.identity.artifact_file: x.raw_bytes() for x in evidence.raw_artifacts}
    if len(raw) != 3:
        raise ValueError("原始证据文件重复")
    collection = evidence.collection
    try:
        rebuilt = parse_harmless_diagnostic(collection,
            diagnostic_bytes=raw[collection.diagnostic_artifact.artifact_file],
            stdout_bytes=raw[collection.stdout_artifact.artifact_file], stderr_bytes=raw[collection.stderr_artifact.artifact_file],
            expected_collection_sha256=expected_collection_sha256)
    except KeyError as exc:
        raise ValueError("缺少原始诊断字节") from exc
    if canonical_sha256(rebuilt) != canonical_sha256(evidence):
        raise ValueError("解析字段与原始诊断重新解析不一致")
    return rebuilt


def render_harmless_report(evidence):
    evidence = reassess_harmless_diagnostic(evidence, expected_collection_sha256=evidence.collection_sha256)
    c = evidence.collection
    rows = ["# 无害主机诊断离线解析报告", "", "报告语言：zh-CN。", "",
        "**SYNTHETIC：合成测试，未发生真实诊断。**" if c.domain == "SYNTHETIC" else
        "**UNVERIFIED_IMPORT：导入原始字节，未独立认证采集来源，不得改标为真实观测。**", "",
        f"- request_id / run_id：`{c.request_id}` / `{c.run_id}`；固定任务：`{c.task_id}`",
        f"- 采集记录规范 SHA-256：`{evidence.collection_sha256}`",
        f"- 平台：`{c.platform_environment_id}`；probe：{_cell(c.platform_probe_id)}",
        f"- 声明的实际目标：{_cell(c.executable.model_dump(mode='json'))}",
        f"- 声明的诊断工具：{_cell(c.diagnostic_tool.model_dump(mode='json'))}；版本：{_cell(c.diagnostic_tool_version)}",
        f"- 原始进程状态：`{c.process.end_status}`；退出码：`{c.process.returncode}`；Linux signal：`{c.process.linux_signal}`",
        f"- 采集完整：`{c.capture_complete}`；回收：`{c.cleanup_status}`；解析：`{evidence.parse_status}`", "",
        "## 原始证据与精确位置", "", "| 文件 | 字节数 | SHA-256 |", "|---|---:|---|"]
    for artifact in evidence.raw_artifacts:
        item = artifact.identity
        rows.append(f"| {item.artifact_file} | {item.size_bytes} | {item.sha256} |")
    for observation in evidence.observations:
        rows += ["", f"- 原始 XML 节点：`{observation.kind_locator.xml_node}`；错误类别：`{observation.classification}`；访问：`{observation.access_type}`。",
                 "  栈/堆、生命周期、访问大小、故障地址及特定 CVE 根因仍为 UNKNOWN；不从诊断描述推断。"]
    rows += ["", "## 状态原因与未满足条件", ""]
    rows.extend("- " + diagnostic_reason_zh(code) + "（" + _cell(code) + "）" for code in evidence.diagnostic_codes)
    rows += ["",
        "解析仅接受完整、身份一致的 XML v4 和固定 argv。拒绝原因标识对应原始格式、身份或采集完整性检查；不补造缺失栈和日志。",
        "没有已授权、经独立认证的真实采集；没有真实 CVE 目标、专项根因或修复版本差分。本报告不能证明指定 CVE。",
        "候选：NOT_EXECUTED；真实漏洞：NOT_VERIFIED。", "",
        "## 离线重建与独立复核", "", "重建只检验相同对象的内部一致性；独立复核必须另行固定 collection SHA-256，取原始 XML/stdout/stderr 重跑 parse_harmless_diagnostic。两者都不会启动进程。", ""]
    return "\n".join(rows)


def save_harmless_evidence(evidence, *, output_root="data/outputs/host_diagnostic_evidence"):
    """Write an independent no-CVE import/Synthetic archive with original bytes."""
    evidence = reassess_harmless_diagnostic(evidence, expected_collection_sha256=evidence.collection_sha256)
    c = evidence.collection
    folder = _generic_root(output_root) / c.run_id
    folder.parent.mkdir(parents=True, exist_ok=True)
    folder.mkdir(exist_ok=False)
    (folder / "raw").mkdir()
    content = {"collection.json": _json(c), "parsed.json": _json(evidence),
               "report.zh-CN.md": render_harmless_report(evidence).encode("utf-8")}
    for item in evidence.raw_artifacts:
        content["raw/" + item.identity.artifact_file] = item.raw_bytes()
    if len(content) != 6:
        raise ValueError("原始文件身份重复")
    if any(len(raw) > MAX_FILE for raw in content.values()) or sum(map(len, content.values())) > MAX_TOTAL:
        raise ValueError("序列化后的诊断记录超出离线读取上限，归档不完整")
    import json
    manifest = {"manifest_schema_version": "1.0", "report_locale": "zh-CN", "cve_id": None,
        "domain": c.domain, "request_id": c.request_id, "run_id": c.run_id,
        "collection_sha256": evidence.collection_sha256,
        "files": {name: {"sha256": digest_bytes(raw), "byte_length": len(raw)} for name, raw in sorted(content.items())}}
    for name, raw in content.items():
        _write_new(folder / name, raw)
    raw = (json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    _write_new(folder / "manifest.json", raw)
    return folder, digest_bytes(raw)


def read_harmless_evidence(directory, *, expected_manifest_sha256):
    """Verify a caller-pinned archive then reparse every original diagnostic byte."""
    folder = _generic_root(directory)
    raw = _read(folder / "manifest.json")
    if digest_bytes(raw) != expected_manifest_sha256:
        raise ValueError("无害诊断清单与独立摘要不同")
    manifest = _strict_json(raw)
    if (not isinstance(manifest, dict) or set(manifest) != {"manifest_schema_version", "report_locale", "cve_id", "domain",
            "request_id", "run_id", "collection_sha256", "files"} or manifest["manifest_schema_version"] != "1.0"
            or manifest["report_locale"] != "zh-CN" or manifest["cve_id"] is not None
            or not isinstance(manifest["files"], dict) or len(manifest["files"]) != 6):
        raise ValueError("无害诊断清单格式不支持")
    from .models.artifact_package import safe_member
    content = {}
    for name, info in manifest["files"].items():
        safe_member(name)
        if (not isinstance(info, dict) or set(info) != {"sha256", "byte_length"}
                or type(info["byte_length"]) is not int or not 0 <= info["byte_length"] <= 16777216):
            raise ValueError("无害诊断文件摘要格式错误")
        value = _read(folder / name)
        if len(value) != info["byte_length"] or digest_bytes(value) != info["sha256"]:
            raise ValueError("无害诊断原始文件缺失或篡改")
        content[name] = value
    if not {"collection.json", "parsed.json", "report.zh-CN.md"} <= set(content):
        raise ValueError("无害诊断必需记录缺失")
    c = HarmlessDiagnosticCollection.model_validate(_strict_json(content["collection.json"]))
    if (folder.name != c.run_id or manifest["domain"] != c.domain or manifest["request_id"] != c.request_id
            or manifest["run_id"] != c.run_id or manifest["collection_sha256"] != canonical_sha256(c)):
        raise ValueError("无害诊断目录、域或身份跨 run 混淆")
    expected = {"collection.json", "parsed.json", "report.zh-CN.md"} | {
        "raw/" + x.artifact_file for x in (c.diagnostic_artifact, c.stdout_artifact, c.stderr_artifact)}
    if set(content) != expected:
        raise ValueError("无害诊断包含未注册文件或缺失原始证据")
    for path in folder.rglob("*"):
        _regular_path(path)
        if not (stat.S_ISDIR(path.lstat().st_mode) or stat.S_ISREG(path.lstat().st_mode)):
            raise ValueError("无害诊断目录包含未支持的特殊文件")
    actual = {p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file()}
    if actual != expected | {"manifest.json"}:
        raise ValueError("无害诊断包含清单外文件")
    parsed = HarmlessDiagnosticEvidence.model_validate(_strict_json(content["parsed.json"]))
    if canonical_sha256(parsed.collection) != canonical_sha256(c):
        raise ValueError("解析结果与独立采集记录不同")
    rebuilt = parse_harmless_diagnostic(c, diagnostic_bytes=content["raw/" + c.diagnostic_artifact.artifact_file],
        stdout_bytes=content["raw/" + c.stdout_artifact.artifact_file], stderr_bytes=content["raw/" + c.stderr_artifact.artifact_file],
        expected_collection_sha256=manifest["collection_sha256"])
    if canonical_sha256(parsed) != canonical_sha256(rebuilt):
        raise ValueError("解析结果不符合原始三流独立重解析")
    if content["report.zh-CN.md"] != render_harmless_report(rebuilt).encode("utf-8"):
        raise ValueError("中文诊断报告无法逐字节重建")
    return rebuilt


def main(argv=None):
    configure_utf8_stdio()
    parser = argparse.ArgumentParser(description="固定 CPU 诊断准备、离线复核及显式授权的 Windows→WSL Memcheck；不执行候选")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="根据已保存只读探测形成中文阻断报告")
    prepare.add_argument("--probe-dir", required=True)
    prepare.add_argument("--probe-sha256", required=True)
    prepare.add_argument("--task", choices=sorted(DIAGNOSTIC_TASKS), required=True)
    prepare.add_argument("--output-root", default="data/outputs/host_diagnostic_preparations")
    rebuild = commands.add_parser("rebuild", help="离线逐字节重建准备报告")
    rebuild.add_argument("--directory", required=True)
    rebuild.add_argument("--expected-sha256", required=True)
    reparse = commands.add_parser("reparse", help="仅离线解析已固定的无CVE采集字节，不启动工具")
    reparse.add_argument("--collection", required=True)
    reparse.add_argument("--collection-sha256", required=True)
    reparse.add_argument("--xml", required=True)
    reparse.add_argument("--stdout", required=True)
    reparse.add_argument("--stderr", required=True)
    reparse.add_argument("--output-root", default="data/outputs/host_diagnostic_evidence")
    verify = commands.add_parser("verify", help="独立原始证据重解析并重建中文报告")
    verify.add_argument("--directory", required=True)
    verify.add_argument("--manifest-sha256", required=True)
    from .memcheck_registry import MEMCHECK_TASKS
    run = commands.add_parser("run-fixed", help="显式授权后运行注册的固定 CPU Memcheck 任务")
    run.add_argument("--task", choices=sorted(MEMCHECK_TASKS), required=True)
    run.add_argument("--authorize-fixed-memcheck", action="store_true")
    run.add_argument("--operator-id", required=True)
    run.add_argument("--authorization-reference", required=True)
    run.add_argument("--linux-project-root", required=True)
    run.add_argument("--distro", default="Ubuntu-22.04")
    run.add_argument("--wsl-user", default="pocdev")
    run.add_argument("--linux-python", default="/home/pocdev/.venvs/cuda-poc-generator/bin/python")
    run.add_argument("--output-root", default="data/outputs/fixed_memcheck")
    fixed_verify = commands.add_parser("verify-fixed", help="离线重新打开固定诊断全部原件、重解析并重建中文报告")
    fixed_verify.add_argument("--directory", required=True)
    fixed_verify.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "run-fixed":
            from .fixed_memcheck import run_fixed_memcheck_wsl
            import json
            result = run_fixed_memcheck_wsl(args.task, authorize_fixed_memcheck=args.authorize_fixed_memcheck,
                operator_id=args.operator_id, authorization_reference=args.authorization_reference,
                linux_project_root=args.linux_project_root, distro=args.distro, user=args.wsl_user,
                linux_python=args.linux_python, output_root=args.output_root)
            print(json.dumps(result,ensure_ascii=False))
            return 0 if result["effective_state"] == "COMPLETED" and result.get("parse_status") == "PARSED" else 2
        if args.command == "verify-fixed":
            from .memcheck_evidence import read_memcheck_evidence, render_memcheck_report
            evidence = read_memcheck_evidence(args.directory, expected_manifest_sha256=args.manifest_sha256)
            print(render_memcheck_report(evidence),end="")
            return 0 if evidence.parse_status == "PARSED" else 2
        if args.command == "rebuild":
            print(rebuild_preparation(args.directory, expected_preparation_sha256=args.expected_sha256), end="")
            return 0
        if args.command == "verify":
            evidence = read_harmless_evidence(args.directory, expected_manifest_sha256=args.manifest_sha256)
            print(render_harmless_report(evidence), end="")
            return 0
        if args.command == "reparse":
            collection = HarmlessDiagnosticCollection.model_validate(_strict_json(_read(args.collection)))
            evidence = parse_harmless_diagnostic(collection, diagnostic_bytes=_read(args.xml),
                stdout_bytes=_read(args.stdout), stderr_bytes=_read(args.stderr),
                expected_collection_sha256=args.collection_sha256)
            folder, digest = save_harmless_evidence(evidence, output_root=args.output_root)
            print(f"离线证据：{folder}；清单原始字节 SHA-256：{digest}；{collection.domain}；{evidence.parse_status}；NOT_VERIFIED。")
            return 0 if evidence.parse_status == "PARSED" else 2
        record = prepare_diagnostic(task_id=args.task, probe_directory=args.probe_dir, expected_probe_sha256=args.probe_sha256)
        folder = save_preparation(record, output_root=args.output_root)
        print(f"诊断准备已记录：{folder}；状态 REJECTED；真实诊断 NOT_CHECKED；NOT_EXECUTED / NOT_VERIFIED。")
        print(f"准备记录原始字节 SHA-256：{digest_bytes(_json(record))}")
        return 2
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"诊断请求处理失败：{type(exc).__name__}；启动与回收状态以独立执行记录为准。")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
