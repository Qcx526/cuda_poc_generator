"""Deterministic zh-CN view of bound host diagnostics, never a new evidence source."""

from .host_parser_evidence import reassess_host_parser_evidence
from .host_parser_oracle import evaluate_host_parser_requirements


_REASONS = {
    "EXACT_AFFECTED_BUILD_AND_TRUSTED_VERSION_RECORD_REQUIRED": "尚需准确受影响 build 与可信版本记录；工具身份不证明该 build 已公开验证。",
    "INPUT_BYTES_AND_FORMAT_PROFILE_NOT_INDEPENDENTLY_VERIFIED": "输入身份与格式声明已保留，但没有独立核验输入字节和专项结构。",
    "XML_ARGUMENTS_MATCH_PINNED_COLLECTION_ONLY": "原始 XML 中的目标与输入调用参数匹配采集记录；仅支持路径观测。",
    "QUALIFIED_XML_ARGUMENTS_UNAVAILABLE": "没有完整、匹配且受支持的 XML 调用路径观测。",
    "INVALID_WRITE_OBSERVED_WITH_REGION_AND_ROOT_CAUSE_UNKNOWN": "XML kind 明确记录无效写；堆/栈、访问大小和指定 CVE 根因仍未知。",
    "NO_QUALIFIED_INVALID_WRITE_OBSERVATION": "未获得合格的结构化无效写观测；退出码或 signal 不能替代它。",
    "REGION_ACCESS_SIZE_AND_PUBLIC_ROOT_CAUSE_BINDING_UNIMPLEMENTED": "尚未实现异常区域、大小、位置与公开漏洞机制的独立绑定。",
    "ROOT_CAUSE_AND_FIXED_BUILD_DIFFERENTIAL_UNIMPLEMENTED": "尚未实现根因确认，以及同一根因下受影响与修复 build 的充分差分。",
}
_PARSER = {
    "STRUCTURED_MEMCHECK_OBSERVATIONS_ONLY": "仅解析明确支持的 Memcheck 结构化观测。",
    "LINUX_SIGNAL_IS_NOT_CVE_PROOF": "记录了 Linux signal；它不证明指定 CVE。",
    "NO_STRUCTURED_MEMORY_ERROR_OBSERVED": "记录中没有结构化内存错误；不能据此证明输入安全或漏洞不存在。",
    "DIAGNOSTIC_FORMAT_NOT_IMPLEMENTED": "该诊断格式尚未实现，保留原始字节并拒绝推断。",
    "CAPTURE_OR_CLEANUP_INCOMPLETE": "采集、超时或回收状态不完整，拒绝解释诊断。",
    "XML_SIZE_LIMIT": "XML 超过解析长度上限。",
    "XML_UTF8_REQUIRED": "XML 不符合支持的 UTF-8 格式。",
    "XML_DTD_OR_ENTITY_FORBIDDEN": "XML 含禁止的 DTD 或实体声明。",
    "XML_MALFORMED_OR_TRUNCATED": "XML 损坏或截断，不能继续推断。",
    "XML_UNSUPPORTED_ROOT": "XML 根节点或命名空间不受支持。",
    "XML_STRUCTURE_LIMIT": "XML 深度或节点数超过上限。",
    "XML_UNSUPPORTED_NODE_PROFILE": "XML 节点或属性不符合支持的格式。",
    "XML_UNSUPPORTED_PROTOCOL": "XML 协议版本或诊断工具不受支持。",
    "XML_PROCESS_ID_CONFLICT": "XML PID 与采集记录不一致。",
    "XML_MISSING_FINISHED": "XML 缺少最终 FINISHED，不能证明采集完整。",
    "XML_UNSUPPORTED_PROCESS_STATE": "XML 包含不支持的进程状态。",
    "XML_DUPLICATE_FINISHED": "XML 含重复完成标记，拒绝解释。",
    "XML_REQUIRED_OR_DUPLICATE_ARGS": "XML 调用参数节点缺失或重复。",
    "XML_REQUIRED_OR_DUPLICATE_ARGV": "XML 程序参数节点缺失或重复。",
    "XML_INVALID_ARGUMENT": "XML 含无效参数节点。",
    "XML_ARGUMENT_LIMIT": "XML 参数数目超过上限。",
    "XML_TOOL_OR_INPUT_IDENTITY_CONFLICT": "XML 工具或输入身份与采集记录冲突。",
    "XML_ERROR_LIMIT": "XML 错误条数超过上限。",
    "XML_INVALID_OR_DUPLICATE_ERROR_ID": "XML 错误标识无效或重复。",
    "XML_DUPLICATE_XWHAT": "XML 描述节点重复。",
    "XML_FRAME_LIMIT": "XML 栈帧数超过上限。",
    "XML_INVALID_FRAME_LINE": "XML 栈帧行号不是合格整数。",
    "XML_INVALID_INSTRUCTION_POINTER": "XML 栈帧指令指针不符合支持的格式。",
}


def _cell(value):
    if value is None:
        return "未知（UNKNOWN）"
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace(
        "\\", "\\\\").replace("|", "\\|").replace("`", "\\`").replace("\r", "").replace("\n", " ↵ ")


def _parser_reason(code):
    if code in _PARSER:
        return _PARSER[code]
    if code.startswith("XML_REQUIRED_OR_DUPLICATE_NODE:"):
        return "XML 必需节点缺失或重复：" + _cell(code.split(":", 1)[1]) + "。"
    if code.startswith("XML_INVALID_SCALAR_NODE:"):
        return "XML 标量节点无效：" + _cell(code.split(":", 1)[1]) + "。"
    return "该状态未具备可解释的合格诊断，保留 UNKNOWN；错误代码为 " + _cell(code) + "。"


def render_host_parser_report_zh(evidence, *, expected_collection_sha256=None, report_locale="zh-CN") -> str:
    """Reproduce a Chinese view; optional independent pin adds identity checking.

    With no external pin this checks self-contained consistency, not collector
    authenticity. Original XML/stdout/stderr bytes are never translated.
    """
    if report_locale != "zh-CN":
        raise ValueError("unsupported report_locale; only zh-CN is registered")
    # Do not trust caller-supplied classifications or stack frames.
    from .models.host_parser import HostParserEvidence
    evidence = HostParserEvidence.model_validate(evidence)
    pin = expected_collection_sha256 if expected_collection_sha256 is not None else evidence.collection_sha256
    evidence = reassess_host_parser_evidence(evidence, expected_collection_sha256=pin)
    collection = evidence.collection
    assessment = evaluate_host_parser_requirements(evidence, expected_collection_sha256=pin,
                                                   expected_cve_id=collection.cve_id)
    synthetic = collection.domain == "SYNTHETIC"
    lines = ["# CUDA 主机侧诊断证据报告", "", "报告语言：`zh-CN`；渲染版本：`p3b-host-report-zh-1.0`。", "",
        "**SYNTHETIC 合成测试：以下记录不是真实程序或真实 CVE 实验。**" if synthetic else
        "**导入观测：生产采集器未认证，不能将此文件当作可信 CVE 执行证明。**", "",
        "**本轮未执行生成的 PoC，尚无真实 CVE 漏洞验证证据。**", "",
        "## 目标与身份", "", "| 项目 | 值 |", "|---|---|",
        "| 目标 CVE | " + collection.cve_id + " |",
        "| 数据域 | " + collection.domain + " |",
        "| request / run | " + collection.request_id + " / " + collection.run_id + " |",
        "| 平台 / probe | " + collection.platform_environment_id + " / " + _cell(collection.platform_probe_id) + " |",
        "| 平台快照 SHA-256 | " + collection.snapshot_sha256 + " |",
        "| 宿主程序 | " + collection.target.component + " / " + _cell(collection.target.executable.resolved_path) + " |",
        "| 宿主程序 SHA-256 | " + collection.target.executable.file_sha256 + " |",
        "| build 声明及来源状态 | " + _cell(collection.target.build) + " / " + collection.target.build_status + " |",
        "| 版本记录 SHA-256 | " + _cell(collection.target.version_record_sha256) + " |",
        "| 输入 | " + _cell(collection.input.file.original_path) + " |",
        "| 输入 SHA-256 / 字节数 | " + collection.input.file.sha256 + " / " + str(collection.input.file.size_bytes) + " |",
        "| 容器 / 负载 / 格式状态 | " + collection.input.container_format + " / " + collection.input.payload_format + " / " + collection.input.format_status + " |",
        "| 采集记录 SHA-256 | " + evidence.collection_sha256 + " |", "",
        "公开资料来源与准确受影响 build 应另行对照阶段可行性矩阵；本诊断记录不创造漏洞事实。容器、负载、调试和重定位格式不能互相替代。", "",
        "## 诊断能力、进程与回收", "", "| 项目 | 值 |", "|---|---|",
        "| 诊断工具 | " + _cell(collection.diagnostic_tool.resolved_path) + " |",
        "| 诊断版本声明 / 来源状态 / SHA-256 | " + _cell(collection.diagnostic_tool_version) + " / " + collection.diagnostic_tool_version_status + " / " + collection.diagnostic_tool.file_sha256 + " |",
        "| 格式 / 采集器 | " + collection.diagnostic_format + " / " + collection.collector + " |",
        "| 进程 PID / 状态 | " + str(collection.observed_pid) + " / " + collection.process.end_status + " |",
        "| 退出码 / Linux signal | " + _cell(collection.process.returncode) + " / " + _cell(collection.process.linux_signal) + " |",
        "| 采集完整 / 回收 | " + ("是" if collection.capture_complete else "否") + " / " + collection.cleanup_status + " |",
        "| 解析状态 | " + evidence.parse_status + " |",
        "| 生产资格 | UNSUPPORTED |", "",
        "安装或版本输出不等于诊断效果已验证；RLIMIT_AS 不是 GPU 显存限制。当前没有目标漏洞授权执行、驱动安全隔离或不可信输入沙箱。", ""]
    for code in evidence.diagnostic_codes:
        lines.append("- " + _parser_reason(code) + "（`" + code + "`）")
    lines.extend(["", "## 原始证据索引", "", "| 文件 | 字节数 | SHA-256 |", "|---|---:|---|"])
    for item in evidence.raw_artifacts:
        lines.append("| " + _cell(item.identity.artifact_file) + " | " + str(item.identity.size_bytes) + " | " + item.identity.sha256 + " |")
    lines.extend(["", "原始 XML、stdout、stderr 保留原始字节；报告不翻译或重写它们。哈希只检测内容一致性，不是来源签名。", "",
                  "## 结构化错误与精确位置", ""])
    if not evidence.observations:
        lines.append("没有可报告的合格结构化内存错误。退出状态不能代替指定漏洞的内存和根因证据。")
    for index, item in enumerate(evidence.observations, 1):
        lines.extend(["### 观测 " + str(index), "", "| 项目 | 值 |", "|---|---|",
            "| XML 错误类型 / 分类 | " + _cell(item.source_kind) + " / " + item.classification + " |",
            "| 访问类型 | " + item.access_type + " |",
            "| 故障地址 / 大小 / 堆栈区域 / 生命周期 | UNKNOWN / UNKNOWN / UNKNOWN / UNKNOWN |",
            "| 原始节点 | " + _cell(item.kind_locator.xml_node) + " |",
            "| 原始文件 SHA-256 | " + item.kind_locator.artifact_sha256 + " |",
            "| 未解释的原始描述 | " + _cell(item.description_original) + " |", "",
            "| 栈帧原始节点 | 指令指针 | 对象 / 函数 | 文件 / 行号 |", "|---|---|---|---|"])
        for frame in item.frames:
            lines.append("| " + _cell(frame.locator.xml_node) + " | " + _cell(frame.instruction_pointer) +
                " | " + _cell(frame.object_file) + " / " + _cell(frame.function) + " | " +
                _cell(frame.file) + " / " + _cell(frame.line) + " |")
        lines.extend(["", "只保留实际 XML 字段；缺失栈帧信息不补全。指令指针不是故障访问地址。", ""])
    lines.extend(["## A～F 必要条件与未知项", "", "| 条件 | 结果 | 方法 | 中文解释 |", "|---|---|---|---|"])
    for item in assessment.requirements:
        lines.append("| " + item.requirement_id + "：" + item.description + " | " + item.status + " | " + item.method_status +
                     " | " + _REASONS[item.reason_code] + " |")
    lines.extend(["", "## 结论与后续阻断条件", "",
        "**目标 CVE 判定：NOT_VERIFIED；验证资格：UNKNOWN。**", "",
        "无效写、普通 crash、SIGSEGV、Sanitizer 异常或正常退出均不足以证明指定 CVE。A/B/E/F 缺失，且没有已审查的生产专项采集器，因此不能升级真实漏洞结论。", "",
        "后续需要准确受影响与修复 build 的可信二进制及版本记录、原始输入的独立格式检查、真实受限采集、客观堆/栈区域与位置关联、同一根因绑定及充分差分。还需独立授权和适合风险的隔离条件；本模块不执行这些操作。", "",
        "离线报告重建只是同一结构化结果的中文视图；独立重评估从原始 XML 重新解析并检查派生字段。两者都不能把合成数据或未认证导入提升成真实漏洞证明。", ""])
    return "\n".join(lines)
