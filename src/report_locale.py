"""Versioned Chinese views of existing scientific objects; never translate raw logs."""

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from .models.lifecycle import LifecycleContract, canonical_sha256
from .oracle_evidence import _strict_json
from .oracle_report import _associate, _safe, _no_links, _read


REPORT_LOCALE = "zh-CN"
MAX_BYTES = 16 * 1024 * 1024
Kind = Literal["CLAIM", "ORACLE", "GENERATION", "PLATFORM", "EXECUTION", "HOST_PARSER", "FAILURE"]
Domain = Literal["SYNTHETIC", "DOCUMENTED_PUBLIC_REVIEW", "GENERATED_CANDIDATE_RESEARCH",
                 "READ_ONLY_CAPABILITY", "RECORDED_EXECUTION", "UNVERIFIED_IMPORT"]


def configure_utf8_stdio():
    """CLI text only; captured process/log bytes never pass through this path."""
    for stream in (sys.stdout,sys.stderr):
        if hasattr(stream,"reconfigure"):
            stream.reconfigure(encoding="utf-8",errors="backslashreplace",newline="\n")


def failure_with_legacy_zh(legacy, record=None):
    import html
    rows=_heading("执行失败与缺失证据报告")+_table([("状态","UNKNOWN"),("证据持久化","INCOMPLETE"),
        ("request",getattr(record,"request_id",None)),("run",getattr(record,"run_id",None))])
    rows += ["", "必要的通信、观测或持久化条件未满足；远端执行和回收不能据此确认。没有声明证据保存成功或漏洞触发。", "",
             "## 原始兼容诊断", "", "下列原始兼容诊断保持原文，仅用于核对，不能代替客观证据。", "", "<pre>"+html.escape(legacy)+"</pre>", ""]
    return "\n".join(rows)


class ReportFile(LifecycleContract):
    size_bytes: int = Field(ge=0, le=MAX_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ReportViewManifest(LifecycleContract):
    report_schema_version: Literal["1.0"] = "1.0"
    report_locale: Literal["zh-CN"] = "zh-CN"
    renderer_version: Literal["p3b-zh-1.0"] = "p3b-zh-1.0"
    report_kind: Kind
    source_domain: Domain = "UNVERIFIED_IMPORT"
    sources: dict[str, ReportFile]
    report: ReportFile
    integrity_scope: Literal["UNSIGNED_PRESENTATION_ONLY"] = "UNSIGNED_PRESENTATION_ONLY"

    @model_validator(mode="after")
    def filenames(self):
        if not self.sources or len(self.sources)>4 or any(
                not re.fullmatch(r"[a-z][a-z0-9_]*\.json", name) for name in self.sources):
            raise ValueError("中文报告来源名称必须是固定的安全 JSON 文件名")
        return self


def _json(value):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _table(rows):
    return ["| 项目 | 内容 |", "| --- | --- |"] + ["| " + _safe(k) + " | " + _safe(v) + " |" for k, v in rows]


def reason_zh(reason, status="UNKNOWN"):
    """Translate fixed reason codes/templates, not arbitrary evidence or model text."""
    reason = str(reason)
    fixed = {
        "objective verification method is not implemented": "必要的客观验证方法尚未实现，条件保留 UNKNOWN。",
        "evidence capture/integrity/cleanup is not complete": "证据采集、完整性或进程回收未得到完整确认，必要条件不能豁免。",
        "required evidence reference is missing": "缺少该必要条件所需的原始证据引用。",
        "plan is not pinned by the operator/trusted policy": "计划摘要未获得操作者或可信策略的独立固定，拒绝采用该计划。",
        "evidence domain conflict": "证据域发生冲突，合成数据不能升级为真实观测。",
        "tool identity conflict": "实际工具身份与已绑定的工具哈希不一致。",
        "evidence observations disagree for the same predicate": "同一谓词的多个客观观测互相冲突。",
        "contradictory necessary predicates for the same subject": "同一对象的必要条件互相矛盾，按 fail-closed 规则处理。",
        "no qualified evidence": "尚无合格的客观证据。",
        "typed equality against original structured field": "直接比较原始结构化字段：" + ("观测值与预期相同。" if status == "SATISFIED" else "观测值与预期不相同。"),
        "numeric component build in explicit [minimum, maximum) range": "按明确数字版本命名空间比较区间：" + ("符合必要范围；不等于充分验证。" if status == "SATISFIED" else "不符合必要范围，不能称为复现失败。"),
    }
    if reason in fixed:
        return fixed[reason]
    for prefix, text in (
        ("identity conflict:", "身份绑定不一致，冲突字段为"),
        ("reference identity conflict:", "证据引用的身份不一致，冲突字段为"),
        ("applicability is", "必要条件适用性尚未确认，不能自动豁免"),
        ("evidence source, method, type or scope conflict", "证据来源、采集方式、类型或适用范围不一致"),
        ("no reviewed objective CVE", "尚无独立审查通过的 CVE 专项根因或差分采集方法"),
    ):
        if reason.startswith(prefix):
            return text + "；详细原始诊断保留在结构化记录中。" + (" 字段：" + reason[len(prefix):].strip() if prefix.endswith(":") else "")
    return "该项状态为 " + status + "；现有记录不足以支持更强结论，具体原始诊断请核对绑定的结构化源记录。"


def _heading(title, domain=None):
    rows = ["# " + title, "", "报告语言：zh-CN；渲染版本：p3b-zh-1.0。", ""]
    if domain == "SYNTHETIC":
        rows += ["**SYNTHETIC：合成规则/诊断测试，不是真实实验或 CVE 复现。**", ""]
    elif domain == "UNVERIFIED_IMPORT":
        rows += ["**UNVERIFIED_IMPORT：这是导入的结构化记录，尚未独立认证采集来源。**", ""]
    rows += ["本轮未执行生成的 PoC，尚无真实 CVE 漏洞验证证据。", "真实漏洞结论：NOT_VERIFIED。报告不会授予执行许可。", ""]
    return rows


_FACTS = {
    "CVE-2022-21821": ("cuobjdump", "整数溢出；CNA 与原输入的 CWE 分类差异保留", "早于 11.6 Update 2", "11.6 Update 2"),
    "CVE-2023-0196": ("cuobjdump", "空指针解引用；公开影响为有限拒绝服务", "早于 12.1", "12.1"),
    "CVE-2024-0076": ("cuobjdump / nvdisasm", "越界读；原输入的信息泄露推测尚未被主源支持", "公告写早于 12.4；12.4 更新边界仍未知", "12.4U1"),
    "CVE-2024-0124": ("nvdisasm", "解析 ELF 时读取已释放内存", "截至 12.6U1", "12.6U2"),
    "CVE-2025-23308": ("nvdisasm", "主机侧 ELF32 REL 解析相关堆越界写；本机根因未知", "早于 13.0", "13.0"),
    "CVE-2025-23339": ("cuobjdump", "fatbin/cubin 调试信息解析相关栈越界写；本机根因未知", "早于 13.0", "13.0"),
}

# Only this reviewed core can use the curated Chinese translation. Input
# assertions remain unverified and may have platform-specific source paths.
# An arbitrary claim with a familiar CVE ID must never acquire catalog facts.
_TRANSLATION_CORE = {
    "CVE-2022-21821":"7695f23f2f2d0e96e00c123aecb3e53974d481c21a72b211762f9ef7126f6424",
    "CVE-2023-0196":"0a50da0cdd5420f8ebff5c8e8fc9fbf9b5e1b4801f9a8c2eeb0f6612a2a65333",
    "CVE-2024-0076":"a9bba4b095c133368a8bf7eab3db86ef5c3029e38ac71762294e75ad930ee04b",
    "CVE-2024-0124":"233efb07f673762bd17bcbb9147a4c32d3e9d1314c4c66aa394ca5bec7de3fe8",
    "CVE-2025-23308":"14cff02549be9cd1a11b7865be55a9b5592dea949e1e87e319ac92f0248c6d74",
    "CVE-2025-23339":"d37694563c2910dc6ac40c7b0e776f908cf90bd4958996b4a3b0031356ba73e8",
}


def render_claim_zh(claim, eligibility=None):
    from .models.oracle import VulnerabilityClaim
    claim = VulnerabilityClaim.model_validate(claim)
    core_hash=canonical_sha256(claim.model_dump(mode="json",exclude={"input_assertions"}))
    translated=core_hash==_TRANSLATION_CORE.get(claim.cve_id)
    component, mechanism, affected, fixed = (_FACTS[claim.cve_id] if translated else
        (claim.affected_component, "该声明不匹配已审查翻译档案；不得套用同编号 CVE 的既有事实。", claim.affected_version_ranges, claim.fixed_versions))
    rows = _heading("漏洞资料与环境资格审查报告")
    rows += _table([("目标 CVE", claim.cve_id), ("CWE（按来源保留）", claim.cwe),
        ("受影响组件", component), ("公开资料支持的机制", mechanism), ("厂商 Toolkit 发布范围", affected),
        ("厂商更新版本", fixed), ("事实层级", claim.fact_status), ("结构化资料 SHA-256", canonical_sha256(claim)),
        ("当前验证资格", eligibility or "UNKNOWN"), ("真实 CVE 验证", "NOT_VERIFIED")])
    rows += ["", "## 来源与适用范围", "", "下列资料仅属于 DOCUMENTED 文献支持，不是本机漏洞触发证据。工具 build、Toolkit 发布版本、驱动版本分开解释。", ""]
    for source in claim.sources:
        rows += _table([("来源身份", source.source_id), ("来源类别", source.kind), ("原始来源", source.url),
                        ("资料字节 SHA-256（未测量则为空）", source.content_sha256), ("检索日期", source.retrieved_at)]) + [""]
    rows += ["## 缺失证据与阻断条件", "", "尚未取得可信受影响/修复版本的本机对照、精确输入路径、客观错误位置及根因绑定。公开测试 build 不代表任意同系列 build 均已验证。", "原七维断言及英文资料原文在结构化附件中保留，不将模型推测升级为事实。", ""]
    rows += _table([("未解决事项数量", len(claim.unknowns)), ("未验证输入字段数量", len(claim.input_assertions)),
                    ("执行状态", "NOT_EXECUTED"), ("真实漏洞结论", "NOT_VERIFIED")])
    rows += ["", "## 独立复核", "", "本报告可从同一 claim.json 离线逐字节重建。独立资料复核需重新核对来源与其适用范围；重建文本不等于验证资料真实性或复现漏洞。", ""]
    return "\n".join(rows)


def render_oracle_zh(plan, result, claim=None):
    plan, result, claim = _associate(plan, result, claim)
    rows = _heading("目标 CVE 客观条件审查报告", result.domain)
    rows += _table([("目标 CVE", result.cve_id), ("计划身份", plan.oracle_id), ("计划 SHA-256", result.plan_sha256),
        ("原证据清单 SHA-256", result.corpus_manifest_sha256), ("环境资格", result.eligibility.status),
        ("条件总结果", result.condition_status), ("规则结论", result.verdict), ("真实 CVE 验证", result.real_cve_verification)])
    if result.verdict == "VERIFIED":
        rows += ["", "**此 VERIFIED 仅证明 SYNTHETIC 规则满足，不能当作真实 CVE 成功。**"]
    results = {r.condition_id:r for r in result.conditions}
    labels = {"ENVIRONMENT":"环境与版本", "IDENTITY":"输入与工具身份", "ENTRY_BEHAVIOR":"目标入口与行为", "ANOMALY":"客观异常", "ROOT_CAUSE":"专项根因"}
    rows += ["", "## 条件与客观证据", ""]
    for condition in plan.conditions:
        assessment = results[condition.condition_id]
        rows += ["### " + condition.condition_id, ""] + _table([
            ("条件类别", labels[condition.category]), ("必要条件", condition.required), ("适用性", condition.applicability),
            ("判定状态", assessment.status), ("中文解释", reason_zh(assessment.reason, assessment.status)),
            ("预期技术值", condition.expected_value), ("数值范围", [condition.minimum_inclusive, condition.maximum_exclusive]),
            ("客观观测值", assessment.observed_values), ("证据引用", assessment.reference_ids)]) + [""]
    rows += ["## 精确证据引用", ""]
    for ref in plan.references:
        rows += _table([("引用身份", ref.reference_id), ("request / run", [ref.request_id, ref.run_id]),
            ("原始文件", ref.artifact_file), ("原始字节 SHA-256", ref.artifact_sha256), ("结构化位置", ref.json_pointer),
            ("原始来源", ref.original_source), ("采集器", ref.collection_method), ("观测平台", ref.platform_environment_id),
            ("平台探测身份", ref.platform_probe_id), ("工具角色与 SHA-256", [ref.tool_role, ref.tool_sha256]),
            ("输入 SHA-256", ref.candidate_sha256), ("适用范围", ref.scope)]) + [""]
    rows += ["## 实测环境与限制", "", "以下技术字段来自原有结构化观测；历史快照不表示当前机器状态。", ""]
    rows += _table([("原始环境观测字段", result.observed_context)])
    rows += ["", "## 为什么当前不能证明指定 CVE", "", "固定无害 smoke 只有 TOOLCHAIN_SMOKE 适用范围。退出 0、非零退出、崩溃、信号或内存诊断均不足以证明指定根因；缺失必要证据、身份冲突、方法未实现时保持 UNKNOWN 或 NOT_VERIFIED。P3-A/P3-B 不开放真实 VERIFIED。", "", "## 离线重建与独立重评估", "", "离线重建只检查相同科学对象与确定性渲染。独立重评估须另取原始证据及独立固定的 plan/manifest 摘要，并重新运行 Oracle。哈希索引不是签名。", ""]
    if claim is not None:
        rows += ["## 文献来源", ""] + _table([(s.source_id, s.url) for s in claim.sources]) + [""]
    return "\n".join(rows)


def render_generation_zh(record):
    from .models.generation import CandidateResult
    if not isinstance(record, dict) or record.get("execution") != "NOT_EXECUTED" or record.get("verification") != "NOT_VERIFIED":
        raise ValueError("生成报告必须保留 NOT_EXECUTED / NOT_VERIFIED")
    candidate = CandidateResult.model_validate(record["candidate"])
    if candidate.run_id != record.get("run_id"):
        raise ValueError("生成轮次身份不一致")
    reasons = {"COMPLETE":"候选生成阶段完成；静态检查与真实执行、漏洞验证相互独立。", "INPUT_INVALID":"七维输入存在结构或一致性错误，已阻止分析与生成。", "PLATFORM_PROBE_FAILED":"未取得合格平台观测，已阻止后续请求。", "PROVIDER_ERROR":"模型供应商请求失败；没有把失败分析传给生成器。", "GENERATION_FAILED":"候选生成或保存失败；不得宣称存在有效执行或验证证据。"}
    rows = _heading("PoC 单次生成与分析报告") + _table([
        ("目标 CVE", record.get("cve_id")), ("生成轮次", record.get("run_id")), ("生成流程状态", record.get("status")),
        ("状态说明", reasons.get(record.get("status"), "分析结构校验或流程条件未满足；请核对错误类别和绑定原始响应。")),
        ("输入状态", record.get("input_status")), ("分析结构状态", record.get("analysis_status")),
        ("候选状态", candidate.generation), ("静态检查", candidate.static), ("原始记录 SHA-256", canonical_sha256(record)),
        ("产物引用", record.get("artifacts", {})), ("错误类别", record.get("error_type")),
        ("执行状态", candidate.execution), ("漏洞状态", candidate.verification)])
    rows += ["", "## 证据与能力边界", "", "LLM 分析与代码均为候选研究材料。AST 和名称启发检查不能证明可导入、可编译、可执行或触发漏洞。模型输出原文保持原始字节，不翻译为客观事实。失败诊断保存在源记录，不编造日志或占位执行结果。", ""]
    return "\n".join(rows)


def render_platform_zh(result, *, source_domain="UNVERIFIED_IMPORT"):
    from .models.platform import PlatformSnapshot
    rows = _heading("Windows / WSL 只读平台观测报告",source_domain) + _table([("探测状态", result.get("status")), ("探测身份", result.get("probe_id"))])
    for name, snapshot in (("开发宿主", result.get("host_snapshot")), ("选定目标", result.get("snapshot"))):
        rows += ["", "## " + name, ""]
        if snapshot is None:
            rows += ["没有可用的已校验快照；不能将 Windows 信息替代 WSL 信息。", ""]
            continue
        snapshot = PlatformSnapshot.model_validate(snapshot)
        rows += _table([("平台", snapshot.platform_type), ("后端", snapshot.execution_backend), ("环境身份", snapshot.environment_id)])
        for key in ("host_os", "kernel", "architecture", "python_version", "driver_release", "cuda_toolkit_version", "nvcc_version", "supported_architectures"):
            field = getattr(snapshot, key)
            rows += _table([(key, {"status":field.status, "value":field.value, "source_ids":field.source_ids})])
    rows += ["", "## 未知项与诊断", ""]
    for diag in result.get("diagnostics", []):
        rows += _table([("诊断标识", diag.get("code")), ("原因", "该项只读观测或通信未取得合格结果；相关字段保留 UNKNOWN/FAILED，不采用默认值伪装实测。")])
    rows += ["", "工具版本查询不等于编译或诊断效果验证；终止 Windows launcher 也不能证明 Linux 子进程已回收。原始日志和命令字节保持不变。", ""]
    return "\n".join(rows)


def render_execution_zh(record, manifest, *, source_domain="UNVERIFIED_IMPORT"):
    from .models.lifecycle import ExecutionRecord, EvidenceManifest
    record, manifest = ExecutionRecord.model_validate(record), EvidenceManifest.model_validate(manifest)
    if (manifest.request_id, manifest.run_id, manifest.execution_record_sha256) != (record.request_id, record.run_id, canonical_sha256(record)):
        raise ValueError("执行记录和原始证据清单不一致")
    rows = _heading("受控无害动作执行与原始证据报告",source_domain) + _table([
        ("request / run", [record.request_id,record.run_id]), ("固定动作", record.action_id), ("授权引用", record.authorization_reference),
        ("远端状态", record.status), ("有效状态", manifest.effective_status), ("目标环境", record.target_environment),
        ("环境身份", record.platform_environment_id), ("实际工具身份", record.tool_identity.model_dump(mode="json")),
        ("回收确认", manifest.cleanup_confirmation), ("完整采集", manifest.capture_complete), ("截断", manifest.truncated),
        ("原始文件索引", {k:v.model_dump(mode="json") for k,v in manifest.artifacts.items()})])
    if record.process is not None:
        p=record.process
        rows += ["", "## 实际进程状态与资源界限", ""] + _table([
            ("PID / 进程组", [p.pid,p.pgid]), ("原始退出码",p.returncode), ("Linux signal",p.linux_signal),
            ("超时",p.timed_out), ("取消",p.cancelled), ("输出截断",p.truncated), ("采集失败",p.capture_failed),
            ("实际实施的资源界限",p.resources.model_dump(mode="json")), ("清理观测",p.cleanup.model_dump(mode="json")),
            ("开始时间",record.started_at), ("结束时间",record.finished_at)])
    if record.cuda_smoke is not None:
        rows += ["", "## 固定 CUDA 工具步骤", ""]
        for step in record.cuda_smoke.steps:
            rows += _table([(step.step_id,{"state":step.state,"returncode":step.process.returncode,
                "linux_signal":step.process.linux_signal,"timed_out":step.process.timed_out,
                "truncated":step.process.truncated,"cleanup":step.process.cleanup.status,
                "tool_identity":step.process.tool_identity.model_dump(mode="json")})])
    rows += ["", "## 状态原因与限制", "", "有效状态同时取决于实际进程状态、证据采集和独立回收检查。无法确认执行或回收时保留 UNKNOWN/CLEANUP_FAILED；普通非零退出或信号不是 CVE 证据。", "", "## 生命周期", ""]
    rows += _table([(str(event.sequence), {"state":event.state, "observed_at":event.observed_at}) for event in record.events])
    rows += ["", "固定无害动作未执行生成候选。没有 GPU 驱动安全隔离、完整网络隔离或恶意程序沙箱承诺。原始 stdout/stderr 保持字节不变。", ""]
    return "\n".join(rows)


def _render(kind, sources, source_domain="UNVERIFIED_IMPORT"):
    values = {name:_strict_json(raw) for name,raw in sources.items()}
    expected = {"CLAIM":{"claim.json"}, "ORACLE":{"plan.json","result.json"}, "GENERATION":{"generation.json"},
                "PLATFORM":{"platform.json"}, "EXECUTION":{"execution_record.json","manifest.json"},
                "HOST_PARSER":{"host_parser.json"}, "FAILURE":{"failure.json"}}[kind]
    if not expected <= set(values) or set(values) - expected - ({"claim.json"} if kind == "ORACLE" else set()):
        raise ValueError("中文报告源文件集合不受支持")
    if kind == "CLAIM": return render_claim_zh(values["claim.json"])
    if kind == "ORACLE": return render_oracle_zh(values["plan.json"],values["result.json"],values.get("claim.json"))
    if kind == "GENERATION": return render_generation_zh(values["generation.json"])
    if kind == "PLATFORM": return render_platform_zh(values["platform.json"],source_domain=source_domain)
    if kind == "EXECUTION": return render_execution_zh(values["execution_record.json"],values["manifest.json"],source_domain=source_domain)
    if kind == "HOST_PARSER":
        from .host_parser_report import render_host_parser_report_zh
        return render_host_parser_report_zh(values["host_parser.json"])
    failure = values["failure.json"]
    return "\n".join(_heading("实验失败与缺失证据报告") + _table([("状态",failure.get("status","UNKNOWN")),
        ("错误类别",failure.get("error_type")), ("原始诊断标识",failure.get("diagnostic_codes",[])),
        ("原始源记录清单 SHA-256",failure.get("original_manifest_sha256")),
        ("中文解释","必要的输入、工具、身份、资源或持久化前提尚未得到确认；原始诊断标识定位具体未满足项。只有前置探测不等于执行，不能声明成功或完整验证。")]) + [""])


def write_report_view(directory, kind: Kind, sources: dict[str, bytes], *, report_locale="zh-CN", source_domain: Domain="UNVERIFIED_IMPORT"):
    if report_locale != "zh-CN":
        raise ValueError("当前仅支持 report_locale=zh-CN")
    if not sources or any("/" in name or "\\" in name or not name.endswith(".json") or type(raw) is not bytes or len(raw)>MAX_BYTES for name,raw in sources.items()):
        raise ValueError("中文报告只接收有界的固定名 JSON 原始字节")
    derived=None
    if kind=="ORACLE" and "result.json" in sources:
        derived="SYNTHETIC" if _strict_json(sources["result.json"]).get("domain")=="SYNTHETIC" else "RECORDED_EXECUTION"
    elif kind=="HOST_PARSER" and "host_parser.json" in sources:
        derived="SYNTHETIC" if _strict_json(sources["host_parser.json"]).get("collection",{}).get("domain")=="SYNTHETIC" else "UNVERIFIED_IMPORT"
    elif kind=="GENERATION":
        derived="GENERATED_CANDIDATE_RESEARCH"
    elif kind=="CLAIM" and "claim.json" in sources:
        data=_strict_json(sources["claim.json"])
        core={key:value for key,value in data.items() if key!="input_assertions"}
        derived="DOCUMENTED_PUBLIC_REVIEW" if canonical_sha256(core)==_TRANSLATION_CORE.get(data.get("cve_id")) else "UNVERIFIED_IMPORT"
    if derived is not None:
        if source_domain not in {"UNVERIFIED_IMPORT",derived}:
            raise ValueError("报告来源域不得覆盖原科学对象的 Synthetic/真实边界")
        source_domain=derived
    raw_report = _render(kind, sources, source_domain).encode("utf-8")
    ref = lambda raw: ReportFile(size_bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    manifest = ReportViewManifest(report_kind=kind, source_domain=source_domain, sources={name:ref(raw) for name,raw in sources.items()}, report=ref(raw_report))
    folder = _no_links(directory)
    folder.mkdir(parents=True,exist_ok=False,mode=0o700)
    (folder/"sources").mkdir(mode=0o700)
    content = {"sources/"+name:raw for name,raw in sources.items()}
    content.update({"report.zh-CN.md":raw_report,"report_view_manifest.json":_json(manifest)})
    for name,raw in content.items():
        fd=os.open(folder/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    return folder


def rebuild_report_view(directory):
    folder=_no_links(directory)
    manifest=ReportViewManifest.model_validate(_strict_json(_read(folder/"report_view_manifest.json",65536)))
    if set(p.name for p in folder.iterdir())!={"sources","report.zh-CN.md","report_view_manifest.json"}:
        raise ValueError("中文报告目录存在缺失或额外文件")
    if set(p.name for p in (folder/"sources").iterdir())!=set(manifest.sources):
        raise ValueError("中文报告源文件集合不一致")
    sources={}
    for name,ref in manifest.sources.items():
        if "/" in name or "\\" in name or not name.endswith(".json"):
            raise ValueError("中文报告源路径非法")
        raw=_read(folder/"sources"/name,MAX_BYTES)
        if len(raw)!=ref.size_bytes or hashlib.sha256(raw).hexdigest()!=ref.sha256:
            raise ValueError("中文报告源文件哈希或长度不一致")
        sources[name]=raw
    rendered=_render(manifest.report_kind,sources,manifest.source_domain)
    raw=_read(folder/"report.zh-CN.md",MAX_BYTES)
    if raw!=rendered.encode() or len(raw)!=manifest.report.size_bytes or hashlib.sha256(raw).hexdigest()!=manifest.report.sha256:
        raise ValueError("中文报告不是原科学对象的确定性渲染")
    return rendered


def save_localized_oracle_report(directory, plan, result, claim=None, *, report_locale="zh-CN"):
    plan,result,claim=_associate(plan,result,claim)
    sources={"plan.json":_json(plan),"result.json":_json(result)}
    if claim is not None: sources["claim.json"]=_json(claim)
    return write_report_view(directory,"ORACLE",sources,report_locale=report_locale,
                             source_domain="SYNTHETIC" if result.domain=="SYNTHETIC" else "RECORDED_EXECUTION")


def write_execution_view_from_archive(folder, *, source_domain: Domain="UNVERIFIED_IMPORT"):
    """Read a verified legacy archive; publish only a separate Chinese view."""
    from .lifecycle_artifacts import read_execution_evidence, read_cuda_readiness_evidence
    from .execution_artifacts import read_execution_evidence as read_legacy_readiness
    folder=Path(folder)
    destination=folder.parent/"report_views"/(folder.name+"-zh-CN")
    if (folder/"execution_record.json").is_file():
        context=read_execution_evidence(folder)
        return write_report_view(destination,"EXECUTION",{
            "execution_record.json":(folder/"execution_record.json").read_bytes(),
            "manifest.json":(folder/"manifest.json").read_bytes()},source_domain=source_domain)
    if (folder/"readiness_manifest.json").is_file():
        context=read_cuda_readiness_evidence(folder)
        description=context.get("description")
        status=getattr(description,"status","UNKNOWN")
        codes=getattr(description,"diagnostics",[]) if description is not None else context.get("diagnostics",[])
    else:
        context=read_legacy_readiness(folder)
        packet=context.get("packet") or {}
        status=packet.get("status","UNKNOWN")
        codes=packet.get("diagnostics",[])
    return write_report_view(destination,"FAILURE",{"failure.json":_json({"status":status,
        "error_type":"READINESS_ONLY_NO_CANDIDATE_EXECUTION", "diagnostic_codes":codes, "original_manifest_sha256":hashlib.sha256(
            (folder/("readiness_manifest.json" if (folder/"readiness_manifest.json").exists() else "manifest.json")).read_bytes()).hexdigest()})})
