"""Read-only import and portable CVE desk-review packages; never CVE execution.

Only the reviewed catalog import is registered in v1. Arbitrary directories,
Synthetic data and generic smoke cannot be relabeled as CVE experiments.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import uuid
import zipfile
from contextlib import contextmanager

from .models.artifact_package import (ArtifactCategory, ArtifactFile, ArtifactManifest,
    CATEGORIES, CVE_PATTERN, PackageVerification, RUN_PATTERN, SHA_PATTERN, safe_member)
from .models.lifecycle import canonical_sha256
from .models.oracle import VulnerabilityClaim
from .models.generation import CandidateResult
from .models.normalized_input import NormalizedInput
from .oracle_catalog import ROOT, load_reviewed_claim
from .oracle_evidence import _strict_json

MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MISSING = ["未执行生成的 PoC；没有目标 CVE_TRIGGER 执行记录。",
           "没有指定 CVE 的根因绑定或修复版本差分证据。",
           "公开资料引用是 DOCUMENTED 来源，不是本机漏洞实测。"]


def _bytes(value):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _ids(cve_id, run_id):
    if not isinstance(cve_id, str) or not re.fullmatch(CVE_PATTERN, cve_id):
        raise ValueError("CVE ID 非法；禁止路径或任意目录名")
    if not isinstance(run_id, str) or not re.fullmatch(RUN_PATTERN, run_id):
        raise ValueError("run_id 必须是唯一的 32 位小写十六进制 ID")


def _regular_path(path):
    """Reject POSIX symlinks and Windows reparse points in every ancestor."""
    path = Path(path).absolute()
    for item in (path, *path.parents):
        try:
            observed = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(observed.st_mode) or getattr(observed, "st_file_attributes", 0) & 0x400:
            raise ValueError("拒绝符号链接或 Windows 重解析点：" + str(item))
    return path


def _read(path, maximum=MAX_FILE):
    path = _regular_path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise ValueError("输入必须是长度受限的普通文件")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("读取时文件身份发生变化")
        raw = stream.read(maximum + 1)
    after = path.lstat()
    if len(raw) > maximum or len(raw) != before.st_size or (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
        raise ValueError("文件在读取时被替换、截断或修改")
    return raw


def _write_new(path, raw):
    path = _regular_path(path)
    with path.open("xb") as stream:
        if stream.write(raw) != len(raw):
            raise OSError("归档文件写入不完整")
        stream.flush()
        os.fsync(stream.fileno())


@contextmanager
def _locked(cve_dir):
    cve_dir = _regular_path(cve_dir)
    cve_dir.mkdir(parents=True, exist_ok=True)
    lock = cve_dir / ".packaging.lock"
    # Exclusive creation prevents concurrent index updates and overwrite races.
    with lock.open("xb") as stream:
        stream.write(b"p3b-review-packager/1.0\n")
        stream.flush()
        os.fsync(stream.fileno())
    try:
        yield
    finally:
        lock.unlink()


def _claim_report(claim):
    from .report_locale import render_claim_zh
    return render_claim_zh(claim)


def _readme(cve_id, run_id, claim_sha):
    return (f"# {cve_id} 中文资料审查入口\n\n"
        f"本轮 ID：`{run_id}`。报告语言：`zh-CN`。包类型：`RESEARCH_ONLY`。\n\n"
        "本轮未执行生成的 PoC，尚无真实 CVE 漏洞验证证据。\n\n"
        "候选执行状态：`NOT_EXECUTED`；真实漏洞判定：`NOT_VERIFIED`。\n\n"
        "| 路径 | 用途及边界 |\n|---|---|\n"
        "| `input/` | 原始七维 JSON 的逐字节副本，属于未复核输入声明 |\n"
        "| `analysis/vulnerability_claim.json` | 已审查公开来源及未知项，非实测结论 |\n"
        "| `evidence/public_source_references.json` | 公开资料引用元数据；未伪造全文或实验日志 |\n"
        "| `reports/review.zh-CN.md` | 从结构化资料确定性生成的中文审查报告 |\n"
        "| `artifact_manifest.json` | 相对路径、原始字节哈希、大小及来源身份 |\n\n"
        "`poc/`、`execution/` 尚未执行；`oracle/` 未产生新的判定。"
        "ZIP 不包含这些类别的虚构日志。空目录可能不显示于 ZIP。\n\n"
        f"资料声明规范哈希：`{claim_sha}`。ZIP 自身 SHA-256 位于包外 `index.json`。\n\n"
        "SHA-256 仅核对完整性，不构成来源认证或漏洞证明。公开资料的适用性、"
        "准确受影响 build、根因和隔离条件仍需独立审查。\n").encode("utf-8")


def _categories():
    descriptions = {
        "input": ("PRESENT", "已复制七维原始输入，字节哈希不变；不是漏洞实测事实。"),
        "analysis": ("PRESENT", "已有来源审查声明；保留未知项。"),
        "poc": ("NOT_EXECUTED", "本轮未生成或执行 PoC。"),
        "execution": ("NOT_EXECUTED", "没有真实 CVE 工具执行或生命周期证据。"),
        "evidence": ("PRESENT", "仅含公开来源引用，不含目标漏洞执行证据。"),
        "oracle": ("NOT_EVALUATED", "本轮没有新的 Oracle 评估，不改写历史结论。"),
        "reports": ("PRESENT", "已生成可离线重建的中文资料审查报告。"),
    }
    return [ArtifactCategory(category=x, status=descriptions[x][0], explanation_zh=descriptions[x][1])
            for x in CATEGORIES]


def import_review_run(cve_id, run_id, *, output_root=None, input_root=None,
                      parent_run_id=None, parent_manifest_sha256=None):
    """Import only public-source catalog review and original seven JSON bytes.

    No private execution evidence is moved. Missing experimental categories are
    explicit statuses, not placeholder stdout/stderr. Existing runs are immutable.
    """
    _ids(cve_id, run_id)
    claim = load_reviewed_claim(cve_id, input_root=input_root)
    claim = VulnerabilityClaim.model_validate(claim)
    if claim.cve_id != cve_id:
        raise ValueError("公开资料声明与目标 CVE 不一致")
    source_dir = Path(input_root or ROOT / "data" / "inputs") / cve_id
    inputs = {}
    for assertion in claim.input_assertions:
        name = Path(assertion.source_file).name
        safe_member(name)
        raw = _read(source_dir / name)
        if _sha(raw) != assertion.source_sha256:
            raise ValueError("七维输入文件哈希与来源声明不一致")
        if name in inputs and inputs[name] != raw:
            raise ValueError("同名原始输入产生冲突")
        inputs[name] = raw
    if len(inputs) != 7:
        raise ValueError("必须具备七个经哈希绑定的原始 JSON")
    claim_sha = canonical_sha256(claim)
    content = {"input/" + name: raw for name, raw in inputs.items()}
    content.update({"analysis/vulnerability_claim.json": _bytes(claim),
        "evidence/public_source_references.json": _bytes([x.model_dump(mode="json") for x in claim.sources]),
        "reports/review.zh-CN.md": _claim_report(claim).encode("utf-8"),
        "README.zh-CN.md": _readme(cve_id, run_id, claim_sha)})
    files = []
    for name, raw in sorted(content.items()):
        is_input = name.startswith("input/")
        kind = ("INPUT_ASSERTION" if is_input else "REVIEWED_CLAIM" if name.startswith("analysis/")
                else "SOURCE_REFERENCE" if name.startswith("evidence/")
                else "ZH_CN_NAVIGATION" if name == "README.zh-CN.md" else "ZH_CN_REPORT")
        files.append(ArtifactFile(relative_path=name, sha256=_sha(raw), byte_length=len(raw),
            artifact_type=kind, source_stage="P1_A" if is_input else "P3_A" if kind == "REVIEWED_CLAIM" else "P3_B",
            source_record_id="input:" + name[6:] if is_input else "reviewed-claim:" + cve_id,
            source_record_sha256=_sha(raw) if is_input else claim_sha, cve_id=cve_id, run_id=run_id))
    manifest = ArtifactManifest(cve_id=cve_id, run_id=run_id, claim_sha256=claim_sha,
        package_kind="RESEARCH_ONLY", files=files, categories=_categories(), missing_evidence=MISSING,
        parent_run_id=parent_run_id, parent_manifest_sha256=parent_manifest_sha256)
    root = _regular_path(output_root or ROOT / "data" / "outputs")
    cve_dir = root / cve_id
    with _locked(cve_dir):
        if parent_run_id is not None:
            _ids(cve_id, parent_run_id)
            parent = cve_dir / "runs" / parent_run_id
            if _sha(_read(parent / "artifact_manifest.json")) != parent_manifest_sha256:
                raise ValueError("父轮次清单身份不一致")
            read_review_run(cve_id, parent_run_id, output_root=root)
        run = _regular_path(cve_dir / "runs" / run_id)
        run.parent.mkdir(exist_ok=True)
        run.mkdir(exist_ok=False)
        # Failure leaves the new incomplete directory for diagnosis, never
        # removes original inputs or claims a successful package.
        for category in CATEGORIES:
            (run / category).mkdir()
        for name, raw in content.items():
            _write_new(run / name, raw)
        _write_new(run / "artifact_manifest.json", _bytes(manifest))
        _update_index(cve_dir, run_id, manifest, package=None)
    read_review_run(cve_id, run_id, output_root=root)
    return run


def _validate_content(manifest, content):
    """All checks are offline; no current catalog/network or Markdown facts."""
    manifest = ArtifactManifest.model_validate(manifest)
    if set(content) != {x.relative_path for x in manifest.files}:
        raise ValueError("清单文件缺失或包含未列出的成员")
    total = 0
    for item in manifest.files:
        raw = content[item.relative_path]
        total += len(raw)
        if len(raw) != item.byte_length or _sha(raw) != item.sha256:
            raise ValueError("归档原始字节大小或 SHA-256 不一致：" + item.relative_path)
    if total > MAX_TOTAL:
        raise ValueError("归档总字节数超过上限")
    if manifest.evidence_domain == "GENERATED_CANDIDATE_RESEARCH":
        return _validate_generation_content(manifest, content)
    if {x.category: x.status for x in manifest.categories} != {x.category: x.status for x in _categories()}:
        raise ValueError("公开资料包的实际产物类别状态不一致")
    claim = VulnerabilityClaim.model_validate(_strict_json(content["analysis/vulnerability_claim.json"]))
    if claim.cve_id != manifest.cve_id or canonical_sha256(claim) != manifest.claim_sha256:
        raise ValueError("资料声明与归档 CVE 或身份哈希冲突")
    if (claim.fact_status not in {"DOCUMENTED_NOT_REPRODUCED","CONFLICT"} or any(
            x.kind not in {"VENDOR_ADVISORY","CNA_RECORD","PUBLIC_TECHNICAL_ANALYSIS"} for x in claim.sources)):
        raise ValueError("Synthetic、LLM 或未经审查声明不能冒充公开资料审查归档")
    expected_inputs = {}
    for assertion in claim.input_assertions:
        filename = Path(assertion.source_file).name
        safe_member(filename)
        if filename in expected_inputs and expected_inputs[filename] != assertion.source_sha256:
            raise ValueError("原始输入来源互相冲突")
        expected_inputs[filename] = assertion.source_sha256
    if len(expected_inputs) != 7:
        raise ValueError("资料审查包必须包含七维输入的来源身份")
    permitted = {"input/" + name for name in expected_inputs} | {
        "analysis/vulnerability_claim.json", "evidence/public_source_references.json",
        "reports/review.zh-CN.md", "README.zh-CN.md"}
    if set(content) != permitted:
        raise ValueError("v1 仅接受已注册的公开资料审查产物；不能导入任意日志或 smoke")
    for item in manifest.files:
        if item.relative_path.startswith("input/"):
            _assert_raw_target(_strict_json(content[item.relative_path]),manifest.cve_id)
            if item.sha256 != expected_inputs[item.relative_path[6:]] or (
                item.source_record_sha256 != item.sha256 or item.artifact_type != "INPUT_ASSERTION"
                or item.source_record_id != "input:" + item.relative_path[6:] or item.source_stage != "P1_A"):
                raise ValueError("输入来源身份或哈希被替换")
        elif (item.source_record_sha256 != manifest.claim_sha256
              or item.source_record_id != "reviewed-claim:" + manifest.cve_id):
            raise ValueError("产物来源声明身份不一致")
        if not item.relative_path.startswith("input/"):
            expected_metadata = {
                "analysis/vulnerability_claim.json": ("REVIEWED_CLAIM", "P3_A"),
                "evidence/public_source_references.json": ("SOURCE_REFERENCE", "P3_B"),
                "reports/review.zh-CN.md": ("ZH_CN_REPORT", "P3_B"),
                "README.zh-CN.md": ("ZH_CN_NAVIGATION", "P3_B"),
            }[item.relative_path]
            if (item.artifact_type, item.source_stage) != expected_metadata:
                raise ValueError("产物类型或来源阶段被替换")
    sources = _bytes([x.model_dump(mode="json") for x in claim.sources])
    if content["evidence/public_source_references.json"] != sources:
        raise ValueError("公开资料引用被替换")
    if content["reports/review.zh-CN.md"] != _claim_report(claim).encode("utf-8"):
        raise ValueError("中文报告不能从结构化声明逐字节重建")
    if content["README.zh-CN.md"] != _readme(manifest.cve_id, manifest.run_id, manifest.claim_sha256):
        raise ValueError("中文入口或未执行声明不一致")
    return manifest


def _assert_raw_target(document, cve_id):
    """A hash-bound input must not explicitly name a different target CVE.

    This checks identity only. It does not upgrade any input assertion to a fact,
    nor infer CVE identity from prose, URLs, generated code or Markdown.
    """
    pending=[document]
    while pending:
        node=pending.pop()
        if isinstance(node,dict):
            for key,value in node.items():
                if key.lower()=="cve_id" and isinstance(value,str) and re.fullmatch(CVE_PATTERN,value) and value!=cve_id:
                    raise ValueError("原始结构化输入明确绑定其他 CVE，禁止跨目标归档")
                if isinstance(value,(dict,list)):
                    pending.append(value)
        elif isinstance(node,list):
            pending.extend(node)


_GENERATION_FILES = {
    "input_manifest": ("input_manifest_v1.json", "input/input_manifest_v1.json", "INPUT_MANIFEST"),
    "analysis": ("cuda_analysis_v1.json", "analysis/cuda_analysis_v1.json", "ANALYSIS_RESULT"),
    "analysis_raw": ("cuda_analysis_v1.raw.txt", "analysis/cuda_analysis_v1.raw.txt", "MODEL_RESPONSE"),
    "candidate": ("cuda_poc_v1.py", "poc/cuda_poc_v1.py", "CANDIDATE_SOURCE"),
    "candidate_status": ("cuda_poc_v1.status.json", "poc/cuda_poc_v1.status.json", "CANDIDATE_STATUS"),
}


def _generation_record(record, cve_id, run_id):
    if not isinstance(record, dict) or record.get("schema_version") != "1.0" or (
            record.get("cve_id") != cve_id or record.get("run_id") != run_id
            or record.get("execution") != "NOT_EXECUTED" or record.get("verification") != "NOT_VERIFIED"):
        raise ValueError("生成记录的 CVE/run 或科学状态不一致")
    candidate = CandidateResult.model_validate(record.get("candidate"))
    if candidate.run_id != run_id:
        raise ValueError("候选记录与本轮 run 不一致")
    artifacts = record.get("artifacts")
    if not isinstance(artifacts, dict) or not {"input_manifest", "candidate_status"} <= set(artifacts):
        raise ValueError("生成记录缺少必需输入/候选状态身份")
    if not set(artifacts) <= set(_GENERATION_FILES):
        raise ValueError("生成归档仅接受已注册产物，不能接受任意文件或 argv")
    for key, item in artifacts.items():
        filename = _GENERATION_FILES[key][0]
        if not isinstance(item, dict) or set(item) != {"file", "sha256"} or item["file"] != filename:
            raise ValueError("生成记录产物名称不受支持")
        if not isinstance(item["sha256"], str) or not re.fullmatch(SHA_PATTERN, item["sha256"]):
            raise ValueError("生成记录缺少合法原始字节 SHA-256")
    if candidate.generation == "GENERATED":
        if "candidate" not in artifacts or candidate.source_file != "cuda_poc_v1.py" or (
                candidate.sha256 != artifacts["candidate"]["sha256"]):
            raise ValueError("候选源码与生成状态或哈希不一致")
    elif "candidate" in artifacts:
        raise ValueError("失败记录不能引用旧候选作为本轮成功产物")
    return candidate


def _generation_input(raw, cve_id, run_id):
    value = _strict_json(raw)
    if not isinstance(value, dict) or value.get("run_id") != run_id:
        raise ValueError("归一化输入未绑定本轮 run")
    value = dict(value)
    value.pop("run_id")
    value.pop("input_status", None)
    normalized = NormalizedInput.model_validate(value)
    if normalized.cve_id != cve_id:
        raise ValueError("归一化输入 CVE 与生成记录不同")
    return normalized


def _generation_readme(cve_id, run_id, record_sha):
    return (f"# {cve_id} 中文候选生成研究入口\n\n"
        f"本轮 ID：`{run_id}`；报告语言：`zh-CN`；包类型：`GENERATION_RESEARCH_INCOMPLETE`。\n\n"
        "本轮未执行生成的 PoC，尚无真实 CVE 漏洞验证证据。\n\n"
        "生成、静态检查、执行和漏洞判定状态相互独立。AST 检查不能证明可执行。\n\n"
        "| 路径 | 用途 |\n|---|---|\n| `input/` | 归一化输入及可获得的七维原始字节副本 |\n"
        "| `analysis/` | 本轮生成记录、实际获得的分析及未改写模型响应 |\n"
        "| `poc/` | 本轮候选状态；仅在真实保存后包含候选源码 |\n"
        "| `reports/generation.zh-CN.md` | 确定性生成报告及失败、缺失原因 |\n"
        "| `artifact_manifest.json` | 每项实际文件、来源身份及缺失类别 |\n\n"
        "`execution/` 未执行，`evidence/` 没有真实 CVE 原始运行日志，`oracle/` 未评估。"
        "缺失原始输入时清单会说明 MISSING，绝不由归一化 JSON 重造原始字节。\n\n"
        f"生成记录规范哈希：`{record_sha}`；候选执行：`NOT_EXECUTED`；漏洞判定：`NOT_VERIFIED`。\n"
        "包外索引记录 ZIP SHA-256，仅证明完整性，不证明来源认证或真实漏洞。\n").encode("utf-8")


def _validate_generation_content(manifest, content):
    record = _strict_json(content["analysis/generation_run.json"])
    candidate = _generation_record(record, manifest.cve_id, manifest.run_id)
    if canonical_sha256(record) != manifest.generation_run_sha256:
        raise ValueError("生成记录规范身份已改变")
    normalized = _generation_input(content["input/input_manifest_v1.json"], manifest.cve_id, manifest.run_id)
    _assert_raw_target(normalized.raw_inputs,manifest.cve_id)
    expected = {"analysis/generation_run.json", "reports/generation.zh-CN.md", "README.zh-CN.md"}
    for key, source in record["artifacts"].items():
        relative = _GENERATION_FILES[key][1]
        expected.add(relative)
        if relative not in content or _sha(content[relative]) != source["sha256"]:
            raise ValueError("生成产物原始字节与本轮记录不符")
    if _strict_json(content["poc/cuda_poc_v1.status.json"]) != candidate.model_dump(mode="json"):
        raise ValueError("候选状态文件与生成记录不一致")
    raw_count = 0
    for source in normalized.sources.values():
        safe_member(source.source_file)
        relative = "input/" + source.source_file
        if relative in content:
            expected.add(relative)
            raw_count += 1
            if source.sha256 is None or _sha(content[relative]) != source.sha256:
                raise ValueError("七维原始输入副本与来源身份不一致")
            _assert_raw_target(_strict_json(content[relative]),manifest.cve_id)
    if "analysis/cuda_analysis_v1.json" in content:
        from .models.analysis import validate_analysis
        validate_analysis(_strict_json(content["analysis/cuda_analysis_v1.json"]),expected_cve_id=manifest.cve_id)
    if set(content) != expected:
        raise ValueError("候选生成包存在未知或跨轮次文件")
    states = {x.category: x.status for x in manifest.categories}
    if states != {x: ("NOT_EXECUTED" if x == "execution" else "NOT_EVALUATED" if x == "oracle"
            else "MISSING" if x == "evidence" or (x == "input" and raw_count != 7)
            else "PRESENT" if x != "poc" or candidate.generation == "GENERATED" else "NOT_EXECUTED")
                  for x in CATEGORIES}:
        raise ValueError("生成归档类别与实际保存或缺失的产物不一致")
    from .report_locale import render_generation_zh
    if content["reports/generation.zh-CN.md"] != render_generation_zh(record).encode("utf-8"):
        raise ValueError("中文生成报告不能离线逐字节重建")
    if content["README.zh-CN.md"] != _generation_readme(manifest.cve_id, manifest.run_id,
                                                         manifest.generation_run_sha256):
        raise ValueError("候选生成中文入口不一致")
    source_kinds = {info[1]: info[2] for info in _GENERATION_FILES.values()}
    source_kinds.update({"analysis/generation_run.json": "GENERATION_RECORD",
        "reports/generation.zh-CN.md": "ZH_CN_REPORT", "README.zh-CN.md": "ZH_CN_NAVIGATION"})
    for item in manifest.files:
        if item.relative_path.startswith("input/") and item.relative_path != "input/input_manifest_v1.json":
            if item.artifact_type != "INPUT_ASSERTION" or item.source_record_sha256 != item.sha256:
                raise ValueError("原始输入来源元数据冲突")
        elif (item.source_record_sha256 != manifest.generation_run_sha256
              or item.artifact_type != source_kinds[item.relative_path]
              or item.source_record_id != "generation-run:" + manifest.run_id):
            raise ValueError("生成产物来源记录被替换")
    return manifest


def create_generation_run(cve_id, run_id, source_directory, run_record, *, output_root=None,
                          input_directory=None):
    """Copy current single-shot artifacts only; no previous v1 artifact reuse."""
    _ids(cve_id, run_id)
    candidate = _generation_record(run_record, cve_id, run_id)
    source_directory = _regular_path(source_directory)
    record_raw = _read(source_directory / "cuda_run_v1.json")
    if canonical_sha256(_strict_json(record_raw)) != canonical_sha256(run_record):
        raise ValueError("磁盘生成记录与本轮内存记录不同")
    record_sha = canonical_sha256(run_record)
    content = {"analysis/generation_run.json": record_raw}
    for key, info in run_record["artifacts"].items():
        filename, relative, _ = _GENERATION_FILES[key]
        raw = _read(source_directory / filename)
        if _sha(raw) != info["sha256"]:
            raise ValueError("本轮生成产物哈希不一致")
        content[relative] = raw
    normalized = _generation_input(content["input/input_manifest_v1.json"], cve_id, run_id)
    input_dir = Path(input_directory) if input_directory is not None else ROOT / "data" / "inputs" / cve_id
    raw_count = 0
    for source in normalized.sources.values():
        safe_member(source.source_file)
        path = input_dir / source.source_file
        if not path.exists():
            continue
        raw = _read(path)
        if source.sha256 is None or _sha(raw) != source.sha256:
            raise ValueError("原始输入已变化，不能将其他输入绑定到本轮生成")
        content["input/" + source.source_file] = raw
        raw_count += 1
    from .report_locale import render_generation_zh
    content["reports/generation.zh-CN.md"] = render_generation_zh(run_record).encode("utf-8")
    content["README.zh-CN.md"] = _generation_readme(cve_id, run_id, record_sha)
    files = []
    kinds = {info[1]: info[2] for info in _GENERATION_FILES.values()}
    kinds.update({"analysis/generation_run.json": "GENERATION_RECORD",
                  "reports/generation.zh-CN.md": "ZH_CN_REPORT", "README.zh-CN.md": "ZH_CN_NAVIGATION"})
    for name, raw in sorted(content.items()):
        is_input = name.startswith("input/") and name != "input/input_manifest_v1.json"
        files.append(ArtifactFile(relative_path=name, sha256=_sha(raw), byte_length=len(raw),
            artifact_type="INPUT_ASSERTION" if is_input else kinds[name],
            source_stage="P1_A" if is_input else "SINGLE_SHOT_GENERATION",
            source_record_id="input:" + name[6:] if is_input else "generation-run:" + run_id,
            source_record_sha256=_sha(raw) if is_input else record_sha, cve_id=cve_id, run_id=run_id))
    category_info = [ArtifactCategory(category=x, status=(
        "NOT_EXECUTED" if x == "execution" else "NOT_EVALUATED" if x == "oracle"
        else "MISSING" if x == "evidence" or (x == "input" and raw_count != 7)
        else "PRESENT" if x != "poc" or candidate.generation == "GENERATED" else "NOT_EXECUTED"),
        explanation_zh=("没有真实 CVE 执行、根因或差分证据。" if x in {"execution", "oracle", "evidence"}
            else f"已绑定本轮实际产物；原始七维输入字节副本 {raw_count}/7；未执行候选。"))
        for x in CATEGORIES]
    manifest = ArtifactManifest(cve_id=cve_id, run_id=run_id,
        package_kind="GENERATION_RESEARCH_INCOMPLETE", evidence_domain="GENERATED_CANDIDATE_RESEARCH",
        generation_run_sha256=record_sha, files=files, categories=category_info,
        missing_evidence=MISSING + ([] if raw_count == 7 else ["部分原始输入字节不可获得，只有归一化输入清单。"] ))
    root = _regular_path(output_root or ROOT / "data" / "outputs")
    cve_dir = root / cve_id
    with _locked(cve_dir):
        run = _regular_path(cve_dir / "runs" / run_id)
        run.parent.mkdir(exist_ok=True)
        run.mkdir(exist_ok=False)
        for category in CATEGORIES:
            (run / category).mkdir()
        for name, raw in content.items():
            _write_new(run / name, raw)
        _write_new(run / "artifact_manifest.json", _bytes(manifest))
        _update_index(cve_dir, run_id, manifest, package=None)
    read_review_run(cve_id, run_id, output_root=root)
    return run


def read_review_run(cve_id, run_id, *, output_root=None):
    _ids(cve_id, run_id)
    run = _regular_path(Path(output_root or ROOT / "data" / "outputs") / cve_id / "runs" / run_id)
    manifest_raw = _read(run / "artifact_manifest.json")
    manifest = ArtifactManifest.model_validate(_strict_json(manifest_raw))
    if manifest_raw != _bytes(manifest):
        raise ValueError("本地冻结清单字节发生改变")
    if manifest.cve_id != cve_id or manifest.run_id != run_id:
        raise ValueError("目录与清单目标身份冲突")
    index = _strict_json(_read(run.parent.parent / "index.json"))
    try:
        entry = index["runs"][run_id]
        if index["cve_id"] != cve_id or entry["manifest_sha256"] != _sha(manifest_raw):
            raise ValueError("清单与包外索引的绑定冲突")
    except (KeyError, TypeError) as exc:
        raise ValueError("缺少本轮包外身份索引") from exc
    content = {}
    for item in manifest.files:
        content[item.relative_path] = _read(run / safe_member(item.relative_path))
    actual_files = set()
    for directory, dirs, files in os.walk(run, followlinks=False):
        for name in dirs + files:
            _regular_path(Path(directory) / name)
        for name in files:
            actual_files.add((Path(directory) / name).relative_to(run).as_posix())
    if actual_files != set(content) | {"artifact_manifest.json"}:
        raise ValueError("实验目录包含清单外文件，不得静默丢弃")
    return _validate_content(manifest, content), content


def rebuild_review_report(cve_id, run_id, *, output_root=None):
    manifest, content = read_review_run(cve_id, run_id, output_root=output_root)
    if manifest.evidence_domain == "GENERATED_CANDIDATE_RESEARCH":
        from .report_locale import render_generation_zh
        return render_generation_zh(_strict_json(content["analysis/generation_run.json"]))
    claim = VulnerabilityClaim.model_validate(_strict_json(content["analysis/vulnerability_claim.json"]))
    return _claim_report(claim)


def _update_index(cve_dir, run_id, manifest, package):
    path = cve_dir / "index.json"
    if path.exists():
        index = _strict_json(_read(path))
        if set(index) != {"index_schema_version", "cve_id", "runs"} or (
                index["index_schema_version"] != "1.0" or index["cve_id"] != manifest.cve_id
                or not isinstance(index["runs"], dict)):
            raise ValueError("已有包外索引非法")
    else:
        index = {"index_schema_version": "1.0", "cve_id": manifest.cve_id, "runs": {}}
    entry = {"manifest_sha256": _sha(_bytes(manifest)), "package_kind": manifest.package_kind,
             "candidate_execution_status": "NOT_EXECUTED", "real_cve_verification": "NOT_VERIFIED",
             "package": package}
    old = index["runs"].get(run_id)
    if old is not None and (old["manifest_sha256"] != entry["manifest_sha256"]
                             or old.get("package") is not None):
        raise ValueError("历史索引不得覆盖或改绑")
    index["runs"][run_id] = entry
    temporary = cve_dir / (".index-" + uuid.uuid4().hex + ".tmp")
    _write_new(temporary, _bytes(index))
    os.replace(temporary, path)


def package_run(cve_id, run_id, *, output_root=None):
    _ids(cve_id, run_id)
    root = _regular_path(output_root or ROOT / "data" / "outputs")
    cve_dir = root / cve_id
    with _locked(cve_dir):
        manifest, content = read_review_run(cve_id, run_id, output_root=root)
        destination = _regular_path(cve_dir / "packages")
        destination.mkdir(exist_ok=True)
        target = destination / (cve_id + "_" + run_id + ".zip")
        if target.exists():
            raise FileExistsError("同一 run 的 ZIP 已存在，禁止覆盖")
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, raw in sorted({**content, "artifact_manifest.json": _bytes(manifest)}.items()):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, raw)
        raw = buffer.getvalue()
        _write_new(target, raw)
        verification = verify_package(target, expected_sha256=_sha(raw))
        _update_index(cve_dir, run_id, manifest, package={"relative_path": "packages/" + target.name,
            "sha256": verification.package_sha256, "byte_length": len(raw)})
    return target, verification


def verify_package(package, *, expected_sha256):
    """Independent ZIP checks require an out-of-band byte digest pin.

    A digest supplied by an untrusted sender proves no authenticity. No CVE
    verdict is inferred, and no archive member is ever extracted to disk.
    """
    if not isinstance(expected_sha256, str) or not re.fullmatch(SHA_PATTERN, expected_sha256):
        raise ValueError("必须提供包外可信渠道核对的 ZIP SHA-256")
    raw = _read(package, MAX_TOTAL)
    if _sha(raw) != expected_sha256:
        raise ValueError("ZIP 自身 SHA-256 不匹配")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            if len(infos) > 257 or not infos:
                raise ValueError("ZIP 成员数量非法")
            names = []
            total = 0
            for info in infos:
                safe_member(info.filename)
                if info.orig_filename != info.filename:
                    raise ValueError("ZIP 原始成员名包含截断或非安全字符")
                mode = info.external_attr >> 16
                if info.is_dir() or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                    raise ValueError("ZIP 不接受目录、符号链接或特殊文件成员")
                if info.flag_bits & 1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ValueError("不支持加密或未知压缩格式")
                if info.file_size > MAX_FILE or info.file_size < 0:
                    raise ValueError("ZIP 成员字节数超过上限")
                total += info.file_size
                names.append(info.filename)
            if total > MAX_TOTAL or len({x.casefold() for x in names}) != len(names):
                raise ValueError("ZIP 包含重复成员或超量数据")
            content = {}
            for info in infos:
                with archive.open(info) as stream:
                    member = stream.read(MAX_FILE + 1)
                if len(member) != info.file_size:
                    raise ValueError("ZIP 成员长度不一致或已截断")
                content[info.filename] = member
    except (zipfile.BadZipFile, EOFError, RuntimeError, NotImplementedError) as exc:
        raise ValueError("ZIP 损坏、截断或格式不支持") from exc
    if "artifact_manifest.json" not in content:
        raise ValueError("缺少机器可读归档清单")
    manifest_raw = content.pop("artifact_manifest.json")
    manifest = ArtifactManifest.model_validate(_strict_json(manifest_raw))
    _validate_content(manifest, content)
    return PackageVerification(package_sha256=_sha(raw), manifest_sha256=_sha(manifest_raw),
        cve_id=manifest.cve_id, run_id=manifest.run_id, file_count=len(content) + 1,
        byte_length=len(raw), package_kind=manifest.package_kind)
