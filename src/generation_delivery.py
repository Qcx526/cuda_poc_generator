"""Optional generation-to-ZIP delivery; never compiles or runs a candidate.

Delivery receipts are outside the immutable scientific run and ZIP. This avoids
adding a self-referential ZIP digest to the artifacts whose digest it covers.
"""

import json
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from .artifact_packaging import create_generation_run, package_run
from .models.artifact_package import CVE_PATTERN, RUN_PATTERN, SHA_PATTERN
from .models.lifecycle import LifecycleContract


class GenerationDelivery(LifecycleContract):
    delivery_schema_version: Literal["1.0"] = "1.0"
    report_locale: Literal["zh-CN"] = "zh-CN"
    run_id: str = Field(pattern=RUN_PATTERN)
    cve_id: str | None = Field(default=None, pattern=CVE_PATTERN)
    generation_status: str
    archive_status: Literal["ARCHIVED", "FAILED", "NOT_ARCHIVED"]
    package_status: Literal["INTEGRITY_VERIFIED", "FAILED", "NOT_PACKAGED"]
    archive_directory: str | None = None
    package_path: str | None = None
    package_sha256: str | None = Field(default=None, pattern=SHA_PATTERN)
    manifest_sha256: str | None = Field(default=None, pattern=SHA_PATTERN)
    error_type: str | None = None
    explanation_zh: str
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    real_cve_verification: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"

    @model_validator(mode="after")
    def complete_binding(self):
        packaged = self.package_status == "INTEGRITY_VERIFIED"
        if packaged != all(x is not None for x in (self.package_path, self.package_sha256, self.manifest_sha256)):
            raise ValueError("交付成功必须包含本轮 ZIP 路径和独立校验摘要")
        if not packaged and any(x is not None for x in (self.package_path, self.package_sha256, self.manifest_sha256)):
            raise ValueError("失败交付不能引用旧 ZIP 或旧摘要")
        if packaged and (self.archive_status != "ARCHIVED" or self.generation_status != "COMPLETE" or self.cve_id is None):
            raise ValueError("只有本轮生成完成且成功归档才能交付 ZIP")
        if (self.archive_status == "ARCHIVED") != (self.archive_directory is not None):
            raise ValueError("归档状态与本轮目录不一致")
        return self


def render_delivery_report(receipt: GenerationDelivery) -> str:
    receipt = GenerationDelivery.model_validate(receipt.model_dump(mode="python"))
    def cell(value):
        return str(value if value is not None else "未产生").replace("&", "&amp;").replace("<", "&lt;").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    rows = ["# 单次生成与 ZIP 交付报告", "", "报告语言：zh-CN。", "",
            "本轮未执行生成的 PoC，尚无真实 CVE 漏洞验证证据。", "",
            "| 项目 | 本轮结果 |", "|---|---|"]
    for label, value in (("目标 CVE", receipt.cve_id), ("run_id", receipt.run_id),
                         ("生成流程", receipt.generation_status), ("归档状态", receipt.archive_status),
                         ("打包与独立校验", receipt.package_status), ("本轮归档目录", receipt.archive_directory),
                         ("ZIP 文件", receipt.package_path), ("包外 SHA-256", receipt.package_sha256),
                         ("清单 SHA-256", receipt.manifest_sha256), ("错误类别", receipt.error_type)):
        rows.append(f"| {label} | {cell(value)} |")
    rows += ["", "## 结果说明", "", receipt.explanation_zh, "",
             "缺少真实执行、专项根因和受影响/修复版本差分证据。ZIP 完整性校验不是来源认证或漏洞验证。",
             "候选执行：NOT_EXECUTED；漏洞验证：NOT_VERIFIED。", "",
             "## 离线复核", "", "使用包外 SHA-256 调用 artifact_cli verify 重新读取 ZIP；使用 artifact_cli rebuild-report 重建生成报告。",
             "本交付报告可由 delivery.json 确定性重建；失败回执不会回退到旧 run。", ""]
    return "\n".join(rows)


def deliver_generation(*, run_record, source_directory, output_root, input_directory, cve_id):
    """Return a truthful receipt, even when archiving or packaging fails.

    A failed original generation can be archived for diagnosis but never yields
    a successful automatic ZIP delivery. Underlying exclusive-run checks remain
    authoritative; this function never searches historical output for a ZIP.
    """
    run_id = run_record["run_id"]
    base = dict(run_id=run_id, cve_id=cve_id, generation_status=run_record["status"])
    # Validate identities before using them as path components.
    GenerationDelivery(**base, archive_status="NOT_ARCHIVED", package_status="NOT_PACKAGED",
                       explanation_zh="尚未开始归档。")
    archive = None
    phase = "archive"
    try:
        if cve_id is None:
            receipt = GenerationDelivery(**base, archive_status="NOT_ARCHIVED", package_status="NOT_PACKAGED",
                explanation_zh="输入尚未形成合法一致的 CVE 绑定，归档不完整；没有生成本轮 ZIP。")
        else:
            if run_record["status"] == "COMPLETE":
                from .models.generation import CandidateResult
                candidate = CandidateResult.model_validate(run_record.get("candidate"))
                if (candidate.generation != "GENERATED" or run_record.get("input_status") != "VALID"
                        or run_record.get("analysis_status") != "VALID"):
                    raise ValueError("COMPLETE 与输入、分析或候选状态矛盾，拒绝打包")
            archive = create_generation_run(cve_id, run_id, source_directory, run_record,
                                           output_root=output_root, input_directory=input_directory)
            if run_record["status"] != "COMPLETE":
                receipt = GenerationDelivery(**base, archive_status="ARCHIVED", archive_directory=str(archive),
                    package_status="NOT_PACKAGED", explanation_zh="生成流程未完成，仅保存本轮不完整研究材料；没有交付 ZIP。")
            else:
                phase = "package"
                package, verification = package_run(cve_id, run_id, output_root=output_root)
                if (verification.cve_id, verification.run_id) != (cve_id, run_id):
                    raise ValueError("ZIP 独立校验返回了其他 CVE 或 run")
                receipt = GenerationDelivery(**base, archive_status="ARCHIVED", archive_directory=str(archive),
                    package_status="INTEGRITY_VERIFIED", package_path=str(package),
                    package_sha256=verification.package_sha256, manifest_sha256=verification.manifest_sha256,
                    explanation_zh="本轮实际产物已复制至独立 run，ZIP 已重新打开并校验全部成员；该包仍缺少真实漏洞实验与验证证据。")
    except (OSError, ValueError, RuntimeError, TypeError, KeyError) as exc:
        receipt = GenerationDelivery(**base, archive_status="ARCHIVED" if archive else "FAILED",
            archive_directory=str(archive) if archive else None,
            package_status="FAILED" if phase == "package" else "NOT_PACKAGED", error_type=type(exc).__name__,
            explanation_zh="本轮归档或打包未完整完成；失败目录和原始材料保留，不引用任何历史 ZIP，也不声明交付成功。")
    return receipt


def save_delivery_receipt(receipt, *, output_root):
    """Exclusive sidecar, separate from frozen run/ZIP members and their hashes."""
    receipt = GenerationDelivery.model_validate(receipt.model_dump(mode="python"))
    root = Path(output_root)
    if receipt.cve_id is not None:
        root = root / receipt.cve_id
    else:
        root = root / "unbound_generation"
    directory = root / "delivery_attempts" / receipt.run_id
    # Reuse the packaging path guard: no links or Windows alias traversal.
    from .artifact_packaging import _regular_path, _write_new
    _regular_path(directory)
    directory.parent.mkdir(parents=True, exist_ok=True)
    directory.mkdir(exist_ok=False)
    raw = (json.dumps(receipt.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    _write_new(directory / "delivery.json", raw)
    _write_new(directory / "report.zh-CN.md", render_delivery_report(receipt).encode("utf-8"))
    return directory


def rebuild_delivery_report(directory):
    from .artifact_packaging import _read, _regular_path, _strict_json
    folder = _regular_path(directory)
    receipt = GenerationDelivery.model_validate(_strict_json(_read(folder / "delivery.json")))
    expected_parent = receipt.cve_id or "unbound_generation"
    if (folder.name != receipt.run_id or folder.parent.name != "delivery_attempts"
            or folder.parent.parent.name != expected_parent):
        raise ValueError("交付目录和 CVE/run 身份冲突")
    text = render_delivery_report(receipt)
    if _read(folder / "report.zh-CN.md") != text.encode("utf-8"):
        raise ValueError("中文交付报告与结构化回执不一致")
    return text
