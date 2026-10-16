"""Versioned CVE research packaging, independent of execution/Oracle objects."""

import re
from typing import Literal

from pydantic import Field, model_validator

from .lifecycle import LifecycleContract

CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,}$"
RUN_PATTERN = r"^[0-9a-f]{32}$"
SHA_PATTERN = r"^[0-9a-f]{64}$"
CATEGORIES = ("input", "analysis", "poc", "execution", "evidence", "oracle", "reports")


def safe_member(value: str) -> str:
    """One portable POSIX relative name: reject Windows aliases as well."""
    if not value or len(value) > 240 or "\\" in value or ":" in value:
        raise ValueError("归档成员必须是安全的相对路径")
    parts = value.split("/")
    for part in parts:
        if (not part or part in {".", ".."} or part.endswith((".", " "))
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", part)
                or part.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL"}
                or re.fullmatch(r"(?:COM|LPT)[1-9]", part.split(".")[0].upper())):
            raise ValueError("归档成员包含非法路径或 Windows 保留名称")
    return value


class ArtifactFile(LifecycleContract):
    relative_path: str
    sha256: str = Field(pattern=SHA_PATTERN)
    byte_length: int = Field(ge=0, le=16 * 1024 * 1024)
    artifact_type: Literal["INPUT_ASSERTION", "REVIEWED_CLAIM", "SOURCE_REFERENCE",
                           "ZH_CN_REPORT", "ZH_CN_NAVIGATION", "GENERATION_RECORD",
                           "INPUT_MANIFEST", "MODEL_RESPONSE", "CANDIDATE_SOURCE",
                           "CANDIDATE_STATUS", "ANALYSIS_RESULT"]
    source_stage: Literal["P1_A", "P3_A", "P3_B", "SINGLE_SHOT_GENERATION"]
    source_record_id: str = Field(min_length=1)
    source_record_sha256: str = Field(pattern=SHA_PATTERN)
    cve_id: str = Field(pattern=CVE_PATTERN)
    run_id: str = Field(pattern=RUN_PATTERN)

    @model_validator(mode="after")
    def path(self):
        safe_member(self.relative_path)
        if self.relative_path == "artifact_manifest.json":
            raise ValueError("清单不得自引用哈希")
        return self


class ArtifactCategory(LifecycleContract):
    category: Literal["input", "analysis", "poc", "execution", "evidence", "oracle", "reports"]
    status: Literal["PRESENT", "NOT_EXECUTED", "NOT_EVALUATED", "MISSING"]
    explanation_zh: str = Field(min_length=1)


class ArtifactManifest(LifecycleContract):
    package_schema_version: Literal["1.0"] = "1.0"
    report_locale: Literal["zh-CN"] = "zh-CN"
    package_kind: Literal["RESEARCH_ONLY", "INCOMPLETE", "GENERATION_RESEARCH_INCOMPLETE"]
    evidence_domain: Literal["DOCUMENTED_PUBLIC_REVIEW", "GENERATED_CANDIDATE_RESEARCH"] = "DOCUMENTED_PUBLIC_REVIEW"
    cve_id: str = Field(pattern=CVE_PATTERN)
    run_id: str = Field(pattern=RUN_PATTERN)
    parent_run_id: str | None = Field(default=None, pattern=RUN_PATTERN)
    parent_manifest_sha256: str | None = Field(default=None, pattern=SHA_PATTERN)
    claim_sha256: str | None = Field(default=None, pattern=SHA_PATTERN)
    generation_run_sha256: str | None = Field(default=None, pattern=SHA_PATTERN)
    files: list[ArtifactFile] = Field(min_length=1, max_length=256)
    categories: list[ArtifactCategory] = Field(min_length=7, max_length=7)
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    real_cve_verification: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    missing_evidence: list[str] = Field(min_length=1)
    collector_version: Literal["p3b-review-packager/1.0"] = "p3b-review-packager/1.0"

    @model_validator(mode="after")
    def bindings(self):
        names = [x.relative_path.casefold() for x in self.files]
        if len(names) != len(set(names)):
            raise ValueError("重复归档成员（包含大小写冲突）")
        if any(x.cve_id != self.cve_id or x.run_id != self.run_id for x in self.files):
            raise ValueError("禁止跨 CVE 或跨 run 绑定")
        if {x.category for x in self.categories} != set(CATEGORIES):
            raise ValueError("类别清单不完整或重复")
        states = {x.category: x.status for x in self.categories}
        if states["execution"] != "NOT_EXECUTED":
            raise ValueError("研究资料包不得声称已执行 PoC")
        if states["oracle"] not in {"NOT_EVALUATED", "MISSING"}:
            raise ValueError("资料审查包没有新的 Oracle 判定")
        if (self.parent_run_id is None) != (self.parent_manifest_sha256 is None):
            raise ValueError("父轮次 ID 与清单哈希必须同时提供")
        if self.parent_run_id == self.run_id:
            raise ValueError("禁止自引用父轮次")
        if self.evidence_domain == "DOCUMENTED_PUBLIC_REVIEW":
            if (self.claim_sha256 is None or self.generation_run_sha256 is not None
                    or states["poc"] != "NOT_EXECUTED" or self.package_kind not in {"RESEARCH_ONLY", "INCOMPLETE"}):
                raise ValueError("公开资料审查身份或未执行状态非法")
            required = {"README.zh-CN.md", "analysis/vulnerability_claim.json",
                        "evidence/public_source_references.json", "reports/review.zh-CN.md"}
        else:
            if (self.generation_run_sha256 is None or self.claim_sha256 is not None
                    or self.package_kind != "GENERATION_RESEARCH_INCOMPLETE"):
                raise ValueError("候选生成归档身份或不完整状态非法")
            required = {"README.zh-CN.md", "analysis/generation_run.json",
                        "input/input_manifest_v1.json", "reports/generation.zh-CN.md"}
        if not required <= {x.relative_path for x in self.files}:
            raise ValueError("缺少中文入口、绑定声明或报告")
        return self


class PackageVerification(LifecycleContract):
    verification_schema_version: Literal["1.0"] = "1.0"
    status: Literal["INTEGRITY_VERIFIED"] = "INTEGRITY_VERIFIED"
    package_sha256: str = Field(pattern=SHA_PATTERN)
    manifest_sha256: str = Field(pattern=SHA_PATTERN)
    cve_id: str = Field(pattern=CVE_PATTERN)
    run_id: str = Field(pattern=RUN_PATTERN)
    file_count: int = Field(ge=1)
    byte_length: int = Field(ge=0)
    package_kind: Literal["RESEARCH_ONLY", "INCOMPLETE", "GENERATION_RESEARCH_INCOMPLETE"]
    report_locale: Literal["zh-CN"] = "zh-CN"
    authenticity: Literal["UNAUTHENTICATED_EXTERNAL_HASH_PIN"] = "UNAUTHENTICATED_EXTERNAL_HASH_PIN"
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    real_cve_verification: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
