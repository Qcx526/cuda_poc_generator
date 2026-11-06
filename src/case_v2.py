# -*- coding: utf-8 -*-
"""GPU Vulnerability Case v2: one platform-neutral case description.

The CUDA seven-dimension input was a schema for one product. It required seven files,
assumed a CVE, and mixed "what the document claims" with "what we measured". This
module separates those concerns and lets the platform-specific parts live in a typed
extension instead of in the core.

Two things it deliberately does not do:

* it never treats a field's presence as evidence of its truth;
* it never decides visibility by "the document is public, so the text is fine".
"""

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

SCHEMA_VERSION = "gpu-vulnerability-case/v2"


class EvidenceKind(str, Enum):
    INPUT_ASSERTION = "INPUT_ASSERTION"
    STATIC_FACT = "STATIC_FACT"
    RUNTIME_OBSERVATION = "RUNTIME_OBSERVATION"
    LLM_HYPOTHESIS = "LLM_HYPOTHESIS"
    EVIDENCE_REQUEST = "EVIDENCE_REQUEST"
    VERIFICATION_RESULT = "VERIFICATION_RESULT"
    EVALUATION_ONLY = "EVALUATION_ONLY"


class VerificationStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    UNKNOWN = "UNKNOWN"


class Visibility(str, Enum):
    PUBLIC = "PUBLIC"        # may appear in a blind prompt
    FACT = "FACT"            # only in FACT_ASSISTED runs
    EVAL = "EVAL"            # evaluation only, never in a prompt


# Kinds that can be shown to a model at all; the rest exist for the evaluator.
KIND_VISIBILITY = {
    EvidenceKind.INPUT_ASSERTION: Visibility.PUBLIC,
    EvidenceKind.STATIC_FACT: Visibility.FACT,
    EvidenceKind.RUNTIME_OBSERVATION: Visibility.EVAL,
    EvidenceKind.LLM_HYPOTHESIS: Visibility.EVAL,
    EvidenceKind.EVIDENCE_REQUEST: Visibility.PUBLIC,
    EvidenceKind.VERIFICATION_RESULT: Visibility.EVAL,
    EvidenceKind.EVALUATION_ONLY: Visibility.EVAL,
}


class Evidence(BaseModel):
    """One claim, with where it came from and how far it is trusted."""

    id: str
    kind: EvidenceKind
    statement: str
    source: str = Field(description="文档、镜像路径或实验目录")
    target_identity: Optional[str] = Field(
        default=None, description="镜像 SHA256、LUID、容器镜像等")
    digest: Optional[str] = None
    status: VerificationStatus = VerificationStatus.UNKNOWN
    visible_in: Visibility
    notes: Optional[str] = None

    @model_validator(mode="after")
    def _check_visibility_matches_kind(self):
        expected = KIND_VISIBILITY[self.kind]
        if self.visible_in != expected:
            raise ValueError(
                "证据 %s 的 kind=%s 要求 visible_in=%s，实际 %s"
                % (self.id, self.kind.value, expected.value, self.visible_in.value))
        if self.kind == EvidenceKind.STATIC_FACT and not self.target_identity:
            raise ValueError("STATIC_FACT %s 必须绑定 target_identity" % self.id)
        return self


class CaseIdentity(BaseModel):
    case_id: str
    cve_id: Optional[str] = None
    title: str
    sources: List[str] = Field(default_factory=list)


class TargetProfile(BaseModel):
    vendor: str
    component: str
    platform: str                     # windows / linux
    execution_tier: str               # userland_toolchain / kernel_driver / ...
    versions: Dict[str, str] = Field(default_factory=dict)


class EntrySurface(BaseModel):
    medium: str                       # file / ioctl / api_call
    interface: str
    trust_boundary: str
    constraints: List[str] = Field(default_factory=list)


class VulnerabilityDescription(BaseModel):
    public_summary: str
    cwe: Optional[str] = None
    impact: Optional[str] = None
    root_cause_status: VerificationStatus = VerificationStatus.UNKNOWN


class ConstraintKnowledge(BaseModel):
    evidence: List[Evidence] = Field(default_factory=list)
    missing: List[str] = Field(default_factory=list)

    def by_kind(self, kind: EvidenceKind) -> List[Evidence]:
        return [item for item in self.evidence if item.kind is kind]


class ExperimentContract(BaseModel):
    goal: str
    backend: str                      # cuda_container / windows_userland
    allowed_operations: List[str] = Field(default_factory=list)
    risk_level: str = "low"
    requires_independent_verification: bool = True


class PlatformExtension(BaseModel):
    """Typed, versioned home for platform-specific fields."""

    name: str
    version: str
    payload: Dict[str, str] = Field(default_factory=dict)


class GPUCase(BaseModel):
    schema_version: str = SCHEMA_VERSION
    identity: CaseIdentity
    target: TargetProfile
    entry_surface: EntrySurface
    description: VulnerabilityDescription
    knowledge: ConstraintKnowledge
    contract: ExperimentContract
    extension: Optional[PlatformExtension] = None

    @field_validator("schema_version")
    @classmethod
    def _check_version(cls, value: str) -> str:
        if value != SCHEMA_VERSION:
            raise ValueError("schema_version 必须是 %s" % SCHEMA_VERSION)
        return value

    @model_validator(mode="after")
    def _check_extension_matches_target(self):
        if self.extension and self.extension.name not in (
                "cuda_toolchain", "windows_gpu_driver", "shader_compiler",
                "gpu_runtime", "gpu_firmware"):
            raise ValueError("未知平台扩展: %s" % self.extension.name)
        return self
