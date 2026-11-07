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


# Kinds that may *ever* be shown. Everything else is evaluator-only.
PUBLIC_CAPABLE = {EvidenceKind.INPUT_ASSERTION, EvidenceKind.EVIDENCE_REQUEST,
                  EvidenceKind.STATIC_FACT}

# STATIC_FACT is measurements, not prose; it may be shown to a fact-assisted run but
# never to a blind one. The other two need an explicit review flag.
FACT_ONLY_KINDS = {EvidenceKind.STATIC_FACT}


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
    # Default deny: absence of a decision means the evaluator keeps it.
    visible_in: Visibility = Visibility.EVAL
    public_reviewed: bool = Field(
        default=False,
        description="是否已针对盲测逐条审查；PUBLIC 需要它为 True")
    notes: Optional[str] = None

    @model_validator(mode="after")
    def _check_visibility_policy(self):
        """Visibility is a decision, not a consequence of the kind.

        The old table forced one visibility per kind, which made every assertion and
        every evidence request public by construction. Now the default is EVAL and a
        public decision has to be justified for that specific object.
        """
        if self.visible_in is Visibility.PUBLIC:
            if self.kind not in PUBLIC_CAPABLE:
                raise ValueError("%s: %s 不允许 PUBLIC" % (self.id, self.kind.value))
            if self.kind in FACT_ONLY_KINDS:
                raise ValueError("%s: STATIC_FACT 只能进入 FACT_ASSISTED" % self.id)
            if not self.public_reviewed:
                raise ValueError("%s: 进入 PUBLIC 需要公开审查标记" % self.id)
        if self.kind is EvidenceKind.STATIC_FACT:
            if self.visible_in is not Visibility.FACT:
                raise ValueError("%s: STATIC_FACT 的可见性只能是 FACT" % self.id)
            if not self.target_identity:
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
    # 逐条授权：FACT_ASSISTED 只附加这里列出的 STATIC_FACT id，空集合表示一个都不给。
    authorized_fact_ids: List[str] = Field(default_factory=list)
    # 扩展载荷与 missing 同样逐项授权，避免绕过证据列表。
    shared_payload_keys: List[str] = Field(default_factory=list)
    share_missing: bool = False
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
