"""P3-A contracts. Assertions, observations and CVE conclusions stay separate."""

import re
from typing import Literal

from pydantic import Field, JsonValue, model_validator

from .lifecycle import LifecycleContract

Sha = str
Category = Literal["ENVIRONMENT", "IDENTITY", "ENTRY_BEHAVIOR", "ANOMALY", "ROOT_CAUSE"]
ConditionStatus = Literal["SATISFIED", "NOT_SATISFIED", "UNKNOWN", "CONFLICT"]


class SourceDocument(LifecycleContract):
    source_id: str = Field(min_length=1)
    kind: Literal["VENDOR_ADVISORY", "CNA_RECORD", "PUBLIC_TECHNICAL_ANALYSIS",
                  "MEASUREMENT", "LLM_REASONING", "USER_ASSERTION", "SYNTHETIC"]
    url: str = Field(min_length=1)
    retrieved_at: str = Field(min_length=1)
    content_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    support: Literal["DOCUMENTED", "OBSERVED", "ASSERTED", "UNKNOWN", "CONFLICT"]
    locator: str = Field(min_length=1)


class InputAssertion(LifecycleContract):
    dimension: str
    source_file: str
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    field_path: str
    normalized_path: str
    field_state: str
    assertion_kind: Literal["USER_ASSERTION"] = "USER_ASSERTION"
    verification: Literal["UNVERIFIED"] = "UNVERIFIED"


class VulnerabilityClaim(LifecycleContract):
    claim_schema_version: Literal["1.0"] = "1.0"
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    cwe: list[str]
    vulnerability_type: str = Field(min_length=1)
    affected_component: str = Field(min_length=1)
    affected_version_ranges: list[str] = Field(min_length=1)
    version_scheme: Literal["VENDOR_RELEASE_LABEL", "NUMERIC_COMPONENT_BUILD", "UNKNOWN"]
    entry: str = Field(min_length=1)
    controlled_input: str = Field(min_length=1)
    prerequisites: list[str]
    trigger_mechanism: str = Field(min_length=1)
    expected_objective_behavior: str = Field(min_length=1)
    fixed_versions: list[str]
    sources: list[SourceDocument] = Field(min_length=1)
    unknowns: list[str]
    input_assertions: list[InputAssertion] = Field(default_factory=list)
    fact_status: Literal["DOCUMENTED_NOT_REPRODUCED", "UNREVIEWED", "CONFLICT"]

    @model_validator(mode="after")
    def classifications(self):
        if any(not re.fullmatch(r"CWE-[0-9]+", x) for x in self.cwe):
            raise ValueError("invalid CWE")
        if len({x.source_id for x in self.sources}) != len(self.sources):
            raise ValueError("duplicate claim source ID")
        if self.fact_status == "DOCUMENTED_NOT_REPRODUCED" and not any(
                x.kind in {"VENDOR_ADVISORY", "CNA_RECORD", "PUBLIC_TECHNICAL_ANALYSIS"}
                and x.support == "DOCUMENTED" for x in self.sources):
            raise ValueError("LLM/user assertions cannot establish documented facts")
        return self


class EvidenceReference(LifecycleContract):
    reference_id: str = Field(min_length=1)
    domain: Literal["OBJECTIVE", "SYNTHETIC"]
    cve_id: str | None = Field(default=None, pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    artifact_file: str = Field(pattern=r"^[A-Za-z0-9_.-]+\.json$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    json_pointer: str = Field(pattern=r"^/")
    original_source: str = Field(min_length=1)
    platform_environment_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    platform_probe_id: str = Field(min_length=1)
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_role: str = Field(min_length=1)
    tool_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    collection_method: str = Field(min_length=1)
    scope: Literal["TOOLCHAIN_SMOKE", "CVE_TRIGGER", "SYNTHETIC"]
    evidence_type: Literal["PLATFORM", "IDENTITY", "PROCESS", "ROOT_CAUSE", "DIFFERENTIAL"]


class EvidenceRequirement(LifecycleContract):
    evidence_type: Literal["PLATFORM", "IDENTITY", "PROCESS", "ROOT_CAUSE", "DIFFERENTIAL"]
    evidence_source: Literal["OBJECTIVE", "SYNTHETIC"]
    method: Literal["EXACT_FIELD", "NUMERIC_VERSION", "UNIMPLEMENTED", "SYNTHETIC_FACT"]
    scope: Literal["TOOLCHAIN_SMOKE", "CVE_TRIGGER", "SYNTHETIC"]
    reference_ids: list[str]
    completeness_required: bool = True


class TriggerCondition(LifecycleContract):
    condition_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    category: Category
    predicate_type: Literal["EQUALS", "NUMERIC_RANGE", "UNIMPLEMENTED"]
    subject: str = Field(min_length=1)
    expected_value: JsonValue = None
    expected_relation: Literal["EQUALS", "GTE_LT", "UNKNOWN"]
    # Numeric ranges apply only to measured component builds, never U1/U2 labels.
    minimum_inclusive: str | None = None
    maximum_exclusive: str | None = None
    applicability: Literal["APPLICABLE", "NOT_APPLICABLE", "UNKNOWN"]
    required: bool
    requirement: EvidenceRequirement
    provenance: list[str] = Field(min_length=1)
    evaluation_status: Literal["PENDING"] = "PENDING"

    @model_validator(mode="after")
    def predicate(self):
        if self.predicate_type == "EQUALS":
            if type(self.expected_value) not in {str, bool, int, float} or self.expected_relation != "EQUALS":
                raise ValueError("EQUALS needs a scalar and explicit relation")
            if isinstance(self.expected_value, str) and not self.expected_value.strip():
                raise ValueError("blank expected value")
        elif self.predicate_type == "NUMERIC_RANGE":
            if self.expected_relation != "GTE_LT" or self.requirement.method != "NUMERIC_VERSION":
                raise ValueError("numeric build comparison needs NUMERIC_VERSION/GTE_LT")
            for version in (self.minimum_inclusive, self.maximum_exclusive):
                if version is None or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version):
                    raise ValueError("only explicit numeric component builds supported")
            if version_tuple(self.minimum_inclusive) >= version_tuple(self.maximum_exclusive):
                raise ValueError("empty numeric version range")
        elif self.expected_relation != "UNKNOWN":
            raise ValueError("unimplemented predicate must remain unknown")
        if len(set(self.requirement.reference_ids)) != len(self.requirement.reference_ids):
            raise ValueError("duplicate evidence reference")
        return self


def version_tuple(value: str) -> tuple[int, ...]:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", value):
        raise ValueError("not a numeric component build")
    numbers = tuple(int(x) for x in value.split("."))
    return numbers + (0,) * (4 - len(numbers))


class OraclePlan(LifecycleContract):
    plan_schema_version: Literal["1.0"] = "1.0"
    oracle_id: str = Field(min_length=1)
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    domain: Literal["OBJECTIVE", "SYNTHETIC"]
    standard_id: Literal["SYNTHETIC_ALL_REQUIRED_V1", "CVE_METHOD_NOT_IMPLEMENTED_V1"]
    verification_standard: str = Field(min_length=1)
    review_reference: str = Field(min_length=1)
    bindings: dict[str, JsonValue]
    conditions: list[TriggerCondition] = Field(min_length=1)
    references: list[EvidenceReference]
    source_ids: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def consistent(self):
        if (self.domain == "SYNTHETIC") != (self.standard_id == "SYNTHETIC_ALL_REQUIRED_V1"):
            raise ValueError("no reviewed production root-cause assessor is registered in P3-A")
        ids = [x.condition_id for x in self.conditions]
        refs = [x.reference_id for x in self.references]
        if len(ids) != len(set(ids)) or len(refs) != len(set(refs)):
            raise ValueError("duplicate condition/reference ID")
        if len(set(self.source_ids)) != len(self.source_ids):
            raise ValueError("duplicate plan source ID")
        for condition in self.conditions:
            if not set(condition.provenance) <= set(self.source_ids):
                raise ValueError("unbound condition provenance")
            if not set(condition.requirement.reference_ids) <= set(refs):
                raise ValueError("unbound evidence requirement")
        return self


class ConditionEvaluation(LifecycleContract):
    condition_id: str
    status: ConditionStatus
    reason: str
    reference_ids: list[str]
    observed_values: list[JsonValue]


class CVEEligibility(LifecycleContract):
    cve_id: str
    status: Literal["ELIGIBLE", "INELIGIBLE", "UNKNOWN"]
    reasons: list[str]
    # Environment eligibility alone is never execution authorization.
    execution_authorized: Literal[False] = False


class OracleResult(LifecycleContract):
    result_schema_version: Literal["1.0"] = "1.0"
    oracle_id: str
    cve_id: str
    domain: Literal["OBJECTIVE", "SYNTHETIC"]
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    corpus_manifest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    eligibility: CVEEligibility
    conditions: list[ConditionEvaluation]
    condition_status: ConditionStatus
    verdict: Literal["SUPPORTED", "VERIFIED", "NOT_VERIFIED", "UNKNOWN"]
    real_cve_verification: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    reasons: list[str]
    limitations: list[str]
    observed_context: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def no_real_proof(self):
        if self.verdict == "VERIFIED" and (self.domain != "SYNTHETIC" or
                self.condition_status != "SATISFIED" or self.eligibility.status != "ELIGIBLE"):
            raise ValueError("P3-A VERIFIED is synthetic rule proof only")
        return self
