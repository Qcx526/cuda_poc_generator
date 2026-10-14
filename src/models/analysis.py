"""Strict expert output contract; model conclusions are not execution evidence."""

import re
from typing import Annotated, Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, model_validator
from pydantic_core import PydanticCustomError

from .normalized_input import INPUT_DIMENSIONS


NonBlankString = Annotated[str, StringConstraints(strict=True, min_length=1, pattern=r"\S")]
CveId = Annotated[
    str, StringConstraints(strict=True, pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
]
CweId = Annotated[str, StringConstraints(strict=True, pattern=r"^CWE-[0-9]+$")]
StepId = Annotated[str, StringConstraints(strict=True, pattern=r"^S[0-9]{2,}$")]


class AnalysisValidationError(ValueError):
    """Machine readable, value-free validation failure for an expert response."""

    def __init__(self, category: str, diagnostics: List[Dict[str, Any]]) -> None:
        self.category = category
        self.diagnostics = diagnostics
        super().__init__(f"Expert analysis rejected ({category}); see structural diagnostics.")


class StrictAnalysisModel(BaseModel):
    """Reject unknown keys and coercion rather than silently accepting guesses."""

    model_config = ConfigDict(strict=True, extra="forbid")


class Step(StrictAnalysisModel):
    """One required strategy step; its conditions are proposals, not observations."""

    step_id: StepId = Field(description="Ordered step ID: S01, S02, ...")
    description: NonBlankString
    pseudocode: NonBlankString
    success_condition: NonBlankString
    failure_condition: NonBlankString
    expected_cuda_behavior: NonBlankString
    expected_outcome: Optional[NonBlankString] = Field(
        default=None, description="Optional legacy explanatory outcome"
    )


class VerificationStrategy(StrictAnalysisModel):
    """The complete strategy contract advertised in the CUDA expert prompt."""

    goal: NonBlankString = Field(description="利用目标")
    preconditions: List[NonBlankString] = Field(description="触发漏洞前必须满足的 CUDA 前提条件")
    steps: List[Step] = Field(min_length=1)
    confidence: float = Field(strict=True, ge=0.0, le=1.0, allow_inf_nan=False)
    cuda_version_range: NonBlankString = Field(description="受影响的 CUDA Toolkit 版本范围")
    gpu_arch_range: NonBlankString = Field(description="受影响的 GPU 架构范围")
    evidence: Optional[List[NonBlankString]] = Field(
        default=None, description="Optional model-cited sources; not verified evidence"
    )

    @model_validator(mode="after")
    def validate_step_sequence(self) -> "VerificationStrategy":
        """Require unique, ordered, contiguous identifiers starting at S01."""
        if any(step.step_id != f"S{index:02d}" for index, step in enumerate(self.steps, 1)):
            raise PydanticCustomError(
                "invalid_step_sequence", "step identifiers must be unique and ordered S01, S02, ..."
            )
        return self


class RootCauseAnalysis(StrictAnalysisModel):
    """All existing CUDA-specific root-cause fields are mandatory."""

    cve_id: CveId = Field(description="CVE 编号")
    cwe_id: CweId = Field(description="CWE 编号（只校验格式，不代表已核实分类）")
    cuda_attack_surface: NonBlankString = Field(description="受影响的 CUDA 子系统")
    vulnerability_class: NonBlankString = Field(
        description="漏洞类别: integer-overflow, heap-buffer-overflow, UAF, race-condition, etc."
    )
    primitive: NonBlankString = Field(
        description="漏洞原语: OOB-write, OOB-read, UAF, integer-wraparound, double-free, type-confusion"
    )
    root_cause_description: NonBlankString = Field(description="根因的详细技术描述")
    affected_code_path: NonBlankString = Field(description="受影响的 CUDA 代码路径")
    controllability: NonBlankString = Field(
        description="测试者可控制输入的精确描述（buffer size, file content, kernel args, etc.）"
    )
    relevant_mitigations: List[NonBlankString] = Field(description="目标环境中相关的缓解措施列表")


class ExpertAnalysis(StrictAnalysisModel):
    """Validated before a candidate can enter the code generator."""

    root_cause_analysis: RootCauseAnalysis
    verification_strategy: VerificationStrategy


def resolve_target_cve(
    vuln_context: Dict[str, Any], expected_cve_id: Optional[str] = None
) -> Optional[str]:
    """Resolve explicit target IDs before any model request or candidate generation.

    Inspect the seven known dimensions in flat or wrapped form and an optional
    top-level ID. All supplied IDs must be valid and agree with the explicit
    expected ID. A legacy context with no IDs returns None and is not bound to
    a target; the normal application pipeline requires normalized seven inputs.
    This helper checks identity only, not source claims or other input fields.
    """
    if not isinstance(vuln_context, dict):
        raise AnalysisValidationError(
            "SCHEMA_ERROR", [{"path": ["input"], "code": "input_context_not_object"}]
        )
    supplied = []
    if "cve_id" in vuln_context:
        supplied.append((["input", "cve_id"], vuln_context["cve_id"]))
    for dimension in INPUT_DIMENSIONS:
        payload = vuln_context.get(dimension)
        if not isinstance(payload, dict):
            continue
        if "cve_id" in payload:
            supplied.append((["input", dimension, "cve_id"], payload["cve_id"]))
        wrapped = payload.get(dimension)
        if isinstance(wrapped, dict) and "cve_id" in wrapped:
            supplied.append((["input", dimension, dimension, "cve_id"], wrapped["cve_id"]))
    if expected_cve_id is not None:
        supplied.append((["expected_cve_id"], expected_cve_id))
    for path, target in supplied:
        if not isinstance(target, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", target):
            raise AnalysisValidationError(
                "SCHEMA_ERROR", [{"path": path, "code": "invalid_target_cve"}]
            )
    input_ids = {target for path, target in supplied if path[0] == "input"}
    if len(input_ids) > 1:
        raise AnalysisValidationError(
            "CVE_MISMATCH", [{"path": ["input", "cve_id"], "code": "ambiguous_input_target"}]
        )
    target = next(iter(input_ids)) if input_ids else None
    if expected_cve_id is not None and target is not None and target != expected_cve_id:
        raise AnalysisValidationError(
            "CVE_MISMATCH", [{"path": ["expected_cve_id"], "code": "input_target_mismatch"}]
        )
    return expected_cve_id if expected_cve_id is not None else target


def validate_analysis(
    raw: Dict[str, Any], expected_cve_id: Optional[str] = None
) -> ExpertAnalysis:
    """Validate structure and target identity without echoing raw field values.

    Raises AnalysisValidationError with SCHEMA_ERROR or CVE_MISMATCH. Required
    fields have no defaults; missing information cannot become a valid analysis.
    """
    try:
        parsed = ExpertAnalysis.model_validate(raw)
    except ValidationError as exc:
        diagnostics = []
        for error in exc.errors(include_url=False, include_context=False, include_input=False):
            location = list(error["loc"])
            if error["type"] in {"extra_forbidden", "invalid_key"} and location:
                # Even an unknown field name can carry private response content.
                location[-1] = "<unknown_field>"
            diagnostics.append({"path": location, "code": error["type"]})
        raise AnalysisValidationError("SCHEMA_ERROR", diagnostics) from None
    if expected_cve_id is not None:
        if not isinstance(expected_cve_id, str) or not re.fullmatch(
            r"CVE-[0-9]{4}-[0-9]{4,}", expected_cve_id
        ):
            raise AnalysisValidationError(
                "SCHEMA_ERROR", [{"path": ["expected_cve_id"], "code": "invalid_target_cve"}]
            )
        if parsed.root_cause_analysis.cve_id != expected_cve_id:
            raise AnalysisValidationError(
                "CVE_MISMATCH",
                [{"path": ["root_cause_analysis", "cve_id"], "code": "target_cve_mismatch"}],
            )
    return parsed
