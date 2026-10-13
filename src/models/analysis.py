"""Analysis models — expert analysis output and verification strategy."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Step(BaseModel):
    """A single verification step from the expert analysis."""
    step_id: str = Field(default="", description="Step ID, e.g. 'S01'")
    description: str = Field(default="", description="Step description")
    expected_outcome: str = Field(default="", description="Expected outcome for success")


class VerificationStrategy(BaseModel):
    """Verification strategy produced by the CudaSecurityExpert."""
    goal: str = Field(default="", description="Verification goal")
    cuda_version_range: str = Field(default="", description="Target CUDA version range")
    gpu_arch_range: str = Field(default="", description="Target GPU architecture range")
    steps: List[Step] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence: List[str] = Field(default_factory=list,
                                 description="Evidence sources: files, URLs, commit hashes")


class RootCauseAnalysis(BaseModel):
    """Root cause analysis from expert."""
    cve_id: str = Field(default="")
    cwe_id: str = Field(default="")
    cuda_attack_surface: str = Field(default="")
    vulnerability_class: str = Field(default="")
    primitive: str = Field(default="")


class ExpertAnalysis(BaseModel):
    """Full expert analysis output — validated before entering code generation."""
    root_cause_analysis: RootCauseAnalysis = Field(default_factory=RootCauseAnalysis)
    verification_strategy: VerificationStrategy = Field(default_factory=VerificationStrategy)


def validate_analysis(raw: Dict[str, Any]) -> ExpertAnalysis:
    """Parse and validate LLM output as ExpertAnalysis.

    Returns parsed model on success. On failure, raises ValueError.
    Does NOT return raw dicts — garbage stays out of the pipeline.
    """
    if "raw" in raw and len(raw) == 1:
        raise ValueError("LLM returned garbage (only 'raw' key)")
    try:
        return ExpertAnalysis.model_validate(raw)
    except Exception as e:
        raise ValueError(f"ExpertAnalysis validation failed: {e}") from e
