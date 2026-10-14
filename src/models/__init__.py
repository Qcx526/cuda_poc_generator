"""Input normalization, strict analysis contracts and independent candidate states.

Exports:
  VulnerabilityInputBundle
  ExpertAnalysis, VerificationStrategy, Step
"""

from .vulnerability import (
    VulnerabilityInputBundle,
    OSEnvironment,
    CudaEnvironment,
    AffectedComponent,
    AttackSurface,
    VulnerabilityType,
    ImpactControllability,
    RootCause,
)
from .analysis import (
    ExpertAnalysis, VerificationStrategy, Step, AnalysisValidationError,
    resolve_target_cve, validate_analysis,
)
from .normalized_input import NormalizedInput, InputValidationError, FieldState, normalize_input_files
from .generation import CandidateResult

__all__ = [
    "VulnerabilityInputBundle",
    "OSEnvironment", "CudaEnvironment", "AffectedComponent",
    "AttackSurface", "VulnerabilityType", "ImpactControllability", "RootCause",
    "ExpertAnalysis", "VerificationStrategy", "Step", "validate_analysis",
    "AnalysisValidationError", "resolve_target_cve", "NormalizedInput", "InputValidationError",
    "FieldState", "normalize_input_files", "CandidateResult",
]
