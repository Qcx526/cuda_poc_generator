"""Independent candidate states; these models never assert execution or verification."""

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class CandidateResult(BaseModel):
    """Metadata for one generation attempt, not a vulnerability verdict."""

    model_config = ConfigDict(extra="forbid", strict=True)

    run_id: Optional[str] = None
    generation: Literal["NOT_GENERATED", "GENERATED", "GENERATION_FAILED"] = "NOT_GENERATED"
    static: Literal["NOT_CHECKED", "STATIC_VALID", "STATIC_INVALID"] = "NOT_CHECKED"
    execution: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    verification: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"
    source_file: Optional[str] = None
    sha256: Optional[str] = None
    correction_attempts: int = Field(default=0, ge=0, le=2)
    errors: list[str] = Field(default_factory=list)
    check_method: Literal["python_ast_struct_name_heuristics"] = "python_ast_struct_name_heuristics"
