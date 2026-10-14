"""Lossless input provenance and conservative seven-dimension normalization.

VALID describes input structure only. Every assertion remains unverified; this
module does not establish that a CVE description or environment claim is true.
"""

from copy import deepcopy
from enum import Enum
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


INPUT_DIMENSIONS = (
    "os_environment", "cuda_environment", "affected_component", "attack_surface",
    "vulnerability_type", "impact_controllability", "root_cause",
)
CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
_CWE_PATTERN = re.compile(r"CWE-[0-9]+\Z")
_UNKNOWN_STRINGS = {"unknown", "unspecified", "not known", "tbd", "未知", "待确认"}
# Leave headroom for provenance and manifest serialization. Pydantic can reject
# a deeply nested arbitrary JSON payload before Python's recursion limit does.
_MAX_INPUT_NESTING = 128


class FieldState(str, Enum):
    MISSING = "MISSING"
    UNKNOWN = "UNKNOWN"
    CONFLICT = "CONFLICT"
    VALID = "VALID"
    INVALID = "INVALID"


class InputSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_file: str
    sha256: Optional[str] = None
    size_bytes: Optional[int] = None


class FieldProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dimension: str
    normalized_path: str
    source_file: str
    field_path: str
    state: FieldState
    assertion_kind: Literal["input_assertion"] = "input_assertion"
    verification: Literal["unverified"] = "unverified"


class InputDiagnostic(BaseModel):
    """Diagnostics contain locations and reasons, never input field values."""

    model_config = ConfigDict(extra="forbid")
    code: str
    severity: Literal["ERROR", "WARNING"] = "ERROR"
    dimension: str
    normalized_path: str
    source_file: str
    field_paths: List[str] = Field(default_factory=list)
    message: str


class InputValidationError(ValueError):
    def __init__(self, result: "NormalizedInput") -> None:
        self.result = result
        self.diagnostics = result.diagnostics
        codes = sorted({item.code for item in result.diagnostics if item.severity == "ERROR"})
        super().__init__("Input validation failed: " + ", ".join(codes))


class NormalizedInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0"
    cve_id: Optional[str] = None
    dimensions: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    raw_inputs: Dict[str, Any] = Field(default_factory=dict)
    sources: Dict[str, InputSource] = Field(default_factory=dict)
    field_states: Dict[str, FieldState] = Field(default_factory=dict)
    provenance: List[FieldProvenance] = Field(default_factory=list)
    diagnostics: List[InputDiagnostic] = Field(default_factory=list)
    assertion_kind: Literal["input_assertion"] = "input_assertion"
    verification: Literal["unverified"] = "unverified"

    @property
    def is_valid(self) -> bool:
        return not any(item.severity == "ERROR" for item in self.diagnostics)

    def require_valid(self) -> "NormalizedInput":
        if not self.is_valid:
            raise InputValidationError(self)
        return self


def _pointer(parts: tuple) -> str:
    return "/" + "/".join(str(part).replace("~", "~0").replace("/", "~1") for part in parts)


def _same_value(left: Any, right: Any) -> bool:
    """JSON equality must not equate true and 1 or silently coerce types."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_same_value(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_same_value(a, b) for a, b in zip(left, right))
    return left == right


def _unknown(value: Any) -> bool:
    return value is None or (isinstance(value, str)
                             and (not value.strip() or value.strip().lower() in _UNKNOWN_STRINGS))


def _finite_json_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise ValueError("Nonfinite JSON number")
    return value


def _reject_json_constant(token: str) -> None:
    raise ValueError("Nonfinite JSON number")


class _JSONObject(list):
    """Keep duplicate keys until their original paths have been checked."""


def _supported_nesting(document: Any) -> bool:
    pending = [(document, 1)]
    while pending:
        node, depth = pending.pop()
        if not isinstance(node, list):
            continue
        if depth > _MAX_INPUT_NESTING:
            return False
        children = (value for _, value in node) if isinstance(node, _JSONObject) else iter(node)
        pending.extend((child, depth + 1) for child in children if isinstance(child, list))
    return True


_STRING_FIELDS = {
    "os_environment": {
        "os_name", "os_version", "kernel_version", "architecture", "notes", "tested_environment",
        "required_hardware", "configuration_notes",
    },
    "cuda_environment": {
        "cuda_driver_version", "cuda_toolkit_version", "gpu_architecture", "compute_capability",
        "gpu_model", "cuda_version_affected", "fix_version", "driver_version", "tool_path", "note",
        "windows_path_hint", "linux_path_hint",
    },
    "affected_component": {
        "name", "component_name", "version_range", "vendor", "advisory_url", "product_url",
        "description", "type", "affected_binary", "tool_path", "vulnerable_function",
        "file_format_input", "attack_entry_point",
    },
    "attack_surface": {
        "surface_type", "entry_point", "attack_vector", "privilege_required", "trigger_mechanism",
        "exploit_primitive", "subsystem", "entry_type", "required_permissions", "attack_complexity",
        "remote_trigger",
    },
    "vulnerability_type": {
        "cwe_id", "cwe_name", "vulnerability_category", "cvss_severity", "cvss_vector", "subtype",
        "validation_impact",
    },
    "impact_controllability": {
        "exploitation_difficulty", "trigger_feasibility", "privilege_required_level",
        "attack_complexity_level", "user_interaction", "scope", "confidentiality_impact",
        "integrity_impact", "availability_impact",
    },
    "root_cause": {
        "summary", "cwe_classification", "cuda_subsystem", "patch_analysis", "file", "function",
        "line", "vulnerable_code_summary", "fixed_code_summary", "root_cause_detail", "fix_mechanism",
        "introduced_by", "reported_by", "fix_description", "fix_version",
    },
}
_STRING_LIST_FIELDS = {
    "os_environment": {"operating_systems", "software_requirements", "key_dependencies"},
    "cuda_environment": {"affected_tools", "cuda_api_surface"},
    "vulnerability_type": {"related_cwe"},
    "impact_controllability": {"controllable_fields", "controllable_factors", "limiting_factors"},
    "root_cause": {"technical_details", "exploit_requirements", "references", "disclosure_timeline"},
}
# These identical keys explicitly denote the same environment property. Generic
# name, tool_path, fix_version and prose descriptions can have different meanings
# across dimensions, so we deliberately do not compare them as shared facts.
_SHARED_ENV_FIELDS = {
    "os_name", "os_version", "kernel_version", "architecture", "cuda_driver_version",
    "cuda_toolkit_version", "driver_version", "gpu_architecture", "compute_capability", "gpu_model",
}


class _Normalizer:
    def __init__(self, result: NormalizedInput) -> None:
        self.result = result
        self.origins: Dict[str, List[str]] = {}

    def diagnostic(self, dimension: str, path: str, code: str, message: str,
                   state: FieldState = FieldState.INVALID, field_paths: Optional[List[str]] = None) -> None:
        self.result.field_states[path] = state
        self.result.diagnostics.append(InputDiagnostic(
            code=code, dimension=dimension, normalized_path=path,
            source_file=self.result.sources[dimension].source_file,
            field_paths=field_paths if field_paths is not None else self.origins.get(path, []),
            message=message,
        ))

    def decode(self, node: Any, dimension: str, parts: tuple = ()) -> Any:
        if isinstance(node, _JSONObject):
            output = {}
            seen = {}
            for key, value in node:
                decoded = self.decode(value, dimension, parts + (key,))
                if key in seen:
                    if not _same_value(seen[key], decoded):
                        source_path = _pointer(parts + (key,))
                        logical_parts = parts[1:] if parts and parts[0] == dimension else parts
                        path = _pointer(("dimensions", dimension) + logical_parts + (key,))
                        self.diagnostic(dimension, path, "DUPLICATE_KEY_CONFLICT",
                                        "Repeated JSON key has different values; no value was selected.",
                                        FieldState.CONFLICT, [source_path])
                        output.pop(key, None)
                else:
                    seen[key] = decoded
                    output[key] = decoded
            return output
        if isinstance(node, list):
            return [self.decode(value, dimension, parts + (index,)) for index, value in enumerate(node)]
        return node

    def record_origins(self, node: Any, dimension: str, source_parts: tuple, logical_parts: tuple) -> None:
        path = _pointer(("dimensions", dimension) + logical_parts)
        self.origins.setdefault(path, []).append(_pointer(source_parts))
        if isinstance(node, dict):
            for key, value in node.items():
                self.record_origins(value, dimension, source_parts + (key,), logical_parts + (key,))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                self.record_origins(value, dimension, source_parts + (index,), logical_parts + (index,))

    def merge(self, left: dict, right: dict, dimension: str, parts: tuple = ()) -> dict:
        output = deepcopy(left)
        for key, value in right.items():
            if key not in output:
                output[key] = deepcopy(value)
            elif isinstance(output[key], dict) and isinstance(value, dict):
                output[key] = self.merge(output[key], value, dimension, parts + (key,))
            elif not _same_value(output[key], value):
                path = _pointer(("dimensions", dimension) + parts + (key,))
                self.diagnostic(dimension, path, "FIELD_CONFLICT",
                                "Flat and wrapped fields conflict; neither value was selected.",
                                FieldState.CONFLICT)
                del output[key]
        return output

    def flatten(self, raw: dict, dimension: str) -> dict:
        outer = {key: value for key, value in raw.items() if key != dimension}
        for key, value in outer.items():
            self.record_origins(value, dimension, (key,), (key,))
        if dimension not in raw:
            return deepcopy(outer)
        wrapped = raw[dimension]
        if not isinstance(wrapped, dict):
            self.diagnostic(dimension, _pointer(("dimensions", dimension)), "WRAPPER_TYPE_ERROR",
                            "A dimension wrapper must be a JSON object.", field_paths=[_pointer((dimension,))])
            return deepcopy(outer)
        for key, value in wrapped.items():
            self.record_origins(value, dimension, (dimension, key), (key,))
        return self.merge(outer, wrapped, dimension)

    def state_tree(self, value: Any, dimension: str, parts: tuple = ()) -> None:
        path = _pointer(("dimensions", dimension) + parts)
        self.result.field_states.setdefault(path, FieldState.UNKNOWN if _unknown(value) else FieldState.VALID)
        if isinstance(value, dict):
            for key, child in value.items():
                self.state_tree(child, dimension, parts + (key,))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                self.state_tree(child, dimension, parts + (index,))

    def check_types(self, payload: dict, dimension: str) -> None:
        for key, value in payload.items():
            path = _pointer(("dimensions", dimension, key))
            if value is None:
                continue  # Explicitly unknown; required fields are checked below.
            if key == "cve_id" or key in _STRING_FIELDS[dimension] or key in _SHARED_ENV_FIELDS:
                if not isinstance(value, str):
                    self.diagnostic(dimension, path, "FIELD_TYPE_ERROR", "Field must be a string or null.")
            elif key in _STRING_LIST_FIELDS.get(dimension, set()):
                if not isinstance(value, list):
                    self.diagnostic(dimension, path, "FIELD_TYPE_ERROR", "Field must be an array of strings or null.")
                else:
                    for index, item in enumerate(value):
                        if not isinstance(item, str):
                            self.diagnostic(dimension, _pointer(("dimensions", dimension, key, index)),
                                            "FIELD_TYPE_ERROR", "Array item must be a string.")
            elif dimension == "impact_controllability" and key in {"impact", "controllability"}:
                if not isinstance(value, dict) and not (key == "impact" and isinstance(value, str)):
                    self.diagnostic(dimension, path, "FIELD_TYPE_ERROR", "Field must be an object (impact also permits a string).")
                elif isinstance(value, dict):
                    for child, item in value.items():
                        if item is not None and not isinstance(item, str):
                            self.diagnostic(dimension, _pointer(("dimensions", dimension, key, child)),
                                            "FIELD_TYPE_ERROR", "Impact/controllability property must be a string or null.")
            elif dimension == "vulnerability_type" and key == "cvss_score" and not _unknown(value):
                try:
                    score = float(value) if type(value) in (str, int, float) else math.nan
                except ValueError:
                    score = math.nan
                if not math.isfinite(score) or not 0 <= score <= 10:
                    self.diagnostic(dimension, path, "FIELD_RANGE_ERROR", "CVSS score must be a finite number in [0, 10].")

    def require_one(self, payload: dict, dimension: str, keys: tuple) -> None:
        if any(isinstance(payload.get(key), str) and not _unknown(payload[key]) for key in keys):
            return
        for key in keys:
            path = _pointer(("dimensions", dimension, key))
            if self.result.field_states.get(path) in {FieldState.CONFLICT, FieldState.INVALID}:
                continue
            state = FieldState.UNKNOWN if key in payload else FieldState.MISSING
            self.diagnostic(dimension, path, "REQUIRED_FIELD_UNKNOWN" if key in payload else "REQUIRED_FIELD_MISSING",
                            "At least one required field must contain a nonempty known string: " + ", ".join(keys), state)

    def finish(self) -> NormalizedInput:
        ids = {}
        for dimension in INPUT_DIMENSIONS:
            payload = self.result.dimensions[dimension]
            self.state_tree(payload, dimension)
            for field in _STRING_FIELDS[dimension] | _STRING_LIST_FIELDS.get(dimension, set()):
                if field not in payload:
                    self.result.field_states.setdefault(
                        _pointer(("dimensions", dimension, field)), FieldState.MISSING
                    )
            self.check_types(payload, dimension)
            self.require_one(payload, dimension, ("cve_id",))
            cve_id = payload.get("cve_id")
            if isinstance(cve_id, str) and not _unknown(cve_id):
                if CVE_PATTERN.fullmatch(cve_id):
                    ids[dimension] = cve_id
                else:
                    self.diagnostic(dimension, _pointer(("dimensions", dimension, "cve_id")),
                                    "CVE_ID_FORMAT_ERROR", "CVE ID must use CVE-YYYY-NNNN (at least four sequence digits).")
        for dimension, keys in {
            "affected_component": ("name", "component_name"),
            "attack_surface": ("entry_point",),
            "vulnerability_type": ("cwe_id",),
            "root_cause": ("summary", "vulnerable_code_summary"),
        }.items():
            self.require_one(self.result.dimensions[dimension], dimension, keys)
        cwe = self.result.dimensions["vulnerability_type"].get("cwe_id")
        if isinstance(cwe, str) and not _unknown(cwe) and not _CWE_PATTERN.fullmatch(cwe):
            self.diagnostic("vulnerability_type", "/dimensions/vulnerability_type/cwe_id",
                            "CWE_ID_FORMAT_ERROR", "CWE ID must use CWE followed by a numeric identifier.")
        if len(set(ids.values())) > 1:
            for dimension in ids:
                self.diagnostic(dimension, _pointer(("dimensions", dimension, "cve_id")), "CVE_ID_CONFLICT",
                                "CVE identifiers disagree across the seven input files.", FieldState.CONFLICT)
        elif ids:
            self.result.cve_id = next(iter(ids.values()))
        for key in sorted(_SHARED_ENV_FIELDS):
            supplied = {dim: payload[key] for dim, payload in self.result.dimensions.items()
                        if key in payload and not _unknown(payload[key])}
            if len(supplied) > 1 and any(not _same_value(value, next(iter(supplied.values())))
                                         for value in supplied.values()):
                for dimension in supplied:
                    self.diagnostic(dimension, _pointer(("dimensions", dimension, key)), "SHARED_FIELD_CONFLICT",
                                    "An explicitly shared environment field disagrees across input files.", FieldState.CONFLICT)
        for path, source_paths in self.origins.items():
            dimension = path.split("/")[2]
            state = self.result.field_states.get(path, FieldState.CONFLICT)
            for source_path in source_paths:
                self.result.provenance.append(FieldProvenance(
                    dimension=dimension, normalized_path=path,
                    source_file=self.result.sources[dimension].source_file, field_path=source_path, state=state,
                ))
        return self.result


def normalize_input_files(directory: str | Path, input_files: Optional[Dict[str, str]] = None) -> NormalizedInput:
    """Read all seven files without modifying them or selecting conflicting values.

    Invalid/missing/non-object files have raw_inputs[dimension] = None. Their
    original on-disk bytes remain unchanged and their exact hash is retained when
    readable. Valid parsed objects retain all fields in raw_inputs.
    """
    base = Path(directory)
    result = NormalizedInput(dimensions={dimension: {} for dimension in INPUT_DIMENSIONS})
    normalizer = _Normalizer(result)
    for index, dimension in enumerate(INPUT_DIMENSIONS, 1):
        filename = (input_files or {}).get(dimension) or f"{index}_{dimension}.json"
        filepath = base / filename
        source_file = Path(os.path.relpath(filepath, base)).as_posix()
        result.sources[dimension] = InputSource(source_file=source_file)
        result.raw_inputs[dimension] = None
        path = _pointer(("dimensions", dimension))
        try:
            content = filepath.read_bytes()
        except FileNotFoundError:
            normalizer.diagnostic(dimension, path, "INPUT_FILE_MISSING", "Required input file does not exist.", FieldState.MISSING)
            continue
        except OSError:
            normalizer.diagnostic(dimension, path, "INPUT_FILE_READ_ERROR", "Input file could not be read.")
            continue
        result.sources[dimension].sha256 = hashlib.sha256(content).hexdigest()
        result.sources[dimension].size_bytes = len(content)
        try:
            document = json.loads(content.decode("utf-8-sig"), object_pairs_hook=_JSONObject,
                                  parse_float=_finite_json_float, parse_constant=_reject_json_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            normalizer.diagnostic(dimension, path, "INPUT_JSON_ERROR", "Input is not valid finite UTF-8 JSON.")
            continue
        if not isinstance(document, _JSONObject):
            normalizer.diagnostic(dimension, path, "INPUT_OBJECT_REQUIRED", "Input JSON root must be an object.")
            continue
        if not _supported_nesting(document):
            normalizer.diagnostic(dimension, path, "INPUT_JSON_ERROR", "Input exceeds the supported 128-level JSON nesting depth.")
            continue
        try:
            before = len(result.diagnostics)
            raw = normalizer.decode(document, dimension)
            if len(result.diagnostics) > before:
                continue
            result.raw_inputs[dimension] = deepcopy(raw)
            result.dimensions[dimension] = normalizer.flatten(raw, dimension)
        except RecursionError:
            result.raw_inputs[dimension] = None
            result.dimensions[dimension] = {}
            prefix = _pointer(("dimensions", dimension)) + "/"
            normalizer.origins = {key: value for key, value in normalizer.origins.items()
                                  if not key.startswith(prefix)}
            normalizer.diagnostic(dimension, path, "INPUT_JSON_ERROR", "Input exceeds supported JSON nesting depth.")
    return normalizer.finish()
