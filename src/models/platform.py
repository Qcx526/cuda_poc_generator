"""Strict platform observations with explicit epistemic status and provenance."""

import copy
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from ..platform_identity import compute_environment_id


FieldStatus = Literal["OBSERVED", "INFERRED", "CONFIGURED", "UNKNOWN", "NOT_CHECKED", "FAILED"]
UNKNOWN_STATUSES = {"UNKNOWN", "NOT_CHECKED", "FAILED"}


class PlatformField(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)

    status: FieldStatus
    value: JsonValue
    source_ids: list[str]
    method: str = Field(min_length=1)

    @model_validator(mode="after")
    def check_state(self):
        if not self.method.strip():
            raise ValueError("field method must not be blank")
        if any(not item.strip() for item in self.source_ids):
            raise ValueError("source identifiers must not be blank")
        if len(set(self.source_ids)) != len(self.source_ids):
            raise ValueError("duplicate source identifiers")
        if self.status in UNKNOWN_STATUSES:
            if self.value is not None:
                raise ValueError("unknown, unchecked or failed fields must have a null value")
        elif self.value is None:
            raise ValueError("known fields must contain an actual value")
        if self.status == "OBSERVED" and not self.source_ids:
            raise ValueError("observed fields require a recorded source")
        return self


class ProbeSource(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    method: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    command_id: str | None

    @model_validator(mode="after")
    def check_nonblank(self):
        if not self.method.strip() or not self.environment.strip():
            raise ValueError("provenance method and environment must not be blank")
        if self.command_id is not None and not self.command_id.strip():
            raise ValueError("command identity must not be blank")
        return self


class ProbeDiagnostic(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    code: str = Field(min_length=1)
    field: str = Field(min_length=1)
    message: str = Field(min_length=1)


class PlatformSnapshot(BaseModel):
    """A current probe record; it cannot attest execution or CVE verification."""

    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)

    schema_version: Literal["1.0"]
    platform_type: Literal["windows", "linux", "wsl"]
    environment_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    execution_backend: Literal["local", "wsl"]
    host_os: PlatformField
    kernel: PlatformField
    architecture: PlatformField
    python_version: PlatformField
    gpu_devices: PlatformField
    driver_release: PlatformField
    cuda_driver_api_version: PlatformField
    driver_reported_cuda_version: PlatformField
    cuda_toolkit_version: PlatformField
    nvcc_path: PlatformField
    nvcc_version: PlatformField
    supported_architectures: PlatformField
    compute_sanitizer_path: PlatformField
    compute_sanitizer_version: PlatformField
    host_compiler: PlatformField
    probe_status: Literal["COMPLETE", "PARTIAL", "FAILED"]
    provenance: dict[str, ProbeSource]
    diagnostics: list[ProbeDiagnostic]
    metadata: dict[str, JsonValue]

    @model_validator(mode="after")
    def check_snapshot(self):
        if self.execution_backend == "wsl" and self.platform_type != "wsl":
            raise ValueError("WSL backend requires a WSL platform snapshot")
        for name in self.provenance:
            if not name.strip():
                raise ValueError("provenance identifiers must not be blank")
        for name in ("probe_id", "nonce", "environment_label"):
            if not isinstance(self.metadata.get(name), str) or not self.metadata[name].strip():
                raise ValueError(f"metadata.{name} must be a nonblank string")
        if any(source.environment != self.metadata["environment_label"] for source in self.provenance.values()):
            raise ValueError("provenance belongs to a different environment")
        for name in ("platform_classification", "backend_selection", "reported_cuda_umd_version"):
            if name in self.metadata:
                entry = PlatformField.model_validate(self.metadata[name])
                self._check_sources(f"metadata.{name}", entry)
                self._text(f"metadata.{name}", entry)
        for name in self.__class__.model_fields:
            item = getattr(self, name)
            if isinstance(item, PlatformField):
                self._check_sources(name, item)
        self._check_values()
        if compute_environment_id(self.model_dump(mode="json")) != self.environment_id:
            raise ValueError("environment_id does not match scientific platform content")
        return self

    def _check_sources(self, name, item):
        missing = set(item.source_ids).difference(self.provenance)
        if missing:
            raise ValueError(f"{name} references unrecorded sources")

    @staticmethod
    def _text(name, item):
        if item.value is not None and (not isinstance(item.value, str) or not item.value.strip()):
            raise ValueError(f"{name} requires a nonblank string value")

    def _check_values(self):
        for name in (
            "host_os", "kernel", "architecture", "python_version", "driver_release",
            "driver_reported_cuda_version", "cuda_toolkit_version", "nvcc_path",
            "nvcc_version", "compute_sanitizer_path", "compute_sanitizer_version",
        ):
            self._text(name, getattr(self, name))
        driver_api = self.cuda_driver_api_version.value
        if driver_api is not None and (type(driver_api) is not int or driver_api <= 0):
            raise ValueError("cuda_driver_api_version must be a positive integer")
        if self.platform_type in {"linux", "wsl"}:
            for name in ("nvcc_path", "compute_sanitizer_path"):
                path = getattr(self, name).value
                if path is not None and ("\\" in path or re.match(r"^[A-Za-z]:", path) or not path.startswith("/")):
                    raise ValueError(f"{name} must use an absolute Linux path")
        self._check_architectures()
        self._check_gpus()
        self._check_compilers()

    def _check_architectures(self):
        architectures = self.supported_architectures.value
        if architectures is None:
            return
        if not isinstance(architectures, list) or any(
            not isinstance(item, str) or not re.fullmatch(r"(?:sm|compute)_[0-9]+[a-z]?", item)
            for item in architectures
        ):
            raise ValueError("supported_architectures requires nvcc architecture strings")
        if len(set(architectures)) != len(architectures):
            raise ValueError("supported_architectures contains duplicates")

    def _check_gpus(self):
        devices = self.gpu_devices.value
        if devices is None:
            return
        if not isinstance(devices, list):
            raise ValueError("gpu_devices requires a device list")
        indices = set()
        for position, device in enumerate(devices):
            prefix = f"gpu_devices[{position}]"
            if not isinstance(device, dict) or set(device) != {"index", "name", "compute_capability", "sm_arch"}:
                raise ValueError(f"{prefix} requires index/name/compute_capability/sm_arch fields")
            fields = {key: PlatformField.model_validate(value) for key, value in device.items()}
            for key, value in fields.items():
                self._check_sources(f"{prefix}.{key}", value)
            index = fields["index"].value
            if index is not None:
                if type(index) is not int or index < 0 or index in indices:
                    raise ValueError(f"{prefix}.index must be a unique nonnegative integer")
                indices.add(index)
            self._text(f"{prefix}.name", fields["name"])
            capability = fields["compute_capability"].value
            sm = fields["sm_arch"].value
            if capability is not None and (
                not isinstance(capability, str) or not re.fullmatch(r"[1-9][0-9]*\.[0-9]", capability)
            ):
                raise ValueError(f"{prefix}.compute_capability requires major.minor")
            if sm is not None:
                if fields["sm_arch"].status != "INFERRED":
                    raise ValueError(f"{prefix}.sm_arch must be labelled INFERRED")
                if capability is None or sm != "sm_" + capability.replace(".", ""):
                    raise ValueError(f"{prefix}.sm_arch must agree with compute capability")

    def _check_compilers(self):
        compilers = self.host_compiler.value
        if compilers is None:
            return
        if not isinstance(compilers, dict) or not compilers or not set(compilers).issubset({"gcc", "g++", "msvc"}):
            raise ValueError("host_compiler requires compiler-name to wrapped-field entries")
        for name, item in compilers.items():
            entry = PlatformField.model_validate(item)
            self._check_sources(f"host_compiler.{name}", entry)
            self._text(f"host_compiler.{name}", entry)


def seal_snapshot(payload):
    """Compute a new record identity and validate a newly collected snapshot.

    Reading an existing record must use ``PlatformSnapshot.model_validate`` so
    that a stored identity mismatch is detected instead of silently repaired.
    """
    result = copy.deepcopy(payload)
    result["environment_id"] = compute_environment_id(result)
    return PlatformSnapshot.model_validate(result)
