"""Bounded native-file export and exact Windows-side evidence association."""

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Literal

from pydantic import Field, model_validator

from .models.execution import ExecutionRequest, OperatorAuthorization, PreflightPolicy
from .models.lifecycle import (ExecutionRecord, LifecycleContract, NativeEvidenceVerification,
                               canonical_sha256)
from .models.platform import PlatformSnapshot
from .models.tool_result import ToolResult


STEP_IDS = ("nvcc_version", "cuobjdump_version", "nvdisasm_version", "compile", "cuobjdump", "nvdisasm")
BASE_FILES = ("lease.json", "request.json", "authorization.json", "policy.json", "snapshot.json",
              "tool_record.json", "preflight.json", "execution_record.json", "stdout.bin", "stderr.bin",
              "worker_events.jsonl", "cancel.json", "work/safe_smoke.cu", "work/out/safe_smoke.cubin")
NATIVE_FILES = frozenset(BASE_FILES) | frozenset(
    "steps/" + step + "/" + name for step in STEP_IDS for name in ("stdout.bin", "stderr.bin", "process_result.json"))
WINDOWS_NAMES = {name: "native_" + name.replace("/", "_") for name in NATIVE_FILES}
MAX_NATIVE_FILE = 4194304
MAX_NATIVE_TOTAL = 8388608


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _load(raw):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate native evidence key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite native evidence JSON")))


def _model(model, value):
    return model.model_validate(value.model_dump(mode="python") if isinstance(value, model) else value)


class NativeArtifact(LifecycleContract):
    file: str
    size_bytes: int = Field(ge=0, le=MAX_NATIVE_FILE)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def fixed_file(self):
        if self.file not in NATIVE_FILES:
            raise ValueError("native evidence file is not registered")
        return self


class NativeEvidenceIndex(LifecycleContract):
    native_schema_version: Literal["1.0"] = "1.0"
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    run_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    target_environment: str
    execution_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_record_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    indexed_at: str
    status: Literal["COMPLETE", "INCOMPLETE", "UNAVAILABLE"]
    files: dict[str, NativeArtifact] = Field(max_length=64)
    missing_files: list[str] = Field(default_factory=list, max_length=64)
    diagnostics: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def coherent(self):
        from .models.execution import aware_time
        aware_time(self.indexed_at)
        if any(name != item.file for name, item in self.files.items()):
            raise ValueError("native evidence keys disagree with registered file identities")
        if (len(set(self.missing_files)) != len(self.missing_files)
                or not set(self.missing_files).issubset(NATIVE_FILES)
                or set(self.missing_files) & set(self.files)):
            raise ValueError("invalid missing native evidence identities")
        if sum(item.size_bytes for item in self.files.values()) > MAX_NATIVE_TOTAL:
            raise ValueError("native evidence total exceeds bound")
        if self.status == "COMPLETE" and (not self.files or self.missing_files):
            raise ValueError("complete native evidence cannot omit required files")
        return self


class NativeEvidenceBundle(LifecycleContract):
    bundle_schema_version: Literal["1.0"] = "1.0"
    index: NativeEvidenceIndex
    index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    index_b64: str = Field(max_length=131072)
    files_b64: dict[str, str] = Field(max_length=64)

    @model_validator(mode="after")
    def exact_original_bytes(self):
        raw_index = base64.b64decode(self.index_b64, validate=True)
        if len(raw_index) > 65536 or _digest(raw_index) != self.index_sha256 or _load(raw_index) != self.index.model_dump(mode="json"):
            raise ValueError("native index differs before and after transport")
        if set(self.files_b64) != set(self.index.files):
            raise ValueError("native transport must retain exactly every indexed file")
        for name, encoded in self.files_b64.items():
            if len(encoded) > (MAX_NATIVE_FILE * 4 // 3 + 8):
                raise ValueError("native encoded file exceeds bound")
            raw = base64.b64decode(encoded, validate=True)
            entry = self.index.files[name]
            if len(raw) != entry.size_bytes or _digest(raw) != entry.sha256:
                raise ValueError("native file differs before and after transport: " + name)
        return self


def required_native_files(record):
    record = _model(ExecutionRecord, record)
    names = {"lease.json", "request.json", "authorization.json", "policy.json", "snapshot.json", "tool_record.json",
             "execution_record.json", "stdout.bin", "stderr.bin"}
    if record.process is not None:
        names |= {"worker_events.jsonl", "preflight.json"}
    if record.cuda_smoke is not None:
        names.add("work/safe_smoke.cu")
        for step in record.cuda_smoke.steps:
            names |= {"steps/" + step.step_id + "/" + item for item in ("stdout.bin", "stderr.bin", "process_result.json")}
        if record.cuda_smoke.artifact is not None:
            names.add("work/out/safe_smoke.cubin")
    return names


def _read_registered(folder, name):
    if name not in NATIVE_FILES:
        raise ValueError("native export path is not registered")
    path = folder
    if folder.is_symlink():
        raise ValueError("native task directory cannot redirect")
    for component in name.split("/"):
        path /= component
        if path.is_symlink():
            raise ValueError("native evidence cannot redirect through symlinks")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_NATIVE_FILE:
            raise ValueError("native evidence must be a bounded regular file")
        raw = stream.read(MAX_NATIVE_FILE + 1)
    if len(raw) > MAX_NATIVE_FILE:
        raise ValueError("native evidence grew beyond its bound")
    return raw


def export_native_evidence(folder, record, expected_native_files=None):
    """Read only fixed task paths; persist an exclusive index of original bytes."""
    folder = Path(folder)
    record = _model(ExecutionRecord, record)
    required = required_native_files(record)
    if expected_native_files is not None:
        expected = set(expected_native_files)
        if not expected.issubset(NATIVE_FILES):
            raise ValueError("native expected files must use the fixed registry")
        required |= expected
    content, missing = {}, []
    for name in sorted(NATIVE_FILES):
        try:
            content[name] = _read_registered(folder, name)
        except FileNotFoundError:
            if name in required:
                missing.append(name)
    if sum(len(raw) for raw in content.values()) > MAX_NATIVE_TOTAL:
        raise ValueError("native evidence exceeds the aggregate bound")
    index_path = folder / "native_evidence_index.json"
    if index_path.exists():
        if index_path.is_symlink() or index_path.stat().st_size > 65536:
            raise ValueError("unsafe native index")
        raw_index = index_path.read_bytes()
        index = _model(NativeEvidenceIndex, _load(raw_index))
    else:
        index = NativeEvidenceIndex(request_id=record.request_id, run_id=record.run_id,
            target_environment=record.target_environment, execution_record_sha256=canonical_sha256(record),
            request_sha256=record.request_sha256, authorization_sha256=record.authorization_sha256,
            policy_sha256=record.policy_sha256, snapshot_sha256=record.snapshot_sha256, tool_record_id=record.tool_record_id,
            indexed_at=datetime.now(timezone.utc).isoformat(), status="INCOMPLETE" if missing else "COMPLETE",
            files={name: NativeArtifact(file=name, size_bytes=len(raw), sha256=_digest(raw)) for name, raw in content.items()},
            missing_files=missing, diagnostics=["NATIVE_REQUIRED_FILES_MISSING"] if missing else [])
        raw_index = (index.model_dump_json(indent=2) + "\n").encode("utf-8")
        with index_path.open("xb") as stream:
            stream.write(raw_index)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            index_path.chmod(0o600)
            fd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    if (index.request_id != record.request_id or index.run_id != record.run_id
            or index.execution_record_sha256 != canonical_sha256(record)):
        raise ValueError("native index belongs to another request/run/record")
    return NativeEvidenceBundle(index=index, index_sha256=_digest(raw_index),
        index_b64=base64.b64encode(raw_index).decode("ascii"),
        files_b64={name: base64.b64encode(raw).decode("ascii") for name, raw in content.items()})


def validate_native_evidence(bundle, record, request, authorization, policy, snapshot, tool_record):
    """Verify transported native bytes against original, independently held inputs."""
    if bundle is None:
        return {}, NativeEvidenceVerification(status="UNAVAILABLE", file_count=0, size_bytes=0,
                                               diagnostics=["NATIVE_FILES_NOT_ACCESSIBLE"])
    bundle = _model(NativeEvidenceBundle, bundle)
    record = _model(ExecutionRecord, record)
    identities = {"request_id": record.request_id, "run_id": record.run_id,
                  "target_environment": record.target_environment, "execution_record_sha256": canonical_sha256(record),
                  "request_sha256": record.request_sha256, "authorization_sha256": record.authorization_sha256,
                  "policy_sha256": record.policy_sha256, "snapshot_sha256": record.snapshot_sha256,
                  "tool_record_id": record.tool_record_id}
    if any(getattr(bundle.index, name) != expected for name, expected in identities.items()):
        raise ValueError("native evidence identity conflicts with Windows execution record")
    content = {name: base64.b64decode(raw, validate=True) for name, raw in bundle.files_b64.items()}
    if "lease.json" in content:
        lease = _load(content["lease.json"])
        if (not isinstance(lease, dict) or lease.get("request_id") != record.request_id
                or lease.get("run_id") != record.run_id or lease.get("target_environment") != record.target_environment
                or not isinstance(lease.get("worker"), dict) or lease["worker"].get("pid") != record.worker_pid):
            raise ValueError("native lease identity conflicts with the original task/worker")
        if request.request_schema_version == "1.2" and lease.get("boot_id") != request.cuda_toolchain.target_boot_id:
            raise ValueError("native lease boot identity differs from authorized target clock")
    if "preflight.json" in content:
        from .models.execution import PreflightResult
        checked = _model(PreflightResult, _load(content["preflight.json"]))
        if checked.request_id != record.request_id:
            raise ValueError("native preflight belongs to another task")
        if record.process is not None and (checked.status != "READY"
                or checked.measured_candidate_sha256 != record.candidate_sha256
                or checked.measured_tool_sha256 != request.tool_identity.file_sha256):
            raise ValueError("native preflight does not establish the observed execution identities")
    if "worker_events.jsonl" in content:
        events = content["worker_events.jsonl"].splitlines()
        if len(events) > 1024:
            raise ValueError("native worker journal exceeds the lifecycle bound")
        for row in events:
            observed = _load(row)
            if not isinstance(observed, dict) or set(observed) != {"kind", "observed_at", "details"}:
                raise ValueError("native worker journal has invalid event structure")
            from .models.execution import aware_time
            aware_time(observed["observed_at"])
    for name, model, expected in (("execution_record.json", ExecutionRecord, record),
            ("request.json", ExecutionRequest, request), ("authorization.json", OperatorAuthorization, authorization),
            ("policy.json", PreflightPolicy, policy), ("snapshot.json", PlatformSnapshot, snapshot),
            ("tool_record.json", ToolResult, tool_record)):
        if name not in content:
            continue
        original = _load(content[name])
        if expected is None:
            if original is not None:
                raise ValueError("native original authority differs from Windows authority")
        elif _model(model, original) != _model(model, expected):
            raise ValueError("native original input differs from Windows input: " + name)
    if record.process is not None:
        for name, raw in (("stdout.bin", record.process.stdout_bytes()), ("stderr.bin", record.process.stderr_bytes())):
            if name in content and content[name] != raw:
                raise ValueError("native original output differs from Windows process output")
    elif any(content.get(name, b"") for name in ("stdout.bin", "stderr.bin")):
        raise ValueError("native output exists without an observed process")
    if record.cuda_smoke is not None:
        smoke = record.cuda_smoke
        if "work/safe_smoke.cu" in content and _digest(content["work/safe_smoke.cu"]) != smoke.source_sha256:
            raise ValueError("native CUDA source differs from registered input")
        for step in smoke.steps:
            prefix = "steps/" + step.step_id + "/"
            for name, expected in (("stdout.bin", step.process.stdout_bytes()), ("stderr.bin", step.process.stderr_bytes())):
                if prefix + name in content and content[prefix + name] != expected:
                    raise ValueError("native step output differs from original observed step")
            if prefix + "process_result.json" in content and _model(type(step.process), _load(content[prefix + "process_result.json"])) != step.process:
                raise ValueError("native step process record differs after transport")
        if smoke.artifact is not None and "work/out/safe_smoke.cubin" in content:
            raw = content["work/out/safe_smoke.cubin"]
            if _digest(raw) != smoke.artifact.sha256 or len(raw) != smoke.artifact.size_bytes:
                raise ValueError("native compiler artifact differs from validated metadata")
            from .cuda_registry import validate_smoke_cubin_bytes
            validate_smoke_cubin_bytes(raw, expected_sha256=smoke.artifact.sha256)
    missing = required_native_files(record) - set(content)
    if missing - set(bundle.index.missing_files):
        raise ValueError("native index hides missing required original files")
    status = "VERIFIED" if not missing and bundle.index.status == "COMPLETE" else (
        "UNAVAILABLE" if bundle.index.status == "UNAVAILABLE" else "INCOMPLETE")
    return content, NativeEvidenceVerification(status=status, index_sha256=bundle.index_sha256,
        file_count=len(content), size_bytes=sum(len(raw) for raw in content.values()),
        diagnostics=list(bundle.index.diagnostics) + (["NATIVE_REQUIRED_FILES_MISSING"] if missing else []))
