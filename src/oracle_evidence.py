"""Read-only, pinned evidence for the P3-A deterministic Oracle.

An integrity-checked P2-C corpus describes fixed harmless toolchain observations.
It is not proof of a CVE, a signed attestation, or an authorization to execute.
No process, network request, or natural-language evidence extractor lives here.
"""

from dataclasses import dataclass, InitVar
import hashlib
import json
import math
from pathlib import Path
import re
from types import MappingProxyType
from typing import Literal, Mapping

from .lifecycle_artifacts import read_execution_evidence
from .native_evidence import WINDOWS_NAMES


_SHA256 = re.compile(r"[0-9a-f]{64}")
_FILENAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
_MAX_JSON = 16 * 1024 * 1024
_OBJECTIVE_ORIGIN = object()
_PLATFORM_FIELDS = frozenset({
    "host_os", "kernel", "architecture", "python_version", "driver_release",
    "cuda_driver_api_version", "driver_reported_cuda_version", "cuda_toolkit_version",
    "nvcc_version", "compute_sanitizer_version",
})
_PROCESS_PATHS = frozenset({
    "/started", "/action_started", "/returncode", "/linux_signal", "/timed_out",
    "/cancelled", "/truncated", "/capture_failed", "/resource_limit_reason",
    "/tool_identity/file_sha256", "/tool_identity/resolved_path",
    "/actual_tool_identity/file_sha256", "/actual_tool_identity/resolved_path",
    "/cleanup/status", "/resources/status",
})
_RECORD_PATHS = frozenset({
    "/status", "/action_id", "/fixture_execution_status", "/candidate_execution_status",
    "/verification_status", "/cuda_smoke/kernel_execution_status",
    "/cuda_smoke/verification_status", "/cuda_smoke/source_sha256", "/cuda_smoke/arch",
    "/cuda_smoke/artifact/sha256", "/cuda_smoke/artifact/size_bytes",
})
_STEP_POINTER = re.compile(r"/cuda_smoke/steps/([0-5])(/.*)")
_NATIVE_STEP = re.compile(r"native_steps_(nvcc_version|cuobjdump_version|nvdisasm_version|compile|cuobjdump|nvdisasm)_process_result\.json")
_VERSION_BANNERS = {
    "nvcc": "nvcc: NVIDIA (R) Cuda compiler driver",
    "cuobjdump": "cuobjdump: NVIDIA (R) fat binary listing tool",
    "nvdisasm": "nvdisasm: NVIDIA (R) CUDA disassembler",
}
_VERSION_LINE = re.compile(r"Cuda compilation tools, release ([0-9]{1,3}\.[0-9]{1,3}), V([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,6})")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _tool_version(role, record, identity):
    """P3A_NVIDIA_VERSION_BANNER_V1; only exact bound --version output."""
    if (role not in _VERSION_BANNERS or record.end_status != "NORMAL_EXIT" or record.returncode != 0
            or record.truncated or record.capture_failed
            or record.tool_identity != identity or identity.status != "OBSERVED"
            or record.argv != [identity.resolved_path, "--version"]):
        return None
    raw = record.stdout_bytes()
    if len(raw) > 4096 or _digest(raw) != record.stdout_sha256:
        return None
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        return None
    if not lines or lines[0] != _VERSION_BANNERS[role]:
        return None
    matches = [_VERSION_LINE.fullmatch(line) for line in lines]
    matches = [match for match in matches if match is not None]
    if len(matches) != 1 or sum("Cuda compilation tools" in line for line in lines) != 1:
        return None
    release, build = matches[0].groups()
    if build.rsplit(".", 1)[0] != release:
        return None
    canonical = json.dumps(record.model_dump(mode="json"), ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"), allow_nan=False).encode("utf-8")
    return {"release": release, "build": build, "record_sha256": _digest(canonical)}


def _freeze(value):
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(child) for child in value)
    if value is None or type(value) in (str, int, float, bool, bytes):
        return value
    raise ValueError("unsupported corpus metadata value")


def _strict_json(raw: bytes):
    if len(raw) > _MAX_JSON:
        raise ValueError("Oracle JSON artifact exceeds its read bound")

    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate evidence JSON key")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("nonfinite evidence JSON value")

    def finite(number):
        value = float(number)
        if not math.isfinite(value):
            raise ValueError("nonfinite evidence JSON number")
        return value

    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid, parse_float=finite)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("invalid evidence JSON encoding or nesting") from exc


def _pointer(value, pointer: str):
    if not isinstance(pointer, str) or len(pointer) > 2048 or (pointer and not pointer.startswith("/")):
        raise ValueError("invalid evidence JSON pointer")
    parts = pointer[1:].split("/") if pointer else []
    if len(parts) > 64:
        raise ValueError("evidence pointer exceeds nesting bound")
    for encoded in parts:
        if re.search(r"~(?:[^01]|$)", encoded):
            raise ValueError("invalid JSON pointer escape")
        part = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            if part not in value:
                raise ValueError("evidence JSON pointer does not exist")
            value = value[part]
        elif isinstance(value, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", part) or len(part) > 9 or int(part) >= len(value):
                raise ValueError("invalid evidence array index")
            value = value[int(part)]
        else:
            raise ValueError("evidence pointer traverses a scalar")
    return value


def _production_pointer(filename, pointer, document):
    if filename == "platform_snapshot.json":
        parts = pointer.split("/")
        if len(parts) != 3 or parts[1] not in _PLATFORM_FIELDS or parts[2] != "value":
            raise ValueError("platform field is outside the objective Oracle allowlist")
        field = document.get(parts[1]) if isinstance(document, dict) else None
        if not isinstance(field, dict) or field.get("status") != "OBSERVED" or field.get("value") is None:
            raise ValueError("platform field is not an observed value")
        return
    if filename == "execution_record.json":
        if pointer in _RECORD_PATHS:
            return
        step = _STEP_POINTER.fullmatch(pointer)
        if step and (step[2] in {"/state", "/step_id"} or
                     step[2].startswith("/process") and step[2][len("/process"):] in _PROCESS_PATHS):
            return
        if pointer.startswith("/process") and pointer[len("/process"):] in _PROCESS_PATHS:
            return
    elif filename == "process_result.json" or _NATIVE_STEP.fullmatch(filename):
        if pointer in _PROCESS_PATHS:
            return
    raise ValueError("artifact field is outside the objective Oracle allowlist")


@dataclass(frozen=True)
class EvidenceCorpus:
    """Immutable byte corpus; only the trusted loader creates objective corpora.

    Synthetic inputs are a separate domain even when their offline rule result
    is VERIFIED. They cannot establish a real-world CVE result. The manifest
    pin and collector are trust anchors supplied independently by the operator;
    their hashes do not authenticate a compromised host or collector.
    """

    domain: Literal["SYNTHETIC", "OBJECTIVE"]
    binding: Mapping[str, object]
    artifacts: Mapping[str, bytes]
    artifact_sha256: Mapping[str, str]
    provenance: Mapping[str, Mapping[str, str]]
    qualified: bool
    diagnostics: tuple[str, ...]
    original_source: str
    collector: str
    scope: Literal["SYNTHETIC", "TOOLCHAIN_SMOKE"]
    _objective_origin: InitVar[object] = None

    def __post_init__(self, _objective_origin):
        if self.domain not in {"SYNTHETIC", "OBJECTIVE"} or type(self.qualified) is not bool:
            raise ValueError("invalid corpus domain or qualification")
        if (self.domain == "SYNTHETIC") != (self.scope == "SYNTHETIC"):
            raise ValueError("synthetic and objective evidence scopes cannot mix")
        if self.domain == "OBJECTIVE" and _objective_origin is not _OBJECTIVE_ORIGIN:
            raise ValueError("objective evidence must originate from the pinned P2-C loader")
        if not self.original_source or not self.collector:
            raise ValueError("corpus must retain original source and collector")
        if set(self.artifacts) != set(self.artifact_sha256) or set(self.artifacts) != set(self.provenance):
            raise ValueError("every corpus artifact requires one hash and provenance entry")
        for name, raw in self.artifacts.items():
            if not isinstance(name, str) or not _FILENAME.fullmatch(name) or type(raw) is not bytes:
                raise ValueError("corpus artifacts must use safe filenames and original bytes")
            if len(raw) > _MAX_JSON or _digest(raw) != self.artifact_sha256[name]:
                raise ValueError("corpus artifact hash or length is invalid")
        for field in ("binding", "artifacts", "artifact_sha256", "provenance"):
            object.__setattr__(self, field, _freeze(getattr(self, field)))
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))

    @classmethod
    def from_synthetic(cls, *, artifacts: Mapping[str, bytes], binding: Mapping[str, object],
                       label: str):
        if label != "SYNTHETIC":
            raise ValueError("offline fixture evidence must be labeled SYNTHETIC")
        return cls(domain="SYNTHETIC", binding=binding, artifacts=artifacts,
                   artifact_sha256={name: _digest(raw) for name, raw in artifacts.items()},
                   provenance={name: {"original_source": "SYNTHETIC_FIXTURE", "collector": "p3a-synthetic-1.0",
                                      "scope": "SYNTHETIC"} for name in artifacts},
                   qualified=True, diagnostics=("SYNTHETIC_RULE_TEST_ONLY",), original_source="SYNTHETIC_FIXTURE",
                   collector="p3a-synthetic-1.0", scope="SYNTHETIC")

    def resolve(self, artifact_filename: str, sha256: str, json_pointer: str):
        """Derive a value from original hashed JSON, never caller-supplied prose."""
        if not isinstance(json_pointer, str) or len(json_pointer) > 2048 or (json_pointer and not json_pointer.startswith("/")):
            raise ValueError("invalid evidence JSON pointer")
        if (not isinstance(artifact_filename, str) or not artifact_filename.endswith(".json")
                or artifact_filename not in self.artifacts):
            raise ValueError("Oracle evidence must reference a registered JSON artifact")
        if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
            raise ValueError("invalid expected evidence SHA-256")
        raw = self.artifacts[artifact_filename]
        if sha256 != self.artifact_sha256[artifact_filename] or _digest(raw) != sha256:
            raise ValueError("evidence source bytes differ from the pinned artifact")
        document = _strict_json(raw)
        if self.domain == "OBJECTIVE":
            _production_pointer(artifact_filename, json_pointer, document)
        return _pointer(document, json_pointer)

    def validate_tool_binding(self, artifact_filename: str, json_pointer: str,
                              role: str, sha256: str) -> None:
        """Reject a valid tool hash relabeled onto another tool's observation."""
        tools = self.binding.get("tool_sha256", {})
        if not isinstance(role, str) or role not in tools or tools[role] != sha256:
            raise ValueError("evidence tool role or hash differs from the pinned toolchain")
        if artifact_filename not in self.artifact_sha256:
            raise ValueError("tool binding references an unregistered artifact")
        self.resolve(artifact_filename, self.artifact_sha256[artifact_filename], json_pointer)
        if self.domain == "SYNTHETIC":
            return
        if artifact_filename == "platform_snapshot.json":
            component_role = {"/nvcc_version/value": "nvcc",
                              "/compute_sanitizer_version/value": "compute_sanitizer"}.get(json_pointer)
            if component_role is not None and role != component_role:
                raise ValueError("component version field belongs to a different actual tool role")
            return
        native_step = _NATIVE_STEP.fullmatch(artifact_filename)
        step_pointer = _STEP_POINTER.fullmatch(json_pointer) if artifact_filename == "execution_record.json" else None
        if native_step:
            step_id = native_step[1]
        elif step_pointer:
            document = _strict_json(self.artifacts[artifact_filename])
            step_id = document["cuda_smoke"]["steps"][int(step_pointer[1])]["step_id"]
        else:
            step_id = None
        if step_id is not None:
            expected_role = "nvcc" if step_id == "compile" else step_id.removesuffix("_version")
        elif artifact_filename == "execution_record.json" and (
                json_pointer.startswith("/cuda_smoke/artifact/") or json_pointer == "/cuda_smoke/source_sha256"):
            expected_role = "nvcc"
        else:
            expected_role = self.binding.get("record_tool_role")
        if expected_role is None or role != expected_role:
            raise ValueError("evidence field belongs to a different actual tool role")


def _manifest_bytes(folder: Path) -> bytes:
    path = folder / "manifest.json"
    if folder.is_symlink() or path.is_symlink() or not path.is_file() or path.stat().st_size > 131072:
        raise ValueError("unsafe, missing or oversized pinned evidence manifest")
    with path.open("rb") as stream:
        raw = stream.read(131073)
    if len(raw) > 131072:
        raise ValueError("pinned evidence manifest exceeds its read bound")
    return raw


def load_p2c_evidence(folder, *, expected_manifest_sha256: str) -> EvidenceCorpus:
    """Validate existing evidence offline; never execute or rewrite its files."""
    if not isinstance(expected_manifest_sha256, str) or not _SHA256.fullmatch(expected_manifest_sha256):
        raise ValueError("an independently supplied manifest SHA-256 pin is required")
    folder = Path(folder)
    manifest_raw = _manifest_bytes(folder)
    if _digest(manifest_raw) != expected_manifest_sha256:
        raise ValueError("pinned evidence manifest SHA-256 mismatch")
    pinned = _strict_json(manifest_raw)
    if not isinstance(pinned, dict):
        raise ValueError("pinned evidence manifest must be an object")
    context = read_execution_evidence(folder, expected_request_id=pinned.get("request_id"),
                                      expected_run_id=pinned.get("run_id"),
                                      expected_record_sha256=pinned.get("execution_record_sha256"))
    if _manifest_bytes(folder) != manifest_raw:
        raise ValueError("pinned evidence manifest changed while being read")
    record, manifest, request = context["record"], context["manifest"], context["request"]
    if record.action_id != "p2c-cuda-smoke-v1" or record.cuda_smoke is None:
        raise ValueError("P3-A objective adapter supports only the fixed P2-C toolchain smoke")
    diagnostics = []
    for passed, reason in (
        (context["native_verification"].status == "VERIFIED", "NATIVE_EVIDENCE_NOT_VERIFIED"),
        (manifest.capture_complete and not manifest.truncated, "CAPTURE_INCOMPLETE"),
        (context["cleanup_confirmation"] == "CONFIRMED", "CLEANUP_NOT_CONFIRMED"),
        (context["effective_status"] == "COMPLETED", "EXECUTION_NOT_COMPLETED"),
    ):
        if not passed:
            diagnostics.append(reason)
    qualified = not diagnostics
    tool_hashes = {role: identity.file_sha256 for role, identity in request.cuda_toolchain.tools.items()}
    actual_identity = record.tool_identity
    actual_roles = [role for role, identity in request.cuda_toolchain.tools.items()
                    if identity.file_sha256 == actual_identity.file_sha256
                    and identity.resolved_path == actual_identity.resolved_path]
    if len(actual_roles) != 1:
        raise ValueError("actual final tool identity has no unique authorized role")
    versions = {}
    version_sources = {}
    snapshot = context.get("snapshot")
    toolkit = None if snapshot is None else snapshot.cuda_toolkit_version
    for role in _VERSION_BANNERS:
        version_record = request.cuda_toolchain.version_records.get(role)
        version = None if version_record is None else _tool_version(role, version_record, request.cuda_toolchain.tools[role])
        if version is None:
            diagnostics.append("TOOL_VERSION_UNKNOWN:" + role)
        elif toolkit is not None and toolkit.status == "OBSERVED" and toolkit.value != version["release"]:
            raise ValueError("observed platform Toolkit release conflicts with measured tool release")
        versions[role] = version
        if version_record is not None:
            version_sources[role] = {"artifact_filename": "execution_request.json",
                "artifact_sha256": manifest.artifacts["execution_request.json"].sha256,
                "json_pointer": "/cuda_toolchain/version_records/" + role + "/stdout_b64",
                "stdout_sha256": version_record.stdout_sha256,
                "tool_result_sha256": None if version is None else version["record_sha256"],
                "parser": "P3A_NVIDIA_VERSION_BANNER_V1"}
    binding = {name: getattr(record, name) for name in (
        "request_id", "run_id", "platform_environment_id", "platform_probe_id", "candidate_sha256",
        "snapshot_sha256", "tool_record_id", "request_sha256", "authorization_sha256", "policy_sha256",
    )}
    binding.update(tool_sha256=tool_hashes, execution_record_sha256=manifest.execution_record_sha256,
                   manifest_sha256=expected_manifest_sha256, target_environment=record.target_environment,
                   action_id=record.action_id, record_tool_role=actual_roles[0], tool_versions=versions,
                   tool_version_provenance=version_sources)
    reverse_names = {destination: original for original, destination in WINDOWS_NAMES.items()}
    artifacts = context["artifacts"]
    return EvidenceCorpus(domain="OBJECTIVE", binding=binding, artifacts=artifacts,
        artifact_sha256={name: entry.sha256 for name, entry in manifest.artifacts.items()},
        provenance={name: {"original_source": reverse_names.get(name, name),
                           "collector": manifest.collector_version, "scope": "TOOLCHAIN_SMOKE"}
                    for name in artifacts},
        qualified=qualified, diagnostics=tuple(diagnostics), original_source="P2_C_NATIVE_EXECUTION",
        collector=manifest.collector_version, scope="TOOLCHAIN_SMOKE", _objective_origin=_OBJECTIVE_ORIGIN)
