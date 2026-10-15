"""Windows-to-WSL transport restricted to a registered harmless P2-A fixture."""

import json
import os
from pathlib import Path, PurePosixPath
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing import Literal

from .execution_worker import (FIXTURE_ID, FIXTURE_RELATIVE_PATH, FIXTURE_SHA256,
                               FIXTURE_SOURCE, expected_resource_proof, proof_bytes)
from .models.execution import ExecutionRequest, PreflightResult, ResourceSupport, request_sha256
from .models.platform import PlatformSnapshot
from .models.tool_result import ToolResult, digest_bytes
from .tools.process import measure_tool_identity, run_tool
from .wsl_bridge import validate_wsl_options


class ResourceProof(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    fixture_id: Literal["p2-fixed-print-v1"]
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    cpu_seconds: int = Field(ge=1, le=30)
    memory_bytes: int = Field(ge=67108864, le=1073741824)
    message: Literal["harmless fixture completed"]


class ExecutionPacket(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    schema_version: Literal["1.0"]
    operation: Literal["DESCRIBE", "FIXED_FIXTURE"]
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    request_id: str | None = Field(pattern=r"^[0-9a-f]{32}$")
    request_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    policy_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    worker_exit_code: Literal[0]
    status: Literal["DESCRIBED", "REJECTED", "UNKNOWN", "UNSUPPORTED", "FIXTURE_COMPLETED", "FIXTURE_FAILED"]
    target_snapshot: PlatformSnapshot | None
    current_snapshot: PlatformSnapshot | None
    target_environment: str | None
    tool_result: ToolResult | None
    fixture_id: Literal["p2-fixed-print-v1"]
    fixture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fixture_path: str
    cwd: str
    preflight: PreflightResult | None
    resource_proof: ResourceProof | None
    resource_support: ResourceSupport
    diagnostics: list[str]
    candidate_execution_status: Literal["NOT_EXECUTED"]
    verification_status: Literal["NOT_VERIFIED"]

    @field_validator("worker_exit_code", mode="before")
    @classmethod
    def actual_integer_exit(cls, value):
        if type(value) is not int:
            raise ValueError("worker exit observation must be an integer, not a boolean")
        return value

    @model_validator(mode="after")
    def consistent(self):
        if self.fixture_sha256 != FIXTURE_SHA256:
            raise ValueError("worker has a different fixed fixture registry")
        if self.operation == "DESCRIBE" and self.request_id is not None:
            raise ValueError("description cannot claim an execution request")
        if self.operation == "DESCRIBE" and any(item is not None for item in
                                                (self.request_sha256, self.authorization_sha256, self.policy_sha256)):
            raise ValueError("description cannot claim execution contract digests")
        if self.status == "DESCRIBED" and (self.operation != "DESCRIBE" or self.tool_result is None
                                          or not self.tool_result.ok or self.target_snapshot is None):
            raise ValueError("description lacks an observed target/tool")
        if self.status in {"FIXTURE_COMPLETED", "FIXTURE_FAILED"}:
            if (self.operation != "FIXED_FIXTURE" or self.preflight is None
                    or self.preflight.status != "READY" or self.tool_result is None
                    or any(item is None for item in (self.request_sha256, self.authorization_sha256, self.policy_sha256))):
                raise ValueError("fixture process cannot precede successful preflight")
        if self.status == "FIXTURE_COMPLETED" and (not self.tool_result.ok or self.resource_proof is None):
            raise ValueError("completed fixture lacks a normal exit and resource evidence")
        if self.status != "FIXTURE_COMPLETED" and self.resource_proof is not None:
            raise ValueError("failed or read-only observations cannot claim completed resource proof")
        if (self.operation == "FIXED_FIXTURE" and self.status in {"REJECTED", "UNKNOWN", "UNSUPPORTED"}
                and self.tool_result is not None):
            raise ValueError("a rejected execution preflight must not have launched a fixture process")
        return self


def _strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate worker key")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("nonfinite worker number")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid)


def parse_execution_packet(raw, *, operation, nonce, request_id, target_environment,
                           expected_request=None):
    """Revalidate the raw worker bytes; never repair a received observation."""
    if not isinstance(raw, bytes) or len(raw) > 4194304:
        raise ValueError("invalid worker output size")
    packet = ExecutionPacket.model_validate(_strict_json(raw))
    if (packet.operation, packet.nonce, packet.request_id) != (operation, nonce, request_id):
        raise ValueError("worker operation/request/nonce mismatch")
    if packet.target_environment != target_environment:
        raise ValueError("worker target environment mismatch")
    for snapshot in (packet.target_snapshot, packet.current_snapshot):
        if snapshot is not None and (snapshot.platform_type != "wsl" or snapshot.execution_backend != "wsl"
                                     or snapshot.metadata["environment_label"] != target_environment):
            raise ValueError("worker snapshot belongs to a foreign target")
    if packet.tool_result is not None and (packet.tool_result.platform_type != "wsl"
                                           or packet.tool_result.target_environment != target_environment):
        raise ValueError("worker tool record belongs to a foreign target")
    if packet.status == "DESCRIBED":
        if (packet.tool_result.argv != [packet.tool_result.tool_identity.resolved_path, "--version"]
                or packet.tool_result.cwd != packet.cwd
                or packet.fixture_path != str(PurePosixPath(packet.cwd) / FIXTURE_RELATIVE_PATH)):
            raise ValueError("description is not the fixed read-only tool observation")
    if expected_request is not None:
        req = ExecutionRequest.model_validate(expected_request.model_dump(mode="python")
                                               if isinstance(expected_request, ExecutionRequest) else expected_request)
        if req.request_id != packet.request_id:
            raise ValueError("unexpected request identity")
        if packet.request_sha256 is not None and packet.request_sha256 != request_sha256(req):
            raise ValueError("worker request content differs from the expected exact contract")
        if packet.target_snapshot is not None and (packet.target_snapshot.environment_id != req.platform_environment_id
                                                   or packet.target_snapshot.metadata["probe_id"] != req.platform_probe_id):
            raise ValueError("worker replaced the bound platform snapshot")
        if packet.status in {"FIXTURE_COMPLETED", "FIXTURE_FAILED"}:
            record = packet.tool_result
            config = {"request_id": req.request_id, "nonce": nonce,
                      "cpu_seconds": req.resource_limits.cpu_seconds,
                      "memory_bytes": req.resource_limits.memory_bytes}
            stdin = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if ((record.start_status == "STARTED" and (record.tool_identity.resolved_path != req.tool_identity.resolved_path
                                                       or record.tool_identity.file_sha256 != req.tool_identity.file_sha256))
                    or record.argv != [req.tool_identity.resolved_path, "-I", "-c", FIXTURE_SOURCE.decode("utf-8")]
                    or packet.fixture_path != req.candidate_path or packet.cwd != req.cwd
                    or record.cwd != req.cwd
                    or record.resource_limits.timeout_seconds != req.resource_limits.wall_time_seconds
                    or record.resource_limits.max_output_bytes != req.resource_limits.max_output_bytes
                    or record.stdin_sha256 != digest_bytes(stdin) or record.stdin_size_bytes != len(stdin)
                    or packet.current_snapshot is None
                    or packet.current_snapshot.environment_id != req.platform_environment_id
                    or packet.preflight.request_id != req.request_id
                    or packet.preflight.measured_candidate_sha256 != req.candidate_sha256
                    or packet.preflight.measured_tool_sha256 != req.tool_identity.file_sha256):
                raise ValueError("fixture observation is not bound to the requested tool/target/source")
            if packet.status == "FIXTURE_COMPLETED":
                expected = expected_resource_proof(req, nonce)
                if packet.resource_proof.model_dump(mode="python") != expected or record.stdout_bytes() != proof_bytes(expected) or record.stderr_bytes():
                    raise ValueError("resource proof does not match the original process bytes")
    elif packet.status == "FIXTURE_COMPLETED":
        raise ValueError("completed fixture requires its expected execution request")
    return packet.model_dump(mode="json")


def _linux_root(value):
    if (not isinstance(value, str) or not PurePosixPath(value).is_absolute()
            or ".." in PurePosixPath(value).parts or "\\" in value
            or any(char in value for char in "\r\n\0") or value.startswith("//")):
        raise ValueError("explicit trusted Linux project root must be an absolute POSIX path")
    return str(PurePosixPath(value))


def build_execution_worker_source(payload, *, linux_project_root, worker_entrypoint="fixture"):
    """Pin Python source files to this reviewed host checkout before importing."""
    root = _linux_root(linux_project_root)
    if worker_entrypoint not in {"fixture", "lifecycle"}:
        raise ValueError("unregistered worker entry point")
    host_root = Path(__file__).resolve().parent.parent
    hashes = {path.relative_to(host_root).as_posix(): digest_bytes(path.read_bytes())
              for path in sorted((host_root / "src").rglob("*.py"))}
    hashes[FIXTURE_RELATIVE_PATH] = FIXTURE_SHA256
    if worker_entrypoint == "lifecycle":
        from .registered_actions import REGISTERED_ACTIONS
        hashes.update({action.relative_path: action.sha256 for action in REGISTERED_ACTIONS.values()})
        from .cuda_registry import CUDA_SMOKE_RELATIVE_PATH, CUDA_SMOKE_SHA256
        hashes[CUDA_SMOKE_RELATIVE_PATH] = CUDA_SMOKE_SHA256
    entrypoint = "src.execution_worker" if worker_entrypoint == "fixture" else "src.lifecycle_worker"
    return ("import hashlib,importlib.abc,importlib.util,json,pathlib,sys\n"
            "ROOT=pathlib.Path(" + repr(root) + ").resolve(strict=True)\n"
            "HASHES=json.loads(" + repr(json.dumps(hashes, sort_keys=True)) + ")\n"
            "SOURCES={}\n"
            "for relative,expected in HASHES.items():\n"
            "    source=ROOT/relative\n"
            "    raw=source.read_bytes()\n"
            "    if source.is_symlink() or hashlib.sha256(raw).hexdigest()!=expected:\n"
            "        raise SystemExit('trusted worker source identity mismatch')\n"
            "    SOURCES[relative]=raw\n"
            "class VerifiedLoader(importlib.abc.Loader):\n"
            "    def __init__(self,relative): self.relative=relative\n"
            "    def create_module(self,spec): return None\n"
            "    def exec_module(self,module):\n"
            "        module.__file__=str(ROOT/self.relative)\n"
            "        exec(compile(SOURCES[self.relative],module.__file__,'exec'),module.__dict__)\n"
            "class VerifiedFinder(importlib.abc.MetaPathFinder):\n"
            "    def find_spec(self,fullname,path=None,target=None):\n"
            "        if fullname!='src' and not fullname.startswith('src.'): return None\n"
            "        relative=fullname.replace('.','/')\n"
            "        package=relative+'/__init__.py'\n"
            "        module=relative+'.py'\n"
            "        selected=package if package in SOURCES else module\n"
            "        if selected not in SOURCES: raise ImportError('unmeasured src module')\n"
            "        return importlib.util.spec_from_loader(fullname,VerifiedLoader(selected),is_package=selected==package)\n"
            "sys.meta_path.insert(0,VerifiedFinder())\n"
            "from " + entrypoint + " import main\n"
            "PAYLOAD=json.loads(" + repr(json.dumps(payload, ensure_ascii=True, allow_nan=False)) + ")\n"
            "raise SystemExit(main(PAYLOAD,project_root=ROOT))\n").encode("utf-8")


def _bridge(payload, *, distro, user, linux_python, linux_project_root, artifact_root=None):
    validate_wsl_options(distro, linux_python, user)
    root = _linux_root(linux_project_root)
    if os.name != "nt":
        raise ValueError("this entry point requires Windows Python; WSL has its independent worker")
    launcher = measure_tool_identity("wsl.exe", source="Windows WSL launcher file identity")
    if launcher.status != "OBSERVED":
        raise ValueError("WSL launcher file identity could not be established")
    source = build_execution_worker_source(payload, linux_project_root=root)
    record = run_tool([launcher.resolved_path, "--distribution", distro, "--user", user,
                       "--exec", linux_python, "-I", "-"], timeout_seconds=90,
                      max_output_bytes=4194304, input_bytes=source, artifact_root=artifact_root,
                      allowed_tool_identities={launcher.resolved_path: launcher.file_sha256},
                      command_source="fixed P2-A harmless fixture transport; explicit Linux source root")
    if not record.ok:
        return {"packet": None, "transport": record.model_dump(mode="json")}
    packet = parse_execution_packet(record.stdout_bytes(), operation=payload["operation"],
                                    nonce=payload["nonce"], request_id=None if payload["request"] is None else payload["request"]["request_id"],
                                    target_environment="wsl:" + distro, expected_request=payload["request"])
    return {"packet": packet, "transport": record.model_dump(mode="json")}


def describe_fixed_fixture_wsl(*, distro="Ubuntu-22.04", user="pocdev",
                               linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python",
                               linux_project_root, artifact_root=None):
    payload = {"operation": "DESCRIBE", "nonce": uuid.uuid4().hex, "request": None,
               "authorization": None, "snapshot": None, "tool_record": None, "policy": None}
    return _bridge(payload, distro=distro, user=user, linux_python=linux_python,
                   linux_project_root=linux_project_root, artifact_root=artifact_root)


def execute_fixed_fixture_wsl(request, authorization, snapshot, tool_record, policy, *,
                              distro="Ubuntu-22.04", user="pocdev",
                              linux_python="/home/pocdev/.venvs/cuda-poc-generator/bin/python",
                              linux_project_root, artifact_root=None):
    def plain(value):
        return value.model_dump(mode="python") if isinstance(value, BaseModel) else value
    req = ExecutionRequest.model_validate(plain(request))
    payload = {"operation": "FIXED_FIXTURE", "nonce": uuid.uuid4().hex,
               "request": req.model_dump(mode="json"), "authorization": plain(authorization),
               "snapshot": plain(snapshot), "tool_record": plain(tool_record), "policy": plain(policy)}
    return _bridge(payload, distro=distro, user=user, linux_python=linux_python,
                   linux_project_root=linux_project_root, artifact_root=artifact_root)
