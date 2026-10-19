"""Versioned contract for executing one transferred, frozen harmless fixture.

The legacy P2 execution records describe registry execution and are deliberately
left unchanged.  These records describe the separate received-file experiment.
"""

import hashlib
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, model_validator

from ..candidate_adapter import CandidateTransferReceipt
from ..registered_actions import get_registered_action
from .execution import ExecutionResourceLimits, ResourceSupport, absolute_target_path
from .lifecycle import (ArtifactReference, LifecycleContract, LifecycleEvent,
                        LifecycleState, ProcessObservation, TERMINAL_STATES,
                        canonical_sha256, validate_events)
from .platform import PlatformSnapshot
from .tool_result import ToolIdentity


ID = r"^[0-9a-f]{32}$"
SHA = r"^[0-9a-f]{64}$"
ACTION = "p2b-normal-v1"


class StagedSourceIdentity(LifecycleContract):
    device: int = Field(ge=0)
    inode: int = Field(gt=0)
    uid: int = Field(ge=0)
    gid: int = Field(ge=0)
    mode: Literal[384] = 384  # 0600
    nlink: Literal[1] = 1
    size_bytes: int = Field(gt=0, le=1048576)
    mtime_ns: int = Field(ge=0)
    ctime_ns: int = Field(ge=0)
    source_path: str = Field(min_length=1)
    source_sha256: str = Field(pattern=SHA)
    receipt_sha256: str = Field(pattern=SHA)
    transfer_id: str = Field(pattern=ID)
    transfer_request_id: str = Field(pattern=ID)
    action_id: Literal["p2b-normal-v1"] = ACTION

    @model_validator(mode="after")
    def exact_fixture(self):
        if (self.source_sha256 != get_registered_action(ACTION).sha256
                or self.size_bytes != len(get_registered_action(ACTION).source)
                or not absolute_target_path(self.source_path, "wsl")
                or PurePosixPath(self.source_path).name != "candidate.py"):
            raise ValueError("staged identity must name the exact frozen harmless source")
        return self


class StagedFixtureDescription(LifecycleContract):
    description_schema_version: Literal["staged-harmless-1.0"] = "staged-harmless-1.0"
    description_id: str = Field(pattern=ID)
    status: Literal["DESCRIBED", "UNKNOWN", "UNSUPPORTED"]
    target_environment: str
    snapshot: PlatformSnapshot | None
    native_task_root: str
    receipt: CandidateTransferReceipt
    source_identity: StagedSourceIdentity | None
    tool_identity: ToolIdentity | None
    target_boot_id: str
    observed_monotonic_ns: int = Field(ge=0)
    resource_support: ResourceSupport
    diagnostics: list[str]
    report_locale: Literal["zh-CN"] = "zh-CN"
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    verification_status: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"

    @model_validator(mode="after")
    def described(self):
        if not absolute_target_path(self.native_task_root, "wsl"):
            raise ValueError("native task root must be an absolute WSL path")
        if self.status == "DESCRIBED":
            if (self.snapshot is None or self.snapshot.execution_backend != "wsl"
                    or self.snapshot.metadata.get("environment_label") != self.target_environment
                    or self.source_identity is None or self.tool_identity is None
                    or self.tool_identity.status != "OBSERVED"
                    or self.resource_support.status != "OBSERVED"
                    or self.source_identity.receipt_sha256 == "0" * 64
                    or self.source_identity.source_path != self.receipt.staged_path
                    or self.source_identity.source_sha256 != self.receipt.source_sha256
                    or self.source_identity.transfer_id != self.receipt.transfer_id
                    or self.source_identity.transfer_request_id != self.receipt.request_id):
                raise ValueError("described fixed stage must carry exact measured platform, source and tool")
        return self


class StagedFixtureRequest(LifecycleContract):
    request_schema_version: Literal["staged-harmless-1.0"] = "staged-harmless-1.0"
    authorized_action: Literal["FIXED_STAGED_HARMLESS"] = "FIXED_STAGED_HARMLESS"
    request_id: str = Field(pattern=ID)
    run_id: str = Field(pattern=ID)
    action_id: Literal["p2b-normal-v1"] = ACTION
    transfer_id: str = Field(pattern=ID)
    transfer_request_id: str = Field(pattern=ID)
    receipt_sha256: str = Field(pattern=SHA)
    source_identity: StagedSourceIdentity
    description_sha256: str = Field(pattern=SHA)
    platform_environment_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    platform_probe_id: str = Field(min_length=1, max_length=128)
    snapshot_sha256: str = Field(pattern=SHA)
    target_environment: str
    execution_backend: Literal["wsl"] = "wsl"
    target_boot_id: str
    observed_monotonic_ns: int = Field(ge=0)
    tool_identity: ToolIdentity
    resource_limits: ExecutionResourceLimits
    authorization_reference: str = Field(min_length=1, max_length=256)
    expected_artifacts: Literal["RECEIPT_SOURCE_PROOF_STDOUT_STDERR_PROCESS"] = "RECEIPT_SOURCE_PROOF_STDOUT_STDERR_PROCESS"

    @model_validator(mode="after")
    def fixed_scope(self):
        source = self.source_identity
        if (self.transfer_id, self.transfer_request_id, self.receipt_sha256) != (
                source.transfer_id, source.transfer_request_id, source.receipt_sha256):
            raise ValueError("request differs from the independently measured transfer")
        if (not self.target_environment.startswith("wsl:") or self.tool_identity.status != "OBSERVED"
                or any(char in self.authorization_reference for char in "\0\r\n")):
            raise ValueError("invalid fixed staged target or authority reference")
        return self


class StagedFixtureAuthorization(LifecycleContract):
    authorization_schema_version: Literal["staged-harmless-1.0"] = "staged-harmless-1.0"
    authorized_action: Literal["FIXED_STAGED_HARMLESS"] = "FIXED_STAGED_HARMLESS"
    request_id: str = Field(pattern=ID)
    run_id: str = Field(pattern=ID)
    transfer_id: str = Field(pattern=ID)
    receipt_sha256: str = Field(pattern=SHA)
    source_sha256: str = Field(pattern=SHA)
    request_sha256: str = Field(pattern=SHA)
    operator_id: str = Field(min_length=1, max_length=128)
    authorization_reference: str = Field(min_length=1, max_length=256)
    issuer_kind: Literal["operator", "trusted_policy"]
    target_boot_id: str
    not_before_monotonic_ns: int = Field(ge=0)
    expires_monotonic_ns: int = Field(ge=0)

    @model_validator(mode="after")
    def bounded(self):
        if not 0 < self.expires_monotonic_ns - self.not_before_monotonic_ns <= 300000000000:
            raise ValueError("fixed fixture authorization must expire within five minutes")
        if any(not x.strip() or any(c in x for c in "\0\r\n") for x in (
                self.operator_id, self.authorization_reference)):
            raise ValueError("operator and authorization reference must be single-line values")
        return self


class StagedFixturePolicy(LifecycleContract):
    policy_schema_version: Literal["staged-harmless-1.0"] = "staged-harmless-1.0"
    request_sha256: str = Field(pattern=SHA)
    description_sha256: str = Field(pattern=SHA)
    allowed_operator_ids: list[str] = Field(min_length=1, max_length=16)
    allowed_authorization_references: list[str] = Field(min_length=1, max_length=16)
    allowed_tool_path: str
    allowed_tool_sha256: str = Field(pattern=SHA)
    native_task_root: str
    transfer_id: str = Field(pattern=ID)
    receipt_sha256: str = Field(pattern=SHA)
    source_sha256: str = Field(pattern=SHA)
    resource_limits: ExecutionResourceLimits
    max_description_age_seconds: int = Field(default=300, ge=1, le=300)

    @model_validator(mode="after")
    def scoped(self):
        if not absolute_target_path(self.native_task_root, "wsl") or not absolute_target_path(self.allowed_tool_path, "wsl"):
            raise ValueError("policy task and tool paths must be absolute WSL paths")
        if len(set(self.allowed_operator_ids)) != len(self.allowed_operator_ids) or len(set(
                self.allowed_authorization_references)) != len(self.allowed_authorization_references):
            raise ValueError("policy authority lists must be unique")
        return self


class StagedFixtureRecord(LifecycleContract):
    execution_schema_version: Literal["staged-harmless-1.0"] = "staged-harmless-1.0"
    report_locale: Literal["zh-CN"] = "zh-CN"
    domain: Literal["FIXED_STAGED_HARMLESS_EXPERIMENT"] = "FIXED_STAGED_HARMLESS_EXPERIMENT"
    cve_id: None = None
    request_id: str = Field(pattern=ID)
    run_id: str = Field(pattern=ID)
    action_id: Literal["p2b-normal-v1"] = ACTION
    transfer_id: str = Field(pattern=ID)
    receipt_sha256: str = Field(pattern=SHA)
    source_identity: StagedSourceIdentity
    request_sha256: str = Field(pattern=SHA)
    authorization_sha256: str | None = Field(default=None, pattern=SHA)
    policy_sha256: str = Field(pattern=SHA)
    description_sha256: str = Field(pattern=SHA)
    snapshot_sha256: str = Field(pattern=SHA)
    platform_environment_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    platform_probe_id: str
    target_environment: str
    tool_identity: ToolIdentity
    worker_identity: dict
    status: LifecycleState
    events: list[LifecycleEvent]
    process: ProcessObservation | None
    staged_observation: dict | None
    artifacts: dict[str, ArtifactReference]
    diagnostics: list[str]
    fixed_source_execution_status: Literal["NOT_EXECUTED", "EXECUTED", "UNKNOWN"]
    candidate_execution_status: Literal["NOT_EXECUTED"] = "NOT_EXECUTED"
    verification_status: Literal["NOT_VERIFIED"] = "NOT_VERIFIED"

    @model_validator(mode="after")
    def observed(self):
        validate_events(self.events, self.status)
        if self.status not in TERMINAL_STATES:
            raise ValueError("retained staged experiment must be terminal")
        if self.transfer_id != self.source_identity.transfer_id or self.receipt_sha256 != self.source_identity.receipt_sha256:
            raise ValueError("record source and receipt identity conflict")
        if self.process is None:
            if self.fixed_source_execution_status != "NOT_EXECUTED" and self.status not in {"UNKNOWN", "CAPTURE_FAILED"}:
                raise ValueError("source cannot be declared executed without process evidence")
        else:
            if self.process.worker_pid != self.worker_identity.get("pid"):
                raise ValueError("process and worker identity conflict")
            actual = self.process.tool_identity
            same_image = (actual.status == "OBSERVED"
                and actual.resolved_path == self.tool_identity.resolved_path
                and actual.file_sha256 == self.tool_identity.file_sha256)
            if (actual.status == "OBSERVED" and not same_image) or (self.process.action_started and not same_image):
                raise ValueError("process executable path or SHA-256 differs from the authorized image")
            if self.process.target_environment != self.target_environment:
                raise ValueError("process target identity conflict")
            if self.process.action_started and self.staged_observation is None:
                raise ValueError("started received file requires exact fd observation")
            if self.fixed_source_execution_status == "EXECUTED" and not self.process.action_started:
                raise ValueError("source execution requires observed release gate")
            if self.process.started and self.process.cleanup.status != "CONFIRMED" and self.status not in {"CLEANUP_FAILED", "UNKNOWN"}:
                raise ValueError("unconfirmed cleanup cannot be reported complete")
        if self.status == "COMPLETED" and (self.process is None or not self.process.action_started
                or self.fixed_source_execution_status != "EXECUTED" or self.process.returncode != 0
                or self.process.timed_out or self.process.cancelled or self.process.truncated
                or self.process.capture_failed or self.process.cleanup.status != "CONFIRMED"):
            raise ValueError("completed staged task requires actual fixed file execution and clean evidence")
        if self.status == "COMPLETED":
            if not {"stdout.bin", "stderr.bin", "process_result.json", "staged_observation.json"}.issubset(
                    self.artifacts):
                raise ValueError("completed staged task requires raw process and received-file evidence")
            for name, raw in (("stdout.bin", self.process.stdout_bytes()),
                              ("stderr.bin", self.process.stderr_bytes())):
                artifact = self.artifacts[name]
                if artifact.size_bytes != len(raw) or artifact.sha256 != hashlib.sha256(raw).hexdigest():
                    raise ValueError("raw stream reference differs from the original process bytes")
        if self.process is not None and self.process.action_started:
            observation = self.staged_observation or {}
            proofs = [item.get("details") for item in observation.get("events", [])
                      if item.get("event") == "STAGED_SOURCE_READY"] if isinstance(observation, dict) else []
            proof = proofs[0] if len(proofs) == 1 else None
            expected = self.source_identity.model_dump(mode="json")
            if (proof is None or any(proof.get(key) != value for key, value in expected.items())
                    or proof.get("request_id") != self.request_id or proof.get("run_id") != self.run_id
                    or proof.get("pid") != self.process.pid):
                raise ValueError("received-file FD proof differs from authorized source identity")
        if any(name != artifact.file for name, artifact in self.artifacts.items()):
            raise ValueError("artifact map key disagrees with retained file")
        return self


def validate_staged_binding(record, request, authorization, policy, description):
    record = StagedFixtureRecord.model_validate(record)
    req = StagedFixtureRequest.model_validate(request)
    auth = None if authorization is None else StagedFixtureAuthorization.model_validate(authorization)
    trusted = StagedFixturePolicy.model_validate(policy)
    desc = StagedFixtureDescription.model_validate(description)
    if (record.request_id, record.run_id, record.transfer_id, record.receipt_sha256, record.source_identity) != (
            req.request_id, req.run_id, req.transfer_id, req.receipt_sha256, req.source_identity):
        raise ValueError("record and requested staged file conflict")
    if (record.request_sha256, record.authorization_sha256, record.policy_sha256,
            record.description_sha256) != (canonical_sha256(req), None if auth is None else canonical_sha256(auth),
                                          canonical_sha256(trusted), canonical_sha256(desc)):
        raise ValueError("record contract hashes disagree with independent inputs")
    if auth is None:
        if record.status != "REJECTED" or record.process is not None:
            raise ValueError("missing operator authority must reject before process start")
    else:
        if (auth.request_id, auth.run_id, auth.transfer_id, auth.receipt_sha256, auth.source_sha256,
                auth.request_sha256) != (req.request_id, req.run_id, req.transfer_id, req.receipt_sha256,
                                        req.source_identity.source_sha256, canonical_sha256(req)):
            raise ValueError("authorization does not bind exact request and received bytes")
        if auth.operator_id not in trusted.allowed_operator_ids or auth.authorization_reference not in trusted.allowed_authorization_references:
            raise ValueError("operator authority is outside independent policy")
    if (trusted.request_sha256, trusted.description_sha256, trusted.transfer_id,
            trusted.receipt_sha256, trusted.source_sha256, trusted.resource_limits) != (
            canonical_sha256(req), req.description_sha256, req.transfer_id,
            req.receipt_sha256, req.source_identity.source_sha256, req.resource_limits):
        raise ValueError("trusted policy does not bind exact staged request")
    if (desc.source_identity != req.source_identity or desc.receipt.transfer_id != req.transfer_id
            or desc.tool_identity != req.tool_identity or desc.target_environment != req.target_environment
            or desc.snapshot is None or canonical_sha256(desc.snapshot) != req.snapshot_sha256
            or record.snapshot_sha256 != req.snapshot_sha256):
        raise ValueError("target description, source or snapshot changed")
    if record.process is not None and record.process.action_started:
        observation = record.staged_observation or {}
        proofs = [item.get("details") for item in observation.get("events", [])
                  if item.get("event") == "STAGED_SOURCE_READY"] if isinstance(observation, dict) else []
        bound = proofs[0] if len(proofs) == 1 else None
        expected = req.source_identity.model_dump(mode="json")
        if (bound is None or any(bound.get(key) != value for key, value in expected.items())
                or bound.get("request_id") != req.request_id or bound.get("run_id") != req.run_id
                or bound.get("pid") != record.process.pid):
            raise ValueError("observed opened staged file differs from admitted source")
    return record, req, auth, trusted, desc
