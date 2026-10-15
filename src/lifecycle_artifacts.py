"""Private, immutable lifecycle evidence and deterministic offline reports.

The evidence reader verifies associations as well as file digests.  A manifest
is an integrity index, not a signature or a replacement for operator trust.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from .models.execution import (ExecutionRequest, OperatorAuthorization,
                               PreflightPolicy, aware_time, request_sha256,
                               snapshot_sha256)
from .models.lifecycle import ExecutionRecord, EvidenceManifest, RemoteRecoveryCheck, NativeEvidenceVerification
from .models.platform import PlatformSnapshot
from .models.tool_result import ToolResult
from .probe_artifacts import protect_directory
from .native_evidence import (NativeEvidenceBundle, WINDOWS_NAMES, validate_native_evidence)


COLLECTOR_VERSION = "p2b-1.0"
ALLOWED_FILES = frozenset({
    "stdout.bin", "stderr.bin", "execution_record.json", "lifecycle.json",
    "process_result.json", "execution_request.json", "operator_authorization.json",
    "preflight_policy.json", "platform_snapshot.json", "binding_tool_result.json",
    "transport_result.json", "transport_stdout.bin", "transport_stderr.bin",
    "worker_packet.json", "recovery_transport_result.json", "recovery_stdout.bin",
    "recovery_stderr.bin", "recovery_packet.json", "cancellation_transport_result.json",
    "cancellation_stdout.bin", "cancellation_stderr.bin", "cancellation_packet.json",
}) | frozenset(WINDOWS_NAMES.values()) | {"native_evidence_index.json"}
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_RAW_BYTES = 16 * 1024 * 1024


class EvidenceWriteError(OSError):
    """Persistence failed; the observed record remains available to the caller."""

    def __init__(self, message, *, record=None, evidence_directory=None):
        super().__init__(message)
        self.record = record
        self.evidence_directory = evidence_directory
        self.storage_status = "INCOMPLETE"


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2,
                       allow_nan=False) + "\n").encode("utf-8")


def _canonical_digest(value):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def _load(raw):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate lifecycle evidence JSON key")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("nonfinite lifecycle evidence JSON number")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def _model(model, value):
    return model.model_validate(value.model_dump(mode="python") if isinstance(value, model) else value)


def default_lifecycle_output_root():
    if os.name == "nt":
        return Path(__file__).resolve().parent.parent / "data" / "outputs" / "execution_lifecycle"
    return Path.home() / ".local" / "state" / "cuda-poc-generator" / "execution_lifecycle"


def prepare_execution_directory(root, request_id, run_id):
    """Reserve an exclusive run directory before writing any private material."""
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value)
           for value in (request_id, run_id)):
        raise ValueError("request and run identifiers must be lowercase 32-digit hex")
    folder = Path(root or default_lifecycle_output_root()) / (request_id + "-" + run_id)
    if folder.is_symlink():
        raise EvidenceWriteError("Lifecycle run directory must not be a symlink", evidence_directory=str(folder))
    try:
        protection = protect_directory(folder)
        if os.name != "nt" and stat.S_IMODE(folder.stat().st_mode) != 0o700:
            raise OSError("Lifecycle evidence requires effective native POSIX directory mode 0700")
    except OSError as exc:
        raise EvidenceWriteError("Cannot reserve protected lifecycle evidence: " + str(exc),
                                 evidence_directory=str(folder)) from exc
    return folder, protection


def _write_file(folder, name, raw, record):
    destination = folder / name
    temporary = folder / ("." + name + "." + uuid.uuid4().hex + ".tmp")
    reserved = False
    try:
        # Reserve ownership exclusively. Readers reject this empty placeholder
        # until the fully fsynced sibling is atomically published over it.
        with destination.open("xb"):
            pass
        reserved = True
        with temporary.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            temporary.chmod(0o600)
            if stat.S_IMODE(temporary.stat().st_mode) != 0o600:
                raise OSError("Lifecycle evidence file protection could not be applied")
        os.replace(temporary, destination)
        _sync_directory(folder)
    except OSError as exc:
        for partial in (temporary, destination) if reserved else (temporary,):
            try:
                partial.unlink(missing_ok=True)
            except OSError:
                pass
        raise EvidenceWriteError("Lifecycle evidence write failed: " + str(exc), record=record,
                                 evidence_directory=str(folder)) from exc


def _sync_directory(folder):
    if os.name == "nt":
        return "UNSUPPORTED"
    fd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return "APPLIED"


def _read_file(folder, name, limit):
    path = folder / name
    if folder.is_symlink() or path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("unsafe, missing or oversized lifecycle evidence: " + name)
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("oversized lifecycle evidence: " + name)
    return raw


def _one_transport(transport, packet, *, request, record, operation="EXECUTE", allow_missing_packet=False):
    if transport is None:
        if packet is not None:
            raise ValueError("worker packet requires its original transport observation")
        return None, None
    transport = _model(ToolResult, transport)
    if packet is not None:
        if not transport.ok or _load(transport.stdout_bytes()) != packet:
            raise ValueError("worker packet must exactly match successful raw transport bytes")
        if (packet.get("request_id") != request.request_id or packet.get("run_id") != record.run_id):
            raise ValueError("worker packet belongs to another request or run")
        if packet.get("candidate_execution_status") != "NOT_EXECUTED" or packet.get("verification_status") != "NOT_VERIFIED":
            raise ValueError("worker packet cannot claim candidate execution or CVE verification")
        from .lifecycle_bridge import parse_lifecycle_packet
        packet = parse_lifecycle_packet(transport.stdout_bytes(), operation=operation, nonce=packet["nonce"],
                                        request_id=request.request_id, run_id=record.run_id,
                                        target_environment=record.target_environment, expected_request=request)
        remote = packet.get("record")
        if remote is not None and _model(ExecutionRecord, remote) != record:
            raise ValueError("worker packet contains a different execution record")
        if operation == "EXECUTE" and remote is None:
            raise ValueError("execution worker packet must retain its observed execution record")
    elif transport.ok:
        # Successful byte transport can contain an invalid protocol packet.  Such
        # bytes are retained, but cannot accompany a confirmed remote completion.
        try:
            suppressed = _load(transport.stdout_bytes())
        except (ValueError, UnicodeError):
            suppressed = None
        if isinstance(suppressed, dict) and suppressed.get("request_id") == request.request_id and suppressed.get("run_id") == record.run_id:
            raise ValueError("successful transport cannot suppress its worker packet")
        if not allow_missing_packet and record.status not in {"UNKNOWN", "CLEANUP_FAILED", "START_FAILED", "REJECTED", "UNSUPPORTED"}:
            raise ValueError("successful transport cannot suppress its worker packet for a confirmed run")
    return transport, packet


def _validate_authority(request, authorization, policy, record, snapshot, binding_tool_result):
    request = _model(ExecutionRequest, request)
    policy = _model(PreflightPolicy, policy)
    authorization = None if authorization is None else _model(OperatorAuthorization, authorization)
    snapshot = None if snapshot is None else _model(PlatformSnapshot, snapshot)
    binding_tool_result = None if binding_tool_result is None else _model(ToolResult, binding_tool_result)
    if (request.request_id != record.request_id or request_sha256(request) != record.request_sha256
            or request.candidate_sha256 != record.candidate_sha256
            or request.platform_environment_id != record.platform_environment_id
            or request.platform_probe_id != record.platform_probe_id
            or request.binding.target_environment != record.target_environment
            or request.binding.tool_record_id != record.tool_record_id
            or request.fixture_id != record.action_id):
        raise ValueError("execution record does not bind its exact original request")
    if _canonical_digest(policy) != record.policy_sha256:
        raise ValueError("policy differs from the original execution input")
    if (authorization is None) != (record.authorization_sha256 is None):
        raise ValueError("authorization evidence is missing or unexpectedly attached")
    if authorization is not None and _canonical_digest(authorization) != record.authorization_sha256:
        raise ValueError("authorization differs from the original execution input")
    if snapshot is not None:
        if (snapshot_sha256(snapshot) != record.snapshot_sha256
                or snapshot.environment_id != request.platform_environment_id
                or snapshot.metadata["probe_id"] != request.platform_probe_id):
            raise ValueError("platform observation differs from the original execution input")
    elif record.snapshot_sha256 is not None:
        raise ValueError("original platform snapshot must be retained")
    if binding_tool_result is not None:
        if (binding_tool_result.record_id != request.binding.tool_record_id
                or binding_tool_result.target_environment != record.target_environment
                or binding_tool_result.tool_identity.file_sha256 != request.tool_identity.file_sha256
                or binding_tool_result.tool_identity.resolved_path != request.tool_identity.resolved_path):
            raise ValueError("retained tool observation does not match the candidate/tool binding")
    elif record.process is not None:
        raise ValueError("launched lifecycle requires its original candidate/tool binding observation")
    if record.process is not None:
        if authorization is None:
            raise ValueError("launched lifecycle requires original operator authorization")
        fields = ("request_id", "candidate_sha256", "platform_environment_id", "platform_probe_id",
                  "authorized_action", "fixture_id", "resource_limits", "authorization_reference")
        if (any(getattr(request, field) != getattr(authorization, field) for field in fields)
                or authorization.tool_resolved_path != request.tool_identity.resolved_path
                or authorization.tool_file_sha256 != request.tool_identity.file_sha256
                or authorization.authorization_reference != record.authorization_reference
                or authorization.operator_id != record.operator_id):
            raise ValueError("operator authorization does not bind the launched lifecycle")
        if (policy.expected_environment_id != request.platform_environment_id
                or policy.expected_probe_id != request.platform_probe_id
                or policy.expected_target_environment != record.target_environment
                or policy.expected_snapshot_sha256 != record.snapshot_sha256
                or authorization.operator_id not in policy.allowed_operator_ids
                or authorization.authorization_reference not in policy.allowed_authorization_references
                or policy.allowed_tools.get(authorization.tool_resolved_path) != authorization.tool_file_sha256
                or policy.fixture_hashes.get(request.fixture_id) != request.candidate_sha256):
            raise ValueError("trusted policy does not bind the launched lifecycle")
        if request.request_schema_version == "1.2":
            if request.cuda_toolchain != authorization.cuda_toolchain or request.cuda_toolchain != policy.cuda_toolchain:
                raise ValueError("CUDA toolchain scope differs from original operator authorization/policy")
            if record.started_monotonic_ns is None or not (
                    authorization.not_before_monotonic_ns <= record.started_monotonic_ns < authorization.expires_monotonic_ns):
                raise ValueError("CUDA authorization was ineffective in its target boot clock at execution start")
            if record.cuda_smoke is None:
                raise ValueError("CUDA process requires its exact fixed workflow observations")
            from .cuda_registry import build_cuda_step_argv
            for step in record.cuda_smoke.steps:
                role = "nvcc" if step.step_id == "compile" else step.step_id.removesuffix("_version")
                expected = request.cuda_toolchain.tools[role]
                if (step.process.target_environment != record.target_environment or step.process.cwd != request.cwd
                        or step.process.resource_limits != request.resource_limits
                        or step.process.argv != build_cuda_step_argv(step.step_id, request.cuda_toolchain.tools, request.cuda_toolchain.arch, request.cwd)
                        or (step.process.tool_identity.resolved_path, step.process.tool_identity.file_sha256)
                        != (expected.resolved_path, expected.file_sha256)):
                    raise ValueError("CUDA process changed its fixed authorized tool command or limits")
        elif not aware_time(authorization.not_before) <= aware_time(record.started_at) < aware_time(authorization.expires_at):
            raise ValueError("authorization was ineffective at execution start")
    return request, authorization, policy, snapshot, binding_tool_result


def _effective_state(record, recovery_packet):
    recovery = None
    if recovery_packet is not None and recovery_packet.get("recovery") is not None:
        recovery = _model(RemoteRecoveryCheck, recovery_packet["recovery"])
        if recovery.request_id != record.request_id or recovery.run_id != record.run_id:
            raise ValueError("independent cleanup observation belongs to another run")
        if record.execution_schema_version == "1.1" and record.finished_monotonic_ns is not None:
            if recovery.checked_monotonic_ns is None or recovery.checked_monotonic_ns < record.finished_monotonic_ns:
                raise ValueError("independent cleanup has no later observation in the target boot clock")
        elif record.worker_pid is not None and aware_time(recovery.checked_at) < aware_time(record.finished_at):
            raise ValueError("independent cleanup observation predates execution completion")
    if record.worker_pid is None and (record.process is None or not record.process.started):
        if record.status == "UNKNOWN":
            return "UNKNOWN", "UNKNOWN"
        return record.status, "NOT_STARTED"
    if recovery is None or recovery.status == "UNKNOWN":
        return "UNKNOWN", "UNKNOWN"
    if recovery.status == "FAILED":
        return "CLEANUP_FAILED", "FAILED"
    return record.status, "CONFIRMED"


def _capture_state(record, transport, packet, recovery_transport, recovery_packet):
    observations = [item for item in (record.process, transport, recovery_transport) if item is not None]
    if record.cuda_smoke is not None:
        observations.extend(step.process for step in record.cuda_smoke.steps)
    truncated = any(item.truncated for item in observations)
    incomplete = any(item.capture_failed for item in observations)
    if transport is not None and packet is None:
        incomplete = True
    if recovery_transport is not None and recovery_packet is None:
        incomplete = True
    return not truncated and not incomplete, truncated


def _context(record, *, request, authorization, policy, snapshot, binding_tool_result,
             transport, worker_packet, recovery_transport, recovery_packet,
             cancellation_transport=None, cancellation_packet=None):
    record = _model(ExecutionRecord, record)
    request, authorization, policy, snapshot, binding_tool_result = _validate_authority(
        request, authorization, policy, record, snapshot, binding_tool_result)
    if transport is None:
        raise ValueError("lifecycle bridge evidence requires its original Windows launcher observation")
    recovery_transport, recovery_packet = _one_transport(
        recovery_transport, recovery_packet, request=request, record=record, operation="STATUS")
    # A lost/invalid primary stream can be recovered only from an independently
    # received exact target record, never by trusting a caller-supplied summary.
    recovered_record = recovery_packet is not None and recovery_packet.get("record") is not None
    transport, worker_packet = _one_transport(transport, worker_packet, request=request, record=record,
                                               allow_missing_packet=recovered_record)
    cancellation_transport, cancellation_packet = _one_transport(
        cancellation_transport, cancellation_packet, request=request, record=record, operation="CANCEL")
    observed_ids = [item.run_id for item in (transport, recovery_transport, cancellation_transport) if item is not None]
    if len(observed_ids) != len(set(observed_ids)):
        raise ValueError("independent cleanup transport must be a distinct run")
    if record.worker_pid is not None and worker_packet is None and not recovered_record:
        raise ValueError("remote execution record requires primary or independently recovered target provenance")
    effective_status, cleanup_confirmation = _effective_state(record, recovery_packet)
    bundles = [packet["native_evidence"] for packet in (worker_packet, recovery_packet)
               if packet is not None and packet.get("native_evidence") is not None]
    native_bundle = None if not bundles else _model(NativeEvidenceBundle, bundles[0])
    if any(_model(NativeEvidenceBundle, bundle) != native_bundle for bundle in bundles[1:]):
        raise ValueError("native original evidence changed between initial dispatch and independent recovery")
    native_files, native_verification = validate_native_evidence(native_bundle, record, request, authorization,
                                                                 policy, snapshot, binding_tool_result)
    if record.execution_schema_version == "1.1":
        recheck_failed = recovery_packet is not None and any("NATIVE_EVIDENCE_RECHECK_FAILED" in message
                                                            for message in recovery_packet["diagnostics"])
        if recheck_failed or recovery_packet is None or recovery_packet.get("native_evidence") is None:
            observed = native_verification.model_dump(mode="python")
            observed.update(status="FAILED" if recheck_failed else "UNAVAILABLE",
                            diagnostics=observed["diagnostics"] + ["NATIVE_EVIDENCE_RECHECK_FAILED" if recheck_failed
                                                                    else "NATIVE_RECHECK_NOT_AVAILABLE"])
            native_verification = NativeEvidenceVerification.model_validate(observed)
        if (request.request_schema_version == "1.2" and recovery_packet is not None
                and recovery_packet.get("recovery") is not None and record.finished_monotonic_ns is not None
                and recovery_packet["recovery"].get("target_boot_id") != request.cuda_toolchain.target_boot_id):
            raise ValueError("independent target clock belongs to another boot identity")
    if worker_packet is not None:
        for key, expected in (("request_sha256", record.request_sha256),
                              ("authorization_sha256", record.authorization_sha256),
                              ("policy_sha256", record.policy_sha256)):
            if key in worker_packet and worker_packet[key] != expected:
                raise ValueError("worker packet original execution input mismatch: " + key)
    return {"record": record, "request": request, "authorization": authorization, "policy": policy,
            "snapshot": snapshot, "binding_tool_result": binding_tool_result, "transport": transport,
            "worker_packet": worker_packet, "recovery_transport": recovery_transport,
            "recovery_packet": recovery_packet, "effective_status": effective_status,
            "cancellation_transport": cancellation_transport, "cancellation_packet": cancellation_packet,
            "native_bundle": native_bundle, "native_files": native_files, "native_verification": native_verification,
            "cleanup_confirmation": cleanup_confirmation}


def _content(context):
    record = context["record"]
    process = record.process
    content = {
        "stdout.bin": process.stdout_bytes() if process else b"",
        "stderr.bin": process.stderr_bytes() if process else b"",
        "execution_record.json": _json_bytes(record.model_dump(mode="json")),
        "lifecycle.json": _json_bytes([event.model_dump(mode="json") for event in record.events]),
        "process_result.json": _json_bytes(process.model_dump(mode="json") if process else None),
    }
    for name, key in (("execution_request.json", "request"), ("operator_authorization.json", "authorization"),
                      ("preflight_policy.json", "policy"), ("platform_snapshot.json", "snapshot"),
                      ("binding_tool_result.json", "binding_tool_result")):
        value = context[key]
        if value is not None:
            content[name] = _json_bytes(value.model_dump(mode="json"))
    for prefix, transport_key, packet_key in (("transport", "transport", "worker_packet"),
                                              ("recovery", "recovery_transport", "recovery_packet"),
                                              ("cancellation", "cancellation_transport", "cancellation_packet")):
        transport = context[transport_key]
        if transport is not None:
            content[prefix + "_result.json" if prefix == "transport" else prefix + "_transport_result.json"] = _json_bytes(transport.model_dump(mode="json"))
            content[prefix + "_stdout.bin"] = transport.stdout_bytes()
            content[prefix + "_stderr.bin"] = transport.stderr_bytes()
            if context[packet_key] is not None:
                # Keep exact received bytes, not a reserialization of the packet.
                content["worker_packet.json" if prefix == "transport" else prefix + "_packet.json"] = transport.stdout_bytes()
    if context["native_bundle"] is not None:
        import base64
        content["native_evidence_index.json"] = base64.b64decode(context["native_bundle"].index_b64, validate=True)
        content.update({WINDOWS_NAMES[name]: raw for name, raw in context["native_files"].items()})
    if any(name not in content for name in record.evidence_files):
        raise ValueError("execution record references missing or unsupported evidence files")
    if any(name not in content for name in context["request"].expected_artifacts):
        raise ValueError("execution request declares an expected artifact that was not actually collected")
    return content


def _make_manifest(context, content, protection, publication=None, collector_version=None):
    record = context["record"]
    complete, truncated = _capture_state(record, context["transport"], context["worker_packet"],
                                          context["recovery_transport"], context["recovery_packet"])
    if context["cancellation_transport"] is not None:
        cancellation = context["cancellation_transport"]
        truncated = truncated or cancellation.truncated
        complete = complete and not cancellation.truncated and not cancellation.capture_failed and context["cancellation_packet"] is not None
    identities = {key: getattr(record, key) for key in (
        "request_id", "run_id", "request_sha256", "authorization_sha256", "policy_sha256",
        "snapshot_sha256", "candidate_sha256", "platform_environment_id", "platform_probe_id", "tool_record_id")}
    extra = {}
    if record.execution_schema_version == "1.1" or context["native_bundle"] is not None:
        if publication is None:
            raise ValueError("new native evidence requires actual file publication observations")
        extra = {"evidence_schema_version": "1.1", "collector_version": collector_version or "p2c-1.1",
                 "native_evidence": context["native_verification"], "publication": publication}
        complete = complete and context["native_verification"].status == "VERIFIED"
    return EvidenceManifest.model_validate({
        **identities, "execution_record_sha256": _canonical_digest(record),
        "tool_file_sha256": record.tool_identity.file_sha256, "collector_version": COLLECTOR_VERSION,
        "remote_status": record.status, "effective_status": context["effective_status"],
        "cleanup_confirmation": context["cleanup_confirmation"],
        "artifacts": {name: {"file": name, "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                      for name, raw in content.items()},
        "capture_complete": complete, "truncated": truncated, "protection": protection,
        **extra,
    })


def write_execution_evidence(root, result_or_record, *, request, authorization, policy,
                             snapshot=None, binding_tool_result=None, transport=None,
                             worker_packet=None, recovery_transport=None, recovery_packet=None,
                             cancellation_transport=None, cancellation_packet=None):
    """Persist a complete validated observation; never overwrite an earlier run.

    A bridge result may be supplied directly.  Its claimed ``effective_state`` is
    deliberately ignored: report state is derived from retained observations.
    """
    if isinstance(result_or_record, dict) and "record" in result_or_record:
        result = result_or_record
        record = result["record"]
        transport = result.get("transport", transport)
        worker_packet = result.get("worker_packet", worker_packet)
        recovery_transport = result.get("recovery_transport", recovery_transport)
        recovery_packet = result.get("recovery_packet", recovery_packet)
        cancellation_transport = result.get("cancellation_transport", cancellation_transport)
        cancellation_packet = result.get("cancellation_packet", cancellation_packet)
    else:
        record = result_or_record
    context = _context(record, request=request, authorization=authorization, policy=policy,
                       snapshot=snapshot, binding_tool_result=binding_tool_result,
                       transport=transport, worker_packet=worker_packet,
                       recovery_transport=recovery_transport, recovery_packet=recovery_packet,
                       cancellation_transport=cancellation_transport, cancellation_packet=cancellation_packet)
    content = _content(context)
    record = context["record"]
    try:
        folder, protection = prepare_execution_directory(root, record.request_id, record.run_id)
    except EvidenceWriteError as exc:
        exc.record = record
        raise
    try:
        publication = {"file_fsync": True, "atomic_publication": True,
                       "directory_fsync": _sync_directory(folder)}
    except OSError as exc:
        raise EvidenceWriteError("Lifecycle directory durability observation failed", record=record,
                                 evidence_directory=str(folder)) from exc
    manifest = _make_manifest(context, content, protection, publication)
    for name, raw in content.items():
        _write_file(folder, name, raw, record)
    # The manifest is the commit marker: a partial write is never readable as a
    # successful evidence set.  The report can always be regenerated afterwards.
    _write_file(folder, "report.md", render_execution_report(record, manifest, transport=context["transport"],
                recovery_transport=context["recovery_transport"], cancellation_transport=context["cancellation_transport"],
                snapshot=context["snapshot"], authorization=context["authorization"]).encode("utf-8"), record)
    _write_file(folder, "manifest.json", _json_bytes(manifest.model_dump(mode="json")), record)
    return folder


def read_execution_evidence(folder, *, expected_request_id=None, expected_run_id=None,
                            expected_record_sha256=None, verify_report=True):
    """Re-read and associate records, packet bytes, authority and raw output."""
    folder = Path(folder)
    manifest = _model(EvidenceManifest, _load(_read_file(folder, "manifest.json", 131072)))
    if not set(manifest.artifacts).issubset(ALLOWED_FILES):
        raise ValueError("unsupported lifecycle evidence manifest file")
    for supplied, stored, label in ((expected_request_id, manifest.request_id, "request"),
                                     (expected_run_id, manifest.run_id, "run"),
                                     (expected_record_sha256, manifest.execution_record_sha256, "record")):
        if supplied is not None and supplied != stored:
            raise ValueError("lifecycle evidence " + label + " identity mismatch")
    content = {}
    for name, entry in manifest.artifacts.items():
        limit = MAX_RAW_BYTES if name.endswith(".bin") else MAX_JSON_BYTES
        if entry.size_bytes > limit:
            raise ValueError("declared lifecycle evidence size exceeds bound")
        raw = _read_file(folder, name, limit)
        if len(raw) != entry.size_bytes or hashlib.sha256(raw).hexdigest() != entry.sha256:
            raise ValueError("lifecycle evidence artifact digest or length mismatch: " + name)
        content[name] = raw
    required = {"execution_record.json", "execution_request.json", "preflight_policy.json",
                "lifecycle.json", "stdout.bin", "stderr.bin", "process_result.json",
                "transport_result.json", "transport_stdout.bin", "transport_stderr.bin"}
    if not required.issubset(content):
        raise ValueError("missing required lifecycle evidence files")

    def value(name):
        return _load(content[name]) if name in content else None

    context = _context(value("execution_record.json"), request=value("execution_request.json"),
                       authorization=value("operator_authorization.json"), policy=value("preflight_policy.json"),
                       snapshot=value("platform_snapshot.json"), binding_tool_result=value("binding_tool_result.json"),
                       transport=value("transport_result.json"), worker_packet=value("worker_packet.json"),
                       recovery_transport=value("recovery_transport_result.json"), recovery_packet=value("recovery_packet.json"),
                       cancellation_transport=value("cancellation_transport_result.json"), cancellation_packet=value("cancellation_packet.json"))
    canonical = _content(context)
    if set(canonical) != set(content):
        raise ValueError("lifecycle evidence file set omits or adds original observations")
    # JSON formatting is not itself semantic, but exact packet and output bytes
    # must remain tied to original transport and process records.
    for name, expected in canonical.items():
        if name.endswith(".json") and not name.startswith("native_") and name not in {"worker_packet.json", "recovery_packet.json"}:
            if _load(content[name]) != _load(expected):
                raise ValueError("lifecycle evidence structured association mismatch: " + name)
        elif content[name] != expected:
            raise ValueError("lifecycle evidence raw bytes association mismatch: " + name)
    derived = _make_manifest(context, content, manifest.protection, manifest.publication, manifest.collector_version)
    if manifest != derived:
        raise ValueError("lifecycle manifest identity or outcome differs from retained observations")
    if manifest.protection.get("status") != "APPLIED":
        raise ValueError("lifecycle evidence protection was not applied")
    if verify_report and _read_file(folder, "report.md", 131072) != render_execution_report(
            context["record"], manifest, transport=context["transport"], recovery_transport=context["recovery_transport"],
            cancellation_transport=context["cancellation_transport"], snapshot=context["snapshot"],
            authorization=context["authorization"]).encode("utf-8"):
        raise ValueError("deterministic lifecycle report mismatch")
    return {**context, "manifest": manifest, "artifacts": content}


def rebuild_execution_report(folder):
    """Regenerate a report from verified original evidence without overwriting it."""
    if (Path(folder) / "readiness_manifest.json").exists():
        result = read_cuda_readiness_evidence(folder)
        return render_execution_report(readiness=result)
    result = read_execution_evidence(folder, verify_report=False)
    return render_execution_report(result["record"], result["manifest"], transport=result["transport"],
                                   recovery_transport=result["recovery_transport"], cancellation_transport=result["cancellation_transport"],
                                   snapshot=result["snapshot"], authorization=result["authorization"])


def _text(value):
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
    return str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|").replace("`", "'")


def render_execution_report(record=None, manifest=None, *, transport=None, recovery_transport=None, cancellation_transport=None,
                            snapshot=None, authorization=None, readiness=None):
    """Render verified structured observations without LLM interpretation."""
    if readiness is not None:
        if record is not None or manifest is not None:
            raise ValueError("readiness observations cannot be combined with execution records")
        return _render_cuda_readiness(readiness)
    record = _model(ExecutionRecord, record)
    manifest = _model(EvidenceManifest, manifest)
    lines = ["# P2-B controlled execution lifecycle report", "",
             "This report describes a fixed, registered harmless action. CVE verification: NOT_VERIFIED.", "",
             "Request ID: " + record.request_id, "Run ID: " + record.run_id,
             "Action: " + _text(record.action_id), "Remote recorded status: " + record.status,
             "Effective status after independent cleanup check: " + manifest.effective_status,
             "Independent cleanup confirmation: " + manifest.cleanup_confirmation, "",
             "Operator: " + _text(record.operator_id),
             "Authorization reference: " + _text(record.authorization_reference),
             "Policy SHA-256: " + record.policy_sha256,
             "Target environment: " + _text(record.target_environment),
             "Platform environment: " + record.platform_environment_id,
             "Platform probe: " + _text(record.platform_probe_id),
             "Candidate SHA-256: " + record.candidate_sha256,
             "Tool observation: " + record.tool_record_id, "",
             "Started: " + str(record.started_at), "Finished: " + str(record.finished_at), ""]
    lines.extend(["## Controller launcher observations", ""])
    for label, observation in (("Initial dispatch", transport), ("Scoped cancellation", cancellation_transport),
                                ("Independent recovery check", recovery_transport)):
        if observation is not None:
            observation = _model(ToolResult, observation)
            lines.append(label + ": " + observation.end_status + "; platform=" + observation.platform_type
                         + "; returncode=" + str(observation.returncode) + "; record=" + observation.record_id)
            if manifest.collector_version == "p2c-1.1":
                lines.extend([label + " actual argv: " + _text(observation.argv),
                    label + " command source: " + _text(observation.command_identity.source),
                    label + " controller target: " + _text(observation.target_environment),
                    label + " actual cwd: " + _text(observation.cwd),
                    label + " controller start/end: " + observation.started_at + " / " + observation.finished_at,
                    label + " measured executable: " + _text(observation.tool_identity.model_dump(mode="json"))])
            try:
                from .lifecycle_bridge import parse_lifecycle_packet
                raw_packet = _load(observation.stdout_bytes())
                operation = {"Initial dispatch": "EXECUTE", "Scoped cancellation": "CANCEL",
                             "Independent recovery check": "STATUS"}[label]
                packet = parse_lifecycle_packet(observation.stdout_bytes(), operation=operation,
                    nonce=raw_packet["nonce"], request_id=record.request_id, run_id=record.run_id,
                    target_environment=record.target_environment)
            except (ValueError, KeyError, TypeError):
                packet = None
            if packet is None:
                lines.append(label + " worker response: no validated protocol response; launcher exit alone is not acknowledgement.")
            else:
                lines.append(label + " worker diagnostics: " + _text(packet["diagnostics"]))
                if packet.get("recovery") is not None:
                    lines.append(label + " target recovery observation: " + _text(packet["recovery"]))
        else:
            lines.append(label + ": no retained launcher observation supplied.")
    lines.append("")
    if record.process is None:
        lines.extend(["No target process was confirmed started.", ""])
    else:
        process = record.process.model_dump(mode="json")
        lines.extend(["## Observed process", ""])
        for key in ("pid", "process_group_id", "pgid", "returncode", "linux_signal", "termination_method",
                    "cleanup_status", "group_empty", "timed_out", "truncated", "capture_failed"):
            if key in process:
                lines.append(key + ": " + _text(process[key]))
        lines.extend(["", "Actual executable: " + _text(record.tool_identity.resolved_path),
                      "Executable SHA-256: " + _text(record.tool_identity.file_sha256), ""])
        lines.extend(["Requested resource bounds: " + _text(process["resource_limits"]),
                      "Observed enforcement: " + _text(process["resources"]),
                      "Observed cleanup: " + _text(process["cleanup"]), ""])
    lines.extend(["## Lifecycle events", "", "| Sequence | State | Time | Observation |", "|---:|---|---|---|"])
    for index, event in enumerate(record.events):
        entry = event.model_dump(mode="json")
        lines.append("| " + str(entry.get("sequence", index)) + " | " + _text(entry.get("state", entry.get("status")))
                     + " | " + _text(entry.get("observed_at", entry.get("timestamp", entry.get("at")))) + " | "
                     + _text(entry.get("detail", entry.get("message", entry.get("reason", "")))) + " |")
    lines.extend(["", "## Resource and cleanup limits", "",
                  "Wall-clock watchdog, output cap, POSIX process groups, RLIMIT_CPU and RLIMIT_AS are action-specific.",
                  "RLIMIT_AS limits CPU address space; it is not a GPU VRAM limit.",
                  "No GPU driver isolation, complete network isolation or untrusted-code sandbox is claimed.", "",
                  "## Raw evidence", "", "| Artifact | Bytes | SHA-256 |", "|---|---:|---|"])
    for name, item in sorted(manifest.artifacts.items()):
        lines.append(f"| {name} | {item.size_bytes} | {item.sha256} |")
    lines.extend(["", "Capture complete: " + str(manifest.capture_complete),
                  "Output truncated: " + str(manifest.truncated),
                  "Recorded protection: " + _text(manifest.protection), "",
                  "## Outcome and evidence boundary", ""])
    lines.extend("- " + _text(message) for message in record.diagnostics)
    if not record.diagnostics:
        lines.append("No additional diagnostic was recorded.")
    lines.extend(["", "A zero exit status is process evidence only. This action does not evaluate any CVE trigger conditions.",
                  "Candidate execution: NOT_EXECUTED. Vulnerability verification: NOT_VERIFIED.",
                  "A stopped Windows launcher does not establish Linux cleanup; the independent target observation is required.",
                  "This report is regenerated from verified records and raw evidence, without a model.",
                  "Hashes identify retained bytes, including any retained prefix; they do not recover missing output.",
                  "The manifest is an integrity index, not a digital signature or hardware attestation.", ""])
    if manifest.evidence_schema_version == "1.1":
        lines[0] = "# P2-C fixed harmless CUDA toolchain experiment report" if record.cuda_smoke else "# Controlled lifecycle and native evidence report"
        lines.extend(["## Cross-environment original-file verification", "",
                      "Native original-file verification: " + manifest.native_evidence.status,
                      "Native index original-byte SHA-256: " + str(manifest.native_evidence.index_sha256),
                      "Verified native files: " + str(manifest.native_evidence.file_count),
                      "Native retained bytes: " + str(manifest.native_evidence.size_bytes),
                      "Native diagnostics: " + _text(manifest.native_evidence.diagnostics),
                      "File publication observations: " + _text(manifest.publication.model_dump(mode="json")),
                      "Directory fsync is unsupported on Windows; file fsync and atomic same-directory publication do not provide database transactions.", ""])
        if authorization is not None:
            lines.extend(["Authorization issuer kind: " + authorization.issuer_kind,
                          "Authorized scope/action: " + authorization.authorized_action,
                          "Authorization UTC reference observations: " + authorization.not_before + " to " + authorization.expires_at,
                          "Authorization enforcement clock: " + authorization.authorization_clock,
                          "Authorized target boot monotonic window (ns): " + str(authorization.not_before_monotonic_ns)
                          + " to " + str(authorization.expires_monotonic_ns),
                          "Task local monotonic observations (ns): " + str(record.started_monotonic_ns) + " / " + str(record.finished_monotonic_ns),
                          "UTC timestamps remain unmodified; local monotonic order is not a Windows/WSL hardware timeline.", ""])
        if snapshot is not None:
            snapshot = _model(PlatformSnapshot, snapshot)
            lines.extend(["## Observed target GPU and toolkit", ""])
            for name, observation in snapshot.model_dump(mode="json").items():
                if isinstance(observation, dict) and "status" in observation and any(word in name for word in ("gpu", "cuda", "nvcc", "driver", "toolkit")):
                    lines.append(name + ": " + _text(observation))
            lines.append("")
        if record.cuda_smoke is not None:
            smoke = record.cuda_smoke
            lines.extend(["## Fixed CUDA compilation and inspection", "",
                          "Registered action: " + smoke.action_id, "Source SHA-256: " + smoke.source_sha256,
                          "Validated target architecture: " + smoke.arch,
                          "Compiler artifact: " + _text(smoke.artifact.model_dump(mode="json") if smoke.artifact else None),
                          "Kernel launch: NOT_EXECUTED. Compilation and inspection do not prove runtime behavior or any CVE.", ""])
            for role, version in sorted(smoke.tool_versions.items()):
                lines.append(role + " measured version: " + _text(version.stdout_bytes().decode("utf-8", errors="replace")[:2048])
                             + "; version ToolResult=" + version.record_id)
            for step in smoke.steps:
                process = step.process
                lines.extend(["", "### Tool step: " + step.step_id, "", "State: " + step.state,
                              "Command source: fixed reviewed CUDA registry and validated task directory",
                              "Actual native argv: " + _text(process.argv), "Native cwd: " + _text(process.cwd),
                              "Actual executable identity: " + _text(process.actual_tool_identity.model_dump(mode="json") if process.actual_tool_identity else None),
                              "Guard executable identity: " + _text(process.launcher_tool_identity.model_dump(mode="json")),
                              "Observed process identity: " + _text({name: getattr(process, name) for name in
                                  ("pid", "ppid", "pgid", "session_id", "start_ticks", "uid", "gid", "worker_pid")}),
                              "Descendant identities and exec observations: " + _text(process.descendant_identities),
                              "Actual return code/signal: " + str(process.returncode) + " / " + str(process.linux_signal),
                              "Target start/end: " + str(process.started_at) + " / " + process.finished_at,
                              "Observed resource enforcement: " + _text(process.resources.model_dump(mode="json")),
                              "Observed cleanup: " + _text(process.cleanup.model_dump(mode="json")),
                              "Raw stdout: native_steps_" + step.step_id + "_stdout.bin; bytes=" + str(process.stdout_size_bytes) + "; SHA-256=" + process.stdout_sha256,
                              "Raw stderr: native_steps_" + step.step_id + "_stderr.bin; bytes=" + str(process.stderr_size_bytes) + "; SHA-256=" + process.stderr_sha256,
                              "Timeout/truncated/capture_failed: " + str(process.timed_out) + " / " + str(process.truncated) + " / " + str(process.capture_failed)])
            lines.append("")
    return "\n".join(lines)


def _readiness_context(transport, packet, diagnostics):
    transport = _model(ToolResult, transport)
    if not isinstance(diagnostics, list) or any(not isinstance(item, str) for item in diagnostics):
        raise ValueError("readiness diagnostics must be literal observer strings")
    description = None
    if packet is not None:
        if not transport.ok or _load(transport.stdout_bytes()) != packet:
            raise ValueError("readiness packet differs from the original launcher bytes")
        from .lifecycle_bridge import parse_lifecycle_packet
        packet = parse_lifecycle_packet(transport.stdout_bytes(), operation="DESCRIBE_CUDA", nonce=packet["nonce"],
            request_id=packet["request_id"], run_id=packet["run_id"], target_environment=packet["target_environment"])
        if packet.get("cuda_description") is not None:
            from .cuda_smoke_worker import CudaSmokeDescription
            description = _model(CudaSmokeDescription, packet["cuda_description"])
    elif transport.ok:
        try:
            omitted = _load(transport.stdout_bytes())
        except (ValueError, UnicodeError):
            omitted = None
        if isinstance(omitted, dict) and omitted.get("operation") == "DESCRIBE_CUDA":
            raise ValueError("readiness evidence cannot hide a returned CUDA description packet")
    return {"transport": transport, "packet": packet, "description": description, "diagnostics": diagnostics}


def _render_cuda_readiness(readiness):
    context = _readiness_context(readiness["transport"], readiness.get("packet"), readiness.get("diagnostics", []))
    transport, description = context["transport"], context["description"]
    status = "UNKNOWN" if description is None else description.status
    lines = ["# P2-C CUDA smoke readiness report", "", "Preparation status: " + status,
             "No ExecutionRequest or native compilation is claimed by this readiness observation.",
             "Candidate execution: NOT_EXECUTED. Kernel launch: NOT_EXECUTED. CVE verification: NOT_VERIFIED.", "",
             "Launcher process status: " + transport.end_status, "Launcher return code: " + str(transport.returncode),
             "Launcher record: " + transport.record_id,
             "Windows/controller observation start/end: " + transport.started_at + " / " + transport.finished_at,
             "Original launcher stdout: transport_stdout.bin; SHA-256=" + transport.stdout_sha256,
             "Original launcher stderr: transport_stderr.bin; SHA-256=" + transport.stderr_sha256,
             "Transport diagnostics: " + _text(context["diagnostics"])]
    if context["packet"] is not None:
        packet = context["packet"]
        lines.extend(["Readiness request/run identity: " + packet["request_id"] + " / " + packet["run_id"],
                      "Target environment: " + _text(packet["target_environment"]),
                      "Raw worker diagnostics: " + _text(packet["diagnostics"])])
    if description is not None:
        lines.extend(["CUDA readiness diagnostics: " + _text(description.diagnostics),
                      "Registered source SHA-256: " + description.source_sha256,
                      "Observed resource support: " + _text(description.resource_support.model_dump(mode="json"))])
        if description.scope is not None:
            lines.append("Measured toolchain scope: " + _text(description.scope.model_dump(mode="json")))
        if description.snapshot is not None:
            lines.extend(["Target environment content identity: " + description.snapshot.environment_id,
                          "Target probe: " + description.snapshot.metadata["probe_id"]])
    lines.extend(["", "Read-only version and identity queries are not a CUDA compile or vulnerability test.",
                  "Missing tools, unsupported versions or incomplete communication must not be reported as execution success.",
                  "This report is deterministic and can be rebuilt from the retained original bytes.", ""])
    return "\n".join(lines)


def write_cuda_readiness_evidence(root, transport, packet, diagnostics):
    """Save real pre-request failures without manufacturing an ExecutionRecord."""
    context = _readiness_context(transport, packet, diagnostics)
    transport = context["transport"]
    folder = Path(root or default_lifecycle_output_root()) / "readiness" / transport.run_id
    try:
        protection = protect_directory(folder)
        directory_fsync = _sync_directory(folder)
    except OSError as exc:
        raise EvidenceWriteError("CUDA readiness evidence storage unavailable", evidence_directory=str(folder)) from exc
    content = {"transport_result.json": _json_bytes(transport.model_dump(mode="json")),
               "transport_stdout.bin": transport.stdout_bytes(), "transport_stderr.bin": transport.stderr_bytes(),
               "readiness_diagnostics.json": _json_bytes(diagnostics)}
    if packet is not None:
        content["worker_packet.json"] = transport.stdout_bytes()
    manifest = {"readiness_schema_version": "1.0", "transport_run_id": transport.run_id,
                "transport_record_id": transport.record_id, "protection": protection,
                "publication": {"file_fsync": True, "atomic_publication": True, "directory_fsync": directory_fsync},
                "artifacts": {name: {"size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                              for name, raw in content.items()},
                "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    for name, raw in content.items():
        _write_file(folder, name, raw, None)
    _write_file(folder, "report.md", render_execution_report(readiness=context).encode("utf-8"), None)
    _write_file(folder, "readiness_manifest.json", _json_bytes(manifest), None)
    return folder


def read_cuda_readiness_evidence(folder):
    folder = Path(folder)
    manifest = _load(_read_file(folder, "readiness_manifest.json", 65536))
    allowed = {"transport_result.json", "transport_stdout.bin", "transport_stderr.bin", "worker_packet.json", "readiness_diagnostics.json"}
    required = allowed - {"worker_packet.json"}
    if (set(manifest) != {"readiness_schema_version", "transport_run_id", "transport_record_id", "protection", "publication",
                         "artifacts", "candidate_execution_status", "verification_status"}
            or manifest["readiness_schema_version"] != "1.0" or not required.issubset(manifest["artifacts"])
            or not set(manifest["artifacts"]).issubset(allowed) or manifest["candidate_execution_status"] != "NOT_EXECUTED"
            or manifest["verification_status"] != "NOT_VERIFIED"):
        raise ValueError("invalid CUDA readiness evidence manifest")
    content = {}
    for name, entry in manifest["artifacts"].items():
        raw = _read_file(folder, name, MAX_JSON_BYTES)
        if set(entry) != {"size_bytes", "sha256"} or type(entry["size_bytes"]) is not int or len(raw) != entry["size_bytes"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError("CUDA readiness original bytes were changed or lost")
        content[name] = raw
    context = _readiness_context(_load(content["transport_result.json"]),
        _load(content["worker_packet.json"]) if "worker_packet.json" in content else None, _load(content["readiness_diagnostics.json"]))
    transport = context["transport"]
    if (transport.run_id != manifest["transport_run_id"] or transport.record_id != manifest["transport_record_id"]
            or transport.stdout_bytes() != content["transport_stdout.bin"] or transport.stderr_bytes() != content["transport_stderr.bin"]):
        raise ValueError("CUDA readiness transport associations are inconsistent")
    if _read_file(folder, "report.md", 1048576) != render_execution_report(readiness=context).encode("utf-8"):
        raise ValueError("CUDA readiness report differs from original observations")
    return context
