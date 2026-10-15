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

from .models.execution import (ExecutionRequest, OperatorAuthorization,
                               PreflightPolicy, aware_time, request_sha256,
                               snapshot_sha256)
from .models.lifecycle import ExecutionRecord, EvidenceManifest, RemoteRecoveryCheck
from .models.platform import PlatformSnapshot
from .models.tool_result import ToolResult
from .probe_artifacts import protect_directory


COLLECTOR_VERSION = "p2b-1.0"
ALLOWED_FILES = frozenset({
    "stdout.bin", "stderr.bin", "execution_record.json", "lifecycle.json",
    "process_result.json", "execution_request.json", "operator_authorization.json",
    "preflight_policy.json", "platform_snapshot.json", "binding_tool_result.json",
    "transport_result.json", "transport_stdout.bin", "transport_stderr.bin",
    "worker_packet.json", "recovery_transport_result.json", "recovery_stdout.bin",
    "recovery_stderr.bin", "recovery_packet.json", "cancellation_transport_result.json",
    "cancellation_stdout.bin", "cancellation_stderr.bin", "cancellation_packet.json",
})
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
    try:
        with (folder / name).open("xb") as stream:
            stream.write(raw)
        if os.name != "nt":
            (folder / name).chmod(0o600)
            if stat.S_IMODE((folder / name).stat().st_mode) != 0o600:
                raise OSError("Lifecycle evidence file protection could not be applied")
    except OSError as exc:
        raise EvidenceWriteError("Lifecycle evidence write failed: " + str(exc), record=record,
                                 evidence_directory=str(folder)) from exc


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
        if not aware_time(authorization.not_before) <= aware_time(record.started_at) < aware_time(authorization.expires_at):
            raise ValueError("authorization was ineffective at execution start")
    return request, authorization, policy, snapshot, binding_tool_result


def _effective_state(record, recovery_packet):
    recovery = None
    if recovery_packet is not None and recovery_packet.get("recovery") is not None:
        recovery = _model(RemoteRecoveryCheck, recovery_packet["recovery"])
        if recovery.request_id != record.request_id or recovery.run_id != record.run_id:
            raise ValueError("independent cleanup observation belongs to another run")
        if record.worker_pid is not None and aware_time(recovery.checked_at) < aware_time(record.finished_at):
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
    if any(name not in content for name in record.evidence_files):
        raise ValueError("execution record references missing or unsupported evidence files")
    if any(name not in content for name in context["request"].expected_artifacts):
        raise ValueError("execution request declares an expected artifact that was not actually collected")
    return content


def _make_manifest(context, content, protection):
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
    return EvidenceManifest.model_validate({
        **identities, "execution_record_sha256": _canonical_digest(record),
        "tool_file_sha256": record.tool_identity.file_sha256, "collector_version": COLLECTOR_VERSION,
        "remote_status": record.status, "effective_status": context["effective_status"],
        "cleanup_confirmation": context["cleanup_confirmation"],
        "artifacts": {name: {"file": name, "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                      for name, raw in content.items()},
        "capture_complete": complete, "truncated": truncated, "protection": protection,
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
    manifest = _make_manifest(context, content, protection)
    for name, raw in content.items():
        _write_file(folder, name, raw, record)
    # The manifest is the commit marker: a partial write is never readable as a
    # successful evidence set.  The report can always be regenerated afterwards.
    _write_file(folder, "report.md", render_execution_report(record, manifest, transport=context["transport"],
                recovery_transport=context["recovery_transport"], cancellation_transport=context["cancellation_transport"]).encode("utf-8"), record)
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
        if name.endswith(".json") and name not in {"worker_packet.json", "recovery_packet.json"}:
            if _load(content[name]) != _load(expected):
                raise ValueError("lifecycle evidence structured association mismatch: " + name)
        elif content[name] != expected:
            raise ValueError("lifecycle evidence raw bytes association mismatch: " + name)
    derived = _make_manifest(context, content, manifest.protection)
    if manifest != derived:
        raise ValueError("lifecycle manifest identity or outcome differs from retained observations")
    if manifest.protection.get("status") != "APPLIED":
        raise ValueError("lifecycle evidence protection was not applied")
    if verify_report and _read_file(folder, "report.md", 131072) != render_execution_report(
            context["record"], manifest, transport=context["transport"], recovery_transport=context["recovery_transport"],
            cancellation_transport=context["cancellation_transport"]).encode("utf-8"):
        raise ValueError("deterministic lifecycle report mismatch")
    return {**context, "manifest": manifest, "artifacts": content}


def rebuild_execution_report(folder):
    """Regenerate a report from verified original evidence without overwriting it."""
    result = read_execution_evidence(folder, verify_report=False)
    return render_execution_report(result["record"], result["manifest"], transport=result["transport"],
                                   recovery_transport=result["recovery_transport"], cancellation_transport=result["cancellation_transport"])


def _text(value):
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
    return str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|").replace("`", "'")


def render_execution_report(record, manifest, *, transport=None, recovery_transport=None, cancellation_transport=None):
    """Render verified structured observations without LLM interpretation."""
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
    return "\n".join(lines)
