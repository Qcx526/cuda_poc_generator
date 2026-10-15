"""Private, hash-checked P2-A fixture evidence; no LLM or CVE interpretation."""

import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

from .models.execution import (ExecutionRequest, OperatorAuthorization, PreflightPolicy, request_sha256,
                               snapshot_sha256, aware_time)
from .models.tool_result import ToolResult
from .probe_artifacts import protect_directory


def _json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode("utf-8")


def _load(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate evidence JSON key")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("nonfinite evidence JSON number")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def _validate_result(result, request):
    if not isinstance(result, dict) or set(result) != {"packet", "transport"}:
        raise ValueError("execution bridge evidence requires packet and transport")
    transport = ToolResult.model_validate(result["transport"].model_dump(mode="python")
                                         if isinstance(result["transport"], ToolResult) else result["transport"])
    packet = result["packet"]
    # A packet must originate in retained transport bytes, not be constructed by
    # the caller after a failed launcher. Failed transport is kept with no packet.
    if packet is not None:
        if not transport.ok or _load(transport.stdout_bytes()) != packet:
            raise ValueError("worker packet does not match successful raw transport")
        from .execution_bridge import parse_execution_packet
        packet = parse_execution_packet(transport.stdout_bytes(), operation=packet["operation"],
                                        nonce=packet["nonce"], request_id=packet["request_id"],
                                        target_environment=packet["target_environment"],
                                        expected_request=request)
    if request is not None:
        request = ExecutionRequest.model_validate(request.model_dump(mode="python")
                                                  if isinstance(request, ExecutionRequest) else request)
        if packet is not None and packet["request_id"] != request.request_id:
            raise ValueError("worker evidence belongs to another request")
    elif packet is not None and packet["operation"] != "DESCRIBE":
        raise ValueError("fixture evidence requires its independently supplied request")
    if packet is None and transport.ok:
        raise ValueError("successful transport must retain its validated worker packet")
    return transport, packet, request


def _validate_authority(request, authorization, policy, packet):
    if authorization is None and policy is None:
        if packet is not None and packet["status"] in {"FIXTURE_COMPLETED", "FIXTURE_FAILED"}:
            raise ValueError("fixture evidence requires the original operator authorization and policy")
        return None, None
    if authorization is None or policy is None or request is None:
        raise ValueError("retain operator authorization and trusted policy together with their request")
    auth = OperatorAuthorization.model_validate(authorization.model_dump(mode="python")
                                                if isinstance(authorization, OperatorAuthorization) else authorization)
    trusted = PreflightPolicy.model_validate(policy.model_dump(mode="python") if isinstance(policy, PreflightPolicy) else policy)
    fields = ("request_id", "candidate_sha256", "platform_environment_id", "platform_probe_id",
              "authorized_action", "fixture_id", "resource_limits", "authorization_reference")
    if (any(getattr(auth, name) != getattr(request, name) for name in fields)
            or auth.tool_resolved_path != request.tool_identity.resolved_path
            or auth.tool_file_sha256 != request.tool_identity.file_sha256):
        raise ValueError("operator authorization does not bind this exact request scope")
    if (trusted.expected_environment_id != request.platform_environment_id
            or trusted.expected_probe_id != request.platform_probe_id
            or trusted.expected_target_environment != request.binding.target_environment
            or trusted.execution_backend != request.execution_backend
            or auth.operator_id not in trusted.allowed_operator_ids
            or auth.authorization_reference not in trusted.allowed_authorization_references
            or trusted.scope_root != request.cwd
            or trusted.allowed_tools.get(auth.tool_resolved_path) != auth.tool_file_sha256
            or trusted.fixture_hashes.get(request.fixture_id) != request.candidate_sha256):
        raise ValueError("trusted policy does not bind the authorized request scope")
    if packet is not None:
        from .execution_worker import contract_digest
        if (packet.get("authorization_sha256") is not None
                and packet["authorization_sha256"] != contract_digest(OperatorAuthorization, auth)):
            raise ValueError("operator authorization differs from the original worker input")
        if packet.get("policy_sha256") is not None and packet["policy_sha256"] != contract_digest(PreflightPolicy, trusted):
            raise ValueError("policy differs from the original worker input")
        if packet["target_snapshot"] is not None and snapshot_sha256(packet["target_snapshot"]) != trusted.expected_snapshot_sha256:
            raise ValueError("policy snapshot differs from the retained platform observation")
        if packet["status"] in {"FIXTURE_COMPLETED", "FIXTURE_FAILED"}:
            moment = aware_time(packet["preflight"]["checked_at"])
            if not aware_time(auth.not_before) <= moment < aware_time(auth.expires_at):
                raise ValueError("authorization was ineffective at recorded preflight time")
    return auth, trusted


def default_execution_output_root():
    if os.name == "nt":
        return Path(__file__).resolve().parent.parent / "data" / "outputs" / "execution_preflight"
    return Path.home() / ".local" / "state" / "cuda-poc-generator" / "execution_preflight"


def render_execution_report(manifest, packet):
    lines = ["# P2-A controlled fixture communication report", "",
             "This deterministic report covers a fixed harmless fixture only.",
             "Candidate execution: NOT_EXECUTED. CVE verification: NOT_VERIFIED.", "",
             "Evidence ID: " + manifest["evidence_id"],
             "Request ID: " + str(manifest["request_id"]),
             "Transport record: " + manifest["transport_record_id"],
             "Status: " + (packet["status"] if packet is not None else "TRANSPORT_FAILED"), ""]
    if packet is not None:
        lines.extend(["Operation: " + packet["operation"],
                      "Target environment: " + str(packet["target_environment"]), ""])
        if packet["target_snapshot"] is not None:
            lines.extend(["Platform content identity: " + packet["target_snapshot"]["environment_id"],
                          "Platform probe: " + packet["target_snapshot"]["metadata"]["probe_id"], ""])
        if packet.get("tool_result") is not None:
            tool = ToolResult.model_validate(packet["tool_result"])
            lines.extend(["Target tool status: " + tool.end_status,
                          "Target return code: " + str(tool.returncode),
                          "Target tool record: " + tool.record_id,
                          "Executable SHA-256: " + str(tool.tool_identity.file_sha256), ""])
    lines.extend(["| Retained artifact | Bytes | SHA-256 |", "|---|---:|---|"])
    for name, item in sorted(manifest["artifacts"].items()):
        lines.append(f"| {name} | {item['size_bytes']} | {item['sha256']} |")
    lines.extend(["", "Communication, normal exit and resource setup are not vulnerability evidence.",
                  "Paths, argv and original output are private in this evidence directory.",
                  "The manifest detects accidental changes; it is not a digital signature or hardware attestation.", ""])
    return "\n".join(lines)


def write_execution_evidence(root, result, *, request=None, authorization=None, policy=None):
    """Write only validated transport and exact packet bytes to a private folder."""
    transport, packet, request = _validate_result(result, request)
    auth, trusted = _validate_authority(request, authorization, policy, packet)
    evidence_id = uuid.uuid4().hex
    folder = Path(root or default_execution_output_root()) / evidence_id
    protection = protect_directory(folder)
    content = {"transport_stdout.bin": transport.stdout_bytes(),
               "transport_stderr.bin": transport.stderr_bytes(),
               "transport_result.json": _json_bytes(transport.model_dump(mode="json"))}
    if packet is not None:
        content["worker_packet.json"] = transport.stdout_bytes()
        if packet.get("tool_result") is not None:
            tool = ToolResult.model_validate(packet["tool_result"])
            content.update({"stdout.bin": tool.stdout_bytes(), "stderr.bin": tool.stderr_bytes(),
                            "tool_result.json": _json_bytes(tool.model_dump(mode="json"))})
    if request is not None:
        content["execution_request.json"] = _json_bytes(request.model_dump(mode="json"))
    if auth is not None:
        content["operator_authorization.json"] = _json_bytes(auth.model_dump(mode="json"))
        content["preflight_policy.json"] = _json_bytes(trusted.model_dump(mode="json"))
    manifest = {"evidence_schema_version": "1.0", "evidence_id": evidence_id,
                "request_id": request.request_id if request is not None else None,
                "request_sha256": request_sha256(request) if request is not None else None,
                "transport_record_id": transport.record_id,
                "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED",
                "access_control": protection,
                "artifacts": {name: {"size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                              for name, raw in content.items()}}
    content["manifest.json"] = _json_bytes(manifest)
    content["report.md"] = render_execution_report(manifest, packet).encode("utf-8")
    for name, raw in content.items():
        with (folder / name).open("xb") as stream:
            stream.write(raw)
        if os.name != "nt":
            (folder / name).chmod(0o600)
            if stat.S_IMODE((folder / name).stat().st_mode) != 0o600:
                raise OSError("Execution evidence requires private native filesystem permissions")
    return folder


def read_execution_evidence(folder, *, expected_request_id=None):
    """Verify bounded fixed-name artifacts, raw bytes, contracts and identities."""
    folder = Path(folder)
    allowed = {"transport_stdout.bin", "transport_stderr.bin", "transport_result.json",
               "worker_packet.json", "stdout.bin", "stderr.bin", "tool_result.json", "execution_request.json",
               "operator_authorization.json", "preflight_policy.json"}
    def read(name, limit=67108864):
        path = folder / name
        if folder.is_symlink() or path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            raise ValueError("unsafe, missing or oversized execution evidence")
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("oversized execution evidence")
        return raw
    manifest = _load(read("manifest.json", 65536))
    if (manifest.get("evidence_schema_version") != "1.0"
            or manifest.get("candidate_execution_status") != "NOT_EXECUTED"
            or manifest.get("verification_status") != "NOT_VERIFIED"
            or not isinstance(manifest.get("artifacts"), dict)
            or not set(manifest["artifacts"]).issubset(allowed)):
        raise ValueError("invalid execution manifest")
    if expected_request_id is not None and manifest["request_id"] != expected_request_id:
        raise ValueError("execution evidence request mismatch")
    artifacts = {}
    for name, item in manifest["artifacts"].items():
        raw = read(name)
        if len(raw) != item["size_bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("execution artifact digest mismatch")
        artifacts[name] = raw
    request = _load(artifacts["execution_request.json"]) if "execution_request.json" in artifacts else None
    packet = _load(artifacts["worker_packet.json"]) if "worker_packet.json" in artifacts else None
    transport, packet, request = _validate_result(
        {"transport": _load(artifacts["transport_result.json"]), "packet": packet}, request)
    if (transport.record_id != manifest["transport_record_id"]
            or transport.stdout_bytes() != artifacts["transport_stdout.bin"]
            or transport.stderr_bytes() != artifacts["transport_stderr.bin"]
            or manifest["request_id"] != (request.request_id if request else None)
            or manifest["request_sha256"] != (request_sha256(request) if request else None)):
        raise ValueError("execution evidence identity or raw transport mismatch")
    if packet is not None and packet.get("tool_result") is not None:
        tool = ToolResult.model_validate(_load(artifacts["tool_result.json"]))
        if (tool.model_dump(mode="json") != packet["tool_result"]
                or tool.stdout_bytes() != artifacts["stdout.bin"] or tool.stderr_bytes() != artifacts["stderr.bin"]):
            raise ValueError("target tool evidence mismatch")
    if ("operator_authorization.json" in artifacts) != ("preflight_policy.json" in artifacts):
        raise ValueError("operator evidence is incomplete")
    _validate_authority(request,
                        _load(artifacts["operator_authorization.json"]) if "operator_authorization.json" in artifacts else None,
                        _load(artifacts["preflight_policy.json"]) if "preflight_policy.json" in artifacts else None, packet)
    if read("report.md", 65536) != render_execution_report(manifest, packet).encode("utf-8"):
        raise ValueError("deterministic execution report mismatch")
    return {"manifest": manifest, "packet": packet, "transport": transport, "request": request}
