"""WSL receiver for byte staging of one immutable harmless registry action."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import uuid

from .registered_actions import get_registered_action
from .tools.process import canonical_target_environment, current_platform_type


def _start_ticks():
    raw = Path("/proc/self/stat").read_text(encoding="ascii")
    return int(raw.rsplit(") ", 1)[1].split()[19])


def _write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)


def _private_root():
    base = Path.home() / ".local" / "state" / "cuda-poc-generator" / "candidate_transfers"
    current = Path(base.anchor)
    for part in base.parts[1:]:
        current = current / part
        if current.exists() or current.is_symlink():
            if current.is_symlink() or not current.is_dir():
                raise ValueError("candidate transfer root contains a symlink or non-directory component")
        else:
            current.mkdir(mode=0o700)
    base.chmod(0o700)
    return base


def receive_registered_candidate(payload):
    required = {"schema_version", "operation", "request_id", "transfer_id", "action_id", "source_b64", "source_sha256"}
    if type(payload) is not dict or set(payload) != required:
        raise ValueError("candidate transfer request fields do not match schema")
    if payload["schema_version"] != "1.0" or payload["operation"] != "STAGE_REGISTERED_HARMLESS":
        raise ValueError("unsupported candidate transfer operation")
    for name in ("request_id", "transfer_id"):
        if type(payload[name]) is not str or re.fullmatch(r"[0-9a-f]{32}", payload[name]) is None:
            raise ValueError("invalid candidate transfer identity")
    if current_platform_type() != "wsl":
        raise ValueError("candidate transfer receiver is not running in WSL")
    action = get_registered_action(payload["action_id"])
    if payload["action_id"] != "p2b-normal-v1":
        raise ValueError("only the reviewed harmless normal-exit fixture is registered for this adapter")
    if type(payload["source_b64"]) is not str or len(payload["source_b64"]) > 1_500_000:
        raise ValueError("candidate source exceeds transfer limit")
    source = base64.b64decode(payload["source_b64"], validate=True)
    digest = hashlib.sha256(source).hexdigest()
    if digest != payload["source_sha256"] or digest != action.sha256 or source != action.source:
        raise ValueError("transferred bytes do not match the immutable harmless registry action")
    folder = _private_root() / payload["transfer_id"]
    folder.mkdir(mode=0o700, exist_ok=False)
    source_path = folder / "candidate.py"
    _write_new(source_path, source)
    copied = source_path.read_bytes()
    if hashlib.sha256(copied).hexdigest() != digest or copied != source:
        raise ValueError("WSL staged candidate bytes failed independent reread")
    response = {"schema_version": "1.0", "status": "STAGED_AND_VERIFIED", "request_id": payload["request_id"],
        "transfer_id": payload["transfer_id"], "action_id": action.fixture_id, "source_sha256": digest,
        "source_bytes": len(source), "target_environment": canonical_target_environment(),
        "receiver_pid": os.getpid(), "receiver_ppid": os.getppid(), "receiver_uid": os.getuid(),
        "receiver_gid": os.getgid(), "receiver_start_ticks": _start_ticks(),
        "staged_relative_path": "candidate.py", "staged_path": str(source_path),
        "candidate_execution_status": "NOT_EXECUTED", "verification_status": "NOT_VERIFIED"}
    receipt = (json.dumps(response, ensure_ascii=False, sort_keys=True, allow_nan=False, indent=2) + "\n").encode("utf-8")
    _write_new(folder / "transfer_receipt.json", receipt)
    return response


def main(payload, *, project_root=None):
    response = receive_registered_candidate(payload)
    sys.stdout.buffer.write((json.dumps(response, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0
