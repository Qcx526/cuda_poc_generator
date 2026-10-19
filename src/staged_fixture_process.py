"""Execute the exact received bytes of one frozen harmless Python fixture.

This is an internal, authorized lifecycle adapter, not an arbitrary source or
argv interface.  Source bytes are obtained from a pinned transfer file FD and
verified again by the child before compilation.  No registry source is executed
as a substitute for the received file.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from .registered_actions import get_registered_action


ACTION_ID = "p2b-normal-v1"
_MAX_SOURCE_BYTES = 1048576
_IDENTITY_FIELDS = ("device", "inode", "uid", "gid", "mode", "nlink", "size_bytes", "mtime_ns", "ctime_ns")


def _transfer_root():
    return Path.home() / ".local" / "state" / "cuda-poc-generator" / "candidate_transfers"


def _identifier(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value) is not None


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _identity(info):
    return dict(zip(_IDENTITY_FIELDS, (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
        stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)))


def _decode_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate field in staged transfer receipt")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite staged receipt value")))


def _receipt(value):
    from .candidate_adapter import CandidateTransferReceipt
    model = CandidateTransferReceipt.model_validate(
        value.model_dump(mode="python") if isinstance(value, CandidateTransferReceipt) else value)
    return model.model_dump(mode="json")


def _open_directory_path(path):
    """Open every directory component without following a symlink."""
    selected = Path(path)
    if not selected.is_absolute() or ".." in selected.parts:
        raise ValueError("staged transfer root must be an absolute normalized path")
    descriptor = os.open(selected.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in selected.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_fd
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _private_directory(descriptor):
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("staged transfer directory is not private to the trusted worker")


def _protected_file(descriptor):
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise ValueError("staged transfer file is not a private, singly linked regular file")
    return info


def _read_protected(descriptor, maximum):
    before = _protected_file(descriptor)
    if not 0 < before.st_size <= maximum:
        raise ValueError("staged transfer file has an unsupported length")
    raw = os.pread(descriptor, maximum + 1, 0)
    after = _protected_file(descriptor)
    if _identity(before) != _identity(after) or len(raw) != before.st_size:
        raise ValueError("staged transfer file changed during identity measurement")
    return raw, _identity(after)


@dataclass(frozen=True)
class _StagedHarmlessPlan:
    """Internal file-descriptor capability; constructed by verified receipt intake."""

    source_fd: int
    source_observation: dict

    def expected_proof(self, *, request_id, run_id, nonce, pid):
        return {"event": "STAGED_SOURCE_READY", "request_id": request_id, "run_id": run_id,
            "nonce": nonce, "pid": pid, "source_fd": self.source_fd, **self.source_observation}

    def bootstrap(self, *, control_fd, limits, request_id, run_id, nonce):
        """The only executable text passed with -c is this fixed intake guard."""
        config = {"source_fd": self.source_fd, "control_fd": control_fd,
            "observation": self.source_observation, "request_id": request_id, "run_id": run_id,
            "nonce": nonce, "parent_pid": os.getpid(),
            "cpu_seconds": limits.cpu_seconds, "memory_bytes": limits.memory_bytes}
        return _BOOTSTRAP + "\n_staged_main(" + repr(config) + ")\n"

    def verify_proof(self, proof, *, request_id, run_id, nonce, pid):
        if proof != self.expected_proof(request_id=request_id, run_id=run_id, nonce=nonce, pid=pid):
            raise ValueError("staged child proof differs from the exact received file identity")
        # The child has already read and hash-checked the immutable bytes that it
        # will compile. This is an additional independent FD identity observation.
        current = os.stat(f"/proc/{pid}/fd/{self.source_fd}")
        expected = self.source_observation
        if any(_identity(current)[field] != expected[field] for field in _IDENTITY_FIELDS):
            raise ValueError("staged child FD no longer identifies the authorized source file")


_BOOTSTRAP = r'''def _staged_main(cfg):
    import ctypes, hashlib, json, os, resource, signal, socket, stat
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "staged PR_SET_PDEATHSIG failed")
    parent_death_signal = ctypes.c_int()
    if (libc.prctl(2, ctypes.byref(parent_death_signal), 0, 0, 0) != 0
            or parent_death_signal.value != signal.SIGKILL
            or os.getppid() != cfg["parent_pid"]):
        raise RuntimeError("staged parent death protection was not confirmed")
    resource.setrlimit(resource.RLIMIT_CPU, (cfg["cpu_seconds"],) * 2)
    resource.setrlimit(resource.RLIMIT_AS, (cfg["memory_bytes"],) * 2)
    fd, expected = cfg["source_fd"], cfg["observation"]
    def identity(info):
        return {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
            "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode), "nlink": info.st_nlink,
            "size_bytes": info.st_size, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
            or not 0 < before.st_size <= 1048576):
        raise ValueError("received source FD is not a protected regular file")
    raw = os.pread(fd, 1048577, 0)
    after = os.fstat(fd)
    observed = identity(after)
    if (identity(before) != observed or len(raw) != before.st_size
            or any(observed[k] != expected[k] for k in observed)
            or hashlib.sha256(raw).hexdigest() != expected["source_sha256"]):
        raise ValueError("received source changed or differs from its authorized bytes")
    proof = {"event": "STAGED_SOURCE_READY", "request_id": cfg["request_id"],
        "run_id": cfg["run_id"], "nonce": cfg["nonce"], "pid": os.getpid(),
        "source_fd": fd, **expected}
    channel = socket.socket(fileno=cfg["control_fd"])
    channel.sendall((json.dumps(proof, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
    channel.detach()
    # Keep the source FD alive through RESOURCE_READY so the trusted parent can
    # independently inspect /proc/<pid>/fd. raw is immutable and is the sole code
    # input: neither registry source nor a later path reopening is used.
    namespace = {"__name__": "__main__", "__file__": expected["source_path"]}
    exec(compile(raw, expected["source_path"], "exec"), namespace)
'''


@contextmanager
def _open_staged_fixture(receipt, receipt_sha256):
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise ValueError("fixed staged fixture intake requires Linux descriptor semantics")
    if not _digest(receipt_sha256):
        raise ValueError("staged receipt SHA-256 is required")
    record = _receipt(receipt)
    from .tools.process import canonical_target_environment
    if record["target_environment"] != canonical_target_environment():
        raise ValueError("staged receipt belongs to a different target environment")
    if not _identifier(record["transfer_id"]) or record["action_id"] != ACTION_ID:
        raise ValueError("only the frozen harmless normal fixture may use staged execution")
    root = _transfer_root()
    folder = root / record["transfer_id"]
    source_path = folder / "candidate.py"
    if record["staged_path"] != str(source_path):
        raise ValueError("receipt source path is not the fixed transfer destination")
    root_fd = folder_fd = receipt_fd = source_fd = None
    try:
        root_fd = _open_directory_path(root)
        _private_directory(root_fd)
        folder_fd = os.open(record["transfer_id"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_fd)
        _private_directory(folder_fd)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        receipt_fd = os.open("transfer_receipt.json", flags, dir_fd=folder_fd)
        receipt_raw, _ = _read_protected(receipt_fd, 65536)
        if hashlib.sha256(receipt_raw).hexdigest() != receipt_sha256 or _decode_json(receipt_raw) != record:
            raise ValueError("staged receipt bytes do not bind this exact transfer")
        if record["receiver_uid"] != os.getuid() or record["receiver_gid"] != os.getgid():
            raise ValueError("staged transfer was received under a different OS identity")
        source_fd = os.open("candidate.py", flags, dir_fd=folder_fd)
        raw, identity = _read_protected(source_fd, _MAX_SOURCE_BYTES)
        digest = hashlib.sha256(raw).hexdigest()
        action = get_registered_action(ACTION_ID)
        if (digest != record["source_sha256"] or digest != action.sha256
                or len(raw) != record["source_bytes"]):
            raise ValueError("staged bytes do not match the authorized frozen harmless fixture")
        observation = {**identity, "source_path": str(source_path), "source_sha256": digest,
            "receipt_sha256": receipt_sha256, "transfer_id": record["transfer_id"],
            "transfer_request_id": record["request_id"], "action_id": ACTION_ID}
        yield _StagedHarmlessPlan(source_fd=source_fd, source_observation=observation)
    finally:
        for descriptor in (source_fd, receipt_fd, folder_fd, root_fd):
            if descriptor is not None:
                os.close(descriptor)


def inspect_staged_fixture(receipt, receipt_sha256):
    """Read and identify the fixed staged file; never launch a process."""
    with _open_staged_fixture(receipt, receipt_sha256) as plan:
        return dict(plan.source_observation)


def run_staged_fixture(receipt, receipt_sha256, limits, *, expected_source_identity,
        expected_tool, cwd, target_environment, request_id, run_id, nonce,
        cancellation_file=None, on_event=None):
    """Internal adapter; the caller must independently authorize and preflight."""
    from .lifecycle_process import _run_controlled_action
    with _open_staged_fixture(receipt, receipt_sha256) as plan:
        if type(expected_source_identity) is not dict or plan.source_observation != expected_source_identity:
            raise ValueError("staged source identity changed after execution admission")
        if Path(cwd) != Path(plan.source_observation["source_path"]).parent:
            raise ValueError("staged fixture cwd must be its private receiving directory")
        return _run_controlled_action(get_registered_action(ACTION_ID), limits,
            expected_tool=expected_tool, cwd=cwd, target_environment=target_environment,
            request_id=request_id, run_id=run_id, nonce=nonce, cancellation_file=cancellation_file,
            on_event=on_event, staged_plan=plan)
