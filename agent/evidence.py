# -*- coding: utf-8 -*-
"""Evidence: a hash-chained record of what ran, plus the bytes it produced.

Two things the previous version could not do, and both matter for a long run:

* It stored the last few kilobytes of output in the log and threw the rest away. Here the
  full stream goes to ``artifacts/`` with its own hash, and the record keeps a reference
  and a truncation flag, so a prompt can stay small without the evidence going missing.
* It hashed each record on its own. A record could be deleted or reordered and nothing
  would notice. Each record now carries the previous record's hash, and ``verify_chain``
  re-derives the whole chain, so deletion, reordering and edits are all detectable.

A hash chain is tamper *evident*, not tamper *proof*: someone who rewrites the whole file
can rebuild a consistent chain. It protects against accident and casual edits, not against
an adversary with write access.
"""

import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

SCHEMA = "agent-tool-execution/v1"

SECRET_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9]{16,}"), "sk-***REDACTED***"),
    (re.compile(r"(api[_-]?key\s*[=:]\s*[\"']?)[A-Za-z0-9\-_]{12,}", re.I), r"\1***REDACTED***"),
    (re.compile(r"(Authorization:\s*Bearer\s+)[A-Za-z0-9\-_.]{12,}", re.I), r"\1***REDACTED***"),
]

GENESIS = "0" * 64


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> Optional[str]:
    if not Path(path).is_file():
        return None
    return sha256_bytes(Path(path).read_bytes())


def redact(text: str) -> tuple:
    """Return (clean_text, hits). Secrets never reach disk unredacted."""
    hits = 0
    for pattern, replacement in SECRET_PATTERNS:
        text, count = pattern.subn(replacement, text)
        hits += count
    return text, hits


class ArtifactStore:
    """Content-addressed blobs, one file per artifact, referenced from records."""

    def __init__(self, root: Path):
        self.root = Path(root)
        for sub in ("stdout", "stderr", "http", "files"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)

    def save(self, category: str, name: str, payload) -> dict:
        data = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
        digest = sha256_bytes(data)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:80] or "blob"
        path = self.root / category / ("%s-%s" % (digest[:12], safe))
        path.write_bytes(data)
        return {"artifact": str(path.relative_to(self.root)).replace("\\", "/"),
                "sha256": digest, "bytes": len(data)}


class EvidenceLog:
    """Append-only, hash-chained JSONL."""

    def __init__(self, path: Path, artifacts: Optional[ArtifactStore] = None,
                 run_id: str = ""):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.artifacts = artifacts
        self.run_id = run_id
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def _last(self) -> tuple:
        lines = self.path.read_text(encoding="utf-8").splitlines()
        if not lines:
            return 0, GENESIS
        last = json.loads(lines[-1])
        return last.get("sequence", len(lines)), last.get("record_sha256", GENESIS)

    def append(self, kind: str, payload: dict, status: str = "success") -> dict:
        sequence, previous = self._last()
        entry = {
            "schema": SCHEMA,
            "run_id": self.run_id,
            "sequence": sequence + 1,
            "kind": kind,
            "status": status,
            "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "previous_record_sha256": previous,
            **payload,
        }
        # Reserved fields win over payload keys: an HTTP status of None must not erase
        # the record status, and a tool cannot relabel its own execution outcome.
        entry["status"] = status
        entry["kind"] = kind
        entry["sequence"] = sequence + 1
        digest = sha256_bytes(json.dumps(entry, sort_keys=True,
                                         ensure_ascii=False).encode("utf-8"))
        entry["record_sha256"] = digest
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def record(self, kind: str, payload: dict) -> dict:
        """Compatibility alias: older callers use record()."""
        return self.append(kind, payload)

    def tail(self, count: int = 10) -> list:
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines[-count:] if line.strip()]

    def verify(self) -> dict:
        return verify_chain(self.path)


def verify_chain(path: Path) -> dict:
    """Recompute the chain: sequence continuity, previous-hash links, record hashes."""
    path = Path(path)
    if not path.is_file():
        return {"ok": False, "errors": ["evidence log missing"], "records": 0}
    errors = []
    expected_seq, previous = 1, GENESIS
    count = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        count += 1
        try:
            entry = json.loads(raw)
        except ValueError as exc:
            errors.append("record %d: not JSON (%s)" % (count, exc))
            continue
        stored = entry.pop("record_sha256", None)
        if entry.get("sequence") != expected_seq:
            errors.append("record %d: sequence is %r, expected %d"
                          % (count, entry.get("sequence"), expected_seq))
        if entry.get("previous_record_sha256") != previous:
            errors.append("record %d: previous hash does not match the chain" % count)
        recomputed = sha256_bytes(json.dumps(entry, sort_keys=True,
                                             ensure_ascii=False).encode("utf-8"))
        if recomputed != stored:
            errors.append("record %d: content does not match its hash" % count)
        previous = stored or ""
        expected_seq += 1
    return {"ok": not errors, "errors": errors, "records": count,
            "last_record_sha256": previous}


class Runner:
    """Executes a command and captures what actually happened."""

    DEFAULT_TIMEOUT = 300
    MAX_TIMEOUT = 3600

    def __init__(self, workspace: Path, log: EvidenceLog, timeout: int = DEFAULT_TIMEOUT):
        self.workspace = Path(workspace)
        self.log = log
        self.timeout = clamp_timeout(timeout) or self.DEFAULT_TIMEOUT

    def run(self, argv: list, cwd: Optional[Path] = None, env_extra: Optional[dict] = None,
            timeout: Optional[int] = None, label: str = "shell") -> dict:
        limit = clamp_timeout(timeout) or self.timeout
        cwd = Path(cwd or self.workspace)
        env = dict(os.environ)
        env.update(env_extra or {})
        started = time.time()
        timed_out = False
        try:
            proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True,
                                  errors="replace", timeout=limit, env=env)
            exit_code, stdout, stderr = proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = -9
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = "timeout after %ds" % limit
        except FileNotFoundError as exc:
            exit_code, stdout, stderr = -2, "", str(exc)
        stdout, out_hits = redact(stdout)
        stderr, err_hits = redact(stderr)

        artifacts = []
        if self.log.artifacts is not None:
            stamp = time.strftime("%H%M%S")
            artifacts.append(self.log.artifacts.save("stdout", "%s-%s.out" % (label, stamp), stdout))
            artifacts.append(self.log.artifacts.save("stderr", "%s-%s.err" % (label, stamp), stderr))

        status = ("timeout" if timed_out
                  else "success" if exit_code == 0 else "failed")
        record = {
            "tool_name": label,
            "argv": [str(a) for a in argv],
            "cwd": str(cwd),
            "exit": exit_code,
            "duration_ms": int((time.time() - started) * 1000),
            "status": status,
            "timed_out": timed_out,
            "timeout_seconds": limit,
            "stdout_preview": stdout[:2000],
            "stderr_preview": stderr[:1200],
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "truncated": len(stdout) > 2000 or len(stderr) > 1200,
            "redactions": out_hits + err_hits,
            "artifacts": artifacts,
            "environment": {"os": platform.platform(),
                            "python": sys.version.split()[0]},
        }
        return self.log.append("exec", record, status=status)


def clamp_timeout(value) -> Optional[int]:
    """Validate a caller-supplied timeout; None means 'not usable, use default'."""
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    return min(seconds, Runner.MAX_TIMEOUT)
