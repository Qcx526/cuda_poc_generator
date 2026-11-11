# -*- coding: utf-8 -*-
"""Evidence log: one append-only record per action the agent takes.

The rule this file enforces is the one the previous project kept relearning: a claim is
only worth what the harness observed. Every tool call writes what was run, with which
arguments, what came back, and the hash of every file it touched. Nothing is rewritten;
a later correction is a new record that points at the old one.
"""

import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> Optional[str]:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class EvidenceLog:
    """Append-only JSONL beside the workspace."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def record(self, kind: str, payload: dict) -> dict:
        entry = {
            "seq": self._next_seq(),
            "kind": kind,
            "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            **payload,
        }
        entry["record_sha256"] = sha256_bytes(
            json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8"))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def _next_seq(self) -> int:
        return sum(1 for _ in self.path.open(encoding="utf-8")) + 1

    def tail(self, count: int = 10) -> list:
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines[-count:] if line.strip()]


class Runner:
    """Executes a command and captures what actually happened."""

    def __init__(self, workspace: Path, log: EvidenceLog, timeout: int = 300):
        self.workspace = workspace
        self.log = log
        self.timeout = timeout

    def run(self, argv: list, cwd: Optional[Path] = None,
            env_extra: Optional[dict] = None, timeout: Optional[int] = None) -> dict:
        cwd = Path(cwd or self.workspace)
        limit = timeout or self.timeout
        env = dict(os.environ)
        env.update(env_extra or {})
        started = time.time()
        try:
            proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True,
                                  errors="replace", timeout=limit, env=env)
            exit_code, stdout, stderr = proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired as exc:
            exit_code = -9
            stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
            stderr = "timeout after %ds" % limit
        except FileNotFoundError as exc:
            exit_code, stdout, stderr = -2, "", str(exc)

        record = {
            "argv": [str(a) for a in argv],
            "cwd": str(cwd),
            "exit": exit_code,
            "duration_ms": int((time.time() - started) * 1000),
            "stdout": stdout[-8000:],
            "stdout_sha256": sha256_bytes(stdout.encode("utf-8")),
            "stderr": stderr[-4000:],
            "environment": {
                "os": platform.platform(),
                "python": sys.version.split()[0],
                "cwd_entries": sorted(p.name for p in cwd.iterdir())[:40]
                if cwd.is_dir() else [],
            },
        }
        self.log.record("exec", record)
        return record
