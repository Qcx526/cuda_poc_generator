# -*- coding: utf-8 -*-
"""Builtin tools: the minimum an agent needs to start investigating.

Each tool returns a dict with the same shape - ``ok``, a short ``summary`` for the prompt,
and ``artifacts`` pointing at full output - so one record format covers every call.
"""

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from .evidence import clamp_timeout, redact, sha256_bytes

TEXT_TYPES = ("application/json", "text/plain", "text/html", "application/xml",
              "text/xml", "text/markdown")


def build_tools(workspace, runner, log, memory):
    artifacts = log.artifacts

    def shell(command: str, timeout: int = 300) -> dict:
        seconds = clamp_timeout(timeout) or 300
        record = runner.run(["cmd", "/c", command] if _is_windows() else ["sh", "-c", command],
                            timeout=seconds, label="shell")
        return {"ok": record["exit"] == 0 and not record["timed_out"],
                "summary": {"exit": record["exit"], "timed_out": record["timed_out"],
                            "stdout": record["stdout_preview"][:1500],
                            "stderr": record["stderr_preview"][:800]},
                "status": record["status"], "artifacts": record["artifacts"],
                "timeout_seconds": record["timeout_seconds"]}

    def fs_list(path: str = ".") -> dict:
        listing = workspace.listdir(path)
        return {"ok": True, "summary": listing, "artifacts": []}

    def fs_read(path: str) -> dict:
        content = workspace.read(path)
        ref = artifacts.save("files", Path(path).name, content["content"]) if artifacts else None
        return {"ok": True,
                "summary": {"path": content["path"], "bytes": content["bytes"],
                            "truncated": content["truncated"],
                            "content": content["content"][:4000]},
                "artifacts": [ref] if ref else []}

    def fs_write(path: str, content: str) -> dict:
        written = workspace.write(path, content)
        ref = artifacts.save("files", Path(path).name, content) if artifacts else None
        return {"ok": True, "summary": written, "artifacts": [ref] if ref else []}

    def http_get(url: str, mode: str = "text", limit: int = 4000, timeout: int = 30) -> dict:
        """mode: text (tags stripped), json (parsed + pretty), raw (untouched)."""
        request = urllib.request.Request(url, headers={"User-Agent": "agent/1.0"})
        try:
            with urllib.request.urlopen(request, timeout=clamp_timeout(timeout) or 30) as resp:
                status = getattr(resp, "status", None)
                content_type = resp.headers.get("Content-Type", "")
                final_url = resp.geturl()
                body = resp.read(4 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            body = exc.read()[:2000]
            entry = {"url": url, "http_status": exc.code, "error": str(exc),
                     "bytes": len(body)}
            log.append("http", entry, status="failed")
            return {"ok": False, "summary": entry, "artifacts": []}
        except Exception as exc:  # noqa: BLE001 - network failure is an observation
            entry = {"url": url, "http_status": None,
                     "error": "%s: %s" % (type(exc).__name__, exc)}
            log.append("http", entry, status="failed")
            return {"ok": False, "summary": entry, "artifacts": []}

        text = body.decode("utf-8", errors="replace")
        text, hits = redact(text)
        digest = sha256_bytes(body)
        ref = artifacts.save("http", _slug(url), body) if artifacts else None
        extracted = text
        if mode == "json":
            try:
                extracted = json.dumps(json.loads(text), ensure_ascii=False, indent=1)
            except ValueError:
                extracted = text
        elif mode == "text" and "html" in content_type.lower():
            extracted = _strip_html(text)

        truncated = len(extracted) > limit
        summary = {"url": url, "final_url": final_url, "http_status": status,
                   "content_type": content_type, "bytes": len(body), "sha256": digest,
                   "mode": mode, "truncated": truncated, "redactions": hits,
                   "body_preview": extracted[:limit]}
        log.append("http", {k: v for k, v in summary.items() if k != "body_preview"},
                   status="success")
        return {"ok": 200 <= (status or 0) < 400, "summary": summary,
                "artifacts": [ref] if ref else []}

    def env_probe() -> dict:
        probes = {
            "os": ("cmd", "/c", "ver") if _is_windows() else ("sh", "-c", "uname -a"),
            "python": ("python", "--version"),
            "gpu": ("nvidia-smi", "--query-gpu=name,driver_version,memory.total",
                    "--format=csv,noheader"),
            "docker": ("docker", "--version"),
        }
        found, refs = {}, []
        for name, argv in probes.items():
            record = runner.run(list(argv), timeout=30, label="env_" + name)
            found[name] = {"exit": record["exit"],
                           "stdout": record["stdout_preview"][:300],
                           "stderr": record["stderr_preview"][:160]}
            refs.extend(record["artifacts"])
        return {"ok": True, "summary": found, "artifacts": refs}

    def artifact_read(artifact: str, offset: int = 0, limit: int = 4000) -> dict:
        """Read part of a stored artifact. Never writes, never leaves the artifact root."""
        root = artifacts.root.resolve() if artifacts else None
        if root is None:
            return {"ok": False, "summary": {"error": "no artifact store"},
                    "artifacts": [], "status": "failed"}
        candidate = (root / artifact).resolve()
        if root not in candidate.parents and candidate != root:
            return {"ok": False, "summary": {"error": "artifact path escapes the run",
                                             "artifact": artifact},
                    "artifacts": [], "status": "failed"}
        if not candidate.is_file():
            return {"ok": False, "summary": {"error": "artifact not found",
                                             "artifact": artifact},
                    "artifacts": [], "status": "failed"}
        try:
            start = max(0, int(offset))
            span = max(1, min(int(limit), 64000))
        except (TypeError, ValueError):
            return {"ok": False, "summary": {"error": "offset/limit must be integers"},
                    "artifacts": [], "status": "failed"}
        data = candidate.read_bytes()
        chunk = data[start:start + span]
        text = chunk.decode("utf-8", errors="replace")
        end = start + len(chunk)
        summary = {"artifact": artifact, "total_bytes": len(data), "offset": start,
                   "read_bytes": len(chunk), "next_offset": end,
                   "has_more": end < len(data),
                   "truncated": len(text) < len(chunk), "content": text}
        return {"ok": True, "summary": summary, "artifacts": [],
                "status": "success" if not summary["has_more"] else "partial"}

    def memory_note(kind: str, text: str, tags: list = None, evidence: list = None) -> dict:
        try:
            entry = memory.add(kind, text, tags=tags, evidence=evidence, source="agent")
        except ValueError as exc:
            return {"ok": False, "summary": {"error": str(exc)}, "artifacts": []}
        return {"ok": True, "summary": {"id": entry["id"], "type": entry["type"]},
                "artifacts": []}

    return [
        {"name": "shell", "fn": shell, "category": "execution", "source": "builtin",
         "description": "Run a shell command in the workspace. Full output is saved as an "
                        "artifact; the reply carries a preview and the exit status.",
         "parameters": {"command": "str", "timeout": "int(1..3600)"}},
        {"name": "fs_list", "fn": fs_list, "category": "files", "source": "builtin",
         "description": "List a directory in the workspace.",
         "parameters": {"path": "str"}},
        {"name": "fs_read", "fn": fs_read, "category": "files", "source": "builtin",
         "description": "Read a text file from the workspace; full content is also stored.",
         "parameters": {"path": "str"}},
        {"name": "fs_write", "fn": fs_write, "category": "files", "source": "builtin",
         "description": "Write a text file into the workspace.",
         "parameters": {"path": "str", "content": "str"}},
        {"name": "http_get", "fn": http_get, "category": "research", "source": "builtin",
         "description": "Fetch a URL. mode=text strips HTML, mode=json pretty-prints, "
                        "mode=raw keeps the body. Records status, content-type, final URL, "
                        "length, sha256 and whether the preview was truncated.",
         "parameters": {"url": "str", "mode": "text|json|raw", "limit": "int",
                        "timeout": "int"}},
        {"name": "artifact_read", "fn": artifact_read, "category": "files",
         "source": "builtin",
         "description": "Read a stored artifact in chunks by its reference (e.g. "
                        "'http/ab12cd34ef56-page.body'). Returns total size, bytes read "
                        "and whether more remains.",
         "parameters": {"artifact": "str", "offset": "int", "limit": "int"}},
        {"name": "env_probe", "fn": env_probe, "category": "research", "source": "builtin",
         "description": "Report OS, python, GPU/driver and docker as they really are.",
         "parameters": {}},
        {"name": "memory_note", "fn": memory_note, "category": "memory", "source": "builtin",
         "description": "Record attempt/finding/hypothesis/failed/open. A finding needs "
                        "evidence ids; otherwise use hypothesis.",
         "parameters": {"kind": "attempt|finding|hypothesis|failed|open", "text": "str",
                        "tags": "list", "evidence": "list"}},
    ]


def _strip_html(text: str) -> str:
    """Remove tags and scripts. The raw body stays in the artifact either way."""
    import re
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _slug(url: str) -> str:
    import re
    tail = re.sub(r"[^A-Za-z0-9]+", "-", url.split("//")[-1])[:60]
    return (tail or "response") + ".body"


def _is_windows() -> bool:
    return os.name == "nt"
