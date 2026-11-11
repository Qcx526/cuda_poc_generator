# -*- coding: utf-8 -*-
"""Builtin tools: the minimum an agent needs to start investigating.

Deliberately small. Anything more specific - JPEG construction, ELF mutation, a probe
binary - is either a legacy adapter or something the agent writes itself, because a
runtime that ships its conclusions as tools is a pipeline wearing a costume.
"""

import json
import subprocess
import urllib.request
from pathlib import Path


def build_tools(workspace, runner, log):
    def shell(command: str, timeout: int = 300) -> dict:
        """Run a shell command inside the workspace and return what it printed."""
        record = runner.run(["cmd", "/c", command] if _is_windows() else ["sh", "-c", command])
        return {"exit": record["exit"], "stdout": record["stdout"][-4000:],
                "stderr": record["stderr"][-2000:]}

    def fs_list(path: str = ".") -> dict:
        return workspace.listdir(path)

    def fs_read(path: str) -> dict:
        return workspace.read(path)

    def fs_write(path: str, content: str) -> dict:
        return workspace.write(path, content)

    def http_get(url: str, limit: int = 6000) -> dict:
        request = urllib.request.Request(url, headers={"User-Agent": "agent/1.0"})
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read(800000).decode("utf-8", errors="replace")
        log.record("http", {"url": url, "bytes": len(body)})
        return {"url": url, "status": getattr(response, "status", None),
                "content": body[:limit]}

    def memory_note(kind: str, text: str) -> dict:
        return {"recorded": log.record("note", {"kind": kind, "text": text})["seq"]}

    def env_probe() -> dict:
        """What this machine actually has, so the agent stops guessing versions."""
        probes = {
            "os": ("cmd", "/c", "ver") if _is_windows() else ("sh", "-c", "uname -a"),
            "python": ("python", "--version"),
            "gpu": ("nvidia-smi", "--query-gpu=name,driver_version,memory.total",
                    "--format=csv,noheader"),
            "docker": ("docker", "--version"),
        }
        found = {}
        for name, argv in probes.items():
            record = runner.run(list(argv), timeout=30)
            found[name] = {"exit": record["exit"], "stdout": record["stdout"].strip()[:400],
                           "stderr": record["stderr"].strip()[:200]}
        return found

    return [
        {"name": "shell", "fn": shell, "category": "execution", "source": "builtin",
         "description": "Run a shell command in the workspace. Use it for compilers, "
                        "probes, docker, or anything you write yourself.",
         "parameters": {"command": "str", "timeout": "int"}},
        {"name": "fs_list", "fn": fs_list, "category": "files", "source": "builtin",
         "description": "List a directory in the workspace.",
         "parameters": {"path": "str"}},
        {"name": "fs_read", "fn": fs_read, "category": "files", "source": "builtin",
         "description": "Read a text file from the workspace.",
         "parameters": {"path": "str"}},
        {"name": "fs_write", "fn": fs_write, "category": "files", "source": "builtin",
         "description": "Write a text file into the workspace.",
         "parameters": {"path": "str", "content": "str"}},
        {"name": "http_get", "fn": http_get, "category": "research", "source": "builtin",
         "description": "Fetch a URL and return its body as text. Use for advisories and docs.",
         "parameters": {"url": "str", "limit": "int"}},
        {"name": "env_probe", "fn": env_probe, "category": "research", "source": "builtin",
         "description": "Report OS, python, GPU/driver and docker as they really are on this host.",
         "parameters": {}},
        {"name": "memory_note", "fn": memory_note, "category": "memory", "source": "builtin",
         "description": "Record a finding, a failed attempt, or an open question for later turns.",
         "parameters": {"kind": "str", "text": "str"}},
    ]


def _is_windows() -> bool:
    import os
    return os.name == "nt"
