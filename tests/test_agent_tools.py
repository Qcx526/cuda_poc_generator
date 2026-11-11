# -*- coding: utf-8 -*-
"""Tool-level contracts: HTTP truncation/source, shell timeout, registry composition."""

import json

import pytest

import agent.tools_builtin as builtin
from agent.evidence import ArtifactStore, EvidenceLog, Runner
from agent.memory import ResearchMemory
from agent.registry import ToolRegistry, build_registry
from agent.workspace import Workspace


class FakeResponse:
    def __init__(self, body: bytes, status=200, content_type="text/html", url="https://x/y"):
        self._body = body
        self.status = status
        self.headers = {"Content-Type": content_type}
        self._url = url

    def read(self, limit=None):
        return self._body[:limit] if limit else self._body

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture()
def tools(tmp_path):
    log = EvidenceLog(tmp_path / "evidence.jsonl", ArtifactStore(tmp_path / "artifacts"),
                      run_id="run-test")
    runner = Runner(tmp_path / "ws", log)
    return builtin.build_tools(Workspace(tmp_path / "ws"), runner, log,
                               ResearchMemory(tmp_path / "memory.jsonl")), log, tmp_path


def test_http_records_source_and_truncation(tools, monkeypatch):
    specs, log, tmp_path = tools
    http = next(s for s in specs if s["name"] == "http_get")["fn"]
    body = ("<html><body><p>" + "内容" * 4000 + "</p></body></html>").encode("utf-8")
    monkeypatch.setattr(builtin.urllib.request, "urlopen", lambda *a, **k: FakeResponse(body))

    result = http("https://example.test/page", mode="text", limit=500)
    summary = result["summary"]
    assert summary["http_status"] == 200
    assert summary["content_type"] == "text/html"
    assert summary["final_url"] == "https://x/y"
    assert summary["truncated"] is True
    assert summary["bytes"] == len(body)
    assert "html" not in summary["body_preview"]
    artifact = tmp_path / "artifacts" / result["artifacts"][0]["artifact"]
    assert artifact.read_bytes() == body, "raw body must be kept even when text is extracted"


def test_http_json_mode_pretty_prints(tools, monkeypatch):
    specs, _, _ = tools
    http = next(s for s in specs if s["name"] == "http_get")["fn"]
    payload = json.dumps({"cve": "CVE-2026-65160", "cwe": "CWE-369"}).encode("utf-8")
    monkeypatch.setattr(builtin.urllib.request, "urlopen",
                        lambda *a, **k: FakeResponse(payload, content_type="application/json"))
    result = http("https://example.test/cve", mode="json")
    assert "\n" in result["summary"]["body_preview"]
    assert result["summary"]["truncated"] is False


def test_http_failure_is_recorded_not_raised(tools, monkeypatch):
    specs, log, _ = tools
    http = next(s for s in specs if s["name"] == "http_get")["fn"]

    def boom(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(builtin.urllib.request, "urlopen", boom)
    result = http("https://example.test/down")
    assert result["ok"] is False
    assert "connection refused" in result["summary"]["error"]
    assert log.tail(1)[0]["status"] == "failed"


def test_shell_timeout_reaches_runner(tools):
    specs, log, tmp_path = tools
    shell = next(s for s in specs if s["name"] == "shell")["fn"]
    target = tmp_path / "ws" / "sleep.py"
    target.write_text("import time" + chr(10) + "time.sleep(5)" + chr(10), encoding="utf-8")
    result = shell("python sleep.py", timeout=1)
    assert result["ok"] is False
    assert result["status"] == "timeout"
    assert result["timeout_seconds"] == 1


def test_shell_timeout_is_validated(tools):
    specs, _, _ = tools
    shell = next(s for s in specs if s["name"] == "shell")["fn"]
    result = shell("echo hi", timeout=0)
    assert result["timeout_seconds"] == 300, "invalid timeout falls back to the default"


def test_memory_note_requires_evidence_for_findings(tools):
    specs, _, tmp_path = tools
    note = next(s for s in specs if s["name"] == "memory_note")["fn"]
    refused = note("finding", "除零已确认")
    assert refused["ok"] is False
    assert "evidence" in refused["summary"]["error"]
    ok = note("hypothesis", "除零可能在 MCU 计数")
    assert ok["ok"] is True and ok["summary"]["id"]


def test_registry_always_has_builtins(tmp_path):
    log = EvidenceLog(tmp_path / "e.jsonl", ArtifactStore(tmp_path / "a"))
    registry, conflicts = build_registry(Workspace(tmp_path / "ws"), Runner(tmp_path, log),
                                         log, ResearchMemory(tmp_path / "m.jsonl"),
                                         legacy=False)
    assert set(registry.names()) >= {"shell", "fs_list", "fs_read", "fs_write",
                                     "http_get", "env_probe", "memory_note"}
    assert conflicts == []


def test_legacy_tools_add_without_replacing_builtins(tmp_path, monkeypatch):
    import agent.registry as registry_module
    log = EvidenceLog(tmp_path / "e.jsonl", ArtifactStore(tmp_path / "a"))
    monkeypatch.setattr(registry_module, "_legacy_specs", lambda: [
        {"name": "shell", "description": "impostor", "parameters": {}, "fn": lambda: "no"},
        {"name": "legacy_probe", "description": "extra", "parameters": {}, "fn": lambda: 1},
    ])
    registry, conflicts = build_registry(Workspace(tmp_path / "ws"), Runner(tmp_path, log),
                                         log, ResearchMemory(tmp_path / "m.jsonl"),
                                         legacy=True)
    assert conflicts == ["shell"]
    assert registry.get("shell").description.startswith("Run a shell command")
    assert registry.get("legacy_probe") is not None


def test_duplicate_registration_is_refused():
    registry = ToolRegistry()
    spec = {"name": "t", "description": "d", "parameters": {}, "fn": lambda: None}
    registry.register_many([spec])
    with pytest.raises(ValueError):
        registry.register_many([spec])


def test_native_tool_call_is_adapted_to_action(tmp_path):
    from agent.native_tools import NativeActionModel

    class FakeModel:
        def bind_tools(self, tools):
            self.tools = tools
            return self

        def invoke(self, messages):
            class Response:
                content = "调用工具"
                tool_calls = [{"name": "env_probe", "args": {}, "id": "c1", "type": "tool_call"}]
            return Response()

    log = EvidenceLog(tmp_path / "e.jsonl", ArtifactStore(tmp_path / "a"))
    registry, _ = build_registry(Workspace(tmp_path / "ws"), Runner(tmp_path / "ws", log),
                                 log, ResearchMemory(tmp_path / "m.jsonl"))
    action, error, mode = NativeActionModel(FakeModel(), registry).act([])
    assert error == "" and mode == "native"
    assert action["tool"] == "env_probe"


def test_native_adapter_falls_back_to_json(tmp_path):
    from agent.native_tools import NativeActionModel

    class FakeModel:
        def bind_tools(self, tools):
            return self

        def invoke(self, messages):
            class Response:
                content = '{"thought":"t","final":"done"}'
                tool_calls = []
            return Response()

    log = EvidenceLog(tmp_path / "e.jsonl", ArtifactStore(tmp_path / "a"))
    registry, _ = build_registry(Workspace(tmp_path / "ws"), Runner(tmp_path / "ws", log),
                                 log, ResearchMemory(tmp_path / "m.jsonl"))
    action, error, mode = NativeActionModel(FakeModel(), registry).act([])
    assert mode == "json_fallback" and action["final"] == "done"


def test_openai_tool_schema_lists_required_params(tmp_path):
    from agent.native_tools import to_openai_tools

    log = EvidenceLog(tmp_path / "e.jsonl", ArtifactStore(tmp_path / "a"))
    registry, _ = build_registry(Workspace(tmp_path / "ws"), Runner(tmp_path / "ws", log),
                                 log, ResearchMemory(tmp_path / "m.jsonl"))
    tools = {t["function"]["name"]: t["function"] for t in to_openai_tools(registry)}
    assert "command" in tools["shell"]["parameters"]["required"]
