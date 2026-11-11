# -*- coding: utf-8 -*-
"""Tool result contract: dispatch failure, operation failure and success must not blur.

Three layers see the same fact and must agree: the registry envelope, the runtime turn
and the evidence record. Each case below asserts all three, because the original defect
was exactly that they disagreed - a shell exiting 1 looked like success everywhere.
"""

import json

import pytest

import agent.tavily_provider as provider
import agent.tools_builtin as builtin
from agent.evidence import ArtifactStore, EvidenceLog, Runner
from agent.memory import ResearchMemory
from agent.registry import Tool, ToolRegistry, build_registry
from agent.runtime import AgentRuntime
from agent.workspace import Workspace


class ScriptedClient:
    def __init__(self, answers):
        self.answers = list(answers)

    def chat(self, messages, temperature=None, max_tokens=None):
        return self.answers.pop(0) if self.answers else json.dumps(
            {"thought": "done", "final": "stop"})


class FakeTavily:
    def __init__(self, payload=None, error=None):
        self.payload, self.error = payload, error

    def search(self, **kwargs):
        if self.error:
            raise self.error
        return self.payload

    def extract(self, urls):
        if self.error:
            raise self.error
        return self.payload


def build(tmp_path, search=False):
    log = EvidenceLog(tmp_path / "evidence.jsonl", ArtifactStore(tmp_path / "artifacts"),
                      run_id="run-contract")
    registry, _, _ = build_registry(Workspace(tmp_path / "ws"), Runner(tmp_path / "ws", log),
                                    log, ResearchMemory(tmp_path / "m.jsonl"), search=search)
    return registry, log


def run_one(tmp_path, tool, args):
    """Run a single tool through the runtime so all three layers are exercised."""
    client = ScriptedClient([
        json.dumps({"thought": "try", "tool": tool, "args": args}),
        json.dumps({"thought": "stop", "final": "done"}),
    ])
    runtime = AgentRuntime(goal="contract", root=tmp_path, client=client, max_turns=2,
                           search=False)
    result = runtime.run()
    record = [json.loads(line) for line in
              (tmp_path / "evidence.jsonl").read_text(encoding="utf-8").splitlines()]
    tool_records = [r for r in record if r["kind"] == "tool"]
    return result, tool_records[-1], runtime


def test_shell_nonzero_exit_is_a_failure(tmp_path):
    result, record, _ = run_one(tmp_path, "shell", {"command": "exit 1"})
    turn = result.turns[0]
    assert turn.dispatched is True
    assert turn.operation_ok is False
    assert turn.status == "failed"
    assert record["status"] == "failed" and record["dispatched"] is True
    assert record["operation_ok"] is False
    assert record["artifacts"], "stdout/stderr must still be archived on failure"


def test_http_500_is_a_failure_with_body_kept(tmp_path, monkeypatch):
    log = EvidenceLog(tmp_path / "evidence.jsonl", ArtifactStore(tmp_path / "artifacts"))
    registry, _, _ = build_registry(Workspace(tmp_path / "ws"), Runner(tmp_path / "ws", log),
                                    log, ResearchMemory(tmp_path / "m.jsonl"), search=False)

    def boom(request, timeout=None):
        raise builtin.urllib.error.HTTPError("https://x/y", 500, "Server Error", {},
                                             None)

    monkeypatch.setattr(builtin.urllib.request, "urlopen", boom)
    envelope = registry.call("http_get", {"url": "https://x/y"})
    assert envelope["dispatched"] is True
    assert envelope["ok"] is False
    assert envelope["summary"]["http_status"] == 500
    assert log.tail(1)[0]["status"] == "failed"


def test_tavily_401_is_a_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test")
    monkeypatch.setattr(provider, "_client", lambda: FakeTavily(error=RuntimeError("401")))
    registry, log = build(tmp_path, search=True)
    envelope = registry.call("web_search", {"query": "nvidia advisory"})
    assert envelope["dispatched"] is True and envelope["ok"] is False
    assert "401" in envelope["summary"]["error"]
    assert log.tail(1)[0]["status"] == "failed"


def test_tavily_search_success_carries_content(tmp_path, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test")
    payload = {"results": [{"title": "NVIDIA bulletin", "url": "https://nvd.nist.gov/x",
                            "score": 0.88, "content": "A" * 900}]}
    monkeypatch.setattr(provider, "_client", lambda: FakeTavily(payload=payload))
    registry, _ = build(tmp_path, search=True)
    envelope = registry.call("web_search", {"query": "CVE-2026-65160", "max_results": 3})
    item = envelope["summary"]["items"][0]
    assert envelope["ok"] is True and envelope["status"] == "success"
    assert item["content"] and len(item["content"]) == provider.SEARCH_SNIPPET_CHARS
    assert item["content_truncated"] is True
    assert item["score"] == 0.88


def test_tavily_empty_results_is_not_a_hit(tmp_path, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test")
    monkeypatch.setattr(provider, "_client", lambda: FakeTavily(payload={"results": []}))
    registry, _ = build(tmp_path, search=True)
    envelope = registry.call("web_search", {"query": "nothing"})
    assert envelope["ok"] is True
    assert envelope["status"] == "empty"
    assert envelope["summary"]["items"] == []


def test_search_argument_validation(tmp_path, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test")
    registry, _ = build(tmp_path, search=True)
    assert registry.call("web_search", {"query": "x", "max_results": 0})["ok"] is False
    assert registry.call("web_search", {"query": "x", "max_results": 99})["ok"] is False
    assert registry.call("web_search", {"query": "x", "search_depth": "deep"})["ok"] is False


def test_extract_empty_body_is_a_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test")
    payload = {"results": [{"url": "https://x", "raw_content": ""}], "failed_results": []}
    monkeypatch.setattr(provider, "_client", lambda: FakeTavily(payload=payload))
    registry, log = build(tmp_path, search=True)
    envelope = registry.call("web_extract", {"url": "https://x"})
    assert envelope["ok"] is False and envelope["status"] == "failed"
    assert "empty" in envelope["summary"]["error"]
    assert log.tail(1)[0]["artifacts"], "raw response is still archived on failure"


def test_extract_partial_when_some_urls_fail(tmp_path, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test")
    payload = {"results": [{"url": "https://x", "raw_content": "body"}],
               "failed_results": [{"url": "https://y", "error": "timeout"}]}
    monkeypatch.setattr(provider, "_client", lambda: FakeTavily(payload=payload))
    registry, _ = build(tmp_path, search=True)
    envelope = registry.call("web_extract", {"url": "https://x"})
    assert envelope["ok"] is True and envelope["status"] == "partial"
    assert envelope["summary"]["failed_results"]


def test_unknown_tool_is_a_dispatch_error(tmp_path):
    registry, log = build(tmp_path)
    envelope = registry.call("no_such_tool", {})
    assert envelope["dispatched"] is False and envelope["ok"] is False
    assert envelope["status"] == "dispatch_error"
    assert "unknown tool" in envelope["error"]


def test_bad_arguments_are_a_dispatch_error(tmp_path):
    registry, _ = build(tmp_path)
    envelope = registry.call("fs_read", {"wrong": "kwarg"})
    assert envelope["dispatched"] is False
    assert "bad arguments" in envelope["error"]


def test_legacy_tool_returning_plain_object_is_success(tmp_path):
    registry = ToolRegistry()
    registry.register(Tool(name="legacy", description="old style", parameters={},
                           fn=lambda: {"value": 42}))
    envelope = registry.call("legacy", {})
    assert envelope["dispatched"] is True and envelope["ok"] is True
    assert envelope["result"] == {"value": 42}


def test_artifact_read_chunks_and_stays_inside_the_run(tmp_path):
    registry, log = build(tmp_path)
    body = "".join("line %05d\n" % i for i in range(500))
    ref = log.artifacts.save("http", "page.body", body)

    first = registry.call("artifact_read", {"artifact": ref["artifact"], "limit": 100})
    assert first["ok"] is True and first["status"] == "partial"
    assert first["summary"]["has_more"] is True
    assert first["summary"]["total_bytes"] == len(body.encode("utf-8"))

    second = registry.call("artifact_read", {"artifact": ref["artifact"],
                                             "offset": first["summary"]["next_offset"],
                                             "limit": 100})
    assert second["summary"]["offset"] == 100

    escape = registry.call("artifact_read", {"artifact": "../../../etc/passwd"})
    assert escape["ok"] is False and "escapes" in escape["summary"]["error"]
