# -*- coding: utf-8 -*-
"""P18 additions: internal TypeError, usage normalisation, observation rendering."""

import json

import pytest

from agent.evidence import ArtifactStore, EvidenceLog, Runner
from agent.memory import ResearchMemory
from agent.registry import Tool, ToolRegistry, build_registry
from agent.runtime import AgentRuntime
from agent.workspace import Workspace
from src.llm_client import _normalise_usage


class ScriptedClient:
    def __init__(self, answers):
        self.answers = list(answers)

    def chat(self, messages, temperature=None, max_tokens=None):
        return self.answers.pop(0) if self.answers else json.dumps(
            {"thought": "done", "final": "stop"})


def test_internal_type_error_is_a_tool_fault_not_a_bad_argument(tmp_path):
    registry = ToolRegistry()

    def broken(**kwargs):
        return "x" + 1          # TypeError raised inside the tool body

    registry.register(Tool(name="broken", description="d", parameters={}, fn=broken))
    outcome = registry.call("broken", {})
    assert outcome["dispatched"] is True
    assert outcome["ok"] is False
    assert "internal fault" in outcome["error"]


def test_bad_argument_is_a_dispatch_error(tmp_path):
    registry = ToolRegistry()
    registry.register(Tool(name="needs_one", description="d",
                           parameters={"x": "str"}, fn=lambda x: x))
    outcome = registry.call("needs_one", {})
    assert outcome["dispatched"] is False
    assert "bad arguments" in outcome["error"]


def test_usage_normalisation_variants():
    assert _normalise_usage({"input_tokens": 3, "output_tokens": 4,
                             "total_tokens": 7}) == {"prompt_tokens": 3,
                                                     "completion_tokens": 4,
                                                     "total_tokens": 7}
    assert _normalise_usage({"prompt_tokens": 2, "completion_tokens": 5})["total_tokens"] == 7
    assert _normalise_usage(None) is None
    assert _normalise_usage({}) is None


def test_observation_rendering_is_tool_aware(tmp_path):
    runtime = AgentRuntime(goal="g", root=tmp_path, client=ScriptedClient([]), max_turns=1)

    search = {"ok": True, "summary": {"results": 1, "items": [
        {"title": "t", "url": "u", "score": 0.9, "content": "c" * 300}]}, "artifacts": []}
    rendered = runtime._render_observation(search, 500)
    assert "results=1" in rendered and "c" * 100 in rendered

    read = {"ok": True, "summary": {"artifact": "http/x.json", "offset": 0,
                                    "has_more": True, "total_bytes": 9000,
                                    "content": "body" * 50}, "artifacts": []}
    rendered = runtime._render_observation(read, 500)
    assert "has_more=True" in rendered and "total=9000" in rendered

    shell = {"ok": False, "summary": {"exit": 1, "timed_out": False,
                                      "stdout": "out", "stderr": "err"}, "artifacts": []}
    rendered = runtime._render_observation(shell, 500)
    assert rendered.startswith("STATUS=failed") and "exit=1" in rendered
