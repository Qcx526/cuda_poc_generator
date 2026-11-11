# -*- coding: utf-8 -*-
"""Runtime contract tests.

The model is scripted here on purpose: this tests the loop, the tool dispatch, the
evidence trail and the workspace guard. It does not test any decode verdict - those
still come from real decoders in the JPEG suites.
"""

import json

import pytest

from agent import AgentRuntime
from agent.registry import Tool, ToolRegistry
from agent.workspace import Workspace


class ScriptedClient:
    """Returns canned answers in order, and records the prompts it was given."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.prompts = []

    def chat(self, messages, temperature=None, max_tokens=None):
        self.prompts.append(messages[-1]["content"])
        if not self.answers:
            return json.dumps({"thought": "out of script", "final": "stop"})
        return self.answers.pop(0)


def test_agent_calls_tool_then_finishes(tmp_path):
    client = ScriptedClient([
        json.dumps({"thought": "看看环境", "tool": "env_probe", "args": {}}),
        json.dumps({"thought": "够了", "final": "环境已确认，未做进一步实验。"}),
    ])
    runtime = AgentRuntime(goal="探测环境", root=tmp_path, client=client, max_turns=4)
    result = runtime.run()

    assert result.stopped == "final"
    assert len(result.turns) == 1
    assert result.turns[0].tool == "env_probe"
    assert "os" in result.turns[0].observation
    evidence = (tmp_path / "evidence.jsonl").read_text(encoding="utf-8").splitlines()
    kinds = [json.loads(line)["kind"] for line in evidence]
    assert "start" in kinds and "tool" in kinds and "finish" in kinds


def test_agent_stops_at_turn_budget(tmp_path):
    answers = [json.dumps({"thought": "loop", "tool": "fs_list", "args": {"path": "."}})] * 3
    runtime = AgentRuntime(goal="不会结束", root=tmp_path, client=ScriptedClient(answers),
                           max_turns=3)
    result = runtime.run()
    assert result.stopped == "max_turns"
    assert len(result.turns) == 3
    assert "未在 3 轮内得出结论" in result.final


def test_unknown_tool_is_reported_not_crashing(tmp_path):
    client = ScriptedClient([
        json.dumps({"thought": "乱试", "tool": "no_such_tool", "args": {}}),
        json.dumps({"thought": "结束", "final": "工具不存在"}),
    ])
    result = AgentRuntime(goal="x", root=tmp_path, client=client, max_turns=3).run()
    assert result.turns[0].observation["ok"] is False
    assert "unknown tool" in result.turns[0].observation["error"]


def test_malformed_response_does_not_abort(tmp_path):
    client = ScriptedClient(["这不是 JSON", json.dumps({"thought": "t", "final": "ok"})])
    result = AgentRuntime(goal="x", root=tmp_path, client=client, max_turns=3).run()
    assert result.stopped == "final"
    assert "no tool and no final" in result.turns[0].observation["error"]


def test_memory_is_visible_in_later_prompt(tmp_path):
    client = ScriptedClient([
        json.dumps({"thought": "记一笔", "tool": "memory_note",
                    "args": {"kind": "open", "text": "nvJPEG 版本未知"}}),
        json.dumps({"thought": "结束", "final": "done"}),
    ])
    runtime = AgentRuntime(goal="x", root=tmp_path, client=client, max_turns=3)
    runtime.run()
    assert "nvJPEG 版本未知" in runtime.memory.digest()
    assert "已有记忆" in client.prompts[-1]


def test_workspace_refuses_escape(tmp_path):
    space = Workspace(tmp_path / "ws")
    space.write("ok.txt", "hi")
    assert space.read("ok.txt")["content"] == "hi"
    with pytest.raises(PermissionError):
        space.write("../outside.txt", "nope")


def test_registry_reports_missing_binary():
    registry = ToolRegistry()
    registry.register(Tool(name="ghost", description="needs a binary that is not here",
                           parameters={}, fn=lambda: None, requires=["definitely-not-here"]))
    assert registry.describe()[0]["available"] is False
    outcome = registry.call("ghost", {})
    assert outcome["ok"] is False and "needs" in outcome["error"]
