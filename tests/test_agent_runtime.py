# -*- coding: utf-8 -*-
"""Runtime contract tests: schema, dispatch, evidence, memory, resume.

The model is scripted here on purpose - this tests the loop and the records, not any
decode verdict. Decode verdicts still come from real decoders in the JPEG suites.
"""

import json

import pytest

from agent import AgentRuntime
from agent.runtime import RuntimeError_, parse_action


class ScriptedClient:
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
    result = AgentRuntime(goal="探测环境", root=tmp_path, client=client, max_turns=4).run()

    assert result.stopped == "final"
    assert len(result.turns) == 1
    assert result.turns[0].tool == "env_probe"
    assert "os" in result.turns[0].observation["summary"]

    kinds = [json.loads(line)["kind"]
             for line in (tmp_path / "evidence.jsonl").read_text(encoding="utf-8").splitlines()]
    assert kinds[0] == "start" and "tool" in kinds and kinds[-1] == "finish"


def test_agent_stops_at_turn_budget(tmp_path):
    answers = [json.dumps({"thought": "loop", "tool": "fs_list", "args": {"path": "."}})] * 3
    result = AgentRuntime(goal="不会结束", root=tmp_path, client=ScriptedClient(answers),
                          max_turns=3).run()
    assert result.stopped == "max_turns"
    assert len(result.turns) == 3
    assert "未在 3 轮内得出结论" in result.final


def test_unknown_tool_is_rejected_by_schema(tmp_path):
    client = ScriptedClient([
        json.dumps({"thought": "乱试", "tool": "no_such_tool", "args": {}}),
        json.dumps({"thought": "结束", "final": "工具不存在"}),
    ])
    result = AgentRuntime(goal="x", root=tmp_path, client=client, max_turns=3).run()
    assert result.turns[0].status == "invalid"
    assert "unknown tool" in result.turns[0].observation["error"]


def test_malformed_response_does_not_abort(tmp_path):
    client = ScriptedClient(["这不是 JSON", json.dumps({"thought": "t", "final": "ok"})])
    result = AgentRuntime(goal="x", root=tmp_path, client=client, max_turns=3).run()
    assert result.stopped == "final"
    assert result.turns[0].status == "invalid"
    assert "no JSON object" in result.turns[0].observation["error"]


def test_memory_is_visible_in_later_prompt(tmp_path):
    client = ScriptedClient([
        json.dumps({"thought": "记一笔", "tool": "memory_note",
                    "args": {"kind": "open", "text": "nvJPEG 版本未知"}}),
        json.dumps({"thought": "结束", "final": "done"}),
    ])
    runtime = AgentRuntime(goal="x", root=tmp_path, client=client, max_turns=3)
    runtime.run()
    assert "nvJPEG 版本未知" in runtime.memory.digest()
    assert "相关记忆" in client.prompts[-1]
    assert "nvJPEG 版本未知" in client.prompts[-1]


def test_workspace_refuses_escape(tmp_path):
    runtime = AgentRuntime(goal="x", root=tmp_path, client=ScriptedClient([]), max_turns=1)
    runtime.workspace.write("ok.txt", "hi")
    assert runtime.workspace.read("ok.txt")["content"] == "hi"
    with pytest.raises(PermissionError):
        runtime.workspace.write("../outside.txt", "nope")


def test_parse_action_requires_exactly_one_of_tool_and_final():
    _, error = parse_action('{"thought":"a","tool":"shell","final":"b"}', ["shell"])
    assert "exactly one" in error
    _, error = parse_action('{"thought":"a"}', ["shell"])
    assert "exactly one" in error


def test_parse_action_rejects_unknown_fields_and_bad_args():
    _, error = parse_action('{"thought":"a","tool":"shell","args":{},"extra":1}', ["shell"])
    assert "unknown fields" in error
    _, error = parse_action('{"thought":"a","tool":"shell","args":"not an object"}', ["shell"])
    assert "args must be" in error
    _, error = parse_action('{"thought":5,"tool":"shell","args":{}}', ["shell"])
    assert "thought must be" in error


def test_parse_action_accepts_fenced_json():
    action, error = parse_action('```json\n{"thought":"t","tool":"shell","args":{"command":"echo hi"}}\n```',
                                 ["shell"])
    assert error == "" and action["tool"] == "shell"


def test_new_run_refuses_to_overwrite_existing(tmp_path):
    AgentRuntime(goal="第一个目标", root=tmp_path, client=ScriptedClient([]), max_turns=1)
    with pytest.raises(RuntimeError_):
        AgentRuntime(goal="另一个目标", root=tmp_path, client=ScriptedClient([]), max_turns=1)
