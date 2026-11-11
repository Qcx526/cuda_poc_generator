# -*- coding: utf-8 -*-
"""Resume contract: continue the same run, refuse unsafe ones, never overwrite."""

import json

import pytest

from agent import AgentRuntime
from agent.evidence import verify_chain
from agent.runtime import RuntimeError_


class ScriptedClient:
    def __init__(self, answers):
        self.answers = list(answers)

    def chat(self, messages, temperature=None, max_tokens=None):
        if not self.answers:
            return json.dumps({"thought": "done", "final": "stop"})
        return self.answers.pop(0)


def _turn(tool="fs_list", args=None, final=None):
    if final is not None:
        return json.dumps({"thought": "结束", "final": final})
    return json.dumps({"thought": "看看", "tool": tool, "args": args or {"path": "."}})


def test_resume_appends_and_keeps_evidence(tmp_path):
    first = AgentRuntime(goal="同一个目标", root=tmp_path,
                         client=ScriptedClient([_turn(), _turn(final="第一段完成")]),
                         max_turns=2).run()
    assert first.stopped == "final"
    transcript_before = (tmp_path / "transcript.jsonl").read_text(encoding="utf-8")
    assert transcript_before.count("\n") >= 2

    second = AgentRuntime(goal="同一个目标", root=tmp_path,
                          client=ScriptedClient([_turn(), _turn(final="第二段完成")]),
                          max_turns=2, resume=True).run()
    assert second.resume_state == "RESUMED"
    transcript_after = (tmp_path / "transcript.jsonl").read_text(encoding="utf-8")
    assert transcript_after.startswith(transcript_before), "transcript must not be truncated"
    assert "第二段完成" in second.final
    assert verify_chain(tmp_path / "evidence.jsonl")["ok"]


def test_resume_with_different_goal_is_refused(tmp_path):
    AgentRuntime(goal="目标甲", root=tmp_path, client=ScriptedClient([_turn(final="ok")]),
                 max_turns=1).run()
    with pytest.raises(RuntimeError_) as exc:
        AgentRuntime(goal="目标乙", root=tmp_path, client=ScriptedClient([]),
                     max_turns=1, resume=True)
    assert "goal differs" in str(exc.value)


def test_resume_with_broken_chain_is_refused(tmp_path):
    AgentRuntime(goal="目标", root=tmp_path, client=ScriptedClient([_turn(final="ok")]),
                 max_turns=1).run()
    path = tmp_path / "evidence.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError_) as exc:
        AgentRuntime(goal="目标", root=tmp_path, client=ScriptedClient([]),
                     max_turns=1, resume=True)
    message = str(exc.value)
    assert "evidence chain is broken" in message or "does not match the recorded head" in message


def test_resume_after_interruption_is_marked(tmp_path):
    runtime = AgentRuntime(goal="目标", root=tmp_path, client=ScriptedClient([]), max_turns=1)
    # Simulate a crash right after a tool call: a tool record with no finish record.
    runtime.log.append("tool", {"tool_name": "shell", "arguments": {"command": "echo hi"}})
    state = json.loads((tmp_path / "run.json").read_text(encoding="utf-8"))
    state["status"] = "running"
    (tmp_path / "run.json").write_text(json.dumps(state), encoding="utf-8")

    resumed = AgentRuntime(goal="目标", root=tmp_path, client=ScriptedClient([_turn(final="继续")]),
                           max_turns=1, resume=True)
    assert resumed.resume_state == "INTERRUPTED"
    assert json.loads((tmp_path / "run.json").read_text(encoding="utf-8"))["interrupted"] is True


def test_resume_without_run_file_is_refused(tmp_path):
    with pytest.raises(RuntimeError_) as exc:
        AgentRuntime(goal="目标", root=tmp_path, client=ScriptedClient([]),
                     max_turns=1, resume=True)
    assert "run.json is missing" in str(exc.value)


def test_new_run_writes_goal_hash_and_tools(tmp_path):
    AgentRuntime(goal="目标", root=tmp_path, client=ScriptedClient([_turn(final="ok")]),
                 max_turns=1)
    state = json.loads((tmp_path / "run.json").read_text(encoding="utf-8"))
    assert state["goal_sha256"] and state["status"] == "running"
    assert "shell" in state.get("tools", []) or state["tools"] == []
