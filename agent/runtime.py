# -*- coding: utf-8 -*-
"""Single-agent runtime: the model decides, the runtime records.

There is no stage list here. Each turn the model sees the goal, the tool menu, a digest
of its own memory and the tail of its transcript, and answers with either a tool call or
a final answer. The runtime executes, records evidence, and hands back what happened.
Nothing about JPEG, ELF or CUDA appears in this file - that knowledge is the model's job
or a tool's, not the loop's.
"""

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .evidence import EvidenceLog, Runner
from .memory import ResearchMemory
from .registry import ToolRegistry
from .tools_builtin import build_tools
from .workspace import Workspace

SYSTEM = """你是一个自主的 NVIDIA GPU 漏洞研究 Agent。

你只做一件事：用现有工具把研究目标推进到有证据的结论。你可以任意组合工具、
写自己的脚本、下载资料、修改方案。没有规定的步骤，也不要求你必须复现某个漏洞。

每一轮只输出一个 JSON 对象，二选一：
1) 调用工具：
   {"thought": "<这一步想验证什么>", "tool": "<工具名>", "args": {<参数>}}
2) 结束并给出结论：
   {"thought": "<为什么可以停了>", "final": "<结论：做了什么、看到什么、证据是什么、还差什么>"}

规则：
- 结论必须区分「我推测」「工具输出显示」「已复现」；
- 不确定就说不确定，不要为了让报告好看而夸大；
- 工具报错时先读错误信息，再决定换工具还是改方法；
- 每轮开始前先看记忆摘要，避免重复已经失败的尝试。
"""


@dataclass
class Turn:
    index: int
    thought: str
    tool: Optional[str]
    args: dict
    observation: dict
    at: str = ""


@dataclass
class RunResult:
    goal: str
    final: str
    turns: List[Turn] = field(default_factory=list)
    stopped: str = "final"
    workspace: str = ""

    def to_dict(self) -> dict:
        return {"goal": self.goal, "final": self.final, "stopped": self.stopped,
                "workspace": self.workspace,
                "turns": [{"index": t.index, "thought": t.thought, "tool": t.tool,
                           "args": t.args, "at": t.at,
                           "observation": _shrink(t.observation)} for t in self.turns]}


def _shrink(observation: dict, limit: int = 1200) -> dict:
    text = json.dumps(observation, ensure_ascii=False)
    if len(text) <= limit:
        return observation
    return {"truncated": True, "preview": text[:limit]}


class AgentRuntime:
    def __init__(self, *, goal: str, root: Path, client, max_turns: int = 12,
                 registry: Optional[ToolRegistry] = None, timeout: int = 300):
        self.goal = goal
        self.root = Path(root)
        self.client = client
        self.max_turns = max_turns
        self.workspace = Workspace(self.root / "workspace")
        self.log = EvidenceLog(self.root / "evidence.jsonl")
        self.memory = ResearchMemory(self.root / "memory.jsonl")
        self.runner = Runner(self.workspace.root, self.log, timeout=timeout)
        self.registry = registry or ToolRegistry()
        if not self.registry.names():
            for spec in build_tools(self.workspace, self.runner, self.log):
                from .registry import Tool
                self.registry.register(Tool(**spec))
        self.transcript_path = self.root / "transcript.jsonl"
        self.transcript_path.write_text("", encoding="utf-8")
        self.log.record("start", {"goal": goal, "tools": self.registry.names(),
                                  "max_turns": max_turns})

    # -- prompt ---------------------------------------------------------
    def _tool_menu(self) -> str:
        lines = []
        for item in self.registry.describe():
            status = "可用" if item["available"] else "缺失依赖:%s" % item["missing"]
            params = ", ".join("%s:%s" % (k, v) for k, v in item["parameters"].items())
            lines.append("- %s(%s) [%s] %s" % (item["name"], params, status, item["description"]))
        return "\n".join(lines)

    def _prompt(self, turns: List[Turn]) -> str:
        recent = ""
        for turn in turns[-4:]:
            recent += "\n[第%d轮] 想法: %s\n工具: %s %s\n观测: %s\n" % (
                turn.index, turn.thought[:200], turn.tool,
                json.dumps(turn.args, ensure_ascii=False)[:200],
                json.dumps(_shrink(turn.observation), ensure_ascii=False)[:700])
        digest = self.memory.digest()
        return ("研究目标：\n%s\n\n可用工具：\n%s\n\n已有记忆：\n%s\n\n最近过程：%s\n"
                "工作区：%s\n\n请给出下一轮 JSON。"
                % (self.goal, self._tool_menu(), digest or "(空)", recent or "(无)",
                   self.workspace.root))

    # -- loop -----------------------------------------------------------
    def run(self) -> RunResult:
        turns: List[Turn] = []
        final_text = ""
        stopped = "max_turns"
        for index in range(1, self.max_turns + 1):
            raw = self.client.chat([{"role": "system", "content": SYSTEM},
                                    {"role": "user", "content": self._prompt(turns)}],
                                   temperature=0.2)
            action = _parse_action(raw)
            self._append_transcript({"turn": index, "raw": raw, "parsed": action})

            if action.get("final"):
                final_text = action["final"]
                stopped = "final"
                break
            tool_name = action.get("tool")
            if not tool_name:
                turns.append(Turn(index, action.get("thought", ""), None, {},
                                  {"error": "no tool and no final in response"}))
                continue

            outcome = self.registry.call(tool_name, action.get("args") or {})
            self.log.record("tool", {"tool": tool_name, "args": action.get("args") or {},
                                     "ok": outcome.get("ok")})
            observation = outcome.get("result") if outcome.get("ok") else outcome
            turn = Turn(index, action.get("thought", ""), tool_name,
                        action.get("args") or {}, observation,
                        time.strftime("%H:%M:%S"))
            turns.append(turn)
            self._append_transcript({"turn": index, "tool": tool_name, "observation":
                                     _shrink(observation)})
            self.memory.add("attempt", "%s %s -> %s" % (
                tool_name, json.dumps(action.get("args") or {}, ensure_ascii=False)[:200],
                json.dumps(_shrink(observation, 400), ensure_ascii=False)[:300]))

        if not final_text:
            final_text = ("未在 %d 轮内得出结论。最后一轮观测：%s"
                          % (self.max_turns,
                             json.dumps(_shrink(turns[-1].observation), ensure_ascii=False)[:600])
                          if turns else "没有任何工具调用。")
        result = RunResult(goal=self.goal, final=final_text, turns=turns,
                           stopped=stopped, workspace=str(self.workspace.root))
        self.log.record("finish", {"stopped": stopped, "turns": len(turns),
                                   "final_sha256": _hash(final_text)})
        (self.root / "result.json").write_text(
            json.dumps(result.to_dict(), ensure_ascii=False, indent=1), encoding="utf-8")
        return result

    def _append_transcript(self, entry: dict) -> None:
        with self.transcript_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _hash(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_action(raw: str) -> dict:
    """Extract the JSON action; tolerate a code fence and nothing else."""
    match = re.search(r"```(?:json)?\s*(.*?)```", raw, re.S)
    candidate = match.group(1) if match else raw
    try:
        return json.loads(candidate)
    except ValueError:
        pass
    brace = re.search(r"\{.*\}", candidate, re.S)
    if brace:
        try:
            return json.loads(brace.group(0))
        except ValueError:
            return {}
    return {}
