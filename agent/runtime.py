# -*- coding: utf-8 -*-
"""Single-agent runtime: the model decides, the runtime records and can resume.

There is no stage list. Each turn the model sees the goal, the tool menu, memory that
matches the goal, and the tail of the transcript; it answers with a tool call or a final
answer. The runtime validates the answer against a schema, executes, records evidence,
and keeps enough state on disk to continue the same investigation tomorrow.

Resume is deliberately conservative. If the process died while a tool was running, the
runtime cannot know whether that tool finished, so it marks the run
``INTERRUPTED / EXECUTION_STATE_UNKNOWN`` and says so instead of re-running it.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .evidence import ArtifactStore, EvidenceLog, Runner, sha256_bytes, verify_chain
from .memory import ResearchMemory
from .registry import ToolRegistry, build_registry
from .workspace import Workspace

SYSTEM = """你是一个自主的 NVIDIA GPU 漏洞研究 Agent。

你只做一件事：用现有工具把研究目标推进到有证据的结论。没有规定步骤，也不要求复现某个漏洞。

每轮只输出一个 JSON 对象，二选一：
1) 调用工具：{"thought": "...", "tool": "<工具名>", "args": {...}}
2) 结束：  {"thought": "...", "final": "..."}

规则：
- 结论区分「推测」「工具输出显示」「已复现」；
- 工具报错先读错误，再决定换工具还是改方法；
- 看记忆摘要，避免重复已失败的尝试；
- 只输出 JSON，不要输出其它文字。
"""

ALLOWED_KEYS = {"thought", "tool", "args", "final"}


def log_tail(path: Path):
    if not Path(path).is_file():
        return None
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return json.loads(lines[-1]) if lines else None


class RuntimeError_(RuntimeError):
    """Run-level misuse: wrong goal, corrupt evidence, unsafe resume."""


def parse_action(raw: str, known_tools: List[str]) -> tuple:
    """Strict action schema. Returns (action, error); never guesses intent."""
    import re
    match = re.search(r"```(?:json)?\s*(.*?)```", raw, re.S)
    candidate = (match.group(1) if match else raw).strip()
    start, end = candidate.find("{"), candidate.rfind("}")
    if start < 0 or end <= start:
        return {}, "no JSON object in response"
    try:
        action = json.loads(candidate[start:end + 1])
    except ValueError as exc:
        return {}, "invalid JSON: %s" % exc
    if not isinstance(action, dict):
        return {}, "action must be a JSON object"

    unknown = set(action) - ALLOWED_KEYS
    if unknown:
        return {}, "unknown fields: %s" % ", ".join(sorted(unknown))
    if "thought" in action and not isinstance(action["thought"], str):
        return {}, "thought must be a string"
    has_tool, has_final = "tool" in action, "final" in action
    if has_tool == has_final:
        return {}, "exactly one of 'tool' or 'final' is required"
    if has_final:
        if not isinstance(action["final"], str) or not action["final"].strip():
            return {}, "final must be a non-empty string"
        return action, ""
    if not isinstance(action["tool"], str):
        return {}, "tool must be a string"
    if action["tool"] not in known_tools:
        return {}, "unknown tool %r; known: %s" % (action["tool"], ", ".join(known_tools))
    args = action.get("args", {})
    if not isinstance(args, dict):
        return {}, "args must be a JSON object"
    action["args"] = args
    return action, ""


@dataclass
class Turn:
    index: int
    thought: str
    tool: Optional[str]
    args: dict
    observation: dict
    status: str = "success"
    dispatched: bool = True
    operation_ok: bool = True
    dispatched: bool = True
    operation_ok: bool = True
    at: str = ""


@dataclass
class RunResult:
    goal: str
    final: str
    turns: List[Turn] = field(default_factory=list)
    stopped: str = "final"
    workspace: str = ""
    run_id: str = ""
    resume_state: str = "NEW"

    def to_dict(self) -> dict:
        return {"run_id": self.run_id, "goal": self.goal, "final": self.final,
                "stopped": self.stopped, "resume_state": self.resume_state,
                "workspace": self.workspace,
                "turns": [{"index": t.index, "thought": t.thought, "tool": t.tool,
                           "args": t.args, "status": t.status,
                           "dispatched": t.dispatched, "operation_ok": t.operation_ok,
                           "at": t.at,
                           "observation": shrink(t.observation)} for t in self.turns]}


def shrink(value, limit: int = 1200) -> dict:
    text = json.dumps(value, ensure_ascii=False)
    if len(text) <= limit:
        return value if isinstance(value, dict) else {"value": value}
    return {"truncated": True, "preview": text[:limit]}


class AgentRuntime:
    def __init__(self, *, goal: str, root: Path, client, max_turns: int = 12,
                 registry: Optional[ToolRegistry] = None, legacy: bool = False,
                 search: bool = True, timeout: int = 300, resume: bool = False):
        self.goal = goal.strip()
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.client = client
        self.max_turns = max_turns
        self.resume_state = "NEW"

        self.workspace = Workspace(self.root / "workspace")
        self.artifacts = ArtifactStore(self.root / "artifacts")
        self.run_state = self._prepare_run(resume)
        self.run_id = self.run_state["run_id"]

        self.log = EvidenceLog(self.root / "evidence.jsonl", self.artifacts, self.run_id)
        self.memory = ResearchMemory(self.root / "memory.jsonl", self.run_id)
        self.runner = Runner(self.workspace.root, self.log, timeout=timeout)
        if registry is None:
            registry, conflicts, providers = build_registry(
                self.workspace, self.runner, self.log, self.memory,
                legacy=legacy, search=search)
            self.tool_conflicts = conflicts
            self.provider_status = providers
        else:
            self.tool_conflicts = []
            self.provider_status = []
        self.registry = registry
        self.transcript_path = self.root / "transcript.jsonl"
        # First record in every log: what this run is and what it could call.
        self.log.append("start", {"goal_sha256": self.run_state["goal_sha256"],
                                  "tools": self.registry.names(),
                                  "legacy_conflicts": self.tool_conflicts,
                                  "providers": self.provider_status,
                                  "mode": "resume" if resume else "new"})

    # -- run state ------------------------------------------------------
    def _prepare_run(self, resume: bool) -> dict:
        path = self.root / "run.json"
        goal_sha = sha256_bytes(self.goal.encode("utf-8"))
        if resume:
            if not path.is_file():
                raise RuntimeError_("resume requested but run.json is missing")
            state = json.loads(path.read_text(encoding="utf-8"))
            if state.get("goal_sha256") != goal_sha:
                raise RuntimeError_("goal differs from the recorded run; refusing to resume")
            check = verify_chain(self.root / "evidence.jsonl")
            if not check["ok"]:
                raise RuntimeError_("evidence chain is broken: %s"
                                    % "; ".join(check["errors"][:3]))
            anchored = state.get("evidence_head")
            if anchored and check["last_record_sha256"] != anchored:
                raise RuntimeError_("evidence tail does not match the recorded head "
                                    "(records were removed after the run)")
            # A run that stopped between a tool record and its finish may have died mid
            # action. The runtime says so rather than silently repeating that action.
            last = log_tail(self.root / "evidence.jsonl")
            if last and last.get("kind") in ("tool", "exec"):
                state["interrupted"] = True
                state["interrupt_reason"] = "EXECUTION_STATE_UNKNOWN"
            state["status"] = "running"
            state["resumed_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            path.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")
            self.resume_state = ("INTERRUPTED" if state.get("interrupted")
                                 else "RESUMED")
            return state

        if path.is_file():
            existing = json.loads(path.read_text(encoding="utf-8"))
            raise RuntimeError_("run already exists (%s); use --resume instead of overwriting"
                                % existing.get("run_id"))
        state = {
            "run_id": "run-" + hashlib.sha256(
                (self.goal + str(time.time())).encode("utf-8")).hexdigest()[:12],
            "goal": self.goal,
            "goal_sha256": goal_sha,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "status": "running",
            "turns": 0,
            "tools": [],
        }
        path.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")
        return state

    def _save_state(self, **updates) -> None:
        state = dict(self.run_state)
        state.update(updates)
        # Anchor the head of the evidence log. Without it a truncated tail looks like a
        # shorter but perfectly valid chain, because each remaining record still links.
        tail = log_tail(self.log.path)
        if tail:
            state["evidence_head"] = tail.get("record_sha256")
            state["evidence_sequence"] = tail.get("sequence")
        (self.root / "run.json").write_text(
            json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")

    # -- prompt ---------------------------------------------------------
    def _tool_menu(self) -> str:
        lines = []
        for item in self.registry.describe():
            status = "ok" if item["available"] else "missing:%s" % item["missing"]
            params = ", ".join("%s:%s" % (k, v) for k, v in item["parameters"].items())
            lines.append("- %s(%s) [%s] %s" % (item["name"], params, status,
                                               item["description"]))
        return "\n".join(lines)

    def _render_observation(self, observation, budget: int) -> str:
        """Render one observation for the prompt, sized by what the tool returned.

        Cutting every observation to the same short length threw away the body an extract
        or an artifact read had just fetched. A search needs its result list, a shell
        needs its exit status and the head of stdout, a read needs the text plus the
        pointer that continues it.
        """
        if not isinstance(observation, dict):
            return str(observation)[:budget]
        summary = observation.get("summary")
        if not isinstance(summary, dict):
            return json.dumps(observation, ensure_ascii=False)[:budget]

        parts = []
        if "exit" in summary:
            parts.append("exit=%s timeout=%s" % (summary.get("exit"), summary.get("timed_out")))
            parts.append("stdout:\n" + (summary.get("stdout") or "")[:budget])
            if summary.get("stderr"):
                parts.append("stderr:\n" + summary["stderr"][:600])
        elif "items" in summary:
            parts.append("results=%s" % summary.get("results"))
            for item in summary["items"][:5]:
                parts.append("- [%s] %s | %s" % (item.get("score"), item.get("title"),
                                                 (item.get("content") or "")[:200]))
        elif "content" in summary:
            parts.append("artifact=%s offset=%s has_more=%s total=%s"
                         % (summary.get("artifact"), summary.get("offset"),
                            summary.get("has_more"), summary.get("total_bytes")))
            parts.append((summary.get("content") or "")[:budget])
        elif "content_preview" in summary:
            parts.append("chars=%s truncated=%s payload=%s"
                         % (summary.get("chars"), summary.get("truncated"),
                            str(summary.get("payload_sha256", ""))[:12]))
            parts.append(summary["content_preview"][:budget])
        elif "error" in summary:
            parts.append("error: " + str(summary["error"])[:400])
        else:
            parts.append(json.dumps(summary, ensure_ascii=False)[:budget])

        if observation.get("artifacts"):
            refs = [a.get("artifact") for a in observation["artifacts"][:3] if a]
            if refs:
                parts.append("artifacts: " + ", ".join(refs))
        if not observation.get("ok", True):
            parts.insert(0, "STATUS=failed")
        return "\n".join(parts)[:budget + 700]

    def _prompt(self, turns: List[Turn], remaining: int) -> str:
        recent = ""
        for turn in turns[-4:]:
            recent += "\n[第%d轮] 想法: %s\n工具: %s %s\n观测: %s\n" % (
                turn.index, turn.thought[:160], turn.tool,
                json.dumps(turn.args, ensure_ascii=False)[:160],
                self._render_observation(turn.observation, 2400))
        older = turns[:-4]
        if older:
            lines = ["[更早 %d 轮，完整记录在 evidence.jsonl]" % len(older)]
            for turn in older[-6:]:
                lines.append("- 第%d轮 %s -> %s" % (turn.index, turn.tool, turn.status))
            recent = "\n".join(lines) + "\n" + recent
        digest = self.memory.digest(self.goal)
        return ("研究目标：\n%s\n\n可用工具：\n%s\n\n相关记忆：\n%s\n\n最近过程：%s\n"
                "剩余轮次：%d\n工作区：%s\n\n下一轮 JSON："
                % (self.goal, self._tool_menu(), digest or "(空)", recent or "(无)",
                   remaining, self.workspace.root))

    # -- loop -----------------------------------------------------------
    def run(self) -> RunResult:
        turns: List[Turn] = self._load_turns()
        final_text, stopped = "", "max_turns"
        start_index = len(turns)

        for offset in range(1, self.max_turns + 1):
            index = start_index + offset
            remaining = self.max_turns - offset + 1
            raw = self.client.chat([{"role": "system", "content": SYSTEM},
                                    {"role": "user", "content": self._prompt(turns, remaining)}],
                                   temperature=0.2)
            action, error = parse_action(raw, self.registry.names())
            self._append_transcript({"turn": index, "raw": raw, "error": error})

            if error:
                turns.append(Turn(index, "", None, {}, {"error": error}, status="invalid"))
                self.log.append("action_rejected", {"error": error}, status="rejected")
                continue
            if "final" in action:
                final_text, stopped = action["final"], "final"
                break

            tool_name = action["tool"]
            args = action["args"]
            outcome = self.registry.call(tool_name, args)
            dispatched, ok = outcome["dispatched"], outcome["ok"]
            # A dispatched-but-failed tool still produced evidence (stdout, HTTP error).
            # Only a dispatch failure has nothing to show, so it is reported as rejected.
            observation = (outcome["result"] if dispatched
                           else {"error": outcome["error"], "status": "dispatch_error"})
            status = "success" if ok else ("rejected" if not dispatched else "failed")
            record = self.log.append("tool", {
                "tool_name": tool_name,
                "arguments": args,
                "dispatched": dispatched,
                "operation_ok": ok,
                "summary": shrink(outcome.get("summary"), 600),
                "error": outcome.get("error"),
                "artifacts": outcome.get("artifacts", []),
            }, status=status)
            turn = Turn(index, action.get("thought", ""), tool_name, args, observation,
                        status=status, dispatched=dispatched, operation_ok=ok,
                        at=time.strftime("%H:%M:%S"))
            turns.append(turn)
            self._append_transcript({"turn": index, "tool": tool_name,
                                     "sequence": record["sequence"],
                                     "observation": shrink(observation, 800)})
            self.memory.add("attempt", "%s %s -> %s" % (
                tool_name, json.dumps(args, ensure_ascii=False)[:160],
                json.dumps(shrink(observation, 300), ensure_ascii=False)[:240]))
            self._save_state(turns=len(turns))

        if not final_text:
            final_text = ("未在 %d 轮内得出结论。最后一轮观测：%s"
                          % (self.max_turns,
                             json.dumps(shrink(turns[-1].observation), ensure_ascii=False)[:500])
                          if turns else "没有任何工具调用。")
        check = self.log.verify()
        self.log.append("finish", {"stopped": stopped, "turns": len(turns),
                                   "final_sha256": sha256_bytes(final_text.encode("utf-8")),
                                   "evidence_ok": check["ok"]})
        self._save_state(status="finished", turns=len(turns), finished_at=time.strftime(
            "%Y-%m-%dT%H:%M:%S"))
        result = RunResult(goal=self.goal, final=final_text, turns=turns, stopped=stopped,
                           workspace=str(self.workspace.root), run_id=self.run_id,
                           resume_state=self.resume_state)
        (self.root / "result.json").write_text(
            json.dumps(result.to_dict(), ensure_ascii=False, indent=1), encoding="utf-8")
        return result

    # -- persistence ----------------------------------------------------
    def _append_transcript(self, entry: dict) -> None:
        with self.transcript_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _load_turns(self) -> List[Turn]:
        if not self.transcript_path.is_file():
            return []
        turns = []
        for line in self.transcript_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            if "tool" in entry and "observation" in entry:
                turns.append(Turn(entry["turn"], "", entry["tool"], {},
                                  entry["observation"], at=""))
        return turns
