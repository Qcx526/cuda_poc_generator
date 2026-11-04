# -*- coding: utf-8 -*-
"""Driver-specific analysis: from a vague advisory to testable trigger hypotheses.

The CUDA expert prompt does not fit here. A toolchain CVE names its input ("a
malformed ELF"); a driver advisory names a layer and a consequence and stops. So
the model is not asked to summarise - it is asked to produce a ranked set of
hypotheses, each of which names an entry point, an object state and the field
that is supposed to decide the outcome, so the next run can falsify one of them.

What the model is *not* allowed to invent is ABI: structure layouts, escape types
and flags come from the repository and are passed in as fixed context.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ROOT = Path(__file__).resolve().parent.parent
ADVISORY_TABLES = ROOT / "data" / "driver" / "advisory_tables.json"
KNOWLEDGE = ROOT / "data" / "knowledge_bases" / "gpu_driver_kernel_method.md"

SYSTEM = """你是 NVIDIA GPU 驱动漏洞的触发条件分析器。

规则（违反任何一条即视为无效输出）：
1. 公告只给层、CWE、影响和版本范围，不给函数与字段。你的任务是把这些模糊信息
   变成**可执行的调用序列 + 参数结构 + 候选触发输入**，而不是复述公告。
2. 给出多个候选假设，按可信度排序；每个假设必须能被一次实验证伪。
3. ABI 不得臆造：D3DKMT 结构体、escape 的 Type/Flags、既有工具的函数签名，
   只能引用上下文中给出的定义。缺定义时写 unknown，不要编造偏移。
4. 区分三类信息：公告原文（official）、仓库实测（measured）、你的推断（inferred）。
   每条关键结论都要标注来源类别。
5. 不得假设"调用成功即漏洞触发"；要写清楚预期的运行时现象。
6. 输出严格 JSON，不要 Markdown 代码围栏。"""


def _as_text(value: Any) -> str:
    """Narrative fields arrive as strings, dicts or lists; all three are readable."""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return "" if value is None else str(value)


def _as_list(value: Any) -> list:
    """A single value is a one-element list; models drop brackets all the time."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _as_bool(value: Any) -> bool:
    """A model that writes "known except offset 32" is answering True with detail.

    Only an explicit unknown/未确认/no is False; anything else that mentions known
    counts as known, and a bare string with neither is False.
    """
    if isinstance(value, bool):
        return value
    text = _as_text(value).strip().lower()
    if not text:
        return False
    # "unknown" contains "known", so the negative has to be tested first.
    if any(word in text for word in ("unknown", "未确认", "未知", "不确定", "false", "no")):
        return "known" in text.replace("unknown", "") or "已知" in text
    return True


def _as_dict_list(value: Any) -> list:
    out = []
    for item in _as_list(value):
        out.append(item if isinstance(item, dict) else {"value": _as_text(item)})
    return out


class EntryPoint(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    api: str = Field(description="实际调用的接口，如 D3DKMTEscape / DeviceIoControl")
    why: str = ""
    reachability: str = Field(default="unknown",
                              description="official / measured / inferred / unknown")
    module: str = ""

    @field_validator("name", "api", "why", "reachability", "module", mode="before")
    @classmethod
    def _text(cls, value):
        return _as_text(value)


class TriggerConstraint(BaseModel):
    model_config = ConfigDict(extra="allow")

    field: str
    values: List[Any] = Field(default_factory=list)
    rationale: str = ""
    source: str = "inferred"

    @field_validator("values", mode="before")
    @classmethod
    def _values(cls, value):
        return _as_list(value)

    @field_validator("field", "rationale", "source", mode="before")
    @classmethod
    def _text(cls, value):
        return _as_text(value)


class InputHypothesis(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    layout: str = Field(description="已知结构体名或字段序列；未知则写 unknown")
    fields: Dict[str, Any] = Field(default_factory=dict)
    known_abi: bool = False

    @field_validator("known_abi", mode="before")
    @classmethod
    def _known(cls, value):
        return _as_bool(value)

    @field_validator("fields", mode="before")
    @classmethod
    def _fields(cls, value):
        if isinstance(value, dict):
            return value
        return {"description": _as_text(value)} if value is not None else {}

    @field_validator("name", "layout", mode="before")
    @classmethod
    def _text(cls, value):
        return _as_text(value)


class DriverAnalysis(BaseModel):
    """Exactly the ten pieces the generator needs; nothing decorative."""

    model_config = ConfigDict(extra="allow")

    vulnerability_primitive: str
    affected_component: str
    candidate_entry_points: List[EntryPoint]
    required_api_sequence: List[str]
    object_lifecycle: List[str]
    input_structure_hypotheses: List[InputHypothesis]
    trigger_constraints: List[TriggerConstraint]
    candidate_mutation_axes: List[Dict[str, Any]]
    expected_runtime_behavior: str
    next_experiment: str

    @model_validator(mode="before")
    @classmethod
    def _normalise(cls, data):
        """Models answer in the right shape only about half the time.

        A dict where a sentence was expected is still content, and discarding the
        whole analysis over punctuation wastes a completed inference. Coerce, then
        let the generator use it.
        """
        if not isinstance(data, dict):
            return data
        fixed = dict(data)
        for key in ("vulnerability_primitive", "affected_component",
                    "expected_runtime_behavior", "next_experiment"):
            if key in fixed:
                fixed[key] = _as_text(fixed[key])
        for key in ("candidate_entry_points", "input_structure_hypotheses"):
            if key in fixed:
                fixed[key] = _as_dict_list(fixed[key])
        for key in ("required_api_sequence", "object_lifecycle"):
            if key in fixed:
                fixed[key] = [_as_text(item) for item in _as_list(fixed[key])]
        if "candidate_mutation_axes" in fixed:
            fixed["candidate_mutation_axes"] = _as_dict_list(fixed["candidate_mutation_axes"])
        if "trigger_constraints" in fixed:
            fixed["trigger_constraints"] = _as_dict_list(fixed["trigger_constraints"])
        return fixed

    def ranked(self) -> List[EntryPoint]:
        order = {"measured": 0, "official": 1, "inferred": 2, "unknown": 3}
        return sorted(self.candidate_entry_points,
                      key=lambda item: order.get(item.reachability, 9))


def _read(path: Path, limit: int = 4000) -> str:
    try:
        return path.read_text(encoding="utf-8")[:limit]
    except OSError:
        return ""


def _tool_context() -> str:
    """The signatures the model must reuse instead of inventing."""
    parts = []
    for rel in ("tools/driver/escape_probe.py", "tools/probe_d3dkmt.py",
                "tools/driver/drs_probe.py"):
        text = _read(ROOT / rel, 2200)
        if text:
            parts.append("### %s\n```python\n%s\n```" % (rel, text))
    return "\n\n".join(parts)


def advisory_block(cve: str) -> str:
    """Official affected ranges, as structured data rather than prose."""
    try:
        tables = json.loads(ADVISORY_TABLES.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "（无官方产品表）"
    entry = tables.get(cve)
    return json.dumps(entry, ensure_ascii=False, indent=2) if entry else "（该 CVE 无官方表条目）"


def build_prompt(*, cve: str, description: str, spec: Optional[dict] = None,
                 last_run: Optional[dict] = None,
                 history_text: str = "",
                 static_facts: str = "") -> List[Dict[str, str]]:
    spec_text = json.dumps(spec, ensure_ascii=False, indent=2)[:3000] if spec else "（无）"
    run_text = json.dumps(last_run, ensure_ascii=False, indent=2)[:2500] if last_run else "（首轮，无执行结果）"
    user = f"""## CVE
{cve}

## 公告描述
{description}

## 官方受影响范围（CSAF）
{advisory_block(cve)}

## 现有规格 specs/{cve}/spec.json
{spec_text}

## 驱动静态事实（只读，来自二进制分析）
{static_facts.strip() or CONTRACT_UNKNOWN_FACTS}

## 方法笔记
{_read(KNOWLEDGE, 2000) or "（无）"}

## 仓库内已有的驱动工具（只能引用这里的 ABI，不要臆造）
{_tool_context()}

## 上一轮执行结果
{run_text}

## 历史实验（只读检索，含成功与失败的原始记录；不是唯一方案）
{history_text or "（无）"}

历史分类的含义（不要越级解读）：
- SETUP_PATH_SUCCESS：adapter/device/context 初始化成功，只证明初始化路径可用。
- D3DKMT_ESCAPE_CALL_OBSERVED：只确认 escape 调用发生过；返回 0xC000000D 等错误码
  **不能**证明进入 NVIDIA KMD 的厂商处理函数。
- DRIVER_INTERFACE_REACHED：有独立运行时证据（断点命中/probe 命中）才成立。
- VULNERABILITY_TRIGGERED：需要可归因的触发证据，本次没有任何一条达到。

请在此基础上做**对照分析**，并写进 next_experiment：
- 历史成功路径与当前失败路径分别调用了什么；
- 调用顺序、参数、结构体差异；
- 哪些步骤可以直接复用，哪些仍然未知（写 UNKNOWN，不要猜）。

请输出一个 JSON 对象，字段严格为：
vulnerability_primitive, affected_component, candidate_entry_points[],
required_api_sequence[], object_lifecycle[], input_structure_hypotheses[],
trigger_constraints[], candidate_mutation_axes[], expected_runtime_behavior,
next_experiment

其中 candidate_entry_points 的元素含 name/api/why/reachability/module；
trigger_constraints 的元素含 field/values/rationale/source；
input_structure_hypotheses 的元素含 name/layout/fields/known_abi。"""
    return [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": user}]


def extract_json(text: str) -> Dict[str, Any]:
    """Take the first complete JSON object in the reply.

    Slicing from the first brace to the last is wrong as soon as the model writes
    a closing brace in prose after the object, so each candidate start is decoded
    in turn and the first one that parses wins.
    """
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    raise ValueError("模型输出中没有可解析的 JSON 对象")


CONTRACT_UNKNOWN_FACTS = ("（本组未提供静态事实。不要假设已知任何内核函数地址、"
                          "授权分支或私有命令格式；缺口一律记为 UNKNOWN。）")


def analyse(client, *, cve: str, description: str, spec: Optional[dict] = None,
            last_run: Optional[dict] = None, history_text: str = "",
            static_facts: str = "",
            record_dir: Optional[Path] = None, round_index: int = 1) -> DriverAnalysis:
    """One analysis pass; optionally persist the exact prompt and response.

    The prompt is written to disk because "the feedback reached the model" is a
    claim that has to be checkable after the fact, not inferred from the output.
    """
    messages = build_prompt(cve=cve, description=description, spec=spec,
                            last_run=last_run, history_text=history_text,
                            static_facts=static_facts)
    if record_dir is not None:
        target = Path(record_dir) / cve
        target.mkdir(parents=True, exist_ok=True)
        (target / ("analyst_prompt_round%d.txt" % round_index)).write_text(
            "\n\n".join("%s://n%s" % (m["role"], m["content"]) for m in messages),
            encoding="utf-8")
    text = client.chat(messages, temperature=0.2)
    try:
        parsed = extract_json(text)
    except ValueError as exc:
        # A malformed object is a formatting slip, not a failed analysis: say where
        # it broke and ask once more instead of discarding the round.
        repair = messages + [
            {"role": "assistant", "content": text[:2000]},
            {"role": "user", "content": "上面的 JSON 无法解析（%s）。"
                                        "只重新输出完整合法的 JSON 对象，不要解释，不要代码围栏。" % exc}]
        text = client.chat(repair, temperature=0.1)
        parsed = extract_json(text)
    if record_dir is not None:
        (Path(record_dir) / cve / ("analyst_response_round%d.txt" % round_index)
         ).write_text(text, encoding="utf-8")
    return DriverAnalysis.model_validate(parsed)
