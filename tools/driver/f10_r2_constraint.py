# -*- coding: utf-8 -*-
"""Constraint-first A/B: ask for analysable claims, not for code.

Both arms get the same task. Arm A sees the old blind brief as prose; arm B sees the
V2 PUBLIC_ONLY payload as JSON. The evaluator checks claims against the input each arm
actually received - a quote must appear in the text, a cited id must exist - so a
plausible sentence that cites nothing cannot score as supported.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.case_context import PUBLIC_ONLY, build_context   # noqa: E402
from src.config_loader import ConfigLoader                # noqa: E402
from src.llm_client import LLMClient                      # noqa: E402

OUT = ROOT / "data" / "driver" / "f10step1r1"
CASE = ROOT / "data" / "cases" / "cve-2025-23340.v2.json"
SPEC = ROOT / "specs" / "CVE-2025-23340" / "spec.json"

TASK = """你是 GPU 漏洞研究助手。基于下面给出的输入信息，输出一份结构化分析。

只输出一个 JSON 对象，字段如下：

{
  "entry_surface": {"tool": "...", "medium": "...", "component": "..."},
  "facts": [{"id": "F1", "kind": "INPUT_ASSERTION", "statement": "...", "cites": ["<证据 id 或原文片段>"], "quote": "<逐字摘自输入的片段>"}],
  "hypotheses": [{"id": "H1", "statement": "...", "basis": ["<证据 id 或原文片段>"], "evidence_request": {"tool": "<工具名>", "observable": "<可观测的输出或行为，例如 stderr 文本 / 退出信号 / 输出长度>", "would_refute_if": "<什么结果会推翻它>"}}],
  "unknowns": ["..."]
}

规则：
- kind 只能是 INPUT_ASSERTION / STATIC_FACT / HYPOTHESIS 之一；
- 没有直接依据的内容只能放进 hypotheses，不得写进 facts；
- quote 必须逐字出现在输入文本中，否则视为无依据；
- 不得给出输入中没有的具体数值、地址或参数；不确定就写进 unknowns；
- 最多 4 条 facts、3 条 hypotheses。

输入信息：
"""


def old_input() -> str:
    import os
    os.environ["CPG_BLIND_CONTRACT"] = "1"
    from src.spec_model import load
    return load(SPEC).prompt_brief()


def v2_input() -> dict:
    return build_context(CASE, PUBLIC_ONLY)


def parse(text: str) -> dict:
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        return {}
    try:
        return json.loads(text[start:end + 1])
    except ValueError:
        return {}


def evaluate(answer: dict, prompt: str, allowed_ids: set) -> dict:
    """Check each claim against the input that arm actually saw."""
    citations, supported, unsupported = [], [], []
    for item in answer.get("facts", []) + answer.get("hypotheses", []):
        refs = item.get("cites") or item.get("basis") or []
        quote = (item.get("quote") or "").strip()
        if allowed_ids and any(str(r) not in allowed_ids for r in refs):
            citations.append({"id": item.get("id"), "bad_refs": refs})
        if quote:
            (supported if quote in prompt else unsupported).append(item.get("id"))
        elif refs:
            unsupported.append(item.get("id"))
    numbers = set(re.findall(r"0x[0-9a-fA-F]{4,}|\b\d{3,}\b", json.dumps(answer)))
    invented = sorted(n for n in numbers if n not in prompt)
    requests = [h.get("evidence_request", {}) for h in answer.get("hypotheses", [])]
    observable = [r for r in requests if r.get("observable") and r.get("would_refute_if")]
    return {"facts": len(answer.get("facts", [])),
            "hypotheses": len(answer.get("hypotheses", [])),
            "bad_citations": citations,
            "quotes_supported": supported,
            "quotes_unsupported": unsupported,
            "numbers_not_in_input": invented,
            "requests_with_observable": len(observable),
            "requests_total": len(requests)}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    a_text = old_input()
    b_context = v2_input()
    b_text = json.dumps(b_context["payload"], ensure_ascii=False, indent=1)

    frozen = {
        "note": "两组输入冻结于本次运行；差异见 diff 字段",
        "arm_a": {"sha256": __import__("hashlib").sha256(a_text.encode()).hexdigest(),
                  "chars": len(a_text), "text": a_text},
        "arm_b": {"sha256": b_context["context_sha256"], "chars": len(b_text),
                  "evidence_ids": b_context["included_evidence"], "text": b_text},
        "diff": ["A 为纯文本 7 行；B 为 JSON，含 evidence 列表与 contract 字段",
                 "B 的 evidence 带 id，A 无 id，只能用原文片段引用",
                 "B 多出 entry_surface.trust_boundary 与 contract（goal/backend/risk）"],
    }
    (OUT / "frozen_inputs.json").write_text(
        json.dumps(frozen, ensure_ascii=False, indent=1), encoding="utf-8")

    client = LLMClient(ConfigLoader())
    results = {}
    for arm, text, ids in (("A", a_text, set()), ("B", b_text, set(b_context["included_evidence"]))):
        raw = client.chat([{"role": "system", "content": "只输出 JSON。"},
                           {"role": "user", "content": TASK + text}], temperature=0.0)
        answer = parse(raw)
        (OUT / ("arm_%s_response.txt" % arm)).write_text(raw, encoding="utf-8")
        results[arm] = {"answer": answer,
                        "evaluation": evaluate(answer, text, ids)}
    (OUT / "evaluation.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")

    for arm, item in results.items():
        e = item["evaluation"]
        print(arm, "facts", e["facts"], "hyp", e["hypotheses"],
              "| 引用错误", len(e["bad_citations"]),
              "| 有据引用", len(e["quotes_supported"]),
              "| 无据", len(e["quotes_unsupported"]),
              "| 编造数值", e["numbers_not_in_input"],
              "| ER 可观测", e["requests_with_observable"], "/", e["requests_total"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
