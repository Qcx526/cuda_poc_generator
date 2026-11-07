# -*- coding: utf-8 -*-
"""Preflight: three real prompt contexts through one entry point, then one model call.

The point is not to score anything. It is to show that both platforms produce a
context through the same function, that the contexts differ only by authorised
evidence, and that a model given one of them cites what it was actually given.
"""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.case_context import FACT_ASSISTED, PUBLIC_ONLY, build_context  # noqa: E402
from src.config_loader import ConfigLoader                              # noqa: E402
from src.llm_client import LLMClient                                    # noqa: E402

CUDA = ROOT / "data" / "cases" / "cve-2025-23340.v2.json"
DRIVER = ROOT / "data" / "cases" / "nvlddmkm-610-47-escape.v2.json"
OUT = ROOT / "data" / "driver" / "f10"

PROMPT = """你是 GPU 漏洞研究助手。下面是某次实验允许你看到的全部上下文。

请输出 JSON 数组，最多 3 条：
- id: H1/H2/H3
- statement: 你的推断，一句话
- kind: FACT 或 HYPOTHESIS（只能二选一；凡是上下文里没有直接给出的，写 HYPOTHESIS）
- cites: 你引用的证据 id 列表（必须来自上下文 evidence 里的 id，没有就写 []）
- evidence_request: 什么观测能验证或推翻它
- confidence: low/medium/high

硬性要求：
- 不得编造地址、结构名或证据 id；
- 上下文未给出的信息，不得当成已知事实；
- 只输出 JSON 数组。"""


def _client() -> LLMClient:
    return LLMClient(ConfigLoader())


def _ask(context: dict) -> str:
    body = json.dumps(context["payload"], ensure_ascii=False, indent=1)
    return _client().chat(
        [{"role": "system", "content": "只输出严格 JSON，不解释。"},
         {"role": "user", "content": PROMPT + "\n\n" + body}], temperature=0.0)


def _parse(text: str) -> list:
    start, end = text.find("["), text.rfind("]")
    if start < 0 or end < 0:
        return []
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def _audit(items: list, allowed: set, known_text: str) -> dict:
    cited, invented, facts_without_source = set(), [], []
    for item in items:
        for cite in item.get("cites") or []:
            if str(cite) in allowed:
                cited.add(str(cite))
            else:
                invented.append(str(cite))
        if item.get("kind") == "FACT" and not item.get("cites"):
            facts_without_source.append(item.get("id"))
    hexes = [h for h in __import__("re").findall(r"0x[0-9a-fA-F]{4,}", json.dumps(items))
             if h.lower() not in known_text.lower()]
    return {"cited_valid": sorted(cited), "invalid_citations": invented,
            "facts_without_cites": facts_without_source,
            "unknown_addresses": sorted(set(hexes))}


def main() -> int:
    cases = {
        "cuda_public": (CUDA, PUBLIC_ONLY, None),
        "driver_public": (DRIVER, PUBLIC_ONLY, None),
        "driver_facts": (DRIVER, FACT_ASSISTED, None),
    }
    contexts, results = {}, {}
    for name, (path, mode, auth) in cases.items():
        contexts[name] = build_context(path, mode, auth)

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "prompt_contexts.json").write_text(
        json.dumps({k: {kk: vv for kk, vv in v.items() if kk != "payload"}
                    for k, v in contexts.items()}, ensure_ascii=False, indent=1),
        encoding="utf-8")

    for name in ("cuda_public", "driver_facts"):
        raw = _ask(contexts[name])
        items = _parse(raw)
        allowed = {e["id"] for e in contexts[name]["payload"]["evidence"]}
        known = json.dumps(contexts[name]["payload"], ensure_ascii=False)
        results[name] = {"raw": raw, "items": items,
                         "audit": _audit(items, allowed, known),
                         "context_sha256": contexts[name]["context_sha256"]}

    (OUT / "llm_outputs.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")

    for name, result in results.items():
        print(name, json.dumps(result["audit"], ensure_ascii=False))
        print("  items:", len(result["items"]),
              "hash:", result["context_sha256"][:12])
    print("contexts:",
          {k: (v["included_evidence"], v["context_sha256"][:8]) for k, v in contexts.items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
