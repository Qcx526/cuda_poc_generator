# -*- coding: utf-8 -*-
"""A/B comparison: does giving the model real binary facts improve its constraints?

Arm A reasons from public API semantics and observed status differences alone.
Arm B gets the same task plus facts that were re-extracted from the image
(data/driver/f9_evidence.json), each with a source and a reproducible command.

The scoring is mechanical on purpose: citations that resolve, addresses that do not
exist, and whether an EvidenceRequest could actually settle the claim.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.config_loader import ConfigLoader          # noqa: E402
from src.llm_client import LLMClient                # noqa: E402

TASK = """你在分析一个 Windows 内核显示驱动（nvlddmkm 610.47）如何判定 D3DKMTEscape 请求合法。
已知的用户态观测：同一 Type、同一空缓冲区，仅改 Flags 会得到不同状态
（INVALID_PARAMETER / ACCESS_DENIED / NOT_SUPPORTED / BUFFER_TOO_SMALL）。

请给出 3 条候选约束，说明"请求合法性由什么决定"。每条必须包含：
- id：C1/C2/C3
- statement：一句话约束
- status：SUPPORTED / REFUTED / UNKNOWN（只能是这三个之一）
- rationale：依据是什么，明确区分"直接观察"与"推测"
- evidence_request：什么样的观测能证实或推翻它
- cites：引用的证据编号列表（没有就写 []）

硬性要求：
- 不得把返回值直接解释成"命中了某个内部函数/分支"；
- 不得编造地址、结构体或函数名；不确定就写 UNKNOWN；
- 只输出 JSON 数组，不要解释文字。"""

FACTS = """可用事实（编号即引用 id）：

[F1] 镜像 SHA256 = 31af1ce957c6065d0b4b01ba2a7ad27df386e32c15b536ce653a162e3425fa9c
     PE32+ x64，image_base 0x140000000，节数 32。
     来源：data/driver/f9_evidence.json；复现：python -m tools.driver.f9_evidence

[F2] 入口 RVA = 0x733a0e0（VA 0x14733a0e0），由 PE 可选头 EntryPoint 字段直接读出。
     来源/复现同上。

[F3] .pdata 中登记的函数共 79,615 个（异常目录大小 / 12）。
     来源/复现同上。

[F4] WDK 10.0.26100 的 DRIVER_INITIALIZATION_DATA 中，DxgkDdiEscape 位于偏移 0x110
     （Version 4 字节 + 之前的函数指针各 8 字节，按对齐累加）。
     来源：D:/Windows Kits/10/Include/10.0.26100.0/km/dispmprt.h 第 2726 行。
     注意：这是头文件布局事实，不证明该驱动真的填了这个字段。

[F5] RVA 0x6912f0 处有一函数，前 8 条指令已反汇编（见 f9_evidence.json 的 probe 段）。
     注意：该函数的作用未知，早期文档称其为 "handler" 属人工标注，不是事实。"""


def _client() -> LLMClient:
    return LLMClient(ConfigLoader())


def ask(client, facts: str) -> str:
    prompt = TASK if not facts else TASK + "\n\n" + facts
    return client.chat([{"role": "system", "content": "你是二进制分析助手，只输出严格 JSON。"},
                        {"role": "user", "content": prompt}], temperature=0.0)


def parse(text: str) -> list:
    match = re.search(r"\[[\s\S]*\]", text)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def score(items: list, known_rvas: set, fact_ids: set) -> dict:
    valid_citations, invented, falsifiable, branch_claims = 0, [], 0, []
    for item in items:
        for cite in item.get("cites") or []:
            if str(cite).strip("[] ") in fact_ids:
                valid_citations += 1
        for hexnum in re.findall(r"0x[0-9a-fA-F]{4,}", json.dumps(item, ensure_ascii=False)):
            if hexnum.lower() not in known_rvas:
                invented.append(hexnum)
        request = str(item.get("evidence_request") or "")
        if len(request) > 20 and any(k in request for k in ("断点", "ETW", "栈", "观测", "记录")):
            falsifiable += 1
        text = json.dumps(item, ensure_ascii=False)
        if re.search(r"(命中|到达|进入).{0,8}(分支|函数|分派)", text) and \
                item.get("status") == "SUPPORTED":
            branch_claims.append(item.get("id"))
    return {"count": len(items), "valid_citations": valid_citations,
            "invented_addresses": sorted(set(invented)),
            "falsifiable_requests": falsifiable,
            "unsupported_branch_claims": branch_claims}


def main() -> int:
    evidence = json.loads((ROOT / "data" / "driver" / "f9_evidence.json")
                          .read_text(encoding="utf-8"))
    known = {v.lower() for v in (
        evidence["driver"]["entry_rva"],
        "0x%x" % int(evidence["probe"]["rva"], 16),
        "0x110", evidence["driver"]["image_base"],
        "0x14733a0e0")}
    for row in evidence["probe"]["instructions"]:
        known.add(row["rva"].lower())

    client = _client()
    out = {}
    for arm, block in (("A", ""), ("B", FACTS)):
        raw = ask(client, block)
        items = parse(raw)
        out[arm] = {"raw": raw, "items": items,
                    "score": score(items, known, {"F1", "F2", "F3", "F4", "F5"})}

    target = ROOT / "data" / "driver" / "f9_llm"
    target.mkdir(parents=True, exist_ok=True)
    (target / "ab_comparison.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    for arm in ("A", "B"):
        print(arm, json.dumps(out[arm]["score"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
