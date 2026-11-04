# -*- coding: utf-8 -*-
"""Turn static facts into a context block the analyst can cite, not guess from.

The failure this avoids is subtle: a decompiled function *reads* like ground
truth, so a model will happily describe its purpose as fact. Every line here
therefore carries where it came from, and the prompt that consumes it is told
that "purpose" is never a fact - only addresses, counts and strings are.

Three sources, three labels:

* ``pe_headers`` / ``exception_directory`` - the loader's own tables
* ``ghidra_decompiler`` - machine-produced code and cross-references
* ``analyst_hypothesis`` - anything a model says *about* the above
"""

import json
from typing import Dict, List, Optional

UNKNOWN = "UNKNOWN"


def _fmt(value: Optional[object]) -> str:
    return UNKNOWN if value in (None, "", []) else str(value)


def image_block(facts: Dict[str, object]) -> str:
    """Identity of the binary: without this, an address means nothing."""
    return "\n".join([
        "## 目标二进制（静态事实，来源 pe_headers）",
        "- 路径: %s" % _fmt(facts.get("path")),
        "- SHA256: %s" % _fmt(facts.get("sha256")),
        "- 大小: %s 字节" % _fmt(facts.get("size")),
        "- 架构: %s | PE32+: %s | ImageBase: %s"
        % (_fmt(facts.get("machine")), _fmt(facts.get("pe32plus")),
           _fmt(facts.get("image_base"))),
        "- 函数数（.pdata）: %s" % _fmt(facts.get("functions")),
        "- 导入: %s" % (", ".join(facts.get("imports") or []) or UNKNOWN),
        "- 导出: %s" % (", ".join(facts.get("exports") or []) or "无"),
        "- PDB: %s" % _fmt((facts.get("pdb") or {}).get("path")),
    ])


def function_block(facts: Dict[str, object]) -> str:
    """One function, with the fields an argument can actually be built on."""
    if not facts or facts.get("error"):
        return "## 目标函数\n（未导出；来源: %s）" % _fmt(facts.get("error") if facts else UNKNOWN)
    callers: List[str] = list(facts.get("callers") or [])
    callees: List[str] = list(facts.get("callees") or [])
    strings: List[str] = list(facts.get("string_refs") or [])
    lines = [
        "## 目标函数（来源 ghidra_decompiler）",
        "- RVA: 0x%s | 名称: %s | 大小: %s 字节 | 指令数: %s"
        % (_fmt(facts.get("rva")), _fmt(facts.get("name")),
           _fmt(facts.get("size")), _fmt(facts.get("instructions"))),
        "- 调用者 (%d): %s" % (len(callers), ", ".join(callers[:8]) or "无"),
        "- 被调用 (%d): %s" % (len(callees), ", ".join(callees[:12]) or "无"),
        "- 字符串引用 (%d): %s" % (len(strings), "; ".join(strings[:8]) or "无"),
    ]
    return "\n".join(lines)


def decompiled_block(facts: Dict[str, object], limit: int = 4000) -> str:
    code = (facts or {}).get("decompiled") or ""
    if not code:
        return "## 反编译\n（未获得；可能该函数未被识别）"
    return "## 反编译（机器生成，注意这是反编译结果而非原始源码）\n```c\n%s\n```" % code[:limit]


RULES = """## 使用规则（必须遵守）
1. `pe_headers` / `exception_directory` / `ghidra_decompiler` 标注的内容视为**事实**；
   你关于函数用途、字段含义的任何判断都属于 `analyst_hypothesis`，必须显式标注。
2. 不得把"函数名"当成语义证据：NVIDIA 驱动大量函数名来自 .pdata 或导入表，可能无意义。
3. 不得从一次反编译推断出"这就是漏洞函数"；只能提出候选，并说明支撑它的地址级证据。
4. 任何关于授权检查的结论，都要落到具体分支地址与比较操作数；没有地址的结论＝假设。
5. 缺失的信息写 UNKNOWN，不要用常识补齐。"""


def build_context(image: Dict[str, object], function: Optional[Dict[str, object]] = None,
                  cve: str = "", hypothesis: str = "") -> str:
    blocks = [RULES, image_block(image)]
    if function is not None:
        blocks += [function_block(function), decompiled_block(function)]
    if cve or hypothesis:
        blocks.append("## 研究目标\n- CVE: %s\n- 当前假设（analyst_hypothesis）: %s"
                      % (cve or UNKNOWN, hypothesis or UNKNOWN))
    return "\n\n".join(blocks)


def to_json(image: Dict[str, object], function: Optional[Dict[str, object]] = None) -> str:
    return json.dumps({"image": image, "function": function}, ensure_ascii=False, indent=2)
