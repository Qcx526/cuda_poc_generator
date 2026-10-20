# -*- coding: utf-8 -*-
"""Markdown rendering of one closed-loop run (thesis appendix material)."""

from typing import List

from .closed_loop import LoopResult


def render_loop_report(result: LoopResult, *, title: str = "") -> str:
    """Render the iteration trace; deterministic, no timestamps."""
    lines: List[str] = []
    lines.append("# %s" % (title or ("闭环复现记录：%s" % result.cve_id)))
    lines.append("")
    lines.append("| 项 | 值 |")
    lines.append("|---|---|")
    lines.append("| CVE | `%s` |" % result.cve_id)
    lines.append("| 状态 | `%s` |" % result.status)
    lines.append("| 迭代次数 | %d |" % result.iterations_used)
    lines.append("| 最终判定 | `%s` |" % (result.final_verdict or "—"))
    lines.append("")

    if result.trace:
        lines.append("## 迭代轨迹")
        lines.append("")
        lines.append("| # | 判定 | 诊断 | 处置指令（截断） |")
        lines.append("|---|---|---|---|")
        for record in result.trace:
            directive = (record.directive or "—").replace("\n", " ")
            if len(directive) > 90:
                directive = directive[:90] + "…"
            lines.append("| %d | `%s` | `%s` | %s |" % (
                record.iteration, record.verdict or "—",
                record.diagnosis_code or "—", directive))
        lines.append("")

    if result.reasons:
        lines.append("## 结束原因")
        lines.append("")
        for reason in result.reasons:
            lines.append("- %s" % reason)
        lines.append("")

    lines.append("## 边界说明")
    lines.append("")
    lines.append("`SUPPORTED` 只表示受控样本崩溃、良性基线干净、机制对照未全崩，")
    lines.append("且目标版本处于受影响区间；它不等于 CVE 级 `VERIFIED`。")
    lines.append("")
    return "\n".join(lines)
