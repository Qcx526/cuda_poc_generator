# -*- coding: utf-8 -*-
"""One page: what was reproduced, what was found, what is still open.

Two mainlines, stated the way they are judged:

* reproduce the CVE - the advisory names a component, an effect and a version
  range; a candidate that shows that effect on a version inside the range has
  reproduced it. A later release no longer crashing is the fix working, not the
  reproduction failing.
* find something new - a crash at a different fault site is recorded whether or
  not it turns out to be novel. Only when it should be called a new
  vulnerability does the question "does the current release still crash" apply.

  python -m src.status_report --out data/report/status.zh-CN.md
"""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional


def _specs(root: Path) -> List[dict]:
    rows = []
    for path in sorted((root / "specs").glob("*/spec.json")):
        try:
            spec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        oracle = spec.get("oracle") or {}
        rows.append({
            "cve": spec.get("cve_id", path.parent.name),
            "component": spec.get("component", ""),
            "advisory": oracle.get("advisory", ""),
            "affected": oracle.get("affected", ""),
            "fixed_in": oracle.get("fixed_in", ""),
            "effect": oracle.get("expected_effect", ""),
        })
    return rows


def _latest_loop(root: Path, cve: str) -> Dict[str, str]:
    """The most recent run that produced a verdict, not the most recent file.

    A run that died in a stage carries no verdict; showing it would report a
    grader bug as the state of the reproduction.
    """
    candidates = sorted((root / "data" / "loop").glob("*/%s/loop_report.zh-CN.md" % cve),
                        key=lambda p: p.stat().st_mtime, reverse=True)
    fallback: Dict[str, str] = {}
    for report in candidates:
        text = report.read_text(encoding="utf-8", errors="replace")
        row = {"run": str(report.parent.relative_to(root))}
        for label, key in (("状态", "status"), ("最终判定", "verdict")):
            marker = "| %s | `" % label
            for line in text.splitlines():
                if marker in line:
                    row[key] = line.split("`")[1]
                    break
        verdict = row.get("verdict", "")
        if verdict and verdict not in ("—", "-"):
            return row
        if not fallback:
            fallback = row
    return fallback


def _findings(root: Path) -> Dict[str, List[dict]]:
    grouped: Dict[str, List[dict]] = {}
    for path in sorted((root / "data" / "findings" / "novel").glob("*/*/finding.json")):
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        grouped.setdefault(row.get("cve_id", "?"), []).append(row)
    return grouped


def _version_columns(finding: dict) -> str:
    """What the finding did on every release it was tried against.

    A finding is a candidate new vulnerability only when it survives the newest
    release tested; crashing on an old one and not on the newest is a bug that
    someone already fixed.
    """
    rows = finding.get("versions") or []
    if not rows:
        return "未测"

    def key(row):
        tag = str(row.get("image", "")).split(":")[-1]
        parts = tag.split("-")[0].split(".")
        try:
            return tuple(int(p) for p in parts)
        except ValueError:
            return (0,)

    rows = sorted(rows, key=key)
    text = "; ".join("%s %s" % (str(row.get("image", "")).split(":")[-1].split("-")[0],
                                 "崩" if row.get("crashed") else "不崩")
                     for row in rows)
    newest = rows[-1]
    return "%s → %s" % (text, "候选新漏洞" if newest.get("crashed") else "非新漏洞")


def build(root: Path) -> str:
    specs = _specs(root)
    findings = _findings(root)
    lines = ["# 复现与新发现：当前状态", "",
             "判定口径：公告给出的组件、现象、受影响版本；在其中一个版本上复现该现象即为成功。",
             "后续版本不再崩溃说明修复生效，不构成复现失败。", "",
             "## 一、CVE 复现", "",
             "| CVE | 组件 | 受影响版本 | 修复版本 | 最近一次闭环 | 判定 |",
             "|---|---|---|---|---|---|"]
    for spec in specs:
        loop = _latest_loop(root, spec["cve"])
        lines.append("| %s | %s | %s | %s | %s | `%s` |"
                     % (spec["cve"], spec["component"][:28], spec["affected"],
                        spec["fixed_in"], loop.get("run", "—"),
                        loop.get("verdict", "未跑")))
    lines += ["", "## 二、变异发现的新崩溃", ""]
    if not findings:
        lines += ["暂无记录。", ""]
    for cve, rows in sorted(findings.items()):
        lines += ["### %s" % cve, "",
                  "| 样本 | 崩溃点 | 访问类型 | 实测版本 | 查重结论 |",
                  "|---|---|---|---|---|"]
        for row in rows:
            disclosure = row.get("disclosure") or {}
            lines.append("| %s | `%s` | %s | %s | %s |"
                         % (row.get("artifact", ""), row.get("fingerprint", ""),
                            row.get("severity", "—"),
                            _version_columns(row),
                            disclosure.get("verdict", row.get("triage", "未查重"))))
        lines.append("")
    lines += ["## 三、说明", "",
              "- 新发现只在判断“是否为新漏洞”时才需要跑修复版本；仍崩即为候选新漏洞。",
              "- 样本与证据存放于 `data/findings/novel/`，含 sha256、崩溃点与 memcheck 记录。",
              ""]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="reproduction and findings status")
    parser.add_argument("--root", default=".")
    parser.add_argument("--out", default="data/report/status.zh-CN.md")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    text = build(root)
    target = Path(args.out)
    if not target.is_absolute():
        target = root / target
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    print(text)
    print("written to %s" % target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
