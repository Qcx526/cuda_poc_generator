# -*- coding: utf-8 -*-
"""The one page has to say the truth about both mainlines."""

import json
from pathlib import Path

from src.status_report import build


def _root(tmp_path: Path) -> Path:
    spec = tmp_path / "specs" / "CVE-X"
    spec.mkdir(parents=True)
    (spec / "spec.json").write_text(json.dumps({
        "cve_id": "CVE-X", "component": "cuobjdump",
        "oracle": {"advisory": "NVIDIA a_id/1", "affected": "prior to 12.4",
                   "fixed_in": "12.4", "expected_effect": "oob read -> DoS"},
    }), encoding="utf-8")

    run = tmp_path / "data" / "loop" / "a" / "CVE-X"
    run.mkdir(parents=True)
    (run / "loop_report.zh-CN.md").write_text(
        "| 状态 | `SUPPORTED` |\n| 最终判定 | `SUPPORTED` |\n", encoding="utf-8")

    finding = tmp_path / "data" / "findings" / "novel" / "CVE-X" / "one"
    finding.mkdir(parents=True)
    (finding / "finding.json").write_text(json.dumps({
        "cve_id": "CVE-X", "artifact": "x.cubin", "fingerprint": "cuobjdump+0x12000",
        "severity": "null-read", "triage": "UNTRIAGED",
        "versions": [{"image": "nvidia/cuda:12.4.1-devel", "crashed": True}],
    }), encoding="utf-8")
    return tmp_path


def test_the_page_states_the_reproduction_rule(tmp_path):
    text = build(_root(tmp_path))
    assert "在其中一个版本上复现该现象即为成功" in text
    assert "不构成复现失败" in text


def test_reproduction_and_findings_are_both_listed(tmp_path):
    text = build(_root(tmp_path))
    assert "CVE-X" in text and "`SUPPORTED`" in text
    assert "cuobjdump+0x12000" in text


def test_a_finding_that_survives_the_newest_release_is_a_candidate(tmp_path):
    text = build(_root(tmp_path))
    assert "12.4.1 崩" in text and "候选新漏洞" in text


def test_a_run_without_a_verdict_is_not_reported_as_the_state(tmp_path):
    root = _root(tmp_path)
    broken = root / "data" / "loop" / "b" / "CVE-X"
    broken.mkdir(parents=True)
    (broken / "loop_report.zh-CN.md").write_text(
        "| 状态 | `ERROR` |\n| 最终判定 | `—` |\n", encoding="utf-8")
    # Newer mtime on the broken run: it must still not win.
    import os
    os.utime(broken / "loop_report.zh-CN.md", (9e9, 9e9))
    text = build(root)
    assert "`ERROR`" not in text


def test_a_finding_with_a_disclosure_match_reports_it(tmp_path):
    root = _root(tmp_path)
    path = root / "data" / "findings" / "novel" / "CVE-X" / "one" / "finding.json"
    row = json.loads(path.read_text(encoding="utf-8"))
    row["disclosure"] = {"verdict": "已有人上报（KNOWN）",
                         "matches": ["CVE-2024-53877"]}
    path.write_text(json.dumps(row, ensure_ascii=False), encoding="utf-8")
    text = build(root)
    assert "已有人上报（KNOWN）" in text and "CVE-2024-53877" not in text.split("## 三")[0].split("### CVE-X")[1].splitlines()[3]


def test_the_disclosure_document_registers_like_a_cve(tmp_path):
    from src.novel_findings import write_disclosure

    root = _root(tmp_path)
    directory = root / "data" / "findings" / "novel" / "CVE-X" / "one"
    row = json.loads((directory / "finding.json").read_text(encoding="utf-8"))
    row["disclosure"] = {"component": "nvdisasm", "effect": "NULL 解引用",
                         "trigger": "sh_type 未知值", "verdict": "已有人上报（KNOWN）",
                         "matches": ["CVE-2024-53877（<12.8，修复 12.8）"],
                         "affected_statement": "实测 12.4 崩、13.0 不崩",
                         "conclusion": "已披露问题，不作为新漏洞上报"}
    (directory / "finding.json").write_text(json.dumps(row, ensure_ascii=False), encoding="utf-8")
    text = (write_disclosure(directory)).read_text(encoding="utf-8")
    assert "组件" in text and "NULL 解引用" in text
    assert "实测 12.4 崩、13.0 不崩" in text
    assert "CVE-2024-53877" in text
    assert "不作为新漏洞上报" in text


def test_a_finding_with_a_disclosure_match_reports_it(tmp_path):
    root = _root(tmp_path)
    path = root / "data" / "findings" / "novel" / "CVE-X" / "one" / "finding.json"
    row = json.loads(path.read_text(encoding="utf-8"))
    row["disclosure"] = {"verdict": "已有人上报（KNOWN）",
                         "matches": ["CVE-2024-53877"]}
    path.write_text(json.dumps(row, ensure_ascii=False), encoding="utf-8")
    text = build(root)
    assert "已有人上报（KNOWN）" in text and "CVE-2024-53877" not in text.split("## 三")[0].split("### CVE-X")[1].splitlines()[3]


def test_the_disclosure_document_registers_like_a_cve(tmp_path):
    from src.novel_findings import write_disclosure

    root = _root(tmp_path)
    directory = root / "data" / "findings" / "novel" / "CVE-X" / "one"
    row = json.loads((directory / "finding.json").read_text(encoding="utf-8"))
    row["disclosure"] = {"component": "nvdisasm", "effect": "NULL 解引用",
                         "trigger": "sh_type 未知值", "verdict": "已有人上报（KNOWN）",
                         "matches": ["CVE-2024-53877（<12.8，修复 12.8）"],
                         "affected_statement": "实测 12.4 崩、13.0 不崩",
                         "conclusion": "已披露问题，不作为新漏洞上报"}
    (directory / "finding.json").write_text(json.dumps(row, ensure_ascii=False), encoding="utf-8")
    text = (write_disclosure(directory)).read_text(encoding="utf-8")
    assert "组件" in text and "NULL 解引用" in text
    assert "实测 12.4 崩、13.0 不崩" in text
    assert "CVE-2024-53877" in text
    assert "不作为新漏洞上报" in text
