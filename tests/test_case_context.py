# -*- coding: utf-8 -*-
"""The integration entry point: stable output, auditable inclusion, no widening."""

from pathlib import Path

from src.case_context import FACT_ASSISTED, PUBLIC_ONLY, build_context

CUDA = Path("data/cases/cve-2025-23340.v2.json")
DRIVER = Path("data/cases/nvlddmkm-610-47-escape.v2.json")


def test_cuda_public_context_is_reproducible():
    first = build_context(CUDA, PUBLIC_ONLY)
    second = build_context(CUDA, PUBLIC_ONLY)
    assert first["context_sha256"] == second["context_sha256"]
    assert first["included_evidence"], "公开断言不应为空"


def test_cuda_public_context_leaks_no_recipe():
    payload = build_context(CUDA, PUBLIC_ONLY)["payload"]
    text = str(payload)
    for marker in ("sh_size", "1..11", "24 的倍数", "root_cause", "attack_vector"):
        assert marker not in text, marker


def test_driver_facts_require_explicit_authorisation():
    context = build_context(DRIVER, FACT_ASSISTED)
    assert "S1" in context["included_evidence"]
    assert "R1" in context["excluded_evidence"]          # EVAL 证据不出现
    blind = build_context(DRIVER, PUBLIC_ONLY)
    text = str(blind["payload"])
    for marker in ("0x110", "0x733e240", "31af1ce9"):
        assert marker not in text, marker
    # 授权的事实只在 FACT_ASSISTED 出现
    assert "0x733e240" in str(context["payload"])


def test_a_caller_cannot_widen_authorisation():
    """Passing an id the case never authorised must not add it."""
    context = build_context(DRIVER, FACT_ASSISTED, authorized_fact_ids=["S1", "O1"])
    assert "O1" not in context["included_evidence"]
    assert "S2" not in context["included_evidence"], "未被点名的 S2 不应自动附加"


def test_narrowing_keeps_only_the_requested_fact():
    context = build_context(DRIVER, FACT_ASSISTED, authorized_fact_ids=["S1"])
    assert context["included_evidence"] == ["S1"]
