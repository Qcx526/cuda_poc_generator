# -*- coding: utf-8 -*-
"""Blind contract: what a model may see when history is closed.

The F7 run used --freeze-history and still received the parser entry, the oracle
condition and the historical mutation seed, because that flag only gated one field.
These tests pin the whole projection down against the real spec files.
"""

import os
from pathlib import Path

import pytest

from src.spec_model import load

SPECS = sorted(Path("specs").glob("*/spec.json"))

FORBIDDEN = ("parser:", "oracle:", "observed to crash", "already refuted",
             "verified by execution", "field ", "trigger (driver tier)")

pytestmark = pytest.mark.skipif(not SPECS, reason="no specs on disk")


@pytest.fixture(autouse=True)
def _blind():
    os.environ["CPG_BLIND_CONTRACT"] = "1"
    yield
    os.environ.pop("CPG_BLIND_CONTRACT", None)


@pytest.mark.parametrize("spec_path", SPECS, ids=[p.parent.name for p in SPECS])
def test_blind_brief_carries_no_solution(spec_path):
    text = load(spec_path).prompt_brief()
    for token in FORBIDDEN:
        assert token not in text, "%s 泄漏 %r" % (spec_path.parent.name, token)


@pytest.mark.parametrize("spec_path", SPECS, ids=[p.parent.name for p in SPECS])
def test_blind_brief_still_identifies_the_target(spec_path):
    """Blind must stay usable: tool, invocation and input format are public."""
    text = load(spec_path).prompt_brief()
    assert "cve:" in text and "component:" in text
    # User-mode tool targets name an invocation; driver targets legitimately do not
    # (the entry API is internal knowledge, so blind mode withholds it).
    if "user" in text and "driver" not in text.split("component:")[1][:120].lower():
        assert "invoke:" in text or "input:" in text
    assert len(text) > 40


def test_blind_is_strictly_smaller_than_the_full_brief():
    spec = load(SPECS[0])
    os.environ.pop("CPG_BLIND_CONTRACT", None)
    full = spec.prompt_brief()
    os.environ["CPG_BLIND_CONTRACT"] = "1"
    blind = spec.prompt_brief()
    assert len(blind) < len(full)


def test_affected_window_is_rendered_not_a_boolean():
    """It used to print 'affected: True', which told the model nothing."""
    for spec_path in SPECS:
        text = load(spec_path).prompt_brief()
        for line in text.splitlines():
            if line.startswith("affected:"):
                assert line.strip() != "affected: True"
