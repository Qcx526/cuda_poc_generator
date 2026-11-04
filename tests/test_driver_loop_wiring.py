# -*- coding: utf-8 -*-
"""Loop wiring.

A defect found in P13-3-H1: ``run()`` accepted ``static_facts`` but did not pass
it to ``build_controller``, so the "guided" group silently ran as the baseline.
The experiment looked valid because both groups produced code; only the prompt
length gave it away. This test fails if the argument is dropped again.
"""

import pytest

from src import driver_loop


def test_run_forwards_static_facts_to_the_controller(monkeypatch):
    captured = {}

    def fake_build_controller(**kwargs):
        captured.update(kwargs)
        raise RuntimeError("stop-here")

    monkeypatch.setattr(driver_loop, "build_controller", fake_build_controller)
    with pytest.raises(RuntimeError):
        driver_loop.run("CVE-X", rounds=1, static_facts="FACTS-MARKER")
    assert captured.get("static_facts") == "FACTS-MARKER"


def test_run_without_facts_passes_an_empty_string(monkeypatch):
    captured = {}

    def fake_build_controller(**kwargs):
        captured.update(kwargs)
        raise RuntimeError("stop-here")

    monkeypatch.setattr(driver_loop, "build_controller", fake_build_controller)
    with pytest.raises(RuntimeError):
        driver_loop.run("CVE-X", rounds=1)
    assert captured.get("static_facts") == ""


MARKER = "MUTATION-MARKER-12345"


def test_the_analyst_prompt_carries_the_mutation_context():
    from src import driver_analyst

    text = "\n".join(m["content"] for m in driver_analyst.build_prompt(
        cve="CVE-X", description="d", mutation_context=MARKER))
    assert MARKER in text
    assert "结构化变异上下文" in text


def test_the_generator_prompt_carries_the_mutation_context():
    from src import driver_generator

    text = "\n".join(m["content"] for m in driver_generator.build_prompt(
        cve="CVE-X", analysis={}, spec=None, last_run=None,
        mutation_context=MARKER))
    assert MARKER in text
    assert "合法变异" in text


def test_without_the_switch_both_prompts_say_so_explicitly():
    from src import driver_analyst, driver_generator

    analyst = "\n".join(m["content"] for m in driver_analyst.build_prompt(
        cve="CVE-X", description="d"))
    generator = "\n".join(m["content"] for m in driver_generator.build_prompt(
        cve="CVE-X", analysis={}, spec=None, last_run=None))
    assert "不启用结构化变异" in analyst
    assert "不启用结构化变异" in generator


def test_run_forwards_the_mutation_context(monkeypatch):
    captured = {}

    def fake_build_controller(**kwargs):
        captured.update(kwargs)
        raise RuntimeError("stop-here")

    monkeypatch.setattr(driver_loop, "build_controller", fake_build_controller)
    with pytest.raises(RuntimeError):
        driver_loop.run("CVE-X", rounds=1, mutation_context="MUT")
    assert captured.get("mutation_context") == "MUT"
