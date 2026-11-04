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
