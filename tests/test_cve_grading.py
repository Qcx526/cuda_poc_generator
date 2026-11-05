# -*- coding: utf-8 -*-
"""Five-step grading, and the regression for the 0076 contradiction.

The case worth guarding: the framework said SUPPORTED while the generated harness
said NOT_REPRODUCED. Both were describing true things - one a crash in cuobjdump,
the other the absence of one in nvdisasm - and a single boolean could not say so.
"""

from pathlib import Path

from src import cve_grading as g

OBS = Path("data/loop/f7/CVE-2024-0076/iteration_1_observation.txt")


def test_samples_and_tool_executions_are_counted_separately():
    """4 samples x 2 tools = 8 executions; calling that '1/4' understates both."""
    facts = g.parse(OBS)
    assert facts.samples == 4
    assert facts.tool_executions == 8
    assert facts.crashes == 2


def test_the_0076_run_stops_at_differential_supported():
    facts = g.parse(OBS)
    result = g.grade(facts, ["nvdisasm", "cuobjdump"])
    assert result["highest"] == g.DIFFERENTIAL_SUPPORTED
    assert g.CVE_MECHANISM_SUPPORTED not in result["levels"]
    assert facts.single_field_differential is False


def test_a_crash_in_an_unnamed_tool_does_not_reach_mechanism():
    facts = g.RunFacts(tool_executions=2, crashes=1, crashing_tools=["readelf"],
                       benign_clean=True, control_clean=True,
                       single_field_differential=True)
    result = g.grade(facts, ["nvdisasm", "cuobjdump"])
    assert result["highest"] == g.DIFFERENTIAL_SUPPORTED


def test_mechanism_requires_a_single_field_differential():
    facts = g.RunFacts(tool_executions=2, crashes=1, crashing_tools=["nvdisasm"],
                       benign_clean=True, control_clean=True,
                       single_field_differential=True)
    assert g.grade(facts, ["nvdisasm"])["highest"] == g.CVE_MECHANISM_SUPPORTED


def test_attribution_is_never_granted_automatically():
    facts = g.RunFacts(tool_executions=2, crashes=1, crashing_tools=["nvdisasm"],
                       benign_clean=True, control_clean=True,
                       single_field_differential=True)
    assert g.CVE_ATTRIBUTED not in g.grade(facts, ["nvdisasm"])["levels"]


def test_a_dirty_baseline_blocks_even_the_differential_level():
    facts = g.RunFacts(tool_executions=4, crashes=1, crashing_tools=["nvdisasm"],
                       benign_clean=False, control_clean=True,
                       single_field_differential=True)
    assert g.grade(facts, ["nvdisasm"])["highest"] == g.CRASH_OBSERVED


def test_toolkit_version_comes_from_the_container_banner():
    assert g.parse(OBS).toolkit_version == "11.2.2"
