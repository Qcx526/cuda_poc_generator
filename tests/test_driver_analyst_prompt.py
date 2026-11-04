# -*- coding: utf-8 -*-
"""The static-facts channel.

The point of the channel is that a group either receives verified binary facts or
is told that it has none. A silent empty string would let the baseline group drift
towards pretending it knows kernel addresses, so the absence is stated explicitly.
"""

from src import driver_analyst


def _text(messages):
    return "\n".join(m["content"] for m in messages)


def test_verified_facts_reach_the_prompt():
    facts = "DriverEntry RVA = 0x733a0e0\nDxgkDdiEscape offset = 0x110"
    text = _text(driver_analyst.build_prompt(cve="CVE-X", description="d",
                                             static_facts=facts))
    assert "0x733a0e0" in text
    assert "0x110" in text
    assert driver_analyst.CONTRACT_UNKNOWN_FACTS not in text


def test_absence_of_facts_is_stated_not_implied():
    text = _text(driver_analyst.build_prompt(cve="CVE-X", description="d"))
    assert driver_analyst.CONTRACT_UNKNOWN_FACTS in text
    assert "UNKNOWN" in driver_analyst.CONTRACT_UNKNOWN_FACTS


def test_the_section_is_labelled_as_read_only_static_input():
    text = _text(driver_analyst.build_prompt(cve="CVE-X", description="d",
                                             static_facts="x"))
    assert "驱动静态事实" in text
    assert "只读" in text
