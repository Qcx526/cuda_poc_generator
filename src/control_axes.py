# -*- coding: utf-8 -*-
"""Which control reverts which field, decided from the bytes.

The three-condition verdict used to accept whatever controls the candidate chose,
and a candidate can choose controls that are guaranteed to pass: restore the same
field that produced the crash and the control will not crash, without saying
anything about whether the crash is the CVE. That is how a false positive earns a
SUPPORTED.

A control only answers a question if it differs from the crafted sample in the
field that question is about. This module reads both files and says which
declared axis a control actually covers.
"""

from typing import Dict, List, Sequence


def differing_offsets(crafted: bytes, control: bytes) -> set:
    """Byte positions that differ; empty when the sizes disagree."""
    if len(crafted) != len(control):
        return set()
    return {index for index, (a, b) in enumerate(zip(crafted, control)) if a != b}


def covers_axis(differences: set, axis: dict) -> bool:
    """True when every difference falls inside the axis's own field."""
    if not differences:
        return False
    start = int(axis.get("offset", -1))
    width = int(axis.get("width", 0))
    if start < 0 or width <= 0:
        return False
    return all(start <= offset < start + width for offset in differences)


def mechanism_axes(spec: dict) -> List[dict]:
    """The axes whose name says they are about the mechanism."""
    block = spec.get("mutation") or {}
    return [axis for axis in (block.get("axes") or [])
            if str(axis.get("name", "")).startswith("mechanism")]


def missing_controls(spec: dict, crafted: Dict[str, bytes],
                     controls: Dict[str, bytes]) -> List[str]:
    """Mechanism axes no control covers, as human-readable field names.

    An empty list means either every mechanism axis is covered, or the spec does
    not declare any - the caller cannot demand what was never specified.
    """
    axes = mechanism_axes(spec)
    if not axes:
        return []
    covered = set()
    for control_bytes in controls.values():
        for crafted_bytes in crafted.values():
            differences = differing_offsets(crafted_bytes, control_bytes)
            for axis in axes:
                if covers_axis(differences, axis):
                    covered.add(axis.get("field", ""))
    return [axis.get("field", "") for axis in axes
            if axis.get("field", "") not in covered]


def reason(missing: Sequence[str]) -> str:
    """A note, not a veto: the CVE is reproduced either way."""
    return ("提示：没有对照样本只改动 %s；若公告明确以该机制为触发条件，"
            "可另跑一次变异确认，但这不影响复现结论" % "、".join(missing))
