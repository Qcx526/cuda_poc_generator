# -*- coding: utf-8 -*-
"""A SUPPORTED verdict must survive the question the spec asked.

The three conditions compare the candidate's own controls. A candidate that only
restores the field that produced the crash passes all three without ever testing
whether the crash belongs to the CVE. The spec names a mechanism axis; if no
control exercises it, the verdict cannot stand.
"""

import json
from pathlib import Path

from src.closed_loop import LoopConfig, LoopState
from src.loop_stages import make_grader

SPEC = {"cve_id": "CVE-X", "mutation": {"axes": [
    {"name": "boundary", "field": "sh_size", "offset": 32, "width": 8, "values": [0, 24]},
    {"name": "mechanism", "field": "sh_type", "offset": 4, "width": 4, "values": [1, 4]},
]}}

LOG = """\
[CPG_LABEL] benign.cubin BENIGN
[CPG_RUN] benign.cubin exit=0
[CPG_LABEL] poc.cubin MALICIOUS
[CPG_RUN] poc.cubin exit=139
[CPG_LABEL] ctrl_size.cubin CONTROL
[CPG_RUN] ctrl_size.cubin exit=0
"""


def _project(tmp_path: Path, control_changes_type: bool) -> Path:
    """Two controls at most: each changes exactly one axis, as a real pair does."""
    spec_dir = tmp_path / "specs" / "CVE-X"
    spec_dir.mkdir(parents=True)
    (spec_dir / "spec.json").write_text(json.dumps(SPEC), encoding="utf-8")

    samples = tmp_path / "samples"
    samples.mkdir()
    crafted = bytearray(64)
    size_control = bytearray(crafted)
    size_control[32:40] = b"\xff" * 8                # boundary axis only
    type_control = bytearray(crafted)
    type_control[4:8] = b"\x01\x00\x00\x00"       # mechanism axis only

    (samples / "poc.cubin").write_bytes(bytes(crafted))
    (samples / "ctrl_size.cubin").write_bytes(bytes(size_control))
    log = LOG
    if control_changes_type:
        (samples / "ctrl_type.cubin").write_bytes(bytes(type_control))
        log += ("[CPG_LABEL] ctrl_type.cubin CONTROL\n"
                "[CPG_RUN] ctrl_type.cubin exit=0\n")
    (samples / "benign.cubin").write_bytes(bytes(64))
    (samples / "log.txt").write_text(log, encoding="utf-8")
    return samples


def _grade(tmp_path: Path, samples: Path):
    config = LoopConfig(cve_id="CVE-X", samples_dir=str(samples),
                        project_root=str(tmp_path))
    state = LoopState(iteration=1, observation_file=str(samples / "log.txt"))
    return make_grader(config, version_in_range=None)(state)


def test_a_size_only_control_cannot_carry_a_supported_verdict(tmp_path):
    samples = _project(tmp_path, control_changes_type=False)
    result = _grade(tmp_path, samples)
    assert result.verdict != "SUPPORTED"
    assert any("机制轴" in reason for reason in result.reasons)


def test_a_control_that_moves_the_mechanism_axis_leaves_the_verdict_alone(tmp_path):
    samples = _project(tmp_path, control_changes_type=True)
    result = _grade(tmp_path, samples)
    assert result.verdict == "SUPPORTED"
    assert not any("机制轴" in reason for reason in result.reasons)
