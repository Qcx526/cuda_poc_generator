# -*- coding: utf-8 -*-
"""Every spec in the repository must still load.

A spec that stops validating does not fail loudly: the three-line fallback in
spec_invocations swallows the error and returns an empty tool list, which turns
the framework's own verification pass off. Grading then rests entirely on what
the candidate printed about itself, and the run still reports SUPPORTED.

That is not hypothetical - adding advisory fields to the oracle block broke the
pydantic model, and a full loop ran to SUPPORTED with zero framework-authored
crash lines. One test over the directory prevents the next occurrence.
"""

from pathlib import Path

import pytest

from src.spec_model import load

SPECS = sorted(Path(__file__).resolve().parent.parent.joinpath("specs").glob("*/spec.json"))


def test_there_are_specs_to_check():
    assert SPECS, "specs/ is empty; the parametrised case below would silently pass"


@pytest.mark.parametrize("path", SPECS, ids=[p.parent.name for p in SPECS])
def test_spec_loads(path: Path):
    spec = load(path)
    assert spec.cve_id


def test_a_broken_spec_is_reported_rather_than_skipped(tmp_path: Path):
    """The second pass must say why it did not run."""
    from src.loop_stages import StageContext, spec_problem

    spec_dir = tmp_path / "specs" / "CVE-X"
    spec_dir.mkdir(parents=True)
    (spec_dir / "spec.json").write_text('{"cve_id": "CVE-X", "oracle": {"nope": 1}}',
                                        encoding="utf-8")
    context = StageContext(project_root=tmp_path, cve_id="CVE-X",
                           container_image="img", workdir=tmp_path,
                           tier="userland_toolchain", python_exe="py")
    problem = spec_problem(context)
    assert "规格校验失败" in problem
