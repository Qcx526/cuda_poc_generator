# -*- coding: utf-8 -*-
"""Schema, projection and legacy adapter for gpu-vulnerability-case/v2."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from src import case_projection as proj
from src.case_legacy import adapt
from src.case_v2 import (Evidence, EvidenceKind, GPUCase, VerificationStatus,
                         Visibility)

CASES = Path("data/cases")
CUDA = CASES / "cve-2025-23340.v2.json"
DRIVER = CASES / "nvlddmkm-610-47-escape.v2.json"


def _load(path: Path) -> GPUCase:
    return GPUCase.model_validate(json.loads(path.read_text(encoding="utf-8")))


@pytest.mark.parametrize("path", [CUDA, DRIVER], ids=["cuda", "driver"])
def test_one_loader_parses_both_platforms(path):
    case = _load(path)
    assert case.schema_version == "gpu-vulnerability-case/v2"
    assert case.target.platform in ("linux", "windows")
    assert case.contract.backend


def test_cuda_case_does_not_require_driver_fields():
    case = _load(CUDA)
    assert case.extension.name == "cuda_toolchain"
    assert class_missing(case, "driver") is True


def class_missing(case: GPUCase, name: str) -> bool:
    """Driver-specific fields live in the extension, never in the core model."""
    return name not in case.target.model_dump() and name not in case.entry_surface.model_dump()


def test_driver_case_does_not_require_cuda_fields():
    case = _load(DRIVER)
    assert case.extension.name == "windows_gpu_driver"
    assert "cuda_toolkit" not in json.dumps(case.target.model_dump())


def test_public_projection_hides_the_cuda_recipe():
    text = proj.render(_load(CUDA), proj.PUBLIC_ONLY)
    for marker in ("sh_size", "1..11", "24 的倍数", "root_cause", "attack_vector"):
        assert marker not in text, marker


def test_public_projection_hides_static_facts():
    text = proj.render(_load(DRIVER), proj.PUBLIC_ONLY)
    assert "31af1ce9" not in text          # 镜像 SHA256 属 FACT
    assert "0x733e240" not in text         # 候选回调 RVA 属 FACT


def test_fact_assisted_projection_includes_only_facts():
    text = proj.render(_load(DRIVER), proj.FACT_ASSISTED)
    assert "31af1ce9" in text
    assert "0x733e240" in text
    assert "未证实" not in text            # EVAL 级解释不进投影


def test_eval_only_evidence_never_appears():
    case = _load(DRIVER)
    hidden = [e.id for e in case.knowledge.evidence if e.visible_in is Visibility.EVAL]
    assert hidden, "该案例应至少有一条评测专用证据"
    for mode in (proj.PUBLIC_ONLY, proj.FACT_ASSISTED):
        text = proj.render(case, mode)
        for identifier in hidden:
            assert '"id": "%s"' % identifier not in text


def test_static_fact_must_bind_a_target_identity():
    with pytest.raises(ValidationError):
        Evidence(id="X", kind=EvidenceKind.STATIC_FACT, statement="无来源",
                 source="某处", status=VerificationStatus.SUPPORTED,
                 visible_in=Visibility.FACT)


def test_visibility_is_decided_by_kind_not_by_the_document():
    with pytest.raises(ValidationError):
        Evidence(id="Y", kind=EvidenceKind.EVALUATION_ONLY, statement="触发配方",
                 source="公告", status=VerificationStatus.UNKNOWN,
                 visible_in=Visibility.PUBLIC)


def test_legacy_adapter_preserves_provenance():
    bundle = adapt(Path("data/inputs/CVE-2025-23340"))
    provenance = bundle.provenance
    assert len(provenance["file_sha256"]) == 7
    assert provenance["missing_files"] == []
    assert any("EVALUATION_ONLY" in line for line in provenance["diagnostics"])
    assert bundle.case.description.cwe == "CWE-131"


def test_legacy_values_stay_unverified():
    bundle = adapt(Path("data/inputs/CVE-2025-23340"))
    for item in bundle.case.knowledge.evidence:
        assert item.status is VerificationStatus.UNKNOWN, item.id
