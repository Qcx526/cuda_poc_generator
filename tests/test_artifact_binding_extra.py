"""SYNTHETIC attacks recompute every digest; labels alone are not target binding."""

from copy import deepcopy
import hashlib
import json

import pytest

from src import artifact_packaging as ap
from src.models.artifact_package import ArtifactManifest
from src.models.lifecycle import canonical_sha256
from src.models.oracle import VulnerabilityClaim
from tests.test_artifact_packaging import generation_fixture, CVE, RUN


def _rebind_review(manifest,content,claim):
    """Attacker updates all unsigned consistency fields, never original inputs."""
    sha=canonical_sha256(claim)
    content["analysis/vulnerability_claim.json"]=ap._bytes(claim)
    content["evidence/public_source_references.json"]=ap._bytes([s.model_dump(mode="json") for s in claim.sources])
    content["reports/review.zh-CN.md"]=ap._claim_report(claim).encode()
    content["README.zh-CN.md"]=ap._readme(manifest.cve_id,manifest.run_id,sha)
    data=manifest.model_dump(mode="python")
    data["claim_sha256"]=sha
    for item in data["files"]:
        raw=content[item["relative_path"]]
        item["sha256"]=hashlib.sha256(raw).hexdigest()
        item["byte_length"]=len(raw)
        item["source_record_sha256"]=item["sha256"] if item["relative_path"].startswith("input/") else sha
    return ArtifactManifest.model_validate(data)


def test_consistently_rehashed_raw_input_from_other_cve_is_not_a_valid_review_package(tmp_path):
    ap.import_review_run(CVE,RUN,output_root=tmp_path)
    manifest,content=ap.read_review_run(CVE,RUN,output_root=tmp_path)
    filename=next(p for p in content if p.startswith("input/"))
    content[filename]=content[filename].replace(CVE.encode(),b"CVE-2025-23339")
    claim=VulnerabilityClaim.model_validate_json(content["analysis/vulnerability_claim.json"])
    data=claim.model_dump(mode="python")
    for assertion in data["input_assertions"]:
        if assertion["source_file"].endswith(filename[6:]):
            assertion["source_sha256"]=hashlib.sha256(content[filename]).hexdigest()
    claim=VulnerabilityClaim.model_validate(data)
    forged=_rebind_review(manifest,content,claim)
    with pytest.raises(ValueError,match="其他 CVE"):
        ap._validate_content(forged,content)


def test_self_consistent_llm_claim_cannot_be_reclassified_as_reviewed_public_sources(tmp_path):
    ap.import_review_run(CVE,RUN,output_root=tmp_path)
    manifest,content=ap.read_review_run(CVE,RUN,output_root=tmp_path)
    claim=VulnerabilityClaim.model_validate_json(content["analysis/vulnerability_claim.json"])
    data=claim.model_dump(mode="python")
    data["fact_status"]="UNREVIEWED"
    for source in data["sources"]:
        source.update(kind="LLM_REASONING",support="ASSERTED")
    forged=_rebind_review(manifest,content,VulnerabilityClaim.model_validate(data))
    with pytest.raises(ValueError,match="LLM"):
        ap._validate_content(forged,content)


def test_hash_consistent_analysis_for_wrong_cve_is_rejected_in_generation_archive(tmp_path):
    from tests.test_baseline import ANALYSIS
    source,record=generation_fixture(tmp_path)
    analysis=deepcopy(ANALYSIS)
    analysis["root_cause_analysis"]["cve_id"]="CVE-2025-23339"
    raw=ap._bytes(analysis)
    (source/"cuda_analysis_v1.json").write_bytes(raw)
    record["analysis_status"]="VALID"
    record["artifacts"]["analysis"]={"file":"cuda_analysis_v1.json","sha256":hashlib.sha256(raw).hexdigest()}
    (source/"cuda_run_v1.json").write_bytes(ap._bytes(record))
    with pytest.raises(ValueError):
        ap.create_generation_run(CVE,RUN,source,record,output_root=tmp_path/"outputs")
