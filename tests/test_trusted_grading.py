# -*- coding: utf-8 -*-
"""A candidate's printed exit code never decides a verdict on its own."""

import json
from pathlib import Path

from src.trusted_grading import (MATCHED, NO_CLAIM, UNSUPPORTED, reconcile,
                                 runs_from_trusted, trust_status)


def _trusted(tmp_path: Path, invocations) -> Path:
    path = tmp_path / "iteration_1_trusted.json"
    path.write_text(json.dumps({"invocations": invocations}, ensure_ascii=False),
                    encoding="utf-8")
    return path


def _inv(tool, name, exit_code, sha="a" * 64, version="v1"):
    return {"run_id": "d:%s:%s" % (tool, name), "tool": tool, "tool_version": version,
            "input_sha256": sha, "exit_code": exit_code, "stdout": "", "stderr": ""}


def test_forged_crash_is_a_mismatch_not_a_verdict(tmp_path):
    claims = "[CPG_RUN] fake.cubin::nvdisasm exit=139\n[CPG_LABEL] fake.cubin MALICIOUS\n"
    trusted = _trusted(tmp_path, [_inv("nvdisasm", "fake.cubin", 0)])
    result = reconcile(claims, trusted)
    assert result["mismatched"], "声称 139、实测 0 必须记为不符"
    assert not result["matched"]


def test_matching_claim_is_matched(tmp_path):
    claims = "[CPG_RUN] benign.cubin::nvdisasm exit=0\n"
    trusted = _trusted(tmp_path, [_inv("nvdisasm", "benign.cubin", 0)])
    assert reconcile(claims, trusted)["matched"][0]["file"] == "benign.cubin"


def test_legacy_line_is_reported_as_unsupported(tmp_path):
    claims = "[CPG_RUN] poc.cubin exit=-11\n"
    trusted = _trusted(tmp_path, [_inv("nvdisasm", "poc.cubin", 139)])
    result = reconcile(claims, trusted)
    assert result["unsupported"], "无工具名的旧格式不能被猜成 nvdisasm"
    assert result["legacy_count"] == 1


def test_no_claims_is_not_success(tmp_path):
    trusted = _trusted(tmp_path, [_inv("nvdisasm", "poc.cubin", 139)])
    result = reconcile("", trusted)
    assert result["no_claim"] is True
    assert not result["matched"]


def test_missing_trusted_record_is_evidence_missing(tmp_path):
    status = trust_status(tmp_path / "nope.json", "[CPG_RUN] poc::nvdisasm exit=139")
    assert status["level"] == "EVIDENCE_MISSING"


def test_runs_carry_sha_and_tool_version(tmp_path):
    trusted = _trusted(tmp_path, [_inv("cuobjdump", "poc.cubin", 139, sha="b" * 64,
                                       version="cuobjdump v9")])
    runs = runs_from_trusted(trusted, "[CPG_LABEL] poc.cubin MALICIOUS\n")
    assert runs[0]["sha256"] == "b" * 64
    assert runs[0]["tool_version"] == "cuobjdump v9"
    assert runs[0]["label"] == "MALICIOUS"
