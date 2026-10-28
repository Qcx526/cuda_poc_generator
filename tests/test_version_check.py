# -*- coding: utf-8 -*-
"""A finding accumulates versions; it does not get overwritten by the newest one."""

import json

from src.version_check import record


def _finding(tmp_path):
    meta = {"cve_id": "CVE-X", "artifact": "poc.cubin", "fingerprint": "a+0x1000"}
    (tmp_path / "finding.json").write_text(json.dumps(meta), encoding="utf-8")
    return tmp_path / "finding.json"


def test_a_second_version_is_appended(tmp_path):
    path = _finding(tmp_path)
    record(tmp_path, {"image": "img-a", "crashed": True, "exit_code": 139})
    record(tmp_path, {"image": "img-b", "crashed": False, "exit_code": 0})
    versions = json.loads(path.read_text(encoding="utf-8"))["versions"]
    assert [row["image"] for row in versions] == ["img-a", "img-b"]


def test_re_running_the_same_image_replaces_its_entry(tmp_path):
    path = _finding(tmp_path)
    record(tmp_path, {"image": "img-a", "crashed": True, "exit_code": 139})
    record(tmp_path, {"image": "img-a", "crashed": False, "exit_code": 0})
    versions = json.loads(path.read_text(encoding="utf-8"))["versions"]
    assert len(versions) == 1
    assert versions[0]["crashed"] is False


def test_the_original_finding_is_left_alone(tmp_path):
    path = _finding(tmp_path)
    record(tmp_path, {"image": "img-a", "crashed": True})
    meta = json.loads(path.read_text(encoding="utf-8"))
    assert meta["fingerprint"] == "a+0x1000"
    assert meta["artifact"] == "poc.cubin"
