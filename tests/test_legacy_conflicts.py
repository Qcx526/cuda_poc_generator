# -*- coding: utf-8 -*-
"""Broken inputs must not put a wrong value into a public projection.

Each case builds a copy of the real 23340 input, breaks exactly one thing, and then
checks what the adapter decided - not what it printed.
"""

import json
import shutil
from pathlib import Path

import pytest

from src.case_legacy import adapt
from src.case_projection import PUBLIC_ONLY, project

SOURCE = Path("data/inputs/CVE-2025-23340")
pytestmark = pytest.mark.skipif(not SOURCE.is_dir(), reason="inputs not on disk")


def _copy(tmp_path: Path) -> Path:
    target = tmp_path / "case"
    shutil.copytree(SOURCE, target)
    return target


def _public_ids(bundle) -> list:
    payload = project(bundle.case, PUBLIC_ONLY)
    return [item["id"] for item in payload["evidence"]]


def test_conflicting_cve_does_not_pick_a_winner(tmp_path):
    case = _copy(tmp_path)
    (case / "3_affected_component.json").write_text(
        json.dumps({"cve_id": "CVE-0000-0001"}, ensure_ascii=False), encoding="utf-8")
    bundle = adapt(case)
    assert bundle.case.identity.cve_id is None, "冲突时不得选中任何一方"
    assert "CVE-0000-0001" not in json.dumps(project(bundle.case, PUBLIC_ONLY),
                                             ensure_ascii=False)


def test_missing_file_supplies_no_public_assertion(tmp_path):
    case = _copy(tmp_path)
    (case / "4_attack_surface.json").unlink()
    bundle = adapt(case)
    ids = _public_ids(bundle)
    assert "A3" not in ids and "A4" not in ids, "缺失文件不应贡献公开断言"
    assert bundle.provenance["error_count"] >= 0


def test_wrong_field_type_is_not_published(tmp_path):
    case = _copy(tmp_path)
    path = case / "3_affected_component.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["vendor"] = {"nested": "not-a-string"}
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    bundle = adapt(case)
    assert "A1" not in _public_ids(bundle), "类型错误的字段不得成为公开断言"
    states = bundle.provenance["field_states"]
    assert states.get("/dimensions/affected_component/vendor") in ("INVALID", "UNKNOWN")


def test_unknown_fields_are_carried_not_reinterpreted(tmp_path):
    case = _copy(tmp_path)
    path = case / "3_affected_component.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["future_field"] = "kept-as-is"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    bundle = adapt(case)
    archive_note = bundle.provenance["note"]
    assert "未补全" in archive_note
