# -*- coding: utf-8 -*-
"""Observation records must not launder evidence."""

import json
from pathlib import Path

from src import driver_observation as obs


def test_a_userland_call_is_direct_but_scoped():
    record = obs.Observation(obs.SOURCE_USERLAND, "api_call", "t", "exp", 1, "sig",
                             {"api": "D3DKMTEscape", "status": 0xC000000D},
                             "log", obs.DIRECT, "仅证明用户态返回值，不证明内核执行")
    assert record.confidence == obs.DIRECT
    assert "内核" in record.limitations


def test_etw_without_a_file_is_unavailable_not_empty():
    record = obs.from_etw("exp", 1, Path("does/not/exist.json"))
    assert record.confidence == obs.UNAVAILABLE
    assert record.observed == {}


def test_etw_summary_stays_indirect_and_says_why(tmp_path):
    summary = tmp_path / "s.json"
    summary.write_text(json.dumps({"total": 10, "by_task": {"68": 9}}), encoding="utf-8")
    record = obs.from_etw("exp", 1, summary)
    assert record.confidence == obs.INDIRECT
    assert "不能证明" in record.limitations


def test_run_log_becomes_one_observation_per_call(tmp_path):
    log = tmp_path / "run.log"
    claims = {"calls": [{"api": "A", "status": 0}, {"api": "B", "status": 1}]}
    log.write_text("CPG_PROBE x\nCPG_CLAIMS " + json.dumps(claims), encoding="utf-8")
    records = obs.from_run_log("exp", 1, log)
    assert [r.observed["api"] for r in records] == ["A", "B"]


def test_prompt_block_marks_unavailable_explicitly():
    text = obs.prompt_block([
        {"source": "etw:DxgKrnl", "event_type": "etw_summary", "observed": {},
         "confidence": obs.UNAVAILABLE, "limitations": "无 ETL"}])
    assert "UNAVAILABLE" in text
    assert "不得当作已证明" in text


def test_save_and_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(obs, "STORE", tmp_path)
    items = [obs.Observation(obs.SOURCE_MOCK, "mock_call", "t", "exp", 1, "sig")]
    obs.save(items, "unit")
    loaded = obs.load("unit")
    assert loaded and loaded[0]["source"] == obs.SOURCE_MOCK
