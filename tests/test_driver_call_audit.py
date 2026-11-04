# -*- coding: utf-8 -*-
"""Escape accounting: a call on dead objects is not exploration."""

import json
from pathlib import Path

from src import driver_call_audit as audit


def _log(tmp_path, calls):
    path = Path(tmp_path) / "round1"
    path.mkdir()
    target = path / "run.log"
    target.write_text("CPG_PROBE x\nCPG_CLAIMS " + json.dumps({"calls": calls}),
                      encoding="utf-8")
    return target


def test_an_escape_after_failed_create_device_is_invalid_setup(tmp_path):
    log = _log(tmp_path, [
        {"api": "D3DKMTOpenAdapterFromHdc", "status": 0},
        {"api": "D3DKMTCreateDevice", "status": 0xC000000D},
        {"api": "D3DKMTEscape(Type=0,Flags=0,hDevice=0x1,hContext=0x2)", "status": 0xC000000D},
    ])
    verdicts = audit.audit_round(log, "round1")
    assert verdicts[0].kind == audit.INVALID_SETUP
    assert any("device" in reason for reason in verdicts[0].reasons)


def test_a_properly_built_chain_counts_as_input_rejected(tmp_path):
    log = _log(tmp_path, [
        {"api": "D3DKMTOpenAdapterFromHdc", "status": 0},
        {"api": "D3DKMTCreateDevice", "status": 0},
        {"api": "D3DKMTEscape(Type=0,Flags=0,hDevice=0x1,hContext=0x2)", "status": 0xC000000D},
    ])
    verdicts = audit.audit_round(log, "round1")
    assert verdicts[0].kind == audit.INPUT_REJECTED
    assert verdicts[0].setup_valid is True


def test_a_zero_handle_marks_the_call_invalid(tmp_path):
    log = _log(tmp_path, [
        {"api": "D3DKMTOpenAdapterFromHdc", "status": 0},
        {"api": "D3DKMTCreateDevice", "status": 0},
        {"api": "D3DKMTEscape(Type=0,hDevice=0x1,hContext=0)", "status": 0xC000000D},
    ])
    verdicts = audit.audit_round(log, "round1")
    assert verdicts[0].kind == audit.INVALID_SETUP


def test_raw_status_is_preserved(tmp_path):
    log = _log(tmp_path, [
        {"api": "D3DKMTOpenAdapterFromHdc", "status": 0},
        {"api": "D3DKMTCreateDevice", "status": 0},
        {"api": "D3DKMTEscape(hDevice=0x1,hContext=0x2)", "status": -1073741811},
    ])
    verdict = audit.audit_round(log, "round1")[0]
    assert verdict.status == -1073741811
    assert verdict.kind == audit.INPUT_REJECTED


def test_summary_counts_only_setup_valid_calls_as_exploration(tmp_path):
    log = _log(tmp_path, [
        {"api": "D3DKMTOpenAdapterFromHdc", "status": 0},
        {"api": "D3DKMTCreateDevice", "status": 0xC000000D},
        {"api": "D3DKMTEscape(hDevice=1,hContext=2)", "status": 0xC000000D},
    ])
    summary = audit.summarise(audit.audit_round(log, "round1"))
    assert summary["escapes"] == 1
    assert summary["valid_explorations"] == 0
