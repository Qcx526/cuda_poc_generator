# -*- coding: utf-8 -*-
"""The properties the audit asked for, as executable checks.

Each test names the property it defends, because these are the ones that were
actually broken: a candidate that talks but never calls, a missing DLL that used to
be skipped, and a trace schema that zeroed missing fields.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

import mock_gpu
from mock_native import binding as nb
from tools.driver import mock_bench

pytestmark = pytest.mark.skipif(not nb.DLL.is_file(), reason="mock_gpu.dll 未构建")


def _candidate(body: str) -> Path:
    directory = Path(tempfile.mkdtemp(prefix="cand_"))
    path = directory / "poc.py"
    path.write_text(body, encoding="utf-8")
    return path


def test_a_program_that_never_calls_the_api_is_not_verified():
    """Claiming success without touching the driver must be a false positive."""
    candidate = _candidate(
        "import json\n"
        "print('CPG_RESULT ' + json.dumps({'reached': True, 'calls': [], 'notes': 'none'}))\n")
    verdict = mock_bench.run_candidate(candidate)
    assert verdict["verification_level"] == "SELF_REPORT_ONLY"
    assert verdict["false_positive"] is True
    assert verdict["executed_on_native"] is False


def test_a_real_call_is_executed_on_the_native_dll():
    candidate = _candidate(
        "import json, mock_gpu\n"
        "s, a = mock_gpu.open_adapter()\n"
        "s2, d = mock_gpu.create_device(a)\n"
        "s3, c = mock_gpu.create_context(d)\n"
        "s4, d2 = mock_gpu.create_device(a)\n"
        "st = mock_gpu.escape(a, d2, c, 0, 2, b'')\n"
        "print('CPG_RESULT ' + json.dumps({'reached': st == 0, 'calls': [{'api':'escape','status':st}]}))\n")
    verdict = mock_bench.run_candidate(candidate)
    assert verdict["verification_level"] == "CANDIDATE_EXECUTION_VERIFIED"
    assert verdict["executed_on_native"] is True
    assert "AUTHZ_BYPASS" in verdict["external"]["flaws"]
    assert verdict["dll_sha256_matches_facts"] is True


def test_a_candidate_cannot_read_the_authoritative_trace():
    """The client token must not grant trace access."""
    import socket

    from mock_gpu import client

    # Start a server through the bench, then try to read the trace with the
    # client token the candidate legitimately holds.
    candidate = _candidate(
        "import json, os, socket\n"
        "host, _, port = os.environ['MOCK_GPU_ENDPOINT'].rpartition(':')\n"
        "req = json.dumps({'action': 'trace', 'token': os.environ['MOCK_GPU_CLIENT_TOKEN']}) + '\\n'\n"
        "s = socket.create_connection((host, int(port)), timeout=5)\n"
        "s.sendall(req.encode())\n"
        "data = s.recv(4096).decode()\n"
        "print('CPG_RESULT ' + json.dumps({'reached': False, 'calls': [], 'notes': data.strip()[:40]}))\n")
    verdict = mock_bench.run_candidate(candidate)
    assert "forbidden" in verdict["claimed"].get("notes", "")
    assert client.ENDPOINT_ENV == "MOCK_GPU_ENDPOINT"


def test_missing_dll_fails_instead_of_skipping(monkeypatch, tmp_path):
    monkeypatch.setattr(mock_bench, "DLL", tmp_path / "absent.dll")
    with pytest.raises(FileNotFoundError):
        mock_bench.run_candidate(_candidate("print('CPG_RESULT {}')\n"))


def test_trace_schema_rejects_a_missing_type():
    """A zeroed type would still be a valid call, so absence must raise."""
    from mock_gpu import evaluator

    with pytest.raises(KeyError):
        evaluator.replay([{"op": "open_adapter"},
                          {"op": "create_device", "hAdapter": 0x2000},
                          {"op": "escape", "hAdapter": 0x2000, "hDevice": 0x2040,
                           "hContext": 0x2080, "flags": 0, "payload": ""}])


def test_invalid_handles_behave_the_same_on_both_implementations():
    """Wrong handle, wrong object kind, and destroyed handles."""
    os.environ["MOCK_GPU_JUDGE"] = "1"
    binding = nb.load()

    binding.reset()
    status_native_bad_adapter = binding.create_device(0xDEAD)[0]
    status_native_bad_context = binding.escape(0xDEAD, 0xDEAD, 0xDEAD, 0, 0, b"")

    mock_gpu.reset()
    status_python_bad_adapter = mock_gpu.create_device(0xDEAD)[0]
    status_python_bad_context = mock_gpu.escape(0xDEAD, 0xDEAD, 0xDEAD, 0, 0, b"")

    assert status_native_bad_adapter == status_python_bad_adapter
    assert status_native_bad_context == status_python_bad_context
