# -*- coding: utf-8 -*-
"""Native benchmark acceptance: these must fail, not skip, when the DLL is absent.

The earlier version put a module-level skipif here, which meant a machine without
MSVC silently "passed" the acceptance suite. Offline parity tests may skip; the
benchmark acceptance may not.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from mock_native import binding as nb
from tools.driver import mock_bench

pytestmark = pytest.mark.native_required


@pytest.fixture(scope="module", autouse=True)
def require_native_dll():
    if not nb.DLL.is_file():
        pytest.fail("原生 DLL 缺失，正式验收不允许跳过: %s" % nb.DLL, pytrace=False)


def _candidate(body: str) -> Path:
    directory = Path(tempfile.mkdtemp(prefix="cand_"))
    path = directory / "poc.py"
    path.write_text(body, encoding="utf-8")
    return path


def test_claiming_success_without_calling_is_a_false_positive():
    candidate = _candidate(
        "import json\n"
        "print('CPG_RESULT ' + json.dumps({'reached': True, 'calls': [], 'notes': 'none'}))\n")
    verdict = mock_bench.run_candidate(candidate)
    assert verdict["verification_level"] == "SELF_REPORT_ONLY"
    assert verdict["false_positive"] is True
    assert verdict["facts"]["native_api_called"] is False


def test_a_full_poc_reaches_trigger_confirmed():
    candidate = _candidate(
        "import json, mock_gpu\n"
        "s, a = mock_gpu.open_adapter()\n"
        "s2, d = mock_gpu.create_device(a)\n"
        "s3, c = mock_gpu.create_context(d)\n"
        "s4, d2 = mock_gpu.create_device(a)\n"
        "st = mock_gpu.escape(a, d2, c, 0, 2, b'')\n"
        "print('CPG_RESULT ' + json.dumps({'reached': st == 0, 'calls': [{'api':'escape','status':st}]}))\n")
    verdict = mock_bench.run_candidate(candidate)
    assert verdict["verification_level"] == "TRIGGER_CONFIRMED"
    facts = verdict["facts"]
    assert facts["native_api_called"] is True
    assert facts["valid_objects_built"] is True
    assert facts["escape_called"] is True
    assert facts["escape_with_valid_objects"] is True
    assert facts["oracle_confirmed"] is True
    assert verdict["dll_sha256_matches_facts"] is True


def test_objects_built_without_escape_is_a_distinct_level():
    candidate = _candidate(
        "import json, mock_gpu\n"
        "s, a = mock_gpu.open_adapter()\n"
        "s2, d = mock_gpu.create_device(a)\n"
        "s3, c = mock_gpu.create_context(d)\n"
        "print('CPG_RESULT ' + json.dumps({'reached': False, 'calls': []}))\n")
    verdict = mock_bench.run_candidate(candidate)
    assert verdict["verification_level"] == "OBJECTS_BUILT_ONLY"
    assert verdict["facts"]["escape_called"] is False


def test_escape_on_dead_objects_is_not_a_valid_escape():
    candidate = _candidate(
        "import json, mock_gpu\n"
        "s, a = mock_gpu.open_adapter()\n"
        "s2, d = mock_gpu.create_device(a)\n"
        "s3, c = mock_gpu.create_context(d)\n"
        "mock_gpu.destroy_context(c)\n"
        "st = mock_gpu.escape(a, d, c, 0, 0, b'')\n"
        "print('CPG_RESULT ' + json.dumps({'reached': False, 'calls': [{'api':'escape','status':st}]}))\n")
    verdict = mock_bench.run_candidate(candidate)
    assert verdict["verification_level"] == "ESCAPE_WITH_INVALID_OBJECTS"
    assert verdict["facts"]["escape_with_valid_objects"] is False


def test_a_candidate_cannot_read_the_authoritative_trace():
    candidate = _candidate(
        "import json, os, socket\n"
        "host, _, port = os.environ['MOCK_GPU_ENDPOINT'].rpartition(':')\n"
        "req = json.dumps({'action': 'trace', 'token': os.environ['MOCK_GPU_CLIENT_TOKEN']}) + '\\n'\n"
        "s = socket.create_connection((host, int(port)), timeout=5)\n"
        "s.sendall(req.encode())\n"
        "print('CPG_RESULT ' + json.dumps({'reached': False, 'calls': [], 'notes': s.recv(4096).decode()}))\n")
    verdict = mock_bench.run_candidate(candidate)
    assert "forbidden" in verdict["claimed"].get("notes", "")


def test_a_candidate_cannot_find_the_judge_token_anywhere():
    """Hunt the way a hostile candidate would: env, temp, cwd.

    Either the token is absent, or the isolation claim is false and this test says so.
    """
    candidate = _candidate(
        "import json, os, glob, tempfile\n"
        "hits = []\n"
        "for key in os.environ:\n"
        "    if 'JUDGE' in key.upper():\n"
        "        hits.append('env:' + key)\n"
        "for pattern in (tempfile.gettempdir() + '/*.json', tempfile.gettempdir() + '/bench_*/*', 'secrets.json'):\n"
        "    for path in glob.glob(pattern):\n"
        "        try:\n"
        "            text = open(path, encoding='utf-8', errors='ignore').read(4096)\n"
        "        except OSError:\n"
        "            continue\n"
        "        if 'judge_token' in text:\n"
        "            hits.append('file:' + path)\n"
        "print('CPG_RESULT ' + json.dumps({'reached': False, 'calls': [], 'notes': 'hits=%d' % len(hits)}))\n")
    verdict = mock_bench.run_candidate(candidate)
    assert verdict["claimed"]["notes"] == "hits=0"


def test_missing_dll_fails_instead_of_skipping(monkeypatch, tmp_path):
    monkeypatch.setattr(mock_bench, "DLL", tmp_path / "absent.dll")
    with pytest.raises(FileNotFoundError):
        mock_bench.run_candidate(_candidate("print('CPG_RESULT {}')\n"))
