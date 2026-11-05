# -*- coding: utf-8 -*-
"""Blind-run guarantees: what the model may see, and what the candidate may reach.

Two separate leaks are covered here. The first is epistemic: the oracle verdict
reaching round 2's prompt. The second is environmental: the candidate inheriting
the provider key because it was launched with the parent's environment.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from mock_native import binding as nb
from tools.driver import mock_bench, mock_experiment

pytestmark = pytest.mark.native_required

FORBIDDEN = ("oracle_confirmed", "flaws", "trigger_count", "AUTHZ_BYPASS", "OOB_READ")


class _StubClient:
    """Returns the same trivial program twice, so round 2 is reachable cheaply."""

    def __init__(self):
        self.calls = 0

    def chat(self, messages, temperature=0.1):
        self.calls += 1
        return ("```python\nimport json, mock_gpu\n"
                "s, a = mock_gpu.open_adapter()\n"
                "print('CPG_RESULT ' + json.dumps({'reached': False, 'calls': []}))\n"
                "```\n")


def test_public_feedback_drops_every_oracle_field():
    verdict = {"exit_code": 0, "ran": True,
               "external": {"triggered": True, "flaws": ["AUTHZ_BYPASS"],
                            "facts": {"oracle_confirmed": True},
                            "trace": [{"op": "escape", "status": 0}]},
               "facts": {"oracle_confirmed": True},
               "stderr_tail": ""}
    feedback = mock_experiment.public_feedback(verdict)
    text = json.dumps(feedback)
    for word in FORBIDDEN:
        assert word not in text
    assert feedback["calls"] == [{"op": "escape", "status": 0}]


def test_round_two_prompt_contains_no_oracle_truth(tmp_path):
    """End-to-end: run two rounds and read the prompt that round 2 actually got."""
    stub = _StubClient()
    workdir = tmp_path / "runs"
    mock_experiment.run("leakcheck", rounds=2, workdir=workdir, client=stub)
    prompt = (workdir / "leakcheck" / "round2" / "prompt.txt").read_text(encoding="utf-8")
    for word in FORBIDDEN:
        assert word not in prompt, "round2 prompt leaked %s" % word
    assert stub.calls == 2


def test_candidate_cannot_read_the_provider_key_or_dotenv():
    """The key lives in the parent environment; it must not be inherited."""
    directory = Path(tempfile.mkdtemp(prefix="cred_"))
    candidate = directory / "poc.py"
    candidate.write_text(
        "import json, os\n"
        "leaks = []\n"
        "if 'DEEPSEEK_API_KEY' in os.environ:\n"
        "    leaks.append('env_key')\n"
        "for name in ('.env', 'config/default.yaml'):\n"
        "    try:\n"
        "        open(name, encoding='utf-8').read(64)\n"
        "        leaks.append('file:' + name)\n"
        "    except OSError:\n"
        "        pass\n"
        "try:\n"
        "    import src.config_loader  # noqa: F401\n"
        "    leaks.append('import_config')\n"
        "except Exception:\n"
        "    pass\n"
        "import mock_gpu\n"
        "s, a = mock_gpu.open_adapter()\n"
        "print('CPG_RESULT ' + json.dumps({'reached': False, 'calls': [],"
        " 'notes': 'leaks=%d adapter_ok=%s' % (len(leaks), s == 0)}))\n",
        encoding="utf-8")
    verdict = mock_bench.run_candidate(candidate)
    notes = verdict["claimed"].get("notes", "")
    assert "leaks=0" in notes
    assert "adapter_ok=True" in notes


def test_a_rejected_request_is_not_recorded_as_a_trigger():
    """Cross-device + PRIVILEGED but an invalid payload: rejected, not triggered."""
    import mock_gpu

    os.environ["MOCK_GPU_JUDGE"] = "1"
    binding = nb.load()

    for api in (binding,):
        api.reset()
        _, adapter = api.open_adapter()
        _, device_a = api.create_device(adapter)
        _, context_a = api.create_context(device_a)
        _, device_b = api.create_device(adapter)
        huge = (9999).to_bytes(4, "little") + b"\x00" * 4
        status = api.escape(adapter, device_b, context_a, 3, 0x2, huge)
        assert status == 0xC000000D, "预期拒绝，实际 %x" % status
        assert api.triggers() == []

    mock_gpu.reset()
    _, adapter = mock_gpu.open_adapter()
    _, device_a = mock_gpu.create_device(adapter)
    _, context_a = mock_gpu.create_context(device_a)
    _, device_b = mock_gpu.create_device(adapter)
    status = mock_gpu.escape(adapter, device_b, context_a, 3, 0x2, huge)
    assert status == 0xC000000D
    from mock_gpu import api as mock_api
    assert mock_api.call_trace()[-1]["status"] == 0xC000000D


def test_trace_carries_a_payload_digest_for_offline_replay():
    directory = Path(tempfile.mkdtemp(prefix="dig_"))
    candidate = directory / "poc.py"
    candidate.write_text(
        "import json, mock_gpu\n"
        "s, a = mock_gpu.open_adapter()\n"
        "s2, d = mock_gpu.create_device(a)\n"
        "s3, c = mock_gpu.create_context(d)\n"
        "body = b'\\x00' * 4\n"
        "payload = (len(body) + 1).to_bytes(4, 'little') + body\n"
        "st = mock_gpu.escape(a, d, c, 3, 0, payload)\n"
        "print('CPG_RESULT ' + json.dumps({'reached': st == 0, 'calls': []}))\n",
        encoding="utf-8")
    trace_path = directory / "trace.json"
    verdict = mock_bench.run_candidate(candidate, trace_path=trace_path)

    escape_steps = [s for s in verdict["external"]["trace"] if s["op"] == "escape"]
    assert escape_steps, "没有 escape 记录"
    assert len(escape_steps[0]["payload_sha256"]) == 64
    assert escape_steps[0]["payload_hex"] == "0500000000000000"
    assert verdict["facts"]["oracle_confirmed"] is True
    saved = json.loads(trace_path.read_text(encoding="utf-8"))
    assert saved["trace"][-1]["payload_sha256"] == escape_steps[0]["payload_sha256"]


def _run_poc(body: str):
    directory = Path(tempfile.mkdtemp(prefix="pl_"))
    candidate = directory / "poc.py"
    candidate.write_text(body, encoding="utf-8")
    trace_path = directory / "trace.json"
    return mock_bench.run_candidate(candidate, trace_path=trace_path), trace_path


def _escape_steps(verdict):
    return [s for s in verdict["external"]["trace"] if s["op"] == "escape"]


def test_a_short_payload_is_recorded_in_full():
    verdict, _ = _run_poc(
        "import json, mock_gpu\n"
        "s, a = mock_gpu.open_adapter()\n"
        "_, d = mock_gpu.create_device(a)\n"
        "_, c = mock_gpu.create_context(d)\n"
        "st = mock_gpu.escape(a, d, c, 0, 0, b'\\x7f')\n"
        "print('CPG_RESULT ' + json.dumps({'reached': st == 0, 'calls': []}))\n")
    step = _escape_steps(verdict)[0]
    assert step["payload_hex"] == "7f"
    assert step["payload_len"] == 1
    assert step["replayable"] is True


def test_a_payload_over_128_bytes_is_recorded_without_truncation():
    verdict, trace_path = _run_poc(
        "import json, mock_gpu, hashlib\n"
        "s, a = mock_gpu.open_adapter()\n"
        "_, d = mock_gpu.create_device(a)\n"
        "_, c = mock_gpu.create_context(d)\n"
        "payload = bytes(range(200))\n"
        "st = mock_gpu.escape(a, d, c, 0, 0, payload)\n"
        "print('CPG_RESULT ' + json.dumps({'reached': st == 0, 'calls': [],"
        " 'notes': hashlib.sha256(payload).hexdigest()}))\n")
    step = _escape_steps(verdict)[0]
    assert step["payload_len"] == 200
    assert len(step["payload_hex"]) == 400        # 完整，不是前缀
    assert step["payload_sha256"] == verdict["claimed"]["notes"]
    saved = json.loads(trace_path.read_text(encoding="utf-8"))
    assert saved["trace"][-1]["payload_hex"] == step["payload_hex"]


def test_a_rejected_payload_is_still_recorded_with_its_status():
    verdict, _ = _run_poc(
        "import json, mock_gpu\n"
        "s, a = mock_gpu.open_adapter()\n"
        "_, d = mock_gpu.create_device(a)\n"
        "_, c = mock_gpu.create_context(d)\n"
        "payload = (9999).to_bytes(4, 'little') + b'\\x00' * 4\n"
        "st = mock_gpu.escape(a, d, c, 3, 0, payload)\n"
        "print('CPG_RESULT ' + json.dumps({'reached': False, 'calls': [{'api':'escape','status':st}]}))\n")
    step = _escape_steps(verdict)[0]
    assert step["status"] == 0xC000000D
    assert step["payload_len"] == 8
    assert verdict["facts"]["oracle_confirmed"] is False


def test_the_recorded_digest_matches_what_was_executed():
    verdict, _ = _run_poc(
        "import json, mock_gpu, hashlib\n"
        "s, a = mock_gpu.open_adapter()\n"
        "_, d = mock_gpu.create_device(a)\n"
        "_, c = mock_gpu.create_context(d)\n"
        "body = b'\\x11' * 40\n"
        "payload = len(body).to_bytes(4, 'little') + body\n"
        "st = mock_gpu.escape(a, d, c, 1, 0, payload)\n"
        "print('CPG_RESULT ' + json.dumps({'reached': st == 0, 'calls': [],"
        " 'notes': hashlib.sha256(payload).hexdigest()}))\n")
    step = _escape_steps(verdict)[0]
    import hashlib
    expected = hashlib.sha256(len(b"\x11" * 40).to_bytes(4, "little") + b"\x11" * 40).hexdigest()
    assert step["payload_sha256"] == expected
