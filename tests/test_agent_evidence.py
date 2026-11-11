# -*- coding: utf-8 -*-
"""Evidence contract: hash chain, artifacts, redaction, timeout enforcement."""

import json
import sys
from pathlib import Path

import pytest

from agent.evidence import (ArtifactStore, EvidenceLog, Runner, clamp_timeout, redact,
                            verify_chain)


@pytest.fixture()
def log(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    return EvidenceLog(tmp_path / "evidence.jsonl", store, run_id="run-test")


def test_chain_links_and_verifies(log):
    log.append("start", {"goal": "x"})
    log.append("tool", {"tool_name": "shell"})
    log.append("finish", {"stopped": "final"})
    result = verify_chain(log.path)
    assert result["ok"] and result["records"] == 3


def test_chain_detects_deletion(tmp_path, log):
    for index in range(3):
        log.append("tool", {"tool_name": "t%d" % index})
    lines = log.path.read_text(encoding="utf-8").splitlines()
    log.path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    result = verify_chain(log.path)
    assert not result["ok"]
    assert any("sequence" in error or "previous hash" in error for error in result["errors"])


def test_chain_detects_edit(tmp_path, log):
    log.append("tool", {"tool_name": "shell", "value": 1})
    entry = json.loads(log.path.read_text(encoding="utf-8").splitlines()[0])
    entry["value"] = 2
    log.path.write_text(json.dumps(entry, ensure_ascii=False) + "\n", encoding="utf-8")
    result = verify_chain(log.path)
    assert not result["ok"]
    assert any("does not match its hash" in error for error in result["errors"])


def test_chain_detects_reorder(log):
    log.append("tool", {"tool_name": "a"})
    log.append("tool", {"tool_name": "b"})
    lines = log.path.read_text(encoding="utf-8").splitlines()
    log.path.write_text("\n".join([lines[1], lines[0]]) + "\n", encoding="utf-8")
    assert not verify_chain(log.path)["ok"]


def test_full_output_becomes_an_artifact_with_hash(log, tmp_path):
    runner = Runner(tmp_path, log)
    record = runner.run([sys.executable, "-c", "print('x' * 5000)"])
    assert record["truncated"] is True
    assert len(record["stdout_preview"]) == 2000
    artifacts = record["artifacts"]
    assert artifacts and artifacts[0]["bytes"] >= 5000
    saved = tmp_path / "artifacts" / artifacts[0]["artifact"]
    assert saved.is_file()
    assert artifacts[0]["sha256"] == __import__("hashlib").sha256(saved.read_bytes()).hexdigest()


def test_timeout_is_clamped_and_applied(tmp_path, log):
    runner = Runner(tmp_path, log, timeout=30)
    record = runner.run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
    assert record["timed_out"] is True
    assert record["exit"] == -9
    assert record["timeout_seconds"] == 1
    assert record["status"] == "timeout"


def test_timeout_validation():
    assert clamp_timeout(0) is None
    assert clamp_timeout(-5) is None
    assert clamp_timeout("abc") is None
    assert clamp_timeout(999999) == Runner.MAX_TIMEOUT


def test_secrets_are_redacted_before_disk(tmp_path, log):
    runner = Runner(tmp_path, log)
    record = runner.run([sys.executable, "-c",
                         "print('api_key = abcdef1234567890abcdef')"])
    assert "abcdef1234567890abcdef" not in record["stdout_preview"]
    assert record["redactions"] >= 1
    assert "REDACTED" in record["stdout_preview"]


def test_redact_keeps_normal_text():
    text, hits = redact("nothing secret here")
    assert text == "nothing secret here" and hits == 0
