# -*- coding: utf-8 -*-
"""Tavily provider contract: env loading, unconfigured, bad key, search, extract.

The SDK is never called for real here. What is tested is the wiring: credentials come
from the existing .env path, an absent key leaves the agent usable, a failing key is an
observation rather than a crash, and both results land in evidence/artifacts.
"""

import json

import pytest

import agent.tavily_provider as provider
from agent.evidence import ArtifactStore, EvidenceLog, Runner
from agent.memory import ResearchMemory
from agent.registry import build_registry
from agent.workspace import Workspace


class FakeClient:
    def __init__(self, payload=None, error=None):
        self.payload = payload
        self.error = error
        self.calls = []

    def search(self, **kwargs):
        self.calls.append(("search", kwargs))
        if self.error:
            raise self.error
        return self.payload

    def extract(self, urls):
        self.calls.append(("extract", urls))
        if self.error:
            raise self.error
        return self.payload


@pytest.fixture()
def log(tmp_path):
    return EvidenceLog(tmp_path / "evidence.jsonl", ArtifactStore(tmp_path / "artifacts"),
                       run_id="run-tavily")


@pytest.fixture()
def registry_env(tmp_path, log):
    def build():
        return build_registry(Workspace(tmp_path / "ws"), Runner(tmp_path / "ws", log),
                              log, ResearchMemory(tmp_path / "m.jsonl"), search=True)
    return build


def test_dotenv_supplies_the_key(tmp_path, monkeypatch):
    """ConfigLoader reads the key from the project .env, not from a second config file."""
    import src.config_loader as loader_module

    root = tmp_path / "proj"
    (root / "config").mkdir(parents=True)
    (root / "config" / "default.yaml").write_text(
        (loader_module.Path("config/default.yaml")).read_text(encoding="utf-8"),
        encoding="utf-8")
    (root / ".env").write_text("TAVILY_API_KEY=tvly-from-dotenv\n", encoding="utf-8")
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    monkeypatch.setattr(loader_module, "resolve_project_root", lambda: root)

    loader_module.ConfigLoader()
    import os
    assert os.environ.get("TAVILY_API_KEY") == "tvly-from-dotenv"
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)


def test_missing_key_leaves_agent_usable(registry_env, monkeypatch):
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    registry, conflicts, providers = registry_env()
    assert "web_search" not in registry.names()
    assert "shell" in registry.names(), "builtins must survive an absent provider"
    assert providers and providers[0]["provider"] == "tavily"
    assert providers[0]["available"] is False
    assert "not set" in providers[0]["reason"]
    assert conflicts == []


def test_status_reports_missing_sdk(monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-x")
    monkeypatch.setattr(provider, "status", provider.status)
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "tavily":
            raise ImportError("no module")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    state = provider.status()
    assert state["available"] is False
    assert "not installed" in state["reason"]


def test_wrong_key_is_an_observation(registry_env, monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-bad")
    registry, _, _ = registry_env()
    assert "web_search" in registry.names()
    monkeypatch.setattr(provider, "_client",
                        lambda: FakeClient(error=RuntimeError("401 Unauthorized")))
    tool = registry.get("web_search")
    outcome = tool.fn(query="nvJPEG divide by zero")
    assert outcome["ok"] is False
    assert "401" in outcome["summary"]["error"]


def test_search_records_payload_and_artifact(registry_env, monkeypatch, log, tmp_path):
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-good")
    payload = {"results": [{"title": "NVIDIA advisory", "url": "https://nvd.nist.gov/x",
                            "score": 0.91, "raw_content": "text"}]}
    monkeypatch.setattr(provider, "_client", lambda: FakeClient(payload=payload))
    registry, _, _ = registry_env()

    outcome = registry.get("web_search").fn(query="CVE-2026-65160", max_results=3)
    assert outcome["ok"] is True
    assert outcome["summary"]["results"] == 1
    artifact = tmp_path / "artifacts" / outcome["artifacts"][0]["artifact"]
    assert json.loads(artifact.read_text(encoding="utf-8"))["results"][0]["url"].endswith("/x")
    record = log.tail(1)[0]
    assert record["kind"] == "search"
    assert record["payload_sha256"] == outcome["artifacts"][0]["sha256"]


def test_extract_truncates_preview_but_keeps_full_body(registry_env, monkeypatch, tmp_path):
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-good")
    body = "A" * 9000
    payload = {"results": [{"url": "https://example.test/doc", "raw_content": body}]}
    monkeypatch.setattr(provider, "_client", lambda: FakeClient(payload=payload))
    registry, _, _ = registry_env()

    outcome = registry.get("web_extract").fn(url="https://example.test/doc")
    assert outcome["ok"] is True
    assert outcome["summary"]["truncated"] is True
    assert len(outcome["summary"]["content_preview"]) == 4000
    artifact = tmp_path / "artifacts" / outcome["artifacts"][0]["artifact"]
    assert body in artifact.read_text(encoding="utf-8")


def test_key_never_appears_in_evidence(registry_env, monkeypatch, log):
    secret = "tvly-SUPERSECRETVALUE123"
    monkeypatch.setenv("TAVILY_API_KEY", secret)
    monkeypatch.setattr(provider, "_client",
                        lambda: FakeClient(error=RuntimeError("failed for key " + secret)))
    registry, _, _ = registry_env()
    registry.get("web_search").fn(query="x")
    text = log.path.read_text(encoding="utf-8")
    assert secret not in text
    assert "tvly-***REDACTED***" in text
