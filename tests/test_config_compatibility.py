"""Offline P3-C reference semantics; no provider requests or real credentials."""

from copy import deepcopy
import importlib
import os
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from src.config_loader import ConfigLoader


PUBLISHED = {
    "model_name": "deepseek-flash",
    "api_base": "https://api.deepseek.com",
    "api_key_env": "DEEPSEEK_API_KEY",
}
PLACEHOLDERS = {
    "model_name": "CPG_LLM_MODEL_NAME",
    "api_base": "CPG_LLM_API_BASE",
    "api_key_env": "CPG_LLM_API_KEY_ENV",
}


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    for key in tuple(os.environ):
        if key.upper() not in {"PATH", "SYSTEMROOT", "COMSPEC", "TEMP", "TMP"}:
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr("src.config_loader.load_dotenv", lambda *args, **kwargs: False)


@pytest.fixture
def configuration(tmp_path):
    def load(fields):
        target = tmp_path / "configuration.yaml"
        target.write_text(yaml.safe_dump({"llm": fields}), encoding="utf-8")
        before = target.read_bytes()
        result = ConfigLoader(str(target))
        assert target.read_bytes() == before
        return result
    return load


@pytest.mark.parametrize("field", PUBLISHED)
def test_precise_legacy_placeholder_uses_published_default(configuration, caplog, field):
    cfg = configuration({field: PLACEHOLDERS[field]})
    assert cfg.llm[field] == PUBLISHED[field]
    assert cfg.configuration_diagnostics == [{
        "field": f"llm.{field}", "code": "LEGACY_PLACEHOLDER_DEFAULT",
    }]
    assert "历史 CPG 占位符" in caplog.text


@pytest.mark.parametrize("field", PUBLISHED)
def test_standard_override_preserves_custom_service(configuration, monkeypatch, field):
    selected = {"model_name": "my-private-model", "api_base": "https://service.invalid/v1",
                "api_key_env": "CUSTOM_PROVIDER_KEY"}[field]
    monkeypatch.setenv(PLACEHOLDERS[field], selected)
    cfg = configuration({field: PLACEHOLDERS[field]})
    assert cfg.llm[field] == selected
    assert cfg.configuration_diagnostics == []


@pytest.mark.parametrize("literal", [
    "MY_MODEL_NAME", "${MY_MODEL_NAME}", "$MY_MODEL_NAME", "prefix-${MY_MODEL_NAME}",
    "CPG_LLM_API_BASE", "https://service.invalid/v1", "custom-model",
])
def test_ordinary_strings_are_not_environment_references(configuration, monkeypatch, literal):
    monkeypatch.setenv("MY_MODEL_NAME", "must-not-be-selected")
    assert configuration({"model_name": literal}).llm["model_name"] == literal


@pytest.mark.parametrize("field", PUBLISHED)
def test_explicit_environment_reference_and_default(configuration, monkeypatch, field):
    reference = {"env": "CUSTOM_SETTING", "default": PUBLISHED[field]}
    assert configuration({field: reference}).llm[field] == PUBLISHED[field]
    monkeypatch.setenv("CUSTOM_SETTING", "custom-selected-value")
    cfg = configuration({field: reference})
    assert cfg.llm[field] == "custom-selected-value"
    assert cfg.configuration_diagnostics[0]["code"] == "EXPLICIT_ENVIRONMENT_REFERENCE"


@pytest.mark.parametrize("field", PUBLISHED)
def test_explicit_literal_escapes_legacy_placeholder(configuration, field):
    assert configuration({field: {"literal": PLACEHOLDERS[field]}}).llm[field] == PLACEHOLDERS[field]


def test_standard_override_precedes_missing_explicit_reference(configuration, monkeypatch):
    monkeypatch.setenv("CPG_LLM_MODEL_NAME", "selected-by-standard-override")
    cfg = configuration({"model_name": {"env": "UNSET_PRIVATE_VARIABLE"}})
    assert cfg.llm["model_name"] == "selected-by-standard-override"


@pytest.mark.parametrize("reference", [
    {"env": "UNSET"}, {"env": ""}, {"env": "BAD-NAME"}, {"env": "${NAME}"},
    {"env": 12}, {"env": "NAME", "default": ""},
    {"env": "NAME", "default": 12}, {"env": "NAME", "extra": "value"},
    {"default": "value"}, {"literal": "", "env": "NAME"}, {"literal": 12},
])
def test_invalid_or_missing_reference_fails_closed(configuration, reference):
    with pytest.raises(ValueError):
        configuration({"model_name": reference})


def test_empty_environment_value_does_not_silently_use_default(configuration, monkeypatch):
    monkeypatch.setenv("CUSTOM_SETTING", "")
    with pytest.raises(ValueError):
        configuration({"model_name": {"env": "CUSTOM_SETTING", "default": "fallback"}})


def test_reference_resolution_is_not_recursive(configuration, monkeypatch):
    monkeypatch.setenv("FIRST", "${SECOND}")
    monkeypatch.setenv("SECOND", "must-not-be-selected")
    assert configuration({"model_name": {"env": "FIRST"}}).llm["model_name"] == "${SECOND}"


def test_reference_error_and_diagnostics_do_not_echo_configuration_values(configuration, caplog):
    private_marker = "SENSITIVE_MARKER_FOR_OFFLINE_TEST"
    with pytest.raises(ValueError) as error:
        configuration({"model_name": {"env": "BAD-NAME", "default": private_marker}})
    assert private_marker not in str(error.value) + caplog.text


def test_user_worktree_configuration_is_not_rewritten():
    target = Path(__file__).resolve().parents[1] / "config" / "default.yaml"
    before = target.read_bytes()
    cfg = ConfigLoader(str(target))
    assert cfg.llm["api_base"] == PUBLISHED["api_base"]
    assert cfg.llm["api_key_env"] == PUBLISHED["api_key_env"]
    assert target.read_bytes() == before


def test_custom_dotenv_and_process_override_without_real_provider(configuration, monkeypatch, tmp_path):
    import dotenv
    module = importlib.import_module("src.config_loader")
    llm_module = importlib.import_module("src.llm_client")
    monkeypatch.setattr(module, "resolve_project_root", lambda: tmp_path)
    monkeypatch.setattr(module, "load_dotenv", dotenv.load_dotenv)
    (tmp_path / ".env").write_text(
        "CPG_LLM_MODEL_NAME=dotenv-custom-model\n"
        "CPG_LLM_API_BASE=https://custom.invalid/v1\n"
        "CPG_LLM_API_KEY_ENV=OFFLINE_CUSTOM_KEY\n"
        "OFFLINE_CUSTOM_KEY=offline-value\n", encoding="utf-8",
    )
    monkeypatch.setenv("CPG_LLM_MODEL_NAME", "process-custom-model")
    with patch.object(llm_module, "ChatOpenAI") as constructor:
        cfg = configuration(deepcopy(PLACEHOLDERS))
        llm_module.LLMClient(cfg)
    assert cfg.llm == {
        "model_name": "process-custom-model", "api_base": "https://custom.invalid/v1",
        "api_key_env": "OFFLINE_CUSTOM_KEY",
    }
    assert constructor.call_args.kwargs["api_key"] == "offline-value"
    assert constructor.call_args.kwargs["base_url"] == cfg.llm["api_base"]
    constructor.return_value.invoke.assert_not_called()


def test_api_key_env_reference_returns_key_variable_name_not_key(configuration, monkeypatch):
    monkeypatch.setenv("KEY_SELECTOR", "OFFLINE_CUSTOM_KEY")
    monkeypatch.setenv("OFFLINE_CUSTOM_KEY", "offline-secret-value")
    cfg = configuration({"api_key_env": {"env": "KEY_SELECTOR"}})
    assert cfg.llm["api_key_env"] == "OFFLINE_CUSTOM_KEY"
    assert "offline-secret-value" not in repr(cfg.config) + repr(cfg.configuration_diagnostics)
