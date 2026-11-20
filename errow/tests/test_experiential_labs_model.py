"""Experiential Labs DeepSeek V4.1 Flash Uncensored connection defaults."""

from __future__ import annotations

import pytest

from errow.config.settings import EXPERIENTIAL_LABS_API_BASE, LlmSettings


_MODEL = "openai/deepseek-v4.1-flash-uncensored"
_ENV_KEYS = [
    "errow_LLM",
    "LLM_API_KEY",
    "OPENAI_API_KEY",
    "LLM_API_BASE",
    "OPENAI_API_BASE",
    "OPENAI_BASE_URL",
    "LITELLM_BASE_URL",
    "OLLAMA_API_BASE",
    "EXPLABS_API_KEY",
    "EXPLABS_BASE_URL",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_defaults_base_url_and_reads_explabs_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("errow_LLM", _MODEL)
    monkeypatch.setenv("EXPLABS_API_KEY", "key-1")
    llm = LlmSettings()
    assert llm.api_base == EXPERIENTIAL_LABS_API_BASE
    assert llm.api_key == "key-1"


def test_explabs_base_url_env_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("errow_LLM", _MODEL)
    monkeypatch.setenv("EXPLABS_BASE_URL", "https://gw.example/v1")
    assert LlmSettings().api_base == "https://gw.example/v1"


def test_explicit_llm_vars_win(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("errow_LLM", _MODEL)
    monkeypatch.setenv("LLM_API_KEY", "explicit")
    monkeypatch.setenv("LLM_API_BASE", "https://explicit.example/v1")
    monkeypatch.setenv("EXPLABS_API_KEY", "other")
    llm = LlmSettings()
    assert llm.api_key == "explicit"
    assert llm.api_base == "https://explicit.example/v1"


def test_other_models_untouched(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("errow_LLM", "openai/gpt-5.4")
    monkeypatch.setenv("EXPLABS_API_KEY", "key-1")
    llm = LlmSettings()
    assert llm.api_base is None
    assert llm.api_key is None
