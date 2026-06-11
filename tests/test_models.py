"""Tests for configurable LLM provider routing."""

import pytest

from spider.config import SpiderConfig
from spider.models import get_lm


class DummyLM:
    """Capture DSPy LM constructor arguments without calling providers."""

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.model = kwargs["model"]


def test_get_lm_forces_openrouter(monkeypatch):
    """OpenRouter provider should bypass Ollama availability checks."""
    monkeypatch.setattr("spider.models.dspy.LM", DummyLM)
    monkeypatch.setattr("spider.models._ollama_available", lambda _base_url: True)

    config = SpiderConfig(
        _env_file=None,
        model_provider="openrouter",
        openrouter_api_key="test-key",
        fallback_model="openrouter/openai/gpt-4o-mini",
    )

    lm = get_lm(config)

    assert lm.model == "openrouter/openai/gpt-4o-mini"
    assert lm.kwargs["api_key"] == "test-key"
    assert "api_base" not in lm.kwargs


def test_get_lm_prefixes_bare_openrouter_model(monkeypatch):
    """Bare OpenRouter model IDs should be normalized for LiteLLM routing."""
    monkeypatch.setattr("spider.models.dspy.LM", DummyLM)

    config = SpiderConfig(
        _env_file=None,
        model_provider="openrouter",
        openrouter_api_key="test-key",
        fallback_model="inclusionai/ling-2.6-1t",
    )

    lm = get_lm(config)

    assert lm.model == "openrouter/inclusionai/ling-2.6-1t"


def test_get_lm_forces_ollama_even_with_openrouter_key(monkeypatch):
    """Ollama provider should not fall back when explicitly selected."""
    monkeypatch.setattr("spider.models.dspy.LM", DummyLM)
    monkeypatch.setattr("spider.models._ollama_available", lambda _base_url: False)

    config = SpiderConfig(
        _env_file=None,
        model_provider="ollama",
        openrouter_api_key="test-key",
        primary_model="local-model",
        ollama_base_url="http://ollama.test:11434",
    )

    lm = get_lm(config)

    assert lm.model == "ollama/local-model"
    assert lm.kwargs["api_base"] == "http://ollama.test:11434"
    assert "api_key" not in lm.kwargs


def test_get_lm_auto_uses_openrouter_when_ollama_is_unavailable(monkeypatch):
    """Auto provider should preserve cloud fallback when local Ollama is down."""
    monkeypatch.setattr("spider.models.dspy.LM", DummyLM)
    monkeypatch.setattr("spider.models._ollama_available", lambda _base_url: False)

    config = SpiderConfig(
        _env_file=None,
        model_provider="auto",
        openrouter_api_key="test-key",
        fallback_model="openrouter/anthropic/claude-3.5-sonnet",
    )

    lm = get_lm(config)

    assert lm.model == "openrouter/anthropic/claude-3.5-sonnet"
    assert lm.kwargs["api_key"] == "test-key"


def test_get_lm_openrouter_requires_api_key(monkeypatch):
    """Forced OpenRouter should fail clearly without credentials."""
    monkeypatch.setattr("spider.models.dspy.LM", DummyLM)
    monkeypatch.delenv("SPIDER_OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    config = SpiderConfig(_env_file=None, model_provider="openrouter")

    with pytest.raises(ValueError, match="SPIDER_OPENROUTER_API_KEY"):
        get_lm(config)


def test_config_accepts_prefixed_and_legacy_env_names(monkeypatch):
    """Documented SPIDER_* names and legacy unprefixed names should both work."""
    monkeypatch.setenv("SPIDER_MODEL_PROVIDER", "openrouter")
    monkeypatch.setenv("SPIDER_OPENROUTER_API_KEY", "prefixed-key")
    monkeypatch.setenv("FALLBACK_MODEL", "openrouter/openai/gpt-4o-mini")

    config = SpiderConfig(_env_file=None)

    assert config.model_provider == "openrouter"
    assert config.openrouter_api_key == "prefixed-key"
    assert config.fallback_model == "openrouter/openai/gpt-4o-mini"
