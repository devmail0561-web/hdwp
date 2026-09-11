# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

"""Tests for multi-provider LLM support."""
from __future__ import annotations

import os
from unittest.mock import patch

import importlib.util

import pytest

_has_openai = importlib.util.find_spec("openai") is not None
_skip_no_openai = pytest.mark.skipif(not _has_openai, reason="openai package not installed")

from hdwp.core.context.config_schema import LLMConfig
from hdwp.core.llm.layer import (
    AnthropicLLMLayer,
    OpenAICompatibleLLMLayer,
    create_llm_layer,
)


def test_create_llm_layer_no_config_no_key() -> None:
    """No config, no ANTHROPIC_API_KEY → None."""
    with patch.dict(os.environ, {}, clear=True):
        # Ensure ANTHROPIC_API_KEY is absent
        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            result = create_llm_layer(None)
    assert result is None


def test_create_llm_layer_legacy_anthropic() -> None:
    """No config, ANTHROPIC_API_KEY set → AnthropicLLMLayer (legacy compat)."""
    import sys
    import types
    # Provide a stub anthropic module so the import in AnthropicLLMLayer succeeds
    stub = types.ModuleType("anthropic")
    stub.AsyncAnthropic = lambda **kw: object()  # type: ignore[attr-defined]
    with patch.dict(sys.modules, {"anthropic": stub}):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            result = create_llm_layer(None)
    assert isinstance(result, AnthropicLLMLayer)


def test_create_llm_layer_disabled() -> None:
    """Config with enabled=False → None regardless of env."""
    config = LLMConfig(enabled=False, provider="anthropic")
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
        result = create_llm_layer(config)
    assert result is None


def test_create_llm_layer_anthropic() -> None:
    """Config provider=anthropic + ANTHROPIC_API_KEY → AnthropicLLMLayer."""
    import sys
    import types
    stub = types.ModuleType("anthropic")
    stub.AsyncAnthropic = lambda **kw: object()  # type: ignore[attr-defined]
    config = LLMConfig(enabled=True, provider="anthropic", model="claude-sonnet-4-6")
    with patch.dict(sys.modules, {"anthropic": stub}):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}):
            result = create_llm_layer(config)
    assert isinstance(result, AnthropicLLMLayer)


def test_create_llm_layer_anthropic_no_key() -> None:
    """Config provider=anthropic, no key → None with warning."""
    config = LLMConfig(enabled=True, provider="anthropic")
    env = {k: v for k, v in os.environ.items()
           if k not in ("ANTHROPIC_API_KEY", "HDWP_LLM_API_KEY")}
    with patch.dict(os.environ, env, clear=True):
        result = create_llm_layer(config)
    assert result is None


@_skip_no_openai
def test_create_llm_layer_openai() -> None:
    """Config provider=openai + OPENAI_API_KEY → OpenAICompatibleLLMLayer."""
    config = LLMConfig(enabled=True, provider="openai", model="gpt-4o-mini")
    with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
        with patch("openai.AsyncOpenAI"):
            result = create_llm_layer(config)
    assert isinstance(result, OpenAICompatibleLLMLayer)


def test_create_llm_layer_openai_no_key() -> None:
    """Config provider=openai, no key → None with warning."""
    config = LLMConfig(enabled=True, provider="openai", model="gpt-4o")
    env = {k: v for k, v in os.environ.items()
           if k not in ("OPENAI_API_KEY", "HDWP_LLM_API_KEY")}
    with patch.dict(os.environ, env, clear=True):
        result = create_llm_layer(config)
    assert result is None


@_skip_no_openai
def test_create_llm_layer_ollama_with_base_url() -> None:
    """Config provider=ollama + base_url → OpenAICompatibleLLMLayer, no key needed."""
    config = LLMConfig(
        enabled=True,
        provider="ollama",
        model="llama3.2",
        base_url="http://localhost:11434/v1",
    )
    with patch("openai.AsyncOpenAI") as mock_client:
        result = create_llm_layer(config)
    assert isinstance(result, OpenAICompatibleLLMLayer)
    # api_key should be "none" for Ollama
    mock_client.assert_called_once_with(
        api_key="none", base_url="http://localhost:11434/v1"
    )


@_skip_no_openai
def test_create_llm_layer_ollama_default_base_url() -> None:
    """Config provider=ollama without base_url → uses localhost:11434/v1 default."""
    config = LLMConfig(enabled=True, provider="ollama", model="mistral")
    with patch("openai.AsyncOpenAI") as mock_client:
        result = create_llm_layer(config)
    assert isinstance(result, OpenAICompatibleLLMLayer)
    mock_client.assert_called_once_with(
        api_key="none", base_url="http://localhost:11434/v1"
    )


def test_openai_compatible_layer_raises_without_package() -> None:
    """OpenAICompatibleLLMLayer raises RuntimeError if openai not installed."""
    import builtins
    original_import = builtins.__import__

    def mock_import(name: str, *args, **kwargs):  # type: ignore[no-untyped-def]
        if name == "openai":
            raise ImportError("No module named 'openai'")
        return original_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        with pytest.raises(RuntimeError, match="openai package requis"):
            OpenAICompatibleLLMLayer("key", model="gpt-4o")


def test_llm_config_in_context_yaml(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Loading a YAML with llm: section → LLMConfig parsed correctly."""
    from pathlib import Path
    from hdwp.core.context.loader import ContextLoader

    yaml_content = """
target:
  base_url: "http://test.local"
  name: "Test"
scope:
  include:
    - "http://test.local/*"
llm:
  enabled: true
  provider: ollama
  model: llama3.2
  base_url: http://localhost:11434/v1
"""
    config_file = tmp_path / "ctx.yaml"
    config_file.write_text(yaml_content)
    ctx = ContextLoader.load(Path(config_file))
    assert ctx.config.llm.enabled is True
    assert ctx.config.llm.provider == "ollama"
    assert ctx.config.llm.model == "llama3.2"
    assert ctx.config.llm.base_url == "http://localhost:11434/v1"


def test_llm_config_defaults() -> None:
    """LLMConfig default values are correct."""
    config = LLMConfig()
    assert config.enabled is False
    assert config.provider == "anthropic"
    assert config.model == "claude-sonnet-4-6"
    assert config.base_url is None
