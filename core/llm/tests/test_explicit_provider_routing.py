"""Explicit routing providers outrank model-family inference."""

from __future__ import annotations

import pytest

from core.llm.accounting import CostBasis, cost_basis_for_model_config
from core.llm.client import _pinned_llm_config
from core.llm.config import LLMConfig, ModelConfig
from core.llm.model_data import resolve_model_costs, resolve_model_limits
from core.security.llm_family import (
    explicit_provider_of,
    family_of,
    provider_of,
    routing_model_id,
)


@pytest.fixture(autouse=True)
def _clear_cloud_credentials(monkeypatch):
    for name in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "MISTRAL_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    ("opaque_model", "expected_family", "cloud_provider"),
    [
        ("gpt-oss:20b", "openai", "openai"),
        ("gemma3", "google", "gemini"),
        ("mistral", "mistral", "mistral"),
        ("command-r", "cohere", "cohere"),
    ],
)
def test_ollama_qualifier_is_authoritative_for_config_for_model(
    opaque_model,
    expected_family,
    cloud_provider,
):
    qualified = f"ollama/{opaque_model}"
    route = ModelConfig(
        provider="ollama",
        model_name=opaque_model,
        api_key="ollama-route-key",
        api_base="https://ollama.example.invalid/v1",
        max_context=65_536,
        max_tokens=8_192,
    )
    wrong_cloud_route = ModelConfig(
        provider=cloud_provider,
        model_name=opaque_model,
        api_key="wrong-cloud-key",
        api_base="https://cloud.example.invalid/v1",
    )
    config = LLMConfig(
        primary_model=None,
        fallback_models=[wrong_cloud_route, route],
        specialized_models={},
    )

    assert family_of(qualified) == expected_family
    assert provider_of(qualified) == "ollama"
    assert explicit_provider_of(qualified) == "ollama"
    assert routing_model_id(qualified) == opaque_model

    resolved = config.config_for_model(qualified)
    assert resolved is route
    assert resolved.provider == "ollama"
    assert resolved.model_name == opaque_model
    assert resolved.api_key == "ollama-route-key"
    assert resolved.api_base == "https://ollama.example.invalid/v1"

    unconfigured = LLMConfig(
        primary_model=None,
        fallback_models=[],
        specialized_models={},
    ).config_for_model(qualified)
    assert unconfigured.provider == "ollama"
    assert unconfigured.model_name == opaque_model


@pytest.mark.parametrize(
    "opaque_model",
    ["gpt-oss:20b", "gemma3", "mistral", "command-r"],
)
def test_ollama_qualifier_is_authoritative_for_pinned_model(
    monkeypatch,
    opaque_model,
):
    monkeypatch.setenv("OPENAI_API_KEY", "cloud-openai-key")
    monkeypatch.setenv("GEMINI_API_KEY", "cloud-gemini-key")
    monkeypatch.setenv("MISTRAL_API_KEY", "cloud-mistral-key")
    monkeypatch.setattr(
        "core.llm.config._get_configured_models",
        lambda: [{
            "provider": "ollama",
            "model": opaque_model,
            "api_key": "ollama-route-key",
            "api_base": "https://ollama.example.invalid/v1",
            "max_context": 65_536,
            "max_output": 8_192,
        }],
    )

    config = _pinned_llm_config(f"ollama/{opaque_model}")

    model = config.primary_model
    assert model is not None
    assert model.provider == "ollama"
    assert model.model_name == opaque_model
    assert model.api_key == "ollama-route-key"
    assert model.api_base == "https://ollama.example.invalid/v1"
    assert model.max_context == 65_536
    assert model.max_tokens == 8_192
    assert model.cost_per_1k_tokens == 0.0
    assert config.exact_pinned is True
    assert config.fallback_models == []
    assert config.specialized_models == {}
    assert resolve_model_limits(model.model_name) is None
    assert resolve_model_costs(model.model_name) is None
    assert cost_basis_for_model_config(model) is CostBasis.UNKNOWN
