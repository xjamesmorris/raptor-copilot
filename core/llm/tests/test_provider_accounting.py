"""Accounting capabilities for existing provider classes."""

from __future__ import annotations

import pytest

from core.llm.accounting import (
    AccountingMode,
    CostBasis,
    CostObservation,
    ModelKeyAggregation,
    PinnedRouteSnapshot,
    PinnedRouteViolation,
    RouteIdentity,
)
from core.llm.config import ModelConfig
from core.llm.providers import (
    AnthropicProvider,
    ClaudeCodeLLMProvider,
    GeminiProvider,
    LLMProvider,
    OpenAICompatibleProvider,
)
from core.llm.tool_use.types import StopReason, TurnResponse


def _instance(cls, *, provider: str, model: str, rate: float = 0.0):
    instance = cls.__new__(cls)
    instance.config = ModelConfig(
        provider=provider,
        model_name=model,
        cost_per_1k_tokens=rate,
    )
    return instance


def test_base_provider_capability_fails_closed() -> None:
    class _Provider(LLMProvider):
        def generate(self, prompt, system_prompt=None, **kwargs):
            raise NotImplementedError

        def generate_structured(
            self, prompt, schema, system_prompt=None, **kwargs,
        ):
            raise NotImplementedError

    provider = _instance(_Provider, provider="new-route", model="model")

    capability = provider.accounting_capability()

    assert capability.mode is AccountingMode.UNKNOWN
    assert capability.hard_limit_supported is False
    assert capability.model_key_aggregation is ModelKeyAggregation.REFUSE
    assert provider.expected_cost_basis() is CostBasis.UNKNOWN


def test_structured_repair_revalidates_exact_pin_before_dispatch() -> None:
    class _Provider(LLMProvider):
        def generate(self, prompt, system_prompt=None, **kwargs):
            raise AssertionError("repair dispatch must not occur")

        def generate_structured(
            self, prompt, schema, system_prompt=None, **kwargs,
        ):
            raise NotImplementedError

    provider = _instance(
        _Provider,
        provider="anthropic",
        model="pinned-model",
    )
    provider._raptor_pinned_route_snapshot = (
        PinnedRouteSnapshot.from_model_config(provider.config)
    )
    provider.config.api_base = "https://changed.invalid"

    with pytest.raises(PinnedRouteViolation, match="Pinned route violation"):
        provider._structured_fallback(
            "prompt",
            {"type": "object"},
            None,
        )


@pytest.mark.parametrize(
    ("provider_cls", "provider_name", "model"),
    [
        (OpenAICompatibleProvider, "openai", "gpt-5.4"),
        (AnthropicProvider, "anthropic", "claude-opus-4-6"),
        (AnthropicProvider, "bedrock", "us.anthropic.claude-opus-4-7"),
        (GeminiProvider, "gemini", "gemini-2.5-pro"),
    ],
)
def test_known_direct_routes_are_catalog_capable_but_not_hard(
    provider_cls,
    provider_name: str,
    model: str,
) -> None:
    provider = _instance(
        provider_cls, provider=provider_name, model=model,
    )

    capability = provider.accounting_capability()
    observation = provider.cost_observation(0.25)

    assert capability.mode is AccountingMode.AUTHORITATIVE
    assert capability.hard_limit_supported is False
    assert (
        capability.model_key_aggregation
        is ModelKeyAggregation.LEGACY_MODEL_NAME
    )
    assert observation.basis is CostBasis.CATALOG_PRICED
    assert observation.estimated_usd == pytest.approx(0.25)
    assert observation.provider_billed_usd is None


def test_configured_rate_route_is_estimated_not_provider_billed() -> None:
    provider = _instance(
        OpenAICompatibleProvider,
        provider="custom",
        model="unlisted-model",
        rate=0.01,
    )

    observation = provider.cost_observation(0.125)

    assert observation.basis is CostBasis.CONFIGURED_RATE
    assert observation.estimated_usd == pytest.approx(0.125)
    assert observation.provider_billed_usd is None


def test_unclassified_openai_compatible_route_refuses_model_key() -> None:
    provider = _instance(
        OpenAICompatibleProvider,
        provider="future-route",
        model="unlisted-model",
        rate=0.01,
    )

    assert (
        provider.accounting_capability().model_key_aggregation
        is ModelKeyAggregation.REFUSE
    )


@pytest.mark.parametrize("api_base", [None, "http://localhost:11434/v1"])
def test_ollama_route_is_always_unknown(api_base: str | None) -> None:
    provider = _instance(
        OpenAICompatibleProvider,
        provider="ollama",
        model="llama",
    )
    provider.config.api_base = api_base

    capability = provider.accounting_capability()
    observation = provider.cost_observation(0.0)

    assert capability.mode is AccountingMode.UNKNOWN
    assert capability.hard_limit_supported is False
    assert (
        capability.model_key_aggregation
        is ModelKeyAggregation.LEGACY_MODEL_NAME
    )
    assert observation.basis is CostBasis.UNKNOWN


def test_claude_code_cost_is_cli_reported_only_when_present() -> None:
    provider = _instance(
        ClaudeCodeLLMProvider,
        provider="claudecode",
        model="session-default",
    )

    capability = provider.accounting_capability()
    absent = provider.cost_observation(0.0, cost_reported=False)
    explicit_zero = provider.cost_observation(
        0.0, cost_reported=True,
    )

    assert capability.mode is AccountingMode.UNKNOWN
    assert capability.hard_limit_supported is False
    assert (
        capability.model_key_aggregation
        is ModelKeyAggregation.LEGACY_MODEL_NAME
    )
    assert absent.basis is CostBasis.UNKNOWN
    assert explicit_zero.basis is CostBasis.CLI_REPORTED
    assert explicit_zero.estimated_usd == 0.0


def test_claude_code_turn_keeps_absent_cost_unknown() -> None:
    provider = _instance(
        ClaudeCodeLLMProvider,
        provider="claudecode",
        model="session-default",
    )
    response = TurnResponse(
        content=[],
        stop_reason=StopReason.ERROR,
        input_tokens=1,
        output_tokens=0,
        cost_usd=0.0,
        cost_observation=CostObservation.unknown(),
    )

    observed = provider.turn_cost_observation(response)
    assert observed.basis is CostBasis.UNKNOWN
    assert observed.route == RouteIdentity("claudecode", "session-default")


def test_claude_code_turn_keeps_explicit_zero_cli_reported() -> None:
    provider = _instance(
        ClaudeCodeLLMProvider,
        provider="claudecode",
        model="session-default",
    )
    observation = provider.cost_observation(0.0, cost_reported=True)
    response = TurnResponse(
        content=[],
        stop_reason=StopReason.COMPLETE,
        input_tokens=1,
        output_tokens=0,
        cost_usd=0.0,
        cost_observation=observation,
    )

    assert (
        provider.turn_cost_observation(response).basis
        is CostBasis.CLI_REPORTED
    )


@pytest.mark.parametrize("stop_reason", [StopReason.ERROR, StopReason.REFUSED])
def test_base_error_and_refused_turns_are_unknown(
    stop_reason: StopReason,
) -> None:
    class _Provider(LLMProvider):
        def generate(self, prompt, system_prompt=None, **kwargs):
            raise NotImplementedError

        def generate_structured(
            self, prompt, schema, system_prompt=None, **kwargs,
        ):
            raise NotImplementedError

    provider = _instance(
        _Provider,
        provider="future-route",
        model="future-model",
        rate=0.01,
    )
    response = TurnResponse(
        content=[],
        stop_reason=stop_reason,
        input_tokens=5,
        output_tokens=1,
    )

    observation = provider.turn_cost_observation(response)

    assert observation == CostObservation.unknown(
        route=RouteIdentity("future-route", "future-model"),
    )


@pytest.mark.parametrize(
    "provider",
    [
        _instance(OpenAICompatibleProvider, provider="openai", model="gpt-5.4"),
        _instance(AnthropicProvider, provider="anthropic", model="claude-opus-4-6"),
        _instance(GeminiProvider, provider="gemini", model="gemini-2.5-pro"),
        _instance(
            ClaudeCodeLLMProvider,
            provider="claudecode",
            model="session-default",
        ),
    ],
)
def test_no_current_provider_supports_hard_usd_limit(provider) -> None:
    assert provider.accounting_capability().hard_limit_supported is False
