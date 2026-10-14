"""Tests for ``LLMClient(pinned_model=…)`` — caller-pinned model mode.

When a caller signals it will override the model on every ``generate()``
call (via ``model_config=``), the previous code path resolved + advertised
the operator's default ``primary_model`` anyway.  The log read
``Primary model: gemini-2.5-pro`` even when every call would actually hit
Anthropic, plus the upstream thinking-model auto-resolution path fired
its own misleading ``Auto-selected thinking model: gemini…`` line.

Pinned mode short-circuits both: ``_pinned_llm_config`` calls the inferred
provider's builder directly (so the resolver's lenient fall-through to
"whatever provider IS configured" can't substitute a different provider
for the pinned one), the fallback chain is empty, and the banner reflects
what's actually going to fire.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import core.llm.client as _client_mod
from core.llm.accounting import (
    AccountingCapability,
    AccountingMode,
    CostObservation,
    ModelKeyAggregation,
    PinnedRouteViolation,
    RouteIdentity,
)
from core.llm.client import LLMClient, _pinned_llm_config
from core.llm.config import LLMConfig, ModelConfig
from core.llm.providers import (
    LLMProvider,
    LLMResponse,
    StructuredResponse,
)
from core.llm.task_types import TaskType
from core.llm.tool_use.loop import ToolUseLoop
from core.llm.tool_use.types import StopReason, TextBlock, TurnResponse
from core.testing import make_test_client


@pytest.fixture(autouse=True)
def _reset_banner_flag():
    """Reset once-per-process banner flag so tests are order-independent."""
    _client_mod._MODEL_BANNER_SHOWN = False
    yield
    _client_mod._MODEL_BANNER_SHOWN = False


class _RaptorLogCapture:
    """Capture records sent to the ``raptor`` logger.

    RAPTOR's :class:`RaptorLogger` sets ``propagate=False`` on the
    ``raptor`` logger, so pytest's ``caplog`` (which hooks the root
    logger) never sees these records — attaching a handler directly
    is the workaround used throughout ``core/llm/tests/``.
    """

    def __enter__(self):
        self.records: list = []
        self._h = logging.Handler()
        self._h.handle = lambda r: (self.records.append(r), True)[1]
        self._lg = logging.getLogger("raptor")
        self._lg.addHandler(self._h)
        return self

    def __exit__(self, *exc):
        self._lg.removeHandler(self._h)
        return False

    def messages(self) -> list:
        return [r.getMessage() for r in self.records]


_CACHE_SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "string"}},
}


class _PinnedFakeProvider(LLMProvider):
    """Offline provider exercising real client/provider/tool boundaries."""

    def __init__(self, config: ModelConfig, tag: str) -> None:
        super().__init__(config)
        self.tag = tag
        self.generate_calls = 0
        self.structured_calls = 0
        self.turn_calls = 0

    def accounting_capability(self) -> AccountingCapability:
        return AccountingCapability(
            mode=AccountingMode.AUTHORITATIVE,
            hard_limit_supported=False,
            model_key_aggregation=ModelKeyAggregation.LEGACY_MODEL_NAME,
        )

    def generate(self, prompt, system_prompt=None, **kwargs):
        del prompt, system_prompt, kwargs
        self.generate_calls += 1
        route = RouteIdentity(self.config.provider, self.config.model_name)
        observation = CostObservation.configured_rate(0.05, route=route)
        return LLMResponse(
            content=self.tag,
            model=route.model,
            provider=route.provider,
            tokens_used=4,
            cost=0.05,
            finish_reason="stop",
            input_tokens=3,
            output_tokens=1,
            cost_observation=observation,
        )

    def generate_structured(
        self, prompt, schema, system_prompt=None, **kwargs,
    ):
        del prompt, schema, system_prompt, kwargs
        self.structured_calls += 1
        route = RouteIdentity(self.config.provider, self.config.model_name)
        observation = CostObservation.configured_rate(0.05, route=route)
        return StructuredResponse(
            result={"answer": self.tag},
            raw=json.dumps({"answer": self.tag}),
            cost=0.05,
            tokens_used=4,
            model=route.model,
            provider=route.provider,
            input_tokens=3,
            output_tokens=1,
            cost_observation=observation,
        )

    def supports_tool_use(self) -> bool:
        return True

    def context_window(self) -> int:
        return 100_000

    def estimate_tokens(self, text: str) -> int:
        return max(1, len(text) // 4)

    def turn(self, messages, tools, **kwargs):
        del messages, tools, kwargs
        self.turn_calls += 1
        route = RouteIdentity(self.config.provider, self.config.model_name)
        observation = CostObservation.configured_rate(0.05, route=route)
        return TurnResponse(
            content=[TextBlock(text=self.tag)],
            stop_reason=StopReason.COMPLETE,
            input_tokens=3,
            output_tokens=1,
            cost_usd=0.05,
            cost_observation=observation,
        )


def _configure_shared_cache(client: LLMClient, cache_dir: Path) -> None:
    client.config.enable_caching = True
    client.config.cache_dir = cache_dir
    client.config.cache_ttl_seconds = None
    client.config.cache_max_entries = None
    client.config.enable_cost_tracking = False
    client.config.scorecard_enabled = False
    cache_dir.mkdir(parents=True, exist_ok=True)


def _pinned_client(
    cache_dir: Path,
    tag: str,
    **route_fields,
) -> tuple[LLMClient, _PinnedFakeProvider]:
    availability = MagicMock(
        external_llm=True, claude_code=False, llm_available=True,
    )
    with patch(
        "core.llm.detection.detect_llm_availability",
        return_value=availability,
    ):
        client = LLMClient(pinned_config=ModelConfig(
            provider="anthropic",
            model_name="test-primary",
            api_key="not-used",
            cost_per_1k_tokens=0.01,
            **route_fields,
        ))
    _configure_shared_cache(client, cache_dir)
    provider = _PinnedFakeProvider(client.config.primary_model, tag)
    client.providers["anthropic:test-primary"] = provider
    return client, provider


def _unpinned_client(
    cache_dir: Path,
    tag: str,
    **route_fields,
) -> tuple[LLMClient, _PinnedFakeProvider]:
    client = make_test_client(cache_dir.parent)
    client.config.primary_model.cost_per_1k_tokens = 0.01
    for field, value in route_fields.items():
        setattr(client.config.primary_model, field, value)
    _configure_shared_cache(client, cache_dir)
    provider = _PinnedFakeProvider(client.config.primary_model, tag)
    client.providers["anthropic:test-primary"] = provider
    return client, provider


def _invoke(client: LLMClient, *, structured: bool):
    if structured:
        return client.generate_structured(
            "same prompt", _CACHE_SCHEMA,
        ).result["answer"]
    return client.generate("same prompt").content


def _response_cache_files(cache_dir: Path) -> list[Path]:
    return sorted(cache_dir.glob("*.json"))


def test_pinned_llm_config_anthropic_inference_from_claude_prefix(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-fake-key")
    cfg = _pinned_llm_config("claude-opus-4-8")
    assert cfg.primary_model.provider == "anthropic"
    assert cfg.primary_model.model_name == "claude-opus-4-8"
    assert cfg.primary_model.role == "code"
    assert cfg.fallback_models == []
    assert cfg.enable_fallback is False
    assert cfg.specialized_models == {}
    assert cfg.get_model_for_task(TaskType.VERDICT_BINARY) is cfg.primary_model


def test_pinned_llm_config_explicit_provider_slash_model(monkeypatch):
    """``provider/model`` syntax strips the prefix and is authoritative."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-fake-key")
    cfg = _pinned_llm_config("anthropic/claude-sonnet-4-6")
    assert cfg.primary_model.provider == "anthropic"
    assert cfg.primary_model.model_name == "claude-sonnet-4-6"


def test_pinned_llm_config_inference_table(monkeypatch):
    """Recognized bare names infer their existing provider route."""
    # Make every provider's env-key probe succeed so the builder doesn't
    # influence the resolved provider.
    for v in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.setenv(v, "test-fake-key")
    cases = [
        ("claude-opus-4-8",        "anthropic"),
        ("claude-haiku-4-5",       "anthropic"),
        ("gpt-4o-mini",            "openai"),
        ("gemini-2.5-pro",         "gemini"),
        ("anthropic/claude-opus",  "anthropic"),
        ("openai/gpt-5",           "openai"),
    ]
    for name, expected in cases:
        cfg = _pinned_llm_config(name)
        assert cfg.primary_model.provider == expected, name


def test_pinned_llm_config_no_credentials_returns_bare_config():
    """When the inferred provider has no env credentials, returns a bare
    uncredentialed ModelConfig with the pinned name (does NOT fall through
    to a different provider — that lenient behaviour is what caused the
    misleading gemini banner the fix is removing)."""
    cfg = _pinned_llm_config("anthropic/claude-opus-4-8")  # explicit pin, no key
    assert cfg.primary_model.provider == "anthropic"
    assert cfg.primary_model.model_name == "claude-opus-4-8"
    assert cfg.fallback_models == []
    assert cfg.enable_fallback is False


def test_pinned_llm_config_provider_name_uses_provider_builder(monkeypatch):
    """A pin that names a PROVIDER ("claudecode") uses that provider
    builder's config verbatim — including its own model_name — instead
    of falling through provider inference to a keyless anthropic config
    that dies with an SDK auth error at call time."""
    monkeypatch.setenv("RAPTOR_CC_MODEL", "claude-opus-4-7")
    monkeypatch.setattr(
        "shutil.which",
        lambda name: "/usr/bin/claude" if name == "claude" else None,
    )
    cfg = _pinned_llm_config("claudecode")
    assert cfg.primary_model.provider == "claudecode"
    assert cfg.primary_model.model_name == "claude-opus-4-7"
    assert cfg.fallback_models == []
    assert cfg.enable_fallback is False
    assert cfg.specialized_models == {}
    assert cfg.exact_pinned is False


def test_pinned_llm_config_provider_name_unavailable_raises(monkeypatch):
    """Provider-name pin whose backend is absent fails loudly at
    construction instead of synthesising a config for the wrong provider."""
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(ValueError, match="claudecode"):
        _pinned_llm_config("claudecode")


def test_pinned_llm_config_unknown_bare_model_raises_with_remedy():
    with pytest.raises(ValueError, match="provider/model"):
        _pinned_llm_config("totally-unknown-model")


def test_pinned_config_is_mutually_exclusive_with_other_constructor_routes():
    pinned = ModelConfig(provider="anthropic", model_name="pinned")
    config = LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic", model_name="configured",
        ),
        fallback_models=[],
    )

    with pytest.raises(ValueError, match="mutually exclusive"):
        LLMClient(config=config, pinned_config=pinned)
    with pytest.raises(ValueError, match="mutually exclusive"):
        LLMClient(pinned_model="anthropic/pinned", pinned_config=pinned)


@patch("core.llm.detection.detect_llm_availability")
def test_pinned_config_is_immutable_and_disables_all_rerouting(
    mock_detect,
):
    mock_detect.return_value = MagicMock(
        external_llm=True, claude_code=False, llm_available=True,
    )
    pinned = ModelConfig(
        provider="anthropic",
        model_name="pinned-model",
        api_key="secret-not-in-errors",
        api_base="https://private.invalid/v1",
    )
    client = LLMClient(pinned_config=pinned)

    assert client.config.enable_fallback is False
    assert client.config.fallback_models == []
    assert client.config.specialized_models == {}
    assert client.config.get_model_for_task(TaskType.VERDICT_BINARY) \
        is client.config.primary_model

    pinned.model_name = "mutated-model"
    with pytest.raises(PinnedRouteViolation) as exc:
        client.generate("prompt")
    message = str(exc.value)
    assert "pinned-model" in message
    assert "secret-not-in-errors" not in message
    assert "private.invalid" not in message


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("api_base", "https://changed.invalid/v1"),
        ("bedrock_api", "runtime"),
        ("aws_profile", "changed-profile"),
        ("aws_region", "us-west-2"),
        ("enabled", False),
    ],
)
@patch("core.llm.detection.detect_llm_availability")
def test_pinned_config_rejects_route_field_mutation(
    mock_detect, field, value,
):
    mock_detect.return_value = MagicMock(
        external_llm=True, claude_code=False, llm_available=True,
    )
    pinned = ModelConfig(
        provider="anthropic",
        model_name="pinned-model",
        api_key="secret-not-in-errors",
    )
    client = LLMClient(pinned_config=pinned)
    setattr(pinned, field, value)

    with pytest.raises(PinnedRouteViolation) as exc:
        client.generate("prompt")

    message = str(exc.value)
    assert "changed.invalid" not in message
    assert "changed-profile" not in message
    assert "us-west-2" not in message


@patch("core.llm.detection.detect_llm_availability")
def test_pinned_config_rejects_per_call_route_override(mock_detect):
    mock_detect.return_value = MagicMock(
        external_llm=True, claude_code=False, llm_available=True,
    )
    client = LLMClient(pinned_config=ModelConfig(
        provider="anthropic",
        model_name="pinned-model",
        api_key="unused",
    ))

    with pytest.raises(PinnedRouteViolation):
        client.generate(
            "prompt",
            model_config=ModelConfig(
                provider="openai",
                model_name="other-model",
                api_key="unused",
            ),
        )


@patch("core.llm.detection.detect_llm_availability")
def test_pinned_config_model_name_is_the_logical_model(mock_detect):
    mock_detect.return_value = MagicMock(
        external_llm=True, claude_code=False, llm_available=True,
    )
    client = LLMClient(pinned_config=ModelConfig(
        provider="anthropic",
        model_name="pinned-model",
        api_key="unused",
    ))

    assert client.model_name == "pinned-model"


def test_pinned_happy_path_dispatches_freeform_structured_and_tool(
    tmp_path,
) -> None:
    client, provider = _pinned_client(
        tmp_path / "shared-cache",
        "fresh-pinned",
        api_base="https://private.invalid/v1",
    )

    freeform = client.generate("freeform")
    structured = client.generate_structured("structured", _CACHE_SCHEMA)
    tool_result = ToolUseLoop(client.primary_provider, []).run("tool")

    assert freeform.content == "fresh-pinned"
    assert structured.result == {"answer": "fresh-pinned"}
    assert tool_result.final_text == "fresh-pinned"
    assert provider.generate_calls == 1
    assert provider.structured_calls == 1
    assert provider.turn_calls == 1
    assert client._models_to_try(
        client.config.primary_model, None,
    ) == [client.config.primary_model]
    assert provider._raptor_pinned_route_snapshot == client._pinned_snapshot
    provider.validate_pinned_route()
    assert client.get_stats()["accounting"]["configured_rate_calls"] == 2


@pytest.mark.parametrize("structured", [False, True])
@pytest.mark.parametrize(
    ("producer_fields", "consumer_fields"),
    [
        ({"api_base": "https://route-b.invalid/v1"}, {}),
        ({}, {}),
    ],
)
def test_exact_pinned_consumer_never_reuses_unpinned_entry(
    tmp_path,
    structured: bool,
    producer_fields: dict,
    consumer_fields: dict,
) -> None:
    """S1/S4: logical entries cannot authorize an exact-pin cache hit."""
    cache_dir = tmp_path / "shared-cache"
    producer, producer_provider = _unpinned_client(
        cache_dir, "unproven-producer", **producer_fields,
    )
    consumer, consumer_provider = _pinned_client(
        cache_dir, "fresh-consumer", **consumer_fields,
    )

    assert _invoke(producer, structured=structured) == "unproven-producer"
    assert _invoke(consumer, structured=structured) == "fresh-consumer"
    assert (
        producer_provider.structured_calls if structured
        else producer_provider.generate_calls
    ) == 1
    assert (
        consumer_provider.structured_calls if structured
        else consumer_provider.generate_calls
    ) == 1
    assert consumer.cache_hits == 0
    assert consumer.get_stats()["cache_bypassed_pinned"] == 1
    rendered = json.dumps(consumer.get_stats(), sort_keys=True)
    assert "route-b.invalid" not in rendered


@pytest.mark.parametrize("structured", [False, True])
@pytest.mark.parametrize(
    ("producer_fields", "consumer_fields"),
    [
        ({}, {"api_base": "https://route-a.invalid/v1"}),
        (
            {
                "api_base": "https://route-b.invalid/v1",
                "aws_profile": "profile-b",
                "aws_region": "us-east-1",
                "bedrock_api": "mantle",
            },
            {
                "api_base": "https://route-c.invalid/v1",
                "aws_profile": "profile-c",
                "aws_region": "eu-west-1",
                "bedrock_api": "runtime",
            },
        ),
    ],
)
def test_exact_pinned_clients_never_share_response_entries(
    tmp_path,
    structured: bool,
    producer_fields: dict,
    consumer_fields: dict,
) -> None:
    """S2/S3: exact-pin producers write nothing; consumers dispatch fresh."""
    cache_dir = tmp_path / "shared-cache"
    producer, producer_provider = _pinned_client(
        cache_dir, "pinned-producer", **producer_fields,
    )
    consumer, consumer_provider = _pinned_client(
        cache_dir, "pinned-consumer", **consumer_fields,
    )

    assert _invoke(producer, structured=structured) == "pinned-producer"
    assert _response_cache_files(cache_dir) == []
    assert _invoke(consumer, structured=structured) == "pinned-consumer"
    assert _response_cache_files(cache_dir) == []
    assert (
        producer_provider.structured_calls if structured
        else producer_provider.generate_calls
    ) == 1
    assert (
        consumer_provider.structured_calls if structured
        else consumer_provider.generate_calls
    ) == 1
    assert producer.get_stats()["cache_bypassed_pinned"] == 1
    assert consumer.get_stats()["cache_bypassed_pinned"] == 1
    assert producer.cache_hits == consumer.cache_hits == 0
    private_values = (
        "route-b.invalid",
        "route-c.invalid",
        "profile-b",
        "profile-c",
        "us-east-1",
        "eu-west-1",
        "mantle",
        "runtime",
    )
    rendered = json.dumps(
        {"producer": producer.get_stats(), "consumer": consumer.get_stats()},
        sort_keys=True,
    )
    assert not any(value in rendered for value in private_values)


@pytest.mark.parametrize("structured", [False, True])
def test_exact_pinned_producer_does_not_seed_unpinned_cache(
    tmp_path,
    structured: bool,
) -> None:
    """S5: an unpinned consumer after a pinned producer must dispatch."""
    cache_dir = tmp_path / "shared-cache"
    producer, producer_provider = _pinned_client(
        cache_dir,
        "pinned-producer",
        api_base="https://route-b.invalid/v1",
    )
    consumer, consumer_provider = _unpinned_client(
        cache_dir, "fresh-unpinned",
    )

    assert _invoke(producer, structured=structured) == "pinned-producer"
    assert _response_cache_files(cache_dir) == []
    assert _invoke(consumer, structured=structured) == "fresh-unpinned"
    assert (
        producer_provider.structured_calls if structured
        else producer_provider.generate_calls
    ) == 1
    assert (
        consumer_provider.structured_calls if structured
        else consumer_provider.generate_calls
    ) == 1
    assert consumer.cache_hits == 0
    assert len(_response_cache_files(cache_dir)) == 1


@pytest.mark.parametrize("structured", [False, True])
def test_exact_pin_never_consults_legacy_identityless_entry(
    tmp_path,
    structured: bool,
) -> None:
    cache_dir = tmp_path / "shared-cache"
    client, provider = _pinned_client(cache_dir, "fresh-pinned")
    if structured:
        key = client._get_structured_cache_key(
            "same prompt",
            None,
            client.config.primary_model.model_name,
            _CACHE_SCHEMA,
            {},
            provider=client.config.primary_model.provider,
        )
        (cache_dir / f"structured-{key}.json").write_text(
            json.dumps({
                "result": {"answer": "legacy"},
                "raw": "{}",
                "model": "test-primary",
                "provider": "anthropic",
            }),
            encoding="utf-8",
        )
        client._get_cached_structured_response = MagicMock(
            side_effect=AssertionError("pinned cache read attempted"),
        )
    else:
        key = client._get_cache_key(
            "same prompt",
            None,
            client.config.primary_model.model_name,
            {},
            provider=client.config.primary_model.provider,
        )
        (cache_dir / f"{key}.json").write_text(
            json.dumps({
                "content": "legacy",
                "model": "test-primary",
                "provider": "anthropic",
            }),
            encoding="utf-8",
        )
        client._get_cached_response = MagicMock(
            side_effect=AssertionError("pinned cache read attempted"),
        )

    assert _invoke(client, structured=structured) == "fresh-pinned"
    getter = (
        client._get_cached_structured_response
        if structured else client._get_cached_response
    )
    getter.assert_not_called()
    assert (
        provider.structured_calls if structured else provider.generate_calls
    ) == 1
    assert client.get_stats()["cache_bypassed_pinned"] == 1


def test_legacy_provider_only_pin_keeps_shared_cache(monkeypatch, tmp_path):
    import core.llm.config as cfg_mod

    monkeypatch.setitem(
        cfg_mod._PROVIDER_BUILDERS,
        "anthropic",
        lambda: ModelConfig(
            provider="anthropic",
            model_name="test-primary",
            api_key="not-used",
            cost_per_1k_tokens=0.01,
        ),
    )
    availability = MagicMock(
        external_llm=True, claude_code=False, llm_available=True,
    )
    with patch(
        "core.llm.detection.detect_llm_availability",
        return_value=availability,
    ):
        client = LLMClient(pinned_model="anthropic")
    _configure_shared_cache(client, tmp_path / "shared-cache")
    provider = _PinnedFakeProvider(client.config.primary_model, "legacy-pin")
    client.providers["anthropic:test-primary"] = provider

    assert client._pinned_snapshot is None
    assert client.generate("same prompt").content == "legacy-pin"
    assert client.generate("same prompt").finish_reason == "cached"
    assert provider.generate_calls == 1
    assert client.cache_hits == 1
    assert client.get_stats().get("cache_bypassed_pinned", 0) == 0


@patch("core.llm.detection.detect_llm_availability")
def test_llmclient_pinned_banner_suppresses_default_primary(mock_detect, monkeypatch):
    """With ``pinned_model``, banner reports the pin instead of the
    operator's auto-resolved primary, and skips the misleading "Primary
    model:" / "Fallback models:" lines."""
    mock_detect.return_value = MagicMock(
        external_llm=True, claude_code=False, llm_available=True,
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-fake-key")
    with _RaptorLogCapture() as cap:
        LLMClient(pinned_model="claude-opus-4-8")
    msgs = cap.messages()
    assert any("Pinned model: claude-opus-4-8" in m for m in msgs), msgs
    assert not any(m.startswith("Primary model:") for m in msgs), msgs
    assert not any(m.startswith("Fallback models:") for m in msgs), msgs


@patch("core.llm.detection.detect_llm_availability")
def test_llmclient_default_banner_unchanged(mock_detect, monkeypatch):
    """Without ``pinned_model``, banner behaviour is unchanged — the fix is
    additive (no regression for callers that don't opt in)."""
    mock_detect.return_value = MagicMock(
        external_llm=True, claude_code=False, llm_available=True,
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-fake-key")
    with _RaptorLogCapture() as cap:
        LLMClient()
    msgs = cap.messages()
    assert (any(m.startswith("Primary model:") for m in msgs)
            or any("no primary model" in m for m in msgs)), msgs


class TestPinnedMaxTokensCap:
    """The pinned model's own published output cap must win over the
    base config's value — ``max(base, pinned)`` sent the base model's
    larger limit to a smaller-cap pinned model, a non-retryable 400 on
    every call."""

    @staticmethod
    def _install_base(monkeypatch, max_tokens: int):
        import core.llm.config as cfg_mod
        from core.llm.config import ModelConfig
        base = ModelConfig(
            provider="anthropic", model_name="claude-base-model",
            api_key="test-fake-key", max_tokens=max_tokens,
        )
        monkeypatch.setitem(
            cfg_mod._PROVIDER_BUILDERS, "anthropic", lambda: base,
        )

    @staticmethod
    def _install_limits(monkeypatch, table: dict):
        import core.llm.model_data as model_data
        monkeypatch.setattr(
            model_data, "resolve_model_limits",
            lambda name: table.get(name),
        )

    def test_smaller_cap_pinned_model_gets_its_own_cap(self, monkeypatch):
        self._install_base(monkeypatch, max_tokens=64000)
        self._install_limits(monkeypatch, {
            "claude-small-test": {"max_output": 8192, "max_context": 200000},
        })
        cfg = _pinned_llm_config("anthropic/claude-small-test")
        assert cfg.primary_model.max_tokens == 8192

    def test_larger_cap_pinned_model_not_clamped_by_base(self, monkeypatch):
        """Other direction: the original max() intent — a base config
        sized for a small default model must not clamp a pinned model
        with a larger published cap."""
        self._install_base(monkeypatch, max_tokens=4096)
        self._install_limits(monkeypatch, {
            "claude-big-test": {"max_output": 32000, "max_context": 200000},
        })
        cfg = _pinned_llm_config("anthropic/claude-big-test")
        assert cfg.primary_model.max_tokens == 32000

    def test_unknown_model_keeps_base_value(self, monkeypatch):
        """No published limits: the base's operator-sized value beats
        the blind 4096 floor (pre-fix behaviour preserved)."""
        self._install_base(monkeypatch, max_tokens=64000)
        self._install_limits(monkeypatch, {})
        cfg = _pinned_llm_config("anthropic/claude-unknown-test")
        assert cfg.primary_model.max_tokens == 64000


def test_pinned_llm_config_tolerates_non_dict_config_entries(monkeypatch):
    """_read_config_models deliberately passes non-dict entries
    through; a stray string/number in the operator's models.json must
    degrade to a skip (like every sibling consumer), not an
    AttributeError from every LLMClient(pinned_model=...)."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    entries = [
        "garbage-string-entry",
        42,
        {"provider": "anthropic", "model": "claude-opus-4-8",
         "api_key": "test-fake-key"},
    ]
    monkeypatch.setattr(
        "core.llm.config._get_configured_models", lambda: list(entries),
    )
    # Shorthand resolution walks configured model names; credential
    # discovery walks provider entries — both paths must skip the
    # non-dict entries and land on the real one.
    cfg = _pinned_llm_config("claude-opus-4-8")
    assert cfg.primary_model is not None
    assert cfg.primary_model.provider == "anthropic"
    assert cfg.primary_model.api_key == "test-fake-key"
