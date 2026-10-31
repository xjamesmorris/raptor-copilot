"""ToolUseLoop accounting policy and attempt-settlement behavior."""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from core.llm.accounting import (
    AccountingCapability,
    AccountingMode,
    CostBasis,
    CostObservation,
    LLMAccountingUnavailableError,
    LLMHardLimitUnsupportedError,
    ModelKeyAggregation,
    PinnedRouteSnapshot,
    PinnedRouteViolation,
    RouteIdentity,
    TrustedUsdRoute,
    UsdBudgetContract,
    attach_cost_observation,
)
from core.llm.config import ModelConfig
from core.llm.providers import LLMProvider, OpenAICompatibleProvider
from core.llm.tool_use.loop import ToolUseLoop
from core.llm.tool_use.types import (
    CostBudgetExceeded,
    StopReason,
    StreamChunk,
    TextBlock,
    TurnResponse,
)

_ROUTE = RouteIdentity("anthropic", "claude-opus-4-6")


class _TurnProvider:
    def __init__(
        self,
        *,
        basis: CostBasis,
        responses: Sequence[TurnResponse | BaseException],
    ) -> None:
        self.config = ModelConfig(
            provider=_ROUTE.provider,
            model_name=_ROUTE.model,
        )
        self.basis = basis
        self.responses = list(responses)
        self.calls = 0
        self.last_kwargs = {}

    def supports_tool_use(self) -> bool:
        return True

    def supports_streaming(self) -> bool:
        return False

    def supports_prompt_caching(self) -> bool:
        return False

    def accounting_capability(self) -> AccountingCapability:
        mode = (
            AccountingMode.AUTHORITATIVE
            if self.basis in (
                CostBasis.PROVIDER_BILLED,
                CostBasis.CATALOG_PRICED,
                CostBasis.CONFIGURED_RATE,
            )
            else (
                AccountingMode.SUBSCRIPTION
                if self.basis is CostBasis.SUBSCRIPTION
                else AccountingMode.UNKNOWN
            )
        )
        return AccountingCapability(
            mode=mode,
            hard_limit_supported=False,
            model_key_aggregation=ModelKeyAggregation.LEGACY_MODEL_NAME,
        )

    def expected_cost_basis(self) -> CostBasis:
        return self.basis

    def estimate_tokens(self, text: str) -> int:
        return max(1, len(text) // 4)

    def context_window(self) -> int:
        return 100_000

    def compute_cost(self, response: TurnResponse) -> float:
        return response.cost_observation.legacy_cost_usd

    def turn_cost_observation(
        self, response: TurnResponse,
    ) -> CostObservation:
        return response.cost_observation

    def turn(
        self,
        messages,
        tools,
        *,
        system,
        max_tokens,
        cache_control,
        **kwargs,
    ) -> TurnResponse:
        del messages, tools, system, max_tokens, cache_control
        self.last_kwargs = dict(kwargs)
        self.calls += 1
        value = self.responses.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


def _response(observation: CostObservation) -> TurnResponse:
    return TurnResponse(
        content=[TextBlock(text="done")],
        stop_reason=StopReason.COMPLETE,
        input_tokens=10,
        output_tokens=5,
        cost_usd=observation.legacy_cost_usd,
        cost_observation=observation,
    )


def _loop(
    provider: _TurnProvider,
    *,
    contract: UsdBudgetContract,
    trusted: tuple[TrustedUsdRoute, ...] = (),
) -> ToolUseLoop:
    return ToolUseLoop(
        provider,
        [],
        max_cost_usd=1.0,
        usd_budget_contract=contract,
        trusted_usd_routes=trusted,
    )


def test_advisory_unknown_runs_and_reports_incomplete() -> None:
    provider = _TurnProvider(
        basis=CostBasis.UNKNOWN,
        responses=[_response(CostObservation.unknown(route=_ROUTE))],
    )

    result = _loop(
        provider, contract=UsdBudgetContract.ADVISORY,
    ).run("prompt")

    assert result.total_cost_usd == 0.0
    assert result.accounting.unknown_calls == 1
    assert result.accounting.usd_total_complete is False
    assert provider.calls == 1


def test_authoritative_required_refuses_unknown_before_turn() -> None:
    provider = _TurnProvider(
        basis=CostBasis.UNKNOWN,
        responses=[_response(CostObservation.unknown(route=_ROUTE))],
    )

    with pytest.raises(LLMAccountingUnavailableError):
        _loop(
            provider,
            contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        ).run("prompt")

    assert provider.calls == 0


@pytest.mark.parametrize("max_cost", [None, 0.0, -1.0])
def test_non_advisory_contract_requires_positive_cost_limit(
    max_cost,
) -> None:
    provider = _TurnProvider(
        basis=CostBasis.CATALOG_PRICED,
        responses=[],
    )
    with pytest.raises(ValueError, match="positive max_cost_usd"):
        ToolUseLoop(
            provider,
            [],
            max_cost_usd=max_cost,
            usd_budget_contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        )


def test_missing_accounting_methods_refuse_strict_but_allow_advisory() -> None:
    class _MinimalProvider:
        def __init__(self) -> None:
            self.calls = 0
            self.config = ModelConfig(
                provider="future-route",
                model_name="future-model",
            )

        def supports_tool_use(self) -> bool:
            return True

        def supports_streaming(self) -> bool:
            return False

        def supports_prompt_caching(self) -> bool:
            return False

        def context_window(self) -> int:
            return 100_000

        def estimate_tokens(self, text: str) -> int:
            return max(1, len(text) // 4)

        def compute_cost(self, response: TurnResponse) -> float:
            return 0.0

        def turn(self, *args, **kwargs) -> TurnResponse:
            del args, kwargs
            self.calls += 1
            return _response(CostObservation.unknown(route=RouteIdentity(
                "future-route", "future-model",
            )))

    strict_provider = _MinimalProvider()
    strict = ToolUseLoop(
        strict_provider,
        [],
        max_cost_usd=1.0,
        usd_budget_contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
    )
    with pytest.raises(LLMAccountingUnavailableError):
        strict.run("p")
    assert strict_provider.calls == 0

    advisory_provider = _MinimalProvider()
    advisory = ToolUseLoop(advisory_provider, [])
    assert advisory.run("p").final_text == "done"
    assert advisory_provider.calls == 1


def test_authoritative_required_accepts_trusted_catalog() -> None:
    observation = CostObservation.catalog_priced(0.1, route=_ROUTE)
    provider = _TurnProvider(
        basis=CostBasis.CATALOG_PRICED,
        responses=[_response(observation)],
    )
    trusted = (
        TrustedUsdRoute(
            _ROUTE.provider, _ROUTE.model, CostBasis.CATALOG_PRICED,
        ),
    )

    result = _loop(
        provider,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        trusted=trusted,
    ).run("prompt")

    assert result.total_cost_usd == pytest.approx(0.1)
    assert result.accounting.catalog_priced_calls == 1
    assert provider.last_kwargs["max_retries"] == 0


def test_strict_post_turn_unauthorized_basis_latches() -> None:
    provider = _TurnProvider(
        basis=CostBasis.CATALOG_PRICED,
        responses=[_response(
            CostObservation.cli_reported(0.1, route=_ROUTE),
        )],
    )
    loop = _loop(
        provider,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        trusted=(
            TrustedUsdRoute(
                _ROUTE.provider,
                _ROUTE.model,
                CostBasis.CATALOG_PRICED,
            ),
        ),
    )

    with pytest.raises(LLMAccountingUnavailableError):
        loop.run("p")
    with pytest.raises(LLMAccountingUnavailableError):
        loop.run("later")
    assert provider.calls == 1


def test_strict_error_stop_without_cost_latches() -> None:
    provider = _TurnProvider(
        basis=CostBasis.CATALOG_PRICED,
        responses=[TurnResponse(
            content=[],
            stop_reason=StopReason.ERROR,
            input_tokens=0,
            output_tokens=0,
            error_message="failed",
            cost_observation=CostObservation.unknown(route=_ROUTE),
        )],
    )
    loop = _loop(
        provider,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        trusted=(
            TrustedUsdRoute(
                _ROUTE.provider,
                _ROUTE.model,
                CostBasis.CATALOG_PRICED,
            ),
        ),
    )

    with pytest.raises(LLMAccountingUnavailableError):
        loop.run("p")
    assert provider.calls == 1


def test_authoritative_required_reserves_before_turn() -> None:
    observation = CostObservation.catalog_priced(0.1, route=_ROUTE)
    provider = _TurnProvider(
        basis=CostBasis.CATALOG_PRICED,
        responses=[_response(observation)],
    )
    loop = ToolUseLoop(
        provider,
        [],
        max_cost_usd=0.05,
        usd_budget_contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        trusted_usd_routes=(
            TrustedUsdRoute(
                _ROUTE.provider,
                _ROUTE.model,
                CostBasis.CATALOG_PRICED,
            ),
        ),
    )

    with pytest.raises(CostBudgetExceeded):
        loop.run("prompt")

    assert provider.calls == 0


def test_hard_limit_required_is_unsupported_before_turn() -> None:
    provider = _TurnProvider(
        basis=CostBasis.PROVIDER_BILLED,
        responses=[_response(
            CostObservation.provider_billed(0.1, route=_ROUTE),
        )],
    )

    with pytest.raises(LLMHardLimitUnsupportedError):
        _loop(
            provider,
            contract=UsdBudgetContract.HARD_LIMIT_REQUIRED,
        ).run("prompt")

    assert provider.calls == 0


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("timed out"),
        RuntimeError("cancelled"),
        KeyboardInterrupt(),
    ],
)
def test_strict_unknown_failure_settles_and_latches(
    error: BaseException,
) -> None:
    provider = _TurnProvider(
        basis=CostBasis.CATALOG_PRICED,
        responses=[error, _response(
            CostObservation.catalog_priced(0.1, route=_ROUTE),
        )],
    )
    loop = _loop(
        provider,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        trusted=(
            TrustedUsdRoute(
                _ROUTE.provider,
                _ROUTE.model,
                CostBasis.CATALOG_PRICED,
            ),
        ),
    )

    with pytest.raises(LLMAccountingUnavailableError):
        loop.run("first")
    with pytest.raises(LLMAccountingUnavailableError):
        loop.run("second")

    assert provider.calls == 1
    assert loop.accounting_summary.unknown_failed_attempts == 1
    assert loop.accounting_summary.exposure_unresolved is True
    assert (
        loop.accounting_summary.retained_reservation_estimate_usd > 0
    )


def test_observed_failed_turn_is_settled_once() -> None:
    observation = CostObservation.catalog_priced(0.2, route=_ROUTE)
    error = RuntimeError("503 service unavailable")
    attach_cost_observation(error, observation)
    provider = _TurnProvider(
        basis=CostBasis.CATALOG_PRICED,
        responses=[error],
    )
    loop = _loop(
        provider,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        trusted=(
            TrustedUsdRoute(
                _ROUTE.provider,
                _ROUTE.model,
                CostBasis.CATALOG_PRICED,
            ),
        ),
    )

    with pytest.raises(RuntimeError, match="503"):
        loop.run("prompt")

    assert provider.calls == 1
    assert loop.accounting_summary.catalog_priced_calls == 1
    assert loop.accounting_summary.unknown_failed_attempts == 0


def test_post_settlement_baseexception_propagates_once(monkeypatch) -> None:
    observation = CostObservation.catalog_priced(0.2, route=_ROUTE)
    provider = _TurnProvider(
        basis=CostBasis.CATALOG_PRICED,
        responses=[_response(observation)],
    )
    loop = _loop(provider, contract=UsdBudgetContract.ADVISORY)
    original = loop._settle_turn_observation

    def settle_then_interrupt(attempt, observed):
        original(attempt, observed)
        raise KeyboardInterrupt

    monkeypatch.setattr(loop, "_settle_turn_observation", settle_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        loop.run("p")

    assert provider.calls == 1
    assert loop.accounting_summary.catalog_priced_calls == 1


def test_advisory_unknown_failure_preserves_original_exception() -> None:
    error = ValueError("provider failed")
    provider = _TurnProvider(
        basis=CostBasis.UNKNOWN,
        responses=[error],
    )
    loop = _loop(provider, contract=UsdBudgetContract.ADVISORY)

    with pytest.raises(ValueError, match="provider failed"):
        loop.run("prompt")

    assert loop.accounting_summary.unknown_failed_attempts == 1
    assert (
        loop.accounting_summary.retained_reservation_estimate_usd == 0
    )


def test_error_response_without_cost_is_unknown_failed_attempt() -> None:
    provider = _TurnProvider(
        basis=CostBasis.UNKNOWN,
        responses=[TurnResponse(
            content=[],
            stop_reason=StopReason.ERROR,
            input_tokens=0,
            output_tokens=0,
            error_message="transport failed",
            cost_observation=CostObservation.unknown(route=_ROUTE),
        )],
    )

    result = _loop(
        provider, contract=UsdBudgetContract.ADVISORY,
    ).run("prompt")

    assert result.terminated_by == "provider_error"
    assert result.accounting.unknown_failed_attempts == 1
    assert result.accounting.unknown_calls == 0


def test_pre_content_stream_retries_each_settle_once() -> None:
    class _StreamingProvider(_TurnProvider):
        def supports_streaming(self) -> bool:
            return True

        def turn_stream(self, *args, **kwargs):
            del args, kwargs
            self.calls += 1
            if self.calls <= 2:
                raise RuntimeError("pre-content disconnect")
            yield StreamChunk(type="text_delta", text="done")
            yield StreamChunk(
                type="usage", input_tokens=2, output_tokens=1,
            )
            yield StreamChunk(
                type="done", stop_reason=StopReason.COMPLETE,
            )

    provider = _StreamingProvider(
        basis=CostBasis.UNKNOWN,
        responses=[],
    )

    result = ToolUseLoop(provider, [], stream=True).run("prompt")

    assert provider.calls == 3
    assert result.accounting.unknown_failed_attempts == 2
    assert result.accounting.unknown_calls == 1


def test_stream_policy_error_is_re_raised_unchanged(monkeypatch) -> None:
    provider = _TurnProvider(
        basis=CostBasis.UNKNOWN,
        responses=[],
    )
    loop = ToolUseLoop(provider, [], stream=True)
    sentinel = LLMAccountingUnavailableError("policy")
    monkeypatch.setattr(
        loop,
        "_execute_turn_attempt",
        lambda *a, **k: (_ for _ in ()).throw(sentinel),
    )

    with pytest.raises(LLMAccountingUnavailableError) as excinfo:
        loop._consume_stream(0, [])
    assert excinfo.value is sentinel


def test_tool_turn_revalidates_exact_pin_before_dispatch() -> None:
    observation = CostObservation.catalog_priced(0.1, route=_ROUTE)
    provider = _TurnProvider(
        basis=CostBasis.CATALOG_PRICED,
        responses=[_response(observation)],
    )
    provider._raptor_pinned_route_snapshot = (
        PinnedRouteSnapshot.from_model_config(provider.config)
    )
    provider.config.api_base = "https://changed.invalid"

    with pytest.raises(PinnedRouteViolation, match="Pinned route violation"):
        _loop(
            provider,
            contract=UsdBudgetContract.ADVISORY,
        ).run("prompt")

    assert provider.calls == 0


def test_tool_loop_actual_provider_pinned_validator_returns_cleanly() -> None:
    provider = OpenAICompatibleProvider.__new__(OpenAICompatibleProvider)
    LLMProvider.__init__(
        provider,
        ModelConfig(
            provider="openai",
            model_name="gpt-5.4",
            api_key="unused",
        ),
    )
    provider._tool_use_unsupported = False
    provider._raptor_pinned_route_snapshot = (
        PinnedRouteSnapshot.from_model_config(provider.config)
    )
    loop = ToolUseLoop(provider, [])

    loop._validate_pinned_route()

    assert provider._raptor_pinned_route_snapshot == (
        PinnedRouteSnapshot.from_model_config(provider.config)
    )


def test_loop_latch_is_idempotent() -> None:
    provider = _TurnProvider(
        basis=CostBasis.UNKNOWN,
        responses=[],
    )
    loop = ToolUseLoop(provider, [])

    first = loop._latch_accounting_error(reason="first")
    second = loop._latch_accounting_error(reason="second")

    assert first is second
