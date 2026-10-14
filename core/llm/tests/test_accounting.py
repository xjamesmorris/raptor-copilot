"""Provider-neutral accounting policy and value-object contracts."""

from __future__ import annotations

import math

import pytest

from core.llm.accounting import (
    AccountingCapability,
    AccountingMode,
    AccountingSummary,
    AttemptLedger,
    AttemptSettlementError,
    CostBasis,
    CostObservation,
    ModelKeyAggregation,
    RouteIdentity,
    TrustedUsdRoute,
    UsdBudgetContract,
    attach_cost_observation,
    cli_cost_observation,
    cost_basis_for_model_config,
    cost_observation_from_exception,
    direct_api_accounting_capability,
    estimated_cost_observation,
    format_accounting_summary,
    is_basis_authorized,
    is_observation_authorized,
)
from core.llm.config import LLMConfig, ModelConfig


def test_provider_billed_zero_is_authoritative_zero() -> None:
    route = RouteIdentity("openai", "model")
    observation = CostObservation.provider_billed(0.0, route=route)

    assert observation.basis is CostBasis.PROVIDER_BILLED
    assert observation.provider_billed_usd == 0.0
    assert observation.estimated_usd is None
    assert observation.legacy_cost_usd == 0.0
    assert is_observation_authorized(observation, ()) is True


@pytest.mark.parametrize("amount", [-1.0, math.nan, math.inf, -math.inf, True])
def test_malformed_cost_amounts_are_rejected(amount: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        CostObservation.provider_billed(amount)  # type: ignore[arg-type]
    with pytest.raises((TypeError, ValueError)):
        CostObservation.catalog_priced(
            amount,  # type: ignore[arg-type]
            route=RouteIdentity("anthropic", "model"),
        )


def test_non_billed_bases_never_become_known_zero() -> None:
    route = RouteIdentity("anthropic", "model")
    observations = (
        CostObservation.catalog_priced(0.0, route=route),
        CostObservation.configured_rate(0.0, route=route),
        CostObservation.cli_reported(0.0, route=route),
        CostObservation.subscription(route=route),
        CostObservation.unknown(route=route),
    )

    assert all(obs.provider_billed_usd is None for obs in observations)
    assert observations[-2].legacy_cost_usd == 0.0
    assert observations[-1].legacy_cost_usd == 0.0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"basis": CostBasis.PROVIDER_BILLED},
        {
            "basis": CostBasis.PROVIDER_BILLED,
            "provider_billed_usd": 1.0,
            "estimated_usd": 1.0,
        },
        {"basis": CostBasis.CATALOG_PRICED},
        {"basis": CostBasis.CONFIGURED_RATE},
        {"basis": CostBasis.CLI_REPORTED},
        {
            "basis": CostBasis.CATALOG_PRICED,
            "estimated_usd": 1.0,
            "provider_billed_usd": 1.0,
        },
        {
            "basis": CostBasis.SUBSCRIPTION,
            "estimated_usd": 1.0,
        },
        {
            "basis": CostBasis.UNKNOWN,
            "provider_billed_usd": 1.0,
        },
        {
            "basis": CostBasis.CONFIGURED_RATE,
            "estimated_usd": 1.0,
            "catalog_version": "v1",
        },
    ],
)
def test_cost_observation_rejects_inconsistent_basis_fields(
    kwargs: dict,
) -> None:
    with pytest.raises(ValueError):
        CostObservation(**kwargs)


def test_trusted_route_authorizes_only_exact_catalog_or_configured_basis() -> None:
    route = RouteIdentity("Anthropic", "model")
    trusted = (
        TrustedUsdRoute(
            provider="anthropic",
            model="model",
            basis=CostBasis.CATALOG_PRICED,
        ),
    )

    assert is_observation_authorized(
        CostObservation.catalog_priced(1.0, route=route),
        trusted,
    )
    assert not is_observation_authorized(
        CostObservation.catalog_priced(
            1.0, route=RouteIdentity("bedrock", "model"),
        ),
        trusted,
    )
    assert not is_observation_authorized(
        CostObservation.configured_rate(1.0, route=route),
        trusted,
    )
    assert not is_observation_authorized(
        CostObservation.cli_reported(1.0, route=route),
        trusted,
    )


@pytest.mark.parametrize(
    "basis",
    [
        CostBasis.PROVIDER_BILLED,
        CostBasis.CLI_REPORTED,
        CostBasis.SUBSCRIPTION,
        CostBasis.UNKNOWN,
    ],
)
def test_trusted_route_rejects_non_declarable_basis(basis: CostBasis) -> None:
    with pytest.raises(ValueError):
        TrustedUsdRoute("provider", "model", basis)


def test_accounting_capability_defaults_fail_closed() -> None:
    capability = AccountingCapability()

    assert capability.mode is AccountingMode.UNKNOWN
    assert capability.hard_limit_supported is False
    assert capability.model_key_aggregation is ModelKeyAggregation.REFUSE


def test_accounting_summary_preserves_basis_subtotals_and_completeness() -> None:
    route = RouteIdentity("anthropic", "model")
    summary = (
        AccountingSummary()
        .add(CostObservation.provider_billed(1.25, route=route))
        .add(CostObservation.catalog_priced(0.50, route=route))
        .add(CostObservation.subscription(route=route))
        .add(CostObservation.unknown(route=route))
        .add_unknown_failure(retained_reservation_estimate_usd=0.75)
    )

    assert summary.provider_billed_usd == pytest.approx(1.25)
    assert summary.catalog_priced_usd == pytest.approx(0.50)
    assert summary.subscription_calls == 1
    assert summary.unknown_calls == 1
    assert summary.unknown_failed_attempts == 1
    assert summary.retained_reservation_estimate_usd == pytest.approx(0.75)
    assert summary.exposure_unresolved is True
    assert summary.usd_total_complete is False
    assert summary.legacy_total_cost == pytest.approx(1.75)


def test_accounting_summary_merge_propagates_unknown_remaining() -> None:
    known = AccountingSummary().with_authoritative_remaining(4.0)
    unknown = AccountingSummary()

    assert known.merge(unknown).authoritative_remaining_usd is None
    assert unknown.merge(known).authoritative_remaining_usd is None
    assert (
        known.merge(
            AccountingSummary().with_authoritative_remaining(2.0),
        ).authoritative_remaining_usd
        == 2.0
    )


def test_unknown_only_summary_never_presents_zero_as_total_cost() -> None:
    route = RouteIdentity("future", "model")
    summary = (
        AccountingSummary()
        .add(CostObservation.unknown(route=route))
        .add(CostObservation.subscription(route=route))
    )

    assert format_accounting_summary(summary) == (
        "Estimated USD $0.00 — incomplete "
        "(1 unknown, 1 subscription calls)"
    )


def test_attempt_ledger_settles_exactly_once() -> None:
    ledger = AttemptLedger(
        route=RouteIdentity("anthropic", "model"),
        reservation_usd=1.0,
    )
    settlement = ledger.settle_observation(
        CostObservation.catalog_priced(
            0.25,
            route=RouteIdentity("anthropic", "model"),
        ),
    )

    assert settlement.reservation_usd == 1.0
    assert settlement.observation.estimated_usd == 0.25
    assert ledger.settled is True
    with pytest.raises(AttemptSettlementError):
        ledger.settle_no_spend()


def test_attempt_ledger_missing_settlement_is_programming_error() -> None:
    ledger = AttemptLedger(
        route=RouteIdentity("anthropic", "model"),
        reservation_usd=0.0,
    )
    with pytest.raises(AttemptSettlementError):
        ledger.require_settled()


def test_attempt_ledger_rejects_foreign_observation_route() -> None:
    ledger = AttemptLedger(
        route=RouteIdentity("anthropic", "model"),
        reservation_usd=0.0,
    )
    with pytest.raises(
        AttemptSettlementError,
        match="does not match attempt route",
    ):
        ledger.settle_observation(
            CostObservation.catalog_priced(
                0.1,
                route=RouteIdentity("bedrock", "model"),
            ),
        )


def test_exception_observation_round_trip_preserves_exception_type() -> None:
    error = ValueError("failed")
    observation = CostObservation.configured_rate(
        0.10,
        route=RouteIdentity("custom", "model"),
    )

    assert attach_cost_observation(error, observation) is error
    assert cost_observation_from_exception(error) == observation


def test_exception_observation_walks_cause_and_context() -> None:
    cause_observation = CostObservation.configured_rate(0.1)
    cause = ValueError("cause")
    attach_cost_observation(cause, cause_observation)
    caused = RuntimeError("wrapper")
    caused.__cause__ = cause
    assert cost_observation_from_exception(caused) == cause_observation

    context_observation = CostObservation.cli_reported(0.2)
    context = ValueError("context")
    attach_cost_observation(context, context_observation)
    contextual = RuntimeError("wrapper")
    contextual.__context__ = context
    assert cost_observation_from_exception(contextual) == context_observation


def test_exception_observation_respects_suppression_and_depth_cap() -> None:
    hidden = ValueError("hidden")
    attach_cost_observation(hidden, CostObservation.configured_rate(0.1))
    suppressed = RuntimeError("suppressed")
    suppressed.__context__ = hidden
    suppressed.__suppress_context__ = True
    assert cost_observation_from_exception(suppressed) is None

    chain = [RuntimeError(str(i)) for i in range(9)]
    for current, cause in zip(chain[:-1], chain[1:], strict=True):
        current.__cause__ = cause
    attach_cost_observation(chain[8], CostObservation.configured_rate(0.2))
    assert cost_observation_from_exception(chain[0]) is None


def test_budget_contract_values_are_stable() -> None:
    assert UsdBudgetContract.ADVISORY.value == "advisory"
    assert (
        UsdBudgetContract.AUTHORITATIVE_REQUIRED.value
        == "authoritative_required"
    )
    assert (
        UsdBudgetContract.HARD_LIMIT_REQUIRED.value
        == "hard_limit_required"
    )


def test_llm_config_accounting_defaults_are_advisory_and_empty() -> None:
    config = LLMConfig.__new__(LLMConfig)
    config.primary_model = None
    config.fallback_models = []
    config.specialized_models = {}
    config.enable_fallback = True
    config.usd_budget_contract = UsdBudgetContract.ADVISORY
    config.trusted_usd_routes = ()
    config.__post_init__()

    assert config.usd_budget_contract is UsdBudgetContract.ADVISORY
    assert config.trusted_usd_routes == ()


def test_llm_config_rejects_untyped_trusted_route_declaration() -> None:
    config = LLMConfig.__new__(LLMConfig)
    config.primary_model = None
    config.fallback_models = []
    config.specialized_models = {}
    config.enable_fallback = True
    config.usd_budget_contract = "authoritative_required"
    config.trusted_usd_routes = [{"provider": "x", "model": "y"}]

    with pytest.raises(TypeError, match="TrustedUsdRoute"):
        config.__post_init__()


def test_catalog_pricing_is_estimated_not_provider_billed() -> None:
    config = ModelConfig(
        provider="anthropic",
        model_name="claude-opus-4-6",
    )
    observation = estimated_cost_observation(config, 1.25)
    capability = direct_api_accounting_capability(config)

    assert cost_basis_for_model_config(config) is CostBasis.CATALOG_PRICED
    assert observation.basis is CostBasis.CATALOG_PRICED
    assert observation.provider_billed_usd is None
    assert observation.estimated_usd == pytest.approx(1.25)
    assert capability.mode is AccountingMode.AUTHORITATIVE
    assert capability.hard_limit_supported is False
    assert (
        capability.model_key_aggregation
        is ModelKeyAggregation.LEGACY_MODEL_NAME
    )


def test_configured_rate_is_estimated_and_requires_exact_trust() -> None:
    config = ModelConfig(
        provider="custom",
        model_name="model",
        cost_per_1k_tokens=0.01,
    )
    observation = estimated_cost_observation(config, 0.25)

    assert cost_basis_for_model_config(config) is CostBasis.CONFIGURED_RATE
    assert observation.basis is CostBasis.CONFIGURED_RATE
    assert not is_observation_authorized(observation, ())
    assert is_observation_authorized(
        observation,
        (
            TrustedUsdRoute(
                "custom", "model", CostBasis.CONFIGURED_RATE,
            ),
        ),
    )


@pytest.mark.parametrize(
    ("rate", "expected"),
    [
        (0.01, CostBasis.CONFIGURED_RATE),
        (0.0, CostBasis.UNKNOWN),
        (-0.01, CostBasis.UNKNOWN),
        ("bad", CostBasis.UNKNOWN),
    ],
)
def test_cost_basis_for_unlisted_model_rate_mapping(
    rate,
    expected: CostBasis,
) -> None:
    config = ModelConfig(
        provider="custom",
        model_name="unlisted-model",
        cost_per_1k_tokens=rate,
    )
    assert cost_basis_for_model_config(config) is expected


def test_catalog_model_beats_configured_rate_fallback() -> None:
    config = ModelConfig(
        provider="anthropic",
        model_name="claude-opus-4-6",
        cost_per_1k_tokens=999.0,
    )
    assert cost_basis_for_model_config(config) is CostBasis.CATALOG_PRICED


def test_authorization_requires_route_and_rejects_non_declarable_bases() -> None:
    assert not is_observation_authorized(
        CostObservation.catalog_priced(0.1, route=None),
        (
            TrustedUsdRoute(
                "anthropic", "model", CostBasis.CATALOG_PRICED,
            ),
        ),
    )
    route = RouteIdentity("anthropic", "model")
    for basis in (
        CostBasis.CLI_REPORTED,
        CostBasis.SUBSCRIPTION,
        CostBasis.UNKNOWN,
    ):
        assert not is_basis_authorized(
            basis=basis,
            route=route,
            trusted_routes=(),
        )


@pytest.mark.parametrize("api_base", [None, "http://localhost:11434/v1"])
def test_ollama_is_unknown_regardless_of_base_url(
    api_base: str | None,
) -> None:
    config = ModelConfig(
        provider="ollama",
        model_name="llama",
        api_base=api_base,
        cost_per_1k_tokens=0.0,
    )
    capability = direct_api_accounting_capability(config)
    observation = estimated_cost_observation(config, 0.0)

    assert capability.mode is AccountingMode.UNKNOWN
    assert capability.hard_limit_supported is False
    assert observation.basis is CostBasis.UNKNOWN
    assert observation.provider_billed_usd is None


def test_cli_reported_presence_distinguishes_absent_and_zero() -> None:
    route = RouteIdentity("claudecode", "model")

    absent = cli_cost_observation(
        cost_usd=0.0, cost_reported=False, route=route,
    )
    explicit_zero = cli_cost_observation(
        cost_usd=0.0, cost_reported=True, route=route,
    )

    assert absent.basis is CostBasis.UNKNOWN
    assert explicit_zero.basis is CostBasis.CLI_REPORTED
    assert explicit_zero.estimated_usd == 0.0
    assert explicit_zero.provider_billed_usd is None


def test_exact_pinned_config_requires_primary_model() -> None:
    with pytest.raises(
        ValueError,
        match="requires primary_model",
    ):
        LLMConfig(
            primary_model=None,
            fallback_models=[],
            specialized_models={},
            exact_pinned=True,
        )
