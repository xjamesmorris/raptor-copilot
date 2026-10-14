"""LLMClient accounting policy, settlement, and latch behavior."""

from __future__ import annotations

import math
import threading
from pathlib import Path

import pytest

from core.llm.accounting import (
    AccountingCapability,
    AccountingMode,
    CostBasis,
    CostObservation,
    LLMAccountingUnavailableError,
    LLMHardLimitUnsupportedError,
    ModelKeyAggregation,
    RouteIdentity,
    TrustedUsdRoute,
    UsdBudgetContract,
    attach_cost_observation,
)
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.providers import LLMResponse, StructuredResponse
from core.testing import make_test_client

_SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "string"}},
}


class _Provider:
    def __init__(
        self,
        *,
        basis: CostBasis,
        fail: bool = False,
        attach_failure_cost: bool = False,
    ) -> None:
        self.basis = basis
        self.response_basis = basis
        self.fail = fail
        self.attach_failure_cost = attach_failure_cost
        self.generate_calls = 0
        self.structured_calls = 0
        self.total_cost = 0.0
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cache_read_tokens = 0
        self.total_cache_write_tokens = 0
        self.call_count = 0
        self.total_duration = 0.0

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

    def _observation(self, route: RouteIdentity) -> CostObservation:
        if self.response_basis is CostBasis.PROVIDER_BILLED:
            return CostObservation.provider_billed(0.25, route=route)
        if self.response_basis is CostBasis.CATALOG_PRICED:
            return CostObservation.catalog_priced(0.25, route=route)
        if self.response_basis is CostBasis.CONFIGURED_RATE:
            return CostObservation.configured_rate(0.25, route=route)
        if self.response_basis is CostBasis.CLI_REPORTED:
            return CostObservation.cli_reported(0.25, route=route)
        if self.response_basis is CostBasis.SUBSCRIPTION:
            return CostObservation.subscription(route=route)
        return CostObservation.unknown(route=route)

    def cost_observation(
        self, cost: float, *, cost_reported: bool | None = None,
    ) -> CostObservation:
        del cost, cost_reported
        return self._observation(
            RouteIdentity("anthropic", "claude-opus-4-6"),
        )

    def generate(self, prompt, system_prompt=None, **kwargs):
        del prompt, system_prompt, kwargs
        self.generate_calls += 1
        route = RouteIdentity("anthropic", "claude-opus-4-6")
        observation = self._observation(route)
        if self.fail:
            error = RuntimeError("503 service unavailable")
            if self.attach_failure_cost:
                attach_cost_observation(error, observation)
            raise error
        return LLMResponse(
            content="ok",
            model=route.model,
            provider=route.provider,
            tokens_used=10,
            cost=observation.legacy_cost_usd,
            finish_reason="stop",
            cost_observation=observation,
        )

    def generate_structured(
        self, prompt, schema, system_prompt=None, **kwargs,
    ):
        del prompt, schema, system_prompt, kwargs
        self.structured_calls += 1
        route = RouteIdentity("anthropic", "claude-opus-4-6")
        observation = self._observation(route)
        if self.fail:
            error = RuntimeError("503 service unavailable")
            if self.attach_failure_cost:
                attach_cost_observation(error, observation)
            raise error
        return StructuredResponse(
            result={"answer": "ok"},
            raw='{"answer":"ok"}',
            cost=observation.legacy_cost_usd,
            tokens_used=10,
            model=route.model,
            provider=route.provider,
            cost_observation=observation,
        )


def _client(
    tmp_path: Path,
    *,
    contract: UsdBudgetContract,
    basis: CostBasis,
    trusted: bool = False,
    fail: bool = False,
    attach_failure_cost: bool = False,
    max_retries: int = 1,
):
    client = make_test_client(tmp_path, max_retries=max_retries)
    client.config.primary_model = ModelConfig(
        provider="anthropic",
        model_name="claude-opus-4-6",
        api_key="unused",
    )
    client.config.usd_budget_contract = contract
    client.config.enable_cost_tracking = True
    client.config.trusted_usd_routes = (
        (
            TrustedUsdRoute(
                "anthropic", "claude-opus-4-6", basis,
            ),
        )
        if trusted
        else ()
    )
    provider = _Provider(
        basis=basis,
        fail=fail,
        attach_failure_cost=attach_failure_cost,
    )
    client.providers["anthropic:claude-opus-4-6"] = provider
    return client, provider


@pytest.mark.parametrize(
    "basis",
    [
        CostBasis.CATALOG_PRICED,
        CostBasis.CONFIGURED_RATE,
        CostBasis.CLI_REPORTED,
        CostBasis.SUBSCRIPTION,
        CostBasis.UNKNOWN,
    ],
)
def test_authoritative_required_refuses_undeclared_basis_before_dispatch(
    tmp_path: Path,
    basis: CostBasis,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        basis=basis,
    )

    with pytest.raises(LLMAccountingUnavailableError):
        client.generate("p")

    assert provider.generate_calls == 0


@pytest.mark.parametrize(
    "basis",
    [CostBasis.CATALOG_PRICED, CostBasis.CONFIGURED_RATE],
)
def test_declared_estimate_basis_is_admitted(
    tmp_path: Path,
    basis: CostBasis,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        basis=basis,
        trusted=True,
    )

    response = client.generate("p")

    assert response.content == "ok"
    assert provider.generate_calls == 1
    assert client.get_stats()["accounting"]["usd_total_complete"] is True


def test_provider_billed_needs_no_declaration(tmp_path: Path) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        basis=CostBasis.PROVIDER_BILLED,
    )

    response = client.generate("p")

    assert response.cost_observation.basis is CostBasis.PROVIDER_BILLED
    assert provider.generate_calls == 1


def test_hard_limit_required_refuses_every_current_provider(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.HARD_LIMIT_REQUIRED,
        basis=CostBasis.PROVIDER_BILLED,
    )

    with pytest.raises(LLMHardLimitUnsupportedError) as excinfo:
        client.generate("p")

    assert provider.generate_calls == 0
    assert (
        excinfo.value.accounting.as_dict()
        == client.get_stats()["accounting"]
    )


def test_hard_limit_required_refuses_structured_before_dispatch(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.HARD_LIMIT_REQUIRED,
        basis=CostBasis.PROVIDER_BILLED,
    )

    with pytest.raises(LLMHardLimitUnsupportedError):
        client.generate_structured("p", _SCHEMA)

    assert provider.structured_calls == 0


def test_authoritative_required_refuses_untrusted_structured_route(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        basis=CostBasis.CATALOG_PRICED,
    )

    with pytest.raises(LLMAccountingUnavailableError):
        client.generate_structured("p", _SCHEMA)

    assert provider.structured_calls == 0


def test_authoritative_required_refuses_when_cost_tracking_disabled(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        basis=CostBasis.CATALOG_PRICED,
        trusted=True,
    )
    client.config.enable_cost_tracking = False

    with pytest.raises(
        LLMAccountingUnavailableError,
        match="enable_cost_tracking",
    ):
        client.generate("p")

    assert provider.generate_calls == 0


def test_pre_dispatch_refusal_carries_accumulated_accounting(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.ADVISORY,
        basis=CostBasis.CATALOG_PRICED,
    )
    client.generate("first")
    client.config.usd_budget_contract = (
        UsdBudgetContract.AUTHORITATIVE_REQUIRED
    )
    provider.basis = CostBasis.UNKNOWN

    with pytest.raises(LLMAccountingUnavailableError) as excinfo:
        client.generate("second")

    stats = client.get_stats()
    assert provider.generate_calls == 1
    assert stats["accounting"]["catalog_priced_calls"] == 1
    assert excinfo.value.accounting.as_dict() == stats["accounting"]


def test_missing_accounting_methods_refuse_strict_but_allow_advisory(
    tmp_path: Path,
) -> None:
    class _MinimalProvider:
        total_cost = 0.0
        total_tokens = 0
        total_input_tokens = 0
        total_output_tokens = 0
        total_cache_read_tokens = 0
        total_cache_write_tokens = 0
        call_count = 0
        total_duration = 0.0

        def __init__(self) -> None:
            self.calls = 0

        def generate(self, prompt, system_prompt=None, **kwargs):
            del prompt, system_prompt, kwargs
            self.calls += 1
            return LLMResponse(
                content="ok",
                model="test-primary",
                provider="anthropic",
                tokens_used=0,
                cost=0.0,
                finish_reason="stop",
            )

    strict = make_test_client(tmp_path / "strict")
    strict.config.usd_budget_contract = (
        UsdBudgetContract.AUTHORITATIVE_REQUIRED
    )
    strict.config.enable_cost_tracking = True
    strict_provider = _MinimalProvider()
    strict.providers["anthropic:test-primary"] = strict_provider
    with pytest.raises(LLMAccountingUnavailableError):
        strict.generate("p")
    assert strict_provider.calls == 0

    advisory = make_test_client(tmp_path / "advisory")
    advisory_provider = _MinimalProvider()
    advisory.providers["anthropic:test-primary"] = advisory_provider
    assert advisory.generate("p").content == "ok"
    assert advisory_provider.calls == 1


def test_cache_hit_precedes_authority_refusal(tmp_path: Path) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.ADVISORY,
        basis=CostBasis.UNKNOWN,
    )
    client.generate("cached")
    client.config.usd_budget_contract = (
        UsdBudgetContract.AUTHORITATIVE_REQUIRED
    )

    response = client.generate("cached")

    assert response.finish_reason == "cached"
    assert provider.generate_calls == 1


def test_structured_cache_hit_precedes_authority_refusal(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.ADVISORY,
        basis=CostBasis.UNKNOWN,
    )
    client.generate_structured("cached", _SCHEMA)
    client.config.usd_budget_contract = (
        UsdBudgetContract.AUTHORITATIVE_REQUIRED
    )

    response = client.generate_structured("cached", _SCHEMA)

    assert response.cached is True
    assert provider.structured_calls == 1


def test_advisory_unknown_is_explicitly_incomplete(tmp_path: Path) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.ADVISORY,
        basis=CostBasis.UNKNOWN,
    )

    response = client.generate("p")
    stats = client.get_stats()

    assert response.cost == 0.0
    assert response.cost_observation.basis is CostBasis.UNKNOWN
    assert provider.generate_calls == 1
    assert isinstance(stats["total_cost"], float)
    assert isinstance(stats["budget_remaining"], float)
    assert stats["accounting"]["unknown_calls"] == 1
    assert stats["accounting"]["usd_total_complete"] is False
    assert stats["accounting"]["authoritative_remaining_usd"] is None


@pytest.mark.parametrize("source", ["response", "provider"])
def test_foreign_route_observation_downgrades_to_unknown(
    tmp_path: Path,
    source: str,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.ADVISORY,
        basis=CostBasis.CATALOG_PRICED,
    )
    foreign = CostObservation.catalog_priced(
        0.25,
        route=RouteIdentity("bedrock", "claude-opus-4-6"),
    )
    if source == "response":
        provider.generate = lambda *a, **k: LLMResponse(
            content="ok",
            model="claude-opus-4-6",
            provider="anthropic",
            tokens_used=1,
            cost=0.25,
            finish_reason="stop",
            cost_observation=foreign,
        )
    else:
        provider.generate = lambda *a, **k: LLMResponse(
            content="ok",
            model="claude-opus-4-6",
            provider="anthropic",
            tokens_used=1,
            cost=0.25,
            finish_reason="stop",
        )
        provider.cost_observation = lambda *a, **k: foreign

    response = client.generate("p")

    assert response.cost_observation == CostObservation.unknown(
        route=RouteIdentity("anthropic", "claude-opus-4-6"),
    )
    assert client.get_stats()["accounting"]["unknown_calls"] == 1


def test_zero_cost_unknown_response_uses_response_fallback_path(
    tmp_path: Path,
) -> None:
    class _NoObservationMethodProvider:
        total_cost = 0.0
        total_tokens = 0
        total_input_tokens = 0
        total_output_tokens = 0
        total_cache_read_tokens = 0
        total_cache_write_tokens = 0
        call_count = 0
        total_duration = 0.0

        def __init__(self) -> None:
            self.calls = 0

        def generate(self, prompt, system_prompt=None, **kwargs):
            del prompt, system_prompt, kwargs
            self.calls += 1
            return LLMResponse(
                content="zero",
                model="test-primary",
                provider="anthropic",
                tokens_used=0,
                cost=0.0,
                finish_reason="stop",
                cost_observation=CostObservation.unknown(
                    route=RouteIdentity("bedrock", "test-primary"),
                ),
            )

    client = make_test_client(tmp_path)
    provider = _NoObservationMethodProvider()
    client.providers["anthropic:test-primary"] = provider

    response = client.generate("p")

    assert provider.calls == 1
    assert response.cost_observation == CostObservation.unknown(
        route=RouteIdentity("anthropic", "test-primary"),
    )
    assert client.get_stats()["accounting"]["unknown_calls"] == 1


def test_foreign_route_observation_latches_under_strict_policy(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        basis=CostBasis.CATALOG_PRICED,
        trusted=True,
    )
    provider.generate = lambda *a, **k: LLMResponse(
        content="ok",
        model="claude-opus-4-6",
        provider="anthropic",
        tokens_used=1,
        cost=0.25,
        finish_reason="stop",
        cost_observation=CostObservation.catalog_priced(
            0.25,
            route=RouteIdentity("bedrock", "claude-opus-4-6"),
        ),
    )

    with pytest.raises(LLMAccountingUnavailableError):
        client.generate("p")
    with pytest.raises(LLMAccountingUnavailableError):
        client.generate("later")


@pytest.mark.parametrize("bad_cost", [math.nan, math.inf, -1.0])
def test_malformed_freeform_cost_downgrades_without_poisoning_legacy_fields(
    tmp_path: Path,
    bad_cost: float,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.ADVISORY,
        basis=CostBasis.UNKNOWN,
    )

    def generate(*args, **kwargs):
        del args, kwargs
        provider.generate_calls += 1
        return LLMResponse(
            content="ok",
            model="claude-opus-4-6",
            provider="anthropic",
            tokens_used=1,
            cost=bad_cost,
            finish_reason="stop",
        )

    provider.generate = generate

    response = client.generate("p")

    assert response.cost == 0.0
    assert math.isfinite(client.total_cost)
    assert client.get_stats()["accounting"]["unknown_calls"] == 1


@pytest.mark.parametrize("bad_cost", [math.nan, math.inf, -1.0])
def test_malformed_structured_cost_downgrades_without_poisoning_legacy_fields(
    tmp_path: Path,
    bad_cost: float,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.ADVISORY,
        basis=CostBasis.UNKNOWN,
    )

    def generate_structured(*args, **kwargs):
        del args, kwargs
        provider.structured_calls += 1
        return StructuredResponse(
            result={"answer": "ok"},
            raw="{}",
            cost=bad_cost,
            tokens_used=1,
            model="claude-opus-4-6",
            provider="anthropic",
        )

    provider.generate_structured = generate_structured

    response = client.generate_structured("p", _SCHEMA)

    assert response.cost == 0.0
    assert math.isfinite(client.total_cost)
    assert client.get_stats()["accounting"]["unknown_calls"] == 1


def test_strict_unknown_failure_latches_and_retains_reservation(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        basis=CostBasis.CATALOG_PRICED,
        trusted=True,
        fail=True,
        attach_failure_cost=False,
        max_retries=3,
    )

    with pytest.raises(LLMAccountingUnavailableError) as first:
        client.generate("first", call_class="review")
    with pytest.raises(LLMAccountingUnavailableError) as second:
        client.generate("second", call_class="review")

    stats = client.get_stats()
    assert first.value.accounting.as_dict() == stats["accounting"]
    assert second.value is first.value
    assert provider.generate_calls == 1
    assert client.total_cost > 0.0
    assert isinstance(stats["budget_remaining"], float)
    assert stats["accounting"]["unknown_failed_attempts"] == 1
    assert stats["accounting"]["exposure_unresolved"] is True
    assert stats["accounting"]["authoritative_remaining_usd"] is None
    assert (
        stats["accounting"]["retained_reservation_estimate_usd"]
        == pytest.approx(client.total_cost)
    )


def test_advisory_unknown_failure_keeps_retry_behavior(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.ADVISORY,
        basis=CostBasis.UNKNOWN,
        fail=True,
        max_retries=2,
    )

    with pytest.raises(RuntimeError):
        client.generate("p")

    assert provider.generate_calls == 2
    assert client.total_cost == pytest.approx(0.0)
    assert client.get_stats()["accounting"]["unknown_failed_attempts"] == 2


def test_advisory_baseexception_is_settled_before_caller_catches(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.ADVISORY,
        basis=CostBasis.UNKNOWN,
    )

    def interrupt(*args, **kwargs):
        del args, kwargs
        raise KeyboardInterrupt

    provider.generate = interrupt

    with pytest.raises(KeyboardInterrupt):
        client.generate("p")

    assert provider.generate_calls == 0
    assert client.get_stats()["accounting"]["unknown_failed_attempts"] == 1


def test_post_settlement_baseexception_propagates_once_freeform(
    tmp_path: Path,
    monkeypatch,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.ADVISORY,
        basis=CostBasis.CATALOG_PRICED,
    )
    monkeypatch.setattr(
        client,
        "_validated_resolved_model",
        lambda value: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    with pytest.raises(KeyboardInterrupt):
        client.generate("p")

    assert provider.generate_calls == 1
    assert client.get_stats()["accounting"]["catalog_priced_calls"] == 1


def test_post_settlement_baseexception_propagates_once_structured(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import core.llm.client as client_module

    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.ADVISORY,
        basis=CostBasis.CATALOG_PRICED,
    )
    monkeypatch.setattr(
        client_module,
        "unknown_response_fields",
        lambda result, schema: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    with pytest.raises(KeyboardInterrupt):
        client.generate_structured("p", _SCHEMA)

    assert provider.structured_calls == 1
    assert client.get_stats()["accounting"]["catalog_priced_calls"] == 1


def test_strict_observed_failure_settles_once_without_latch(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        basis=CostBasis.CATALOG_PRICED,
        trusted=True,
        fail=True,
        attach_failure_cost=True,
    )

    with pytest.raises(RuntimeError):
        client.generate("p")

    stats = client.get_stats()
    assert provider.generate_calls == 1
    assert client.total_cost == pytest.approx(0.25)
    assert stats["accounting"]["catalog_priced_calls"] == 1
    assert stats["accounting"]["unknown_failed_attempts"] == 0
    assert stats["accounting"]["exposure_unresolved"] is False


def test_structured_post_call_downgrade_is_terminal_no_fallback(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        basis=CostBasis.CATALOG_PRICED,
        trusted=True,
    )
    provider.response_basis = CostBasis.UNKNOWN

    with pytest.raises(LLMAccountingUnavailableError):
        client.generate_structured("p", _SCHEMA)
    with pytest.raises(LLMAccountingUnavailableError):
        client.generate_structured("later", _SCHEMA)

    assert provider.structured_calls == 1


def test_structured_unknown_failure_latch_preserves_cause(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        basis=CostBasis.CATALOG_PRICED,
        trusted=True,
        fail=True,
    )

    with pytest.raises(LLMAccountingUnavailableError) as excinfo:
        client.generate_structured("p", _SCHEMA)

    assert isinstance(excinfo.value.__cause__, RuntimeError)
    with pytest.raises(LLMAccountingUnavailableError) as later:
        client.generate_structured("later", _SCHEMA)
    assert later.value is excinfo.value
    assert provider.structured_calls == 1


def test_freeform_failure_with_unauthorized_observation_latches(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        basis=CostBasis.CATALOG_PRICED,
        trusted=True,
        fail=True,
        attach_failure_cost=True,
    )
    provider.response_basis = CostBasis.CLI_REPORTED

    with pytest.raises(LLMAccountingUnavailableError) as excinfo:
        client.generate("p")

    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert client.get_stats()["accounting"]["cli_reported_calls"] == 1


def test_structured_schema_retry_settles_each_attempt_once(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        basis=CostBasis.CATALOG_PRICED,
        trusted=True,
        max_retries=2,
    )
    route = RouteIdentity("anthropic", "claude-opus-4-6")

    def generate_structured(*args, **kwargs):
        del args, kwargs
        provider.structured_calls += 1
        result = (
            {"answer": "retry", "unexpected": True}
            if provider.structured_calls == 1
            else {"answer": "ok"}
        )
        return StructuredResponse(
            result=result,
            raw="{}",
            cost=0.25,
            tokens_used=10,
            model=route.model,
            provider=route.provider,
            cost_observation=CostObservation.catalog_priced(
                0.25, route=route,
            ),
        )

    provider.generate_structured = generate_structured

    response = client.generate_structured("p", _SCHEMA)

    assert response.result == {"answer": "ok"}
    assert provider.structured_calls == 2
    stats = client.get_stats()
    assert stats["accounting"]["catalog_priced_calls"] == 2
    assert stats["accounting"]["catalog_priced_usd"] == pytest.approx(0.5)
    assert client.total_cost == pytest.approx(0.5)


def test_concurrent_latch_blocks_later_fresh_attempt(
    tmp_path: Path,
) -> None:
    client, provider = _client(
        tmp_path,
        contract=UsdBudgetContract.AUTHORITATIVE_REQUIRED,
        basis=CostBasis.CATALOG_PRICED,
        trusted=True,
        fail=True,
    )
    first_done = threading.Event()
    results: list[str] = []

    def first() -> None:
        try:
            client.generate("first")
        except LLMAccountingUnavailableError:
            results.append("latched")
        finally:
            first_done.set()

    def second() -> None:
        first_done.wait()
        try:
            client.generate("second")
        except LLMAccountingUnavailableError:
            results.append("blocked")

    threads = [threading.Thread(target=first), threading.Thread(target=second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(results) == ["blocked", "latched"]
    assert provider.generate_calls == 1


def test_client_latch_is_idempotent(tmp_path: Path) -> None:
    client = make_test_client(tmp_path)
    route = RouteIdentity("anthropic", "test-primary")

    first = client._latch_accounting_error(route, reason="first")
    second = client._latch_accounting_error(route, reason="second")

    assert first is second


def test_client_scorecard_refuses_unclassified_provider_key(
    tmp_path: Path,
) -> None:
    client = LLMClient.__new__(LLMClient)
    client.config = LLMConfig(
        primary_model=ModelConfig(
            provider="future-route",
            model_name="shared-model",
        ),
        fallback_models=[],
        specialized_models={},
        scorecard_path=tmp_path / "scorecard.json",
    )
    client._scorecard = None

    assert client.scorecard.is_model_refused("shared-model") is True


def test_client_scorecard_refuses_same_alias_across_routes(
    tmp_path: Path,
) -> None:
    client = LLMClient.__new__(LLMClient)
    client.config = LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic",
            model_name="shared-model",
        ),
        fallback_models=[
            ModelConfig(provider="bedrock", model_name="shared-model"),
        ],
        specialized_models={},
        scorecard_path=tmp_path / "scorecard.json",
    )
    client._scorecard = None

    assert client.scorecard.is_model_refused("shared-model") is True


def test_client_scorecard_allows_unambiguous_legacy_route(
    tmp_path: Path,
) -> None:
    client = LLMClient.__new__(LLMClient)
    client.config = LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic",
            model_name="legacy-model",
        ),
        fallback_models=[],
        specialized_models={},
        scorecard_path=tmp_path / "scorecard.json",
    )
    client._scorecard = None

    assert client.scorecard.is_model_refused("legacy-model") is False
