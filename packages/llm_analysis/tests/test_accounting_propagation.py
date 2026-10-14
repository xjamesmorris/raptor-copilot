"""Report propagation for typed accounting and route provenance."""

from __future__ import annotations

import json
import inspect
import logging
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import packages.llm_analysis.agent as agent_module
import raptor_agentic
from core.llm.accounting import (
    AccountingSummary,
    CostObservation,
    LLMAccountingUnavailableError,
    RouteIdentity,
    attach_cost_observation,
)
from core.llm.providers import LLMResponse, StructuredResponse
from packages.llm_analysis.agent import (
    AutonomousSecurityAgentV2,
    VulnerabilityContext,
    _analysis_metadata_from_response,
    _format_analysis_accounting,
    _raise_if_policy_error,
)
from packages.llm_analysis.dataflow_dispatch_client import DispatchClient
from packages.llm_analysis.dispatch import (
    DispatchResult,
    DispatchTask,
    dispatch_task,
    record_dispatch_accounting,
    strip_dispatch_metadata,
)
from packages.llm_analysis.orchestrator import (
    CostTracker,
    _label_claude_dispatch_result,
    _merge_results,
    _should_fallback_to_cc,
    format_cost_summary,
)
from raptor_agentic import (
    _accounting_console_lines,
    _format_report_accounting,
)


class _Task(DispatchTask):
    name = "accounting-test"

    def build_prompt(self, item):
        return str(item["finding_id"])


class _BrokenProcessingTask(_Task):
    def process_result(self, item, result):
        raise RuntimeError("post-processing failed")


def _finding(finding_id: str = "F-1") -> dict:
    return {
        "finding_id": finding_id,
        "rule_id": "test/rule",
        "file_path": "src/a.py",
        "start_line": 1,
    }


def _agent_vulnerability(tmp_path) -> VulnerabilityContext:
    (tmp_path / "a.py").write_text("value = 1\n", encoding="utf-8")
    return VulnerabilityContext({
        "finding_id": "F-agent",
        "rule_id": "test/rule",
        "file": "a.py",
        "startLine": 1,
        "endLine": 1,
        "message": "test finding",
        "level": "warning",
    }, tmp_path)


def _prepare_agent(monkeypatch, tmp_path, llm) -> AutonomousSecurityAgentV2:
    agent = AutonomousSecurityAgentV2.__new__(AutonomousSecurityAgentV2)
    agent.llm = llm
    agent.out_dir = tmp_path / "out"
    agent.out_dir.mkdir()
    agent.use_verified_exemplars = False
    agent._prompt_budget = lambda: 0
    agent._get_verified_outcomes = lambda: ()
    monkeypatch.setattr(
        "packages.llm_analysis.source_intel_inject."
        "evidence_blocks_for_finding",
        lambda finding: (),
    )
    monkeypatch.setattr(
        "core.threat_model.threat_model_untrusted_blocks",
        lambda path: [],
    )
    monkeypatch.setattr(
        "packages.llm_analysis.flow_context_inject."
        "context_blocks_for_finding",
        lambda finding: (),
    )
    monkeypatch.setattr(
        "packages.ghidra.context_inject.ghidra_blocks_for_finding",
        lambda finding: (),
    )
    return agent


def _result(
    observation: CostObservation | None,
    *,
    cost: float = 0.0,
    result: dict | None = None,
    cache_hit: bool = False,
    core_accounted: bool = False,
) -> DispatchResult:
    route = observation.route if observation else RouteIdentity("openai", "same-model")
    return DispatchResult(
        result=result or {
            "is_true_positive": True,
            "is_exploitable": False,
            "exploitability_score": 0.1,
            "reasoning": "ok",
        },
        cost=cost,
        tokens=10,
        model=route.model,
        provider=route.provider,
        cost_observation=observation,
        cache_hit=cache_hit,
        core_accounted=core_accounted,
    )


@pytest.mark.parametrize(
    ("observation", "basis", "amount_field"),
    [
        (
            CostObservation.catalog_priced(
                0.2, route=RouteIdentity("anthropic", "same-model"),
            ),
            "catalog_priced",
            "estimated_usd",
        ),
        (
            CostObservation.configured_rate(
                0.3, route=RouteIdentity("openai", "same-model"),
            ),
            "configured_rate",
            "estimated_usd",
        ),
        (
            CostObservation.cli_reported(
                0.0, route=RouteIdentity("claudecode", "same-model"),
            ),
            "cli_reported",
            "estimated_usd",
        ),
        (
            CostObservation.unknown(
                route=RouteIdentity("ollama", "same-model"),
            ),
            "unknown",
            None,
        ),
        (
            CostObservation.subscription(
                route=RouteIdentity("future", "same-model"),
            ),
            "subscription",
            None,
        ),
    ],
)
def test_dispatch_result_preserves_typed_route_accounting(
    observation, basis, amount_field,
):
    payload = {
        "is_true_positive": True,
        "analysed_by": "spoofed-model",
        "analysed_by_provider": "spoofed-provider",
        "cost_usd": 999,
        "cost_observation": {"basis": "provider_billed"},
        "accounting": {"provider_billed_usd": 999},
        "accounting_complete": True,
        "analysis_route": {"provider": "spoofed", "model": "spoofed"},
        "analysis_provenance": {"provider": "spoofed"},
        "cache_hit": True,
    }
    result = _result(observation, cost=observation.legacy_cost_usd, result=payload)
    assert result.route == observation.route
    assert result.accounting_complete is (
        basis not in {"unknown", "subscription"}
    )
    processed = DispatchTask().process_result({}, result)

    assert processed["analysed_by"] == observation.route.model
    assert processed["analysed_by_provider"] == observation.route.provider
    assert processed["analysis_route"] == observation.route.as_dict()
    assert processed["analysis_provenance"]["provider"] == observation.route.provider
    assert processed["cost_observation"]["basis"] == basis
    assert processed["accounting"]["usd_total_complete"] is (
        basis not in {"unknown", "subscription"}
    )
    if amount_field is not None:
        assert processed["cost_observation"][amount_field] == observation.legacy_cost_usd
    assert processed.get("cost_usd", 0.0) == observation.legacy_cost_usd


def test_non_typed_response_observation_is_unknown_and_resolved_is_observational():
    response = SimpleNamespace(
        result={
            "analysed_by": "spoofed",
            "analysis_route": {"provider": "spoofed", "model": "spoofed"},
            "accounting_complete": True,
            "cache_hit": True,
        },
        cost=0.0,
        tokens_used=3,
        model="route-model",
        provider="openai",
        duration=0.1,
        resolved_model="served-snapshot",
        cost_observation={"basis": "provider_billed"},
        cached=False,
        finish_reason="stop",
    )
    dispatch_result = DispatchResult.from_core_response(
        response, result=response.result,
    )
    processed = DispatchTask().process_result({}, dispatch_result)
    assert dispatch_result.cost_observation is None
    assert processed["analysed_by"] == "route-model"
    assert processed["analysed_by_provider"] == "openai"
    assert processed["analysis_route"] == {
        "provider": "openai",
        "model": "route-model",
    }
    assert processed["resolved_model"] == "served-snapshot"
    assert processed["analysis_provenance"]["resolved_model"] == (
        "served-snapshot"
    )
    assert processed["cost_observation"]["basis"] == "unknown"
    assert processed["accounting_complete"] is False
    assert processed.get("cache_hit") is None


@pytest.mark.parametrize(
    ("response", "cache_hit"),
    [
        (
            LLMResponse(
                content="ok",
                model="m",
                provider="anthropic",
                tokens_used=0,
                cost=0.0,
                finish_reason="cached",
            ),
            True,
        ),
        (
            StructuredResponse(
                result={"ok": True},
                raw="{}",
                model="m",
                provider="anthropic",
                cached=True,
            ),
            True,
        ),
    ],
)
def test_dispatch_result_from_core_response_preserves_cache_evidence(
    response, cache_hit,
):
    result = DispatchResult.from_core_response(response, result={"ok": True})
    assert result.provider == "anthropic"
    assert result.model == "m"
    assert result.cache_hit is cache_hit
    assert result.no_spend is True
    assert result.core_accounted is True


def test_core_response_rejects_scalar_observation_mismatch():
    response = StructuredResponse(
        result={"ok": True},
        raw="{}",
        cost=0.2,
        model="m",
        provider="anthropic",
        cost_observation=CostObservation.catalog_priced(
            0.1, route=RouteIdentity("anthropic", "m"),
        ),
    )
    with pytest.raises(ValueError, match="does not match"):
        DispatchResult.from_core_response(response, result=response.result)


def test_core_response_mismatch_becomes_per_item_error():
    response = StructuredResponse(
        result={"is_true_positive": True},
        raw="{}",
        cost=0.2,
        model="m",
        provider="anthropic",
        cost_observation=CostObservation.catalog_priced(
            0.1, route=RouteIdentity("anthropic", "m"),
        ),
    )
    tracker = CostTracker()
    results = dispatch_task(
        _Task(),
        [_finding()],
        lambda *args: DispatchResult.from_core_response(
            response, result=response.result,
        ),
        {},
        {},
        tracker,
        max_parallel=1,
    )
    assert results[0]["error_type"] == "error"
    assert "does not match" in results[0]["error"]
    assert "is_true_positive" not in results[0]
    assert tracker.get_summary()["failed_dispatches"] == 1


def test_dispatch_result_rejects_untyped_observation():
    with pytest.raises(TypeError, match="CostObservation"):
        DispatchResult(result={}, cost_observation={"basis": "unknown"})


def test_tracker_rejects_scalar_observation_mismatch():
    tracker = CostTracker()
    with pytest.raises(ValueError, match="typed observation"):
        tracker.record_attempt(
            "m",
            cost=0.2,
            observation=CostObservation.catalog_priced(
                0.1, route=RouteIdentity("anthropic", "m"),
            ),
        )


def test_observation_route_wins_over_mislabeled_dispatch_fields():
    observation = CostObservation.catalog_priced(
        0.2, route=RouteIdentity("bedrock", "served-model"),
    )
    result = DispatchResult(
        result={"is_true_positive": True},
        cost=0.2,
        model="requested-model",
        provider="anthropic",
        cost_observation=observation,
    )
    processed = DispatchTask().process_result({}, result)
    assert processed["analysed_by"] == "served-model"
    assert processed["analysed_by_provider"] == "bedrock"
    assert processed["analysis_route"] == {
        "provider": "bedrock",
        "model": "served-model",
    }
    tracker = CostTracker()
    record_dispatch_accounting(tracker, result)
    assert tracker.get_summary()["cost_by_model"] == {"served-model": 0.2}


def test_claude_dispatch_label_is_canonical_and_non_destructive():
    unlabeled = DispatchResult(result={}, model="claude-code")
    assert _label_claude_dispatch_result(unlabeled).provider == "claudecode"
    labeled = DispatchResult(
        result={}, model="m", provider="bedrock",
    )
    assert _label_claude_dispatch_result(labeled).provider == "bedrock"


def test_cost_tracker_mixed_summary_and_honest_zero_rendering():
    tracker = CostTracker(max_cost=10.0)
    observations = [
        CostObservation.provider_billed(
            0.0, route=RouteIdentity("future", "m"),
        ),
        CostObservation.catalog_priced(
            0.2, route=RouteIdentity("anthropic", "m"),
        ),
        CostObservation.configured_rate(
            0.3, route=RouteIdentity("openai", "m"),
        ),
        CostObservation.cli_reported(
            0.0, route=RouteIdentity("claudecode", "m"),
        ),
        CostObservation.subscription(
            route=RouteIdentity("unclassified", "m"),
        ),
        CostObservation.unknown(
            route=RouteIdentity("ollama", "m"),
        ),
    ]
    for observation in observations:
        tracker.record_attempt(
            observation.route.model,
            cost=observation.legacy_cost_usd,
            observation=observation,
        )
    tracker.record_attempt(
        "m",
        cost=0.0,
        observation=CostObservation.unknown(
            route=RouteIdentity("openai", "m"),
        ),
        failed=True,
        retained_reservation_estimate_usd=0.4,
    )

    summary = tracker.get_summary()
    assert summary["total_cost"] == 0.5
    assert summary["provider_billed_calls"] == 1
    assert summary["catalog_priced_calls"] == 1
    assert summary["configured_rate_calls"] == 1
    assert summary["cli_reported_calls"] == 1
    assert summary["subscription_calls"] == 1
    assert summary["unknown_calls"] == 1
    assert summary["unknown_failed_attempts"] == 1
    assert summary["retained_reservation_estimate_usd"] == 0.4
    assert summary["usd_total_complete"] is False
    assert summary["exposure_unresolved"] is True
    assert set(summary["accounting_by_route"]) == {
        "anthropic/m",
        "claudecode/m",
        "future/m",
        "ollama/m",
        "openai/m",
        "unclassified/m",
    }
    rendered = format_cost_summary(summary)
    assert "Known USD $0.00" in rendered
    assert "Estimated USD $0.50" in rendered
    assert "incomplete" in rendered
    assert "unresolved exposure: actual unknown" in rendered
    assert "Total cost: $0" not in rendered
    assert _format_report_accounting(summary) == rendered
    assert _format_analysis_accounting(summary) == rendered
    assert json.loads(json.dumps(summary))["unknown_calls"] == 1
    lines = _accounting_console_lines({
        **summary,
        "thinking_tokens": 12,
        "cost_by_model": {"m1": 0.2, "m2": 0.3},
    })
    assert lines == [
        f"   Accounting: {rendered} (12 thinking tokens)",
        "     m1: $0.20",
        "     m2: $0.30",
    ]
    assert _accounting_console_lines({
        "total_cost": 0.0,
        "thinking_tokens": 7,
    }) == ["   Thinking tokens: 7"]


@pytest.mark.parametrize(
    "observation",
    [
        CostObservation.unknown(
            route=RouteIdentity("ollama", "m"),
        ),
        CostObservation.subscription(
            route=RouteIdentity("unclassified", "m"),
        ),
    ],
)
def test_sequential_process_summary_uses_honest_formatter(
    monkeypatch, tmp_path, caplog, observation,
):
    accounting = AccountingSummary().add(observation)

    class _LLM:
        def get_stats(self):
            return {
                "total_requests": 1,
                "total_cost": 0.0,
                "accounting": accounting.as_dict(),
            }

    availability = SimpleNamespace(external_llm=True, claude_code=False)
    config = SimpleNamespace(
        primary_model=SimpleNamespace(
            provider="anthropic",
            model_name="m",
            cost_per_1k_tokens=0.1,
        ),
    )
    llm = _LLM()
    llm.config = config
    with patch(
        "packages.llm_analysis.agent.detect_llm_availability",
        return_value=availability,
    ), patch(
        "packages.llm_analysis.agent.build_llm_client",
        return_value=llm,
    ):
        agent = AutonomousSecurityAgentV2(
            repo_path=tmp_path,
            out_dir=tmp_path / "out",
            llm_config=config,
            generate_exploits=False,
            generate_patches=False,
            synthesise_checkers=False,
            record_witnesses=False,
            use_verified_exemplars=False,
        )
    monkeypatch.setattr(
        "packages.llm_analysis.agent.parse_sarif_findings",
        lambda path: [],
    )
    monkeypatch.setattr(
        "packages.llm_analysis.agent.deduplicate_findings",
        lambda findings: findings,
    )
    monkeypatch.setattr(
        "packages.llm_analysis.source_intel_inject.prepare_source_intel",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "packages.ghidra.context_inject.prepare_ghidra_context",
        lambda *args, **kwargs: None,
    )
    caplog.set_level(logging.INFO)
    report = agent.process_findings(
        sarif_paths=["empty.sarif"],
        emit_journal=False,
    )
    assert report["llm_stats"]["accounting"] == accounting.as_dict()
    assert "Accounting: Estimated USD $0.00" in caplog.text
    assert "incomplete" in caplog.text
    assert "Total cost: $0" not in caplog.text


def test_report_call_sites_use_shared_formatter_without_zero_cost_literal():
    sources = (
        inspect.getsource(
            agent_module.AutonomousSecurityAgentV2.process_findings,
        ),
        inspect.getsource(agent_module.main),
        inspect.getsource(raptor_agentic.main),
    )
    assert "_format_analysis_accounting" in sources[0]
    assert "_format_analysis_accounting" in sources[1]
    assert "_accounting_console_lines" in sources[2]
    assert "_format_report_accounting" in sources[2]
    assert "print(sanitise_for_terminal(line))" in sources[2]
    for source in sources:
        assert "Total cost: $0" not in source
        assert "Cost: $" not in source


def test_cost_tracker_concurrent_observations_are_exactly_once():
    tracker = CostTracker()
    observation = CostObservation.catalog_priced(
        0.01, route=RouteIdentity("anthropic", "m"),
    )
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(
            lambda _: tracker.record_attempt(
                "m", cost=0.01, observation=observation,
            ),
            range(100),
        ))
    summary = tracker.get_summary()
    assert summary["total_cost"] == pytest.approx(1.0)
    assert summary["catalog_priced_usd"] == pytest.approx(1.0)
    assert summary["catalog_priced_calls"] == 100


@pytest.mark.parametrize("cost", [-0.01, float("nan"), float("inf")])
def test_cost_tracker_rejects_malformed_legacy_amounts(cost):
    tracker = CostTracker()
    with pytest.raises(ValueError, match="finite non-negative"):
        tracker.record_attempt("m", cost=cost)


@pytest.mark.parametrize(
    ("kwargs", "error_type"),
    [
        ({"cost": 0.0, "observation": {"basis": "unknown"}}, TypeError),
        ({"cost": 0.0, "route": "openai/m"}, TypeError),
        ({"cost": "0.1"}, ValueError),
        ({"cost": 0.0, "tokens": 1.5}, ValueError),
        ({"cost": 0.0, "tokens": True}, ValueError),
        ({"cost": 0.0, "thinking_tokens": -1}, ValueError),
    ],
)
def test_record_attempt_type_and_range_guards(kwargs, error_type):
    with pytest.raises(error_type):
        CostTracker().record_attempt("m", **kwargs)


def test_negative_retained_reservation_is_rejected():
    with pytest.raises(ValueError, match="retained_reservation"):
        CostTracker().record_attempt(
            "m",
            cost=0.0,
            observation=CostObservation.unknown(
                route=RouteIdentity("openai", "m"),
            ),
            failed=True,
            retained_reservation_estimate_usd=-0.1,
        )


def test_no_spend_record_rejects_nonzero_cost():
    tracker = CostTracker()
    with pytest.raises(ValueError, match="no-spend"):
        tracker.record_attempt("m", cost=0.01, no_spend=True)


def test_unknown_only_summary_never_claims_complete_zero_cost():
    tracker = CostTracker()
    tracker.record_attempt(
        "m",
        cost=0.0,
        observation=CostObservation.unknown(
            route=RouteIdentity("ollama", "m"),
        ),
    )
    summary = tracker.get_summary()
    assert summary["total_cost"] == 0.0
    assert summary["usd_total_complete"] is False
    assert format_cost_summary(summary) == (
        "Estimated USD $0.00 — incomplete (1 unknown calls)"
    )


def test_legacy_aggregate_cost_is_incomplete_without_fake_attempt_count():
    tracker = CostTracker()
    tracker.add_cost("ranking", 0.2)
    summary = tracker.get_summary()
    assert summary["total_cost"] == 0.2
    assert summary["unknown_calls"] == 0
    assert summary["unclassified_legacy_events"] == 1
    assert summary["usd_total_complete"] is False
    assert format_cost_summary(summary) == (
        "Estimated USD $0.20 "
        "(legacy; accounting basis unavailable) — incomplete "
        "(1 unclassified event)"
    )


def test_cache_hit_is_no_spend_not_unknown():
    tracker = CostTracker()
    results = dispatch_task(
        _Task(),
        [_finding()],
        lambda *args: _result(
            CostObservation.unknown(route=RouteIdentity("openai", "m")),
            cache_hit=True,
            core_accounted=True,
        ),
        {},
        {},
        tracker,
        max_parallel=1,
    )
    summary = tracker.get_summary()
    assert summary["cache_hits"] == 1
    assert summary["unknown_calls"] == 0
    assert summary["unknown_failed_attempts"] == 0
    assert summary["total_cost"] == 0.0
    assert results[0]["cache_hit"] is True
    assert results[0]["accounting_complete"] is True
    assert "cost_observation" not in results[0]


def test_error_envelope_observation_is_settled_once():
    tracker = CostTracker()
    observation = CostObservation.catalog_priced(
        0.25, route=RouteIdentity("anthropic", "m"),
    )
    results = dispatch_task(
        _Task(),
        [_finding()],
        lambda *args: _result(
            observation,
            cost=0.25,
            result={"error": "timeout after usage"},
        ),
        {},
        {},
        tracker,
        max_parallel=1,
    )
    summary = tracker.get_summary()
    assert results[0]["error_type"] == "timeout"
    assert results[0]["analysed_by_provider"] == "anthropic"
    assert results[0]["cost_observation"]["basis"] == "catalog_priced"
    assert summary["total_cost"] == 0.25
    assert summary["catalog_priced_calls"] == 1
    assert summary["failed_dispatches"] == 1


def test_successful_transport_is_accounted_once_when_processing_fails():
    tracker = CostTracker()
    observation = CostObservation.catalog_priced(
        0.2, route=RouteIdentity("anthropic", "m"),
    )
    results = dispatch_task(
        _BrokenProcessingTask(),
        [_finding()],
        lambda *args: _result(observation, cost=0.2),
        {},
        {},
        tracker,
        max_parallel=1,
    )
    summary = tracker.get_summary()
    assert results[0]["error"] == "post-processing failed"
    assert summary["total_cost"] == 0.2
    assert summary["catalog_priced_calls"] == 1
    assert summary["failed_dispatches"] == 0


def test_usage_bearing_legacy_error_is_unknown_failed_not_free():
    tracker = CostTracker()
    results = dispatch_task(
        _Task(),
        [_finding()],
        lambda *args: DispatchResult(
            result={"error": "timeout after usage"},
            cost=0.0,
            tokens=17,
            model="legacy-cli",
            provider="claudecode",
        ),
        {},
        {},
        tracker,
        max_parallel=1,
    )
    summary = tracker.get_summary()
    assert results[0]["error_type"] == "timeout"
    assert results[0]["cost_observation"]["basis"] == "unknown"
    assert summary["unknown_failed_attempts"] == 1
    assert summary["usd_total_complete"] is False


def test_raised_observation_is_settled_once():
    tracker = CostTracker()
    error = attach_cost_observation(
        TimeoutError("timed out"),
        CostObservation.cli_reported(
            0.4, route=RouteIdentity("claudecode", "m"),
        ),
    )

    def fail(*args):
        raise error

    results = dispatch_task(
        _Task(), [_finding()], fail, {}, {}, tracker, max_parallel=1,
    )
    summary = tracker.get_summary()
    assert results[0]["error_type"] == "timeout"
    assert results[0]["analysed_by_provider"] == "claudecode"
    assert summary["total_cost"] == 0.4
    assert summary["cli_reported_calls"] == 1
    assert summary["failed_dispatches"] == 1


def test_policy_refusal_stays_typed_and_disables_cc_fallback():
    tracker = CostTracker()

    def refuse(*args):
        raise LLMAccountingUnavailableError("strict refusal")

    with pytest.raises(LLMAccountingUnavailableError):
        dispatch_task(
            _Task(),
            [_finding("F-1"), _finding("F-2"), _finding("F-3")],
            refuse,
            {},
            {},
            tracker,
            max_parallel=1,
        )
    assert _should_fallback_to_cc([
        {"error": "strict refusal", "error_type": "policy_refusal"},
    ]) is False
    assert _should_fallback_to_cc([
        {"error": "ordinary transport failure", "error_type": "error"},
    ]) is True


def test_core_snapshot_replaces_provisional_results_without_double_counting():
    tracker = CostTracker()
    observation = CostObservation.catalog_priced(
        0.1, route=RouteIdentity("anthropic", "m"),
    )
    tracker.record_attempt(
        "m",
        cost=0.1,
        tokens=10,
        observation=observation,
        core_accounted=True,
    )
    core_accounting = AccountingSummary()
    for amount in (0.1, 0.2):
        core_accounting = core_accounting.add(
            CostObservation.catalog_priced(
                amount, route=RouteIdentity("anthropic", "m"),
            ),
        )
    core_accounting = core_accounting.with_authoritative_remaining(9.7)
    summary = tracker.get_summary(core_stats={
        "total_cost": 0.3,
        "accounting": core_accounting.as_dict(),
        "providers": {
            "anthropic:m": {
                "total_cost": 0.3,
                "total_tokens": 30,
                "accounting": core_accounting.as_dict(),
            },
        },
    })
    assert summary["total_cost"] == 0.3
    assert summary["catalog_priced_usd"] == pytest.approx(0.3)
    assert summary["catalog_priced_calls"] == 2
    assert summary["authoritative_remaining_usd"] == 9.7
    assert summary["total_tokens"] == 30
    assert summary["cost_by_model"]["m"] == pytest.approx(0.3)
    assert summary["accounting_by_route"]["anthropic/m"]["catalog_priced_calls"] == 2


def test_provider_summary_fallback_skips_malformed_entries_and_keeps_noncore():
    tracker = CostTracker()
    tracker.add_cost("ranker", 0.1)
    route = RouteIdentity("anthropic", "m")
    tracker.record_attempt(
        "m",
        cost=0.2,
        tokens=10,
        observation=CostObservation.catalog_priced(0.2, route=route),
        core_accounted=True,
    )
    tracker.record_attempt(
        "claude-code",
        cost=0.25,
        tokens=15,
        observation=CostObservation.unknown(
            route=RouteIdentity("claudecode", "claude-code"),
        ),
    )
    provider_summary = (
        AccountingSummary()
        .add(CostObservation.catalog_priced(0.2, route=route))
        .add(CostObservation.catalog_priced(0.3, route=route))
    )
    summary = tracker.get_summary(core_stats={
        "total_cost": 0.6,
        "cache_hits": 0,
        "providers": {
            "anthropic:m": {
                "total_cost": 0.5,
                "total_tokens": 30,
                "accounting": provider_summary.as_dict(),
            },
            "malformed-key": {
                "total_cost": 99,
                "accounting": provider_summary.as_dict(),
            },
            "bad-value": ["not", "a", "mapping"],
            "openai:bad": {
                "total_cost": "invalid",
                "total_tokens": "invalid",
                "accounting": "invalid",
            },
        },
    }, core_precharged_cost=0.1)
    assert summary["total_cost"] == 0.85
    assert summary["catalog_priced_usd"] == 0.5
    assert summary["catalog_priced_calls"] == 2
    assert summary["unknown_calls"] == 1
    assert summary["unclassified_legacy_events"] == 1
    assert summary["cost_by_model"] == {
        "ranker": 0.1,
        "claude-code": 0.25,
        "m": 0.5,
    }
    assert set(summary["accounting_by_route"]) == {
        "anthropic/m",
        "claudecode/claude-code",
    }


def test_dataflow_client_tracks_zero_unknown_and_preserves_policy_errors():
    tracker = CostTracker()
    response = _result(
        CostObservation.unknown(route=RouteIdentity("ollama", "m")),
    )
    client = DispatchClient(lambda *args: response, "m", cost_tracker=tracker)
    assert client.generate_structured("p", {}) == response.result
    assert tracker.get_summary()["unknown_calls"] == 1

    policy_error = LLMAccountingUnavailableError("strict refusal")
    refusing = DispatchClient(
        lambda *args: (_ for _ in ()).throw(policy_error),
        "m",
        cost_tracker=tracker,
    )
    with pytest.raises(LLMAccountingUnavailableError):
        refusing.generate_structured("p", {})
    with pytest.raises(LLMAccountingUnavailableError):
        _raise_if_policy_error(policy_error)
    _raise_if_policy_error(RuntimeError("ordinary failure"))


def test_dataflow_client_keeps_ordinary_failure_as_no_verdict():
    tracker = CostTracker()
    client = DispatchClient(
        lambda *args: (_ for _ in ()).throw(RuntimeError("transport failed")),
        "m",
        cost_tracker=tracker,
    )
    assert client.generate_structured("p", {}) is None
    assert tracker.get_summary()["failed_dispatches"] == 1


def test_dataflow_error_envelope_tracks_observation_once():
    tracker = CostTracker()
    response = _result(
        CostObservation.configured_rate(
            0.15, route=RouteIdentity("openai", "m"),
        ),
        cost=0.15,
        result={"error": "structured response failed"},
    )
    client = DispatchClient(lambda *args: response, "m", cost_tracker=tracker)
    assert client.generate_structured("p", {}) is None
    summary = tracker.get_summary()
    assert summary["total_cost"] == 0.15
    assert summary["configured_rate_calls"] == 1
    assert summary["failed_dispatches"] == 1


def test_dataflow_non_dict_result_records_failed_once():
    tracker = CostTracker()
    observation = CostObservation.catalog_priced(
        0.12, route=RouteIdentity("anthropic", "m"),
    )
    response = DispatchResult(
        result="not-a-dict",
        cost=0.12,
        model="m",
        provider="anthropic",
        cost_observation=observation,
    )
    client = DispatchClient(lambda *args: response, "m", cost_tracker=tracker)
    assert client.generate_structured("p", {}) is None
    summary = tracker.get_summary()
    assert summary["total_cost"] == 0.12
    assert summary["catalog_priced_calls"] == 1
    assert summary["failed_dispatches"] == 1


def test_sequential_finding_provenance_comes_from_response_not_content(tmp_path):
    response = StructuredResponse(
        result={
            "analysed_by_provider": "spoofed",
            "analysis_provenance": {"provider": "spoofed"},
        },
        raw="{}",
        cost=0.0,
        model="m",
        provider="anthropic",
        cost_observation=CostObservation.catalog_priced(
            0.0, route=RouteIdentity("anthropic", "m"),
        ),
    )
    metadata = _analysis_metadata_from_response(response)
    vuln = VulnerabilityContext(_finding(), tmp_path)
    vuln.analysis = strip_dispatch_metadata(response.result)
    vuln.analysis_metadata = metadata
    output = vuln.to_dict()
    assert "analysed_by_provider" not in output["analysis"]
    assert "analysis_provenance" not in output["analysis"]
    assert output["analysed_by_provider"] == "anthropic"
    assert output["analysis_provenance"]["provider"] == "anthropic"
    assert output["cost_observation"]["basis"] == "catalog_priced"


def test_sequential_analysis_path_attaches_core_metadata(monkeypatch, tmp_path):
    payload = {
        "is_true_positive": True,
        "is_exploitable": False,
        "exploitability_score": 0.1,
        "confidence": "high",
        "severity_assessment": "low",
        "ruling": "not_exploitable",
        "reasoning": "not reachable",
        "attack_scenario": None,
        "exploit_code": None,
        "patch_code": None,
        "cvss_vector": None,
        "cvss_score_estimate": None,
        "vuln_type": None,
        "cwe_id": None,
        "dataflow_summary": None,
        "remediation": "none",
        "false_positive_reason": None,
        "analysed_by_provider": "spoofed",
    }
    response = StructuredResponse(
        result=payload,
        raw="{}",
        cost=0.1,
        model="m",
        provider="anthropic",
        cost_observation=CostObservation.catalog_priced(
            0.1, route=RouteIdentity("anthropic", "m"),
        ),
    )

    class _LLM:
        def generate_structured(self, **kwargs):
            return response

    agent = _prepare_agent(monkeypatch, tmp_path, _LLM())
    vuln = _agent_vulnerability(tmp_path)
    assert agent.analyze_vulnerability(vuln) is True
    output = vuln.to_dict()
    assert "analysed_by_provider" not in output["analysis"]
    assert output["analysed_by_provider"] == "anthropic"
    assert output["analysis_route"] == {
        "provider": "anthropic",
        "model": "m",
    }


def test_retry_selected_result_drops_stale_initial_metadata(
    monkeypatch, tmp_path,
):
    initial_payload = {
        "is_true_positive": True,
        "is_exploitable": False,
        "exploitability_score": 0.1,
        "reasoning": "initial",
    }
    retry_payload = {
        "is_true_positive": True,
        "is_exploitable": False,
        "exploitability_score": 0.2,
        "reasoning": "retry selected",
    }
    initial = SimpleNamespace(
        data=initial_payload,
        quality=0.2,
        incomplete=["reasoning"],
        coerced=[],
    )
    retry = SimpleNamespace(
        data=retry_payload,
        quality=1.0,
        incomplete=[],
        coerced=[],
    )
    response = StructuredResponse(
        result=initial_payload,
        raw="{}",
        cost=0.1,
        model="initial-model",
        provider="anthropic",
        cost_observation=CostObservation.catalog_priced(
            0.1,
            route=RouteIdentity("anthropic", "initial-model"),
        ),
    )

    class _LLM:
        def generate_structured(self, **kwargs):
            return response

    monkeypatch.setattr(
        "core.llm.response_validation.validate_structured_response",
        lambda result, schema: initial,
    )
    monkeypatch.setattr(
        "core.llm.response_validation.attempt_quality_retry",
        lambda *args, **kwargs: retry,
    )
    agent = _prepare_agent(monkeypatch, tmp_path, _LLM())
    vuln = _agent_vulnerability(tmp_path)
    assert agent.analyze_vulnerability(vuln) is True
    assert vuln.analysis["reasoning"] == "retry selected"
    assert vuln.analysis_metadata == {}
    output = vuln.to_dict()
    assert "analysed_by_provider" not in output
    assert "analysis_provenance" not in output


def test_sequential_cost_observation_mismatch_is_analysis_failure(
    monkeypatch, tmp_path,
):
    response = StructuredResponse(
        result={
            "is_true_positive": True,
            "is_exploitable": False,
            "exploitability_score": 0.1,
            "reasoning": "would otherwise be clean",
        },
        raw="{}",
        cost=0.2,
        model="m",
        provider="anthropic",
        cost_observation=CostObservation.catalog_priced(
            0.1, route=RouteIdentity("anthropic", "m"),
        ),
    )

    class _LLM:
        def generate_structured(self, **kwargs):
            return response

    agent = _prepare_agent(monkeypatch, tmp_path, _LLM())
    vuln = _agent_vulnerability(tmp_path)
    assert agent.analyze_vulnerability(vuln) is False
    assert vuln.analysis is None
    assert vuln.analysis_metadata == {}


def test_sequential_analysis_path_reraises_policy(monkeypatch, tmp_path):
    policy_error = LLMAccountingUnavailableError("strict refusal")

    class _LLM:
        def generate_structured(self, **kwargs):
            raise policy_error

    agent = _prepare_agent(monkeypatch, tmp_path, _LLM())
    with pytest.raises(LLMAccountingUnavailableError):
        agent.analyze_vulnerability(_agent_vulnerability(tmp_path))


def test_sequential_dataflow_path_reraises_policy(monkeypatch, tmp_path):
    policy_error = LLMAccountingUnavailableError("strict refusal")

    class _LLM:
        def generate_structured(self, **kwargs):
            raise policy_error

    agent = _prepare_agent(monkeypatch, tmp_path, _LLM())
    vuln = _agent_vulnerability(tmp_path)
    vuln.has_dataflow = True
    vuln.dataflow_source = {"file": "a.py", "line": 1, "label": "source"}
    vuln.dataflow_sink = {"file": "a.py", "line": 1, "label": "sink"}
    vuln.dataflow_steps = []
    with pytest.raises(LLMAccountingUnavailableError):
        agent.validate_dataflow(vuln)


@pytest.mark.parametrize("method_name", ["generate_exploit", "generate_patch"])
def test_sequential_generation_paths_reraise_policy(
    monkeypatch, tmp_path, method_name,
):
    policy_error = LLMAccountingUnavailableError("strict refusal")

    class _LLM:
        def generate(self, **kwargs):
            raise policy_error

    agent = _prepare_agent(monkeypatch, tmp_path, _LLM())
    agent._tier1_pre_flight = lambda vuln: "no_check"
    agent._smt_pre_flight = lambda vuln: "no_check"
    vuln = _agent_vulnerability(tmp_path)
    vuln.exploitable = True
    vuln.analysis = {
        "is_true_positive": True,
        "is_exploitable": True,
        "reasoning": "test",
    }
    with pytest.raises(LLMAccountingUnavailableError):
        getattr(agent, method_name)(vuln)


def test_merge_forces_trusted_error_provenance_over_prep_data():
    prep = {
        "mode": "prep_only",
        "results": [{
            **_finding(),
            "analysed_by_provider": "spoofed",
            "cost_observation": {"basis": "provider_billed"},
        }],
    }
    error = {
        "finding_id": "F-1",
        "error": "timed out",
        "error_type": "timeout",
        "analysed_by": "m",
        "analysed_by_provider": "anthropic",
        "analysis_route": {"provider": "anthropic", "model": "m"},
        "cost_observation": CostObservation.catalog_priced(
            0.2, route=RouteIdentity("anthropic", "m"),
        ).as_dict(),
    }
    merged = _merge_results(prep, [error])
    finding = merged["results"][0]
    assert finding["analysed_by_provider"] == "anthropic"
    assert finding["cost_observation"]["basis"] == "catalog_priced"
