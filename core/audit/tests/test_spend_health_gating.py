"""Spend health-gating: IRIS refinement pays only into live channels,
and the end-of-run consumers' reserve slices are enforced by handover.
Hermetic — no LLM calls, no joern."""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.audit.iris_specs as iris_specs
import core.audit.orchestrator as orch
import core.iris.refine as iris_refine
from core.audit.cost_tracker import PhaseCostLedger
from core.audit.orchestrator import (
    OrchestratorConfig,
    _hold_deepen_reserve,
    _iris_refine_and_bypass,
)
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig


def _real_client(cap: float) -> LLMClient:
    config = LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic", model_name="stub-model", api_key="k",
        ),
        enable_caching=False,
        enable_fallback=False,
        enable_cost_tracking=True,
        max_cost_per_scan=cap,
        max_retries=1,
    )
    return LLMClient(config)


@pytest.fixture
def iris_env(monkeypatch):
    """Stub every external of _iris_refine_and_bypass; returns the
    call recorder."""
    calls: dict[str, int] = {"refine": 0, "joern_runner": 0}

    monkeypatch.setattr(
        iris_specs, "identify_candidates",
        lambda gaps, taint_chain_callees=None: [SimpleNamespace()],
    )

    def fake_refine(candidates, **kw):
        calls["refine"] += 1
        return [], [], [], []

    monkeypatch.setattr(iris_refine, "refine_loop", fake_refine)
    monkeypatch.setattr(orch, "_load_call_graphs_cached", lambda *a: None)
    monkeypatch.setattr(orch, "_run_llm_client", lambda config: None)
    monkeypatch.setattr(orch, "_clear_phase_abort", lambda *a, **kw: None)

    def fake_joern_runner(server, config=None):
        calls["joern_runner"] += 1
        return lambda specs: []

    monkeypatch.setattr(
        orch, "_make_iris_joern_tool_runner", fake_joern_runner,
    )
    return calls


def _run_iris(config, joern_server):
    result = SimpleNamespace(cost_tracker=PhaseCostLedger())
    out = _iris_refine_and_bypass(
        config, [], None, joern_server, {}, [], result=result,
    )
    return out, result


class TestIrisSpendGate:
    def test_skipped_at_zero_dollars_without_any_consumer(self, iris_env):
        config = OrchestratorConfig(target_path=Path("."), out_dir=None)
        (runner, findings), result = _run_iris(config, joern_server=None)
        assert (runner, findings) == (None, [])
        assert iris_env["refine"] == 0
        booked = result.cost_tracker.phases["iris_refinement_skipped"]
        assert booked.calls == 1
        assert booked.cost_usd == 0.0
        assert config.joern_health.gated_spends == ["iris_refinement"]

    def test_skipped_when_health_gate_tripped(self, iris_env):
        config = OrchestratorConfig(target_path=Path("."), out_dir=None)
        config.joern_health = orch.JoernChannelHealth(unhealthy_after=1)
        config.joern_health.record_error("dead", key="a.c:f")
        config.joern_health.record_error("dead", key="a.c:g")
        (runner, findings), result = _run_iris(config, joern_server=object())
        assert (runner, findings) == (None, [])
        assert iris_env["refine"] == 0
        assert iris_env["joern_runner"] == 0
        assert "iris_refinement_skipped" in result.cost_tracker.phases

    def test_codeql_keeps_the_phase_paid_when_joern_down(self, iris_env):
        config = OrchestratorConfig(
            target_path=Path("."), out_dir=None,
            codeql_db_path="/dbs/cpp-db",
        )
        config.joern_health = orch.JoernChannelHealth(unhealthy_after=1)
        config.joern_health.record_error("dead", key="a.c:f")
        config.joern_health.record_error("dead", key="a.c:g")
        _run_iris(config, joern_server=object())
        assert iris_env["refine"] == 1
        # The tripped joern channel contributes no tool runner even
        # though the phase still pays via CodeQL.
        assert iris_env["joern_runner"] == 0

    def test_healthy_joern_pays_with_joern_runner(self, iris_env):
        config = OrchestratorConfig(target_path=Path("."), out_dir=None)
        _run_iris(config, joern_server=object())
        assert iris_env["refine"] == 1
        assert iris_env["joern_runner"] == 1


class TestConsumerReserves:
    def _config(self, client, **kw):
        defaults = {
            "target_path": Path("."), "out_dir": None,
            "llm_budget_client": client,
        }
        defaults.update(kw)
        return OrchestratorConfig(**defaults)

    def test_combined_hold_covers_deepen_and_study(self):
        client = _real_client(cap=25.0)
        config = self._config(client)
        held = _hold_deepen_reserve(config, study_active=True)
        assert abs(held - 25.0 * 0.20) < 1e-9
        assert client._budget_reserve == held

    def test_study_slice_alone_when_deepen_disabled(self):
        client = _real_client(cap=25.0)
        config = self._config(client, deepen_suspicious=False)
        held = _hold_deepen_reserve(config, study_active=True)
        assert abs(held - 25.0 * 0.05) < 1e-9

    def test_zero_study_fraction_changes_nothing(self):
        # Direction control: knob off == pre-change behaviour.
        client = _real_client(cap=25.0)
        config = self._config(client, study_reserve_fraction=0.0)
        held = _hold_deepen_reserve(config, study_active=True)
        assert abs(held - 25.0 * 0.15) < 1e-9

    def test_handover_releases_exactly_the_study_slice(self):
        client = _real_client(cap=25.0)
        config = self._config(client)
        combined = _hold_deepen_reserve(config, study_active=True)
        assert abs(combined - 5.0) < 1e-9
        deepen_only = _hold_deepen_reserve(config)
        assert abs(deepen_only - 3.75) < 1e-9
        assert client._budget_reserve == deepen_only

    def test_exhaustion_flips_across_the_handover(self):
        # Spend sits between cap-(deepen+study) and cap-deepen: the
        # main loop stops, then the drain regains exactly the study
        # slice after the handover.
        client = _real_client(cap=25.0)
        config = self._config(client)
        _hold_deepen_reserve(config, study_active=True)
        client.total_cost = 20.5
        assert client.is_budget_exhausted()
        _hold_deepen_reserve(config)
        assert not client.is_budget_exhausted()

    def test_combined_fraction_clamped(self):
        client = _real_client(cap=10.0)
        config = self._config(
            client, deepen_reserve_fraction=0.8, study_reserve_fraction=0.8,
        )
        held = _hold_deepen_reserve(config, study_active=True)
        assert abs(held - 9.0) < 1e-9  # 0.9 cap clamp


class TestGatedSpendReportSurfacing:
    def test_report_names_gated_spend_without_trip(self, tmp_path):
        from core.audit.diagnostics import write_tier_diagnostics
        from core.audit.orchestrator import TierCounters
        from core.audit.report import generate_report

        write_tier_diagnostics(
            {"joern": TierCounters()}, tmp_path,
            channel_health={"joern": {
                "tripped": False,
                "total_errors": 0,
                "gated_spends": ["iris_refinement"],
            }},
        )
        report = generate_report(tmp_path)
        assert "iris_refinement skipped at $0" in report["summary"]


class TestDrainBoundaryHandover:
    """The handover is BOUND to the run body: the drain goes through
    _drain_study_with_reserve_handover (source-pinned below), and the
    helper's ordering is unit-verified — deleting the re-hold breaks
    these tests, not just a code-review eyeball."""

    def _config(self, client, **kw):
        defaults = {
            "target_path": Path("."), "out_dir": None,
            "llm_budget_client": client,
        }
        defaults.update(kw)
        return OrchestratorConfig(**defaults)

    def test_handover_happens_before_the_drain(self, monkeypatch):
        client = _real_client(cap=25.0)
        config = self._config(client)
        held = orch._hold_deepen_reserve(config, study_active=True)
        assert abs(held - 5.0) < 1e-9
        # Spend sits between cap-(deepen+study) and cap-deepen.
        client.total_cost = 20.5
        observed: dict = {}

        def fake_drain(thread, queue, budget_exhausted):
            observed["reserve_at_drain"] = client._budget_reserve
            observed["budget_exhausted"] = budget_exhausted

        monkeypatch.setattr(orch, "_drain_study_consumer", fake_drain)
        new_held = orch._drain_study_with_reserve_handover(
            config, None, object(), held, time.monotonic(),
            orch.OrchestratorResult(),
        )
        # Deepen-only re-hold happened BEFORE the drain, and the
        # exhaustion flag was recomputed against the new cap.
        assert abs(new_held - 3.75) < 1e-9
        assert abs(observed["reserve_at_drain"] - 3.75) < 1e-9
        assert observed["budget_exhausted"] is False

    def test_zero_new_hold_releases_the_reserve(self, monkeypatch):
        client = _real_client(cap=25.0)
        config = self._config(client, deepen_suspicious=False)
        held = orch._hold_deepen_reserve(config, study_active=True)
        assert abs(held - 1.25) < 1e-9
        monkeypatch.setattr(
            orch, "_drain_study_consumer", lambda *a, **kw: None,
        )
        new_held = orch._drain_study_with_reserve_handover(
            config, None, object(), held, time.monotonic(),
            orch.OrchestratorResult(),
        )
        assert new_held == 0.0
        assert client._budget_reserve == 0.0

    def test_no_consumer_thread_keeps_the_hold(self, monkeypatch):
        client = _real_client(cap=25.0)
        config = self._config(client)
        held = orch._hold_deepen_reserve(config, study_active=True)
        monkeypatch.setattr(
            orch, "_drain_study_consumer",
            lambda *a, **kw: pytest.fail("drained without a consumer"),
        )
        new_held = orch._drain_study_with_reserve_handover(
            config, None, None, held, time.monotonic(),
            orch.OrchestratorResult(),
        )
        assert new_held == held
        assert client._budget_reserve == held

    def test_run_body_routes_the_drain_through_the_helper(self):
        import inspect

        body_src = inspect.getsource(orch._run_audit_body)
        assert "_drain_study_with_reserve_handover(" in body_src
        # The body must not bypass the handover with a direct drain.
        assert "_drain_study_consumer(" not in body_src
