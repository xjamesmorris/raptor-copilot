"""Accounting and route-identity guards for scorecard v2."""

from __future__ import annotations

import pytest

from core.llm.accounting import (
    CostBasis,
    CostObservation,
    ScorecardAggregationRefused,
)
from core.llm.scorecard import EventType, ModelScorecard, Policy


def _seed_trusted_cell(path, model: str = "shared-model") -> None:
    scorecard = ModelScorecard(path, shadow_rate=0.0)
    for _ in range(100):
        scorecard.record_event(
            "audit:CWE-79",
            model,
            EventType.CHEAP_SHORT_CIRCUIT,
            "correct",
        )


def test_refused_model_reads_fail_closed_without_mutating_sidecar(
    tmp_path,
) -> None:
    path = tmp_path / "scorecard.json"
    _seed_trusted_cell(path)
    before = path.read_bytes()
    scorecard = ModelScorecard(
        path,
        shadow_rate=0.0,
        refused_models={"shared-model"},
    )

    assert (
        scorecard.should_short_circuit("audit:CWE-79", "shared-model")
        == Policy.LEARNING
    )
    assert scorecard.get_stat("audit:CWE-79", "shared-model") is None
    assert all(
        stat.model != "shared-model" for stat in scorecard.get_stats()
    )
    assert path.read_bytes() == before


def test_refused_model_write_raises_without_mutating_sidecar(tmp_path) -> None:
    path = tmp_path / "scorecard.json"
    _seed_trusted_cell(path)
    before = path.read_bytes()
    scorecard = ModelScorecard(path, refused_models={"shared-model"})

    with pytest.raises(
        ScorecardAggregationRefused,
        match="model-name-only scorecard aggregation is refused",
    ):
        scorecard.record_event(
            "audit:CWE-79",
            "shared-model",
            EventType.CHEAP_SHORT_CIRCUIT,
            "correct",
        )

    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "basis",
    [CostBasis.UNKNOWN, CostBasis.SUBSCRIPTION],
)
def test_unpriced_usage_is_skipped_without_mutating_sidecar(
    tmp_path, basis,
) -> None:
    path = tmp_path / "scorecard.json"
    _seed_trusted_cell(path, model="legacy")
    before = path.read_bytes()
    scorecard = ModelScorecard(path)

    scorecard.register_uses([{
        "model": "unpriced",
        "decision_class": "_usage",
        "calls": 1,
        "cost_usd": 0.0,
        "cost_basis": basis.value,
    }])

    assert scorecard.get_stat("_usage", "unpriced") is None
    assert path.read_bytes() == before


def test_provider_billed_usage_refuses_v2_without_mutation(tmp_path) -> None:
    path = tmp_path / "scorecard.json"
    _seed_trusted_cell(path, model="legacy")
    before = path.read_bytes()
    scorecard = ModelScorecard(path)

    with pytest.raises(
        ScorecardAggregationRefused,
        match="provider_billed",
    ):
        scorecard.register_uses([{
            "model": "future",
            "decision_class": "_usage",
            "calls": 1,
            "cost_usd": 0.0,
            "cost_basis": CostBasis.PROVIDER_BILLED.value,
        }])

    assert path.read_bytes() == before


@pytest.mark.parametrize("provider_billed_first", [False, True])
def test_mixed_basis_batch_refuses_v2_without_mutation(
    tmp_path,
    provider_billed_first,
) -> None:
    path = tmp_path / "scorecard.json"
    _seed_trusted_cell(path, model="legacy")
    before = path.read_bytes()
    scorecard = ModelScorecard(path)
    estimated = {
        "model": "legacy-estimate",
        "decision_class": "_usage",
        "calls": 1,
        "cost_usd": 0.25,
        "cost_basis": CostBasis.CATALOG_PRICED.value,
    }
    billed = {
        "model": "future-billed",
        "decision_class": "_usage",
        "calls": 1,
        "cost_usd": 0.5,
        "cost_basis": CostBasis.PROVIDER_BILLED.value,
    }
    uses = [billed, estimated] if provider_billed_first else [estimated, billed]

    with pytest.raises(
        ScorecardAggregationRefused,
        match="provider_billed",
    ):
        scorecard.register_uses(uses)

    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "basis",
    [
        CostBasis.CATALOG_PRICED,
        CostBasis.CONFIGURED_RATE,
        CostBasis.CLI_REPORTED,
    ],
)
def test_legacy_estimate_bases_continue_recording(tmp_path, basis) -> None:
    path = tmp_path / "scorecard.json"
    scorecard = ModelScorecard(path)

    scorecard.register_uses([{
        "model": "legacy",
        "decision_class": "_usage",
        "calls": 2,
        "cost_usd": 0.5,
        "cost_basis": basis.value,
    }])

    stat = scorecard.get_stat("_usage", "legacy")
    assert stat is not None
    assert stat.calls == 2
    assert stat.cost_usd == 0.5


def test_freshness_impact_excludes_refused_models(tmp_path) -> None:
    path = tmp_path / "scorecard.json"
    _seed_trusted_cell(path, model="allowed")
    _seed_trusted_cell(path, model="refused")
    guarded = ModelScorecard(path, refused_models={"refused"})

    impact = guarded.measure_freshness_impact(30)

    assert impact["cells"] == 1


def test_register_uses_skips_malformed_identity_entries(tmp_path) -> None:
    scorecard = ModelScorecard(tmp_path / "scorecard.json")
    scorecard.register_uses([
        {"model": None, "decision_class": "_usage", "calls": 1},
        {"model": "m", "decision_class": None, "calls": 1},
        {"model": 7, "decision_class": "_usage", "calls": 1},
    ])
    assert scorecard.get_stats() == []


def test_usage_cost_basis_accepts_typed_and_rejects_untyped() -> None:
    observation = CostObservation.cli_reported(0.1)
    assert (
        ModelScorecard._usage_cost_basis(
            {"cost_observation": observation},
        )
        is CostBasis.CLI_REPORTED
    )
    with pytest.raises(TypeError, match="must be CostObservation"):
        ModelScorecard._usage_cost_basis(
            {"cost_observation": {"basis": "unknown"}},
        )
