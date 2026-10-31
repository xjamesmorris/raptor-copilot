"""Tests for ``core.llm.scorecard._batch.record_event_batch``.

The producers hand their whole run to ONE ``record_events`` cycle
(each ``record_event`` call is a full flock + load + verify +
atomic-rewrite); per-event writes remain only as the failure-isolation
fallback when the batch is rejected.
"""

from __future__ import annotations

import logging

import pytest

from core.llm.scorecard._batch import record_event_batch
from core.llm.scorecard.consensus import record_consensus_outcomes
from core.llm.scorecard.scorecard import ModelScorecard

logger = logging.getLogger(__name__)


def _events(n: int) -> list[dict]:
    return [
        {"decision_class": f"agentic:rule-{i}", "model": "m",
         "event_type": "multi_model_consensus", "outcome": "correct"}
        for i in range(n)
    ]


class _CountingScorecard:
    def __init__(self, *, batch_fails: bool = False) -> None:
        self.batch_calls = 0
        self.single_calls = 0
        self.batch_fails = batch_fails

    def record_events(self, events: list[dict]) -> None:
        self.batch_calls += 1
        if self.batch_fails:
            raise RuntimeError("batch rejected")

    def record_event(self, *args, **kwargs) -> None:
        self.single_calls += 1


def test_happy_path_is_one_batch_call():
    sc = _CountingScorecard()
    n = record_event_batch(sc, _events(5), log=logger, producer="t")
    assert n == 5
    assert sc.batch_calls == 1
    assert sc.single_calls == 0


def test_empty_batch_makes_no_calls():
    sc = _CountingScorecard()
    assert record_event_batch(sc, [], log=logger, producer="t") == 0
    assert sc.batch_calls == 0
    assert sc.single_calls == 0


def test_batch_failure_degrades_to_per_event(caplog):
    sc = _CountingScorecard(batch_fails=True)
    with caplog.at_level(logging.WARNING, logger=__name__):
        n = record_event_batch(sc, _events(3), log=logger, producer="t")
    assert n == 3
    assert sc.batch_calls == 1
    assert sc.single_calls == 3
    assert any("retrying per event" in r.getMessage()
               for r in caplog.records)


def test_consensus_producer_writes_one_batch(tmp_path, monkeypatch):
    sc = ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)
    calls: list[int] = []
    real = sc.record_events

    def _spy(events: list[dict]) -> None:
        calls.append(len(events))
        real(events)

    monkeypatch.setattr(sc, "record_events", _spy)
    n = record_consensus_outcomes(
        sc,
        correlation={
            "agreement_matrix": {"f1": {
                "pro": {"is_exploitable": True},
                "opus": {"is_exploitable": True},
                "flash": {"is_exploitable": False},
            }},
            "confidence_signals": {"f1": "disputed"},
        },
        results_by_id={"f1": {"rule_id": "py/x"}},
    )
    assert n == 3
    assert calls == [3]
    # The events really landed.
    stat = sc.get_stat("agentic:py/x", "flash")
    assert stat is not None
    assert stat.events["multi_model_consensus"].incorrect == 1


@pytest.mark.parametrize("producer_mod,func_name", [
    ("self_consistency", "record_self_consistency_outcomes"),
    ("dataflow_validation", "record_dataflow_validation_outcomes"),
])
def test_sibling_producers_route_through_batch(
    producer_mod, func_name, tmp_path, monkeypatch,
):
    import importlib
    mod = importlib.import_module(f"core.llm.scorecard.{producer_mod}")
    sc = ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)
    calls: list[int] = []
    real = sc.record_events

    def _spy(events: list[dict]) -> None:
        calls.append(len(events))
        real(events)

    monkeypatch.setattr(sc, "record_events", _spy)
    kwargs = {"results_by_id": {
        "f1": {"rule_id": "py/x", "analysed_by": "m",
               "retried": True, "is_exploitable": True,
               "dataflow_validation": {"verdict": "confirmed"}},
    }}
    if producer_mod == "self_consistency":
        kwargs["verdicts_pre_retry"] = {"f1": True}
    n = getattr(mod, func_name)(sc, **kwargs)
    assert n == 1
    assert calls == [1]


def _spy_scorecard(tmp_path, monkeypatch):
    sc = ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)
    batch_calls: list[int] = []
    single_calls: list[str] = []
    real_batch = sc.record_events
    real_single = sc.record_event

    def _batch_spy(events: list[dict]) -> None:
        batch_calls.append(len(events))
        real_batch(events)

    def _single_spy(*args, **kwargs) -> None:
        single_calls.append(str(args))
        real_single(*args, **kwargs)

    monkeypatch.setattr(sc, "record_events", _batch_spy)
    monkeypatch.setattr(sc, "record_event", _single_spy)
    return sc, batch_calls, single_calls


def test_judge_producer_writes_one_batch(tmp_path, monkeypatch):
    from core.llm.scorecard.judge import record_judge_outcomes

    sc, batch_calls, single_calls = _spy_scorecard(tmp_path, monkeypatch)
    results = {f"f{i}": {
        "judge": "disputed", "rule_id": "py/x",
        "analysed_by": "primary", "is_exploitable": True,
        "reasoning": "r",
        "judge_analyses": [
            {"model": "j1", "is_exploitable": True, "reasoning": "a"},
            {"model": "j2", "is_exploitable": False, "reasoning": "b"},
        ],
    } for i in range(3)}
    n = record_judge_outcomes(
        sc, results_by_id=results,
        primary_verdicts_before_judge={f"f{i}": False for i in range(3)},
    )
    assert n == 9  # (primary + 2 judges) x 3 findings
    assert batch_calls == [9]
    assert single_calls == []


def test_cross_family_producer_writes_one_batch(tmp_path, monkeypatch):
    from core.llm.scorecard.cross_family import record_cross_family_outcomes

    sc, batch_calls, single_calls = _spy_scorecard(tmp_path, monkeypatch)
    results = {f"f{i}": {
        "rule_id": "py/x",
        "cross_family_check": {
            "verdict": "disputed", "checker_model": "m2",
            "trigger": "t", "checker_ruling": "cr",
        },
    } for i in range(3)}
    n = record_cross_family_outcomes(sc, results_by_id=results)
    assert n == 3
    assert batch_calls == [3]
    assert single_calls == []


def test_stability_producer_writes_one_batch(tmp_path, monkeypatch):
    import json

    from core.llm.scorecard.stability import record_cross_run_stability

    sc, batch_calls, single_calls = _spy_scorecard(tmp_path, monkeypatch)

    def result(fid, verdict):
        return {"finding_id": fid, "is_exploitable": verdict,
                "is_true_positive": verdict, "rule_id": "py/x",
                "analysed_by": "m1", "resolved_model": "m1",
                "reasoning": "r"}

    prior = tmp_path / "agentic_20260101_000000_pid1_1"
    prior.mkdir()
    (prior / ".raptor-run.json").write_text(json.dumps({
        "target": "/tmp/t", "status": "completed", "command": "agentic",
        "timestamp": "2026-01-01T00:00:00Z"}))
    (prior / "orchestrated_report.json").write_text(json.dumps(
        {"results": [result(f"f{i}", True) for i in range(3)]}))
    current = tmp_path / "agentic_20260102_000000_pid2_2"
    current.mkdir()
    (current / ".raptor-run.json").write_text(json.dumps({
        "target": "/tmp/t", "status": "running", "command": "agentic",
        "timestamp": "2026-01-02T00:00:00Z"}))

    n = record_cross_run_stability(
        sc, out_dir=current,
        results_by_id={f"f{i}": result(f"f{i}", False) for i in range(3)},
    )
    assert n == 3
    assert batch_calls == [3]
    assert single_calls == []


def test_reasoning_divergence_producer_writes_one_batch(
    tmp_path, monkeypatch,
):
    from core.llm.scorecard.reasoning_divergence import (
        record_reasoning_divergence,
    )

    sc, batch_calls, single_calls = _spy_scorecard(tmp_path, monkeypatch)
    base = ("the user supplied index flows unchecked into the memcpy "
            "length parameter of the packet parser")
    n = record_reasoning_divergence(
        sc,
        correlation={
            "agreement_matrix": {"f1": {
                "a": {"is_exploitable": True},
                "b": {"is_exploitable": True},
                "c": {"is_exploitable": True},
            }},
            "confidence_signals": {"f1": "high"},
        },
        results_by_id={"f1": {"rule_id": "py/x"}},
        per_finding_results={"f1": [
            {"analysed_by": "a", "reasoning": base},
            {"analysed_by": "b", "reasoning": base},
            {"analysed_by": "c",
             "reasoning": "credentials appear hardcoded near the token "
                          "making exploitation moot here entirely anyway"},
        ]},
        divergence_threshold=0.1,
    )
    assert n == 3
    assert batch_calls == [3]
    assert single_calls == []


def test_validate_feedback_producer_writes_one_batch(tmp_path, monkeypatch):
    from core.llm.scorecard.validate_feedback import (
        record_validate_feedback_outcomes,
    )

    sc, batch_calls, single_calls = _spy_scorecard(tmp_path, monkeypatch)
    records = [{
        "model": "m1", "cwe": "CWE-79", "prior_verdict": "finding",
        "validate_verdict": "disproven", "file": "a.py",
        "function": f"f{i}", "reason": "unreachable",
    } for i in range(3)]
    n = record_validate_feedback_outcomes(records, scorecard=sc)
    assert n == 3
    assert batch_calls == [3]
    assert single_calls == []
