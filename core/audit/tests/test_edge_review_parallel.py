"""Parallel tier-1 edge-contract review — serial/parallel equivalence.

Zero LLM calls: the pass is driven with a stub client keyed on the
callee named in the prompt; scoping is stubbed to a fixed tier-1 set.
Covers: identical summaries/commits between the serial and parallel
paths, the reserve-headroom budget stop under parallel dispatch (no
new reviews after the trip, in-flight counted), the serial fallback
for one worker / one edge, and two-run determinism.
"""

from __future__ import annotations

import re
import threading
from types import SimpleNamespace

import pytest

import core.llm.concurrency as _conc
from core.audit.edge_review import run_edge_pass


def _target(tmp_path, n: int):
    target = tmp_path / "target"
    target.mkdir(parents=True, exist_ok=True)
    caller_lines = []
    callee_lines = []
    for i in range(n):
        caller_lines += [
            f"int handle{i}(const char *raw) {{",
            f"    return run_query{i}(raw);",
            "}",
        ]
        callee_lines += [
            f"int run_query{i}(const char *q) {{",
            "    return exec(q);",
            "}",
        ]
    (target / "routes.c").write_text(
        "\n".join(caller_lines) + "\n", encoding="utf-8")
    (target / "svc.c").write_text(
        "\n".join(callee_lines) + "\n", encoding="utf-8")
    return target


def _checklist(target, n: int) -> dict:
    return {
        "target_path": str(target),
        "files": [
            {"path": "routes.c", "language": "c", "items": [
                {"name": f"handle{i}", "kind": "function",
                 "line_start": 3 * i + 1, "line_end": 3 * i + 3}
                for i in range(n)]},
            {"path": "svc.c", "language": "c", "items": [
                {"name": f"run_query{i}", "kind": "function",
                 "line_start": 3 * i + 1, "line_end": 3 * i + 3}
                for i in range(n)]},
        ],
    }


def _recs(n: int) -> list[dict]:
    return [
        {
            "caller_file": "routes.c", "caller": f"handle{i}",
            "callee_file": "svc.c", "callee": f"run_query{i}",
            "call_line": 3 * i + 2, "reason": "boundary:socket",
            "touched": False,
        }
        for i in range(n)
    ]


def _stub_scoping(monkeypatch, recs: list[dict]) -> None:
    monkeypatch.setattr(
        "core.audit.edge_obligations.build_and_write",
        lambda out_dir, checklist, context_map, **kw: {
            "tier1": list(recs), "tier2": [], "blind_spots": [],
            "stats": {},
        },
    )
    monkeypatch.setattr(
        "core.audit.edge_review.compute_edge_gaps",
        lambda obligations, **kw: list(obligations["tier1"]),
    )


class _StubLLM:
    """Edge reviewer stub: verdict keyed on the callee in the prompt.

    ``is_budget_exhausted`` honours ``budget_calls``: once that many
    reviews have been paid for, the headroom check trips. Thread-safe.
    """

    def __init__(self, suspicious: set[str], budget_calls: int | None = None):
        self.suspicious = suspicious
        self.budget_calls = budget_calls
        self.calls: list[str] = []
        self._lock = threading.Lock()

    def generate_structured(self, prompt, schema, system_prompt=None, **kw):
        m = re.search(r"run_query\d+", prompt)
        assert m is not None
        callee = m.group(0)
        with self._lock:
            self.calls.append(callee)
        status = "suspicious" if callee in self.suspicious else "clean"
        return SimpleNamespace(
            result={
                "status": status,
                "body": f"contract audit of {callee}",
                "hypothesis": "edge contract mismatch" if status != "clean" else "",
            },
            cost=0.01, model="stub-model", usage=None,
        )

    def is_budget_exhausted(self, estimated_cost=0.1) -> bool:
        if self.budget_calls is None:
            return False
        with self._lock:
            return len(self.calls) >= self.budget_calls


def _config(target, run_dir, llm):
    run_dir.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        out_dir=run_dir, target_path=target,
        llm_client=llm, llm_budget_client=llm,
    )


def _run(tmp_path, monkeypatch, *, n=6, suspicious=frozenset(),
         budget_calls=None, workers=1, tag="run"):
    target = _target(tmp_path / tag, n)
    recs = _recs(n)
    _stub_scoping(monkeypatch, recs)
    llm = _StubLLM(set(suspicious), budget_calls=budget_calls)
    committed: list[tuple[str, str, str]] = []
    commit_lock = threading.Lock()

    def commit_fn(config, outcome, gap):
        with commit_lock:
            committed.append(
                (gap["name"], gap["edge_callee_name"], outcome.status))

    summary, tier2 = run_edge_pass(
        _config(target, tmp_path / tag / "out", llm),
        _checklist(target, n), None,
        commit_fn=commit_fn,
        max_workers=workers,
    )
    return summary, committed, llm


def _comparable(summary: dict) -> dict:
    # wall_time_s is timing-dependent by construction.
    return {k: v for k, v in summary.items() if k != "wall_time_s"}


class TestSerialParallelEquivalence:
    def test_same_summary_and_commits(self, tmp_path, monkeypatch):
        suspicious = {"run_query1", "run_query4"}
        s_summary, s_committed, _ = _run(
            tmp_path, monkeypatch, suspicious=suspicious,
            workers=1, tag="serial",
        )
        p_summary, p_committed, _ = _run(
            tmp_path, monkeypatch, suspicious=suspicious,
            workers=4, tag="parallel",
        )
        assert _comparable(s_summary) == _comparable(p_summary)
        assert sorted(s_committed) == sorted(p_committed)
        assert p_summary["reviewed"] == 6
        assert p_summary["suspicious"] == 2
        assert p_summary["cost_usd"] == pytest.approx(0.06)

    def test_parallel_run_is_deterministic(self, tmp_path, monkeypatch):
        results = []
        for tag in ("a", "b"):
            summary, committed, _ = _run(
                tmp_path, monkeypatch, suspicious={"run_query0"},
                workers=4, tag=tag,
            )
            results.append((_comparable(summary), sorted(committed)))
        assert results[0] == results[1]


class TestBudgetStop:
    def test_reserve_trip_stops_new_dispatch(self, tmp_path, monkeypatch):
        summary, committed, llm = _run(
            tmp_path, monkeypatch, n=8, budget_calls=3, workers=2,
        )
        # Sticky stop: everything not reviewed is counted as
        # budget-skipped, nothing is silently dropped.
        assert summary["reviewed"] + summary["skipped_budget"] == 8
        assert summary["reviewed"] < 8
        assert summary["reviewed"] == len(llm.calls) == len(committed)

    def test_exhausted_before_start_reviews_nothing(
        self, tmp_path, monkeypatch,
    ):
        summary, committed, llm = _run(
            tmp_path, monkeypatch, n=4, budget_calls=0, workers=4,
        )
        assert llm.calls == []
        assert committed == []
        assert summary["reviewed"] == 0
        assert summary["skipped_budget"] == 4


class TestReserveScaling:
    def test_concurrent_dispatches_cannot_claim_the_same_headroom(
        self, tmp_path, monkeypatch,
    ):
        """The reserve estimate scales by reviews already in flight
        (``_EDGE_EST_COST_USD * (inflight + 1)``): with headroom for
        exactly ONE review, two concurrent dispatches must not both
        pass the check — the second sees 2x the estimate and trips
        the sticky stop. Mutating the scaling (dropping ``inflight``
        or the ``+1``) lets both through and fails this test."""
        n = 4
        target = _target(tmp_path / "resv", n)
        _stub_scoping(monkeypatch, _recs(n))
        headroom = 0.15  # one 0.1 review fits; two concurrent don't
        second_probe = threading.Event()

        class _ScalingLLM(_StubLLM):
            def __init__(self):
                super().__init__(set())
                self.probes: list[float] = []

            def is_budget_exhausted(self, estimated_cost=0.1) -> bool:
                with self._lock:
                    self.probes.append(estimated_cost)
                    if len(self.probes) >= 2:
                        second_probe.set()
                return estimated_cost > headroom

            def generate_structured(self, prompt, schema,
                                    system_prompt=None, **kw):
                # Hold the in-flight review open until the concurrent
                # worker has probed the reserve — guarantees the two
                # dispatches actually overlap.
                second_probe.wait(timeout=30)
                return super().generate_structured(
                    prompt, schema, system_prompt=system_prompt, **kw,
                )

        llm = _ScalingLLM()
        committed: list = []
        commit_lock = threading.Lock()

        def commit_fn(config, outcome, gap):
            with commit_lock:
                committed.append(gap["name"])

        summary, _tier2 = run_edge_pass(
            _config(target, tmp_path / "resv" / "out", llm),
            _checklist(target, n), None,
            commit_fn=commit_fn,
            max_workers=2,
        )
        assert summary["reviewed"] == 1
        assert summary["skipped_budget"] == n - 1
        # Exactly two probes (the sticky stop skips later items
        # without probing): the first for one in-flight review, the
        # second scaled up by the review already in flight.
        assert llm.probes == [
            pytest.approx(0.1), pytest.approx(0.2),
        ]


class TestSerialFallback:
    def _forbid_parallel(self, monkeypatch):
        def _boom(*a, **kw):  # pragma: no cover - failure surface
            raise AssertionError("run_parallel used on the serial path")

        monkeypatch.setattr(_conc, "run_parallel", _boom)

    def test_single_worker_takes_serial_path(self, tmp_path, monkeypatch):
        self._forbid_parallel(monkeypatch)
        summary, committed, llm = _run(tmp_path, monkeypatch, n=3, workers=1)
        assert summary["reviewed"] == 3
        # Serial path reviews in gap order.
        assert llm.calls == ["run_query0", "run_query1", "run_query2"]

    def test_single_edge_takes_serial_path(self, tmp_path, monkeypatch):
        self._forbid_parallel(monkeypatch)
        summary, committed, _ = _run(tmp_path, monkeypatch, n=1, workers=8)
        assert summary["reviewed"] == 1
