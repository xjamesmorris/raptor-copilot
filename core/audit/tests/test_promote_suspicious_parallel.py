"""Parallel suspicious-promotion sweep — serial/parallel equivalence.

No real LLM, engine, or subprocess calls: the tool chain, prefilter,
and synthesis seams are stubbed. Covers: identical verdicts between
the serial and parallel paths, item-ordered on-demand synthesis under
parallel completion, the serial fallback for one worker / one item,
and two-run determinism of the parallel path.
"""

from __future__ import annotations

from types import SimpleNamespace

import core.llm.concurrency as _conc
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _promote_suspicious,
)


def _outcome(name: str, status: str = "suspicious") -> ReviewOutcome:
    o = ReviewOutcome(
        file="a.c", function=name, status=status,
        body="looks off", hypothesis=f"overflow in {name}", line=3,
    )
    o.review_result = {"hypothesis": f"overflow in {name}"}
    return o


def _result(outcomes: list[ReviewOutcome]) -> OrchestratorResult:
    r = OrchestratorResult()
    r.outcomes = list(outcomes)
    r.suspicious = sum(1 for o in outcomes if o.status == "suspicious")
    r.findings = sum(1 for o in outcomes if o.status == "finding")
    return r


def _config(tmp_path) -> OrchestratorConfig:
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return OrchestratorConfig(target_path=tmp_path, out_dir=out)


def _patch_mechanical(monkeypatch, *, confirm: set[str], chain=True) -> None:
    """Stub the mechanical seams: chain dispatch, tool run, prefilter."""
    monkeypatch.setattr(
        "core.audit.orchestrator._hypothesis_to_tool_chain",
        lambda *a, **kw: (
            [{"type": "smt", "config": {"verb": "x"}}] if chain else []
        ),
    )
    monkeypatch.setattr(
        "core.audit.orchestrator._run_tool_chain",
        lambda _chain, **kw: (
            ["smt:check"] if kw["function_name"] in confirm else []
        ),
    )
    monkeypatch.setattr(
        "core.audit.orchestrator._is_detection_only", lambda t: False,
    )
    monkeypatch.setattr(
        "core.audit.orchestrator.run_prefilter",
        lambda **kw: SimpleNamespace(hits=[]),
    )
    monkeypatch.setattr(
        "core.audit.orchestrator._read_raw_source",
        lambda *a, **kw: "int f(void) { return 0; }",
    )


def _snapshot(result: OrchestratorResult) -> dict:
    return {
        "statuses": {
            (o.file, o.function): (o.status, o.evidence_tool or "")
            for o in result.outcomes
        },
        "sweep_promoted": result.sweep_promoted,
        "suspicious": result.suspicious,
        "findings": result.findings,
    }


class TestSerialParallelEquivalence:
    def test_same_verdicts_and_counters(self, tmp_path, monkeypatch):
        names = [f"fn{i}" for i in range(8)]
        confirm = {n for i, n in enumerate(names) if i % 2 == 0}
        _patch_mechanical(monkeypatch, confirm=confirm)

        serial = _result([_outcome(n) for n in names])
        _promote_suspicious(serial, _config(tmp_path), max_workers=1)

        parallel = _result([_outcome(n) for n in names])
        _promote_suspicious(parallel, _config(tmp_path), max_workers=4)

        assert _snapshot(serial) == _snapshot(parallel)
        assert parallel.findings == len(confirm)
        for o in parallel.outcomes:
            expected = "finding" if o.function in confirm else "suspicious"
            assert o.status == expected

    def test_parallel_run_is_deterministic(self, tmp_path, monkeypatch):
        names = [f"fn{i}" for i in range(6)]
        confirm = {"fn1", "fn4"}
        _patch_mechanical(monkeypatch, confirm=confirm)

        snaps = []
        for _ in range(2):
            result = _result([_outcome(n) for n in names])
            _promote_suspicious(result, _config(tmp_path), max_workers=4)
            snaps.append(_snapshot(result))
        assert snaps[0] == snaps[1]


class TestSerialFallback:
    def _forbid_parallel(self, monkeypatch):
        def _boom(*a, **kw):  # pragma: no cover - failure surface
            raise AssertionError("run_parallel used on the serial path")

        monkeypatch.setattr(_conc, "run_parallel", _boom)

    def test_single_worker_takes_serial_path(self, tmp_path, monkeypatch):
        _patch_mechanical(monkeypatch, confirm={"fn0"})
        self._forbid_parallel(monkeypatch)
        result = _result([_outcome("fn0"), _outcome("fn1")])
        _promote_suspicious(result, _config(tmp_path), max_workers=1)
        assert result.outcomes[0].status == "finding"
        assert result.outcomes[1].status == "suspicious"

    def test_single_item_takes_serial_path(self, tmp_path, monkeypatch):
        _patch_mechanical(monkeypatch, confirm={"fn0"})
        self._forbid_parallel(monkeypatch)
        result = _result([_outcome("fn0")])
        _promote_suspicious(result, _config(tmp_path), max_workers=8)
        assert result.outcomes[0].status == "finding"


class TestSynthesisOrdering:
    def test_parallel_synthesis_runs_in_item_order(
        self, tmp_path, monkeypatch,
    ):
        # Chain-less hypotheses route to on-demand synthesis, which is
        # capped per run — consumption order must be item order even
        # when workers complete out of order.
        _patch_mechanical(monkeypatch, confirm=set(), chain=False)
        seen: list[str] = []

        def fake_synth(result, config, i, outcome, hyp, cwe, source,
                       joern_server=None):
            seen.append(outcome.function)

        monkeypatch.setattr(
            "core.audit.orchestrator._synthesize_unmapped_suspicious",
            fake_synth,
        )
        names = [f"fn{i}" for i in range(6)]
        result = _result([_outcome(n) for n in names])
        _promote_suspicious(result, _config(tmp_path), max_workers=4)
        assert seen == names

    def test_serial_synthesis_still_inline(self, tmp_path, monkeypatch):
        _patch_mechanical(monkeypatch, confirm=set(), chain=False)
        seen: list[str] = []
        monkeypatch.setattr(
            "core.audit.orchestrator._synthesize_unmapped_suspicious",
            lambda result, config, i, outcome, hyp, cwe, source,
            joern_server=None: seen.append(outcome.function),
        )
        result = _result([_outcome("fn0"), _outcome("fn1")])
        _promote_suspicious(result, _config(tmp_path), max_workers=1)
        assert seen == ["fn0", "fn1"]


class TestJoernCap:
    def test_joern_server_caps_workers(self, tmp_path, monkeypatch):
        # With a Joern lane the pass must not exceed the pass cap —
        # observed via the max_workers run_parallel receives.
        _patch_mechanical(monkeypatch, confirm=set())
        captured: dict = {}

        def fake_run_parallel(items, fn, *, max_workers=None, **kw):
            captured["max_workers"] = max_workers
            return [fn(it) for it in items]

        monkeypatch.setattr(_conc, "run_parallel", fake_run_parallel)
        monkeypatch.setattr(
            "core.audit.orchestrator._guard_blocks_promotion",
            lambda *a, **kw: None,
        )
        result = _result([_outcome(f"fn{i}") for i in range(4)])
        _promote_suspicious(
            result, _config(tmp_path),
            joern_server=object(), max_workers=8,
        )
        assert captured["max_workers"] == 2
