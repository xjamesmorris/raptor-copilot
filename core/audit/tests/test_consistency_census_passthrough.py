"""Consistency channel: prep-census pass-through at the chain dispatch.

The prep phase computes one standing return census over the checklist
files; the in-chain consistency dispatch previously re-walked the tree
(rglob + bounded file reads) PER HYPOTHESIS to rebuild it. Covers: the
passed census is used without touching the tree, the rebuild fallback
when prep produced none, the binary-excerpt exclusion, and the
census-miss retry escape (a callee outside the prep texts), keyed on
the channel's structured reason code.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import core.audit.consistency_verify as cv
from core.audit.callsite_consistency import build_return_census
from core.audit.consistency_verify import (
    ConsistencyResult,
    run_consistency_check,
)
from core.audit.orchestrator import _run_tool_chain

HYP = (
    "9/10 other call sites check the return value of `do_auth()`; "
    "u0 discards it"
)


def _fixture_texts() -> dict[str, str]:
    parts = []
    for i in range(9):
        parts.append(
            f"int c{i}(void) {{\n"
            "    if (do_auth() != 0)\n"
            "        return -1;\n"
            "    return 0;\n}\n"
        )
    parts.append("int u0(void) {\n    do_auth();\n    return 0;\n}\n")
    return {"src/callers.c": "\n".join(parts)}


class _Cfg:
    """Minimal OrchestratorConfig stand-in for _run_tool_chain."""

    def __init__(self, target: Path):
        self.target_path = target
        self.out_dir = None
        self.codeql_db_path = None
        self.project_sinks = None
        self.consistency_census: dict[str, Any] | None = None
        self.consistency_source_texts: dict[str, str] | None = None
        self.consistency_wur_functions: frozenset[str] | None = None


class TestVerifySideCensusUse:
    def test_passed_census_confirms_without_tree_walk(self, tmp_path):
        texts = _fixture_texts()
        census = build_return_census(texts)
        # The target directory holds NO sources: any tree walk would
        # come back empty, so a verdict here proves the passed census
        # and texts were used.
        res = run_consistency_check(
            tmp_path / "does-not-exist", "src/callers.c", "u0", HYP,
            census=census,
            source_texts=texts,
        )
        assert res.outcome == "confirmed"
        assert res.peer_evidence is not None
        assert res.peer_evidence.n == 10

    def test_fallback_rebuild_still_works(self, tmp_path):
        for rel, content in _fixture_texts().items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        res = run_consistency_check(
            tmp_path, "src/callers.c", "u0", HYP,
        )
        assert res.outcome == "confirmed"


class TestDispatchPassThrough:
    CHAIN = [{"type": "consistency", "config": {}}]

    def _record_calls(self, monkeypatch, results):
        calls: list[dict[str, Any]] = []

        def stub(*args: Any, **kwargs: Any) -> ConsistencyResult:
            calls.append(kwargs)
            return results[min(len(calls) - 1, len(results) - 1)]

        monkeypatch.setattr(cv, "run_consistency_check", stub)
        return calls

    def _run(self, cfg, **kwargs):
        return _run_tool_chain(
            self.CHAIN,
            config=cfg,
            file_path="src/callers.c",
            function_name="u0",
            source="",
            hypothesis=HYP,
            line_start=1,
            **kwargs,
        )

    def test_prep_census_reaches_the_channel(self, tmp_path, monkeypatch):
        cfg = _Cfg(tmp_path)
        cfg.consistency_census = {"do_auth": object()}
        cfg.consistency_source_texts = _fixture_texts()
        calls = self._record_calls(monkeypatch, [
            ConsistencyResult(outcome="inconclusive", reason="x"),
        ])
        self._run(cfg)
        assert len(calls) == 1
        assert calls[0]["census"] is cfg.consistency_census
        assert calls[0]["source_texts"] is cfg.consistency_source_texts

    def test_no_prep_census_dispatches_rebuild(self, tmp_path, monkeypatch):
        cfg = _Cfg(tmp_path)
        calls = self._record_calls(monkeypatch, [
            ConsistencyResult(outcome="inconclusive", reason="x"),
        ])
        self._run(cfg)
        assert len(calls) == 1
        assert calls[0]["census"] is None
        assert calls[0]["source_texts"] is None

    def test_empty_prep_census_treated_as_absent(
        self, tmp_path, monkeypatch,
    ):
        cfg = _Cfg(tmp_path)
        cfg.consistency_census = {}
        calls = self._record_calls(monkeypatch, [
            ConsistencyResult(outcome="inconclusive", reason="x"),
        ])
        self._run(cfg)
        assert calls[0]["census"] is None

    def test_target_override_never_uses_prep_census(
        self, tmp_path, monkeypatch,
    ):
        # Binary decompilation excerpts run against a tmpdir override;
        # the prep census describes the real tree, not the excerpt.
        cfg = _Cfg(tmp_path)
        cfg.consistency_census = {"do_auth": object()}
        cfg.consistency_source_texts = _fixture_texts()
        calls = self._record_calls(monkeypatch, [
            ConsistencyResult(outcome="inconclusive", reason="x"),
        ])
        override = tmp_path / "decomp"
        override.mkdir()
        self._run(cfg, target_path_override=override)
        assert calls[0]["census"] is None
        assert calls[0]["source_texts"] is None

    def test_census_miss_in_prep_census_retries_rebuild(
        self, tmp_path, monkeypatch,
    ):
        cfg = _Cfg(tmp_path)
        cfg.consistency_census = {"other_callee": object()}
        cfg.consistency_source_texts = _fixture_texts()
        calls = self._record_calls(monkeypatch, [
            ConsistencyResult(
                outcome="inconclusive",
                # The channel's structured code plus its prose detail,
                # exactly as _inconclusive() renders it.
                reason=(
                    f"{cv.REASON_CENSUS_MISS}: no census entry for "
                    "any hypothesis callee (do_auth)"
                ),
            ),
            ConsistencyResult(
                outcome="confirmed",
                reason="9/10 sites check",
                rule_id="consistency:return-check",
            ),
        ])
        confirmed = self._run(cfg)
        assert len(calls) == 2
        assert calls[0]["census"] is cfg.consistency_census
        assert calls[1].get("census") is None
        assert calls[1].get("source_texts") is None
        assert confirmed == ["consistency:return-check"]

    def test_real_census_miss_path_retries_and_confirms(self, tmp_path):
        """Through the REAL channel end to end — no stubbed reason. A
        prep census lacking the hypothesis callee must produce the
        structured census-miss code, trigger the fallback rebuild,
        and let the rebuild bind from the tree. Mutating either side
        of the reason-code contract (producer constant or consumer
        key) breaks the retry and fails this test."""
        for rel, content in _fixture_texts().items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        cfg = _Cfg(tmp_path)
        # Prep census computed over OTHER files: real, non-empty, and
        # without a do_auth entry.
        other = {
            "src/other.c":
                "int a(void) {\n"
                "    if (other_fn() != 0)\n"
                "        return -1;\n"
                "    return 0;\n}\n",
        }
        cfg.consistency_census = build_return_census(other)
        assert cfg.consistency_census  # non-empty, or no pass-through
        cfg.consistency_source_texts = other
        confirmed = self._run(cfg)
        assert len(confirmed) == 1
        assert confirmed[0].startswith("consistency")

    def test_prep_wur_witnesses_ride_with_the_census(
        self, tmp_path, monkeypatch,
    ):
        # Header-declared wur contracts are harvested by the prepass,
        # not by the chain-side source_texts harvest — losing them
        # would downgrade registry-grade receipts to majority-only.
        cfg = _Cfg(tmp_path)
        cfg.consistency_census = {"do_auth": object()}
        cfg.consistency_source_texts = _fixture_texts()
        cfg.consistency_wur_functions = frozenset({"do_auth"})
        calls = self._record_calls(monkeypatch, [
            ConsistencyResult(outcome="inconclusive", reason="x"),
        ])
        self._run(cfg)
        assert "do_auth" in calls[0]["context"].wur_functions

    def test_other_inconclusive_reasons_do_not_retry(
        self, tmp_path, monkeypatch,
    ):
        cfg = _Cfg(tmp_path)
        cfg.consistency_census = {"do_auth": object()}
        cfg.consistency_source_texts = _fixture_texts()
        calls = self._record_calls(monkeypatch, [
            ConsistencyResult(
                outcome="inconclusive",
                reason="group-too-small: n=2",
            ),
        ])
        self._run(cfg)
        assert len(calls) == 1
