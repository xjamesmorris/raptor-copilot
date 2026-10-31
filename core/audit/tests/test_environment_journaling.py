"""Truthful journaling for environment-caused non-reviews.

Systemic environmental failures journal as ``error`` verdicts with
the machine-readable ``error_class="environment"`` — distinct from
genuine per-function review errors — and such rows must (a) never
count as reviewed for coverage, (b) re-enter the gap set on
resume/next run, and (c) never qualify for verdict reuse or the
in-run recoverable retry pass."""

from __future__ import annotations

import errno
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

from core.audit.gaps import _fold_journal_into_covered, _verify_entries_fold
from core.audit.orchestrator import (
    _RECOVERABLE_ERROR_CLASSES,
    _classify_error,
    _error_outcome,
    get_reviewed_set,
)
from core.audit.record import append_audit_log
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    load_entries,
    reviewed_set,
)


def _wrapped(eno: int) -> RuntimeError:
    exc = RuntimeError("dispatch failed")
    exc.__cause__ = OSError(eno, "synthetic")
    return exc


# ── Classification ────────────────────────────────────────────────────


class TestErrorClassification:
    def test_systemic_errnos_classify_environment(self):
        assert _classify_error(OSError(errno.ENOSPC, "x")) == "environment"
        assert _classify_error(_wrapped(errno.ENOSPC)) == "environment"
        assert _classify_error(_wrapped(errno.EMFILE)) == "environment"
        assert _classify_error(_wrapped(errno.EROFS)) == "environment"

    def test_sub_threshold_auth_refusal_keeps_per_function_class(self):
        # Auth failures feed the breaker window, but a single refusal
        # must not mark the row environment — only a breaker
        # CONCLUSION proves the credential (vs this one call) failed.
        exc = RuntimeError("request rejected")
        exc.status_code = 401
        assert _classify_error(exc) != "environment"

    def test_connect_error_shape_stays_recoverable(self):
        # The wrapped shape a real transport connect failure arrives
        # in (RuntimeError `from` the ECONNREFUSED OSError): a
        # sub-threshold network blip must keep the recoverable
        # api_error lane (end-of-run re-queue), not permanently error
        # the function's review as "environment".
        exc = RuntimeError("dispatch failed")
        exc.__cause__ = OSError(errno.ECONNREFUSED, "connection refused")
        assert _classify_error(exc) == "api_error"

    def test_timeout_with_ambient_network_context_keeps_timeout_class(self):
        # A TimeoutError raised while an ECONNREFUSED sat in implicit
        # __context__ is a timeout — classifying it environment (or
        # network) would strip the reduced-context timeout retry.
        exc = TimeoutError("review call timed out")
        exc.__context__ = OSError(errno.ECONNREFUSED, "connection refused")
        assert _classify_error(exc) == "timeout"

    def test_breaker_conclusion_marks_network_rows_environment(self):
        # Once the breaker has CONCLUDED, the environment is proven
        # down: in-flight failures draining behind the conclusion are
        # environment-caused, not per-function.
        from types import SimpleNamespace as _NS

        exc = RuntimeError("dispatch failed")
        exc.__cause__ = OSError(errno.ECONNREFUSED, "connection refused")
        guard = _NS(concluded=True)
        config = _NS(environment_guard_state=guard)
        assert _classify_error(exc, config) == "environment"
        guard.concluded = False
        assert _classify_error(exc, config) == "api_error"

    def test_budget_keeps_its_own_class(self):
        # Budget exhaustion has its own terminal handling — it must
        # never be relabelled environmental.
        assert _classify_error(
            RuntimeError("LLM budget exceeded: cap"),
        ) == "budget"

    def test_ordinary_transport_errors_stay_api_error(self):
        # A plain connection blip without a systemic errno keeps the
        # recoverable api_error class (end-of-run retry re-queues it).
        assert _classify_error(ConnectionError("reset")) == "api_error"

    def test_environment_is_not_recoverable_in_run(self):
        # Both directions: environment must stay out (retrying into a
        # faulted environment), api_error must stay in (transient
        # brownouts recover by end of run).
        assert "environment" not in _RECOVERABLE_ERROR_CLASSES
        assert "api_error" in _RECOVERABLE_ERROR_CLASSES

    def test_error_outcome_carries_the_class(self):
        gap = {"file": "a.py", "name": "f", "line_start": 3}
        outcome = _error_outcome(gap, _wrapped(errno.ENOSPC))
        assert outcome.status == "error"
        assert outcome.error_class == "environment"


class TestExecutorErrorOutcome:
    def _commit(self, exc: Exception, guard: Any = None) -> Any:
        from core.audit.executor import _commit_error_outcome

        submitted: list[Any] = []
        collector = SimpleNamespace(
            submit=lambda outcome, gap: submitted.append(outcome),
        )
        task = SimpleNamespace(
            key="a.py:f", gap={"file": "a.py", "name": "f", "line_start": 1},
        )
        config = SimpleNamespace(environment_guard_state=guard)
        _commit_error_outcome(task, exc, config, MagicMock(), collector)
        assert len(submitted) == 1
        return submitted[0]

    def test_systemic_failure_stamps_environment(self):
        outcome = self._commit(_wrapped(errno.ENOSPC))
        assert outcome.status == "error"
        assert outcome.error_class == "environment"

    def test_ordinary_failure_stays_task_exception(self):
        outcome = self._commit(ValueError("boom"))
        assert outcome.error_class == "task_exception"

    def test_sub_threshold_network_failure_stays_task_exception(self):
        # Network failures feed the breaker window (via the
        # note_dispatch_failure call in the same writer) but do not
        # mark the row environment below the trip threshold.
        outcome = self._commit(_wrapped(errno.ECONNREFUSED))
        assert outcome.error_class == "task_exception"

    def test_network_failure_after_conclusion_stamps_environment(self):
        guard = SimpleNamespace(
            concluded=True,
            note_dispatch_failure=lambda key, exc: None,
        )
        outcome = self._commit(_wrapped(errno.ECONNREFUSED), guard=guard)
        assert outcome.error_class == "environment"


# ── Journal semantics ────────────────────────────────────────────────


def _entry(verdict: str, function: str = "f",
           error_class: str | None = None) -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts="2020-01-01T00:00:00Z",
        run_id="run1",
        file="a.py",
        function=function,
        verdict=verdict,
        source_hash="",
        line_start=1,
        error_class=error_class,
    )


class TestJournalSemantics:
    def test_error_class_round_trips(self, tmp_path):
        append_entry(
            tmp_path, _entry("error", error_class="environment"),
        )
        entries = load_entries(tmp_path)
        assert len(entries) == 1
        assert entries[0].verdict == "error"
        assert entries[0].error_class == "environment"

    def test_environment_rows_never_reviewed_or_covered(self, tmp_path):
        append_entry(
            tmp_path, _entry("error", "envfail", error_class="environment"),
        )
        append_entry(tmp_path, _entry("clean", "ok"))
        # Resume fast-lookup: the failed function is retried, not
        # suppressed as already reviewed.
        assert reviewed_set(tmp_path) == {"a.py:ok"}
        # Gap fold (per-run journal): the failed function stays a gap.
        covered: set = set()
        _fold_journal_into_covered(covered, tmp_path, None)
        assert "a.py:ok" in covered
        assert "a.py:envfail" not in covered

    def test_environment_rows_never_qualify_for_verdict_reuse(self, tmp_path):
        # The hash-verified fold (same-run resume AND the cross-run
        # project index share this core) drops error rows before any
        # reuse eligibility screen — they neither suppress the gap nor
        # become $0 reuse candidates.
        covered: set = set()
        reuse_sink: dict = {}
        _verify_entries_fold(
            covered,
            [_entry("error", "envfail", error_class="environment")],
            target_path=tmp_path,
            current_spans={},
            reuse_sink=reuse_sink,
            current_strategies_fn=None,
            current_model=None,
            source_label="same-run",
        )
        assert not covered
        assert not reuse_sink

    def test_same_run_resume_fold_keeps_environment_rows_as_gaps(
        self, tmp_path,
    ):
        append_entry(
            tmp_path, _entry("error", "envfail", error_class="environment"),
        )
        covered: set = set()
        reuse_sink: dict = {}
        _fold_journal_into_covered(
            covered, tmp_path, None,
            target_path=tmp_path,
            reuse_sink=reuse_sink,
            own_run_reuse=True,
        )
        assert not covered
        assert not reuse_sink


class TestAuditLogSemantics:
    def test_error_class_lands_in_audit_log_and_stays_unreviewed(
        self, tmp_path,
    ):
        append_audit_log(tmp_path, {
            "action": "orchestrator_review",
            "key": "a.py:envfail:1",
            "status": "error",
            "error_class": "environment",
        })
        append_audit_log(tmp_path, {
            "action": "orchestrator_review",
            "key": "a.py:ok:1",
            "status": "clean",
        })
        reviewed = get_reviewed_set(tmp_path)
        assert "a.py:ok:1" in reviewed
        assert "a.py:envfail:1" not in reviewed
        assert "a.py:envfail" not in reviewed
