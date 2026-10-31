"""Test for /agentic --verbose flag — bumps existing console
StreamHandlers from INFO to DEBUG so per-LLM-call detail surfaces.

The wiring lives at the top of raptor_agentic.py:main; we test the
side effect (handler-level mutation) rather than driving full main().

Note: logging.getLogger() handlers persist across pytest collection,
so we test that the wiring snippet correctly mutates *whatever*
StreamHandlers it finds, rather than asserting specific handler counts.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterator

import pytest


@contextlib.contextmanager
def _preserved_logging_levels() -> Iterator[None]:
    """Snapshot and restore every logging level this module's wiring
    can mutate: configure_run_logging touches the console handlers on
    the "raptor" logger, the tagged console handlers on the root
    logger, and the root logger's own level. Without restore, every
    test collected after this module in the same process runs with
    DEBUG console handlers — noisy output and order-dependent
    level/record assertions elsewhere."""
    root_logger = logging.getLogger()
    raptor_logger = logging.getLogger("raptor")
    handler_levels = [
        (h, h.level)
        for h in {*root_logger.handlers, *raptor_logger.handlers}
    ]
    logger_levels = [
        (root_logger, root_logger.level),
        (raptor_logger, raptor_logger.level),
    ]
    try:
        yield
    finally:
        for handler, level in handler_levels:
            handler.setLevel(level)
        for lg, level in logger_levels:
            lg.setLevel(level)


def _apply_verbose_wiring() -> None:
    """Mirror the snippet at raptor_agentic.py:main when --verbose."""
    from core.logging import configure_run_logging
    configure_run_logging(log_level=None, verbose=True)


def _console_handlers():
    from core.logging import _raptor_console_handlers
    return _raptor_console_handlers()


def _file_handlers():
    return [
        h for h in logging.getLogger("raptor").handlers
        if isinstance(h, logging.FileHandler)
    ]


def _raptor_root_console_handlers():
    from core.logging import _raptor_root_console_handlers
    return _raptor_root_console_handlers()


class TestVerboseWiring:
    @pytest.fixture(autouse=True)
    def _init_raptor_logging(self):
        from core.logging import get_logger
        get_logger()
        # Handlers exist now — snapshot AFTER init so the restore
        # covers exactly the handlers the wiring under test mutates.
        with _preserved_logging_levels():
            yield

    def test_verbose_bumps_console_streamhandlers_to_debug(self):
        # Force any console StreamHandlers back to INFO so we can see
        # the wiring flip them.
        for h in _console_handlers():
            h.setLevel(logging.INFO)

        _apply_verbose_wiring()

        stream_handlers = _console_handlers()
        assert stream_handlers, "expected at least one console StreamHandler"
        for h in stream_handlers:
            assert h.level == logging.DEBUG

    def test_verbose_does_not_affect_file_handler(self):
        file_handlers = _file_handlers()
        if not file_handlers:
            # In some test envs no file handler is attached; nothing to assert.
            return
        before_levels = [h.level for h in file_handlers]

        _apply_verbose_wiring()

        after_levels = [h.level for h in file_handlers]
        assert before_levels == after_levels

    def test_verbose_idempotent(self):
        _apply_verbose_wiring()
        _apply_verbose_wiring()  # second call is a no-op
        for h in _console_handlers():
            assert h.level == logging.DEBUG

    def test_log_level_warning_quiets_console_and_root_handlers(self):
        from core.logging import configure_run_logging

        root_logger = logging.getLogger()
        root_before = root_logger.level
        console = _console_handlers()
        root_console = _raptor_root_console_handlers()
        console_before = [h.level for h in console]
        root_console_before = [h.level for h in root_console]

        try:
            for h in console + root_console:
                h.setLevel(logging.INFO)
            root_logger.setLevel(logging.INFO)

            configure_run_logging(log_level="WARNING", verbose=False)

            assert console, "expected at least one console StreamHandler"
            assert root_console, "expected RAPTOR root console StreamHandler"
            assert all(h.level == logging.WARNING for h in console)
            assert all(h.level == logging.WARNING for h in root_console)
            assert root_logger.level == logging.WARNING
        finally:
            for h, level in zip(console, console_before, strict=True):
                h.setLevel(level)
            for h, level in zip(root_console, root_console_before, strict=True):
                h.setLevel(level)
            root_logger.setLevel(root_before)

    def test_wiring_mutations_are_contained(self):
        """Meta-pin for the isolation contract: the preserve context
        (which the autouse fixture wraps every test in) must restore
        the console-handler levels and the root logger level that
        _apply_verbose_wiring mutates — this file was a polluter that
        left DEBUG console handlers behind for the rest of the pytest
        process."""
        console = _console_handlers()
        root_console = _raptor_root_console_handlers()
        assert console, "expected at least one console StreamHandler"
        for h in console + root_console:
            h.setLevel(logging.INFO)
        root_logger = logging.getLogger()
        root_before = root_logger.level

        with _preserved_logging_levels():
            _apply_verbose_wiring()
            assert all(h.level == logging.DEBUG for h in _console_handlers())

        assert all(h.level == logging.INFO for h in console)
        assert all(h.level == logging.INFO for h in root_console)
        assert root_logger.level == root_before

    def test_launcher_extracts_valid_agentic_log_level_without_consuming_args(self):
        from raptor import _extract_agentic_log_level

        args = ["--repo", "/tmp/target", "--log-level", "warning"]

        assert _extract_agentic_log_level(args) == "WARNING"
        assert args == ["--repo", "/tmp/target", "--log-level", "warning"]

    def test_launcher_ignores_invalid_agentic_log_level_for_child_parser(self):
        from raptor import _extract_agentic_log_level

        assert _extract_agentic_log_level(["--log-level", "NOPE"]) is None
