"""The mechanical SCA phase must not run when --sca requests the deep phase.

With --sca, dependency findings used to be produced twice (the always-on
mechanical subprocess phase plus the opt-in deep run_sca phase) and both
totals were added into total_findings, double-counting dependency vulns
and feeding them into the pipeline via two channels.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace

from raptor_agentic import (
    _persist_redacted_sca_stderr,
    _sca_diagnostic_tool_fields,
    _sca_failure_reason,
    _sca_required_for_success,
    _sca_subprocess_timeout,
    _sandbox_worker_passthrough,
    _should_run_mechanical_sca,
    _tool_state,
)


class TestMechanicalScaGate(unittest.TestCase):

    def test_runs_when_agent_present_and_no_deep_sca(self):
        self.assertTrue(_should_run_mechanical_sca("/path/to/agent", False))

    def test_skipped_when_deep_sca_requested(self):
        # Deep --sca analyses the same dependency set; running both
        # would double-count dependency findings.
        self.assertFalse(_should_run_mechanical_sca("/path/to/agent", True))

    def test_skipped_when_agent_missing(self):
        self.assertFalse(_should_run_mechanical_sca(None, False))
        self.assertFalse(_should_run_mechanical_sca(None, True))

    def test_sca_stderr_redaction_is_shared_by_log_and_file(self):
        with self.subTest("terminal text and file sink use one redaction"):
            from tempfile import TemporaryDirectory

            with TemporaryDirectory() as tmp:
                output = Path(tmp)
                safe = _persist_redacted_sca_stderr(
                    "request failed token=secret-value-123 "
                    "\x1b]0;forged\x07\n",
                    output,
                )
                persisted = (output / "stderr.log").read_text(
                    encoding="utf-8")
                self.assertEqual(persisted, safe)
                self.assertNotIn("secret-value-123", safe)
                self.assertNotIn("\x1b", safe)
                self.assertEqual(
                    (output / "stderr.log").stat().st_mode & 0o777,
                    0o600,
                )

    def test_timeout_diagnostic_flows_into_agentic_tool_state(self):
        diagnostic = {
            "status": "timed_out",
            "disposition": "failed",
            "mode": "mechanical",
            "reason": "SCA internal deadline exhausted",
            "phase": {
                "name": "llm-review",
                "description": "running LLM behavioural review",
            },
        }
        reason = _sca_failure_reason(124, "", diagnostic)
        fields = _sca_diagnostic_tool_fields(
            diagnostic,
            default_disposition="failed",
        )
        state = _tool_state(
            "failed",
            requested=True,
            reason=reason,
            timed_out=True,
            **fields,
        )

        self.assertEqual(state["disposition"], "failed")
        self.assertEqual(state["diagnostic_status"], "timed_out")
        self.assertEqual(state["phase"], "llm-review")
        self.assertIn("running LLM behavioural review", state["reason"])
        self.assertTrue(state["timed_out"])

    def test_missing_agent_has_visible_unsupported_disposition(self):
        state = _tool_state(
            "skipped",
            requested=False,
            reason="SCA agent not available",
            disposition="unsupported",
        )
        self.assertEqual(state["status"], "skipped")
        self.assertEqual(state["disposition"], "unsupported")
        self.assertEqual(state["skip_reason"], "SCA agent not available")

    def test_no_sandbox_compatibility_override_for_worker_argv(self):
        args = SimpleNamespace(
            sandbox="full",
            no_sandbox=True,
            audit=False,
            audit_verbose=False,
            sandbox_floor=None,
        )
        self.assertEqual(
            _sandbox_worker_passthrough(args),
            ["--no-sandbox"],
        )

        args.no_sandbox = False
        args.sandbox = "none"
        self.assertEqual(
            _sandbox_worker_passthrough(args),
            ["--sandbox", "none"],
        )

    def test_sca_timeout_default_and_explicit_override(self):
        self.assertEqual(
            _sca_subprocess_timeout(1800, explicitly_set=False),
            600,
        )
        self.assertEqual(
            _sca_subprocess_timeout(7200, explicitly_set=True),
            7200,
        )
        self.assertEqual(
            _sca_subprocess_timeout(0, explicitly_set=True),
            0,
        )

    def test_import_and_openant_only_do_not_require_additive_sca(self):
        self.assertFalse(_sca_required_for_success(
            run_semgrep=False,
            run_codeql=False,
            deep_sca_requested=False,
        ))
        self.assertTrue(_sca_required_for_success(
            run_semgrep=True,
            run_codeql=False,
            deep_sca_requested=False,
        ))
        self.assertTrue(_sca_required_for_success(
            run_semgrep=False,
            run_codeql=False,
            deep_sca_requested=True,
        ))


if __name__ == "__main__":
    unittest.main()
