"""Doctrine fence for Copilot long-command and child-wait routing.

This repository can prove its own instruction precedence, launcher defaults,
and persisted-event wording. A deterministic test cannot prove why an
external Copilot runtime assigned an event label or delayed a child, so these
tests explicitly fence out that stronger attribution.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _read(relative: str) -> str:
    return (REPO / relative).read_text(encoding="utf-8")


def _section(text: str, start: str, end: str) -> str:
    return text.split(start, 1)[1].split(end, 1)[0]


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_dispatched_children_skip_operator_startup_banner() -> None:
    session_start = _section(
        _read("CLAUDE.md"),
        "## SESSION START",
        "## EXECUTION RULES",
    )
    flat_session_start = _flat(session_start)
    child_guard = session_start.index("Dispatched subagents")
    banner_rule = session_start.index("On the first message:")
    assert child_guard < banner_rule
    assert "`execution_subagent` and task agents" in flat_session_start
    assert "do not inspect or read `.startup-output`" in flat_session_start
    assert "do not print the banner or quick commands" in flat_session_start
    assert (
        "while still performing step 3 if SAGE is available"
        in flat_session_start
    )


def test_frontend_precedence_and_narrow_bash_exception_are_explicit() -> None:
    contract = _section(
        _read("CLAUDE.md"),
        "### Copilot long-run wait contract",
        "---",
    )
    flat_contract = _flat(contract)
    required = (
        "Higher-priority frontend tool instructions govern routing",
        "`execution_subagent` remains mandatory",
        "Direct `bash` is permitted only",
        "complete, unfiltered stdout of exactly one command",
        "This repository does not create a broader exception",
        "if the active frontend instructions do not expose that exception, "
        "use `execution_subagent`",
        "call count is a hard acceptance bound",
        "Tool allowlists grant capabilities; they do not enforce invocation "
        "counts",
        "evaluate each shell command independently",
        "One logical child operation consumes at most one "
        "`execution_subagent` call",
        "stop before exceeding the cap",
        "do not claim that repository instructions can control upstream "
        "scheduling",
        "`execution_subagent` is a built-in managed agent",
        "repository setting was ignored",
        "Usage output is authoritative for the observed managed-child model",
        "distinct from the parent frontend `--model` and RAPTOR "
        "finding-analysis model controls",
    )
    for phrase in required:
        assert phrase in flat_contract
    assert flat_contract.index(required[0]) < flat_contract.index(required[1])
    assert flat_contract.index(required[1]) < flat_contract.index(required[2])
    assert "timeoutSeconds" not in flat_contract
    assert "timeout 180" not in flat_contract


def test_repo_copilot_settings_do_not_claim_managed_child_control() -> None:
    settings = json.loads(_read(".github/copilot/settings.json"))
    assert settings == {
        "model": "gpt-6-astra",
        "effortLevel": "max",
        "contextTier": "long_context",
    }
    assert "subagents" not in settings


def test_wait_doctrine_uses_explicit_observation_not_telemetry_inference() -> None:
    contract = _flat(
        _section(
            _read("CLAUDE.md"),
            "### Copilot long-run wait contract",
            "---",
        )
    )
    required = (
        '`mode="sync"`',
        "stable `shellId`",
        "`initial_wait`",
        "tool result explicitly says the command is still running",
        "do not infer a process or pipeline failure from a "
        "`shell_error_category=command_timeout` or `is_timeout=true` "
        "label alone",
        "`shell_completed` notification",
        "call `read_bash` once with the same `shellId`",
        "launch a duplicate scan",
        "call `stop_bash` with that exact `shellId`",
        "termination of the command's process tree",
        "Never detach an analysis run",
        "SCA's own 600-second operation timeout",
        "max-findings capping",
    )
    for phrase in required:
        assert phrase in contract
    assert "`timeout` wrapper" in contract
    assert "the command moved to the background" not in contract


def test_command_docs_defer_to_frontend_policy_before_bash_exception() -> None:
    for relative in (
        ".claude/commands/agentic.md",
        ".claude/commands/raptor.md",
    ):
        text = _flat(_read(relative))
        assert "higher-priority tool-routing instructions" in text
        assert "Copilot long-run wait contract" in text
        assert "permits direct `bash` for exactly one command" in text
        assert "complete, unfiltered stdout is required" in text
        assert "Otherwise use `execution_subagent`" in text
        assert "result explicitly says the command is still running" in text
        assert "`command_timeout` telemetry label alone" in text


def test_post_run_routing_keeps_multi_command_work_on_execution_subagent() -> None:
    contract = _flat(
        _section(
            _read("CLAUDE.md"),
            "### Copilot long-run wait contract",
            "---",
        )
    )
    assert "use non-shell read tools" in contract
    assert (
        "keep the mandatory `execution_subagent` route unless one exact "
        "command independently satisfies" in contract
    )
    assert "Never broaden that exception to a multi-command validation sequence" in contract
    assert "never divert a child into the operator-facing startup banner" in contract


def test_launcher_adds_no_frontend_wait_deadline_or_autoapproval() -> None:
    launcher = _read("bin/raptor")
    defaults = _section(
        launcher,
        "# Parse RAPTOR-specific args",
        "# Build initial prompt",
    )
    frontend_exec = _section(
        launcher,
        "# RAPTOR_FRONTEND_EXEC_BEGIN",
        "# RAPTOR_FRONTEND_EXEC_END",
    )
    owned_surface = defaults + frontend_exec
    assert "--allow-all-tools" not in owned_surface
    assert "--allow-tool" not in owned_surface
    assert "--deny-tool" not in owned_surface
    assert "timeoutSeconds" not in owned_surface
    assert "execution_subagent" not in owned_surface


def test_readme_labels_observations_and_attribution_limits() -> None:
    readme = _flat(_read("README-Copilot.md"))
    assert "Observed incident evidence and limits" in readme
    assert (
        "does not prove that the version or an internal Copilot mechanism "
        "caused the observed labels or delays" in readme
    )
    assert "no RAPTOR-added command or execution-subagent deadline" in readme
    assert (
        "event stream does not identify either as the cause of the shell or "
        "child wait" in readme
    )
    assert (
        "prove that the RAPTOR command continued and completed after the "
        "observation boundary" in readme
    )
    assert "do not prove why the external runtime applied that label" in readme
    assert "`human_response` at 03:24:52Z and 03:24:58Z" in readme
    assert "directly correlated with pending human approvals" in readme
    assert (
        "does not, by itself, prove the execution subagent's internal "
        "scheduler state or establish an internal deadline" in readme
    )
    forbidden_overclaims = (
        "Copilot CLI reported an expired",
        "The four-hour interval was permission wait",
        "This was not a RAPTOR timeout",
        "the command moved to the background",
    )
    for phrase in forbidden_overclaims:
        assert phrase not in readme


def test_readme_pins_credit_floor_and_child_model_boundary() -> None:
    readme = _flat(_read("README-Copilot.md"))
    required = (
        "minimum `--max-ai-credits` value of **30**",
        "RAPTOR does not invent a smaller credit budget",
        "One call may therefore cross the configured limit",
        "built-in managed agent",
        "did not pin this built-in managed agent",
        "usage output showed GPT-5.6 Luna instead",
        "not a per-call model field",
        "Usage output is authoritative",
        "do not require it to match a requested child model",
        "Parent Copilot session",
        "Copilot managed execution child",
        "RAPTOR finding analysis",
    )
    for phrase in required:
        assert phrase in readme
    assert "gpt-5.4-mini" not in readme
    assert "model mismatch fails" not in readme


def test_bounded_acceptance_documents_prompt_allowlist_and_verification() -> None:
    bounded = _flat(
        _section(
            _read("README-Copilot.md"),
            "### Bounded one-child acceptance",
            "### Observed incident evidence and limits",
        )
    )
    required = (
        "--allow-tool=view",
        "--allow-tool=shell(libexec/raptor-run-lifecycle:*)",
        "--allow-tool=execution_subagent",
        "--deny-tool=write",
        "--deny-tool=edit",
        "each enumerated lifecycle command is a separate exact direct-shell "
        "call",
        "`execution_subagent` is reserved for the one logical child operation",
        "stop before a second child call",
        "not a mechanical call counter",
        "does not control Copilot's upstream scheduler",
        "exactly one unique `execution_subagent` call",
        "record the effective managed-child model",
        "repository configuration cannot pin it",
        "observed child-model difference does not",
    )
    for phrase in required:
        assert phrase in bounded
    assert "--allow-all-tools" in bounded
    assert "Do not add `--allow-all-tools` or `--yolo`" in bounded
