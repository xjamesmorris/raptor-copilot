"""Tests for the generated Copilot custom-agent projection."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_SCRIPT = (
    Path(__file__).resolve().parents[3]
    / ".github"
    / "scripts"
    / "project_agent_projection.py"
)


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location(
        "project_agent_projection",
        _SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_committed_projection_is_exact_and_warning_free(mod) -> None:
    report = mod.build_report()

    assert len(report.agents) == 18
    assert report.errors == ()
    assert report.warnings == ()
    assert not list((mod.REPO / ".claude" / "agents").glob("*.md"))


def test_only_model_field_differs_between_frontends(mod) -> None:
    source, source_errors = mod._load_directory(mod.AUTHORITATIVE_DIR)
    projected, projected_errors = mod._load_directory(mod.COPILOT_DIR)

    assert source_errors == []
    assert projected_errors == []
    assert set(source) == set(projected)
    for agent_id in source:
        authoritative = source[agent_id]
        copilot = projected[agent_id]
        source_metadata = dict(authoritative.metadata)
        projected_metadata = dict(copilot.metadata)
        assert source_metadata.pop("model") == "inherit"
        assert "model" not in projected_metadata
        assert source_metadata == projected_metadata
        assert authoritative.instructions == copilot.instructions
        assert copilot.text == mod.project_agent_text(authoritative)


def test_plugin_hook_policy_covers_reviewed_agents(mod) -> None:
    source, source_errors = mod._load_directory(mod.AUTHORITATIVE_DIR)

    assert source_errors == []
    assert all("hooks" not in document.metadata for document in source.values())
    assert mod._check_plugin_hook_policy(source) == []
    protected = {
        agent_type.removeprefix("raptor-agents:")
        for agent_type in mod._PROTECTED_AGENT_TYPES
    }
    for document in source.values():
        if document.metadata["name"] not in protected:
            continue
        normalized_instructions = " ".join(document.instructions.split())
        assert (
            "Copilot custom agents do not execute Claude plugin hooks"
            in normalized_instructions
        )


def test_json_inventory_is_side_effect_free(mod, capsys) -> None:
    before = {
        path.name: path.read_bytes()
        for path in sorted(mod.COPILOT_DIR.glob("*.md"))
    }

    assert mod.main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    after = {
        path.name: path.read_bytes()
        for path in sorted(mod.COPILOT_DIR.glob("*.md"))
    }
    assert before == after
    assert len(payload["agents"]) == 18
    assert payload["errors"] == []
    assert payload["warnings"] == []
