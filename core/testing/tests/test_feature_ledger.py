"""Tests for the source-derived frontend feature ledger."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from core.testing.feature_ledger import (
    FeatureAssetKind,
    FeatureCollisionClass,
    FeatureEvidence,
    FeatureLedgerEntry,
    FeatureStatus,
    FrontendAdapter,
    HostBuiltin,
    build_feature_ledger,
    build_frontend_inventory,
    frontend_parity_errors,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
COPILOT_BUILTINS = (
    HostBuiltin(
        name="ask",
        behavior="host-provided question command",
        evidence_source="non-inference host discovery",
    ),
    HostBuiltin(
        name="review",
        behavior="host-provided review command",
        evidence_source="non-inference host discovery",
    ),
    HostBuiltin(
        name="version",
        behavior="host-provided version command",
        evidence_source="non-inference host discovery",
    ),
)


def _ledger():
    return build_feature_ledger(
        REPO_ROOT,
        host_builtins=COPILOT_BUILTINS,
    )


def test_current_source_assets_are_all_accounted_for_without_magic_counts() -> None:
    ledger = _ledger()
    expected = {
        FeatureAssetKind.COMMAND: {
            path.relative_to(REPO_ROOT).as_posix()
            for path in (REPO_ROOT / ".claude" / "commands").glob("*.md")
        },
        FeatureAssetKind.SKILL: {
            path.relative_to(REPO_ROOT).as_posix()
            for path in (REPO_ROOT / ".claude" / "skills").rglob("SKILL.md")
        },
        FeatureAssetKind.AGENT: {
            path.relative_to(REPO_ROOT).as_posix()
            for path in (
                REPO_ROOT / "plugins" / "agents" / "agents"
            ).glob("*.md")
        },
    }

    for kind, paths in expected.items():
        observed = {
            entry.source_asset for entry in ledger.entries if entry.asset_kind is kind
        }
        assert observed == paths


def test_command_dispatch_uses_canonical_metadata_parser() -> None:
    ledger = _ledger()

    audit = next(
        entry
        for entry in ledger.entries_for("audit")
        if entry.asset_kind is FeatureAssetKind.COMMAND
    )
    review = next(
        entry
        for entry in ledger.entries_for("review")
        if entry.asset_kind is FeatureAssetKind.COMMAND
    )

    assert audit.behavior == "skill"
    assert dict(audit.metadata)["dispatch"] == "skill"
    assert review.behavior == "libexec/raptor-review $ARGUMENTS"


def test_collision_inventory_preserves_every_namespace_member() -> None:
    ledger = _ledger()
    collisions = {
        (item.canonical_name, item.collision_class): item.members
        for item in ledger.collisions
    }

    assert ("audit", FeatureCollisionClass.COMMAND_SKILL) not in collisions
    assert ("frida", FeatureCollisionClass.COMMAND_SKILL) not in collisions
    for name in ("ask", "review", "version"):
        members = collisions[(name, FeatureCollisionClass.COMMAND_BUILTIN)]
        assert f".claude/commands/{name}.md" in members
        assert f"host-builtin:{name}" in members

    assert len(ledger.entries_for("audit")) == 1
    assert len(ledger.entries_for("audit-in-session")) == 1
    assert len(ledger.entries_for("frida")) == 1
    assert len(ledger.entries_for("frida-instrumentation")) == 1


def test_frontmatter_names_drive_skill_and_agent_inventory() -> None:
    ledger = _ledger()

    assert {
        entry.canonical_name
        for entry in ledger.entries
        if entry.asset_kind is FeatureAssetKind.SKILL
    } >= {
        "Code-Coverage-with-gcov",
        "Function-Call-Tracing",
        "Line-Execution-Checker",
        "audit-in-session",
        "frida-instrumentation",
    }
    coverage = next(
        entry
        for entry in ledger.entries
        if entry.source_asset
        == "plugins/agents/agents/coverage-analysis-generator-agent.md"
    )
    assert coverage.canonical_name == "coverage-analyzer"


def test_non_inference_discovery_never_claims_live_validation() -> None:
    ledger = _ledger()
    builtins = [
        entry
        for entry in ledger.entries
        if entry.asset_kind is FeatureAssetKind.HOST_BUILTIN
    ]

    assert builtins
    assert all(
        entry.evidence is FeatureEvidence.NON_INFERENCE_DISCOVERY for entry in builtins
    )
    assert all(entry.status is FeatureStatus.CANDIDATE_UNVERIFIED for entry in builtins)
    assert all(
        entry.status is not FeatureStatus.LIVE_VERIFIED for entry in ledger.entries
    )

    with pytest.raises(ValueError, match="live_verified"):
        FeatureLedgerEntry(
            canonical_name="synthetic",
            asset_kind=FeatureAssetKind.HOST_BUILTIN,
            source_asset="host-builtin:synthetic",
            behavior="synthetic behavior",
            capability_requirement="host_builtin",
            host_mapping="/synthetic",
            evidence=FeatureEvidence.NON_INFERENCE_DISCOVERY,
            status=FeatureStatus.LIVE_VERIFIED,
        )


def test_machine_readable_ledger_is_stable_and_independent() -> None:
    ledger = _ledger()

    first = ledger.to_dict()
    second = ledger.to_dict()
    assert json.dumps(first, sort_keys=True) == json.dumps(
        second,
        sort_keys=True,
    )

    first["entries"][0]["canonical_name"] = "mutated"
    assert ledger.to_dict()["entries"][0]["canonical_name"] != "mutated"


def test_ledger_contains_no_development_role_defaults_or_private_paths() -> None:
    ledger = _ledger()
    encoded = json.dumps(ledger.to_dict(), sort_keys=True)
    agents = [
        entry
        for entry in ledger.entries
        if entry.asset_kind is FeatureAssetKind.AGENT
    ]

    assert "/home/" not in encoded
    assert all(dict(entry.metadata).get("model") == "inherit" for entry in agents)
    assert all(
        "model" not in dict(entry.metadata)
        for entry in ledger.entries
        if entry.asset_kind is not FeatureAssetKind.AGENT
    )


@pytest.mark.parametrize("adapter", list(FrontendAdapter))
def test_frontend_adapters_have_exact_enabled_unique_inventory(
    adapter: FrontendAdapter,
) -> None:
    ledger = build_feature_ledger(REPO_ROOT)
    inventory = build_frontend_inventory(ledger, adapter)

    assert frontend_parity_errors(ledger, inventory) == ()
    assert {
        entry.source_asset for entry in inventory.entries
    } == {
        entry.source_asset
        for entry in ledger.entries
        if entry.asset_kind is not FeatureAssetKind.HOST_BUILTIN
    }


def test_copilot_json_skill_projection_contains_commands_and_skills() -> None:
    ledger = build_feature_ledger(REPO_ROOT)
    inventory = build_frontend_inventory(ledger, FrontendAdapter.COPILOT)
    prompt_entries = {
        (entry.canonical_name, entry.asset_kind)
        for entry in inventory.entries
        if entry.surface == "skill"
    }

    assert ("audit", FeatureAssetKind.COMMAND) in prompt_entries
    assert ("audit-in-session", FeatureAssetKind.SKILL) in prompt_entries
    assert ("frida", FeatureAssetKind.COMMAND) in prompt_entries
    assert ("frida-instrumentation", FeatureAssetKind.SKILL) in prompt_entries
    assert sum(
        entry.asset_kind is FeatureAssetKind.AGENT
        for entry in inventory.entries
    ) == 18


def test_parity_errors_reject_missing_duplicate_and_disabled_entries() -> None:
    ledger = build_feature_ledger(REPO_ROOT)
    inventory = build_frontend_inventory(ledger, FrontendAdapter.COPILOT)
    first = inventory.entries[0]

    missing = replace(inventory, entries=inventory.entries[1:])
    assert frontend_parity_errors(ledger, missing) == (
        f"missing: {first.source_asset}",
    )

    duplicate = replace(
        inventory,
        entries=inventory.entries + (first,),
    )
    assert any(
        error.startswith(f"duplicate {first.surface} name ")
        for error in frontend_parity_errors(ledger, duplicate)
    )

    disabled = replace(
        inventory,
        entries=(replace(first, enabled=False),) + inventory.entries[1:],
    )
    assert frontend_parity_errors(ledger, disabled) == (
        f"disabled: {first.source_asset}",
    )
