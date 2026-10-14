"""Tests for the source-derived frontend feature ledger."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.testing.feature_ledger import (
    FeatureAssetKind,
    FeatureCollisionClass,
    FeatureEvidence,
    FeatureLedgerEntry,
    FeatureStatus,
    HostBuiltin,
    build_feature_ledger,
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
            for path in (REPO_ROOT / ".claude" / "agents").glob("*.md")
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

    assert ("audit", FeatureCollisionClass.COMMAND_SKILL) in collisions
    assert ("frida", FeatureCollisionClass.COMMAND_SKILL) in collisions
    for name in ("ask", "review", "version"):
        members = collisions[(name, FeatureCollisionClass.COMMAND_BUILTIN)]
        assert f".claude/commands/{name}.md" in members
        assert f"host-builtin:{name}" in members

    assert len(ledger.entries_for("audit")) == 2
    assert len(ledger.entries_for("frida")) == 2


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

    assert "/home/" not in encoded
    assert all("model" not in dict(entry.metadata) for entry in ledger.entries)
