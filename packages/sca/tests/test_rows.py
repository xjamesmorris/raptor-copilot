"""Tests for ``packages.sca.rows`` — the typed read-side row view."""

from __future__ import annotations

from typing import Any

from packages.sca.rows import FindingRow


def _row(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "sca:vuln:npm:lodash:4.17.20:GHSA-x",
        "finding_id": "sca:vuln:npm:lodash:4.17.20:GHSA-x",
        "vuln_type": "sca:vulnerable_dependency",
        "tool": "sca",
        "file": "/repo/package.json",
        "function": "lodash",
        "line": 0,
        "severity": "critical",
        "suppressed": False,
        "suppression_reason": None,
        "title": "lodash@4.17.20 — vulnerable",
        "description": "lodash@4.17.20: bad",
        "sca": {
            "ecosystem": "npm",
            "name": "lodash",
            "reachability": {"verdict": "likely_called"},
            "advisory": {"id": "GHSA-x", "aliases": ["CVE-2021-0001"]},
        },
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# from_row parsing
# ---------------------------------------------------------------------------

def test_from_row_reads_envelope_fields() -> None:
    fr = FindingRow.from_row(_row())
    assert fr is not None
    assert fr.finding_id == "sca:vuln:npm:lodash:4.17.20:GHSA-x"
    assert fr.vuln_type == "sca:vulnerable_dependency"
    assert fr.tool == "sca"
    assert fr.file == "/repo/package.json"
    assert fr.function == "lodash"
    assert fr.line == 0
    assert fr.severity == "critical"
    assert fr.suppressed is False
    assert fr.suppression_reason is None
    assert fr.title == "lodash@4.17.20 — vulnerable"
    assert fr.sca["ecosystem"] == "npm"


def test_from_row_non_dict_is_none() -> None:
    assert FindingRow.from_row(None) is None
    assert FindingRow.from_row("stray string") is None
    assert FindingRow.from_row(["not", "a", "row"]) is None
    assert FindingRow.from_row(42) is None


def test_raw_is_the_original_mapping() -> None:
    """Pass-through consumers re-emit ``raw``; it must be the same
    object (identity, not a copy) so unknown keys survive untouched."""
    row = _row(provenance_refs=[{"run_id": "r1"}], custom_key="kept")
    fr = FindingRow.from_row(row)
    assert fr is not None
    assert fr.raw is row
    assert fr.raw["provenance_refs"] == [{"run_id": "r1"}]
    assert fr.raw["custom_key"] == "kept"


def test_wrong_typed_fields_degrade_to_defaults() -> None:
    """Malformed values read as the write side's "empty" value —
    never a crash (hand-edited findings.json tolerance)."""
    fr = FindingRow.from_row({
        "vuln_type": 7,
        "severity": None,
        "line": "12",
        "suppressed": "yes",          # truthy → True (bool coercion)
        "suppression_reason": 3,
        "sca": "not a dict",
        "description": ["x"],
    })
    assert fr is not None
    assert fr.vuln_type == ""
    assert fr.severity == "info"
    assert fr.line == 0
    assert fr.suppressed is True
    assert fr.suppression_reason is None
    assert fr.sca == {}
    assert fr.description == ""


def test_empty_row_gets_all_defaults() -> None:
    fr = FindingRow.from_row({})
    assert fr is not None
    assert fr.vuln_type == ""
    assert fr.severity == "info"
    assert fr.suppressed is False
    assert fr.sca == {}
    assert fr.raw == {}


# ---------------------------------------------------------------------------
# Kind classification
# ---------------------------------------------------------------------------

def test_kind_classification() -> None:
    cases = {
        "sca:vulnerable_dependency": "is_vulnerable_dependency",
        "sca:hygiene:loose_pin": "is_hygiene",
        "sca:supply_chain:typosquat_candidate": "is_supply_chain",
        "sca:license:denied": "is_license",
        "sca:scan_health:osv_lookup_failed": "is_scan_health",
    }
    flags = list(cases.values())
    for vuln_type, expected in cases.items():
        fr = FindingRow.from_row(_row(vuln_type=vuln_type))
        assert fr is not None
        assert fr.is_sca is True
        for flag in flags:
            assert getattr(fr, flag) is (flag == expected), (
                f"{vuln_type}: {flag}"
            )


def test_non_sca_row_classifies_as_foreign() -> None:
    fr = FindingRow.from_row(_row(vuln_type="semgrep:injection"))
    assert fr is not None
    assert fr.is_sca is False
    assert fr.is_vulnerable_dependency is False


# ---------------------------------------------------------------------------
# Nested reads
# ---------------------------------------------------------------------------

def test_advisory_and_reachability_accessors() -> None:
    fr = FindingRow.from_row(_row())
    assert fr is not None
    assert fr.advisory["id"] == "GHSA-x"
    assert fr.reachability_verdict == "likely_called"


def test_nested_accessors_tolerate_malformed_blocks() -> None:
    fr = FindingRow.from_row(_row(sca={
        "advisory": "junk",
        "reachability": ["junk"],
    }))
    assert fr is not None
    assert fr.advisory == {}
    assert fr.reachability_verdict == "not_evaluated"

    fr = FindingRow.from_row(_row(sca={}))
    assert fr is not None
    assert fr.advisory == {}
    assert fr.reachability_verdict == "not_evaluated"

    # Empty verdict string degrades to the default too.
    fr = FindingRow.from_row(_row(sca={"reachability": {"verdict": ""}}))
    assert fr is not None
    assert fr.reachability_verdict == "not_evaluated"
