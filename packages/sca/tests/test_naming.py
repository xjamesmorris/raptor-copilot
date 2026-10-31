"""Tests for ``packages.sca.naming`` — the shared name-folding rule.

The PEP 503 rule used to be hand-rolled per module; these tests pin
the shared implementation AND the two deliberately-divergent consumer
boundaries (OSV case-folds Cargo, the registry walk doesn't) so the
divergence stays explicit instead of re-forking the rule.
"""

from __future__ import annotations

from packages.sca.naming import fold_name, pep503_name


def test_pep503_folds_runs_and_lowercases() -> None:
    assert pep503_name("Foo_Bar") == "foo-bar"
    assert pep503_name("zope.interface") == "zope-interface"
    assert pep503_name("a.-_b") == "a-b"
    assert pep503_name("requests") == "requests"


def test_fold_name_pypi_uses_pep503() -> None:
    assert fold_name("Foo_Bar", "PyPI") == "foo-bar"


def test_fold_name_npm_lowercases_preserving_scope() -> None:
    assert fold_name("@Scope/Pkg.Name", "npm") == "@scope/pkg.name"


def test_fold_name_default_is_case_sensitive_passthrough() -> None:
    assert fold_name("MyCrate", "Cargo") == "MyCrate"
    assert fold_name("org.Example", "Maven") == "org.Example"


def test_fold_name_extra_lower_opt_in() -> None:
    assert fold_name("MyCrate", "Cargo", extra_lower=("Cargo",)) == "mycrate"
    # The opt-in never widens to other ecosystems.
    assert fold_name("org.Example", "Maven", extra_lower=("Cargo",)) == "org.Example"


def test_osv_boundary_folds_cargo() -> None:
    """OSV rejects case-variant crates.io names; the boundary opts in."""
    from packages.sca.osv import _canonical_name

    assert _canonical_name("Cargo", "MyCrate") == "mycrate"
    assert _canonical_name("PyPI", "Foo_Bar") == "foo-bar"
    assert _canonical_name("Maven", "org.Example") == "org.Example"


def test_registry_walk_keeps_cargo_case_sensitive() -> None:
    """The registry walk deliberately does NOT fold Cargo — crates.io
    metadata fetches are case-sensitive at registry level."""
    from packages.sca.registry_metadata_walk import _norm_name

    assert _norm_name("MyCrate", "Cargo") == "MyCrate"
    assert _norm_name("Foo_Bar", "PyPI") == "foo-bar"
