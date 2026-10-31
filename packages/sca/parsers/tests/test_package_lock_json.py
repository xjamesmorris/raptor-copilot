"""Tests for the package-lock.json parser (npm v1, v2, v3)."""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.package_lock_json import parse


def _write(tmp_path: Path, body: dict) -> Path:
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps(body), encoding="utf-8")
    return p


def test_v3_packages_map_root_and_node_modules(tmp_path: Path) -> None:
    body = {
        "name": "demo",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "demo",
                "version": "1.0.0",
                "dependencies":     {"lodash": "^4.17.21"},
                "devDependencies":  {"jest": "~29.0.0"},
            },
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                "integrity": "sha512-x",
            },
            "node_modules/jest": {
                "version": "29.0.3",
                "dev": True,
            },
            "node_modules/@types/node": {
                "version": "20.10.5",
                "dev": True,
            },
        },
    }
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    assert deps["lodash"].version == "4.17.21"
    assert deps["lodash"].direct is True
    assert deps["lodash"].scope == "main"
    assert deps["jest"].direct is True
    assert deps["jest"].scope == "dev"
    # @types/node is transitive — not in root deps.
    assert deps["@types/node"].direct is False


def test_v3_workspace_link_skipped(tmp_path: Path) -> None:
    body = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {}},
            "packages/inner": {"link": True, "version": "1.0"},
            "node_modules/inner": {
                "resolved": "packages/inner",
                "version": "1.0",
                "link": True,
            },
        },
    }
    deps = parse(_write(tmp_path, body))
    # Both link entries are skipped.
    assert deps == []


def test_v2_falls_back_to_packages_when_present(tmp_path: Path) -> None:
    body = {
        "lockfileVersion": 2,
        "packages": {
            "": {"dependencies": {"a": "^1"}},
            "node_modules/a": {"version": "1.2.3"},
        },
        "dependencies": {
            # The legacy tree is also present in v2 — must NOT be
            # double-counted; we prefer "packages".
            "a": {"version": "1.2.3"},
        },
    }
    deps = parse(_write(tmp_path, body))
    assert len(deps) == 1
    assert deps[0].name == "a"
    assert deps[0].direct is True


def test_v1_legacy_tree(tmp_path: Path) -> None:
    body = {
        "lockfileVersion": 1,
        "dependencies": {
            "lodash": {
                "version": "4.17.21",
                "resolved": "https://registry.npmjs.org/lodash",
            },
            "jest": {
                "version": "29.0.3",
                "dev": True,
                "dependencies": {
                    "deep-dep": {"version": "0.0.1", "dev": True},
                },
            },
        },
    }
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    assert deps["lodash"].direct is True
    assert deps["lodash"].scope == "main"
    assert deps["jest"].scope == "dev"
    assert deps["deep-dep"].direct is False
    assert deps["deep-dep"].scope == "dev"


def test_git_resolved_url_classified(tmp_path: Path) -> None:
    body = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"x": "github:u/x"}},
            "node_modules/x": {
                "version": "0.0.0",
                "resolved": "git+https://github.com/u/x.git#abc123",
            },
        },
    }
    deps = parse(_write(tmp_path, body))
    assert deps[0].pin_style is PinStyle.GIT


def test_invalid_json_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "package-lock.json"
    p.write_text("{ broken", encoding="utf-8")
    assert parse(p) == []


# ---------------------------------------------------------------------------
# npm aliases (``"my-lodash": "npm:lodash@^4"``) resolve to the
# installed package; the alias spelling survives in ``alias_name``
# ---------------------------------------------------------------------------

def test_v3_alias_records_real_package(tmp_path: Path) -> None:
    # npm keys the packages map by install folder (the ALIAS) and
    # writes the real package in the entry's ``name`` field.
    body = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"my-lodash": "npm:lodash@^4.17.0"}},
            "node_modules/my-lodash": {
                "name": "lodash",
                "version": "4.17.4",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz",
            },
        },
    }
    [d] = parse(_write(tmp_path, body))
    assert d.name == "lodash"
    assert d.alias_name == "my-lodash"
    assert d.version == "4.17.4"
    assert d.purl == "pkg:npm/lodash@4.17.4"
    # Declared under the alias in the root manifest echo → direct.
    assert d.direct is True


def test_v3_alias_without_name_field_uses_root_targets(tmp_path: Path) -> None:
    # Defensive: a lockfile that omits the per-entry ``name`` still
    # resolves the alias through the root manifest echo.
    body = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"my-lodash": "npm:lodash@^4.17.0"}},
            "node_modules/my-lodash": {"version": "4.17.4"},
        },
    }
    [d] = parse(_write(tmp_path, body))
    assert d.name == "lodash"
    assert d.alias_name == "my-lodash"
    assert d.direct is True


def test_v1_alias_version_string_resolves_real_package(tmp_path: Path) -> None:
    # v1 records an aliased install as version="npm:<real>@<version>" —
    # previously the alias became the name and the ``npm:…`` string the
    # version, hiding the installed package's advisories AND poisoning
    # the version field.
    body = {
        "lockfileVersion": 1,
        "dependencies": {
            "my-lodash": {"version": "npm:lodash@4.17.4"},
            "ms": {"version": "2.1.3"},
        },
    }
    deps = {d.name: d for d in parse(_write(tmp_path, body))}
    assert set(deps) == {"lodash", "ms"}
    d = deps["lodash"]
    assert d.alias_name == "my-lodash"
    assert d.version == "4.17.4"
    assert d.pin_style is PinStyle.EXACT
    assert d.direct is True
    # Non-aliased sibling untouched.
    assert deps["ms"].alias_name is None
    assert deps["ms"].version == "2.1.3"


def test_v3_non_aliased_rows_unchanged(tmp_path: Path) -> None:
    body = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"lodash": "^4.17.21"}},
            "node_modules/lodash": {"version": "4.17.21"},
        },
    }
    [d] = parse(_write(tmp_path, body))
    assert d.name == "lodash"
    assert d.alias_name is None
    assert d.direct is True


def test_v3_root_alias_does_not_rename_nested_real_package(
    tmp_path: Path,
) -> None:
    # The root aliases the LOCAL NAME "ms" to lodash, but a REAL ms is
    # nested under a dependent (npm omits the per-entry name when it
    # equals the folder). The nested row must stay ms — renaming it
    # would invent lodash findings for a package that isn't installed
    # AND hide ms's advisories.
    body = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"ms": "npm:lodash@^4.17.0",
                                  "a": "^1.0.0"}},
            "node_modules/ms": {"name": "lodash", "version": "4.17.21"},
            "node_modules/a": {"version": "1.0.0"},
            "node_modules/a/node_modules/ms": {"version": "2.1.3"},
        },
    }
    deps = {(d.name, d.version): d for d in parse(_write(tmp_path, body))}
    assert ("lodash", "4.17.21") in deps
    assert deps[("lodash", "4.17.21")].alias_name == "ms"
    nested = deps[("ms", "2.1.3")]
    assert nested.alias_name is None
    assert nested.direct is False
