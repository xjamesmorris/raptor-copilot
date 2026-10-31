"""Tests for ``packages.sca.supply_chain._own_host``."""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import Manifest
from packages.sca.supply_chain._own_host import (
    own_name_version,
    resolve_own_host,
)


def _manifest(p: Path, ecosystem: str) -> Manifest:
    return Manifest(path=p, ecosystem=ecosystem, is_lockfile=False)


def test_package_json_name_and_version(tmp_path: Path) -> None:
    p = tmp_path / "package.json"
    p.write_text(json.dumps({"name": "x", "version": "1.2.3"}))
    assert own_name_version(_manifest(p, "npm")) == ("x", "1.2.3")


def test_pyproject_poetry_fallback(tmp_path: Path) -> None:
    p = tmp_path / "pyproject.toml"
    p.write_text("[tool.poetry]\nname = 'x'\nversion = '0.1'\n")
    assert own_name_version(_manifest(p, "PyPI")) == ("x", "0.1")


def test_pypi_manifest_consults_sibling_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n")
    assert own_name_version(_manifest(req, "PyPI")) == ("x", None)


def test_cargo_workspace_inherited_version_is_none(tmp_path: Path) -> None:
    p = tmp_path / "Cargo.toml"
    p.write_text(
        '[package]\nname = "x"\nversion.workspace = true\n')
    assert own_name_version(_manifest(p, "Cargo")) == ("x", None)


def test_gemfile_consults_sibling_gemspec(tmp_path: Path) -> None:
    (tmp_path / "x.gemspec").write_text(
        'Gem::Specification.new { |s| s.name = "x" }\n')
    gf = tmp_path / "Gemfile"
    gf.write_text('source "https://rubygems.org"\n')
    assert own_name_version(_manifest(gf, "RubyGems")) == ("x", None)


def test_gemspec_interpolated_name_stays_unresolved(tmp_path: Path) -> None:
    """Computed names are never guessed — placeholder host instead."""
    p = tmp_path / "x.gemspec"
    p.write_text('Gem::Specification.new { |s| s.name = base + "-rt" }\n')
    assert own_name_version(_manifest(p, "RubyGems")) == (None, None)


def test_malformed_manifest_yields_placeholder(tmp_path: Path) -> None:
    p = tmp_path / "package.json"
    p.write_text("{ broken")
    host = resolve_own_host(
        _manifest(p, "npm"), reason="t", placeholder_name="<pkg>",
    )
    assert host.name == "<pkg>"
    assert host.declared_in == p
    assert host.parser_confidence.level == "low"


def test_resolved_host_is_high_confidence(tmp_path: Path) -> None:
    p = tmp_path / "package.json"
    p.write_text(json.dumps({"name": "x", "version": "1.0.0"}))
    host = resolve_own_host(_manifest(p, "npm"), reason="t")
    assert host.name == "x"
    assert host.version == "1.0.0"
    assert host.declared_in == p
    assert host.parser_confidence.level == "high"


def test_symlinked_manifest_refused(tmp_path: Path) -> None:
    """Own-name resolution reads through the bounded reader — a
    symlinked manifest is refused, yielding the placeholder."""
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"name": "leak"}))
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    link = hostile / "package.json"
    link.symlink_to(outside)
    host = resolve_own_host(_manifest(link, "npm"), reason="t")
    assert host.name == "<project>"
