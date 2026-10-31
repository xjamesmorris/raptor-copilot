"""npm-alias advisory false-negative regression (end-to-end).

A LOCKFILE-LESS project that declares a dep through an npm alias
(``"my-lodash": "npm:lodash@4.17.4"``) installs the REAL package —
lodash — so lodash's advisories apply. OSV queries key on
``Dependency.name``; recording the alias spelling as the name made the
pipeline query OSV for ``my-lodash`` and silently miss every advisory
against the installed package: a real advisory false negative.

Exercises the full mechanical path — discovery → parse → join →
OSV query → finding assembly — with an in-process fake HTTP client
that only answers for the REAL package, exactly like OSV would.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.http import HttpError
from core.json import JsonCache
from packages.sca.discovery import find_manifests
from packages.sca.findings import build_vuln_findings
from packages.sca.join import join
from packages.sca.osv import OSV_VULN_URL_TEMPLATE, OsvClient
from packages.sca.parsers import parse_manifest

_ADVISORY_ID = "GHSA-jf85-cpcp-j695"

# Real-shaped OSV record for lodash < 4.17.5 (prototype pollution).
_LODASH_RECORD: dict[str, Any] = {
    "id": _ADVISORY_ID,
    "modified": "2024-01-01T00:00:00Z",
    "published": "2018-07-26T00:00:00Z",
    "aliases": ["CVE-2018-3721"],
    "summary": "Prototype Pollution in lodash",
    "details": "Versions of lodash before 4.17.5 are vulnerable.",
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [
                {"type": "SEMVER",
                 "events": [{"introduced": "0"}, {"fixed": "4.17.5"}]},
            ],
        },
    ],
    "severity": [],
    "references": [],
}


class _OsvShapedHttp:
    """Answers ``/querybatch`` the way OSV does: advisories exist for
    the INSTALLED package name only — an alias-name query finds
    nothing."""

    def __init__(self) -> None:
        self.queried_names: list[str] = []

    def post_json(self, url: str, body: dict, timeout: int = 30) -> dict:
        results = []
        for q in body.get("queries", []):
            name = (q.get("package") or {}).get("name", "")
            self.queried_names.append(name)
            if name == "lodash":
                results.append({"vulns": [{"id": _ADVISORY_ID}]})
            else:
                results.append({})
        return {"results": results}

    def get_json(self, url: str, timeout: int = 30) -> dict:
        if url == OSV_VULN_URL_TEMPLATE.format(_ADVISORY_ID):
            return _LODASH_RECORD
        raise HttpError(f"unknown URL in fake: {url}", status=404)

    def get_bytes(self, url: str, timeout: int = 30,
                  max_bytes: int = 0) -> bytes:
        raise NotImplementedError


def test_lockfileless_alias_still_finds_real_packages_advisory(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(json.dumps({
        "name": "demo",
        "dependencies": {"my-lodash": "npm:lodash@4.17.4"},
    }), encoding="utf-8")

    deps = []
    for m in find_manifests(repo):
        deps.extend(parse_manifest(m))
    deps = join(deps)
    assert len(deps) == 1

    http = _OsvShapedHttp()
    client = OsvClient(http, JsonCache(root=tmp_path / "cache"))
    results = client.query_batch(deps)
    findings = build_vuln_findings(deps, results)

    # The installed package's advisory must surface. Pre-fix the
    # pipeline queried OSV for the ALIAS name and produced zero
    # findings — the false negative this test pins.
    assert "lodash" in http.queried_names
    assert len(findings) == 1
    f = findings[0]
    assert f.dependency.name == "lodash"
    assert f.dependency.alias_name == "my-lodash"
    assert f.advisories[0].osv_id == _ADVISORY_ID
    # The manifest spelling is preserved for display / fix paths.
    row_manifest = f.dependency.declared_in
    assert Path(row_manifest).name == "package.json"
