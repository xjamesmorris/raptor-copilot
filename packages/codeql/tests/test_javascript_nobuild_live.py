"""Focused live regression for CodeQL JavaScript no-build extraction.

This is deliberately slow and opt-in. It uses the locally installed CodeQL
bundle only: no network, package-manager install, or target build script.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from core.coverage.record import build_from_codeql
from packages.codeql import _resolve_cli
from packages.codeql.agent import CodeQLAgent
from packages.codeql.query_runner import QueryRunner


pytestmark = pytest.mark.slow


def _tree_snapshot(root: Path) -> dict[str, tuple[str, int, str]]:
    snapshot = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = path.stat().st_mode & 0o777
        if path.is_dir():
            snapshot[relative] = ("dir", mode, "")
        else:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            snapshot[relative] = ("file", mode, digest)
    return snapshot


def _write_fixture(target: Path) -> Path:
    target.mkdir(parents=True)
    source = target / "src" / "index.js"
    source.parent.mkdir()
    source.write_text(
        "function mvp03Witness(value) {\n"
        "  return value;\n"
        "}\n"
        "mvp03Witness('extracted');\n",
        encoding="utf-8",
    )
    (target / "package.json").write_text(
        json.dumps(
            {
                "name": "mvp03-codeql-js-nobuild",
                "private": True,
                "scripts": {
                    "preinstall": "printf preinstall > mvp03-lifecycle-ran",
                    "install": "printf install > mvp03-lifecycle-ran",
                    "prepare": "printf prepare > mvp03-lifecycle-ran",
                    "test": "printf test > mvp03-test-ran",
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    # If the pre-fix npm/yarn/pnpm route is selected, fail immediately.
    # The canaries live inside the read-only target mount so the test does
    # not grant repository code any additional writable path.
    canary_bin = target / "canary-bin"
    canary_bin.mkdir()
    for manager in ("npm", "yarn", "pnpm"):
        shim = canary_bin / manager
        shim.write_text(
            "#!/bin/sh\n"
            f"echo 'MVP03 package manager invoked: {manager}' >&2\n"
            "exit 97\n",
            encoding="utf-8",
        )
        shim.chmod(0o555)
    return source


def _write_positive_query(pack: Path) -> None:
    pack.mkdir(parents=True)
    (pack / "qlpack.yml").write_text(
        "name: raptor/mvp03-javascript-nobuild-test\n"
        "version: 0.0.0\n"
        "dependencies:\n"
        '  codeql/javascript-all: "*"\n',
        encoding="utf-8",
    )
    (pack / "Mvp03Witness.ql").write_text(
        "/**\n"
        " * @name MVP-03 JavaScript extraction witness\n"
        " * @description Proves the fixture source reached a queryable DB.\n"
        " * @kind problem\n"
        " * @problem.severity warning\n"
        " * @precision very-high\n"
        " * @id raptor/test/mvp03-javascript-nobuild\n"
        " */\n"
        "import javascript\n"
        "\n"
        "from Function f\n"
        'where f.getName() = "mvp03Witness"\n'
        'select f, "MVP-03 extracted this JavaScript function."\n',
        encoding="utf-8",
    )


class _FocusedQueryRunner:
    """Run one deterministic local query instead of the full suite."""

    def __init__(self, codeql_cli: str, query_pack: Path) -> None:
        self._runner = QueryRunner(codeql_cli=codeql_cli)
        self._query_pack = query_pack
        self.additional_model_packs = {}

    def analyze_all_databases(
        self, databases, out_dir, use_extended=False, max_workers=None,
    ):
        del use_extended, max_workers
        return {
            language: self._runner.run_custom_queries(
                database, self._query_pack, out_dir, language,
            )
            for language, database in databases.items()
        }

    @staticmethod
    def analyze_iris_packs(databases, out_dir, max_workers=None):
        del databases, out_dir, max_workers
        return {}

    @staticmethod
    def analyze_curated_packs(databases, out_dir, max_workers=None):
        del databases, out_dir, max_workers
        return {}

    @staticmethod
    def active_threat_models():
        return ()


def test_javascript_fixture_extracts_and_queries_without_package_manager(
    tmp_path: Path, monkeypatch,
):
    codeql_cli = _resolve_cli()
    if not codeql_cli:
        pytest.skip("CodeQL CLI is not installed")

    target = (tmp_path / "mvp03-js-nobuild-live-target").resolve()
    output = (tmp_path / "mvp03-js-nobuild-live-output").resolve()
    database_root = (tmp_path / "mvp03-js-nobuild-live-databases").resolve()
    query_pack = (tmp_path / "mvp03-js-nobuild-live-query").resolve()
    source = _write_fixture(target)
    _write_positive_query(query_pack)
    database_root.mkdir()

    before = _tree_snapshot(target)
    canary_bin = target / "canary-bin"
    monkeypatch.setenv(
        "PATH",
        os.pathsep.join((str(canary_bin), os.environ.get("PATH", ""))),
    )

    from core import sandbox as sandbox_module

    real_sandbox_run = sandbox_module.run
    create_calls = []
    analyze_calls = []

    def recording_sandbox_run(cmd, *args, **kwargs):
        command = [str(part) for part in cmd]
        if "database" in command and "create" in command:
            create_calls.append((command, dict(kwargs)))
        elif "database" in command and "analyze" in command:
            analyze_calls.append((command, dict(kwargs)))
        return real_sandbox_run(cmd, *args, **kwargs)

    monkeypatch.setattr(sandbox_module, "run", recording_sandbox_run)

    agent = CodeQLAgent(target, out_dir=output, codeql_cli=codeql_cli)
    agent.database_manager.db_root = database_root
    agent.query_runner = _FocusedQueryRunner(codeql_cli, query_pack)
    monkeypatch.setattr(
        agent, "_run_source_summaries_pass", lambda _databases: None,
    )
    monkeypatch.setattr(
        agent, "_run_taint_pack_models_pass", lambda _databases: None,
    )
    monkeypatch.setattr(
        agent, "_run_learned_models_pass", lambda _databases: {},
    )

    from core.sage import hooks as sage_hooks

    monkeypatch.setattr(
        sage_hooks, "recall_context_for_codeql_build", lambda *_args: [],
    )

    result = agent.run_autonomous_analysis(languages=["js"])

    assert result.success, result.errors
    assert result.total_findings == 1
    assert set(result.databases_created) == {"javascript"}
    database_result = result.databases_created["javascript"]
    assert database_result.success
    assert not database_result.cached
    assert database_result.metadata.build_system == "no-build"
    assert database_result.metadata.build_command == ""

    assert len(create_calls) == 1
    create_command, create_kwargs = create_calls[0]
    assert "--command" not in create_command
    assert "--build-mode=none" not in create_command
    assert Path(create_kwargs["target"]).resolve() == target
    assert Path(create_kwargs["output"]).resolve().is_relative_to(database_root)
    assert create_kwargs["block_network"] is True

    assert len(analyze_calls) == 1
    assert analyze_calls[0][1]["block_network"] is True

    assert _tree_snapshot(target) == before
    assert not (target / "package-lock.json").exists()
    assert not (target / "yarn.lock").exists()
    assert not (target / "pnpm-lock.yaml").exists()
    assert not (target / "node_modules").exists()
    assert not (target / "mvp03-lifecycle-ran").exists()
    assert not (target / "mvp03-test-ran").exists()

    assert len(result.sarif_files) == 1
    coverage = build_from_codeql(Path(result.sarif_files[0]))
    assert coverage is not None
    assert any(
        Path(path).name == source.name
        for path in coverage["files_examined"]
    )
