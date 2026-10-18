"""IRIS/local-pack install diagnostics and enrichment-health contract."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

import pytest

import core.sandbox
from core.run.safe_io import (
    ARTIFACT_REFERENCE_MAX_BYTES,
    ARTIFACT_REFERENCE_MAX_COUNT,
    ARTIFACT_REFERENCES_MAX_BYTES,
)
from packages.codeql.agent import CodeQLWorkflowResult
from packages.codeql.query_runner import (
    QueryRunner,
    summarize_iris_enrichment_health,
)


@pytest.fixture(autouse=True)
def _raptor_logger_propagates():
    raptor = logging.getLogger("raptor")
    original = raptor.propagate
    raptor.propagate = True
    yield
    raptor.propagate = original


@pytest.fixture()
def runner(tmp_path):
    fake_cli = tmp_path / "codeql"
    fake_cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_cli.chmod(0o755)
    return QueryRunner(codeql_cli=str(fake_cli))


def _sarif_path(cmd: list[str]) -> Path:
    output = next(arg for arg in cmd if str(arg).startswith("--output="))
    return Path(str(output).removeprefix("--output="))


def _write_empty_sarif(cmd: list[str]) -> None:
    _sarif_path(cmd).write_text(
        json.dumps({
            "version": "2.1.0",
            "runs": [{"results": []}],
        }),
        encoding="utf-8",
    )


def _run_local(
    runner: QueryRunner,
    tmp_path: Path,
    *,
    skip_install: bool = False,
):
    pack = tmp_path / "pack"
    pack.mkdir(exist_ok=True)
    return runner._run_local_pack(
        "python",
        tmp_path / "db",
        pack,
        tmp_path / "out",
        suite_name="raptor-iris-local",
        sarif_name="codeql_python_iris.sarif",
        label="IRIS LocalFlowSource",
        skip_install=skip_install,
    )


def test_install_warning_persists_complete_private_sanitized_streams(
    runner, tmp_path, monkeypatch, caplog,
):
    secret = "glpat-AbCdEfGhIjKlMnOpQrStUvWx"
    stdout = "stdout-start\n" + "o" * 700 + "\n\x1b]0;stdout-tail\x07"
    stderr = (
        f"registry output using {secret}\n"
        + "e" * 700
        + "\n\u202estderr-tail"
    )

    def _fake_run(cmd, **_kwargs):
        if cmd[1:3] == ["pack", "install"]:
            return subprocess.CompletedProcess(
                cmd, 2, stdout=stdout, stderr=stderr,
            )
        _write_empty_sarif(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(core.sandbox, "run", _fake_run)
    monkeypatch.setattr(
        "packages.codeql.codeql_proxy_hosts.proxy_hosts_for_codeql",
        lambda _cli: [],
    )

    with caplog.at_level("WARNING", logger="raptor"):
        result = _run_local(runner, tmp_path)

    assert result.success is True
    health = result.enrichment_health
    assert health is not None
    assert health["status"] == "completed"
    assert health["degraded"] is True
    assert health["install"]["status"] == "failed"
    assert health["install"]["returncode"] == 2
    assert health["install"]["diagnostics"]["status"] == "completed"
    assert health["query"]["status"] == "completed"

    artifact = Path(health["install"]["artifact"])
    assert artifact.stat().st_mode & 0o777 == 0o600
    stored = json.loads(artifact.read_text(encoding="utf-8"))
    assert len(stored["stdout"]) > 700
    assert len(stored["stderr"]) > 700
    assert "stdout-tail" in stored["stdout"]
    assert "stderr-tail" in stored["stderr"]
    assert secret not in stored["stderr"]
    assert "[REDACTED]" in stored["stderr"]
    assert "\x1b" not in stored["stdout"]
    assert "\x07" not in stored["stdout"]
    assert "\u202e" not in stored["stderr"]
    assert "\\x1b" in stored["stdout"]
    assert "\\u202e" in stored["stderr"]

    warning = next(
        record.getMessage()
        for record in caplog.records
        if "pack install (python) returned" in record.getMessage()
    )
    assert len(warning) <= 420
    assert secret not in warning
    assert "\x1b" not in warning
    assert "\u202e" not in warning
    assert "\n" not in warning
    assert "stderr-tail" not in warning
    assert len(health["install"]["reason"]) <= 300


def test_install_success_and_skipped_install_have_distinct_health(
    runner, tmp_path, monkeypatch,
):
    commands: list[list[str]] = []

    def _success(cmd, **_kwargs):
        commands.append(list(cmd))
        if cmd[1:3] == ["pack", "install"]:
            return subprocess.CompletedProcess(
                cmd, 0, stdout="already installed\n", stderr="",
            )
        _write_empty_sarif(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(core.sandbox, "run", _success)
    monkeypatch.setattr(
        "packages.codeql.codeql_proxy_hosts.proxy_hosts_for_codeql",
        lambda _cli: [],
    )
    installed = _run_local(runner, tmp_path)

    assert installed.enrichment_health["status"] == "completed"
    assert installed.enrichment_health["degraded"] is False
    assert installed.enrichment_health["install"]["status"] == "completed"
    assert (
        installed.enrichment_health["install"]["diagnostics"]["status"]
        == "completed"
    )

    commands.clear()
    skipped = _run_local(runner, tmp_path, skip_install=True)
    assert skipped.enrichment_health["status"] == "completed"
    assert skipped.enrichment_health["install"]["status"] == "skipped"
    assert skipped.enrichment_health["install"]["attempted"] is False
    assert (
        skipped.enrichment_health["install"]["diagnostics"]["status"]
        == "skipped"
    )
    assert not any(cmd[1:3] == ["pack", "install"] for cmd in commands)


def test_install_warning_and_query_failure_are_both_preserved(
    runner, tmp_path, monkeypatch,
):
    secret = "glpat-ZyXwVuTsRqPoNmLkJiHgFeDc"
    query_stderr = (
        f"query failed \x1b]0;hostile\x07\u202e using {secret}\n"
        + "q" * 700
        + "\nquery-tail"
    )

    def _fake_run(cmd, **_kwargs):
        if cmd[1:3] == ["pack", "install"]:
            return subprocess.CompletedProcess(
                cmd, 2, stdout="", stderr="install rc two",
            )
        return subprocess.CompletedProcess(
            cmd, 7, stdout="query stdout", stderr=query_stderr,
        )

    monkeypatch.setattr(core.sandbox, "run", _fake_run)
    monkeypatch.setattr(
        "packages.codeql.codeql_proxy_hosts.proxy_hosts_for_codeql",
        lambda _cli: [],
    )

    result = _run_local(runner, tmp_path)

    assert result.success is False
    health = result.enrichment_health
    assert health["status"] == "failed"
    assert health["install"]["status"] == "failed"
    assert health["install"]["returncode"] == 2
    assert health["query"]["status"] == "failed"
    assert health["query"]["returncode"] == 7
    assert health["query"]["diagnostics"]["status"] == "completed"
    query_artifact = Path(health["query"]["artifact"])
    assert query_artifact.stat().st_mode & 0o777 == 0o600
    stored = json.loads(query_artifact.read_text(encoding="utf-8"))
    assert stored["stage"] == "query"
    assert len(stored["stderr"]) > 700
    assert "query-tail" in stored["stderr"]
    assert secret not in stored["stderr"]
    assert "[REDACTED]" in stored["stderr"]
    assert "\x1b" not in stored["stderr"]
    assert "\x07" not in stored["stderr"]
    assert "\u202e" not in stored["stderr"]
    assert result.errors
    assert len(result.errors[0]) <= 300
    assert secret not in result.errors[0]
    assert "\x1b" not in result.errors[0]
    assert "\u202e" not in result.errors[0]
    assert "\\x1b" in result.errors[0]
    aggregate = summarize_iris_enrichment_health({"python": result})
    assert aggregate["status"] == "failed"
    assert aggregate["languages"]["python"]["query"]["returncode"] == 7


def test_artifact_write_failure_surfaces_without_rewriting_execution_state(
    runner, tmp_path, monkeypatch, caplog,
):
    def _fake_run(cmd, **_kwargs):
        if cmd[1:3] == ["pack", "install"]:
            return subprocess.CompletedProcess(
                cmd, 2, stdout="install stdout", stderr="install stderr",
            )
        _write_empty_sarif(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(core.sandbox, "run", _fake_run)
    monkeypatch.setattr(
        "packages.codeql.codeql_proxy_hosts.proxy_hosts_for_codeql",
        lambda _cli: [],
    )

    def _fail_persist(*_args, **_kwargs):
        raise PermissionError("read-only diagnostics directory")

    monkeypatch.setattr(
        "packages.codeql.query_runner."
        "_persist_local_pack_install_diagnostics",
        _fail_persist,
    )

    with caplog.at_level("WARNING", logger="raptor"):
        result = _run_local(runner, tmp_path)

    assert result.success is True
    health = result.enrichment_health
    assert health["status"] == "completed"
    assert health["degraded"] is True
    assert health["install"]["status"] == "failed"
    assert health["install"]["returncode"] == 2
    assert health["install"]["diagnostics"]["status"] == "failed"
    assert health["query"]["status"] == "completed"
    assert "diagnostic artifact write failed" in caplog.text
    assert "read-only diagnostics directory" in (
        health["install"]["diagnostics"]["reason"]
    )


def test_query_artifact_write_failure_keeps_query_failure_state(
    runner, tmp_path, monkeypatch, caplog,
):
    def _fail_query(cmd, **_kwargs):
        return subprocess.CompletedProcess(
            cmd,
            7,
            stdout="query stdout",
            stderr="query failed\x1b]0;hostile\x07\u202e",
        )

    monkeypatch.setattr(core.sandbox, "run", _fail_query)

    def _fail_persist(*_args, **_kwargs):
        raise PermissionError("query diagnostics path is read-only")

    monkeypatch.setattr(
        "packages.codeql.query_runner."
        "_persist_local_pack_query_diagnostics",
        _fail_persist,
    )

    with caplog.at_level("WARNING", logger="raptor"):
        result = _run_local(runner, tmp_path, skip_install=True)

    assert result.success is False
    health = result.enrichment_health
    assert health["status"] == "failed"
    assert health["install"]["status"] == "skipped"
    assert health["query"]["status"] == "failed"
    assert health["query"]["returncode"] == 7
    assert health["query"]["diagnostics"]["status"] == "failed"
    assert "query diagnostic artifact write failed" in caplog.text
    assert "query diagnostics path is read-only" in (
        health["query"]["diagnostics"]["reason"]
    )
    assert result.errors
    assert "\x1b" not in result.errors[0]
    assert "\u202e" not in result.errors[0]


def test_workflow_report_serializes_machine_readable_enrichment_health(
    runner, tmp_path, monkeypatch,
):
    def _fake_run(cmd, **_kwargs):
        if cmd[1:3] == ["pack", "install"]:
            return subprocess.CompletedProcess(
                cmd, 2, stdout="", stderr="install warning",
            )
        _write_empty_sarif(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(core.sandbox, "run", _fake_run)
    monkeypatch.setattr(
        "packages.codeql.codeql_proxy_hosts.proxy_hosts_for_codeql",
        lambda _cli: [],
    )
    result = _run_local(runner, tmp_path)
    aggregate = summarize_iris_enrichment_health({"python": result})
    secret = "glpat-QwErTyUiOpAsDfGhJkLzXcVb"
    hostile_refs = [
        (
            f"out/{index}/\x1b]0;artifact\x07/\u202e/{secret}/"
            + "x" * (ARTIFACT_REFERENCE_MAX_BYTES * 2)
        )
        for index in range(ARTIFACT_REFERENCE_MAX_COUNT + 5)
    ]
    aggregate["artifacts"] = hostile_refs
    aggregate["languages"]["python"]["artifacts"] = hostile_refs
    workflow = CodeQLWorkflowResult(
        success=True,
        repo_path="repo",
        timestamp="now",
        duration_seconds=1.0,
        languages_detected={},
        databases_created={},
        analyses_completed={},
        total_findings=0,
        sarif_files=hostile_refs,
        errors=[],
        enrichment_health=aggregate,
    )

    payload = workflow.to_dict()
    assert payload["success"] is True
    assert payload["enrichment_health"]["status"] == "completed"
    assert payload["enrichment_health"]["degraded"] is True
    assert payload["enrichment_health"]["languages"]["python"][
        "install"
    ]["status"] == "failed"
    refs = payload["enrichment_health"]["artifacts"]
    assert len(refs) <= ARTIFACT_REFERENCE_MAX_COUNT
    assert sum(
        len(ref.encode("utf-8")) + (1 if index else 0)
        for index, ref in enumerate(refs)
    ) <= ARTIFACT_REFERENCES_MAX_BYTES
    assert all(
        len(ref.encode("utf-8")) <= ARTIFACT_REFERENCE_MAX_BYTES
        for ref in refs
    )
    assert all("\x1b" not in ref and "\u202e" not in ref for ref in refs)
    assert all(secret not in ref for ref in refs)
    assert payload["enrichment_health"][
        "artifact_references_truncated"
    ] is True
    assert payload["enrichment_health"][
        "artifact_references_omitted"
    ] > 0
    assert len(payload["sarif_files"]) <= ARTIFACT_REFERENCE_MAX_COUNT
    assert payload["sarif_file_references_truncated"] is True
    assert payload["sarif_file_references_omitted"] > 0
