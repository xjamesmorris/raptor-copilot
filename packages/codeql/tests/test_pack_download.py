"""Tests for auto-download of missing CodeQL query packs."""

import subprocess

import core.run.retry
import core.sandbox

from packages.codeql.query_runner import _extract_missing_pack
from packages.codeql.query_runner import QueryRunner


class TestExtractMissingPack:

    def test_standard_error(self):
        stderr = "Query pack codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls cannot be found."
        assert _extract_missing_pack(stderr) == "codeql/javascript-queries"

    def test_with_version(self):
        stderr = "Error: query pack codeql/python-queries@0.9.0 cannot be found"
        assert _extract_missing_pack(stderr) == "codeql/python-queries"

    def test_without_suite(self):
        stderr = "A fatal error occurred: Query pack codeql/cpp-queries cannot be found. Check the spelling of the pack."
        assert _extract_missing_pack(stderr) == "codeql/cpp-queries"

    def test_no_match(self):
        stderr = "Something else went wrong"
        assert _extract_missing_pack(stderr) is None

    def test_wrong_suite_not_matched(self):
        # "Could not read" means the pack exists but the suite path is wrong — don't download
        stderr = 'A fatal error occurred: Could not read /path/to/nonexistent-suite.qls'
        assert _extract_missing_pack(stderr) is None

    def test_empty(self):
        assert _extract_missing_pack("") is None


def test_failed_download_persists_complete_sanitized_stderr(
    tmp_path, monkeypatch,
):
    fake_cli = tmp_path / "codeql"
    fake_cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_cli.chmod(0o755)
    runner = QueryRunner(codeql_cli=str(fake_cli))

    missing_pack = (
        "Query pack codeql/python-queries:"
        "codeql-suites/python-security-and-quality.qls cannot be found."
    )
    secret = "glpat-AbCdEfGhIjKlMnOpQrSt"
    download_stderr = (
        "registry failure\n"
        + "x" * 300
        + f"\nusing {secret}\n\x1b[31mTAIL"
    )

    def _fake_run(cmd, **kwargs):
        stderr = (
            download_stderr
            if cmd[1:3] == ["pack", "download"]
            else missing_pack
        )
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout="", stderr=stderr,
        )

    monkeypatch.setattr(core.sandbox, "run", _fake_run)
    monkeypatch.setattr(
        core.run.retry,
        "retry_call",
        lambda fn, **kwargs: fn(),
    )
    monkeypatch.setattr(
        "packages.codeql.codeql_proxy_hosts.proxy_hosts_for_codeql",
        lambda _cli: [],
    )

    out_dir = tmp_path / "out"
    result = runner.run_suite(tmp_path / "db", "python", out_dir)

    assert result.success is False
    artifact = out_dir / "codeql_python_pack_download.stderr.log"
    stored = artifact.read_text(encoding="utf-8")
    assert artifact.stat().st_mode & 0o777 == 0o600
    assert len(stored) > 200
    assert "TAIL" in stored
    assert secret not in stored
    assert "[REDACTED]" in stored
    assert "\x1b" not in stored
    assert "\\x1b" in stored

    summary = next(
        error for error in result.errors
        if error.startswith("Pack download failed:")
    )
    assert len(summary.removeprefix("Pack download failed: ")) <= 200
    assert "TAIL" not in summary
    assert any(str(artifact) in error for error in result.errors)
