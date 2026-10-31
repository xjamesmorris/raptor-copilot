"""read_vulnerable_code: containment + capped read of SARIF-located source."""

from __future__ import annotations

import logging
from pathlib import Path

from packages.codeql.autonomous_analyzer import (
    AutonomousCodeQLAnalyzer,
    CodeQLFinding,
)


def _make_analyzer() -> AutonomousCodeQLAnalyzer:
    a = AutonomousCodeQLAnalyzer.__new__(AutonomousCodeQLAnalyzer)
    a.logger = logging.getLogger("test-read-vulnerable-code")
    return a


def _finding(file_path: str, line: int) -> CodeQLFinding:
    return CodeQLFinding(
        rule_id="cpp/test-rule", rule_name="t", message="m",
        level="warning", file_path=file_path, start_line=line,
        end_line=line, snippet="SNIPPET-FALLBACK",
    )


def test_within_cap_reads_marked_context(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.c").write_text(
        "\n".join(f"line{i}" for i in range(1, 30)) + "\n",
        encoding="utf-8",
    )
    out = _make_analyzer().read_vulnerable_code(
        _finding("a.c", 10), repo, context_lines=2,
    )
    assert ">>>" in out
    assert "line10" in out and "line8" in out and "line12" in out
    assert "line20" not in out


def test_out_of_tree_path_degrades_to_snippet(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (tmp_path / "outside.c").write_text("secret\n", encoding="utf-8")
    out = _make_analyzer().read_vulnerable_code(
        _finding("../outside.c", 1), repo,
    )
    assert out == "SNIPPET-FALLBACK"


def test_read_is_capped_for_pathological_files(tmp_path: Path) -> None:
    """The read must be bounded: pre-fix ``readlines()`` loaded the
    whole file, so a finding pointing past the 10 MB cap still quoted
    its real source lines. Post-fix the capped read cannot reach them
    (the truncation is logged); the untruncated in-cap window keeps
    working (asserted above)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    line = "x" * 99 + "\n"  # 100 bytes per line
    n_lines = 115_000  # ~11.5 MB, past the 10 MB cap
    with (repo / "gen.c").open("w", encoding="utf-8") as f:
        for _ in range(n_lines - 1):
            f.write(line)
        f.write("NEEDLE-PAST-CAP\n")
    out = _make_analyzer().read_vulnerable_code(
        _finding("gen.c", n_lines), repo, context_lines=2,
    )
    assert "NEEDLE-PAST-CAP" not in out
