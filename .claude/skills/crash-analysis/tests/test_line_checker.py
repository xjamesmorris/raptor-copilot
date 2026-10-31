"""Compile-and-run regression tests for the line-execution-checker.

The gcov parser used whitespace-token extraction (``iss >> count >>
c1 >> line >> c2``) against gcov's real ``%9s:%5d:%s`` layout, where
the colon is attached to the padded field — every real line failed
the ``c1 == ':'`` sanity check, so executed lines were reported as
Not Executed. These tests generate real coverage with gcc/gcov and
assert the checker's verdict against it.

Hermetic: skipped when g++/gcc/gcov are absent; everything runs in
pytest temp dirs.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parents[1]
CHECKER_SRC = SKILL_DIR / "line-execution-checker" / "line_checker.cpp"

pytestmark = pytest.mark.skipif(
    not (shutil.which("g++") and shutil.which("gcc") and shutil.which("gcov")),
    reason="g++/gcc/gcov toolchain required",
)

# One executed branch, one not: run with no argv → the else arm runs.
_TEST_SRC = """\
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc > 1) {
        puts("taken");
    } else {
        puts("not taken");
    }
    return 0;
}
"""


def _line_of(marker: str) -> int:
    for i, line in enumerate(_TEST_SRC.splitlines(), start=1):
        if marker in line:
            return i
    raise AssertionError(f"marker {marker!r} not in test source")


EXECUTED_LINE = _line_of('puts("not taken")')
UNEXECUTED_LINE = _line_of('puts("taken")')


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=120,
        check=False,
    )


@pytest.fixture(scope="module")
def checker(tmp_path_factory) -> Path:
    build = tmp_path_factory.mktemp("line-checker-build")
    exe = build / "line-checker"
    proc = _run(
        ["g++", "-O2", "-std=c++17", str(CHECKER_SRC), "-o", str(exe)],
        build,
    )
    assert proc.returncode == 0, f"checker build failed:\n{proc.stderr}"
    return exe


@pytest.fixture(scope="module")
def coverage_dir(tmp_path_factory) -> Path:
    """Directory holding a real .gcov produced by gcc --coverage."""
    d = tmp_path_factory.mktemp("coverage")
    (d / "lc_test.c").write_text(_TEST_SRC, encoding="utf-8")
    for cmd in (
        ["gcc", "--coverage", "-O0", "lc_test.c", "-o", "lc_test"],
        ["./lc_test"],
        ["gcov", "lc_test.c"],
    ):
        proc = _run(cmd, d)
        assert proc.returncode == 0, f"{cmd} failed:\n{proc.stderr}"
    assert (d / "lc_test.c.gcov").is_file()
    return d


class TestVerdictAgainstRealGcov:
    def test_executed_line_reports_executed(self, checker, coverage_dir):
        proc = _run([str(checker), f"lc_test.c:{EXECUTED_LINE}"], coverage_dir)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "EXECUTED (1 time)" in proc.stdout
        assert "NOT EXECUTED" not in proc.stdout

    def test_unexecuted_line_reports_not_executed(self, checker, coverage_dir):
        proc = _run(
            [str(checker), f"lc_test.c:{UNEXECUTED_LINE}"], coverage_dir,
        )
        assert proc.returncode == 1
        assert "NOT EXECUTED" in proc.stdout

    def test_gcov_regenerated_without_shell(self, checker, tmp_path):
        """With .gcda/.gcno present but no .gcov, the checker invokes
        gcov itself (argv array, no shell) and still answers."""
        (tmp_path / "lc_test.c").write_text(_TEST_SRC, encoding="utf-8")
        for cmd in (
            ["gcc", "--coverage", "-O0", "lc_test.c", "-o", "lc_test"],
            ["./lc_test"],
        ):
            proc = _run(cmd, tmp_path)
            assert proc.returncode == 0, f"{cmd} failed:\n{proc.stderr}"
        assert not (tmp_path / "lc_test.c.gcov").exists()

        proc = _run([str(checker), f"lc_test.c:{EXECUTED_LINE}"], tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "EXECUTED (1 time)" in proc.stdout

    def test_mixed_queries_exit_nonzero(self, checker, coverage_dir):
        proc = _run(
            [
                str(checker),
                f"lc_test.c:{EXECUTED_LINE}",
                f"lc_test.c:{UNEXECUTED_LINE}",
            ],
            coverage_dir,
        )
        assert proc.returncode == 1
        assert f"lc_test.c:{EXECUTED_LINE} EXECUTED" in proc.stdout
        assert f"lc_test.c:{UNEXECUTED_LINE} NOT EXECUTED" in proc.stdout


class TestNoShellInjection:
    def test_shell_metacharacters_never_execute(self, checker, tmp_path):
        """A query file name is attacker-shaped (bug-tracker derived).
        The old ``system("gcov " + source_file + ...)`` executed shell
        payloads embedded in it; the argv-array replacement must not.
        """
        payload = "x;touch PWNED"  # becomes the file part of file:line
        proc = _run([str(checker), f"{payload}:1"], tmp_path)
        assert proc.returncode == 2  # no coverage data — refused, not executed
        assert not (tmp_path / "PWNED").exists()

    def test_option_shaped_source_not_passed_to_gcov(self, checker, tmp_path):
        proc = _run([str(checker), "--object-directory=/tmp:1"], tmp_path)
        assert proc.returncode == 2
        assert "No coverage data" in proc.stderr
