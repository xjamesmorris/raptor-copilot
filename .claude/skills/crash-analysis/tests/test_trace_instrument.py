"""Compile smoke test for the function-tracing instrumentation library.

``static pid_t gettid(void)`` collided with the ``gettid()`` glibc
2.30+ declares in unistd.h under ``_GNU_SOURCE``, so the documented
build (step 1 of the skill) failed on any modern Linux. Pin the two
documented build commands.

Hermetic: skipped when gcc is absent; builds in a pytest temp dir.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SKILL_DIR = Path(__file__).resolve().parents[1]
TRACER_SRC = SKILL_DIR / "function-tracing" / "trace_instrument.c"

pytestmark = pytest.mark.skipif(
    shutil.which("gcc") is None, reason="gcc required",
)


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=120,
        check=False,
    )


def test_documented_build_commands_succeed(tmp_path: Path) -> None:
    obj = tmp_path / "trace_instrument.o"
    proc = _run(
        ["gcc", "-c", "-fPIC", str(TRACER_SRC), "-o", str(obj)], tmp_path,
    )
    assert proc.returncode == 0, f"compile failed:\n{proc.stderr}"

    lib = tmp_path / "libtrace.so"
    proc = _run(
        ["gcc", "-shared", str(obj), "-o", str(lib), "-ldl", "-lpthread"],
        tmp_path,
    )
    assert proc.returncode == 0, f"link failed:\n{proc.stderr}"
    assert lib.is_file()
