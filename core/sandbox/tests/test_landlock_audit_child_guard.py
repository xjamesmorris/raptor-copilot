"""The Landlock-audit target child never unwinds out of its fork.

The target-child branch performs stdio plumbing (capture dup2s, the
caller's ``stdin=`` mapping, setsid, chdir) after fork. Its inner
stdin handler catches only ``AttributeError``/``OSError`` — a
caller-supplied stdin object whose ``fileno()`` raises ``ValueError``
(a closed file, the realistic mistake) escaped every guard: the
exception unwound the FORKED child through the function's ``finally``
(running ``_cleanup_fds`` + the evidence close in BOTH processes) and
on into the caller's stack — the forked-child-runs-parent-code double
execution the _spawn child guard refuses. The whole child branch must
sit under the ``BaseException`` → ``os._exit`` backstop.

Run in a subprocess: the failure mode under test IS a fork escape, so
a regressed guard must corrupt only the disposable probe interpreter.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Landlock-audit spawn path is Linux-only",
)

_REPO = Path(__file__).resolve().parents[3]

# The probe records survivors in a FILE (O_APPEND, one pid per
# line), not on stdout: the escape fires after the child has already
# dup2'd the capture pipe over fd 1, so an escaped child's prints
# vanish into the drained capture buffer — the marker file is shared
# and shows every process that ran the post-call code.
_PROBE = """
import os, sys, tempfile
from core.sandbox import _landlock_audit as mod
from core.sandbox.ptrace_probe import check_ptrace_available
from core.sandbox.seccomp import check_seccomp_available

if not (check_ptrace_available() and check_seccomp_available()):
    print("SKIP-NO-PTRACE")
    sys.exit(0)

marker = sys.argv[1]
hostile = tempfile.TemporaryFile()
hostile.close()  # fileno() now raises ValueError in the forked child

run_dir = tempfile.mkdtemp()
try:
    result = mod.run_landlock_audit(
        [sys.executable, "-c", "print('ran')"],
        audit_run_dir=run_dir,
        env={"PATH": "/usr/bin:/bin"},
        stdin=hostile,
        capture_output=True, text=True, timeout=60,
    )
    print(f"RC:{result.returncode}")
except BaseException as e:  # noqa: BLE001 — diagnostic probe
    print(f"RAISED:{type(e).__name__}:{e}")
with open(marker, "a") as f:
    f.write(f"{os.getpid()}\\n")
"""


def test_bad_stdin_fails_as_exit_code_without_child_escape(tmp_path):
    marker = tmp_path / "survivors"
    r = subprocess.run(
        [sys.executable, "-c", _PROBE, str(marker)],
        capture_output=True, text=True, timeout=120,
        cwd=_REPO, env={**os.environ},
    )
    if "SKIP-NO-PTRACE" in r.stdout:
        pytest.skip("ptrace/libseccomp unavailable")
    survivors = (marker.read_text().splitlines()
                 if marker.exists() else [])
    assert len(survivors) == 1, (
        f"forked target child escaped the setup guard "
        f"(survivor pids: {survivors}):\n"
        f"stdout={r.stdout}\nstderr={r.stderr}"
    )
    # The failure surfaces in ONE process, as either the child's
    # setup exit code (125) or — because the guarded child dies
    # before the tracer can SEIZE it — the parent's typed
    # tracer-attach error. Never as an exception unwinding BOTH
    # processes (which the single survivor line above pins).
    assert ("RC:125" in r.stdout
            or "RAISED:RuntimeError" in r.stdout), (
        f"expected a single-process failure shape:\n"
        f"stdout={r.stdout}\nstderr={r.stderr}"
    )
    assert r.returncode == 0, r.stderr[-500:]
