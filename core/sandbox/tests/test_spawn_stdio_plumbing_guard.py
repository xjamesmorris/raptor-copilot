"""A bad stdout=/stderr= argument must never unwind the forked child.

The mount-ns child performs its stdio plumbing (dup2 of the caller's
stdout=/stderr=/stdin= arguments) between fork and exec. A hostile or
buggy caller argument — a closed file object, an object without a
usable ``fileno()``, an invalid fd int — raises INSIDE the forked
child. Without the ``os._exit`` backstop, that exception unwinds the
caller's stack in BOTH processes: the orchestrator's finally handlers
(proxy unregister, evidence close, run-lifecycle writes) execute
twice, and under pytest the escaped child re-runs the remainder of
the test session. The plumbing must sit inside the same
``BaseException`` guard as the rest of child setup, so the failure
becomes a status-pipe category + ``os._exit(126)`` and the parent
raises one typed :class:`SandboxSetupError` naming the real cause.

Run in a subprocess: the failure mode under test IS a fork escape, so
a regressed guard must corrupt only the disposable child interpreter,
never this pytest process.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="mount-ns backend is Linux-only",
)

_REPO = Path(__file__).resolve().parents[3]

# The probe records its pid, calls run_sandboxed with a stdout=
# argument whose fileno() raises (a closed file — the realistic
# caller mistake), and prints one REACHED:<pid> marker afterwards.
# If the forked child escapes the plumbing failure, it too reaches
# the marker (and the except clause) — two REACHED lines with
# different pids — which is exactly the double-execution defect.
_PROBE = """
import os, sys, tempfile
from core.sandbox import _spawn
from core.sandbox.errors import SandboxSetupError

if not _spawn.mount_ns_available():
    print("SKIP-NO-MOUNT-NS")
    sys.exit(0)

hostile = tempfile.TemporaryFile()
hostile.close()  # fileno() now raises ValueError in the forked child

try:
    _spawn.run_sandboxed(
        ["/usr/bin/true"],
        target=None, output=None,
        writable_paths=[], readable_paths=None,
        allowed_tcp_ports=None,
        block_network=True, nproc_limit=1024,
        limits={"memory_mb": 0, "max_file_mb": 10240,
                "cpu_seconds": 300},
        seccomp_profile="full", seccomp_block_udp=False,
        env=None, cwd=None, timeout=30,
        capture_output=False, text=True,
        stdout=hostile,
    )
except SandboxSetupError as e:
    print(f"TYPED:{e.setup_category}:{e}")
except BaseException as e:  # noqa: BLE001 — diagnostic probe
    print(f"UNTYPED:{type(e).__name__}:{e}")
print(f"REACHED:{os.getpid()}")
"""


def test_bad_stdout_redirect_fails_typed_without_child_escape():
    r = subprocess.run(
        [sys.executable, "-c", _PROBE],
        capture_output=True, text=True, timeout=120,
        cwd=_REPO, env={**os.environ},
    )
    if "SKIP-NO-MOUNT-NS" in r.stdout:
        pytest.skip("mount-ns not available on this host")
    reached = [ln for ln in r.stdout.splitlines()
               if ln.startswith("REACHED:")]
    # Exactly one process may survive the plumbing failure: the
    # parent. Two markers = the forked child escaped its guard and
    # re-ran the caller's code.
    assert len(reached) == 1, (
        f"forked child escaped the stdio-plumbing guard:\n"
        f"stdout={r.stdout}\nstderr={r.stderr}"
    )
    # The parent surfaces the real cause as the typed setup error
    # (category 'U', pre-mount step), not a bare no-ready-signal
    # mis-diagnosis.
    typed = [ln for ln in r.stdout.splitlines()
             if ln.startswith("TYPED:")]
    assert typed, (
        f"expected a typed SandboxSetupError:\n"
        f"stdout={r.stdout}\nstderr={r.stderr}"
    )
    assert typed[0].startswith("TYPED:U:"), typed[0]
    assert "closed file" in typed[0]
    assert r.returncode == 0, r.stderr[-500:]
