"""``run_landlock_audit(env=None)`` must not exec the full parent env.

_spawn.run_sandboxed's identical case substitutes the scrubbed
allowlist env (``RaptorConfig.get_safe_env()``): a sandboxed child
must not inherit ambient secrets because a caller skipped the
context.run() wrapper. The Landlock-audit lane execed the FULL
parent environment for ``env=None`` — on the namespace-less tier,
where /proc-based exfiltration defences are weakest, that hands the
orchestrator's session credentials and cloud keys to an audited
(attacker-derived) target. The two backends share a signature; their
``env=None`` semantics must not diverge.
"""

from __future__ import annotations

import sys

import pytest

from core.sandbox import _landlock_audit as mod

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Landlock-audit spawn path is Linux-only",
)

_CANARY = "RAPTOR_TEST_AMBIENT_SECRET_CANARY"


def _ptrace_ready() -> bool:
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available
    return check_ptrace_available() and check_seccomp_available()


def test_env_none_execs_scrubbed_allowlist_not_parent_env(
        tmp_path, monkeypatch):
    if not _ptrace_ready():
        pytest.skip("ptrace/libseccomp unavailable")
    # An ambient value outside the safe-env allowlist — the stand-in
    # for a session credential riding the orchestrator's environ.
    monkeypatch.setenv(_CANARY, "leak-me")
    probe = (
        "import os\n"
        f"print('CANARY-PRESENT' if {_CANARY!r} in os.environ"
        " else 'CANARY-ABSENT')\n"
        "print('PATH-PRESENT' if os.environ.get('PATH')"
        " else 'PATH-ABSENT')\n"
    )
    result = mod.run_landlock_audit(
        [sys.executable, "-c", probe],
        audit_run_dir=str(tmp_path),
        env=None,
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "CANARY-ABSENT" in result.stdout, (
        f"env=None execed the full parent environment:\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    # The substitution is the allowlist env, not an empty one — the
    # target still gets the operational basics.
    assert "PATH-PRESENT" in result.stdout


def test_explicit_env_still_passed_verbatim(tmp_path):
    if not _ptrace_ready():
        pytest.skip("ptrace/libseccomp unavailable")
    probe = (
        "import os\n"
        "print('MARKER=' + os.environ.get('AUDIT_ENV_MARKER', ''))\n"
    )
    result = mod.run_landlock_audit(
        [sys.executable, "-c", probe],
        audit_run_dir=str(tmp_path),
        env={"PATH": "/usr/bin:/bin", "AUDIT_ENV_MARKER": "kept"},
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "MARKER=kept" in result.stdout
