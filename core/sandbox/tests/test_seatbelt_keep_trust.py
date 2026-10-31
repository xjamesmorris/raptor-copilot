"""Keep-trust dispatch on the macOS seatbelt lane.

The keep decision travels out-of-band as watcher-shim argv
(``--keep-trust-markers``), mintable only by the spawn layer — the
mirror of the Linux pid1-shim injection. The shim has supported the
flag all along; pre-fix the seatbelt dispatch never SENT it, so
``run_untrusted_networked(keep_trust_markers=True)`` — RAPTOR's own
``claude -p`` skill-dispatch lane — delivered children on macOS whose
trust markers and session credential had been stripped, unable to pass
the libexec trust gates.

Cross-platform: the REAL watcher shim + trampoline run on Linux with
SANDBOX_EXEC swapped for a pass-through script (production layering);
the context-dispatch parity tests use the established fake-darwin
patching pattern from test_context_backend_dispatch.py.
"""

from __future__ import annotations

import subprocess
import sys
from unittest import mock

import pytest

from core.sandbox import _macos_spawn

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX-only",
)

_MARKER_DUMP = ["/bin/sh", "-c",
                'printf "CC=%s RT=%s SP=%s ST=%s" '
                '"${CLAUDECODE:-ABSENT}" "${_RAPTOR_TRUSTED:-ABSENT}" '
                '"${RAPTOR_SESSION_PID:-ABSENT}" '
                '"${RAPTOR_SESSION_TOKEN:-ABSENT}"']

_DISPATCH_ENV = {
    "PATH": "/usr/bin:/bin",
    "CLAUDECODE": "1",
    "_RAPTOR_TRUSTED": "1",
    "RAPTOR_SESSION_PID": "12345",
    "RAPTOR_SESSION_TOKEN": "tok-under-test",
}


def _fake_sandbox_exec(tmp_path):
    fake = tmp_path / "fake-sandbox-exec"
    fake.write_text('#!/bin/sh\nshift 3\nexec "$@"\n')  # drop -p <profile> --
    fake.chmod(0o755)
    return str(fake)


class TestSpawnLevel:
    def test_keep_trust_markers_reach_the_target(self, tmp_path,
                                                 monkeypatch):
        monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                            _fake_sandbox_exec(tmp_path))
        out = tmp_path / "out"
        out.mkdir()
        r = _macos_spawn.run_sandboxed(
            list(_MARKER_DUMP), output=str(out),
            env=dict(_DISPATCH_ENV),
            keep_trust_markers=True,
            capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 0
        assert r.stdout == ("CC=1 RT=1 SP=12345 ST=tok-under-test"), (
            f"keep-trust dispatch lost markers: {r.stdout!r}")

    def test_default_still_strips_markers(self, tmp_path, monkeypatch):
        """The keep lane must not weaken the default: without the
        kwarg the shim applies the full strip tuple as before."""
        monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                            _fake_sandbox_exec(tmp_path))
        out = tmp_path / "out"
        out.mkdir()
        r = _macos_spawn.run_sandboxed(
            list(_MARKER_DUMP), output=str(out),
            env=dict(_DISPATCH_ENV),
            capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 0
        assert r.stdout == "CC=ABSENT RT=ABSENT SP=ABSENT ST=ABSENT", (
            f"default seatbelt run leaked trust markers: {r.stdout!r}")

    def test_env_keep_key_carries_no_authority(self, tmp_path,
                                               monkeypatch):
        """A poisoned caller env carrying the legacy in-band keep key
        must not preserve the markers — the argv flag is the only
        mint."""
        monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                            _fake_sandbox_exec(tmp_path))
        out = tmp_path / "out"
        out.mkdir()
        r = _macos_spawn.run_sandboxed(
            list(_MARKER_DUMP), output=str(out),
            env={**_DISPATCH_ENV, "_RAPTOR_KEEP_TRUST_MARKERS": "1"},
            capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 0
        assert r.stdout == "CC=ABSENT RT=ABSENT SP=ABSENT ST=ABSENT"


class TestContextDispatchParity:
    """The darwin dispatch must forward keep_trust_markers_for_dispatch
    to the backend — the parity twin of the Linux pid1-shim argv
    injection test surface."""

    def _captured_kwargs(self, tmp_path, **run_kwargs):
        from core.sandbox import _macos_spawn as macos_mod
        from core.sandbox import context
        captured = {}

        def fake_run(cmd, **kwargs):
            captured.update(kwargs)
            cp = subprocess.CompletedProcess(cmd, returncode=0,
                                             stdout="", stderr="")
            cp._setup_status = None
            cp.sandbox_info = {"backend": "macos-seatbelt"}
            return cp

        with mock.patch.object(sys, "platform", "darwin"), \
             mock.patch.object(context, "check_seatbelt_available",
                               return_value=True), \
             mock.patch.object(context, "check_mount_available",
                               return_value=False), \
             mock.patch.object(context, "check_net_available",
                               return_value=False), \
             mock.patch.object(macos_mod, "run_sandboxed", fake_run):
            context.run(["/usr/bin/true"], target=str(tmp_path),
                        output=str(tmp_path), timeout=30, **run_kwargs)
        return captured

    def test_dispatch_forwards_keep_flag(self, tmp_path):
        kwargs = self._captured_kwargs(
            tmp_path, keep_trust_markers_for_dispatch=True)
        assert kwargs.get("keep_trust_markers") is True

    def test_dispatch_defaults_to_strip(self, tmp_path):
        kwargs = self._captured_kwargs(tmp_path)
        assert kwargs.get("keep_trust_markers") is False
