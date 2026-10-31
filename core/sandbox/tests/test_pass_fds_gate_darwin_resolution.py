"""fd-policy gate: F_GETPATH fallback when /proc is unavailable.

On darwin there is no /proc, so the gate's
``os.readlink("/proc/self/fd/N")`` raises and every regular-file or
directory fd used to fall through to the "anonymous or unlinked
inode (unresolvable)" refusal — a false diagnosis that refused fully
in-policy ``pass_fds``/``stdin=open(...)`` shapes and made
``pass_fds_declared=True`` the de-facto workaround (weakening the
audit the gate provides). The gate now resolves such fds via fcntl
F_GETPATH, pinned by dev/ino identity against the descriptor (the
``_reopen_write_only`` pattern), and only unpinnable fds keep the
fail-closed anonymous refusal.

Mechanics are exercised on Linux by failing the procfs readlink for
the planted fd only and emulating F_GETPATH — the resolution logic
is plain fcntl/stat with nothing Apple-specific.
"""

from __future__ import annotations

import fcntl as _fcntl_mod
import os
import sys
import tempfile
import unittest
from unittest import mock

import pytest

from core.sandbox.tests.capability import requires_landlock

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="emulated on the Linux gate implementation",
)

_FAKE_F_GETPATH = 50  # darwin's value; absent from Linux fcntl


@requires_landlock
class TestDarwinFdResolution(unittest.TestCase):
    def setUp(self):
        self._out = tempfile.TemporaryDirectory(prefix="raptor-fdres-")
        self.addCleanup(self._out.cleanup)
        self.out = os.path.realpath(self._out.name)

    def _sandbox(self, **kw):
        from core.sandbox import sandbox
        kw.setdefault("output", self.out)
        return sandbox(**kw)

    def _emulate_no_procfs_for(self, fd: int, getpath_result: str):
        """Fail the /proc readlink for *fd* only; serve F_GETPATH."""
        real_readlink = os.readlink
        real_fcntl = _fcntl_mod.fcntl
        probe = f"/proc/self/fd/{fd}"

        def fake_readlink(path, *a, **kw):
            if os.fspath(path) == probe:
                raise OSError(2, "no procfs (emulated darwin)")
            return real_readlink(path, *a, **kw)

        def fake_fcntl(pfd, cmd, arg=0):
            if pfd == fd and cmd == _FAKE_F_GETPATH:
                raw = os.fsencode(getpath_result)
                return raw + b"\x00" * (len(arg) - len(raw))
            return real_fcntl(pfd, cmd, arg)

        patches = [
            mock.patch("os.readlink", fake_readlink),
            mock.patch.object(_fcntl_mod, "F_GETPATH",
                              _FAKE_F_GETPATH, create=True),
            mock.patch.object(_fcntl_mod, "fcntl", fake_fcntl),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_in_policy_fd_resolves_and_is_allowed(self):
        # A read fd under output is in-policy even with reads
        # restricted — the F_GETPATH resolution must let it through
        # instead of the false anonymous-inode refusal.
        path = os.path.join(self.out, "in-policy.txt")
        with open(path, "w") as f:
            f.write("ok\n")
        fd = os.open(path, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        self._emulate_no_procfs_for(fd, path)
        with self._sandbox(restrict_reads=True) as run:
            r = run(["/bin/true"], pass_fds=[fd],
                    capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 0, getattr(r, "stderr", ""))

    def test_out_of_policy_fd_gets_the_true_diagnosis(self):
        # Resolution restores the REAL policy verdict: an fd outside
        # the read allowlist refuses as out-of-policy, not as
        # "anonymous or unlinked inode".
        home = os.path.expanduser("~")
        if not os.access(home, os.W_OK):
            self.skipTest("home directory not writable on this host")
        vdir = tempfile.TemporaryDirectory(
            dir=home, prefix=".raptor-fdres-victim-")
        self.addCleanup(vdir.cleanup)
        victim = os.path.join(vdir.name, "secret.txt")
        with open(victim, "w") as f:
            f.write("victim\n")
        fd = os.open(victim, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        self._emulate_no_procfs_for(fd, victim)
        with self._sandbox(restrict_reads=True) as run:
            with self.assertRaisesRegex(
                    TypeError, "outside the read allowlist") as cm:
                run(["/bin/true"], pass_fds=[fd])
        # The refusal names the resolved path — the real diagnosis,
        # not the pre-resolution "anonymous or unlinked inode" one.
        self.assertIn(victim, str(cm.exception))
        self.assertNotIn("anonymous", str(cm.exception))

    def test_unpinnable_getpath_answer_stays_refused(self):
        # Fail closed: F_GETPATH naming a path whose identity does
        # not match the descriptor (rename race, stale answer) must
        # not be trusted — the fd keeps the anonymous refusal.
        path = os.path.join(self.out, "real.txt")
        decoy = os.path.join(self.out, "decoy.txt")
        for p in (path, decoy):
            with open(p, "w") as f:
                f.write("x\n")
        fd = os.open(path, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        self._emulate_no_procfs_for(fd, decoy)  # wrong inode
        with self._sandbox(restrict_reads=True) as run:
            with self.assertRaisesRegex(TypeError, "anonymous"):
                run(["/bin/true"], pass_fds=[fd])
