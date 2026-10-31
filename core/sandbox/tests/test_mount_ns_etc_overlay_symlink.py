"""etc_overlay onto a symlinked /etc entry (the resolv.conf shape).

``_copy_etc_tree`` recreates host symlinks verbatim, and the stock
``/etc/resolv.conf -> ../run/systemd/resolve/stub-resolv.conf`` link
is exactly such an entry. Both the stub pre-create's ``exists()``
probe and the mount(2) pathname in the 8d bind loop FOLLOW symlinks
— in the PRE-pivot namespace — so the overlay bind silently landed
at the link's host-side destination instead of ``{root}/etc/<name>``:
post-pivot the child saw the copied link dangling into the fresh
empty /run tmpfs and the overlay content was absent. Contained (the
mount lives in the private ns) but the overlaid view is broken —
DNS-config overlays are the canonical cve-env use.

Fix under test: the tmpfs-copy lane replaces a symlinked overlay
target with a regular stub before binding (functional recovery); the
bind loop refuses to bind onto anything still a symlink (honest
fail-closed on the read-only plain-bind lane).

Two tiers: a hermetic unit test of the stub pre-create (mocked
mounts, runs everywhere) and a mount-capable end-to-end test that
reads the overlay content through a symlinked target inside a real
sandbox.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="mount-ns backend is Linux-only",
)

from core.sandbox import mount_ns  # noqa: E402
from core.sandbox.tests.capability import requires_mount  # noqa: E402


def _mount_ns_usable() -> bool:
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if sysctl.exists() and sysctl.read_text().strip() == "1":
        return False
    return True


class TestStubPreCreateReplacesSymlink(unittest.TestCase):
    """Hermetic: _mount_etc_tmpfs_copy's stub pre-create must lstat,
    not exists() — a copied symlink resolving to a live host path
    made exists() True, the stub step skipped, and the later bind
    followed the link off-path."""

    def _run_precreate(self, tmp_path: str, etc_overlay: dict) -> str:
        root = os.path.join(tmp_path, "root")
        etc_inside = os.path.join(root, "etc")
        os.makedirs(etc_inside)

        def _fake_copy(host_dir: str, dst: str) -> None:
            # The copied-verbatim host symlink: absolute target that
            # RESOLVES on the live host (the poisonous case — a
            # dangling link already failed loudly via O_NOFOLLOW).
            os.symlink("/etc/hostname", os.path.join(dst, "resolv.conf"))

        with mock.patch.object(mount_ns, "_mount"), \
                mock.patch.object(mount_ns, "_copy_etc_tree",
                                  _fake_copy):
            mount_ns._mount_etc_tmpfs_copy(
                root, "/etc", etc_inside, etc_overlay)
        return os.path.join(etc_inside, "resolv.conf")

    def test_live_symlink_replaced_by_regular_stub(self):
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "overlay-src.conf")
            with open(src, "w") as f:
                f.write("nameserver 192.0.2.1\n")
            stub = self._run_precreate(
                td, {"/etc/resolv.conf": src})
            st = os.lstat(stub)
            self.assertFalse(
                os.path.islink(stub),
                "copied symlink survived the stub pre-create — the "
                "8d bind would follow it off-path pre-pivot",
            )
            self.assertTrue(os.path.isfile(stub) and st.st_size == 0)

    def test_non_overlay_symlinks_left_alone(self):
        # Only overlay TARGETS are stubbed; unrelated copied links
        # keep their verbatim shape.
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "overlay-src.conf")
            with open(src, "w") as f:
                f.write("x\n")
            self._run_precreate(td, {"/etc/other.conf": src})
            untouched = os.path.join(td, "root", "etc", "resolv.conf")
            self.assertTrue(os.path.islink(untouched))


# Exercises mount-delivered capability; hosts with userns but no
# mount capability degrade by design -> named SKIP.
@requires_mount
class TestOverlaySymlinkedTargetE2E(unittest.TestCase):
    _SANDBOX_TIMEOUT = 8

    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        if not os.path.islink("/etc/resolv.conf"):
            self.skipTest(
                "host /etc/resolv.conf is not a symlink — the "
                "regression shape needs the stock systemd-resolved "
                "link"
            )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_overlay_content_visible_through_symlinked_target(self):
        """cat /etc/resolv.conf inside the sandbox returns the
        overlay content even though the copied host entry is a
        symlink. The extra missing-target entry forces the tmpfs+copy
        lane (where stub replacement makes the overlay functional)."""
        from core.sandbox._spawn import run_sandboxed
        overlay_source = os.path.join(self.tmp.name, "resolv-overlay")
        content = "nameserver 192.0.2.53\n"
        with open(overlay_source, "w") as f:
            f.write(content)
        force_copy_lane = os.path.join(
            self.tmp.name, "missing-target-src")
        with open(force_copy_lane, "w") as f:
            f.write("x\n")
        missing_target = "/etc/raptor_test_overlay_symlink.conf"
        assert not os.path.exists(missing_target)

        r = run_sandboxed(
            ["/bin/cat", "/etc/resolv.conf"],
            target=self.tmp.name, output=self.tmp.name,
            block_network=True,
            nproc_limit=1024,
            limits={"memory_mb": 0, "max_file_mb": 10240,
                    "cpu_seconds": 300},
            writable_paths=[self.tmp.name, "/tmp"],
            readable_paths=None,
            allowed_tcp_ports=None,
            seccomp_profile=None, seccomp_block_udp=False,
            env=None, cwd=None, timeout=self._SANDBOX_TIMEOUT,
            capture_output=True, text=True,
            etc_overlay={
                "/etc/resolv.conf": overlay_source,
                missing_target: force_copy_lane,
            },
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, content, (
            "overlay content absent through the symlinked target — "
            "the bind followed the copied link off-path pre-pivot"
        ))


if __name__ == "__main__":
    unittest.main()
