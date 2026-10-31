"""AF_UNIX allowance parity between the parent predicate and step 9.

The parent-side ``_allow_unix`` predicate claims to mirror the
child-side mount-ns engagement condition at step 9 —
``(target or output or rootfs) and not skip_mount_ns`` — but omitted
``rootfs``. Production rootfs callers (cve-env, fuzzing env builds)
pass neither target nor output, so their children ran under the
default seccomp profile with ``socket(AF_UNIX)`` blocked, despite
having exactly the private mount view (per-sandbox /tmp + /run
tmpfs, minimal-dev /dev/shm) that justifies the allowance on
target/output runs: unix-socket IPC (postgres/php-fpm entrypoints,
Python >= 3.14 multiprocessing forkserver) failed with EPERM inside
image workloads.

Mock-level rootfs-shaped context: the seccomp preexec builder is
recorded and the spawn aborted at fork — the predicate under test is
resolved parent-side, before any child exists.
"""

from __future__ import annotations

import sys
from unittest import mock

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="mount-ns backend is Linux-only",
)


def _allow_unix_for(tmp_path, **path_kwargs) -> bool:
    from core.sandbox import _spawn
    from core.sandbox import _unix_scope
    if not _spawn.mount_ns_available():
        pytest.skip("mount-ns not available on this host")
    recorded: dict = {}

    def fake_seccomp_builder(profile, **kwargs):
        recorded.update(kwargs)
        return lambda: None

    with mock.patch.object(_spawn, "_make_seccomp_preexec",
                           fake_seccomp_builder), \
            mock.patch.object(_unix_scope, "probe_unix_scope",
                              return_value=True), \
            mock.patch("os.fork",
                       side_effect=OSError(11, "abort for test")), \
            pytest.raises(OSError, match="abort for test"):
        _spawn.run_sandboxed(
            ["/usr/bin/true"],
            writable_paths=[], readable_paths=None,
            allowed_tcp_ports=None,
            block_network=True, nproc_limit=1024,
            limits={"memory_mb": 0, "max_file_mb": 10240,
                    "cpu_seconds": 300},
            seccomp_profile="full", seccomp_block_udp=False,
            env=None, cwd=None, timeout=30,
            capture_output=True, text=True,
            **path_kwargs,
        )
    assert "allow_unix_sockets" in recorded, (
        "seccomp preexec builder never invoked — harness broke"
    )
    return bool(recorded["allow_unix_sockets"])


def test_rootfs_only_spawn_gets_the_af_unix_allowance(tmp_path):
    rootfs = tmp_path / "image-root"
    rootfs.mkdir()
    assert _allow_unix_for(tmp_path, target=None, output=None,
                           rootfs=str(rootfs)) is True


def test_target_run_allowance_unchanged(tmp_path):
    tgt = tmp_path / "t"
    tgt.mkdir()
    assert _allow_unix_for(tmp_path, target=str(tgt),
                           output=None) is True


def test_no_mount_engagement_stays_blocked(tmp_path):
    # Both directions: with no target/output/rootfs the mount tree
    # never engages (no private tmpfs masking /run) and AF_UNIX must
    # stay in the seccomp blocklist.
    assert _allow_unix_for(tmp_path, target=None, output=None) is False
