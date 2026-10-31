"""Structured capture metadata and parent-owned cancellation.

These tests exercise the real Linux fork/mount sandbox. They never invoke a
model or an operator-installed CLI.
"""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from core.sandbox import _spawn
from core.sandbox import context as sandbox_context
from core.sandbox.errors import SandboxCancelled
from core.sandbox.tests.capability import (
    requires_landlock,
    requires_mount,
    requires_userns,
)

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="Linux spawn backend"),
    requires_landlock,
    requires_mount,
    requires_userns,
]


def _kwargs(tmp_path: Path) -> dict:
    return {
        "target": str(tmp_path),
        "output": str(tmp_path),
        "block_network": True,
        "nproc_limit": 1024,
        "limits": {
            "memory_mb": 0,
            "max_file_mb": 10240,
            "cpu_seconds": 300,
        },
        "writable_paths": [str(tmp_path), "/tmp"],
        "readable_paths": None,
        "allowed_tcp_ports": None,
        "seccomp_profile": "full",
        "seccomp_block_udp": False,
        "env": {"PATH": "/usr/bin:/bin", "LANG": "C"},
        "cwd": str(tmp_path),
        "timeout": 30,
        "capture_output": True,
        "text": False,
    }


def _capture(result_or_error) -> dict:
    return result_or_error.sandbox_info["capture"]


def test_bind_source_identities_accept_exact_parent_pin(
    tmp_path: Path,
) -> None:
    identity = tmp_path.stat()
    kwargs = _kwargs(tmp_path)
    kwargs["bind_source_identities"] = {
        str(tmp_path): (identity.st_dev, identity.st_ino),
    }

    result = _spawn.run_sandboxed(
        ["/bin/true"],
        **kwargs,
    )

    assert result.returncode == 0
    assert result.sandbox_info["backend"] == "linux-fork-mount-pid-netns"


def test_success_reports_exact_capture_loss_for_both_streams(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_spawn, "_CAPTURE_CAP", 1024)
    program = (
        "import os, threading\n"
        "def emit(fd, byte):\n"
        "    for _ in range(64):\n"
        "        os.write(fd, byte * 128)\n"
        "a=threading.Thread(target=emit,args=(1,b'O'))\n"
        "b=threading.Thread(target=emit,args=(2,b'E'))\n"
        "a.start(); b.start(); a.join(); b.join()\n"
    )

    result = _spawn.run_sandboxed(
        ["/usr/bin/python3", "-c", program],
        **_kwargs(tmp_path),
    )

    assert result.returncode == 0
    assert result.stdout_truncated is True
    assert result.stderr_truncated is True
    assert result.stdout_bytes_kept == 1024
    assert result.stderr_bytes_kept == 1024
    assert result.stdout.startswith(b"O" * 1024)
    assert result.stderr.startswith(b"E" * 1024)
    assert b"[sandbox: stdout capture truncated" in result.stdout
    assert b"[sandbox: stderr capture truncated" in result.stderr
    assert _capture(result) == {
        "enabled": True,
        "stdout_truncated": True,
        "stderr_truncated": True,
        "stdout_bytes_kept": 1024,
        "stderr_bytes_kept": 1024,
    }


def test_timeout_preserves_capped_partial_output_and_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_spawn, "_CAPTURE_CAP", 512)
    teardown_calls: list[int] = []
    real_teardown = _spawn._teardown_target

    def recording_teardown(
        child_pid: int,
        death_w: int,
        parent_fds: set,
        grace_s: float = 1.0,
    ) -> None:
        teardown_calls.append(child_pid)
        real_teardown(child_pid, death_w, parent_fds, grace_s)

    monkeypatch.setattr(_spawn, "_teardown_target", recording_teardown)
    kwargs = _kwargs(tmp_path)
    kwargs["timeout"] = 0.3
    program = (
        "import os, time\n"
        "os.write(1, b'O' * 4096)\n"
        "os.write(2, b'E' * 4096)\n"
        "time.sleep(30)\n"
    )

    with pytest.raises(subprocess.TimeoutExpired) as excinfo:
        _spawn.run_sandboxed(
            ["/usr/bin/python3", "-c", program],
            **kwargs,
        )

    error = excinfo.value
    assert error.stdout_truncated is True
    assert error.stderr_truncated is True
    assert error.stdout_bytes_kept == 512
    assert error.stderr_bytes_kept == 512
    assert error.output.startswith(b"O" * 512)
    assert error.stderr.startswith(b"E" * 512)
    assert b"capture truncated" in error.output
    assert b"capture truncated" in error.stderr
    assert _capture(error)["stdout_bytes_kept"] == 512
    assert _capture(error)["stderr_bytes_kept"] == 512
    assert len(teardown_calls) == 1


@pytest.mark.parametrize("cancel_action", ["write", "eof"])
def test_cancel_fd_is_parent_owned_cloexec_and_never_reaches_target(
    tmp_path: Path,
    cancel_action: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cancel_r, cancel_w = os.pipe()
    teardown_calls: list[int] = []
    real_teardown = _spawn._teardown_target
    monkeypatch.setattr(_spawn, "_CAPTURE_CAP", 512)

    def recording_teardown(
        child_pid: int,
        death_w: int,
        parent_fds: set,
        grace_s: float = 1.0,
    ) -> None:
        teardown_calls.append(child_pid)
        real_teardown(child_pid, death_w, parent_fds, grace_s)

    monkeypatch.setattr(_spawn, "_teardown_target", recording_teardown)
    try:
        assert fcntl.fcntl(cancel_r, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        cancel_target = os.readlink(f"/proc/self/fd/{cancel_r}")
        program = (
            "import json, os, sys, time\n"
            "targets=[]\n"
            "for name in os.listdir('/proc/self/fd'):\n"
            "    try:\n"
            "        targets.append(os.readlink('/proc/self/fd/' + name))\n"
            "    except OSError:\n"
            "        pass\n"
            "print(json.dumps({'cancel_fd_inherited': sys.argv[1] in targets}))\n"
            "sys.stdout.flush()\n"
            "os.write(1, b'O' * 4096)\n"
            "os.write(2, b'E' * 4096)\n"
            "time.sleep(30)\n"
        )

        def cancel() -> None:
            time.sleep(0.5)
            if cancel_action == "write":
                os.write(cancel_w, b"x")
            else:
                os.close(cancel_w)

        thread = threading.Thread(target=cancel, daemon=True)
        thread.start()
        kwargs = _kwargs(tmp_path)
        kwargs["cancel_fd"] = cancel_r
        with pytest.raises(SandboxCancelled) as excinfo:
            _spawn.run_sandboxed(
                ["/usr/bin/python3", "-c", program, cancel_target],
                **kwargs,
            )
        thread.join(timeout=2)

        error = excinfo.value
        first_line = error.output.splitlines()[0]
        assert json.loads(first_line)["cancel_fd_inherited"] is False
        assert error.cancelled is True
        assert error.stdout_truncated is True
        assert error.stderr_truncated is True
        assert error.stdout_bytes_kept == 512
        assert error.stderr_bytes_kept == 512
        assert _capture(error)["enabled"] is True
        assert fcntl.fcntl(cancel_r, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        assert len(teardown_calls) == 1
    finally:
        for fd in (cancel_r, cancel_w):
            try:
                os.close(fd)
            except OSError:
                pass


def test_cancel_fd_without_cloexec_is_refused_before_fork(
    tmp_path: Path,
) -> None:
    cancel_r, cancel_w = os.pipe()
    try:
        flags = fcntl.fcntl(cancel_r, fcntl.F_GETFD)
        fcntl.fcntl(cancel_r, fcntl.F_SETFD, flags & ~fcntl.FD_CLOEXEC)
        marker = tmp_path / "must-not-exist"
        kwargs = _kwargs(tmp_path)
        kwargs["cancel_fd"] = cancel_r
        with pytest.raises(ValueError, match="close-on-exec"):
            _spawn.run_sandboxed(
                [
                    "/usr/bin/python3",
                    "-c",
                    f"from pathlib import Path; Path({str(marker)!r}).touch()",
                ],
                **kwargs,
            )
        assert not marker.exists()
    finally:
        os.close(cancel_r)
        os.close(cancel_w)


def test_baseexception_during_collection_uses_teardown_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_pids: list[int] = []
    teardown_calls: list[int] = []
    real_teardown = _spawn._teardown_target

    def raising_read(_fd: int) -> bytes:
        raise KeyboardInterrupt

    def recording_teardown(
        child_pid: int,
        death_w: int,
        parent_fds: set,
        grace_s: float = 1.0,
    ) -> None:
        teardown_calls.append(child_pid)
        real_teardown(child_pid, death_w, parent_fds, grace_s)

    monkeypatch.setattr(_spawn, "_read_capture_chunk", raising_read)
    monkeypatch.setattr(_spawn, "_teardown_target", recording_teardown)
    kwargs = _kwargs(tmp_path)
    kwargs["child_pid_callback"] = child_pids.append

    with pytest.raises(KeyboardInterrupt) as excinfo:
        _spawn.run_sandboxed(
            [
                "/usr/bin/python3",
                "-c",
                "import sys,time; print('ready'); sys.stdout.flush(); time.sleep(30)",
            ],
            **kwargs,
        )

    assert len(child_pids) == 1
    assert teardown_calls == child_pids
    assert excinfo.value.stdout_bytes_kept == 0
    assert _capture(excinfo.value)["enabled"] is True
    with pytest.raises(ProcessLookupError):
        os.kill(child_pids[0], 0)


def test_context_preserves_timeout_capture_and_backend_posture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_spawn, "_CAPTURE_CAP", 256)
    with pytest.raises(subprocess.TimeoutExpired) as excinfo:
        sandbox_context.run(
            [
                "/usr/bin/python3",
                "-c",
                "import os,time; os.write(1,b'X'*4096); time.sleep(30)",
            ],
            target=str(tmp_path),
            output=str(tmp_path),
            no_degrade=True,
            restrict_reads=True,
            timeout=0.3,
            capture_output=True,
            text=False,
        )

    info = excinfo.value.sandbox_info
    assert info["backend"] == "linux-fork-mount-pid-netns"
    assert info["mount_ns_active"] is True
    assert info["restrict_reads"] is True
    assert info["degrade_waiver_honored"] is False
    assert info["capture"]["stdout_truncated"] is True
    assert info["capture"]["stdout_bytes_kept"] == 256
