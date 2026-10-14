"""Filesystem-boundary tests for the production coverage read hook."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from core.coverage import track_read
from core.project import sessions
from core.run import metadata
from core.run.host_events import (
    HostEventEffectDisposition,
    HostEventKind,
    HostEventProfileId,
    normalize_host_event,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
HOOK = REPO_ROOT / "plugins" / "coverage" / "libexec" / "raptor-hook-read"

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or shutil.which("bash") is None,
    reason="Linux and bash required",
)


def _wait_for_process(pid: int) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if sessions.proc_starttime(pid) is not None:
            return
        time.sleep(0.01)
    raise AssertionError(f"owned process {pid} did not become observable")


@contextlib.contextmanager
def _owned_fixture(tmp_path: Path, monkeypatch):
    source_binary = shutil.which("sleep")
    assert source_binary is not None
    home = tmp_path / "home"
    home.mkdir()
    sessions_dir = home / ".local" / "share" / "raptor" / "sessions.d"
    monkeypatch.setattr(sessions, "SESSIONS_DIR", sessions_dir)
    executable = tmp_path / "bin" / "claude"
    executable.parent.mkdir()
    executable.write_bytes(Path(source_binary).read_bytes())
    executable.chmod(0o700)
    process = subprocess.Popen(
        [str(executable), "60"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        _wait_for_process(process.pid)
        token = sessions.mint_token()
        assert (
            sessions.record_session(
                sessions.NONE_SENTINEL,
                pid=process.pid,
                token=token,
            )
            == process.pid
        )
        target = tmp_path / "target"
        target.mkdir()
        source = target / "a.py"
        source.write_text("x = 1\n")
        run_dir = tmp_path / "out" / "run1"
        run_dir.mkdir(parents=True)
        fields = sessions._parse_entry(sessions_dir / str(process.pid))
        meta: dict[str, object] = {
            "status": "running",
            "command": "scan",
            "session_pid": process.pid,
            "target_path": str(target),
            "session_start": fields["starttime"],
            "session_boot_id": fields["boot_id"],
        }
        if "pidns" in fields:
            meta["session_pidns"] = fields["pidns"]
        (run_dir / metadata.RUN_METADATA_FILE).write_text(
            json.dumps(meta),
            encoding="utf-8",
        )
        sessions.ledger_record_start(run_dir, pid=process.pid)
        env = {
            "HOME": str(home),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "RAPTOR_SESSION_PID": str(process.pid),
            "RAPTOR_SESSION_TOKEN": token,
            "_RAPTOR_TRUSTED": "1",
            "RAPTOR_CC_TRANSPORT_DISABLED": "1",
            "RAPTOR_COPILOT_TRANSPORT_DISABLED": "1",
        }
        yield {
            "env": env,
            "source": source,
            "run_dir": run_dir,
            "target": target,
            "pid": process.pid,
        }
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def _fire(case, *, payload: bytes | None = None):
    raw = (
        payload
        or json.dumps(
            {
                "tool_input": {"file_path": str(case["source"])},
            }
        ).encode()
    )
    return subprocess.run(
        [str(HOOK)],
        input=raw,
        env=case["env"],
        capture_output=True,
        timeout=10,
        check=False,
    )


def test_e01_normal_append_records_read(tmp_path, monkeypatch):
    with _owned_fixture(tmp_path, monkeypatch) as case:
        proc = _fire(case)
        manifest = case["run_dir"] / track_read.MANIFEST_NAME

    assert proc.returncode == 0
    assert proc.stdout == b""
    assert proc.stderr == b""
    assert manifest.read_bytes() == (str(case["source"].resolve()) + "\n").encode()
    assert stat.S_IMODE(manifest.stat().st_mode) == 0o600


def test_e27_symlinked_manifest_is_refused(tmp_path, monkeypatch):
    with _owned_fixture(tmp_path, monkeypatch) as case:
        victim = tmp_path / "victim"
        victim.write_text("original\n")
        manifest = case["run_dir"] / track_read.MANIFEST_NAME
        manifest.symlink_to(victim)

        proc = _fire(case)

    assert proc.returncode == 0
    assert proc.stdout == b""
    assert proc.stderr.count(b"\n") == 1
    assert b"io_refused" in proc.stderr
    assert victim.read_text() == "original\n"


def test_e27_dangling_symlink_not_followed_on_create(tmp_path, monkeypatch):
    with _owned_fixture(tmp_path, monkeypatch) as case:
        victim = tmp_path / "never-created"
        manifest = case["run_dir"] / track_read.MANIFEST_NAME
        manifest.symlink_to(victim)

        proc = _fire(case)

    assert proc.returncode == 0
    assert b"io_refused" in proc.stderr
    assert not victim.exists()


def test_e28_fifo_without_reader_is_refused_without_hanging(
    tmp_path,
    monkeypatch,
):
    with _owned_fixture(tmp_path, monkeypatch) as case:
        manifest = case["run_dir"] / track_read.MANIFEST_NAME
        os.mkfifo(manifest)
        started = time.monotonic()
        proc = _fire(case)
        elapsed = time.monotonic() - started

    assert elapsed < 2
    assert proc.returncode == 0
    assert b"io_refused" in proc.stderr


def test_e28_fifo_with_reader_is_refused_without_hanging(
    tmp_path,
    monkeypatch,
):
    with _owned_fixture(tmp_path, monkeypatch) as case:
        manifest = case["run_dir"] / track_read.MANIFEST_NAME
        os.mkfifo(manifest)
        reader = os.open(manifest, os.O_RDONLY | os.O_NONBLOCK)
        try:
            started = time.monotonic()
            proc = _fire(case)
            elapsed = time.monotonic() - started
        finally:
            os.close(reader)

    assert elapsed < 2
    assert proc.returncode == 0
    assert b"io_refused" in proc.stderr


def test_e28_hard_link_is_refused(tmp_path, monkeypatch):
    with _owned_fixture(tmp_path, monkeypatch) as case:
        victim = tmp_path / "victim"
        victim.write_text("original\n")
        manifest = case["run_dir"] / track_read.MANIFEST_NAME
        os.link(victim, manifest)

        proc = _fire(case)

    assert proc.returncode == 0
    assert b"io_refused" in proc.stderr
    assert victim.read_text() == "original\n"


def test_e28_device_descriptor_is_refused(tmp_path, monkeypatch):
    with _owned_fixture(tmp_path, monkeypatch) as case:
        parsed = normalize_host_event(
            json.dumps(
                {
                    "tool_input": {"file_path": str(case["source"])},
                }
            ).encode(),
            profile=HostEventProfileId.CLAUDE_LEGACY_V1,
            registration_kind=HostEventKind.TOOL_SUCCESS,
        )
        assert parsed.event is not None
        observation = track_read.ReadObservation(
            event=parsed.event,
            reported_path=str(case["source"]),
        )
        with pytest.MonkeyPatch.context() as env_patch:
            for key, value in case["env"].items():
                env_patch.setenv(key, value)
            target = track_read.resolve_read_target().target
        assert target is not None
        real_open = os.open

        def device_open(path, flags, mode=0o777, *, dir_fd=None):
            if path == track_read.MANIFEST_NAME:
                return real_open("/dev/null", os.O_WRONLY | os.O_NONBLOCK)
            if dir_fd is None:
                return real_open(path, flags, mode)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with monkeypatch.context() as patcher:
            patcher.setattr(track_read.os, "open", device_open)
            disposition, _reason, _path = track_read.record_read(target, observation)

    assert disposition is HostEventEffectDisposition.IO_REFUSED


def test_e28_foreign_uid_manifest_is_refused(tmp_path, monkeypatch):
    with _owned_fixture(tmp_path, monkeypatch) as case:
        parsed = normalize_host_event(
            json.dumps(
                {
                    "tool_input": {"file_path": str(case["source"])},
                }
            ).encode(),
            profile=HostEventProfileId.CLAUDE_LEGACY_V1,
            registration_kind=HostEventKind.TOOL_SUCCESS,
        )
        assert parsed.event is not None
        observation = track_read.ReadObservation(
            event=parsed.event,
            reported_path=str(case["source"]),
        )
        with pytest.MonkeyPatch.context() as env_patch:
            for key, value in case["env"].items():
                env_patch.setenv(key, value)
            target = track_read.resolve_read_target().target
        assert target is not None
        real_fstat = os.fstat
        calls = 0

        def foreign_manifest(fd):
            nonlocal calls
            calls += 1
            value = real_fstat(fd)
            if calls == 2:
                values = list(value)
                values[4] = os.geteuid() + 1
                return os.stat_result(values)
            return value

        with monkeypatch.context() as patcher:
            patcher.setattr(track_read.os, "fstat", foreign_manifest)
            disposition, _reason, _path = track_read.record_read(target, observation)

    assert disposition is HostEventEffectDisposition.IO_REFUSED


def test_c4_foreign_uid_run_directory_is_refused(tmp_path, monkeypatch):
    with _owned_fixture(tmp_path, monkeypatch) as case:
        parsed = normalize_host_event(
            json.dumps(
                {
                    "tool_input": {"file_path": str(case["source"])},
                }
            ).encode(),
            profile=HostEventProfileId.CLAUDE_LEGACY_V1,
            registration_kind=HostEventKind.TOOL_SUCCESS,
        )
        assert parsed.event is not None
        observation = track_read.ReadObservation(
            event=parsed.event,
            reported_path=str(case["source"]),
        )
        with pytest.MonkeyPatch.context() as env_patch:
            for key, value in case["env"].items():
                env_patch.setenv(key, value)
            target = track_read.resolve_read_target().target
        assert target is not None
        real_fstat = os.fstat
        calls = 0

        def foreign_directory(fd):
            nonlocal calls
            calls += 1
            value = real_fstat(fd)
            if calls == 1:
                values = list(value)
                values[4] = os.geteuid() + 1
                return os.stat_result(values)
            return value

        with monkeypatch.context() as patcher:
            patcher.setattr(track_read.os, "fstat", foreign_directory)
            disposition, _reason, _path = track_read.record_read(target, observation)

    assert disposition is HostEventEffectDisposition.IO_REFUSED
    assert not (case["run_dir"] / track_read.MANIFEST_NAME).exists()


def test_c4_short_write_is_not_retried(tmp_path, monkeypatch):
    with _owned_fixture(tmp_path, monkeypatch) as case:
        parsed = normalize_host_event(
            json.dumps(
                {
                    "tool_input": {"file_path": str(case["source"])},
                }
            ).encode(),
            profile=HostEventProfileId.CLAUDE_LEGACY_V1,
            registration_kind=HostEventKind.TOOL_SUCCESS,
        )
        assert parsed.event is not None
        observation = track_read.ReadObservation(
            event=parsed.event,
            reported_path=str(case["source"]),
        )
        with pytest.MonkeyPatch.context() as env_patch:
            for key, value in case["env"].items():
                env_patch.setenv(key, value)
            target = track_read.resolve_read_target().target
        assert target is not None
        calls: list[bytes] = []

        def short_write(_fd, data):
            calls.append(data)
            return len(data) - 1

        with monkeypatch.context() as patcher:
            patcher.setattr(track_read.os, "write", short_write)
            disposition, _reason, _path = track_read.record_read(target, observation)

    assert disposition is HostEventEffectDisposition.IO_REFUSED
    assert len(calls) == 1


def test_c4_write_error_is_refused_without_retry(tmp_path, monkeypatch):
    with _owned_fixture(tmp_path, monkeypatch) as case:
        parsed = normalize_host_event(
            json.dumps(
                {
                    "tool_input": {"file_path": str(case["source"])},
                }
            ).encode(),
            profile=HostEventProfileId.CLAUDE_LEGACY_V1,
            registration_kind=HostEventKind.TOOL_SUCCESS,
        )
        assert parsed.event is not None
        observation = track_read.ReadObservation(
            event=parsed.event,
            reported_path=str(case["source"]),
        )
        with pytest.MonkeyPatch.context() as env_patch:
            for key, value in case["env"].items():
                env_patch.setenv(key, value)
            target = track_read.resolve_read_target().target
        assert target is not None
        calls = 0

        def refused_write(_fd, _data):
            nonlocal calls
            calls += 1
            raise OSError("refused")

        with monkeypatch.context() as patcher:
            patcher.setattr(track_read.os, "write", refused_write)
            disposition, _reason, _path = track_read.record_read(target, observation)

    assert disposition is HostEventEffectDisposition.IO_REFUSED
    assert calls == 1


def test_c4_symlinked_run_metadata_is_refused(
    tmp_path,
    monkeypatch,
):
    with _owned_fixture(tmp_path, monkeypatch) as case:
        meta = case["run_dir"] / metadata.RUN_METADATA_FILE
        backing = case["run_dir"] / "owned-metadata.json"
        meta.replace(backing)
        meta.symlink_to(backing.name)

        proc = _fire(case)

    assert proc.returncode == 0
    assert proc.stderr == b""
    assert not (case["run_dir"] / track_read.MANIFEST_NAME).exists()
