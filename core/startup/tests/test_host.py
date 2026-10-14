"""Host-claim identity tests without frontend launcher behavior."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from core.startup.host import (
    Frontend,
    HostClaimError,
    SessionHostClaim,
    _parse_executable,
    _parse_uint,
    _safe_executable_path,
    _supports_direct_process_claim,
    build_session_host_claim,
    host_process_matches,
    parse_metadata_host_claim,
    parse_session_host_claim,
)


def test_host_claim_parser_rejects_partial_unknown_and_noncanonical_fields():
    executable = Path(sys.executable).resolve()
    claim = build_session_host_claim(Frontend.CLAUDE, executable)
    fields = claim.session_fields()
    assert parse_session_host_claim(fields) == claim
    assert parse_metadata_host_claim(claim.metadata_fields()) == claim

    partial = dict(fields)
    partial.pop("host_exe_ino")
    with pytest.raises(HostClaimError, match="partial host claim"):
        parse_session_host_claim(partial)

    unknown = dict(fields)
    unknown["host_future"] = "1"
    with pytest.raises(HostClaimError, match="unknown host claim"):
        parse_session_host_claim(unknown)

    malformed = dict(fields)
    malformed["host_uid"] = f"0{os.geteuid()}"
    with pytest.raises(HostClaimError, match="canonical decimal"):
        parse_session_host_claim(malformed)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("", "empty or too long"),
        ("x" * 4097, "empty or too long"),
        ("bad\npath", "control bytes"),
    ],
)
def test_safe_executable_rejects_invalid_text(value, expected):
    with pytest.raises(ValueError, match=expected):
        _safe_executable_path(value)


def test_safe_executable_rejects_nonregular_and_nonexecutable(tmp_path):
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(ValueError, match="not a regular file"):
        _safe_executable_path(str(directory))

    plain = tmp_path / "plain"
    plain.write_text("not executable\n", encoding="utf-8")
    plain.chmod(0o600)
    with pytest.raises(ValueError, match="not executable"):
        _safe_executable_path(str(plain))


def test_safe_executable_joins_relative_path_to_cwd(tmp_path, monkeypatch):
    executable = tmp_path / "relative-host"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.chdir(tmp_path)
    assert _safe_executable_path("relative-host") == executable


def test_direct_claim_rejects_shebang_and_unreadable(tmp_path):
    script = tmp_path / "claude"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o700)
    assert _supports_direct_process_claim(script) is False
    with patch.object(
        Path,
        "open",
        side_effect=PermissionError("fixture denied"),
    ):
        assert _supports_direct_process_claim(script) is False


@pytest.mark.parametrize(
    "value,positive,expected",
    [
        ("+1", False, "must be an integer"),
        ("²", False, "must be an integer"),
        ("0x10", False, "must be an integer"),
        (-1, False, "outside the supported range"),
        (2**64, False, "outside the supported range"),
        ("01", False, "canonical decimal"),
        (0, True, "outside the supported range"),
        (True, False, "must be an integer"),
    ],
)
def test_parse_uint_rejects_noncanonical_values(value, positive, expected):
    with pytest.raises(HostClaimError, match=expected):
        _parse_uint(value, "field", positive=positive)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("relative/host", "must be absolute"),
        ("/bad\nhost", "empty, too long, or non-printable"),
        ("/" + "x" * 4097, "empty, too long, or non-printable"),
        (123, "must be a string"),
    ],
)
def test_parse_executable_rejects_invalid_values(value, expected):
    with pytest.raises(HostClaimError, match=expected):
        _parse_executable(value, "host executable")


def test_host_process_match_rejects_euid_and_missing_executable():
    claim = SessionHostClaim(
        frontend=Frontend.CLAUDE,
        uid=os.geteuid(),
        executable=Path("/owned/claude"),
        executable_device=10,
        executable_inode=20,
    )
    with patch("core.startup.host.os.geteuid", return_value=claim.uid + 1):
        assert (
            host_process_matches(
                123,
                claim,
                pid_running=lambda _pid: True,
                comm_reader=lambda _pid: "claude",
                uid_reader=lambda _pid: claim.uid,
                executable_identity_reader=lambda _pid: (10, 20),
            )
            is False
        )
    assert (
        host_process_matches(
            123,
            claim,
            pid_running=lambda _pid: True,
            comm_reader=lambda _pid: "claude",
            uid_reader=lambda _pid: claim.uid,
            executable_identity_reader=lambda _pid: None,
        )
        is False
    )


def test_host_process_match_rejects_proc_uid_comm_and_exe_gaps():
    claim = SessionHostClaim(
        frontend=Frontend.CLAUDE,
        uid=os.geteuid(),
        executable=Path("/owned/claude"),
        executable_device=10,
        executable_inode=20,
    )
    common = {
        "pid_running": lambda _pid: True,
        "comm_reader": lambda _pid: "claude",
        "uid_reader": lambda _pid: claim.uid,
        "executable_identity_reader": lambda _pid: (10, 20),
    }
    with patch("core.startup.host.os.geteuid", return_value=claim.uid):
        assert (
            host_process_matches(
                123,
                claim,
                **{**common, "uid_reader": lambda _pid: claim.uid + 1},
            )
            is False
        )
        assert (
            host_process_matches(
                123,
                claim,
                **{**common, "comm_reader": lambda _pid: None},
            )
            is False
        )
        assert (
            host_process_matches(
                123,
                claim,
                **{
                    **common,
                    "executable_identity_reader": lambda _pid: None,
                },
            )
            is False
        )


def test_mapped_executable_identity_ignores_replaced_disk_path(tmp_path):
    executable = tmp_path / "claude"
    executable.write_bytes(b"\x7fELF-old-image")
    executable.chmod(0o700)
    claim = build_session_host_claim(Frontend.CLAUDE, executable)
    mapped_identity = (
        claim.executable_device,
        claim.executable_inode,
    )

    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"\x7fELF-new-image")
    replacement.chmod(0o700)
    os.replace(replacement, executable)
    assert (executable.stat().st_dev, executable.stat().st_ino) != mapped_identity

    assert (
        host_process_matches(
            123,
            claim,
            pid_running=lambda _pid: True,
            comm_reader=lambda _pid: "claude",
            uid_reader=lambda _pid: claim.uid,
            executable_identity_reader=lambda _pid: mapped_identity,
        )
        is True
    )
