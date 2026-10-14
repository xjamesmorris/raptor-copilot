"""Verified host-process identity without frontend launch authority.

An installed frontend executable, a verified session owner, and a usable
headless LLM provider are separate facts.  This module defines only the
identity claim used by the private session registry.  It does not select,
prepare, or launch a frontend and does not infer provider usability.
"""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping

HOST_CLAIM_VERSION = "1"

SESSION_HOST_KEYS = (
    "host_v",
    "host",
    "host_uid",
    "host_exe",
    "host_exe_dev",
    "host_exe_ino",
)

RUN_HOST_KEYS = (
    "session_host_v",
    "session_host",
    "session_host_uid",
    "session_host_exe",
    "session_host_exe_dev",
    "session_host_exe_ino",
)

_MAX_EXECUTABLE_PATH = 4096
_MAX_IDENTITY_INTEGER = (1 << 64) - 1


class Frontend(str, Enum):
    """Interactive RAPTOR host selected by the operator."""

    CLAUDE = "claude"
    COPILOT = "copilot"


class HostClaimError(ValueError):
    """A persisted host claim is partial, malformed, or unknown."""


@dataclass(frozen=True)
class SessionHostClaim:
    """Strong host discriminator stored beside the session identity stamp."""

    frontend: Frontend
    uid: int
    executable: Path
    executable_device: int
    executable_inode: int

    def session_fields(self) -> dict[str, str]:
        return {
            "host_v": HOST_CLAIM_VERSION,
            "host": self.frontend.value,
            "host_uid": str(self.uid),
            "host_exe": str(self.executable),
            "host_exe_dev": str(self.executable_device),
            "host_exe_ino": str(self.executable_inode),
        }

    def metadata_fields(self) -> dict[str, object]:
        return {
            "session_host_v": HOST_CLAIM_VERSION,
            "session_host": self.frontend.value,
            "session_host_uid": self.uid,
            "session_host_exe": str(self.executable),
            "session_host_exe_dev": self.executable_device,
            "session_host_exe_ino": self.executable_inode,
        }


@dataclass(frozen=True)
class SessionOwner:
    """Resolved legacy or strongly verified frontend-session owner."""

    pid: int
    frontend: Frontend
    host_verified: bool
    host_claim: SessionHostClaim | None = None


def _safe_executable_path(value: str) -> Path:
    if not value or len(value) > _MAX_EXECUTABLE_PATH:
        raise ValueError("frontend executable path is empty or too long")
    if not value.isprintable():
        raise ValueError("frontend executable path contains control bytes")
    path = Path(value)
    if not path.is_absolute():
        path = Path.cwd() / path
    path = Path(os.path.abspath(path))
    try:
        st = path.stat()
    except OSError as exc:
        raise ValueError(
            f"frontend executable cannot be inspected: {path}: {exc}"
        ) from exc
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"frontend executable is not a regular file: {path}")
    if not os.access(path, os.X_OK):
        raise ValueError(f"frontend executable is not executable: {path}")
    return path


def _supports_direct_process_claim(path: Path) -> bool:
    """Whether exec'ing *path* yields a directly identifiable process image."""
    if sys.platform != "linux" or not Path("/proc/self/exe").exists():
        return False
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def build_session_host_claim(
    frontend: Frontend,
    executable: str | os.PathLike[str],
    *,
    uid: int | None = None,
) -> SessionHostClaim:
    """Capture the selected executable's stable file identity."""
    path = _safe_executable_path(os.fspath(executable))
    st = path.stat()
    owner_uid = os.geteuid() if uid is None else uid
    if (
        isinstance(owner_uid, bool)
        or not isinstance(owner_uid, int)
        or owner_uid < 0
        or owner_uid > _MAX_IDENTITY_INTEGER
    ):
        raise ValueError("frontend owner uid is invalid")
    return SessionHostClaim(
        frontend=frontend,
        uid=owner_uid,
        executable=path,
        executable_device=st.st_dev,
        executable_inode=st.st_ino,
    )


def _parse_uint(value: object, field: str, *, positive: bool = False) -> int:
    if isinstance(value, bool):
        raise HostClaimError(f"{field} must be an integer")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.isascii() and value.isdigit():
        number = int(value)
        if str(number) != value:
            raise HostClaimError(f"{field} must use canonical decimal")
    else:
        raise HostClaimError(f"{field} must be an integer")
    minimum = 1 if positive else 0
    if number < minimum or number > _MAX_IDENTITY_INTEGER:
        raise HostClaimError(f"{field} is outside the supported range")
    return number


def _parse_executable(value: object, field: str) -> Path:
    if not isinstance(value, str):
        raise HostClaimError(f"{field} must be a string")
    if not value or len(value) > _MAX_EXECUTABLE_PATH or not value.isprintable():
        raise HostClaimError(f"{field} is empty, too long, or non-printable")
    path = Path(value)
    if not path.is_absolute():
        raise HostClaimError(f"{field} must be absolute")
    return path


def _claim_from_values(values: Mapping[str, object]) -> SessionHostClaim:
    if values["version"] != HOST_CLAIM_VERSION:
        raise HostClaimError(f"unknown host claim version {values['version']!r}")
    raw_frontend = values["frontend"]
    if not isinstance(raw_frontend, str):
        raise HostClaimError("host frontend must be a string")
    try:
        frontend = Frontend(raw_frontend)
    except ValueError as exc:
        raise HostClaimError(f"unknown host frontend {raw_frontend!r}") from exc
    return SessionHostClaim(
        frontend=frontend,
        uid=_parse_uint(values["uid"], "host uid"),
        executable=_parse_executable(
            values["executable"],
            "host executable",
        ),
        executable_device=_parse_uint(
            values["device"],
            "host executable device",
        ),
        executable_inode=_parse_uint(
            values["inode"],
            "host executable inode",
            positive=True,
        ),
    )


def _claim_presence(
    fields: Mapping[str, object],
    *,
    keys: tuple[str, ...],
    prefix: str,
) -> bool:
    known = set(keys)
    unknown = [
        key
        for key in fields
        if isinstance(key, str)
        and (key == prefix or key.startswith(prefix + "_"))
        and key not in known
    ]
    present = [key for key in keys if key in fields]
    if unknown:
        raise HostClaimError(
            "unknown host claim field(s): " + ", ".join(sorted(unknown))
        )
    if present and len(present) != len(keys):
        missing = [key for key in keys if key not in fields]
        raise HostClaimError("partial host claim; missing: " + ", ".join(missing))
    return bool(present)


def parse_session_host_claim(
    fields: Mapping[str, object],
) -> SessionHostClaim | None:
    """Parse optional ``sessions.d`` host fields without downgrading errors."""
    if not _claim_presence(fields, keys=SESSION_HOST_KEYS, prefix="host"):
        return None
    return _claim_from_values(
        {
            "version": fields["host_v"],
            "frontend": fields["host"],
            "uid": fields["host_uid"],
            "executable": fields["host_exe"],
            "device": fields["host_exe_dev"],
            "inode": fields["host_exe_ino"],
        }
    )


def parse_metadata_host_claim(
    metadata: Mapping[str, object],
) -> SessionHostClaim | None:
    """Parse optional run-metadata host fields with the same strictness."""
    if not _claim_presence(
        metadata,
        keys=RUN_HOST_KEYS,
        prefix="session_host",
    ):
        return None
    return _claim_from_values(
        {
            "version": metadata["session_host_v"],
            "frontend": metadata["session_host"],
            "uid": metadata["session_host_uid"],
            "executable": metadata["session_host_exe"],
            "device": metadata["session_host_exe_dev"],
            "inode": metadata["session_host_exe_ino"],
        }
    )


def process_uid(pid: int) -> int | None:
    """Owner uid for *pid* on Linux, or ``None`` when unverifiable."""
    if sys.platform != "linux":
        return None
    try:
        return os.stat(f"/proc/{pid}").st_uid
    except OSError:
        return None


def process_executable_identity(pid: int) -> tuple[int, int] | None:
    """``(device, inode)`` for the live process image on Linux."""
    if sys.platform != "linux":
        return None
    try:
        st = os.stat(f"/proc/{pid}/exe")
    except OSError:
        return None
    return st.st_dev, st.st_ino


def frontend_matches_comm(frontend: Frontend, comm: str | None) -> bool:
    """Strong claims accept only the selected host's process-name family."""
    if comm is None:
        return False
    name = comm.strip().lower()
    prefix = frontend.value
    return name == prefix or name.startswith(prefix + "-")


def host_process_matches(
    pid: int,
    claim: SessionHostClaim,
    *,
    pid_running: Callable[[int], bool],
    comm_reader: Callable[[int], str | None],
    uid_reader: Callable[[int], int | None] = process_uid,
    executable_identity_reader: Callable[
        [int], tuple[int, int] | None
    ] = process_executable_identity,
) -> bool:
    """Verify a strong host claim against the exact live process."""
    if claim.uid != os.geteuid() or not pid_running(pid):
        return False
    if uid_reader(pid) != claim.uid:
        return False
    if not frontend_matches_comm(claim.frontend, comm_reader(pid)):
        return False
    return executable_identity_reader(pid) == (
        claim.executable_device,
        claim.executable_inode,
    )


__all__ = [
    "Frontend",
    "HOST_CLAIM_VERSION",
    "HostClaimError",
    "RUN_HOST_KEYS",
    "SESSION_HOST_KEYS",
    "SessionHostClaim",
    "SessionOwner",
    "build_session_host_claim",
    "frontend_matches_comm",
    "host_process_matches",
    "parse_metadata_host_claim",
    "parse_session_host_claim",
    "process_executable_identity",
    "process_uid",
]
