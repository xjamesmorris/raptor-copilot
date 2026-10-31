"""Interactive frontend preparation and verified host-process identity.

The interactive frontend, an installed executable, a verified session owner,
and a usable headless LLM provider are deliberately separate facts:

* :class:`FrontendPreparation` records the operator-selected frontend and
  whether an executable is installed.
* ``launch_state`` records whether this launcher is allowed to exec it.
* ``provider_usable`` is intentionally ``None`` here. Provider detection and
  admission live in ``core.llm`` and are not inferred from frontend presence.
* :class:`SessionHostClaim` binds a launcher-selected frontend to the owning
  process's uid and executable inode. It supplements (never replaces) the
  session token, starttime, boot-id, and pid-namespace checks.

Copilot launch is admitted only when the selected executable supports the
same direct Linux process-identity claim used by the session registry. There
is intentionally no environment-variable or payload escape hatch.
"""

from __future__ import annotations

import os
import shutil
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


class FrontendLaunchState(str, Enum):
    """Whether the interactive launcher may exec the selected frontend."""

    READY = "ready"
    MISSING = "missing"
    GATED = "gated"


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
class FrontendPreparation:
    """Result of resolving one explicitly configured interactive frontend.

    ``provider_usable`` is intentionally tri-state. ``None`` means this
    preparation did not evaluate a headless provider, preventing an installed
    CLI from being misreported as an admitted RAPTOR provider.
    """

    frontend: Frontend
    executable: Path | None
    launch_state: FrontendLaunchState
    provider_usable: bool | None
    session_claim: SessionHostClaim | None
    reason: str | None = None

    @property
    def installed(self) -> bool:
        return self.executable is not None

    @property
    def launchable(self) -> bool:
        return self.launch_state is FrontendLaunchState.READY


@dataclass(frozen=True)
class SessionOwner:
    """Resolved legacy or strongly verified frontend-session owner."""

    pid: int
    frontend: Frontend
    host_verified: bool
    host_claim: SessionHostClaim | None = None


def parse_frontend(value: str) -> Frontend:
    """Parse the explicit frontend selector without aliases or guessing."""
    try:
        return Frontend(value)
    except ValueError as exc:
        choices = ", ".join(item.value for item in Frontend)
        raise ValueError(
            f"unknown frontend {value!r} (expected one of: {choices})"
        ) from exc


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


def prepare_frontend(
    value: str,
    *,
    search_path: str | None = None,
) -> FrontendPreparation:
    """Resolve one frontend without inferring provider usability.

    Copilot requires a directly identifiable native Linux executable. A
    shebang wrapper or unsupported platform remains installed-but-gated
    instead of falling back to the legacy Claude-only identity path.
    """
    frontend = parse_frontend(value)
    found = shutil.which(frontend.value, path=search_path)
    if found is None:
        return FrontendPreparation(
            frontend=frontend,
            executable=None,
            launch_state=FrontendLaunchState.MISSING,
            provider_usable=None,
            session_claim=None,
            reason=f"{frontend.value} executable not found on hardened PATH",
        )
    try:
        executable = _safe_executable_path(found)
    except ValueError as exc:
        return FrontendPreparation(
            frontend=frontend,
            executable=None,
            launch_state=FrontendLaunchState.MISSING,
            provider_usable=None,
            session_claim=None,
            reason=str(exc),
        )
    supports_direct_claim = _supports_direct_process_claim(executable)
    if frontend is Frontend.COPILOT and not supports_direct_claim:
        return FrontendPreparation(
            frontend=frontend,
            executable=executable,
            launch_state=FrontendLaunchState.GATED,
            provider_usable=None,
            session_claim=None,
            reason=(
                "its live host contract is not verified because a directly "
                "identifiable native Linux executable is required"
            ),
        )
    claim = (
        build_session_host_claim(frontend, executable)
        if supports_direct_claim
        else None
    )
    return FrontendPreparation(
        frontend=frontend,
        executable=executable,
        launch_state=FrontendLaunchState.READY,
        provider_usable=None,
        session_claim=claim,
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
    """Accept the selected host's observed process-name shape.

    Copilot CLI's native Linux runtime names its main thread ``MainThread``.
    That value is non-authoritative; the caller must still verify the exact
    executable device/inode and uid before accepting the process.
    """
    if comm is None:
        return False
    name = comm.strip().lower()
    if frontend is Frontend.COPILOT and name == "mainthread":
        return True
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


def launcher_lines(preparation: FrontendPreparation) -> str:
    """Machine output consumed by ``bin/raptor`` for a launchable host."""
    if not preparation.launchable or preparation.executable is None:
        raise ValueError("frontend preparation is not launchable")
    lines = [f"launch_executable={preparation.executable}"]
    if preparation.session_claim is not None:
        lines.extend(
            f"{key}={value}"
            for key, value in preparation.session_claim.session_fields().items()
        )
    return "\n".join(lines)


def _main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(
            "usage: python3 -m core.startup.host <claude|copilot>",
            file=sys.stderr,
        )
        return 2
    try:
        preparation = prepare_frontend(argv[0])
    except ValueError as exc:
        print(f"raptor: {exc}", file=sys.stderr)
        return 2
    if preparation.launch_state is FrontendLaunchState.MISSING:
        if preparation.frontend is Frontend.CLAUDE:
            print("raptor: claude not found. Install Claude Code:", file=sys.stderr)
            print(
                "  https://docs.anthropic.com/en/docs/claude-code/overview",
                file=sys.stderr,
            )
            return 1
        print(
            "raptor: copilot not found. Install GitHub Copilot CLI "
            "before selecting --frontend copilot.",
            file=sys.stderr,
        )
        return 127
    if preparation.launch_state is FrontendLaunchState.GATED:
        print(
            "raptor: Copilot frontend is installed at "
            f"{preparation.executable}, but launch is disabled: "
            f"{preparation.reason or 'its live host contract is not verified'}; "
            "refusing before target trust checks, project activation, session "
            "state, plugin loading, or frontend execution.",
            file=sys.stderr,
        )
        return 78
    print(launcher_lines(preparation))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))


__all__ = [
    "Frontend",
    "FrontendLaunchState",
    "FrontendPreparation",
    "HOST_CLAIM_VERSION",
    "HostClaimError",
    "RUN_HOST_KEYS",
    "SESSION_HOST_KEYS",
    "SessionHostClaim",
    "SessionOwner",
    "build_session_host_claim",
    "frontend_matches_comm",
    "host_process_matches",
    "launcher_lines",
    "parse_frontend",
    "parse_metadata_host_claim",
    "parse_session_host_claim",
    "prepare_frontend",
    "process_executable_identity",
    "process_uid",
]
