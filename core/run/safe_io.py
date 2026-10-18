"""Symlink-safe run-dir and private-artifact helpers for raptor outputs.

The standard run-dir naming pattern in :func:`core.run.output.unique_run_suffix`
is ``timestamp + PID``, predictable to a co-resident local attacker. Combined
with the codebase's prevalent ``Path.mkdir(exist_ok=True)`` pattern, that gives
a TOCTOU window where an attacker can pre-create the predicted path as a
symlink and redirect raptor's writes to a chosen target.

This module's :func:`safe_run_mkdir` closes that window:

  - :func:`os.mkdir` (not ``Path.mkdir``) creates the dir atomically with the
    requested mode. ``Path.mkdir`` calls ``os.mkdir`` underneath, but using the
    raw call here makes the umask-vs-mode interaction explicit.
  - On :class:`FileExistsError`, :func:`os.lstat` reads the path metadata
    without following symlinks. We refuse if the path is anything other than a
    real directory owned by the current user, or if it is world-writable.

Group-writable existing dirs (e.g. mode ``0o775`` from default umask ``0o002``
on systemd-style "user private group" setups) are accepted with a logged
warning rather than refused. The default-umask shape would otherwise refuse
on every existing dir during upgrade.

The check guards the *final* path component only; symlinks higher in the path
resolve normally. An attacker who can manipulate parent directories has access
beyond what this module is intended to defend against.

Threat model assumptions:
  - Single-tenant or low-trust-multi-tenant analysis box
  - Attacker can read ``/proc`` to enumerate PIDs and predict the next one
  - Attacker has write access under the parent of the run-dir-to-be
  - Attacker does NOT share the user's UID

Private diagnostic JSON uses the same final-component no-follow posture and
mode 0600. Machine-readable artifact references are redacted, control-escaped,
and bounded per entry and in aggregate before crossing a report boundary.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from core.logging import get_logger

logger = get_logger()

ARTIFACT_REFERENCE_MAX_BYTES = 1024
ARTIFACT_REFERENCE_MAX_COUNT = 64
ARTIFACT_REFERENCES_MAX_BYTES = 32 * 1024
PRIVATE_TEXT_MAX_BYTES = 1024 * 1024 + 64
_ARTIFACT_RECORD_MAX_DEPTH = 12
_ARTIFACT_FIELD_NAMES = frozenset({
    "artifact",
    "artifacts",
    "artifact_references_truncated",
    "artifact_references_omitted",
})


class UnsafeRunDirError(PermissionError):
    """Raised when an output dir cannot be created or used safely."""


def safe_run_mkdir(path: Path | str) -> None:
    """Create *path* if absent, or accept it if already present and safe.

    Behaviour:
      - If *path* does not exist: created via :func:`os.mkdir` with mode
        ``0o700``, then ``fchmod``'d to ``0o700`` through an
        ``O_DIRECTORY|O_NOFOLLOW`` handle — the mkdir mode alone is
        masked by the caller's umask (a ``0o277`` umask yielded
        ``0o500``), and a path-based chmod could follow an entry
        swapped by a parent-writing attacker.
      - If *path* exists as a real directory owned by the current user and
        not world-writable: accepted (no chmod, no chown).
      - Group-writable existing dirs: accepted with a warning logged.
      - Anything else (symlink, regular file, foreign UID, world-writable):
        :class:`UnsafeRunDirError` raised.

    The function is idempotent for safe pre-existing dirs. It does NOT create
    intermediate parents — callers should ensure the parent exists, or use
    :func:`pathlib.Path.parent.mkdir` separately for parents that are not
    raptor-controlled run-dirs.
    """
    path = Path(path)

    try:
        os.mkdir(path, mode=0o700)
    except FileExistsError:
        pass
    else:
        # The mkdir mode is masked by the process umask (0o277 gave
        # 0o500) — restore the full owner triplet through a handle on
        # the directory we just created, so a hostile umask cannot
        # strip our own write bit and an attacker who can rewrite the
        # parent cannot redirect a path-based chmod.
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY
                     | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
        return

    st = os.lstat(path)

    if not stat.S_ISDIR(st.st_mode):
        msg = (
            f"refusing non-directory output path: {path} "
            f"(may be a symlink or regular file)"
        )
        raise UnsafeRunDirError(msg)

    euid = os.geteuid()
    if st.st_uid != euid:
        msg = (
            f"output dir not owned by current user "
            f"(uid {st.st_uid} ≠ {euid}): {path}"
        )
        raise UnsafeRunDirError(msg)

    if st.st_mode & 0o002:
        msg = (
            f"output dir is world-writable "
            f"(mode {oct(st.st_mode & 0o777)}): {path} "
            f"— chmod o-w to use, or move the dir"
        )
        raise UnsafeRunDirError(msg)

    if st.st_mode & 0o020:
        logger.warning(
            f"output dir is group-writable "
            f"(mode {oct(st.st_mode & 0o777)}, gid {st.st_gid}): {path} "
            f"— attacker injection possible if group has untrusted members"
        )


def write_private_text(
    path: Path | str,
    text: str,
    *,
    max_bytes: int = PRIVATE_TEXT_MAX_BYTES,
) -> Path:
    """Write bounded UTF-8 text through a no-follow mode-0600 handle.

    Private diagnostics are often redacted but still operationally sensitive.
    The byte ceiling keeps an attacker-controlled stderr relay from turning
    this helper into an unbounded disk sink. ``O_NOFOLLOW`` refuses a planted
    final-component symlink, while ``fchmod`` restores mode 0600 even under a
    hostile umask.
    """
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    raw = text.encode("utf-8")
    if len(raw) > max_bytes:
        raise ValueError(
            f"private text exceeds byte budget "
            f"({len(raw)} > {max_bytes})"
        )

    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError(
                errno.EINVAL,
                "refusing non-regular private text artifact",
                str(path),
            )
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise OSError(
                    errno.EIO,
                    "short write to private text artifact",
                    str(path),
                )
            offset += written
    finally:
        os.close(fd)
    return path


def write_private_json(path: Path | str, data: Any) -> Path:
    """Write JSON through a no-follow regular-file handle at mode 0600.

    Diagnostic receipts can contain redacted-but-sensitive operational
    evidence. Unlike a path-based ``write`` followed by ``chmod``, the mode is
    fixed on the opened inode before bytes are emitted, and ``O_NOFOLLOW``
    refuses a pre-planted final-component symlink.
    """
    from core.json import dumps_artifact

    path = Path(path)
    content = dumps_artifact(data)
    if not content.endswith("\n"):
        content += "\n"

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError(
                errno.EINVAL,
                "refusing non-regular private JSON artifact",
                str(path),
            )
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as artifact:
            fd = -1
            artifact.write(content)
    finally:
        if fd >= 0:
            os.close(fd)
    return path


def _truncate_reference_bytes(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    digest = hashlib.sha256(encoded).hexdigest()[:12]
    suffix = f"...[sha256:{digest}]"
    budget = max(max_bytes - len(suffix.encode("ascii")), 0)
    prefix = encoded[:budget].decode("utf-8", errors="ignore")
    return prefix + suffix


def sanitise_artifact_reference(value: object) -> str:
    """Redact, control-escape, and byte-bound one artifact reference."""
    from core.security.log_sanitisation import escape_nonprintable
    from core.security.redaction import redact_secrets

    safe = escape_nonprintable(redact_secrets(str(value)))
    return _truncate_reference_bytes(safe, ARTIFACT_REFERENCE_MAX_BYTES)


def _reference_candidates(
    values: Iterable[object] | object | None,
) -> list[object]:
    if values is None:
        return []
    if isinstance(values, (str, bytes, Path)):
        return [values]
    try:
        return list(values)  # type: ignore[arg-type]
    except TypeError:
        return [values]


def bounded_artifact_reference_fields(
    values: Iterable[object] | object | None,
) -> dict[str, object]:
    """Build bounded ``artifacts``/``artifact`` report fields.

    Limits apply both per reference and across the array. Omitted references
    are counted explicitly rather than represented by a fake path entry.
    """
    refs: list[str] = []
    seen: set[str] = set()
    omitted = 0
    total_bytes = 0
    for value in _reference_candidates(values):
        if value is None:
            continue
        safe = sanitise_artifact_reference(value)
        if not safe or safe in seen:
            continue
        ref_bytes = len(safe.encode("utf-8"))
        separator_bytes = 1 if refs else 0
        if (
            len(refs) >= ARTIFACT_REFERENCE_MAX_COUNT
            or total_bytes + separator_bytes + ref_bytes
            > ARTIFACT_REFERENCES_MAX_BYTES
        ):
            omitted += 1
            continue
        refs.append(safe)
        seen.add(safe)
        total_bytes += separator_bytes + ref_bytes

    fields: dict[str, object] = {"artifacts": refs}
    if refs:
        fields["artifact"] = refs[0]
    if omitted:
        fields["artifact_references_truncated"] = True
        fields["artifact_references_omitted"] = omitted
    return fields


def bound_artifact_references_in_record(
    record: dict[str, object] | None,
    *,
    _depth: int = 0,
) -> dict[str, object] | None:
    """Copy a report/enrichment record with every artifact array bounded."""
    if record is None:
        return None

    bounded: dict[str, object] = {}
    descend = _depth < _ARTIFACT_RECORD_MAX_DEPTH
    for key, value in record.items():
        if key in _ARTIFACT_FIELD_NAMES:
            continue
        if descend and isinstance(value, dict):
            bounded[key] = bound_artifact_references_in_record(
                value,
                _depth=_depth + 1,
            )
        elif descend and isinstance(value, list):
            bounded[key] = [
                (
                    bound_artifact_references_in_record(
                        item,
                        _depth=_depth + 1,
                    )
                    if isinstance(item, dict)
                    else item
                )
                for item in value
            ]
        else:
            bounded[key] = value

    if "artifacts" in record or "artifact" in record:
        source = record.get("artifacts")
        if source is None:
            source = [record.get("artifact")]
        fields = bounded_artifact_reference_fields(source)
        prior_omitted = record.get("artifact_references_omitted", 0)
        try:
            prior_omitted = max(int(prior_omitted), 0)
        except (TypeError, ValueError):
            prior_omitted = 0
        omitted = int(fields.get("artifact_references_omitted", 0))
        omitted += prior_omitted
        if omitted:
            fields["artifact_references_truncated"] = True
            fields["artifact_references_omitted"] = omitted
        bounded.update(fields)
    return bounded
