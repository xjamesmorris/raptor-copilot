"""Read-only identity helpers used by offline receipt construction tests."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .canonical import sha256_hex
from .reasons import (
    ReasonCode,
    ReceiptRejection,
    VerificationDisposition,
    rejection,
)

MAX_TREE_ENTRIES = 4096
MAX_TREE_DEPTH = 16
MAX_TREE_BYTES = 536_870_912
MAX_TREE_FILE_BYTES = 268_435_456
_LOCK_RE = re.compile(r"^inuse\.[1-9][0-9]*\.lock$")
_EMPTY_SHA256 = sha256_hex(b"")


@dataclass(frozen=True, slots=True)
class TreeManifestRow:
    entry_type: str
    mode_octal: str
    size_bytes: int
    sha256: str
    relative_path: str


@dataclass(frozen=True, slots=True)
class BuiltTreeManifest:
    rows: tuple[TreeManifestRow, ...]
    sha256: str
    entry_count: int
    total_regular_file_bytes: int


@dataclass(frozen=True, slots=True)
class EmbeddedPayloadMatch:
    offset: int
    sha256: str


def _relative_path_valid(path: str) -> bool:
    if (
        not path
        or path.startswith("/")
        or path.startswith("./")
        or not path.isprintable()
        or "\t" in path
    ):
        return False
    components = path.split("/")
    return len(components) <= 16 and all(
        component not in {"", ".", ".."} and len(component.encode("utf-8")) <= 255
        for component in components
    )


def manifest_bytes(rows: tuple[TreeManifestRow, ...]) -> bytes:
    """Encode ``sha256-tree-v1`` rows in bytewise path order."""

    encoded_rows: list[tuple[bytes, bytes]] = []
    seen: set[bytes] = set()
    for row in rows:
        if (
            row.entry_type not in {"f", "d"}
            or re.fullmatch(r"[0-7]{4}", row.mode_octal) is None
            or row.size_bytes < 0
            or not _relative_path_valid(row.relative_path)
            or re.fullmatch(r"[0-9a-f]{64}", row.sha256) is None
        ):
            raise ValueError("invalid tree-manifest row")
        if row.entry_type == "d" and (
            row.size_bytes != 0 or row.sha256 != _EMPTY_SHA256
        ):
            raise ValueError("directory tree-manifest row is not canonical")
        encoded_path = row.relative_path.encode("utf-8")
        if encoded_path in seen:
            raise ValueError("duplicate tree-manifest path")
        seen.add(encoded_path)
        encoded_rows.append(
            (
                encoded_path,
                (
                    f"{row.entry_type}\t{row.mode_octal}\t{row.size_bytes}\t"
                    f"{row.sha256}\t{row.relative_path}\n"
                ).encode("utf-8"),
            )
        )
    return b"".join(row for _, row in sorted(encoded_rows))


def _hash_regular_file(path: Path) -> tuple[str, os.stat_result] | ReceiptRejection:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.EXECUTABLE_OPEN_FAILED,
        )
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            return rejection(
                VerificationDisposition.ARTIFACT_MISMATCH,
                ReasonCode.EXECUTABLE_NOT_REGULAR,
            )
        if before.st_nlink != 1:
            return rejection(
                VerificationDisposition.ARTIFACT_MISMATCH,
                ReasonCode.PATH_POLICY_VIOLATION,
            )
        if before.st_size > MAX_TREE_FILE_BYTES:
            return rejection(
                VerificationDisposition.ARTIFACT_MISMATCH,
                ReasonCode.DISTRIBUTION_MANIFEST_MISMATCH,
            )
        remaining = before.st_size
        digest = hashlib.sha256()
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                return rejection(
                    VerificationDisposition.ARTIFACT_MISMATCH,
                    ReasonCode.EXECUTABLE_IDENTITY_MISMATCH,
                )
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    before_tuple = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_size,
        before.st_nlink,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_tuple = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_size,
        after.st_nlink,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_tuple != after_tuple:
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.EXECUTABLE_IDENTITY_MISMATCH,
        )
    return digest.hexdigest(), after


def build_tree_manifest(root: Path) -> BuiltTreeManifest | ReceiptRejection:
    """Build a bounded no-symlink ``sha256-tree-v1`` manifest."""

    try:
        root_stat = root.lstat()
    except OSError:
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.DISTRIBUTION_UNRESOLVED,
        )
    if root.is_symlink() or not stat.S_ISDIR(root_stat.st_mode):
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.PATH_POLICY_VIOLATION,
        )

    rows: list[TreeManifestRow] = []
    total_bytes = 0
    stack: list[tuple[Path, str, int]] = [(root, "", 0)]
    while stack:
        directory, prefix, depth = stack.pop()
        if depth > MAX_TREE_DEPTH:
            return rejection(
                VerificationDisposition.ARTIFACT_MISMATCH,
                ReasonCode.DISTRIBUTION_MANIFEST_MISMATCH,
            )
        try:
            entries = sorted(
                os.scandir(directory),
                key=lambda entry: entry.name.encode("utf-8"),
                reverse=True,
            )
        except OSError:
            return rejection(
                VerificationDisposition.ARTIFACT_MISMATCH,
                ReasonCode.DISTRIBUTION_UNRESOLVED,
            )
        for entry in entries:
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            if not prefix and _LOCK_RE.fullmatch(entry.name):
                continue
            if not _relative_path_valid(relative):
                return rejection(
                    VerificationDisposition.ARTIFACT_MISMATCH,
                    ReasonCode.PATH_POLICY_VIOLATION,
                )
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError:
                return rejection(
                    VerificationDisposition.ARTIFACT_MISMATCH,
                    ReasonCode.DISTRIBUTION_UNRESOLVED,
                )
            if stat.S_ISLNK(entry_stat.st_mode):
                return rejection(
                    VerificationDisposition.ARTIFACT_MISMATCH,
                    ReasonCode.PATH_POLICY_VIOLATION,
                )
            if stat.S_ISDIR(entry_stat.st_mode):
                mode = f"{stat.S_IMODE(entry_stat.st_mode):04o}"
                rows.append(
                    TreeManifestRow(
                        entry_type="d",
                        mode_octal=mode,
                        size_bytes=0,
                        sha256=_EMPTY_SHA256,
                        relative_path=relative,
                    )
                )
                stack.append((Path(entry.path), relative, depth + 1))
            elif stat.S_ISREG(entry_stat.st_mode):
                result = _hash_regular_file(Path(entry.path))
                if isinstance(result, ReceiptRejection):
                    return result
                digest, stable_stat = result
                mode = f"{stat.S_IMODE(stable_stat.st_mode):04o}"
                total_bytes += stable_stat.st_size
                if total_bytes > MAX_TREE_BYTES:
                    return rejection(
                        VerificationDisposition.ARTIFACT_MISMATCH,
                        ReasonCode.DISTRIBUTION_MANIFEST_MISMATCH,
                    )
                rows.append(
                    TreeManifestRow(
                        entry_type="f",
                        mode_octal=mode,
                        size_bytes=stable_stat.st_size,
                        sha256=digest,
                        relative_path=relative,
                    )
                )
            else:
                return rejection(
                    VerificationDisposition.ARTIFACT_MISMATCH,
                    ReasonCode.EXECUTABLE_NOT_REGULAR,
                )
            if len(rows) > MAX_TREE_ENTRIES:
                return rejection(
                    VerificationDisposition.ARTIFACT_MISMATCH,
                    ReasonCode.DISTRIBUTION_MANIFEST_MISMATCH,
                )
    frozen_rows = tuple(sorted(rows, key=lambda row: row.relative_path.encode("utf-8")))
    encoded = manifest_bytes(frozen_rows)
    return BuiltTreeManifest(
        rows=frozen_rows,
        sha256=sha256_hex(encoded),
        entry_count=len(frozen_rows),
        total_regular_file_bytes=total_bytes,
    )


def find_embedded_payload(
    container: bytes,
    payload: bytes,
) -> EmbeddedPayloadMatch | ReceiptRejection:
    """Require exactly one exact payload occurrence in a bounded byte string."""

    if not payload:
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.ARTIFACT_IDENTITY_MISMATCH,
        )
    first = container.find(payload)
    if first < 0 or container.find(payload, first + 1) >= 0:
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.ARTIFACT_IDENTITY_MISMATCH,
        )
    return EmbeddedPayloadMatch(offset=first, sha256=sha256_hex(payload))


__all__ = [
    "BuiltTreeManifest",
    "EmbeddedPayloadMatch",
    "TreeManifestRow",
    "build_tree_manifest",
    "find_embedded_payload",
    "manifest_bytes",
]
