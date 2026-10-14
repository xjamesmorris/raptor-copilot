"""Passive Linux procfs collection for a trusted, same-EUID process."""

from __future__ import annotations

import hashlib
import errno
import os
import re
import stat
import sys
from typing import NoReturn

from .collector import collect_file_identity, collect_file_identity_at
from .collector_types import (
    DEFAULT_PROCFS_LIMITS,
    CollectionDisposition,
    CollectionFailure,
    CollectionReasonCode,
    DescriptorIdentity,
    DescriptorStat,
    EvidenceSubject,
    ExpectedMappedObject,
    ExpectedMappedObjects,
    FileCollectionRequest,
    FileEvidence,
    FileRole,
    LinuxProcessEvidence,
    MappedObjectEvidence,
    MappedObjectRole,
    MappingSegmentObservation,
    MonotonicDeadline,
    MountInfoRow,
    ParsedMountInfo,
    ParsedProcMaps,
    PathBindingState,
    PathObservation,
    PathPolicyId,
    ProcMapKind,
    ProcMapRow,
    ProcStatObservation,
    ProcfsLimits,
    TrustedProcessScope,
    collection_failure,
    errno_class,
)
from .schema import AbsolutePath, DeviceMajorMinor, Sha256


def _missing_pread(fd: int, size: int, offset: int) -> bytes:
    raise OSError(errno.ENOSYS, "pread unavailable")


def _missing_geteuid() -> int:
    return -1


_OS_OPEN = os.open
_CLOSE = os.close
_FSTAT = os.fstat
_STAT = os.stat
_PREAD = getattr(os, "pread", _missing_pread)
_READLINK = os.readlink
_GETEUID = getattr(os, "geteuid", _missing_geteuid)

_U64_MAX = 2**64 - 1
_MAPS_ESCAPE_RE = re.compile(rb"\\[0-7]{3}")
_DELETED_SUFFIX = b" (deleted)"
_MOUNT_ESCAPES = {
    b"011": b"\t",
    b"012": b"\n",
    b"040": b" ",
    b"134": b"\\",
}


def _after_proc_snapshot() -> None:
    """Fault-injection seam used only by focused tests."""


class _ProcAbort(ValueError):
    def __init__(self, failure: CollectionFailure) -> None:
        super().__init__(failure.reason_codes[0].value)
        self.failure = failure


def _abort(failure: CollectionFailure) -> NoReturn:
    raise _ProcAbort(failure)


def _safe_close(fd: int) -> None:
    try:
        _CLOSE(fd)
    except OSError:
        pass


def _deadline_or_default(
    deadline: MonotonicDeadline | None,
    seconds: float,
) -> MonotonicDeadline:
    return deadline if deadline is not None else MonotonicDeadline.after(seconds)


def _check_deadline(deadline: MonotonicDeadline) -> None:
    if deadline.expired():
        _abort(
            collection_failure(
                CollectionDisposition.LIMIT_EXCEEDED,
                CollectionReasonCode.DEADLINE_EXCEEDED,
                subject=EvidenceSubject.PROCESS,
                details={"stage": "proc_deadline"},
            )
        )


def _parse_unsigned(token: bytes, *, base: int, digits: int) -> int:
    if not token or len(token) > digits:
        raise ValueError("numeric field outside lexical bound")
    if base == 10:
        valid = all(0x30 <= byte <= 0x39 for byte in token)
    else:
        valid = all(
            0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x46 or 0x61 <= byte <= 0x66
            for byte in token
        )
    if not valid:
        raise ValueError("numeric field is malformed")
    value = int(token, base)
    if value > _U64_MAX:
        raise ValueError("numeric field exceeds u64")
    return value


def _parse_signed_decimal(token: bytes) -> int:
    body = token[1:] if token.startswith(b"-") else token
    if not body or len(body) > 20 or not all(0x30 <= byte <= 0x39 for byte in body):
        raise ValueError("signed numeric field is malformed")
    value = int(token, 10)
    if not -_U64_MAX <= value <= _U64_MAX:
        raise ValueError("signed numeric field exceeds bound")
    return value


def parse_proc_stat(raw: bytes) -> ProcStatObservation | CollectionFailure:
    """Parse ``/proc/<pid>/stat`` without splitting inside ``comm``."""

    if type(raw) is not bytes:
        raise TypeError("proc stat input must be bytes")
    try:
        if len(raw) > 16_384 or b"\0" in raw:
            raise ValueError("proc stat size or NUL invalid")
        line = raw[:-1] if raw.endswith(b"\n") else raw
        left = line.find(b"(")
        right = line.rfind(b")")
        if left <= 0 or right <= left or right + 2 > len(line):
            raise ValueError("proc stat framing invalid")
        pid_token = line[:left].strip()
        pid = _parse_unsigned(pid_token, base=10, digits=20)
        comm = line[left + 1 : right]
        fields = line[right + 1 :].strip().split()
        if len(fields) < 20 or len(fields[0]) != 1 or not fields[0].isascii():
            raise ValueError("proc stat fields missing")
        for token in fields[1:]:
            _parse_signed_decimal(token)
        parent_pid = _parse_unsigned(fields[1], base=10, digits=20)
        starttime = _parse_unsigned(fields[19], base=10, digits=20)
        return ProcStatObservation(
            pid=pid,
            comm=bytes(comm),
            state=fields[0].decode("ascii"),
            parent_pid=parent_pid,
            starttime_ticks=starttime,
        )
    except (UnicodeError, ValueError, OverflowError):
        return collection_failure(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.PROC_STAT_MALFORMED,
            subject=EvidenceSubject.PROC_STAT,
            details={"stage": "proc_stat"},
        )


def _bounded_lines(
    raw: bytes,
    *,
    byte_limit: int,
    line_limit: int,
    line_byte_limit: int,
    subject: EvidenceSubject,
    limit_reason: CollectionReasonCode,
) -> tuple[bytes, ...]:
    if len(raw) > byte_limit:
        _abort(
            collection_failure(
                CollectionDisposition.LIMIT_EXCEEDED,
                limit_reason,
                subject=subject,
                details={"stage": "parse", "bytes": len(raw), "limit": byte_limit},
            )
        )
    lines_list = raw.split(b"\n")
    if lines_list and lines_list[-1] == b"":
        lines_list.pop()
    lines = tuple(lines_list)
    if len(lines) > line_limit:
        _abort(
            collection_failure(
                CollectionDisposition.LIMIT_EXCEEDED,
                limit_reason,
                subject=subject,
                details={"stage": "parse", "count": len(lines), "limit": line_limit},
            )
        )
    if any(len(line) > line_byte_limit for line in lines):
        _abort(
            collection_failure(
                CollectionDisposition.LIMIT_EXCEEDED,
                limit_reason,
                subject=subject,
                details={"stage": "parse", "limit": line_byte_limit},
            )
        )
    return lines


def _parse_maps_row(line: bytes) -> ProcMapRow:
    fields = line.split(None, 5)
    if len(fields) not in {5, 6}:
        raise ValueError("maps field count invalid")
    address, permissions, offset_token, device, inode_token = fields[:5]
    pathname = fields[5] if len(fields) == 6 else None
    address_parts = address.split(b"-")
    device_parts = device.split(b":")
    if len(address_parts) != 2 or len(device_parts) != 2:
        raise ValueError("maps range or device invalid")
    start = _parse_unsigned(address_parts[0], base=16, digits=16)
    end = _parse_unsigned(address_parts[1], base=16, digits=16)
    offset = _parse_unsigned(offset_token, base=16, digits=16)
    major = _parse_unsigned(device_parts[0], base=16, digits=8)
    minor = _parse_unsigned(device_parts[1], base=16, digits=8)
    inode = _parse_unsigned(inode_token, base=10, digits=20)
    if start >= end:
        raise ValueError("maps range is empty or reversed")
    if (
        len(permissions) != 4
        or permissions[0:1] not in {b"r", b"-"}
        or permissions[1:2] not in {b"w", b"-"}
        or permissions[2:3] not in {b"x", b"-"}
        or permissions[3:4] not in {b"p", b"s"}
    ):
        raise ValueError("maps permissions invalid")
    deleted = False
    if pathname is not None:
        if _MAPS_ESCAPE_RE.search(pathname):
            raise _ProcAbort(
                collection_failure(
                    CollectionDisposition.MALFORMED_INPUT,
                    CollectionReasonCode.PATHNAME_ESCAPE_UNSUPPORTED,
                    subject=EvidenceSubject.PROC_MAPS,
                    details={"stage": "proc_maps"},
                )
            )
        if pathname.endswith(_DELETED_SUFFIX):
            pathname = pathname[: -len(_DELETED_SUFFIX)]
            deleted = True
    if pathname is None:
        kind = ProcMapKind.ANONYMOUS
    elif pathname.startswith(b"["):
        kind = ProcMapKind.SPECIAL
    elif pathname.startswith(b"/") and inode != 0:
        kind = ProcMapKind.FILE
    else:
        kind = ProcMapKind.OTHER
    return ProcMapRow(
        start=start,
        end=end,
        perms=permissions.decode("ascii"),
        offset=offset,
        major=major,
        minor=minor,
        inode=inode,
        pathname=bytes(pathname) if pathname is not None else None,
        deleted=deleted,
        kind=kind,
    )


def parse_proc_maps(
    raw: bytes,
    *,
    limits: ProcfsLimits = DEFAULT_PROCFS_LIMITS,
) -> ParsedProcMaps | CollectionFailure:
    """Parse a bounded proc maps snapshot while preserving pathname bytes."""

    if type(raw) is not bytes or not isinstance(limits, ProcfsLimits):
        raise TypeError("invalid proc maps argument type")
    try:
        lines = _bounded_lines(
            raw,
            byte_limit=limits.maps_bytes,
            line_limit=limits.maps_lines,
            line_byte_limit=limits.maps_line_bytes,
            subject=EvidenceSubject.PROC_MAPS,
            limit_reason=CollectionReasonCode.PROC_MAPS_LIMIT_EXCEEDED,
        )
        rows: list[ProcMapRow] = []
        seen: set[ProcMapRow] = set()
        previous_end = -1
        for line in lines:
            if not line:
                raise ValueError("blank maps row")
            row = _parse_maps_row(line)
            if row in seen:
                continue
            if row.start < previous_end:
                raise ValueError("maps rows overlap or regress")
            previous_end = row.end
            seen.add(row)
            rows.append(row)
        groups: dict[tuple[bytes, int, int, int, bool], int] = {}
        for row in rows:
            if row.kind is not ProcMapKind.FILE or row.pathname is None:
                continue
            key = (row.pathname, row.inode, row.major, row.minor, row.deleted)
            groups[key] = groups.get(key, 0) + 1
            if groups[key] > limits.mapping_segments_per_file:
                _abort(
                    collection_failure(
                        CollectionDisposition.LIMIT_EXCEEDED,
                        CollectionReasonCode.PROC_MAPS_LIMIT_EXCEEDED,
                        subject=EvidenceSubject.PROC_MAPS,
                        details={
                            "stage": "proc_maps",
                            "count": groups[key],
                            "limit": limits.mapping_segments_per_file,
                        },
                    )
                )
        if len(groups) > limits.unique_mapped_files:
            _abort(
                collection_failure(
                    CollectionDisposition.LIMIT_EXCEEDED,
                    CollectionReasonCode.PROC_MAPS_LIMIT_EXCEEDED,
                    subject=EvidenceSubject.PROC_MAPS,
                    details={
                        "stage": "proc_maps",
                        "count": len(groups),
                        "limit": limits.unique_mapped_files,
                    },
                )
            )
        return ParsedProcMaps(
            rows=tuple(rows),
            byte_count=len(raw),
            line_count=len(lines),
            sha256=Sha256(hashlib.sha256(raw).hexdigest()),
        )
    except _ProcAbort as exc:
        return exc.failure
    except (UnicodeError, ValueError, OverflowError):
        return collection_failure(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.PROC_MAPS_MALFORMED,
            subject=EvidenceSubject.PROC_MAPS,
            details={"stage": "proc_maps"},
        )


def _decode_mount_field(value: bytes) -> bytes:
    output = bytearray()
    index = 0
    while index < len(value):
        if value[index] != 0x5C:
            output.append(value[index])
            index += 1
            continue
        if index + 4 > len(value):
            raise ValueError("truncated mountinfo escape")
        code = value[index + 1 : index + 4]
        replacement = _MOUNT_ESCAPES.get(code)
        if replacement is None:
            raise ValueError("unknown mountinfo escape")
        output.extend(replacement)
        index += 4
    return bytes(output)


def _parse_mountinfo_row(line: bytes) -> MountInfoRow:
    halves = line.split(b" - ", 1)
    if len(halves) != 2:
        raise ValueError("mountinfo separator missing")
    before = halves[0].split()
    after = halves[1].split()
    if len(before) < 6 or len(after) < 3:
        raise ValueError("mountinfo fields missing")
    mount_id = _parse_unsigned(before[0], base=10, digits=20)
    parent_id = _parse_unsigned(before[1], base=10, digits=20)
    device = before[2].split(b":")
    if len(device) != 2:
        raise ValueError("mountinfo device invalid")
    major = _parse_unsigned(device[0], base=10, digits=10)
    minor = _parse_unsigned(device[1], base=10, digits=10)
    root = _decode_mount_field(before[3])
    mount_point = _decode_mount_field(before[4])
    if not root.startswith(b"/") or not mount_point.startswith(b"/"):
        raise ValueError("mountinfo path is not absolute")
    filesystem_type = after[0].decode("ascii", errors="strict")
    if not filesystem_type or not filesystem_type.isprintable():
        raise ValueError("mountinfo filesystem type invalid")
    return MountInfoRow(
        mount_id=mount_id,
        parent_id=parent_id,
        major=major,
        minor=minor,
        root=root,
        mount_point=mount_point,
        filesystem_type=filesystem_type,
    )


def parse_mountinfo(
    raw: bytes,
    *,
    limits: ProcfsLimits = DEFAULT_PROCFS_LIMITS,
) -> ParsedMountInfo | CollectionFailure:
    """Parse bounded mountinfo and reject ambiguous mount-point identities."""

    if type(raw) is not bytes or not isinstance(limits, ProcfsLimits):
        raise TypeError("invalid mountinfo argument type")
    try:
        lines = _bounded_lines(
            raw,
            byte_limit=limits.mountinfo_bytes,
            line_limit=limits.mountinfo_lines,
            line_byte_limit=limits.mountinfo_line_bytes,
            subject=EvidenceSubject.MOUNTINFO,
            limit_reason=CollectionReasonCode.MOUNTINFO_LIMIT_EXCEEDED,
        )
        rows = tuple(_parse_mountinfo_row(line) for line in lines if line)
        return ParsedMountInfo(
            rows=rows,
            byte_count=len(raw),
            line_count=len(lines),
            sha256=Sha256(hashlib.sha256(raw).hexdigest()),
        )
    except _ProcAbort as exc:
        return exc.failure
    except (UnicodeError, ValueError, OverflowError):
        return collection_failure(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.MOUNTINFO_MALFORMED,
            subject=EvidenceSubject.MOUNTINFO,
            details={"stage": "mountinfo"},
        )


def _read_bounded_fd(
    fd: int,
    *,
    max_bytes: int,
    deadline: MonotonicDeadline,
    subject: EvidenceSubject,
    limit_reason: CollectionReasonCode,
) -> bytes:
    output = bytearray()
    offset = 0
    while True:
        _check_deadline(deadline)
        try:
            chunk = _PREAD(fd, min(65_536, max_bytes + 1 - len(output)), offset)
        except OSError as exc:
            _abort(
                collection_failure(
                    CollectionDisposition.UNAVAILABLE,
                    CollectionReasonCode.PERMISSION_DENIED
                    if exc.errno in {1, 13}
                    else CollectionReasonCode.IO_ERROR,
                    subject=subject,
                    details={
                        "stage": "proc_read",
                        "errno_class": errno_class(exc.errno),
                    },
                )
            )
        if not chunk:
            return bytes(output)
        output.extend(chunk)
        offset += len(chunk)
        if len(output) > max_bytes:
            _abort(
                collection_failure(
                    CollectionDisposition.LIMIT_EXCEEDED,
                    limit_reason,
                    subject=subject,
                    details={
                        "stage": "proc_read",
                        "bytes": len(output),
                        "limit": max_bytes,
                    },
                )
            )


def _read_proc_file(
    proc_fd: int,
    name: str,
    *,
    max_bytes: int,
    deadline: MonotonicDeadline,
    subject: EvidenceSubject,
    unavailable_reason: CollectionReasonCode,
    limit_reason: CollectionReasonCode,
) -> bytes:
    try:
        fd = _OS_OPEN(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=proc_fd,
        )
    except OSError as exc:
        _abort(
            collection_failure(
                CollectionDisposition.UNAVAILABLE,
                CollectionReasonCode.PERMISSION_DENIED
                if exc.errno in {1, 13}
                else unavailable_reason,
                subject=subject,
                details={
                    "stage": "proc_open",
                    "errno_class": errno_class(exc.errno),
                },
            )
        )
    try:
        return _read_bounded_fd(
            fd,
            max_bytes=max_bytes,
            deadline=deadline,
            subject=subject,
            limit_reason=limit_reason,
        )
    finally:
        _safe_close(fd)


def _parse_effective_uid(raw: bytes) -> int:
    for line in raw.splitlines():
        if not line.startswith(b"Uid:"):
            continue
        fields = line[4:].split()
        if len(fields) != 4:
            break
        return _parse_unsigned(fields[1], base=10, digits=20)
    raise ValueError("effective uid unavailable")


def _namespace_inode(proc_fd: int, namespace: str) -> int:
    try:
        ns_fd = _OS_OPEN(
            "ns",
            os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=proc_fd,
        )
        try:
            text = _READLINK(namespace, dir_fd=ns_fd)
        finally:
            _safe_close(ns_fd)
    except OSError as exc:
        _abort(
            collection_failure(
                CollectionDisposition.UNAVAILABLE,
                CollectionReasonCode.PERMISSION_DENIED
                if exc.errno in {1, 13}
                else CollectionReasonCode.IO_ERROR,
                subject=EvidenceSubject.PROCESS,
                details={
                    "stage": "process_namespace",
                    "errno_class": errno_class(exc.errno),
                },
            )
        )
    match = re.fullmatch(r"[a-z]+:\[([0-9]{1,20})\]", text)
    if match is None:
        _abort(
            collection_failure(
                CollectionDisposition.MALFORMED_INPUT,
                CollectionReasonCode.PROC_STAT_MALFORMED,
                subject=EvidenceSubject.PROCESS,
                details={"stage": "process_namespace"},
            )
        )
    return int(match.group(1))


def _read_self_mount_namespace() -> int:
    try:
        text = _READLINK("/proc/self/ns/mnt")
    except OSError as exc:
        _abort(
            collection_failure(
                CollectionDisposition.UNAVAILABLE,
                CollectionReasonCode.MOUNTINFO_UNAVAILABLE,
                subject=EvidenceSubject.MOUNTINFO,
                details={
                    "stage": "mount_namespace",
                    "errno_class": errno_class(exc.errno),
                },
            )
        )
    match = re.fullmatch(r"mnt:\[([0-9]{1,20})\]", text)
    if match is None:
        _abort(
            collection_failure(
                CollectionDisposition.MALFORMED_INPUT,
                CollectionReasonCode.MOUNTINFO_MALFORMED,
                subject=EvidenceSubject.MOUNTINFO,
                details={"stage": "mount_namespace"},
            )
        )
    return int(match.group(1))


def _stat_exe(proc_fd: int) -> os.stat_result:
    try:
        return _STAT("exe", dir_fd=proc_fd, follow_symlinks=True)
    except OSError as exc:
        _abort(
            collection_failure(
                CollectionDisposition.UNAVAILABLE,
                CollectionReasonCode.PERMISSION_DENIED
                if exc.errno in {1, 13}
                else CollectionReasonCode.PROC_EXE_UNAVAILABLE,
                subject=EvidenceSubject.PROC_EXE,
                details={
                    "stage": "proc_exe",
                    "errno_class": errno_class(exc.errno),
                },
            )
        )


def _hash_proc_exe(
    proc_fd: int,
    scope: TrustedProcessScope,
    expected: ExpectedMappedObject,
    pre_stat: os.stat_result,
    *,
    limits: ProcfsLimits,
) -> FileEvidence:
    try:
        link = _READLINK("exe", dir_fd=proc_fd)
        if link.endswith(" (deleted)"):
            raise ValueError("deleted process executable")
        resolved = AbsolutePath(link)
        fd = _OS_OPEN("exe", os.O_RDONLY | os.O_CLOEXEC, dir_fd=proc_fd)
    except OSError as exc:
        _abort(
            collection_failure(
                CollectionDisposition.UNAVAILABLE,
                CollectionReasonCode.PERMISSION_DENIED
                if exc.errno in {1, 13}
                else CollectionReasonCode.PROC_EXE_UNAVAILABLE,
                subject=EvidenceSubject.PROC_EXE,
                details={
                    "stage": "proc_exe",
                    "errno_class": errno_class(exc.errno),
                },
            )
        )
    except (UnicodeError, ValueError):
        _abort(
            collection_failure(
                CollectionDisposition.UNAVAILABLE,
                CollectionReasonCode.PROC_EXE_UNAVAILABLE,
                subject=EvidenceSubject.PROC_EXE,
                details={"stage": "proc_exe"},
            )
        )
    deadline = MonotonicDeadline.after(limits.file_deadline_seconds)
    try:
        before = _FSTAT(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode
            & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
        ):
            _abort(
                collection_failure(
                    CollectionDisposition.POLICY_REJECTED,
                    CollectionReasonCode.PATH_POLICY_VIOLATION,
                    subject=EvidenceSubject.PROC_EXE,
                    details={"stage": "proc_exe"},
                )
            )
        if before.st_size > 268_435_456:
            _abort(
                collection_failure(
                    CollectionDisposition.LIMIT_EXCEEDED,
                    CollectionReasonCode.SIZE_LIMIT_EXCEEDED,
                    subject=EvidenceSubject.PROC_EXE,
                    details={
                        "stage": "proc_exe",
                        "bytes": before.st_size,
                        "limit": 268_435_456,
                    },
                )
            )
        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            if deadline.expired():
                _abort(
                    collection_failure(
                        CollectionDisposition.LIMIT_EXCEEDED,
                        CollectionReasonCode.DEADLINE_EXCEEDED,
                        subject=EvidenceSubject.PROC_EXE,
                        details={"stage": "proc_exe"},
                    )
                )
            chunk = _PREAD(fd, min(1_048_576, before.st_size - offset), offset)
            if not chunk:
                _abort(
                    collection_failure(
                        CollectionDisposition.MALFORMED_INPUT,
                        CollectionReasonCode.SHORT_READ,
                        subject=EvidenceSubject.PROC_EXE,
                        details={"stage": "proc_exe", "bytes": offset},
                    )
                )
            digest.update(chunk)
            offset += len(chunk)
        if _PREAD(fd, 1, before.st_size):
            _abort(
                collection_failure(
                    CollectionDisposition.CHANGED_DURING_COLLECTION,
                    CollectionReasonCode.FILE_MUTATED,
                    subject=EvidenceSubject.PROC_EXE,
                    details={"stage": "proc_exe"},
                )
            )
        after = _FSTAT(fd)
    except OSError as exc:
        _abort(
            collection_failure(
                CollectionDisposition.UNAVAILABLE,
                CollectionReasonCode.IO_ERROR,
                subject=EvidenceSubject.PROC_EXE,
                details={
                    "stage": "proc_exe",
                    "errno_class": errno_class(exc.errno),
                },
            )
        )
    finally:
        _safe_close(fd)
    identity = (
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
    after_identity = (
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
    if identity != after_identity or (
        pre_stat.st_dev,
        pre_stat.st_ino,
        pre_stat.st_size,
    ) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
    ):
        _abort(
            collection_failure(
                CollectionDisposition.CHANGED_DURING_COLLECTION,
                CollectionReasonCode.PROCESS_CHANGED,
                subject=EvidenceSubject.PROC_EXE,
                details={"stage": "proc_exe"},
            )
        )
    descriptor = DescriptorIdentity(
        stat=DescriptorStat(
            device=before.st_dev,
            inode=before.st_ino,
            mode_octal=f"{stat.S_IMODE(before.st_mode):04o}",
            uid=before.st_uid,
            gid=before.st_gid,
            size_bytes=before.st_size,
            nlink=before.st_nlink,
            mtime_ns=before.st_mtime_ns,
            ctime_ns=before.st_ctime_ns,
        ),
        sha256=digest.hexdigest(),
        format_id=expected.trusted_file.descriptor.format_id,
        elf_build_id_sha1=expected.trusted_file.descriptor.elf_build_id_sha1,
        bytes_hashed=before.st_size,
    )
    trusted = expected.trusted_file.descriptor
    if (
        descriptor.sha256 != trusted.sha256
        or descriptor.stat.device != trusted.stat.device
        or descriptor.stat.inode != trusted.stat.inode
        or descriptor.stat.size_bytes != trusted.stat.size_bytes
    ):
        _abort(
            collection_failure(
                CollectionDisposition.MISMATCH,
                CollectionReasonCode.MAPPED_MODULE_IDENTITY_MISMATCH,
                subject=EvidenceSubject.PROC_EXE,
                details={
                    "stage": "proc_exe",
                    "expected_sha256": trusted.sha256,
                    "observed_sha256": descriptor.sha256,
                },
            )
        )
    return FileEvidence(
        role=FileRole.PROC_EXE,
        descriptor=descriptor,
        path=PathObservation(
            requested_path=AbsolutePath(f"/proc/{scope.pid}/exe"),
            resolved_path=resolved,
            policy_id=PathPolicyId.PROC_EXE_MAGICLINK_V1,
            components=(),
            binding_state=PathBindingState.STABLE,
            asserted_prefix_components=0,
        ),
    )


def _path_is_beneath(path: bytes, root: bytes) -> bool:
    if root == b"/":
        return path.startswith(b"/")
    return path == root or path.startswith(root.rstrip(b"/") + b"/")


def _mount_for_path(
    path: bytes,
    mountinfo: ParsedMountInfo,
) -> MountInfoRow:
    matches = tuple(
        row for row in mountinfo.rows if _path_is_beneath(path, row.mount_point)
    )
    if not matches:
        _abort(
            collection_failure(
                CollectionDisposition.MISMATCH,
                CollectionReasonCode.MAPPED_DEVICE_UNVERIFIABLE,
                subject=EvidenceSubject.MOUNTINFO,
                details={"stage": "mount_match"},
            )
        )
    longest = max(len(row.mount_point) for row in matches)
    finalists = tuple(row for row in matches if len(row.mount_point) == longest)
    if len(finalists) != 1:
        _abort(
            collection_failure(
                CollectionDisposition.AMBIGUOUS,
                CollectionReasonCode.MOUNT_AMBIGUOUS,
                subject=EvidenceSubject.MOUNTINFO,
                details={"stage": "mount_match", "count": len(finalists)},
            )
        )
    return finalists[0]


def _recollect_expected(expected: ExpectedMappedObject) -> FileEvidence:
    trusted = expected.trusted_file
    request = FileCollectionRequest(
        role=trusted.role,
        absolute_path=trusted.path.resolved_path,
        expected_owner_uid=trusted.descriptor.stat.uid,
        allow_root_owner=True,
        require_executable=bool(
            int(trusted.descriptor.stat.mode_octal, 8)
            & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ),
        policy_id=trusted.path.policy_id,
        max_bytes=max(1, trusted.descriptor.stat.size_bytes),
        format_id=trusted.descriptor.format_id,
    )
    if expected.anchor_fd is None:
        result = collect_file_identity(request)
    else:
        if expected.anchor_path is None:
            _abort(
                collection_failure(
                    CollectionDisposition.INVALID_REQUEST,
                    CollectionReasonCode.INVALID_PATH,
                    subject=EvidenceSubject.PROCESS,
                    details={"stage": "mapped_reopen"},
                )
            )
        prefix = expected.anchor_path.value + "/"
        if not trusted.path.resolved_path.value.startswith(prefix):
            _abort(
                collection_failure(
                    CollectionDisposition.INVALID_REQUEST,
                    CollectionReasonCode.INVALID_PATH,
                    subject=EvidenceSubject.PROCESS,
                    details={"stage": "mapped_reopen"},
                )
            )
        result = collect_file_identity_at(
            expected.anchor_fd,
            expected.anchor_path,
            trusted.path.resolved_path.value[len(prefix) :],
            request,
        )
    if isinstance(result, CollectionFailure):
        _abort(result)
    if result.descriptor != trusted.descriptor:
        _abort(
            collection_failure(
                CollectionDisposition.MISMATCH,
                CollectionReasonCode.MAPPED_MODULE_IDENTITY_MISMATCH,
                subject=EvidenceSubject.PROCESS,
                details={
                    "stage": "mapped_reopen",
                    "expected_sha256": trusted.descriptor.sha256,
                    "observed_sha256": result.descriptor.sha256,
                },
            )
        )
    return result


def _optional_fdinfo_mount_id(expected: ExpectedMappedObject) -> int | None:
    trusted = expected.trusted_file
    fd = -1
    info_fd = -1
    try:
        if expected.anchor_fd is None:
            fd = _OS_OPEN(
                trusted.path.resolved_path.value,
                os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        else:
            if expected.anchor_path is None:
                return None
            prefix = expected.anchor_path.value + "/"
            if not trusted.path.resolved_path.value.startswith(prefix):
                return None
            fd = _OS_OPEN(
                trusted.path.resolved_path.value[len(prefix) :],
                os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=expected.anchor_fd,
            )
        observed = _FSTAT(fd)
        if (
            observed.st_dev != trusted.descriptor.stat.device
            or observed.st_ino != trusted.descriptor.stat.inode
        ):
            return None
        info_fd = _OS_OPEN(
            f"/proc/self/fdinfo/{fd}",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        raw = _read_bounded_fd(
            info_fd,
            max_bytes=16_384,
            deadline=MonotonicDeadline.after(1.0),
            subject=EvidenceSubject.MOUNTINFO,
            limit_reason=CollectionReasonCode.MOUNTINFO_LIMIT_EXCEEDED,
        )
        for line in raw.split(b"\n"):
            if not line.startswith(b"mnt_id:"):
                continue
            token = line[len(b"mnt_id:") :].strip()
            return _parse_unsigned(token, base=10, digits=20)
    except (OSError, ValueError, _ProcAbort):
        return None
    finally:
        if info_fd >= 0:
            _safe_close(info_fd)
        if fd >= 0:
            _safe_close(fd)
    return None


def _mapped_evidence(
    expected: ExpectedMappedObject,
    maps: ParsedProcMaps,
    mountinfo: ParsedMountInfo,
    *,
    limits: ProcfsLimits,
) -> MappedObjectEvidence:
    path = expected.trusted_file.path.resolved_path
    path_bytes = path.value.encode("utf-8")
    matching = tuple(
        row
        for row in maps.rows
        if row.kind is ProcMapKind.FILE and row.pathname == path_bytes
    )
    if not matching:
        _abort(
            collection_failure(
                CollectionDisposition.INCOMPLETE,
                CollectionReasonCode.MAPPED_MODULE_MISSING,
                subject=EvidenceSubject.PROCESS,
                details={"stage": "mapped_object", "role": expected.role},
            )
        )
    groups: dict[tuple[int, int, int, bool], list[ProcMapRow]] = {}
    for row in matching:
        groups.setdefault(
            (row.inode, row.major, row.minor, row.deleted),
            [],
        ).append(row)
    if len(groups) != 1:
        _abort(
            collection_failure(
                CollectionDisposition.AMBIGUOUS,
                CollectionReasonCode.MAPPED_MODULE_AMBIGUOUS,
                subject=EvidenceSubject.PROCESS,
                details={
                    "stage": "mapped_object",
                    "role": expected.role,
                    "count": len(groups),
                },
            )
        )
    (inode, major, minor, deleted), rows = next(iter(groups.items()))
    if len(rows) > limits.mapping_segments_per_file:
        _abort(
            collection_failure(
                CollectionDisposition.LIMIT_EXCEEDED,
                CollectionReasonCode.PROC_MAPS_LIMIT_EXCEEDED,
                subject=EvidenceSubject.PROC_MAPS,
                details={
                    "stage": "mapped_object",
                    "count": len(rows),
                    "limit": limits.mapping_segments_per_file,
                },
            )
        )
    if deleted:
        _abort(
            collection_failure(
                CollectionDisposition.MISMATCH,
                CollectionReasonCode.MAPPED_FILE_DELETED,
                subject=EvidenceSubject.PROCESS,
                details={"stage": "mapped_object", "role": expected.role},
            )
        )
    executable = any("x" in row.perms for row in rows)
    if not executable:
        _abort(
            collection_failure(
                CollectionDisposition.INCOMPLETE,
                CollectionReasonCode.MAPPED_MODULE_NOT_EXECUTABLE,
                subject=EvidenceSubject.PROCESS,
                details={"stage": "mapped_object", "role": expected.role},
            )
        )
    trusted = expected.trusted_file.descriptor
    if inode != trusted.stat.inode:
        _abort(
            collection_failure(
                CollectionDisposition.MISMATCH,
                CollectionReasonCode.MAPPED_MODULE_IDENTITY_MISMATCH,
                subject=EvidenceSubject.PROCESS,
                details={"stage": "mapped_object", "role": expected.role},
            )
        )
    mount = _mount_for_path(path_bytes, mountinfo)
    if (major, minor) != (mount.major, mount.minor):
        _abort(
            collection_failure(
                CollectionDisposition.MISMATCH,
                CollectionReasonCode.MAPPED_DEVICE_UNVERIFIABLE,
                subject=EvidenceSubject.PROCESS,
                details={"stage": "mapped_object", "role": expected.role},
            )
        )
    _recollect_expected(expected)
    fdinfo_mount_id = _optional_fdinfo_mount_id(expected)
    if fdinfo_mount_id is not None and fdinfo_mount_id != mount.mount_id:
        _abort(
            collection_failure(
                CollectionDisposition.AMBIGUOUS,
                CollectionReasonCode.MOUNT_AMBIGUOUS,
                subject=EvidenceSubject.MOUNTINFO,
                details={"stage": "fdinfo_mount"},
            )
        )
    return MappedObjectEvidence(
        role=expected.role,
        observed_path=path,
        mapped_inode=inode,
        maps_device=DeviceMajorMinor(f"{major}:{minor}"),
        mount_device=DeviceMajorMinor(f"{mount.major}:{mount.minor}"),
        mount_id=mount.mount_id,
        parent_mount_id=mount.parent_id,
        fdinfo_mount_id=fdinfo_mount_id,
        filesystem_type=mount.filesystem_type,
        executable_mapping=True,
        deleted=False,
        segments=tuple(
            MappingSegmentObservation(
                start=row.start,
                end=row.end,
                offset=row.offset,
                perms=row.perms,
            )
            for row in rows
        ),
    )


def _validate_scope(
    scope: TrustedProcessScope,
    expected: ExpectedMappedObjects,
) -> None:
    if (
        scope.pid <= 0
        or scope.expected_starttime_ticks < 0
        or scope.expected_euid < 0
        or scope.expected_pid_namespace_inode <= 0
        or scope.expected_mount_namespace_inode <= 0
        or scope.expected_euid != _GETEUID()
    ):
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.TRUSTED_SCOPE_INVALID,
                subject=EvidenceSubject.REQUEST,
                details={"stage": "process_scope", "pid": max(scope.pid, 0)},
            )
        )
    if expected.loader.role is not MappedObjectRole.LOADER:
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_ROLE_SET,
                subject=EvidenceSubject.REQUEST,
                details={"stage": "mapped_roles"},
            )
        )
    roles = tuple(item.role for item in expected.native_modules)
    if (
        len(roles) != 2
        or len(set(roles)) != 2
        or set(roles)
        != {
            MappedObjectRole.RUNTIME_NODE,
            MappedObjectRole.CLI_NATIVE_NODE,
        }
    ):
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_ROLE_SET,
                subject=EvidenceSubject.REQUEST,
                details={"stage": "mapped_roles"},
            )
        )
    for item in (expected.loader, *expected.native_modules):
        text = item.trusted_file.path.resolved_path.value
        if text.endswith(" (deleted)") or _MAPS_ESCAPE_RE.search(text.encode("utf-8")):
            _abort(
                collection_failure(
                    CollectionDisposition.INVALID_REQUEST,
                    CollectionReasonCode.INVALID_PATH,
                    subject=EvidenceSubject.REQUEST,
                    details={"stage": "mapped_path"},
                )
            )


def _process_scope_snapshot(
    proc_fd: int,
    *,
    limits: ProcfsLimits,
    deadline: MonotonicDeadline,
) -> tuple[ProcStatObservation, int, int, int]:
    stat_raw = _read_proc_file(
        proc_fd,
        "stat",
        max_bytes=16_384,
        deadline=deadline,
        subject=EvidenceSubject.PROC_STAT,
        unavailable_reason=CollectionReasonCode.IO_ERROR,
        limit_reason=CollectionReasonCode.PROC_MAPS_LIMIT_EXCEEDED,
    )
    parsed_stat = parse_proc_stat(stat_raw)
    if isinstance(parsed_stat, CollectionFailure):
        _abort(parsed_stat)
    status_raw = _read_proc_file(
        proc_fd,
        "status",
        max_bytes=262_144,
        deadline=deadline,
        subject=EvidenceSubject.PROCESS,
        unavailable_reason=CollectionReasonCode.IO_ERROR,
        limit_reason=CollectionReasonCode.PROC_MAPS_LIMIT_EXCEEDED,
    )
    try:
        effective_uid = _parse_effective_uid(status_raw)
    except (ValueError, OverflowError):
        _abort(
            collection_failure(
                CollectionDisposition.MALFORMED_INPUT,
                CollectionReasonCode.PROC_STAT_MALFORMED,
                subject=EvidenceSubject.PROCESS,
                details={"stage": "proc_status"},
            )
        )
    return (
        parsed_stat,
        effective_uid,
        _namespace_inode(proc_fd, "pid"),
        _namespace_inode(proc_fd, "mnt"),
    )


def collect_linux_process_evidence(
    scope: TrustedProcessScope,
    expected: ExpectedMappedObjects,
    *,
    limits: ProcfsLimits = DEFAULT_PROCFS_LIMITS,
    deadline: MonotonicDeadline | None = None,
) -> LinuxProcessEvidence | CollectionFailure:
    """Collect a point-in-time procfs observation for one trusted owned PID.

    The executable identity brackets the complete sample. Re-exec into the same
    inode and same-size image remains indistinguishable at this layer.
    """

    if (
        not isinstance(scope, TrustedProcessScope)
        or not isinstance(expected, ExpectedMappedObjects)
        or not isinstance(limits, ProcfsLimits)
    ):
        raise TypeError("invalid process collection argument type")
    if sys.platform != "linux":
        return collection_failure(
            CollectionDisposition.UNSUPPORTED_PLATFORM,
            CollectionReasonCode.PLATFORM_UNSUPPORTED,
            subject=EvidenceSubject.PROCESS,
            details={"stage": "platform"},
        )
    if any(
        getattr(os, name, None) is None
        for name in ("O_PATH", "O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "pread")
    ):
        return collection_failure(
            CollectionDisposition.UNSUPPORTED_PLATFORM,
            CollectionReasonCode.OS_PRIMITIVE_UNAVAILABLE,
            subject=EvidenceSubject.PROCESS,
            details={"stage": "platform"},
        )
    proc_deadline = _deadline_or_default(deadline, limits.proc_deadline_seconds)
    proc_fd = -1
    try:
        _validate_scope(scope, expected)
        try:
            proc_fd = _OS_OPEN(
                f"/proc/{scope.pid}",
                os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            proc_stat = _FSTAT(proc_fd)
        except OSError as exc:
            _abort(
                collection_failure(
                    CollectionDisposition.UNAVAILABLE,
                    CollectionReasonCode.PERMISSION_DENIED
                    if exc.errno in {1, 13}
                    else CollectionReasonCode.RESOURCE_NOT_FOUND,
                    subject=EvidenceSubject.PROCESS,
                    details={
                        "stage": "process_open",
                        "pid": scope.pid,
                        "errno_class": errno_class(exc.errno),
                    },
                )
            )
        if proc_stat.st_uid != scope.expected_euid:
            _abort(
                collection_failure(
                    CollectionDisposition.MISMATCH,
                    CollectionReasonCode.PROCESS_SCOPE_MISMATCH,
                    subject=EvidenceSubject.PROCESS,
                    details={"stage": "process_owner", "pid": scope.pid},
                )
            )
        exe_before = _stat_exe(proc_fd)
        before, euid, pid_ns, mount_ns = _process_scope_snapshot(
            proc_fd,
            limits=limits,
            deadline=proc_deadline,
        )
        if (
            before.pid != scope.pid
            or before.starttime_ticks != scope.expected_starttime_ticks
            or euid != scope.expected_euid
            or pid_ns != scope.expected_pid_namespace_inode
            or mount_ns != scope.expected_mount_namespace_inode
            or _read_self_mount_namespace() != scope.expected_mount_namespace_inode
        ):
            _abort(
                collection_failure(
                    CollectionDisposition.MISMATCH,
                    CollectionReasonCode.PROCESS_SCOPE_MISMATCH,
                    subject=EvidenceSubject.PROCESS,
                    details={"stage": "process_scope", "pid": scope.pid},
                )
            )
        maps_raw = _read_proc_file(
            proc_fd,
            "maps",
            max_bytes=limits.maps_bytes,
            deadline=proc_deadline,
            subject=EvidenceSubject.PROC_MAPS,
            unavailable_reason=CollectionReasonCode.PROC_MAPS_UNAVAILABLE,
            limit_reason=CollectionReasonCode.PROC_MAPS_LIMIT_EXCEEDED,
        )
        maps = parse_proc_maps(maps_raw, limits=limits)
        if isinstance(maps, CollectionFailure):
            _abort(maps)
        try:
            mount_fd = _OS_OPEN(
                "/proc/self/mountinfo",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        except OSError as exc:
            _abort(
                collection_failure(
                    CollectionDisposition.UNAVAILABLE,
                    CollectionReasonCode.PERMISSION_DENIED
                    if exc.errno in {1, 13}
                    else CollectionReasonCode.MOUNTINFO_UNAVAILABLE,
                    subject=EvidenceSubject.MOUNTINFO,
                    details={
                        "stage": "mountinfo_open",
                        "errno_class": errno_class(exc.errno),
                    },
                )
            )
        try:
            mount_raw = _read_bounded_fd(
                mount_fd,
                max_bytes=limits.mountinfo_bytes,
                deadline=proc_deadline,
                subject=EvidenceSubject.MOUNTINFO,
                limit_reason=CollectionReasonCode.MOUNTINFO_LIMIT_EXCEEDED,
            )
        finally:
            _safe_close(mount_fd)
        mountinfo = parse_mountinfo(mount_raw, limits=limits)
        if isinstance(mountinfo, CollectionFailure):
            _abort(mountinfo)

        proc_exe = _hash_proc_exe(
            proc_fd,
            scope,
            expected.loader,
            exe_before,
            limits=limits,
        )
        comm_raw = _read_proc_file(
            proc_fd,
            "comm",
            max_bytes=limits.comm_bytes + 1,
            deadline=proc_deadline,
            subject=EvidenceSubject.PROCESS,
            unavailable_reason=CollectionReasonCode.IO_ERROR,
            limit_reason=CollectionReasonCode.PROC_MAPS_LIMIT_EXCEEDED,
        )
        comm_line = comm_raw[:-1] if comm_raw.endswith(b"\n") else comm_raw
        comm_truncated = len(comm_line) > limits.comm_bytes
        comm_line = comm_line[: limits.comm_bytes]
        comm = comm_line.decode("utf-8", errors="replace")
        comm = "".join(
            character if character.isprintable() else "?" for character in comm
        )

        loader = _mapped_evidence(
            expected.loader,
            maps,
            mountinfo,
            limits=limits,
        )
        native_by_role = {item.role: item for item in expected.native_modules}
        native = tuple(
            _mapped_evidence(
                native_by_role[role],
                maps,
                mountinfo,
                limits=limits,
            )
            for role in (
                MappedObjectRole.RUNTIME_NODE,
                MappedObjectRole.CLI_NATIVE_NODE,
            )
        )
        distribution_root = expected.distribution_root.resolved_path.value.encode(
            "utf-8"
        )
        allowed_native_paths = {
            item.trusted_file.path.resolved_path.value.encode("utf-8")
            for item in expected.native_modules
        }
        unexpected = {
            row.pathname
            for row in maps.rows
            if row.kind is ProcMapKind.FILE
            and row.pathname is not None
            and "x" in row.perms
            and _path_is_beneath(row.pathname, distribution_root)
            and row.pathname not in allowed_native_paths
        }
        if unexpected:
            _abort(
                collection_failure(
                    CollectionDisposition.MISMATCH,
                    CollectionReasonCode.MAPPED_NATIVE_IMAGE_UNEXPECTED,
                    subject=EvidenceSubject.PROCESS,
                    details={
                        "stage": "mapped_closed_world",
                        "count": len(unexpected),
                    },
                )
            )
        _after_proc_snapshot()
        after, after_euid, after_pid_ns, after_mount_ns = _process_scope_snapshot(
            proc_fd,
            limits=limits,
            deadline=proc_deadline,
        )
        exe_after = _stat_exe(proc_fd)
        if (
            after.pid != before.pid
            or after.starttime_ticks != before.starttime_ticks
            or after_euid != euid
            or after_pid_ns != pid_ns
            or after_mount_ns != mount_ns
            or (
                exe_before.st_dev,
                exe_before.st_ino,
                exe_before.st_size,
            )
            != (
                exe_after.st_dev,
                exe_after.st_ino,
                exe_after.st_size,
            )
            or (
                exe_after.st_dev,
                exe_after.st_ino,
                exe_after.st_size,
            )
            != (
                proc_exe.descriptor.stat.device,
                proc_exe.descriptor.stat.inode,
                proc_exe.descriptor.stat.size_bytes,
            )
        ):
            _abort(
                collection_failure(
                    CollectionDisposition.CHANGED_DURING_COLLECTION,
                    CollectionReasonCode.PROCESS_CHANGED,
                    subject=EvidenceSubject.PROCESS,
                    details={"stage": "process_recheck", "pid": scope.pid},
                )
            )
        return LinuxProcessEvidence(
            observed_pid=scope.pid,
            starttime_before=before.starttime_ticks,
            starttime_after=after.starttime_ticks,
            observed_euid=euid,
            pid_namespace_inode=pid_ns,
            mount_namespace_inode=mount_ns,
            comm_observed=comm,
            comm_truncated=comm_truncated,
            comm_authoritative=False,
            proc_exe=proc_exe,
            loader_mapping=loader,
            native_mappings=(native[0], native[1]),
            maps_sha256=maps.sha256,
            maps_bytes=maps.byte_count,
            maps_lines=maps.line_count,
            mountinfo_sha256=mountinfo.sha256,
            mountinfo_bytes=mountinfo.byte_count,
            mountinfo_lines=mountinfo.line_count,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        RecursionError,
        OverflowError,
    ) as exc:
        if isinstance(exc, _ProcAbort):
            return exc.failure
        if isinstance(exc, OSError):
            return collection_failure(
                CollectionDisposition.UNAVAILABLE,
                CollectionReasonCode.PERMISSION_DENIED
                if exc.errno in {1, 13}
                else CollectionReasonCode.IO_ERROR,
                subject=EvidenceSubject.PROCESS,
                details={
                    "stage": "process_collection",
                    "errno_class": errno_class(exc.errno),
                },
            )
        return collection_failure(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.PROC_STAT_MALFORMED,
            subject=EvidenceSubject.PROCESS,
            details={"stage": "process_collection"},
        )
    finally:
        if proc_fd >= 0:
            _safe_close(proc_fd)


__all__ = [
    "collect_linux_process_evidence",
    "parse_mountinfo",
    "parse_proc_maps",
    "parse_proc_stat",
]
