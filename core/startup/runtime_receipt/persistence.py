"""Hardened explicit-root persistence for non-authorizing runtime receipts."""

from __future__ import annotations

import errno
import hmac
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterator, NoReturn, TypeVar

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised by primitive-removal tests
    fcntl = None  # type: ignore[assignment]

from .canonical import MAX_RECEIPT_BYTES, CanonicalValueError
from .plumbing_types import (
    MAX_POINTER_BYTES,
    CanonicalPid,
    CasApplied,
    CleanupApplied,
    ModeledPointer,
    PlumbingDisposition,
    PlumbingFailure,
    PlumbingReason,
    ReceiptReference,
    ReceiptState,
    StoredReceipt,
    authority_invariant_failure,
    plumbing_failure,
    parse_reference,
    reference_receipt_mismatch,
    reference_transition_mismatch,
    serialize_reference,
)
from .reasons import ReceiptRejection
from .schema import RuntimeReceipt
from .verify import parse_receipt, serialize_receipt

MAX_SESSION_ENTRY_BYTES = 16_384
_RECEIPT_FILE_RE = re.compile(
    r"^(?P<pid>[1-9][0-9]{0,19})\.receipt\."
    r"(?P<digest>[0-9a-f]{64})\.json(?P<temporary>\.tmp)?$"
)


class PersistenceCrashPoint(str, Enum):
    """Deterministic test seams around durable write and cleanup boundaries."""

    BEFORE_TEMP_CREATE = "before_temp_create"
    AFTER_TEMP_WRITE = "after_temp_write"
    AFTER_TEMP_FSYNC = "after_temp_fsync"
    AFTER_RENAME = "after_rename"
    AFTER_PARENT_FSYNC = "after_parent_fsync"
    AFTER_REREAD = "after_reread"
    BEFORE_CAS = "before_cas"
    AFTER_CAS = "after_cas"
    BEFORE_CLEANUP = "before_cleanup"
    AFTER_POINTER_UNLINK = "after_pointer_unlink"
    AFTER_SIDECAR_UNLINK = "after_sidecar_unlink"
    BEFORE_ENTRY_TEMP_CREATE = "before_entry_temp_create"
    AFTER_ENTRY_TEMP_WRITE = "after_entry_temp_write"
    AFTER_ENTRY_TEMP_FSYNC = "after_entry_temp_fsync"
    AFTER_ENTRY_RENAME = "after_entry_rename"
    AFTER_ENTRY_PARENT_FSYNC = "after_entry_parent_fsync"
    AFTER_ENTRY_REREAD = "after_entry_reread"
    BEFORE_ENTRY_UNLINK = "before_entry_unlink"
    AFTER_ENTRY_UNLINK = "after_entry_unlink"


CrashInjector = Callable[[PersistenceCrashPoint], None]
_ResultT = TypeVar("_ResultT")


class _PersistenceAbort(Exception):
    def __init__(self, failure: PlumbingFailure) -> None:
        super().__init__(failure.reason_codes[0].value)
        self.failure = failure


def _checked_persistence_result(
    value: _ResultT,
    expected_type: type[_ResultT],
    *,
    stage: str,
) -> _ResultT:
    failure = authority_invariant_failure(
        value,
        expected_type,
        disposition=PlumbingDisposition.PERSISTENCE_FAILED,
        details={"stage": stage},
    )
    if failure is not None:
        raise _PersistenceAbort(failure)
    return value


@dataclass(frozen=True, slots=True)
class _RootHandle:
    fd: int
    path: Path
    identity: tuple[int, int]


def _after_lock_open(root_fd: int, lock_name: str, lock_fd: int) -> None:
    """Test seam after opening a lock and before pathname revalidation."""


def _after_sidecar_read(root_fd: int, file_name: str, file_fd: int) -> None:
    """Test seam between the first and final sidecar fstat."""


def _after_pointer_read(root_fd: int, file_name: str, file_fd: int) -> None:
    """Test seam between the first and final pointer fstat."""


def _after_session_entry_read(
    root_fd: int,
    file_name: str,
    file_fd: int,
) -> None:
    """Test seam between the first and final session-entry fstat."""


def _current_euid() -> int:
    return os.geteuid()


def _entry_owner_matches(value: os.stat_result) -> bool:
    return value.st_uid == _current_euid()


def _errno_class(error_number: int | None) -> str:
    if error_number == errno.ENOENT:
        return "not_found"
    if error_number in {errno.EACCES, errno.EPERM}:
        return "permission_denied"
    if error_number == errno.ELOOP:
        return "loop"
    if error_number == errno.ENOTDIR:
        return "not_directory"
    if error_number in {errno.EAGAIN, errno.EWOULDBLOCK}:
        return "busy"
    if error_number in {errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP}:
        return "unsupported"
    return "other"


def _abort(
    disposition: PlumbingDisposition,
    *reasons: PlumbingReason,
    stage: str,
    error_number: int | None = None,
) -> NoReturn:
    details = {"stage": stage}
    if error_number is not None:
        details["errno_class"] = _errno_class(error_number)
    raise _PersistenceAbort(plumbing_failure(disposition, *reasons, details=details))


def _required_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int:
        _abort(
            PlumbingDisposition.UNSUPPORTED_PLATFORM,
            PlumbingReason.REQUIRED_OS_PRIMITIVE_MISSING,
            stage=name.lower(),
        )
    return int(value)


def _root_fingerprint(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        stat.S_IFMT(value.st_mode),
        stat.S_IMODE(value.st_mode),
        value.st_uid,
    )


def _file_fingerprint(
    value: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_nlink,
        value.st_mtime_ns,
        value.st_ctime_ns,
        stat.S_IFMT(value.st_mode),
    )


def _open_root(root: Path) -> _RootHandle:
    if not isinstance(root, Path):
        raise TypeError("root must be pathlib.Path")
    if not root.is_absolute():
        _abort(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
            stage="root_path",
        )
    flags = (
        os.O_RDONLY
        | _required_flag("O_DIRECTORY")
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_CLOEXEC")
        | _required_flag("O_NONBLOCK")
    )
    try:
        fd = os.open(root, flags)
    except OSError as exc:
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            PlumbingReason.ROOT_UNAVAILABLE,
            stage="root_open",
            error_number=exc.errno,
        )
    try:
        descriptor_stat = os.fstat(fd)
        path_stat = os.stat(root, follow_symlinks=False)
    except OSError as exc:
        os.close(fd)
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            PlumbingReason.ROOT_UNAVAILABLE,
            stage="root_stat",
            error_number=exc.errno,
        )
    if (
        not stat.S_ISDIR(descriptor_stat.st_mode)
        or not stat.S_ISDIR(path_stat.st_mode)
        or descriptor_stat.st_uid != _current_euid()
        or path_stat.st_uid != _current_euid()
        or stat.S_IMODE(descriptor_stat.st_mode) & 0o022
        or stat.S_IMODE(path_stat.st_mode) & 0o022
        or _root_fingerprint(descriptor_stat) != _root_fingerprint(path_stat)
    ):
        os.close(fd)
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            PlumbingReason.ROOT_POLICY_VIOLATION,
            stage="root_policy",
        )
    return _RootHandle(
        fd=fd,
        path=root,
        identity=(descriptor_stat.st_dev, descriptor_stat.st_ino),
    )


def _recheck_root(root: _RootHandle) -> None:
    try:
        descriptor_stat = os.fstat(root.fd)
        path_stat = os.stat(root.path, follow_symlinks=False)
    except OSError as exc:
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            PlumbingReason.ROOT_UNAVAILABLE,
            stage="root_recheck",
            error_number=exc.errno,
        )
    if (
        descriptor_stat.st_dev,
        descriptor_stat.st_ino,
    ) != root.identity or _root_fingerprint(descriptor_stat) != _root_fingerprint(
        path_stat
    ):
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            PlumbingReason.ROOT_POLICY_VIOLATION,
            stage="root_replaced",
        )


def _validate_regular_stat(
    value: os.stat_result,
    *,
    max_bytes: int,
    allow_empty: bool,
    reason: PlumbingReason,
    stage: str,
) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or not _entry_owner_matches(value)
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_nlink != 1
        or value.st_size > max_bytes
        or (not allow_empty and value.st_size == 0)
    ):
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            reason,
            stage=stage,
        )


def _regular_stat_is_valid(
    value: os.stat_result,
    *,
    max_bytes: int,
    allow_empty: bool,
) -> bool:
    return (
        stat.S_ISREG(value.st_mode)
        and _entry_owner_matches(value)
        and stat.S_IMODE(value.st_mode) == 0o600
        and value.st_nlink == 1
        and value.st_size <= max_bytes
        and (allow_empty or value.st_size > 0)
    )


def _stat_at(root_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            PlumbingReason.SIDECAR_READ_FAILED,
            stage="path_stat",
            error_number=exc.errno,
        )


@contextmanager
def _strict_lock(root: _RootHandle, pid: CanonicalPid) -> Iterator[None]:
    if fcntl is None:
        _abort(
            PlumbingDisposition.UNSUPPORTED_PLATFORM,
            PlumbingReason.STRICT_LOCK_UNAVAILABLE,
            stage="lock_import",
        )
    lock_name = f"{pid.text}.receipt.lock"
    flags = (
        os.O_RDWR
        | _required_flag("O_CLOEXEC")
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_NONBLOCK")
    )
    created = False
    try:
        try:
            lock_fd = os.open(
                lock_name,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=root.fd,
            )
            created = True
        except FileExistsError:
            lock_fd = os.open(lock_name, flags, dir_fd=root.fd)
    except OSError as exc:
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            PlumbingReason.LOCK_POLICY_VIOLATION,
            stage="lock_open",
            error_number=exc.errno,
        )
    operation_failed = False
    try:
        if created:
            os.fchmod(lock_fd, 0o600)
            os.fsync(lock_fd)
            os.fsync(root.fd)
        first = os.fstat(lock_fd)
        _validate_regular_stat(
            first,
            max_bytes=0,
            allow_empty=True,
            reason=PlumbingReason.LOCK_POLICY_VIOLATION,
            stage="lock_policy",
        )
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
                _abort(
                    PlumbingDisposition.STATE_CONFLICT,
                    PlumbingReason.CONCURRENT_FINALIZER,
                    stage="lock_busy",
                    error_number=exc.errno,
                )
            _abort(
                PlumbingDisposition.UNSUPPORTED_PLATFORM,
                PlumbingReason.STRICT_LOCK_UNAVAILABLE,
                stage="lock_acquire",
                error_number=exc.errno,
            )
        _after_lock_open(root.fd, lock_name, lock_fd)
        path_stat = _stat_at(root.fd, lock_name)
        second = os.fstat(lock_fd)
        if (
            path_stat is None
            or _file_fingerprint(first) != _file_fingerprint(second)
            or _file_fingerprint(second) != _file_fingerprint(path_stat)
        ):
            _abort(
                PlumbingDisposition.PERSISTENCE_FAILED,
                PlumbingReason.LOCK_REPLACED,
                stage="lock_recheck",
            )
        try:
            yield
        except BaseException:
            operation_failed = True
            raise
        finally:
            if not operation_failed:
                final_path = _stat_at(root.fd, lock_name)
                final_fd = os.fstat(lock_fd)
                if final_path is None or _file_fingerprint(
                    final_fd
                ) != _file_fingerprint(final_path):
                    _abort(
                        PlumbingDisposition.PERSISTENCE_FAILED,
                        PlumbingReason.LOCK_REPLACED,
                        stage="lock_release",
                    )
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def _read_regular_at(
    root_fd: int,
    name: str,
    *,
    max_bytes: int,
    allow_empty: bool = False,
    missing_reason: PlumbingReason,
    policy_reason: PlumbingReason,
    read_reason: PlumbingReason,
    after_read: Callable[[int, str, int], None],
) -> bytes:
    flags = (
        os.O_RDONLY
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_NONBLOCK")
        | _required_flag("O_CLOEXEC")
    )
    try:
        file_fd = os.open(name, flags, dir_fd=root_fd)
    except FileNotFoundError:
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            missing_reason,
            stage="file_open",
            error_number=errno.ENOENT,
        )
    except OSError as exc:
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            policy_reason,
            stage="file_open",
            error_number=exc.errno,
        )
    try:
        first = os.fstat(file_fd)
        _validate_regular_stat(
            first,
            max_bytes=max_bytes,
            allow_empty=allow_empty,
            reason=policy_reason,
            stage="file_policy",
        )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            try:
                chunk = os.read(file_fd, min(65_536, remaining))
            except OSError as exc:
                _abort(
                    PlumbingDisposition.PERSISTENCE_FAILED,
                    read_reason,
                    stage="file_read",
                    error_number=exc.errno,
                )
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after_read(root_fd, name, file_fd)
        second = os.fstat(file_fd)
        path_stat = _stat_at(root_fd, name)
        if (
            len(raw) != first.st_size
            or len(raw) > max_bytes
            or path_stat is None
            or _file_fingerprint(first) != _file_fingerprint(second)
            or _file_fingerprint(second) != _file_fingerprint(path_stat)
        ):
            _abort(
                PlumbingDisposition.PERSISTENCE_FAILED,
                read_reason,
                stage="file_changed",
            )
        return raw
    finally:
        os.close(file_fd)


def _hit(
    fault: CrashInjector | None,
    point: PersistenceCrashPoint,
) -> None:
    if fault is not None:
        fault(point)


def _write_all(file_fd: int, raw: bytes, *, reason: PlumbingReason) -> None:
    offset = 0
    while offset < len(raw):
        try:
            written = os.write(file_fd, raw[offset:])
        except OSError as exc:
            _abort(
                PlumbingDisposition.PERSISTENCE_FAILED,
                reason,
                stage="temp_write",
                error_number=exc.errno,
            )
        if written <= 0:
            _abort(
                PlumbingDisposition.PERSISTENCE_FAILED,
                reason,
                stage="temp_short_write",
            )
        offset += written


def _atomic_write_at(
    root_fd: int,
    *,
    final_name: str,
    temporary_name: str,
    raw: bytes,
    reason: PlumbingReason,
    fault: CrashInjector | None,
    crash_points: tuple[
        PersistenceCrashPoint,
        PersistenceCrashPoint,
        PersistenceCrashPoint,
        PersistenceCrashPoint,
        PersistenceCrashPoint,
    ] = (
        PersistenceCrashPoint.BEFORE_TEMP_CREATE,
        PersistenceCrashPoint.AFTER_TEMP_WRITE,
        PersistenceCrashPoint.AFTER_TEMP_FSYNC,
        PersistenceCrashPoint.AFTER_RENAME,
        PersistenceCrashPoint.AFTER_PARENT_FSYNC,
    ),
) -> None:
    if _stat_at(root_fd, temporary_name) is not None:
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            reason,
            stage="temp_exists",
        )
    before_create, after_write, after_fsync, after_rename, after_parent_fsync = (
        crash_points
    )
    _hit(fault, before_create)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_CLOEXEC")
        | _required_flag("O_NONBLOCK")
    )
    try:
        file_fd = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=root_fd,
        )
    except OSError as exc:
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            reason,
            stage="temp_open",
            error_number=exc.errno,
        )
    try:
        os.fchmod(file_fd, 0o600)
        _write_all(file_fd, raw, reason=reason)
        _hit(fault, after_write)
        os.fsync(file_fd)
        _hit(fault, after_fsync)
        temporary_stat = os.fstat(file_fd)
        _validate_regular_stat(
            temporary_stat,
            max_bytes=max(len(raw), 1),
            allow_empty=False,
            reason=reason,
            stage="temp_policy",
        )
        if temporary_stat.st_size != len(raw):
            _abort(
                PlumbingDisposition.PERSISTENCE_FAILED,
                reason,
                stage="temp_size",
            )
    finally:
        os.close(file_fd)
    try:
        os.replace(
            temporary_name,
            final_name,
            src_dir_fd=root_fd,
            dst_dir_fd=root_fd,
        )
        _hit(fault, after_rename)
        os.fsync(root_fd)
        _hit(fault, after_parent_fsync)
    except OSError as exc:
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            reason,
            stage="atomic_replace",
            error_number=exc.errno,
        )


def _read_sidecar_raw_at(
    root_fd: int,
    reference: ReceiptReference,
) -> bytes:
    return _read_regular_at(
        root_fd,
        reference.sidecar_name,
        max_bytes=MAX_RECEIPT_BYTES,
        missing_reason=PlumbingReason.SIDECAR_MISSING,
        policy_reason=PlumbingReason.SIDECAR_POLICY_VIOLATION,
        read_reason=PlumbingReason.SIDECAR_READ_FAILED,
        after_read=_after_sidecar_read,
    )


def _stored_receipt_from_raw(
    reference: ReceiptReference,
    raw: bytes,
) -> StoredReceipt:
    parsed = parse_receipt(raw)
    if isinstance(parsed, ReceiptRejection):
        raise _PersistenceAbort(
            plumbing_failure(
                PlumbingDisposition.PERSISTENCE_FAILED,
                PlumbingReason.SIDECAR_PARSE_FAILED,
                source_reason_codes=tuple(
                    reason.value for reason in parsed.reason_codes
                ),
            )
        )
    try:
        canonical = serialize_receipt(parsed)
    except CanonicalValueError:
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            PlumbingReason.SIDECAR_PARSE_FAILED,
            stage="sidecar_serialize",
        )
    if canonical != raw:
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            PlumbingReason.SIDECAR_PARSE_FAILED,
            stage="sidecar_noncanonical",
        )
    mismatch = reference_receipt_mismatch(reference, parsed)
    if mismatch is not None:
        if PlumbingReason.DIGEST_MISMATCH in mismatch.reason_codes:
            reason = PlumbingReason.SIDECAR_DIGEST_MISMATCH
            disposition = PlumbingDisposition.PERSISTENCE_FAILED
        elif PlumbingReason.INVALID_RECEIPT_REFERENCE in mismatch.reason_codes:
            reason = PlumbingReason.SIDECAR_PARSE_FAILED
            disposition = PlumbingDisposition.PERSISTENCE_FAILED
        else:
            reason = mismatch.reason_codes[0]
            disposition = mismatch.disposition
        raise _PersistenceAbort(
            plumbing_failure(
                disposition,
                reason,
                details=mismatch.details,
            )
        )
    return _checked_persistence_result(
        StoredReceipt(
            reference=reference,
            receipt=parsed,
            file_name=reference.sidecar_name,
            created=False,
        ),
        StoredReceipt,
        stage="sidecar_result",
    )


def _read_sidecar_at(
    root_fd: int,
    reference: ReceiptReference,
) -> StoredReceipt:
    return _stored_receipt_from_raw(
        reference,
        _read_sidecar_raw_at(root_fd, reference),
    )


def _read_session_entry_raw_at(
    root_fd: int,
    pid: CanonicalPid,
) -> bytes:
    return _read_regular_at(
        root_fd,
        pid.text,
        max_bytes=MAX_SESSION_ENTRY_BYTES,
        missing_reason=PlumbingReason.SESSION_ENTRY_MISSING,
        policy_reason=PlumbingReason.SESSION_ENTRY_POLICY_VIOLATION,
        read_reason=PlumbingReason.SESSION_ENTRY_INVALID,
        after_read=_after_session_entry_read,
    )


def session_entry_temporary_name(pid: CanonicalPid) -> str:
    """Return the one exact temporary name used by host-v2 entry writes."""
    if not isinstance(pid, CanonicalPid):
        raise TypeError("pid must be CanonicalPid")
    return f".{pid.text}.receipt-entry.tmp"


def _receipt_file_name_valid(
    pid: CanonicalPid,
    file_name: str,
    *,
    temporary: bool,
) -> bool:
    if not isinstance(file_name, str):
        return False
    match = _RECEIPT_FILE_RE.fullmatch(file_name)
    if match is None or bool(match.group("temporary")) is not temporary:
        return False
    try:
        named_pid = CanonicalPid.parse(match.group("pid"))
    except ValueError:
        return False
    return named_pid == pid


def _read_pointer_raw_at(
    root_fd: int,
    pid: CanonicalPid,
) -> bytes:
    name = f"{pid.text}.receipt-pointer-model.json"
    return _read_regular_at(
        root_fd,
        name,
        max_bytes=MAX_POINTER_BYTES,
        missing_reason=PlumbingReason.POINTER_MISSING,
        policy_reason=PlumbingReason.POINTER_INVALID,
        read_reason=PlumbingReason.POINTER_INVALID,
        after_read=_after_pointer_read,
    )


def _read_pointer_reference_at(
    root_fd: int,
    pid: CanonicalPid,
) -> ReceiptReference:
    raw = _read_pointer_raw_at(root_fd, pid)
    reference = parse_reference(raw)
    if isinstance(reference, PlumbingFailure):
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            PlumbingReason.POINTER_INVALID,
            stage="pointer_parse",
        )
    if reference.session_pid != pid:
        _abort(
            PlumbingDisposition.PERSISTENCE_FAILED,
            PlumbingReason.POINTER_INVALID,
            stage="pointer_pid",
        )
    return reference


def _read_modeled_pointer_at(
    root_fd: int,
    pid: CanonicalPid,
) -> ModeledPointer:
    reference = _read_pointer_reference_at(root_fd, pid)
    stored = _checked_persistence_result(
        _read_sidecar_at(root_fd, reference),
        StoredReceipt,
        stage="pointer_sidecar",
    )
    return _checked_persistence_result(
        ModeledPointer(
            reference=reference,
            receipt=stored.receipt,
            file_name=reference.pointer_name,
        ),
        ModeledPointer,
        stage="pointer_result",
    )


def _read_modeled_pointer_stable_at(
    root_fd: int,
    pid: CanonicalPid,
) -> ModeledPointer:
    for attempt in range(3):
        try:
            return _read_modeled_pointer_at(root_fd, pid)
        except _PersistenceAbort as exc:
            if exc.failure.details.get("stage") != "file_changed" or attempt == 2:
                raise
    raise AssertionError("bounded modeled-pointer read did not return")


def _references_equal(left: ReceiptReference, right: ReceiptReference) -> bool:
    return hmac.compare_digest(serialize_reference(left), serialize_reference(right))


def write_receipt_sidecar(
    root: Path,
    reference: ReceiptReference,
    receipt: RuntimeReceipt,
    *,
    fault: CrashInjector | None = None,
) -> StoredReceipt | PlumbingFailure:
    """Write one immutable content-addressed sidecar under an explicit root."""

    if not isinstance(reference, ReceiptReference):
        raise TypeError("reference must be ReceiptReference")
    if not isinstance(receipt, RuntimeReceipt):
        raise TypeError("receipt must be RuntimeReceipt")
    try:
        raw = serialize_receipt(receipt)
    except CanonicalValueError:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
        )
    parsed = parse_receipt(raw)
    if isinstance(parsed, ReceiptRejection):
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
            source_reason_codes=tuple(code.value for code in parsed.reason_codes),
        )
    mismatch = reference_receipt_mismatch(reference, parsed)
    if mismatch is not None:
        return mismatch
    try:
        root_handle = _open_root(root)
        try:
            created = False
            with _strict_lock(root_handle, reference.session_pid):
                existing = _stat_at(root_handle.fd, reference.sidecar_name)
                if existing is not None:
                    observed = _read_sidecar_raw_at(root_handle.fd, reference)
                    if not hmac.compare_digest(observed, raw):
                        _abort(
                            PlumbingDisposition.PERSISTENCE_FAILED,
                            PlumbingReason.SIDECAR_DIGEST_MISMATCH,
                            stage="sidecar_exists",
                        )
                else:
                    _atomic_write_at(
                        root_handle.fd,
                        final_name=reference.sidecar_name,
                        temporary_name=reference.sidecar_temporary_name,
                        raw=raw,
                        reason=PlumbingReason.SIDECAR_WRITE_FAILED,
                        fault=fault,
                    )
                    observed = _read_sidecar_raw_at(root_handle.fd, reference)
                    if not hmac.compare_digest(observed, raw):
                        _abort(
                            PlumbingDisposition.PERSISTENCE_FAILED,
                            PlumbingReason.SIDECAR_DIGEST_MISMATCH,
                            stage="sidecar_reread",
                        )
                    _hit(fault, PersistenceCrashPoint.AFTER_REREAD)
                    created = True
            stored = _checked_persistence_result(
                _read_sidecar_at(root_handle.fd, reference),
                StoredReceipt,
                stage="sidecar_verified",
            )
            if not hmac.compare_digest(serialize_receipt(stored.receipt), raw):
                _abort(
                    PlumbingDisposition.PERSISTENCE_FAILED,
                    PlumbingReason.SIDECAR_DIGEST_MISMATCH,
                    stage="sidecar_postlock",
                )
            return _checked_persistence_result(
                StoredReceipt(
                    reference=stored.reference,
                    receipt=stored.receipt,
                    file_name=stored.file_name,
                    created=created,
                ),
                StoredReceipt,
                stage="sidecar_write_result",
            )
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except _PersistenceAbort as exc:
        return exc.failure


def read_receipt_sidecar(
    root: Path,
    reference: ReceiptReference,
) -> StoredReceipt | PlumbingFailure:
    """Read exactly the sidecar named by a trusted explicit reference."""

    if not isinstance(reference, ReceiptReference):
        raise TypeError("reference must be ReceiptReference")
    try:
        root_handle = _open_root(root)
        try:
            with _strict_lock(root_handle, reference.session_pid):
                observed = _read_sidecar_raw_at(root_handle.fd, reference)
            stored = _checked_persistence_result(
                _read_sidecar_at(root_handle.fd, reference),
                StoredReceipt,
                stage="sidecar_read_result",
            )
            if not hmac.compare_digest(
                observed,
                serialize_receipt(stored.receipt),
            ):
                _abort(
                    PlumbingDisposition.PERSISTENCE_FAILED,
                    PlumbingReason.SIDECAR_READ_FAILED,
                    stage="sidecar_postlock",
                )
            return stored
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except _PersistenceAbort as exc:
        return exc.failure


def read_receipt_sidecar_bytes_for_registry(
    root: Path,
    reference: ReceiptReference,
) -> bytes | PlumbingFailure:
    """Read immutable sidecar bytes without taking the storage lock.

    Real-registry callers use this only while holding the separate session
    lock. Content-addressed policy and read/re-stat checks still apply.
    """
    if not isinstance(reference, ReceiptReference):
        raise TypeError("reference must be ReceiptReference")
    try:
        root_handle = _open_root(root)
        try:
            return _read_sidecar_raw_at(root_handle.fd, reference)
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except _PersistenceAbort as exc:
        return exc.failure


def read_receipt_file_bytes(
    root: Path,
    pid: CanonicalPid,
    file_name: str,
) -> bytes | PlumbingFailure:
    """Read one validated immutable receipt filename under its storage lock."""
    if not isinstance(pid, CanonicalPid):
        raise TypeError("pid must be CanonicalPid")
    if not _receipt_file_name_valid(pid, file_name, temporary=False):
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
        )
    try:
        root_handle = _open_root(root)
        try:
            with _strict_lock(root_handle, pid):
                return _read_regular_at(
                    root_handle.fd,
                    file_name,
                    max_bytes=MAX_RECEIPT_BYTES,
                    missing_reason=PlumbingReason.SIDECAR_MISSING,
                    policy_reason=PlumbingReason.SIDECAR_POLICY_VIOLATION,
                    read_reason=PlumbingReason.SIDECAR_READ_FAILED,
                    after_read=_after_sidecar_read,
                )
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except _PersistenceAbort as exc:
        return exc.failure


def read_session_entry_bytes(
    root: Path,
    pid: CanonicalPid,
    *,
    missing_ok: bool = False,
) -> bytes | None | PlumbingFailure:
    """Read one exact PID entry with the hardened regular-file policy."""
    if not isinstance(pid, CanonicalPid):
        raise TypeError("pid must be CanonicalPid")
    try:
        root_handle = _open_root(root)
        try:
            if missing_ok and _stat_at(root_handle.fd, pid.text) is None:
                return None
            return _read_session_entry_raw_at(root_handle.fd, pid)
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except _PersistenceAbort as exc:
        return exc.failure


def write_session_entry_bytes(
    root: Path,
    pid: CanonicalPid,
    raw: bytes,
    *,
    fault: CrashInjector | None = None,
) -> bytes | PlumbingFailure:
    """Atomically write and byte-verify one real-registry PID entry.

    The caller holds the PID's session lock. This helper never takes the
    receipt-storage lock and performs no receipt or reference parsing.
    """
    if not isinstance(pid, CanonicalPid):
        raise TypeError("pid must be CanonicalPid")
    if type(raw) is not bytes or not raw or len(raw) > MAX_SESSION_ENTRY_BYTES:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.SESSION_ENTRY_INVALID,
        )
    try:
        root_handle = _open_root(root)
        try:
            _atomic_write_at(
                root_handle.fd,
                final_name=pid.text,
                temporary_name=session_entry_temporary_name(pid),
                raw=raw,
                reason=PlumbingReason.SESSION_ENTRY_WRITE_FAILED,
                fault=fault,
                crash_points=(
                    PersistenceCrashPoint.BEFORE_ENTRY_TEMP_CREATE,
                    PersistenceCrashPoint.AFTER_ENTRY_TEMP_WRITE,
                    PersistenceCrashPoint.AFTER_ENTRY_TEMP_FSYNC,
                    PersistenceCrashPoint.AFTER_ENTRY_RENAME,
                    PersistenceCrashPoint.AFTER_ENTRY_PARENT_FSYNC,
                ),
            )
            observed = _read_session_entry_raw_at(root_handle.fd, pid)
            if not hmac.compare_digest(observed, raw):
                _abort(
                    PlumbingDisposition.PERSISTENCE_FAILED,
                    PlumbingReason.SESSION_ENTRY_WRITE_FAILED,
                    stage="entry_reread",
                )
            _hit(fault, PersistenceCrashPoint.AFTER_ENTRY_REREAD)
            return observed
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except _PersistenceAbort as exc:
        return exc.failure


def unlink_session_entry_if_bytes(
    root: Path,
    pid: CanonicalPid,
    expected_raw: bytes,
    *,
    fault: CrashInjector | None = None,
) -> bool | PlumbingFailure:
    """Unlink one real-registry entry only when its full bytes still match."""
    if not isinstance(pid, CanonicalPid):
        raise TypeError("pid must be CanonicalPid")
    if (
        type(expected_raw) is not bytes
        or not expected_raw
        or len(expected_raw) > MAX_SESSION_ENTRY_BYTES
    ):
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.SESSION_ENTRY_INVALID,
        )
    try:
        root_handle = _open_root(root)
        try:
            observed = _read_session_entry_raw_at(root_handle.fd, pid)
            if not hmac.compare_digest(observed, expected_raw):
                _abort(
                    PlumbingDisposition.STATE_CONFLICT,
                    PlumbingReason.SESSION_REPLACED,
                    stage="entry_unlink_recheck",
                )
            _hit(fault, PersistenceCrashPoint.BEFORE_ENTRY_UNLINK)
            try:
                os.unlink(pid.text, dir_fd=root_handle.fd)
                os.fsync(root_handle.fd)
            except OSError as exc:
                _abort(
                    PlumbingDisposition.CLEANUP_FAILED,
                    PlumbingReason.SESSION_ENTRY_CLEANUP_INCOMPLETE,
                    stage="entry_unlink",
                    error_number=exc.errno,
                )
            _hit(fault, PersistenceCrashPoint.AFTER_ENTRY_UNLINK)
            return True
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except _PersistenceAbort as exc:
        return exc.failure


def unlink_session_entry_temporary(
    root: Path,
    pid: CanonicalPid,
) -> bool | PlumbingFailure:
    """Remove only the exact host-v2 session-entry temporary."""
    if not isinstance(pid, CanonicalPid):
        raise TypeError("pid must be CanonicalPid")
    try:
        root_handle = _open_root(root)
        try:
            _unlink_regular_at(
                root_handle.fd,
                session_entry_temporary_name(pid),
                max_bytes=MAX_SESSION_ENTRY_BYTES,
                allow_empty=True,
                reason=PlumbingReason.SESSION_ENTRY_CLEANUP_INCOMPLETE,
            )
            return True
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except _PersistenceAbort as exc:
        return exc.failure


def unlink_receipt_file_exact(
    root: Path,
    pid: CanonicalPid,
    file_name: str,
    *,
    temporary: bool = False,
) -> bool | PlumbingFailure:
    """Remove one validated receipt sidecar or temporary by exact name."""
    if not isinstance(pid, CanonicalPid):
        raise TypeError("pid must be CanonicalPid")
    if not _receipt_file_name_valid(pid, file_name, temporary=temporary):
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
        )
    try:
        root_handle = _open_root(root)
        try:
            with _strict_lock(root_handle, pid):
                _unlink_regular_at(
                    root_handle.fd,
                    file_name,
                    max_bytes=MAX_RECEIPT_BYTES,
                    allow_empty=temporary,
                    reason=PlumbingReason.SIDECAR_CLEANUP_INCOMPLETE,
                )
            return True
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except _PersistenceAbort as exc:
        return exc.failure


def initialize_modeled_pointer(
    root: Path,
    reference: ReceiptReference,
    *,
    fault: CrashInjector | None = None,
) -> ModeledPointer | PlumbingFailure:
    """Model the only ``ABSENT -> PENDING`` pointer transition."""

    if reference.state is not ReceiptState.PENDING:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_TRANSITION,
            details={"state": reference.state.value},
        )
    try:
        raw = serialize_reference(reference)
        root_handle = _open_root(root)
        try:
            stored = _checked_persistence_result(
                _read_sidecar_at(root_handle.fd, reference),
                StoredReceipt,
                stage="pointer_initialize_sidecar",
            )
            sidecar_raw = serialize_receipt(stored.receipt)
            with _strict_lock(root_handle, reference.session_pid):
                if _stat_at(root_handle.fd, reference.pointer_name) is not None:
                    return plumbing_failure(
                        PlumbingDisposition.STATE_CONFLICT,
                        PlumbingReason.CAS_CONFLICT,
                        details={"state": reference.state.value},
                    )
                if not hmac.compare_digest(
                    _read_sidecar_raw_at(root_handle.fd, reference),
                    sidecar_raw,
                ):
                    _abort(
                        PlumbingDisposition.PERSISTENCE_FAILED,
                        PlumbingReason.SIDECAR_READ_FAILED,
                        stage="pointer_initialize_sidecar_recheck",
                    )
                _hit(fault, PersistenceCrashPoint.BEFORE_CAS)
                _atomic_write_at(
                    root_handle.fd,
                    final_name=reference.pointer_name,
                    temporary_name=reference.pointer_temporary_name,
                    raw=raw,
                    reason=PlumbingReason.POINTER_WRITE_FAILED,
                    fault=fault,
                )
                _hit(fault, PersistenceCrashPoint.AFTER_CAS)
                selected_raw = _read_pointer_raw_at(
                    root_handle.fd,
                    reference.session_pid,
                )
                if not hmac.compare_digest(selected_raw, raw):
                    _abort(
                        PlumbingDisposition.STATE_CONFLICT,
                        PlumbingReason.CAS_CONFLICT,
                        stage="pointer_initialize_reread",
                    )
                _hit(fault, PersistenceCrashPoint.AFTER_REREAD)
                return _checked_persistence_result(
                    ModeledPointer(
                        reference=reference,
                        receipt=stored.receipt,
                        file_name=reference.pointer_name,
                    ),
                    ModeledPointer,
                    stage="pointer_initialize_result",
                )
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except (CanonicalValueError, _PersistenceAbort) as exc:
        if isinstance(exc, _PersistenceAbort):
            return exc.failure
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
        )


def read_modeled_pointer(
    root: Path,
    pid: CanonicalPid,
) -> ModeledPointer | PlumbingFailure:
    """Read one exact modeled pointer and its selected sidecar."""

    if not isinstance(pid, CanonicalPid):
        raise TypeError("pid must be CanonicalPid")
    try:
        root_handle = _open_root(root)
        try:
            pointer = _checked_persistence_result(
                _read_modeled_pointer_at(root_handle.fd, pid),
                ModeledPointer,
                stage="pointer_read_result",
            )
            pointer_raw = serialize_reference(pointer.reference)
            sidecar_raw = serialize_receipt(pointer.receipt)
            with _strict_lock(root_handle, pid):
                if not hmac.compare_digest(
                    _read_pointer_raw_at(root_handle.fd, pid),
                    pointer_raw,
                ) or not hmac.compare_digest(
                    _read_sidecar_raw_at(root_handle.fd, pointer.reference),
                    sidecar_raw,
                ):
                    _abort(
                        PlumbingDisposition.STATE_CONFLICT,
                        PlumbingReason.CAS_CONFLICT,
                        stage="pointer_read_recheck",
                    )
            return pointer
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except _PersistenceAbort as exc:
        return exc.failure


def compare_and_swap_modeled_pointer(
    root: Path,
    *,
    expected: ReceiptReference,
    replacement: ReceiptReference,
    fault: CrashInjector | None = None,
) -> CasApplied | PlumbingFailure:
    """CAS one test-owned pointer using only explicit complete references."""

    mismatch = reference_transition_mismatch(expected, replacement)
    if mismatch is not None:
        return mismatch
    try:
        replacement_raw = serialize_reference(replacement)
        root_handle = _open_root(root)
        try:
            current = _checked_persistence_result(
                _read_modeled_pointer_stable_at(
                    root_handle.fd,
                    expected.session_pid,
                ),
                ModeledPointer,
                stage="cas_current",
            )
            current_raw = serialize_reference(current.reference)
            current_sidecar_raw = serialize_receipt(current.receipt)
            replacement_stored = _checked_persistence_result(
                _read_sidecar_at(root_handle.fd, replacement),
                StoredReceipt,
                stage="cas_replacement",
            )
            replacement_sidecar_raw = serialize_receipt(replacement_stored.receipt)
            current_is_expected = _references_equal(
                current.reference,
                expected,
            )
            current_is_replacement = _references_equal(
                current.reference,
                replacement,
            )
            with _strict_lock(root_handle, expected.session_pid):
                if not hmac.compare_digest(
                    _read_pointer_raw_at(
                        root_handle.fd,
                        expected.session_pid,
                    ),
                    current_raw,
                ) or not hmac.compare_digest(
                    _read_sidecar_raw_at(root_handle.fd, current.reference),
                    current_sidecar_raw,
                ):
                    _abort(
                        PlumbingDisposition.STATE_CONFLICT,
                        PlumbingReason.CAS_CONFLICT,
                        stage="cas_current_recheck",
                    )
                if not current_is_expected:
                    reason = (
                        PlumbingReason.CONCURRENT_FINALIZER
                        if current_is_replacement
                        else PlumbingReason.CAS_CONFLICT
                    )
                    return plumbing_failure(
                        PlumbingDisposition.STATE_CONFLICT,
                        reason,
                        details={"state": current.reference.state.value},
                    )
                if not hmac.compare_digest(
                    _read_sidecar_raw_at(root_handle.fd, replacement),
                    replacement_sidecar_raw,
                ):
                    _abort(
                        PlumbingDisposition.PERSISTENCE_FAILED,
                        PlumbingReason.SIDECAR_READ_FAILED,
                        stage="cas_replacement_recheck",
                    )
                _hit(fault, PersistenceCrashPoint.BEFORE_CAS)
                _atomic_write_at(
                    root_handle.fd,
                    final_name=expected.pointer_name,
                    temporary_name=replacement.pointer_temporary_name,
                    raw=replacement_raw,
                    reason=PlumbingReason.POINTER_WRITE_FAILED,
                    fault=fault,
                )
                _hit(fault, PersistenceCrashPoint.AFTER_CAS)
                selected_raw = _read_pointer_raw_at(
                    root_handle.fd,
                    replacement.session_pid,
                )
                if not hmac.compare_digest(selected_raw, replacement_raw):
                    _abort(
                        PlumbingDisposition.STATE_CONFLICT,
                        PlumbingReason.CAS_CONFLICT,
                        stage="cas_reread",
                    )
                _hit(fault, PersistenceCrashPoint.AFTER_REREAD)
                return _checked_persistence_result(
                    CasApplied(prior=expected, current=replacement),
                    CasApplied,
                    stage="cas_result",
                )
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except (CanonicalValueError, _PersistenceAbort) as exc:
        if isinstance(exc, _PersistenceAbort):
            return exc.failure
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
        )


def _unlink_regular_at(
    root_fd: int,
    name: str,
    *,
    max_bytes: int,
    allow_empty: bool,
    reason: PlumbingReason,
) -> None:
    value = _stat_at(root_fd, name)
    if value is None:
        _abort(
            PlumbingDisposition.CLEANUP_FAILED,
            reason,
            stage="cleanup_missing",
        )
    try:
        if not _regular_stat_is_valid(
            value,
            max_bytes=max_bytes,
            allow_empty=allow_empty,
        ):
            _abort(
                PlumbingDisposition.CLEANUP_FAILED,
                reason,
                stage="cleanup_policy",
            )
        os.unlink(name, dir_fd=root_fd)
        os.fsync(root_fd)
    except _PersistenceAbort:
        raise
    except OSError as exc:
        _abort(
            PlumbingDisposition.CLEANUP_FAILED,
            reason,
            stage="cleanup_unlink",
            error_number=exc.errno,
        )


def cleanup_unreferenced_sidecar(
    root: Path,
    reference: ReceiptReference,
    *,
    fault: CrashInjector | None = None,
) -> CleanupApplied | PlumbingFailure:
    """Remove one exact sidecar only when the exact PID pointer does not select it."""

    try:
        root_handle = _open_root(root)
        try:
            current: ReceiptReference | None = None
            current_raw: bytes | None = None
            if _stat_at(root_handle.fd, reference.pointer_name) is not None:
                current = _read_pointer_reference_at(
                    root_handle.fd,
                    reference.session_pid,
                )
                current_raw = serialize_reference(current)
            selected = current is not None and _references_equal(current, reference)
            with _strict_lock(root_handle, reference.session_pid):
                pointer_stat = _stat_at(root_handle.fd, reference.pointer_name)
                if current_raw is None:
                    if pointer_stat is not None:
                        _abort(
                            PlumbingDisposition.STATE_CONFLICT,
                            PlumbingReason.CAS_CONFLICT,
                            stage="cleanup_pointer_appeared",
                        )
                elif pointer_stat is None or not hmac.compare_digest(
                    _read_pointer_raw_at(
                        root_handle.fd,
                        reference.session_pid,
                    ),
                    current_raw,
                ):
                    _abort(
                        PlumbingDisposition.STATE_CONFLICT,
                        PlumbingReason.CAS_CONFLICT,
                        stage="cleanup_pointer_changed",
                    )
                if selected:
                    assert current is not None
                    return plumbing_failure(
                        PlumbingDisposition.CLEANUP_FAILED,
                        PlumbingReason.SIDECAR_STILL_REFERENCED,
                        details={"state": current.state.value},
                    )
                _hit(fault, PersistenceCrashPoint.BEFORE_CLEANUP)
                _unlink_regular_at(
                    root_handle.fd,
                    reference.sidecar_name,
                    max_bytes=MAX_RECEIPT_BYTES,
                    allow_empty=False,
                    reason=PlumbingReason.SIDECAR_CLEANUP_INCOMPLETE,
                )
                _hit(fault, PersistenceCrashPoint.AFTER_SIDECAR_UNLINK)
                return _checked_persistence_result(
                    CleanupApplied(
                        reference=reference,
                        pointer_removed=False,
                        sidecar_removed=True,
                    ),
                    CleanupApplied,
                    stage="sidecar_cleanup_result",
                )
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except _PersistenceAbort as exc:
        return exc.failure


def cleanup_selected_receipt(
    root: Path,
    reference: ReceiptReference,
    *,
    fault: CrashInjector | None = None,
) -> CleanupApplied | PlumbingFailure:
    """Revoke one exact modeled pointer, then remove its exact selected sidecar."""

    try:
        root_handle = _open_root(root)
        try:
            current = _read_pointer_reference_at(
                root_handle.fd,
                reference.session_pid,
            )
            current_raw = serialize_reference(current)
            current_is_expected = _references_equal(current, reference)
            with _strict_lock(root_handle, reference.session_pid):
                if not hmac.compare_digest(
                    _read_pointer_raw_at(
                        root_handle.fd,
                        reference.session_pid,
                    ),
                    current_raw,
                ):
                    _abort(
                        PlumbingDisposition.STATE_CONFLICT,
                        PlumbingReason.CAS_CONFLICT,
                        stage="selected_cleanup_recheck",
                    )
                if not current_is_expected:
                    return plumbing_failure(
                        PlumbingDisposition.STATE_CONFLICT,
                        PlumbingReason.CAS_CONFLICT,
                        details={"state": current.state.value},
                    )
                _hit(fault, PersistenceCrashPoint.BEFORE_CLEANUP)
                try:
                    os.unlink(reference.pointer_name, dir_fd=root_handle.fd)
                    os.fsync(root_handle.fd)
                except OSError as exc:
                    _abort(
                        PlumbingDisposition.CLEANUP_FAILED,
                        PlumbingReason.POINTER_CLEANUP_INCOMPLETE,
                        stage="pointer_unlink",
                        error_number=exc.errno,
                    )
                _hit(fault, PersistenceCrashPoint.AFTER_POINTER_UNLINK)
                _unlink_regular_at(
                    root_handle.fd,
                    reference.sidecar_name,
                    max_bytes=MAX_RECEIPT_BYTES,
                    allow_empty=False,
                    reason=PlumbingReason.SIDECAR_CLEANUP_INCOMPLETE,
                )
                _hit(fault, PersistenceCrashPoint.AFTER_SIDECAR_UNLINK)
                return _checked_persistence_result(
                    CleanupApplied(
                        reference=reference,
                        pointer_removed=True,
                        sidecar_removed=True,
                    ),
                    CleanupApplied,
                    stage="selected_cleanup_result",
                )
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except _PersistenceAbort as exc:
        return exc.failure


def cleanup_sidecar_temporary(
    root: Path,
    reference: ReceiptReference,
) -> CleanupApplied | PlumbingFailure:
    """Remove only the exact temporary sidecar for one PID/digest pair."""

    try:
        root_handle = _open_root(root)
        try:
            with _strict_lock(root_handle, reference.session_pid):
                _unlink_regular_at(
                    root_handle.fd,
                    reference.sidecar_temporary_name,
                    max_bytes=MAX_RECEIPT_BYTES,
                    allow_empty=True,
                    reason=PlumbingReason.SIDECAR_CLEANUP_INCOMPLETE,
                )
                return _checked_persistence_result(
                    CleanupApplied(
                        reference=reference,
                        pointer_removed=False,
                        sidecar_removed=False,
                        temporary_removed=True,
                    ),
                    CleanupApplied,
                    stage="sidecar_temporary_cleanup_result",
                )
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except _PersistenceAbort as exc:
        return exc.failure


def cleanup_pointer_temporary(
    root: Path,
    reference: ReceiptReference,
) -> CleanupApplied | PlumbingFailure:
    """Remove only the exact modeled-pointer temporary for one reference."""

    try:
        root_handle = _open_root(root)
        try:
            with _strict_lock(root_handle, reference.session_pid):
                _unlink_regular_at(
                    root_handle.fd,
                    reference.pointer_temporary_name,
                    max_bytes=MAX_POINTER_BYTES,
                    allow_empty=True,
                    reason=PlumbingReason.POINTER_CLEANUP_INCOMPLETE,
                )
                return _checked_persistence_result(
                    CleanupApplied(
                        reference=reference,
                        pointer_removed=False,
                        sidecar_removed=False,
                        temporary_removed=True,
                    ),
                    CleanupApplied,
                    stage="pointer_temporary_cleanup_result",
                )
        finally:
            _recheck_root(root_handle)
            os.close(root_handle.fd)
    except _PersistenceAbort as exc:
        return exc.failure


__all__ = [
    "CrashInjector",
    "MAX_SESSION_ENTRY_BYTES",
    "PersistenceCrashPoint",
    "cleanup_pointer_temporary",
    "cleanup_selected_receipt",
    "cleanup_sidecar_temporary",
    "cleanup_unreferenced_sidecar",
    "compare_and_swap_modeled_pointer",
    "initialize_modeled_pointer",
    "read_modeled_pointer",
    "read_receipt_file_bytes",
    "read_receipt_sidecar",
    "read_receipt_sidecar_bytes_for_registry",
    "read_session_entry_bytes",
    "session_entry_temporary_name",
    "unlink_receipt_file_exact",
    "unlink_session_entry_if_bytes",
    "unlink_session_entry_temporary",
    "write_session_entry_bytes",
    "write_receipt_sidecar",
]
