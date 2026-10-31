"""Descriptor-backed offline runtime evidence collection."""

from __future__ import annotations

import hashlib
import errno
import os
import re
import stat
import sys
from dataclasses import dataclass, replace
from typing import Iterator, NoReturn

from core.json.bounded import loads_bounded

from .canonical import sha256_hex
from .collector_types import (
    COLLECTOR_SCHEMA,
    COLLECTOR_SCHEMA_VERSION,
    DEFAULT_COLLECTOR_LIMITS,
    DEFAULT_ELF_LIMITS,
    MAX_HELD_DESCRIPTORS,
    ArtifactEvidence,
    ArtifactRequest,
    CollectionDisposition,
    CollectionFailure,
    CollectionReasonCode,
    CollectorElfClass,
    CollectorLimits,
    DescriptorIdentity,
    DescriptorStat,
    DistributionEvidence,
    ElfInspection,
    ElfInterpreterAbsent,
    EmbeddedPayloadObservation,
    EvidenceSubject,
    FileCollectionRequest,
    FileEvidence,
    FileRole,
    MonotonicDeadline,
    ObservedDistributionSource,
    OfflineRuntimeCollectionRequest,
    OfflineRuntimeEvidence,
    OperationCounters,
    PackageManifestObservation,
    PathBindingState,
    PathComponentObservation,
    PathObservation,
    PathPolicyId,
    ResolvedInterpreterEvidence,
    SchemaEvidence,
    TreeEntryObservation,
    TreeManifestObservation,
    TrustedDistributionRequest,
    collection_failure,
    errno_class,
    path_sha256,
)
from .elf import inspect_elf
from .identity import TreeManifestRow, manifest_bytes
from .schema import (
    AbsolutePath,
    ArtifactName,
    Endianness,
    FormatId,
    REQUIRED_ARTIFACT_NAMES,
    SchemaDocumentName,
    Sha256,
    VersionText,
)


def _missing_pread(fd: int, size: int, offset: int) -> bytes:
    raise OSError(errno.ENOSYS, "pread unavailable")


_OS_OPEN = os.open
_CLOSE = os.close
_DUP = os.dup
_FSTAT = os.fstat
_STAT = os.stat
_PREAD = getattr(os, "pread", _missing_pread)
_READLINK = os.readlink
_SCANDIR = os.scandir

_LOCK_RE = re.compile(r"^inuse\.[1-9][0-9]*\.lock$")
_SPECIAL_MODE_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
_WRITABLE_BY_OTHERS = stat.S_IWGRP | stat.S_IWOTH
_EXECUTABLE_BITS = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
_EM_X86_64 = 62
_ET_EXEC = 2
_ET_DYN = 3

_ROLE_MAX_BYTES = {
    FileRole.FRONTEND_EXECUTABLE: 268_435_456,
    FileRole.ELF_INTERPRETER: 16_777_216,
    FileRole.PACKAGE_MANIFEST: 262_144,
    FileRole.DISTRIBUTION_ARTIFACT: 268_435_456,
    FileRole.CONTRACT_INPUT: 8_388_608,
    FileRole.PROC_EXE: 268_435_456,
}
_ARTIFACT_MAX_BYTES = {
    ArtifactName.INDEX_JS: 4_194_304,
    ArtifactName.NPM_LOADER_JS: 1_048_576,
    ArtifactName.SEA_LOADER_JS: 1_048_576,
    ArtifactName.APP_JS: 33_554_432,
    ArtifactName.SDK_INDEX_JS: 16_777_216,
    ArtifactName.CHANGELOG_JSON: 8_388_608,
    ArtifactName.RUNTIME_NODE: 268_435_456,
    ArtifactName.CLI_NATIVE_NODE: 67_108_864,
    ArtifactName.SESSION_EVENTS_SCHEMA: 8_388_608,
    ArtifactName.API_SCHEMA: 8_388_608,
    ArtifactName.EXTRACTION_COMPLETE: 4_096,
}
_ARTIFACT_FORMATS = {
    ArtifactName.INDEX_JS: FormatId.JAVASCRIPT_UTF8,
    ArtifactName.NPM_LOADER_JS: FormatId.JAVASCRIPT_UTF8,
    ArtifactName.SEA_LOADER_JS: FormatId.JAVASCRIPT_UTF8,
    ArtifactName.APP_JS: FormatId.JAVASCRIPT_UTF8,
    ArtifactName.SDK_INDEX_JS: FormatId.OPAQUE,
    ArtifactName.CHANGELOG_JSON: FormatId.JSON_UTF8,
    ArtifactName.RUNTIME_NODE: FormatId.ELF64_X86_64_DYN,
    ArtifactName.CLI_NATIVE_NODE: FormatId.ELF64_X86_64_DYN,
    ArtifactName.SESSION_EVENTS_SCHEMA: FormatId.JSON_UTF8,
    ArtifactName.API_SCHEMA: FormatId.JSON_UTF8,
    ArtifactName.EXTRACTION_COMPLETE: FormatId.EMPTY,
}
_SCHEMA_ARTIFACT = {
    SchemaDocumentName.SESSION_EVENTS: ArtifactName.SESSION_EVENTS_SCHEMA,
    SchemaDocumentName.API: ArtifactName.API_SCHEMA,
}


def _after_file_hash() -> None:
    """Fault-injection seam used only by focused tests."""


def _after_inventory_a() -> None:
    """Fault-injection seam used only by focused tests."""


def _before_file_finalize() -> None:
    """Fault-injection seam used only by focused tests."""


class _CollectorAbort(ValueError):
    def __init__(self, failure: CollectionFailure) -> None:
        super().__init__(failure.reason_codes[0].value)
        self.failure = failure


@dataclass(slots=True)
class _BaseAnchor:
    fd: int
    path: str
    close_fd: bool
    asserted_prefix_components: int
    identity: tuple[int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class _RecordedComponent:
    observation: PathComponentObservation
    identity: tuple[int, int, int, int, int]


@dataclass(slots=True)
class _HeldFile:
    guard_fd: int
    reader_fd: int
    base: _BaseAnchor
    relative_components: tuple[str, ...]
    requested_path: AbsolutePath
    resolved_path: AbsolutePath
    policy_id: PathPolicyId
    role: FileRole
    recorded_components: tuple[_RecordedComponent, ...]
    stable_stat: os.stat_result
    descriptor: DescriptorIdentity
    closed: bool = False

    def close(self) -> None:
        if self.closed:
            return
        _safe_close(self.reader_fd)
        _safe_close(self.guard_fd)
        if self.base.close_fd:
            _safe_close(self.base.fd)
        self.closed = True


@dataclass(slots=True)
class _HeldDirectory:
    guard_fd: int
    reader_fd: int
    base: _BaseAnchor
    relative_components: tuple[str, ...]
    path: PathObservation
    stable_stat: os.stat_result
    closed: bool = False

    def close(self) -> None:
        if self.closed:
            return
        _safe_close(self.reader_fd)
        _safe_close(self.guard_fd)
        if self.base.close_fd:
            _safe_close(self.base.fd)
        self.closed = True


@dataclass(frozen=True, slots=True)
class _InventoryEntry:
    relative_path: str
    entry_type: str
    stable_tuple: tuple[int, int, int, int, int, int, int, int, int]
    mode_octal: str
    size_bytes: int


def _abort(failure: CollectionFailure) -> NoReturn:
    raise _CollectorAbort(failure)


def _safe_close(fd: int) -> None:
    try:
        _CLOSE(fd)
    except OSError:
        pass


def _platform_failure() -> CollectionFailure | None:
    if sys.platform != "linux":
        return collection_failure(
            CollectionDisposition.UNSUPPORTED_PLATFORM,
            CollectionReasonCode.PLATFORM_UNSUPPORTED,
            subject=EvidenceSubject.REQUEST,
            details={"stage": "platform"},
        )
    required = ("O_PATH", "O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "pread")
    if any(getattr(os, name, None) is None for name in required):
        return collection_failure(
            CollectionDisposition.UNSUPPORTED_PLATFORM,
            CollectionReasonCode.OS_PRIMITIVE_UNAVAILABLE,
            subject=EvidenceSubject.REQUEST,
            details={"stage": "platform"},
        )
    return None


def _deadline_or_default(
    deadline: MonotonicDeadline | None,
    seconds: float,
) -> MonotonicDeadline:
    return deadline if deadline is not None else MonotonicDeadline.after(seconds)


def _check_deadline(deadline: MonotonicDeadline, subject: EvidenceSubject) -> None:
    if deadline.expired():
        _abort(
            collection_failure(
                CollectionDisposition.LIMIT_EXCEEDED,
                CollectionReasonCode.DEADLINE_EXCEEDED,
                subject=subject,
                details={"stage": "deadline"},
            )
        )


def _stat_tuple(
    value: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int]:
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
    )


def _component_identity(
    value: os.stat_result,
) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
    )


def _root_stability(
    value: os.stat_result,
) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
    )


def _descriptor_stat(value: os.stat_result) -> DescriptorStat:
    return DescriptorStat(
        device=value.st_dev,
        inode=value.st_ino,
        mode_octal=f"{stat.S_IMODE(value.st_mode):04o}",
        uid=value.st_uid,
        gid=value.st_gid,
        size_bytes=value.st_size,
        nlink=value.st_nlink,
        mtime_ns=value.st_mtime_ns,
        ctime_ns=value.st_ctime_ns,
    )


def _allowed_owner(value: os.stat_result, expected_uid: int, allow_root: bool) -> bool:
    return value.st_uid == expected_uid or (allow_root and value.st_uid == 0)


def _validate_directory_policy(
    value: os.stat_result,
    *,
    expected_uid: int,
    allow_root: bool,
    subject: EvidenceSubject,
    stage: str,
) -> None:
    if not stat.S_ISDIR(value.st_mode):
        _abort(
            collection_failure(
                CollectionDisposition.POLICY_REJECTED,
                CollectionReasonCode.PATH_POLICY_VIOLATION,
                subject=subject,
                details={"stage": stage},
            )
        )
    if not _allowed_owner(value, expected_uid, allow_root):
        _abort(
            collection_failure(
                CollectionDisposition.POLICY_REJECTED,
                CollectionReasonCode.OWNER_MISMATCH,
                subject=subject,
                details={"stage": stage},
            )
        )
    if value.st_mode & _WRITABLE_BY_OTHERS:
        _abort(
            collection_failure(
                CollectionDisposition.POLICY_REJECTED,
                CollectionReasonCode.UNSAFE_MODE,
                subject=subject,
                details={"stage": stage},
            )
        )


def _validate_file_policy(
    value: os.stat_result,
    request: FileCollectionRequest,
    subject: EvidenceSubject,
) -> None:
    if not stat.S_ISREG(value.st_mode):
        _abort(
            collection_failure(
                CollectionDisposition.POLICY_REJECTED,
                CollectionReasonCode.NOT_REGULAR,
                subject=subject,
                details={"stage": "leaf_policy", "role": request.role},
            )
        )
    if not _allowed_owner(value, request.expected_owner_uid, request.allow_root_owner):
        _abort(
            collection_failure(
                CollectionDisposition.POLICY_REJECTED,
                CollectionReasonCode.OWNER_MISMATCH,
                subject=subject,
                details={"stage": "leaf_policy", "role": request.role},
            )
        )
    if value.st_mode & (_WRITABLE_BY_OTHERS | _SPECIAL_MODE_BITS):
        _abort(
            collection_failure(
                CollectionDisposition.POLICY_REJECTED,
                CollectionReasonCode.UNSAFE_MODE,
                subject=subject,
                details={"stage": "leaf_policy", "role": request.role},
            )
        )
    if value.st_nlink != 1:
        _abort(
            collection_failure(
                CollectionDisposition.POLICY_REJECTED,
                CollectionReasonCode.LINK_COUNT_INVALID,
                subject=subject,
                details={"stage": "leaf_policy", "role": request.role},
            )
        )
    if request.require_executable and not value.st_mode & _EXECUTABLE_BITS:
        _abort(
            collection_failure(
                CollectionDisposition.POLICY_REJECTED,
                CollectionReasonCode.NOT_EXECUTABLE,
                subject=subject,
                details={"stage": "leaf_policy", "role": request.role},
            )
        )
    if value.st_size > request.max_bytes:
        _abort(
            collection_failure(
                CollectionDisposition.LIMIT_EXCEEDED,
                CollectionReasonCode.SIZE_LIMIT_EXCEEDED,
                subject=subject,
                details={
                    "stage": "leaf_policy",
                    "role": request.role,
                    "bytes": value.st_size,
                    "limit": request.max_bytes,
                },
            )
        )


def _file_type(value: os.stat_result) -> str:
    if stat.S_ISDIR(value.st_mode):
        return "directory"
    if stat.S_ISREG(value.st_mode):
        return "regular"
    if stat.S_ISLNK(value.st_mode):
        return "symlink"
    return "other"


def _absolute_join(base: str, components: tuple[str, ...] | list[str]) -> str:
    suffix = "/".join(components)
    if base == "/":
        return "/" + suffix
    if not suffix:
        return base
    return base + "/" + suffix


def _relative_components(
    value: str,
    limits: CollectorLimits,
    *,
    max_components: int | None = None,
) -> tuple[str, ...] | None:
    if (
        not value
        or value.startswith("/")
        or value.startswith("./")
        or not value.isprintable()
        or "\t" in value
        or "\x00" in value
    ):
        return None
    components = tuple(value.split("/"))
    component_limit = (
        limits.relative_path_components if max_components is None else max_components
    )
    try:
        valid = len(components) <= component_limit and all(
            component not in {"", ".", ".."}
            and len(component.encode("utf-8")) <= limits.path_component_bytes
            for component in components
        )
    except UnicodeEncodeError:
        return None
    return components if valid else None


def _relative_from_absolute(absolute: str, base: str) -> str | None:
    if base == "/":
        return absolute[1:]
    prefix = base + "/"
    if not absolute.startswith(prefix):
        return None
    return absolute[len(prefix) :]


def _open_error(
    exc: OSError,
    *,
    subject: EvidenceSubject,
    stage: str,
    path: str | None = None,
) -> CollectionFailure:
    details: dict[str, object] = {
        "stage": stage,
        "errno_class": errno_class(exc.errno),
    }
    if path is not None:
        details["path_sha256"] = path_sha256(path)
    if exc.errno == errno.ELOOP:
        disposition = CollectionDisposition.POLICY_REJECTED
        reason = CollectionReasonCode.PATH_POLICY_VIOLATION
    elif exc.errno in {20, 40}:
        disposition = CollectionDisposition.POLICY_REJECTED
        reason = CollectionReasonCode.PATH_POLICY_VIOLATION
    elif exc.errno in {13, 1}:
        disposition = CollectionDisposition.UNAVAILABLE
        reason = CollectionReasonCode.PERMISSION_DENIED
    elif exc.errno == 2:
        disposition = CollectionDisposition.UNAVAILABLE
        reason = CollectionReasonCode.RESOURCE_NOT_FOUND
    else:
        disposition = CollectionDisposition.UNAVAILABLE
        reason = CollectionReasonCode.IO_ERROR
    return collection_failure(
        disposition,
        reason,
        subject=subject,
        details=details,
    )


def _prepare_base(
    *,
    expected_uid: int,
    allow_root: bool,
    anchor_fd: int | None,
    anchor_path: AbsolutePath | None,
    subject: EvidenceSubject,
) -> _BaseAnchor:
    if (anchor_fd is None) != (anchor_path is None):
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_PATH,
                subject=subject,
                details={"stage": "anchor"},
            )
        )
    if anchor_fd is None:
        try:
            fd = _OS_OPEN(
                "/",
                os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            value = _FSTAT(fd)
            _validate_directory_policy(
                value,
                expected_uid=expected_uid,
                allow_root=True,
                subject=subject,
                stage="anchor",
            )
        except _CollectorAbort:
            if "fd" in locals():
                _safe_close(fd)
            raise
        except OSError as exc:
            if "fd" in locals():
                _safe_close(fd)
            _abort(_open_error(exc, subject=subject, stage="anchor", path="/"))
        return _BaseAnchor(
            fd=fd,
            path="/",
            close_fd=True,
            asserted_prefix_components=0,
            identity=_component_identity(value),
        )

    assert anchor_path is not None
    if type(anchor_fd) is not int or anchor_fd < 0:
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_PATH,
                subject=subject,
                details={"stage": "anchor"},
            )
        )
    try:
        link = _READLINK(f"/proc/self/fd/{anchor_fd}")
        value = _FSTAT(anchor_fd)
    except OSError as exc:
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_PATH,
                subject=subject,
                details={
                    "stage": "anchor",
                    "errno_class": errno_class(exc.errno),
                    "path_sha256": path_sha256(anchor_path.value),
                },
            )
        )
    try:
        link_bytes = os.fsencode(link)
        expected_bytes = anchor_path.value.encode("utf-8")
    except UnicodeError:
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_PATH,
                subject=subject,
                details={"stage": "anchor"},
            )
        )
    if link_bytes.endswith(b" (deleted)") or link_bytes != expected_bytes:
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_PATH,
                subject=subject,
                details={
                    "stage": "anchor",
                    "path_sha256": path_sha256(anchor_path.value),
                },
            )
        )
    _validate_directory_policy(
        value,
        expected_uid=expected_uid,
        allow_root=allow_root,
        subject=subject,
        stage="anchor",
    )
    return _BaseAnchor(
        fd=anchor_fd,
        path=anchor_path.value,
        close_fd=False,
        asserted_prefix_components=len(anchor_path.value.split("/")) - 1,
        identity=_component_identity(value),
    )


def _record_component(
    absolute: str,
    index: int,
    value: os.stat_result,
    *,
    link_text_sha256: str | None = None,
) -> _RecordedComponent:
    return _RecordedComponent(
        observation=PathComponentObservation(
            absolute_path=AbsolutePath(absolute),
            component_index=index,
            file_type=_file_type(value),  # type: ignore[arg-type]
            device=value.st_dev,
            inode=value.st_ino,
            uid=value.st_uid,
            gid=value.st_gid,
            mode_octal=f"{stat.S_IMODE(value.st_mode):04o}",
            link_text_sha256=link_text_sha256,
        ),
        identity=_component_identity(value),
    )


def _traverse_directories(
    base: _BaseAnchor,
    components: tuple[str, ...],
    *,
    expected_uid: int,
    allow_root: bool,
    subject: EvidenceSubject,
) -> tuple[int, bool, tuple[_RecordedComponent, ...]]:
    current = base.fd
    current_owned = False
    observed: list[_RecordedComponent] = []
    try:
        for index, component in enumerate(components):
            next_fd = -1
            try:
                try:
                    next_fd = _OS_OPEN(
                        component,
                        os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=current,
                    )
                    value = _FSTAT(next_fd)
                except OSError as exc:
                    _abort(
                        _open_error(
                            exc,
                            subject=subject,
                            stage="ancestor_open",
                            path=_absolute_join(base.path, components[: index + 1]),
                        )
                    )
                _validate_directory_policy(
                    value,
                    expected_uid=expected_uid,
                    allow_root=allow_root,
                    subject=subject,
                    stage="ancestor_policy",
                )
                observation = _record_component(
                    _absolute_join(base.path, components[: index + 1]),
                    base.asserted_prefix_components + index,
                    value,
                )
                observed.append(observation)
                previous_fd = current
                previous_owned = current_owned
                current = next_fd
                current_owned = True
                next_fd = -1
                if previous_owned:
                    _safe_close(previous_fd)
            finally:
                if next_fd >= 0:
                    _safe_close(next_fd)
        result = current, current_owned, tuple(observed)
        current_owned = False
        return result
    finally:
        if current_owned:
            _safe_close(current)


def _hash_reader(
    fd: int,
    *,
    file_size: int,
    limits: CollectorLimits,
    deadline: MonotonicDeadline,
    subject: EvidenceSubject,
) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < file_size:
        _check_deadline(deadline, subject)
        expected = min(limits.hash_chunk_bytes, file_size - offset)
        try:
            chunk = _PREAD(fd, expected, offset)
        except OSError as exc:
            _abort(
                collection_failure(
                    CollectionDisposition.UNAVAILABLE,
                    CollectionReasonCode.IO_ERROR,
                    subject=subject,
                    details={
                        "stage": "file_hash",
                        "errno_class": errno_class(exc.errno),
                    },
                )
            )
        if not chunk:
            _abort(
                collection_failure(
                    CollectionDisposition.MALFORMED_INPUT,
                    CollectionReasonCode.SHORT_READ,
                    subject=subject,
                    details={"stage": "file_hash", "bytes": offset},
                )
            )
        digest.update(chunk)
        offset += len(chunk)
    _check_deadline(deadline, subject)
    try:
        extra = _PREAD(fd, 1, file_size)
    except OSError as exc:
        _abort(
            collection_failure(
                CollectionDisposition.UNAVAILABLE,
                CollectionReasonCode.IO_ERROR,
                subject=subject,
                details={
                    "stage": "file_hash",
                    "errno_class": errno_class(exc.errno),
                },
            )
        )
    if extra:
        _abort(
            collection_failure(
                CollectionDisposition.CHANGED_DURING_COLLECTION,
                CollectionReasonCode.FILE_MUTATED,
                subject=subject,
                details={"stage": "file_hash"},
            )
        )
    _after_file_hash()
    return digest.hexdigest()


def _read_all(
    held: _HeldFile,
    *,
    deadline: MonotonicDeadline,
    subject: EvidenceSubject,
) -> bytes:
    size = held.stable_stat.st_size
    output = bytearray()
    offset = 0
    while offset < size:
        _check_deadline(deadline, subject)
        try:
            chunk = _PREAD(
                held.reader_fd,
                min(1_048_576, size - offset),
                offset,
            )
        except OSError as exc:
            _abort(
                collection_failure(
                    CollectionDisposition.UNAVAILABLE,
                    CollectionReasonCode.IO_ERROR,
                    subject=subject,
                    details={
                        "stage": "file_read",
                        "errno_class": errno_class(exc.errno),
                    },
                )
            )
        if not chunk:
            _abort(
                collection_failure(
                    CollectionDisposition.MALFORMED_INPUT,
                    CollectionReasonCode.SHORT_READ,
                    subject=subject,
                    details={"stage": "file_read", "bytes": offset},
                )
            )
        output.extend(chunk)
        offset += len(chunk)
    try:
        extra = _PREAD(held.reader_fd, 1, size)
    except OSError as exc:
        _abort(
            collection_failure(
                CollectionDisposition.UNAVAILABLE,
                CollectionReasonCode.IO_ERROR,
                subject=subject,
                details={
                    "stage": "file_read",
                    "errno_class": errno_class(exc.errno),
                },
            )
        )
    if extra:
        _abort(
            collection_failure(
                CollectionDisposition.CHANGED_DURING_COLLECTION,
                CollectionReasonCode.FILE_MUTATED,
                subject=subject,
                details={"stage": "file_read"},
            )
        )
    return bytes(output)


def _validate_request(
    request: FileCollectionRequest,
    limits: CollectorLimits,
    *,
    subject: EvidenceSubject,
) -> None:
    if request.expected_owner_uid < 0 or request.max_bytes < 0:
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_PATH,
                subject=subject,
                details={"stage": "file_request"},
            )
        )
    role_bound = min(_ROLE_MAX_BYTES[request.role], limits.generic_file_bytes)
    if request.max_bytes > role_bound:
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_ROLE_SET,
                subject=subject,
                details={
                    "stage": "file_request",
                    "role": request.role,
                    "limit": role_bound,
                },
            )
        )
    if request.format_id is FormatId.SHELL_SCRIPT:
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_ROLE_SET,
                subject=subject,
                details={"stage": "file_request", "role": request.role},
            )
        )


def _open_held_file_from_base(
    base: _BaseAnchor,
    relative_path: str,
    request: FileCollectionRequest,
    *,
    limits: CollectorLimits,
    deadline: MonotonicDeadline,
    subject: EvidenceSubject,
    requested_path: AbsolutePath | None = None,
    resolved_path: AbsolutePath | None = None,
    max_components: int | None = None,
) -> _HeldFile:
    _validate_request(request, limits, subject=subject)
    components = _relative_components(
        relative_path,
        limits,
        max_components=max_components,
    )
    if components is None:
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_RELATIVE_PATH,
                subject=subject,
                details={
                    "stage": "relative_path",
                    "path_sha256": path_sha256(relative_path),
                },
            )
        )
    actual_path_text = _absolute_join(base.path, components)
    if request.absolute_path.value != actual_path_text:
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_PATH,
                subject=subject,
                details={
                    "stage": "path_binding",
                    "path_sha256": path_sha256(request.absolute_path.value),
                },
            )
        )
    parent_fd = base.fd
    parent_owned = False
    recorded: tuple[_RecordedComponent, ...] = ()
    guard_fd = -1
    reader_fd = -1
    try:
        parent_fd, parent_owned, recorded = _traverse_directories(
            base,
            components[:-1],
            expected_uid=request.expected_owner_uid,
            allow_root=request.allow_root_owner,
            subject=subject,
        )
        try:
            guard_fd = _OS_OPEN(
                components[-1],
                os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd,
            )
            guard_stat = _FSTAT(guard_fd)
        except OSError as exc:
            _abort(
                _open_error(
                    exc,
                    subject=subject,
                    stage="leaf_open",
                    path=actual_path_text,
                )
            )
        leaf_type = _file_type(guard_stat)
        if leaf_type == "symlink":
            _abort(
                collection_failure(
                    CollectionDisposition.POLICY_REJECTED,
                    CollectionReasonCode.PATH_POLICY_VIOLATION,
                    subject=subject,
                    details={
                        "stage": "leaf_policy",
                        "path_sha256": path_sha256(actual_path_text),
                    },
                )
            )
        _validate_file_policy(guard_stat, request, subject)
        leaf_record = _record_component(
            actual_path_text,
            base.asserted_prefix_components + len(components) - 1,
            guard_stat,
        )
        recorded = (*recorded, leaf_record)
        try:
            reader_fd = _OS_OPEN(
                f"/proc/self/fd/{guard_fd}",
                os.O_RDONLY | os.O_CLOEXEC,
            )
            reader_stat = _FSTAT(reader_fd)
        except OSError as exc:
            _abort(
                _open_error(
                    exc,
                    subject=subject,
                    stage="descriptor_reopen",
                    path=actual_path_text,
                )
            )
        if _stat_tuple(reader_stat) != _stat_tuple(guard_stat):
            _abort(
                collection_failure(
                    CollectionDisposition.CHANGED_DURING_COLLECTION,
                    CollectionReasonCode.FILE_MUTATED,
                    subject=subject,
                    details={"stage": "descriptor_reopen"},
                )
            )
        digest = _hash_reader(
            reader_fd,
            file_size=guard_stat.st_size,
            limits=limits,
            deadline=deadline,
            subject=subject,
        )
        descriptor = DescriptorIdentity(
            stat=_descriptor_stat(guard_stat),
            sha256=digest,
            format_id=request.format_id,
            elf_build_id_sha1=None,
            bytes_hashed=guard_stat.st_size,
        )
        return _HeldFile(
            guard_fd=guard_fd,
            reader_fd=reader_fd,
            base=base,
            relative_components=components,
            requested_path=requested_path or request.absolute_path,
            resolved_path=resolved_path or request.absolute_path,
            policy_id=request.policy_id,
            role=request.role,
            recorded_components=recorded,
            stable_stat=guard_stat,
            descriptor=descriptor,
        )
    except _CollectorAbort:
        if reader_fd >= 0:
            _safe_close(reader_fd)
        if guard_fd >= 0:
            _safe_close(guard_fd)
        if base.close_fd:
            _safe_close(base.fd)
            base.close_fd = False
        raise
    finally:
        if parent_owned:
            _safe_close(parent_fd)


def _verify_path_binding(held: _HeldFile, subject: EvidenceSubject) -> None:
    base = held.base
    components = held.relative_components
    try:
        anchor_stat = _FSTAT(base.fd)
    except OSError:
        anchor_stat = None
    if anchor_stat is None or _component_identity(anchor_stat) != base.identity:
        _abort(
            collection_failure(
                CollectionDisposition.CHANGED_DURING_COLLECTION,
                CollectionReasonCode.ANCESTOR_REPLACED,
                subject=subject,
                details={"stage": "anchor_recheck"},
                partial_descriptor=held.descriptor,
                path_binding_state=PathBindingState.ANCESTOR_REPLACED,
            )
        )
    if base.path != "/":
        try:
            current_anchor = _READLINK(f"/proc/self/fd/{base.fd}")
        except OSError:
            _abort(
                collection_failure(
                    CollectionDisposition.CHANGED_DURING_COLLECTION,
                    CollectionReasonCode.ANCESTOR_REPLACED,
                    subject=subject,
                    details={"stage": "anchor_recheck"},
                    partial_descriptor=held.descriptor,
                    path_binding_state=PathBindingState.ANCESTOR_REPLACED,
                )
            )
        if current_anchor.endswith(" (deleted)") or current_anchor.encode(
            "utf-8", errors="surrogateescape"
        ) != base.path.encode("utf-8"):
            _abort(
                collection_failure(
                    CollectionDisposition.CHANGED_DURING_COLLECTION,
                    CollectionReasonCode.ANCESTOR_REPLACED,
                    subject=subject,
                    details={"stage": "anchor_recheck"},
                    partial_descriptor=held.descriptor,
                    path_binding_state=PathBindingState.ANCESTOR_REPLACED,
                )
            )
    parent_fd = base.fd
    parent_owned = False
    try:
        for index, component in enumerate(components[:-1]):
            try:
                next_fd = _OS_OPEN(
                    component,
                    os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent_fd,
                )
                value = _FSTAT(next_fd)
            except OSError:
                _abort(
                    collection_failure(
                        CollectionDisposition.CHANGED_DURING_COLLECTION,
                        CollectionReasonCode.ANCESTOR_REPLACED,
                        subject=subject,
                        details={"stage": "path_recheck"},
                        partial_descriptor=held.descriptor,
                        path_binding_state=PathBindingState.ANCESTOR_REPLACED,
                    )
                )
            if _component_identity(value) != held.recorded_components[index].identity:
                _safe_close(next_fd)
                _abort(
                    collection_failure(
                        CollectionDisposition.CHANGED_DURING_COLLECTION,
                        CollectionReasonCode.ANCESTOR_REPLACED,
                        subject=subject,
                        details={"stage": "path_recheck"},
                        partial_descriptor=held.descriptor,
                        path_binding_state=PathBindingState.ANCESTOR_REPLACED,
                    )
                )
            if parent_owned:
                _safe_close(parent_fd)
            parent_fd = next_fd
            parent_owned = True
        try:
            leaf = _STAT(
                components[-1],
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            _abort(
                collection_failure(
                    CollectionDisposition.CHANGED_DURING_COLLECTION,
                    CollectionReasonCode.PATH_REPLACED,
                    subject=subject,
                    details={"stage": "path_recheck"},
                    partial_descriptor=held.descriptor,
                    path_binding_state=PathBindingState.MISSING_AFTER_OPEN,
                )
            )
        except OSError:
            _abort(
                collection_failure(
                    CollectionDisposition.CHANGED_DURING_COLLECTION,
                    CollectionReasonCode.PATH_REPLACED,
                    subject=subject,
                    details={"stage": "path_recheck"},
                    partial_descriptor=held.descriptor,
                    path_binding_state=PathBindingState.REPLACED_AFTER_OPEN,
                )
            )
        if _component_identity(leaf) != held.recorded_components[-1].identity:
            _abort(
                collection_failure(
                    CollectionDisposition.CHANGED_DURING_COLLECTION,
                    CollectionReasonCode.PATH_REPLACED,
                    subject=subject,
                    details={"stage": "path_recheck"},
                    partial_descriptor=held.descriptor,
                    path_binding_state=PathBindingState.REPLACED_AFTER_OPEN,
                )
            )
    finally:
        if parent_owned:
            _safe_close(parent_fd)


def _verify_directory_binding(root: _HeldDirectory) -> None:
    base = root.base
    try:
        anchor_stat = _FSTAT(base.fd)
    except OSError:
        anchor_stat = None
    if anchor_stat is None or _component_identity(anchor_stat) != base.identity:
        _abort(
            collection_failure(
                CollectionDisposition.CHANGED_DURING_COLLECTION,
                CollectionReasonCode.DISTRIBUTION_TREE_CHANGED,
                subject=EvidenceSubject.DISTRIBUTION,
                details={"stage": "distribution_path_recheck"},
            )
        )
    if base.path != "/":
        try:
            current_anchor = _READLINK(f"/proc/self/fd/{base.fd}")
        except OSError:
            _abort(
                collection_failure(
                    CollectionDisposition.CHANGED_DURING_COLLECTION,
                    CollectionReasonCode.DISTRIBUTION_TREE_CHANGED,
                    subject=EvidenceSubject.DISTRIBUTION,
                    details={"stage": "distribution_path_recheck"},
                )
            )
        if current_anchor.endswith(" (deleted)") or current_anchor.encode(
            "utf-8", errors="surrogateescape"
        ) != base.path.encode("utf-8"):
            _abort(
                collection_failure(
                    CollectionDisposition.CHANGED_DURING_COLLECTION,
                    CollectionReasonCode.DISTRIBUTION_TREE_CHANGED,
                    subject=EvidenceSubject.DISTRIBUTION,
                    details={"stage": "distribution_path_recheck"},
                )
            )
    if not root.relative_components:
        return
    current = base.fd
    current_owned = False
    try:
        for index, component in enumerate(root.relative_components):
            try:
                next_fd = _OS_OPEN(
                    component,
                    os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=current,
                )
                value = _FSTAT(next_fd)
            except OSError:
                _abort(
                    collection_failure(
                        CollectionDisposition.CHANGED_DURING_COLLECTION,
                        CollectionReasonCode.DISTRIBUTION_TREE_CHANGED,
                        subject=EvidenceSubject.DISTRIBUTION,
                        details={"stage": "distribution_path_recheck"},
                    )
                )
            observation = root.path.components[index]
            expected = (
                observation.device,
                observation.inode,
                stat.S_IFDIR | int(observation.mode_octal, 8),
                observation.uid,
                observation.gid,
            )
            if _component_identity(value) != expected:
                _safe_close(next_fd)
                _abort(
                    collection_failure(
                        CollectionDisposition.CHANGED_DURING_COLLECTION,
                        CollectionReasonCode.DISTRIBUTION_TREE_CHANGED,
                        subject=EvidenceSubject.DISTRIBUTION,
                        details={"stage": "distribution_path_recheck"},
                    )
                )
            if current_owned:
                _safe_close(current)
            current = next_fd
            current_owned = True
    finally:
        if current_owned:
            _safe_close(current)


def _finalize_held_file(
    held: _HeldFile,
    *,
    subject: EvidenceSubject,
) -> FileEvidence:
    _before_file_finalize()
    try:
        reader_after = _FSTAT(held.reader_fd)
        guard_after = _FSTAT(held.guard_fd)
    except OSError as exc:
        _abort(
            collection_failure(
                CollectionDisposition.CHANGED_DURING_COLLECTION,
                CollectionReasonCode.FILE_MUTATED,
                subject=subject,
                details={
                    "stage": "final_fstat",
                    "errno_class": errno_class(exc.errno),
                },
                partial_descriptor=held.descriptor,
            )
        )
    expected = _stat_tuple(held.stable_stat)
    descriptor_changed = (
        _stat_tuple(reader_after) != expected or _stat_tuple(guard_after) != expected
    )
    _verify_path_binding(held, subject)
    if descriptor_changed:
        _abort(
            collection_failure(
                CollectionDisposition.CHANGED_DURING_COLLECTION,
                CollectionReasonCode.FILE_MUTATED,
                subject=subject,
                details={"stage": "final_fstat"},
                partial_descriptor=held.descriptor,
            )
        )
    return FileEvidence(
        role=held.role,
        descriptor=held.descriptor,
        path=PathObservation(
            requested_path=held.requested_path,
            resolved_path=held.resolved_path,
            policy_id=held.policy_id,
            components=tuple(item.observation for item in held.recorded_components),
            binding_state=PathBindingState.STABLE,
            asserted_prefix_components=held.base.asserted_prefix_components,
        ),
    )


def _inspect_expected_elf(
    held: _HeldFile,
    expected_format: FormatId,
    *,
    subject: EvidenceSubject,
    artifact_semantics: bool,
) -> ElfInspection:
    result = inspect_elf(
        held.reader_fd,
        file_size=held.stable_stat.st_size,
        limits=DEFAULT_ELF_LIMITS,
    )
    if isinstance(result, CollectionFailure):
        if artifact_semantics:
            _abort(
                collection_failure(
                    CollectionDisposition.MISMATCH,
                    CollectionReasonCode.ARTIFACT_FORMAT_MISMATCH,
                    subject=subject,
                    details={"stage": "format_check", "role": held.role},
                )
            )
        _abort(result)
    if result.format_id is not expected_format:
        reason = (
            CollectionReasonCode.ELF_MACHINE_UNSUPPORTED
            if result.machine != _EM_X86_64
            else CollectionReasonCode.ELF_TYPE_UNSUPPORTED
        )
        if artifact_semantics:
            _abort(
                collection_failure(
                    CollectionDisposition.MISMATCH,
                    CollectionReasonCode.ARTIFACT_FORMAT_MISMATCH,
                    subject=subject,
                    details={"stage": "format_check", "role": held.role},
                )
            )
        _abort(
            collection_failure(
                CollectionDisposition.UNSUPPORTED_PLATFORM,
                reason,
                subject=subject,
                details={"stage": "format_check", "role": held.role},
            )
        )
    held.descriptor = replace(
        held.descriptor,
        elf_build_id_sha1=(
            result.build_id_sha1.value if result.build_id_sha1 is not None else None
        ),
    )
    return result


def _check_format(
    held: _HeldFile,
    expected_format: FormatId,
    *,
    deadline: MonotonicDeadline,
    subject: EvidenceSubject,
    artifact_semantics: bool,
) -> ElfInspection | None:
    if expected_format in {
        FormatId.ELF64_X86_64_EXEC,
        FormatId.ELF64_X86_64_DYN,
    }:
        inspection = _inspect_expected_elf(
            held,
            expected_format,
            subject=subject,
            artifact_semantics=artifact_semantics,
        )
        if held.role is FileRole.FRONTEND_EXECUTABLE and isinstance(
            inspection.interpreter, ElfInterpreterAbsent
        ):
            _abort(
                collection_failure(
                    CollectionDisposition.INCOMPLETE,
                    CollectionReasonCode.ELF_INTERPRETER_MISSING,
                    subject=subject,
                    details={"stage": "format_check", "role": held.role},
                )
            )
        if held.role in {
            FileRole.ELF_INTERPRETER,
            FileRole.DISTRIBUTION_ARTIFACT,
        } and not isinstance(inspection.interpreter, ElfInterpreterAbsent):
            _abort(
                collection_failure(
                    CollectionDisposition.MISMATCH,
                    CollectionReasonCode.ARTIFACT_FORMAT_MISMATCH,
                    subject=subject,
                    details={"stage": "format_check", "role": held.role},
                )
            )
        return inspection
    if expected_format is FormatId.EMPTY:
        if held.stable_stat.st_size != 0:
            _abort(
                collection_failure(
                    CollectionDisposition.MISMATCH,
                    CollectionReasonCode.ARTIFACT_FORMAT_MISMATCH,
                    subject=subject,
                    details={"stage": "format_check", "role": held.role},
                )
            )
        return None
    if expected_format in {FormatId.JSON_UTF8, FormatId.JAVASCRIPT_UTF8}:
        raw = _read_all(held, deadline=deadline, subject=subject)
        try:
            raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            _abort(
                collection_failure(
                    CollectionDisposition.MISMATCH,
                    CollectionReasonCode.ARTIFACT_FORMAT_MISMATCH,
                    subject=subject,
                    details={"stage": "format_check", "role": held.role},
                )
            )
        return None
    if expected_format is FormatId.OPAQUE:
        return None
    _abort(
        collection_failure(
            CollectionDisposition.INVALID_REQUEST,
            CollectionReasonCode.INVALID_ROLE_SET,
            subject=subject,
            details={"stage": "format_check", "role": held.role},
        )
    )


def _collect_file(
    request: FileCollectionRequest,
    *,
    limits: CollectorLimits,
    deadline: MonotonicDeadline,
    anchor_fd: int | None,
    anchor_path: AbsolutePath | None,
    relative_path: str | None,
    subject: EvidenceSubject,
) -> FileEvidence:
    base = _prepare_base(
        expected_uid=request.expected_owner_uid,
        allow_root=request.allow_root_owner,
        anchor_fd=anchor_fd,
        anchor_path=anchor_path,
        subject=subject,
    )
    relative = (
        relative_path
        if relative_path is not None
        else _relative_from_absolute(request.absolute_path.value, base.path)
    )
    if relative is None:
        if base.close_fd:
            _safe_close(base.fd)
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_PATH,
                subject=subject,
                details={
                    "stage": "path_binding",
                    "path_sha256": path_sha256(request.absolute_path.value),
                },
            )
        )
    held = _open_held_file_from_base(
        base,
        relative,
        request,
        limits=limits,
        deadline=deadline,
        subject=subject,
        max_components=limits.absolute_path_components,
    )
    try:
        _check_format(
            held,
            request.format_id,
            deadline=deadline,
            subject=subject,
            artifact_semantics=request.role
            in {FileRole.DISTRIBUTION_ARTIFACT, FileRole.CONTRACT_INPUT},
        )
        return _finalize_held_file(held, subject=subject)
    finally:
        held.close()


def _public_file_failure(
    exc: BaseException, subject: EvidenceSubject
) -> CollectionFailure:
    if isinstance(exc, _CollectorAbort):
        return exc.failure
    if isinstance(exc, OSError):
        return _open_error(exc, subject=subject, stage="file_collection")
    if isinstance(exc, (UnicodeError, ValueError, OverflowError)):
        return collection_failure(
            CollectionDisposition.INVALID_REQUEST,
            CollectionReasonCode.INVALID_PATH,
            subject=subject,
            details={"stage": "file_collection"},
        )
    raise exc


def collect_file_identity(
    request: FileCollectionRequest,
    *,
    limits: CollectorLimits = DEFAULT_COLLECTOR_LIMITS,
    deadline: MonotonicDeadline | None = None,
) -> FileEvidence | CollectionFailure:
    """Collect one absolute path without following any path component symlink."""

    if not isinstance(request, FileCollectionRequest) or not isinstance(
        limits, CollectorLimits
    ):
        raise TypeError("invalid file collection argument type")
    unsupported = _platform_failure()
    if unsupported is not None:
        return unsupported
    actual_deadline = _deadline_or_default(deadline, limits.file_deadline_seconds)
    try:
        return _collect_file(
            request,
            limits=limits,
            deadline=actual_deadline,
            anchor_fd=None,
            anchor_path=None,
            relative_path=None,
            subject=EvidenceSubject.FILE,
        )
    except (OSError, UnicodeError, ValueError, OverflowError) as exc:
        return _public_file_failure(exc, EvidenceSubject.FILE)


def collect_file_identity_at(
    anchor_fd: int,
    anchor_path: AbsolutePath,
    relative_path: str,
    request: FileCollectionRequest,
    *,
    limits: CollectorLimits = DEFAULT_COLLECTOR_LIMITS,
    deadline: MonotonicDeadline | None = None,
) -> FileEvidence | CollectionFailure:
    """Collect one path below a recorded caller-owned directory descriptor."""

    if (
        type(anchor_fd) is not int
        or not isinstance(anchor_path, AbsolutePath)
        or type(relative_path) is not str
        or not isinstance(request, FileCollectionRequest)
        or not isinstance(limits, CollectorLimits)
    ):
        raise TypeError("invalid anchored collection argument type")
    unsupported = _platform_failure()
    if unsupported is not None:
        return unsupported
    actual_deadline = _deadline_or_default(deadline, limits.file_deadline_seconds)
    try:
        return _collect_file(
            request,
            limits=limits,
            deadline=actual_deadline,
            anchor_fd=anchor_fd,
            anchor_path=anchor_path,
            relative_path=relative_path,
            subject=EvidenceSubject.FILE,
        )
    except (OSError, UnicodeError, ValueError, OverflowError) as exc:
        return _public_file_failure(exc, EvidenceSubject.FILE)


def _open_distribution_root(
    request: TrustedDistributionRequest,
    *,
    limits: CollectorLimits,
) -> _HeldDirectory:
    base = _prepare_base(
        expected_uid=request.expected_owner_uid,
        allow_root=True,
        anchor_fd=request.anchor_fd,
        anchor_path=request.anchor_path,
        subject=EvidenceSubject.DISTRIBUTION,
    )
    relative = _relative_from_absolute(request.source_directory.value, base.path)
    if relative is None:
        if base.close_fd:
            _safe_close(base.fd)
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_PATH,
                subject=EvidenceSubject.DISTRIBUTION,
                details={"stage": "distribution_root"},
            )
        )
    components = (
        ()
        if not relative
        else _relative_components(
            relative,
            limits,
            max_components=limits.absolute_path_components,
        )
    )
    if components is None:
        if base.close_fd:
            _safe_close(base.fd)
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_PATH,
                subject=EvidenceSubject.DISTRIBUTION,
                details={"stage": "distribution_root"},
            )
        )
    guard_fd = -1
    reader_fd = -1
    parent_fd = base.fd
    parent_owned = False
    recorded: tuple[_RecordedComponent, ...] = ()
    try:
        if components:
            parent_fd, parent_owned, parents = _traverse_directories(
                base,
                components[:-1],
                expected_uid=request.expected_owner_uid,
                allow_root=True,
                subject=EvidenceSubject.DISTRIBUTION,
            )
            try:
                guard_fd = _OS_OPEN(
                    components[-1],
                    os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent_fd,
                )
                root_stat = _FSTAT(guard_fd)
            except OSError as exc:
                _abort(
                    _open_error(
                        exc,
                        subject=EvidenceSubject.DISTRIBUTION,
                        stage="distribution_root",
                        path=request.source_directory.value,
                    )
                )
            _validate_directory_policy(
                root_stat,
                expected_uid=request.expected_owner_uid,
                allow_root=True,
                subject=EvidenceSubject.DISTRIBUTION,
                stage="distribution_root",
            )
            recorded = (
                *parents,
                _record_component(
                    request.source_directory.value,
                    base.asserted_prefix_components + len(components) - 1,
                    root_stat,
                ),
            )
        else:
            guard_fd = _DUP(base.fd)
            root_stat = _FSTAT(guard_fd)
            _validate_directory_policy(
                root_stat,
                expected_uid=request.expected_owner_uid,
                allow_root=True,
                subject=EvidenceSubject.DISTRIBUTION,
                stage="distribution_root",
            )
        try:
            reader_fd = _OS_OPEN(
                f"/proc/self/fd/{guard_fd}",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            reader_stat = _FSTAT(reader_fd)
        except OSError as exc:
            _abort(
                _open_error(
                    exc,
                    subject=EvidenceSubject.DISTRIBUTION,
                    stage="distribution_inventory_open",
                    path=request.source_directory.value,
                )
            )
        if (
            reader_stat.st_dev,
            reader_stat.st_ino,
        ) != (
            root_stat.st_dev,
            root_stat.st_ino,
        ):
            _abort(
                collection_failure(
                    CollectionDisposition.CHANGED_DURING_COLLECTION,
                    CollectionReasonCode.DISTRIBUTION_TREE_CHANGED,
                    subject=EvidenceSubject.DISTRIBUTION,
                    details={"stage": "distribution_inventory_open"},
                )
            )
        _safe_close(reader_fd)
        reader_fd = -1
        return _HeldDirectory(
            guard_fd=guard_fd,
            reader_fd=reader_fd,
            base=base,
            relative_components=components,
            path=PathObservation(
                requested_path=request.source_directory,
                resolved_path=request.source_directory,
                policy_id=PathPolicyId.DISTRIBUTION_REGULAR_NO_SYMLINK_V1,
                components=tuple(item.observation for item in recorded),
                binding_state=PathBindingState.STABLE,
                asserted_prefix_components=base.asserted_prefix_components,
            ),
            stable_stat=root_stat,
        )
    except _CollectorAbort:
        if reader_fd >= 0:
            _safe_close(reader_fd)
        if guard_fd >= 0:
            _safe_close(guard_fd)
        if base.close_fd:
            _safe_close(base.fd)
            base.close_fd = False
        raise
    finally:
        if parent_owned:
            _safe_close(parent_fd)


def _iter_directory_entries(fd: int) -> Iterator[os.DirEntry[str]]:
    iterator = _SCANDIR(fd)
    try:
        entries = list(iterator)
    finally:
        iterator.close()
    for entry in sorted(entries, key=lambda item: os.fsencode(item.name)):
        yield entry


def _inventory_directory(
    root: _HeldDirectory,
    prefix: str,
    depth: int,
    expected_stat: tuple[int, int, int, int, int, int, int, int, int] | None,
    *,
    expected_uid: int,
    limits: CollectorLimits,
    entries: list[_InventoryEntry],
    totals: list[int],
) -> tuple[tuple[str, int, tuple[int, int, int, int, int, int, int, int, int]], ...]:
    if depth > limits.tree_depth:
        _abort(
            collection_failure(
                CollectionDisposition.LIMIT_EXCEEDED,
                CollectionReasonCode.DEPTH_LIMIT_EXCEEDED,
                subject=EvidenceSubject.DISTRIBUTION,
                details={"stage": "tree_inventory", "limit": limits.tree_depth},
            )
        )
    directory_guard_fd = root.guard_fd
    guard_owned = False
    if prefix:
        components = _relative_components(prefix, limits)
        if components is None:
            _abort(
                collection_failure(
                    CollectionDisposition.INVALID_REQUEST,
                    CollectionReasonCode.INVALID_RELATIVE_PATH,
                    subject=EvidenceSubject.DISTRIBUTION,
                    details={"stage": "tree_inventory"},
                )
            )
        base = _BaseAnchor(
            fd=root.guard_fd,
            path=root.path.resolved_path.value,
            close_fd=False,
            asserted_prefix_components=len(root.path.resolved_path.value.split("/"))
            - 1,
            identity=_component_identity(root.stable_stat),
        )
        directory_guard_fd, guard_owned, _ = _traverse_directories(
            base,
            components,
            expected_uid=expected_uid,
            allow_root=True,
            subject=EvidenceSubject.DISTRIBUTION,
        )
    guard_stat = _FSTAT(directory_guard_fd)
    if expected_stat is not None and _stat_tuple(guard_stat) != expected_stat:
        if guard_owned:
            _safe_close(directory_guard_fd)
        _abort(
            collection_failure(
                CollectionDisposition.CHANGED_DURING_COLLECTION,
                CollectionReasonCode.DISTRIBUTION_TREE_CHANGED,
                subject=EvidenceSubject.DISTRIBUTION,
                details={"stage": "tree_inventory"},
            )
        )
    try:
        reader_fd = _OS_OPEN(
            f"/proc/self/fd/{directory_guard_fd}",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        reader_stat = _FSTAT(reader_fd)
    except OSError as exc:
        if "reader_fd" in locals():
            _safe_close(reader_fd)
        if guard_owned:
            _safe_close(directory_guard_fd)
        _abort(
            _open_error(
                exc,
                subject=EvidenceSubject.DISTRIBUTION,
                stage="tree_inventory",
            )
        )
    if (reader_stat.st_dev, reader_stat.st_ino) != (
        guard_stat.st_dev,
        guard_stat.st_ino,
    ):
        _safe_close(reader_fd)
        if guard_owned:
            _safe_close(directory_guard_fd)
        _abort(
            collection_failure(
                CollectionDisposition.CHANGED_DURING_COLLECTION,
                CollectionReasonCode.DISTRIBUTION_TREE_CHANGED,
                subject=EvidenceSubject.DISTRIBUTION,
                details={"stage": "tree_inventory"},
            )
        )
    children: list[
        tuple[str, int, tuple[int, int, int, int, int, int, int, int, int]]
    ] = []
    try:
        for entry in _iter_directory_entries(reader_fd):
            name = entry.name
            try:
                name.encode("utf-8")
            except UnicodeEncodeError:
                _abort(
                    collection_failure(
                        CollectionDisposition.INVALID_REQUEST,
                        CollectionReasonCode.INVALID_RELATIVE_PATH,
                        subject=EvidenceSubject.DISTRIBUTION,
                        details={"stage": "tree_inventory"},
                    )
                )
            if not prefix and _LOCK_RE.fullmatch(name):
                continue
            relative = f"{prefix}/{name}" if prefix else name
            if len(relative.split("/")) > limits.tree_depth:
                _abort(
                    collection_failure(
                        CollectionDisposition.LIMIT_EXCEEDED,
                        CollectionReasonCode.DEPTH_LIMIT_EXCEEDED,
                        subject=EvidenceSubject.DISTRIBUTION,
                        details={
                            "stage": "tree_inventory",
                            "limit": limits.tree_depth,
                        },
                    )
                )
            if _relative_components(relative, limits) is None:
                _abort(
                    collection_failure(
                        CollectionDisposition.INVALID_REQUEST,
                        CollectionReasonCode.INVALID_RELATIVE_PATH,
                        subject=EvidenceSubject.DISTRIBUTION,
                        details={
                            "stage": "tree_inventory",
                            "path_sha256": path_sha256(relative),
                        },
                    )
                )
            try:
                value = entry.stat(follow_symlinks=False)
            except OSError as exc:
                _abort(
                    _open_error(
                        exc,
                        subject=EvidenceSubject.DISTRIBUTION,
                        stage="tree_inventory",
                    )
                )
            if stat.S_ISLNK(value.st_mode):
                _abort(
                    collection_failure(
                        CollectionDisposition.POLICY_REJECTED,
                        CollectionReasonCode.PATH_POLICY_VIOLATION,
                        subject=EvidenceSubject.DISTRIBUTION,
                        details={"stage": "tree_inventory"},
                    )
                )
            if stat.S_ISDIR(value.st_mode):
                _validate_directory_policy(
                    value,
                    expected_uid=expected_uid,
                    allow_root=True,
                    subject=EvidenceSubject.DISTRIBUTION,
                    stage="tree_inventory",
                )
                entry_type = "d"
                size = 0
            elif stat.S_ISREG(value.st_mode):
                if not _allowed_owner(value, expected_uid, True):
                    _abort(
                        collection_failure(
                            CollectionDisposition.POLICY_REJECTED,
                            CollectionReasonCode.OWNER_MISMATCH,
                            subject=EvidenceSubject.DISTRIBUTION,
                            details={"stage": "tree_inventory"},
                        )
                    )
                if value.st_mode & (_WRITABLE_BY_OTHERS | _SPECIAL_MODE_BITS):
                    _abort(
                        collection_failure(
                            CollectionDisposition.POLICY_REJECTED,
                            CollectionReasonCode.UNSAFE_MODE,
                            subject=EvidenceSubject.DISTRIBUTION,
                            details={"stage": "tree_inventory"},
                        )
                    )
                if value.st_nlink != 1:
                    _abort(
                        collection_failure(
                            CollectionDisposition.POLICY_REJECTED,
                            CollectionReasonCode.LINK_COUNT_INVALID,
                            subject=EvidenceSubject.DISTRIBUTION,
                            details={"stage": "tree_inventory"},
                        )
                    )
                entry_type = "f"
                size = value.st_size
                totals[0] += size
                if totals[0] > limits.tree_total_regular_bytes:
                    _abort(
                        collection_failure(
                            CollectionDisposition.LIMIT_EXCEEDED,
                            CollectionReasonCode.TOTAL_BYTE_LIMIT_EXCEEDED,
                            subject=EvidenceSubject.DISTRIBUTION,
                            details={
                                "stage": "tree_inventory",
                                "bytes": totals[0],
                                "limit": limits.tree_total_regular_bytes,
                            },
                        )
                    )
            else:
                _abort(
                    collection_failure(
                        CollectionDisposition.POLICY_REJECTED,
                        CollectionReasonCode.NOT_REGULAR,
                        subject=EvidenceSubject.DISTRIBUTION,
                        details={"stage": "tree_inventory"},
                    )
                )
            entries.append(
                _InventoryEntry(
                    relative_path=relative,
                    entry_type=entry_type,
                    stable_tuple=_stat_tuple(value),
                    mode_octal=f"{stat.S_IMODE(value.st_mode):04o}",
                    size_bytes=size,
                )
            )
            if len(entries) > limits.tree_entries:
                _abort(
                    collection_failure(
                        CollectionDisposition.LIMIT_EXCEEDED,
                        CollectionReasonCode.ENTRY_LIMIT_EXCEEDED,
                        subject=EvidenceSubject.DISTRIBUTION,
                        details={
                            "stage": "tree_inventory",
                            "count": len(entries),
                            "limit": limits.tree_entries,
                        },
                    )
                )
            if entry_type == "d":
                children.append((relative, depth + 1, _stat_tuple(value)))
        try:
            reader_after = _FSTAT(reader_fd)
            guard_after = _FSTAT(directory_guard_fd)
        except OSError:
            _abort(
                collection_failure(
                    CollectionDisposition.CHANGED_DURING_COLLECTION,
                    CollectionReasonCode.DISTRIBUTION_TREE_CHANGED,
                    subject=EvidenceSubject.DISTRIBUTION,
                    details={"stage": "tree_inventory_final_fstat"},
                )
            )
        if prefix:
            stable = _stat_tuple(guard_stat)
            changed = (
                _stat_tuple(reader_after) != stable
                or _stat_tuple(guard_after) != stable
            )
        else:
            stable_root = _root_stability(guard_stat)
            changed = (
                _root_stability(reader_after) != stable_root
                or _root_stability(guard_after) != stable_root
            )
        if changed:
            _abort(
                collection_failure(
                    CollectionDisposition.CHANGED_DURING_COLLECTION,
                    CollectionReasonCode.DISTRIBUTION_TREE_CHANGED,
                    subject=EvidenceSubject.DISTRIBUTION,
                    details={"stage": "tree_inventory_final_fstat"},
                )
            )
    finally:
        _safe_close(reader_fd)
        if guard_owned:
            _safe_close(directory_guard_fd)
    return tuple(children)


def _inventory(
    root: _HeldDirectory,
    *,
    expected_uid: int,
    limits: CollectorLimits,
) -> tuple[_InventoryEntry, ...]:
    entries: list[_InventoryEntry] = []
    totals = [0]
    pending: list[
        tuple[
            str,
            int,
            tuple[int, int, int, int, int, int, int, int, int] | None,
        ]
    ] = [("", 0, None)]
    while pending:
        prefix, depth, expected_stat = pending.pop()
        children = _inventory_directory(
            root,
            prefix,
            depth,
            expected_stat,
            expected_uid=expected_uid,
            limits=limits,
            entries=entries,
            totals=totals,
        )
        pending.extend(reversed(children))
    return tuple(sorted(entries, key=lambda item: item.relative_path.encode("utf-8")))


def _validate_distribution_request(
    request: TrustedDistributionRequest,
    limits: CollectorLimits,
) -> None:
    if (
        request.expected_owner_uid < 0
        or request.expected_package_name != "@github/copilot"
        or request.expected_package_type != "module"
        or request.expected_bin_name != "copilot"
        or request.expected_bin_target != "npm-loader.js"
        or request.platform_directory != "linux-x64"
    ):
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_ROLE_SET,
                subject=EvidenceSubject.REQUEST,
                details={"stage": "distribution_request"},
            )
        )
    if len(request.artifacts) > limits.artifact_requests_hard_max:
        _abort(
            collection_failure(
                CollectionDisposition.LIMIT_EXCEEDED,
                CollectionReasonCode.ENTRY_LIMIT_EXCEEDED,
                subject=EvidenceSubject.REQUEST,
                details={
                    "stage": "artifact_requests",
                    "count": len(request.artifacts),
                    "limit": limits.artifact_requests_hard_max,
                },
            )
        )
    roles = tuple(item.role for item in request.artifacts)
    if len(set(roles)) != len(roles):
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.DUPLICATE_ARTIFACT_ROLE,
                subject=EvidenceSubject.REQUEST,
                details={"stage": "artifact_requests"},
            )
        )
    if set(roles) != REQUIRED_ARTIFACT_NAMES:
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_ROLE_SET,
                subject=EvidenceSubject.REQUEST,
                details={"stage": "artifact_requests"},
            )
        )
    for item in request.artifacts:
        if (
            item.relative_path != item.role.value
            or item.expected_format is not _ARTIFACT_FORMATS[item.role]
            or item.expected_format is FormatId.SHELL_SCRIPT
            or item.max_bytes < 0
            or item.max_bytes > _ARTIFACT_MAX_BYTES[item.role]
        ):
            _abort(
                collection_failure(
                    CollectionDisposition.INVALID_REQUEST,
                    CollectionReasonCode.INVALID_ROLE_SET,
                    subject=EvidenceSubject.REQUEST,
                    details={"stage": "artifact_requests", "role": item.role},
                )
            )
    schema_names = tuple(item.name for item in request.schemas)
    if len(set(schema_names)) != len(schema_names):
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.DUPLICATE_CONTRACT_INPUT,
                subject=EvidenceSubject.REQUEST,
                details={"stage": "schema_inputs"},
            )
        )
    if set(schema_names) != {
        SchemaDocumentName.SESSION_EVENTS,
        SchemaDocumentName.API,
    }:
        _abort(
            collection_failure(
                CollectionDisposition.INVALID_REQUEST,
                CollectionReasonCode.INVALID_ROLE_SET,
                subject=EvidenceSubject.REQUEST,
                details={"stage": "schema_inputs"},
            )
        )
    for schema in request.schemas:
        counts = (
            schema.definition_count,
            schema.property_count,
            schema.event_type_literal_count,
        )
        if (
            min(counts) < 0
            or max(counts) > 2**31 - 1
            or (
                schema.event_variant_count is not None
                and not 0 <= schema.event_variant_count <= 2**31 - 1
            )
        ):
            _abort(
                collection_failure(
                    CollectionDisposition.MISMATCH,
                    CollectionReasonCode.TRUSTED_DIGEST_INPUT_INVALID,
                    subject=EvidenceSubject.CONTRACT,
                    details={"stage": "schema_inputs"},
                )
            )
    if (
        request.grammar.source != "completion_bash_review_record"
        or request.help_contract.manifest_algorithm != "sha256-help-surfaces-v1"
        or min(
            request.grammar.root_flag_count,
            request.grammar.advertised_root_flag_count,
            request.grammar.hidden_root_flag_count,
            request.help_contract.surface_count,
        )
        < 0
        or max(
            request.grammar.root_flag_count,
            request.grammar.advertised_root_flag_count,
            request.grammar.hidden_root_flag_count,
            request.help_contract.surface_count,
        )
        > 2**31 - 1
        or request.grammar.advertised_root_flag_count
        + request.grammar.hidden_root_flag_count
        != request.grammar.root_flag_count
    ):
        _abort(
            collection_failure(
                CollectionDisposition.MISMATCH,
                CollectionReasonCode.TRUSTED_DIGEST_INPUT_INVALID,
                subject=EvidenceSubject.CONTRACT,
                details={"stage": "trusted_contract"},
            )
        )


def _artifact_file_request(
    request: TrustedDistributionRequest,
    artifact: ArtifactRequest,
) -> FileCollectionRequest:
    absolute = AbsolutePath(
        request.source_directory.value + "/" + artifact.relative_path
    )
    return FileCollectionRequest(
        role=FileRole.DISTRIBUTION_ARTIFACT,
        absolute_path=absolute,
        expected_owner_uid=request.expected_owner_uid,
        allow_root_owner=True,
        require_executable=artifact.expected_format
        in {FormatId.ELF64_X86_64_EXEC, FormatId.ELF64_X86_64_DYN},
        policy_id=PathPolicyId.DISTRIBUTION_REGULAR_NO_SYMLINK_V1,
        max_bytes=artifact.max_bytes,
        format_id=artifact.expected_format,
    )


def _package_file_request(
    request: TrustedDistributionRequest,
) -> FileCollectionRequest:
    return FileCollectionRequest(
        role=FileRole.PACKAGE_MANIFEST,
        absolute_path=AbsolutePath(request.source_directory.value + "/package.json"),
        expected_owner_uid=request.expected_owner_uid,
        allow_root_owner=True,
        require_executable=False,
        policy_id=PathPolicyId.DISTRIBUTION_REGULAR_NO_SYMLINK_V1,
        max_bytes=262_144,
        format_id=FormatId.JSON_UTF8,
    )


def _map_missing(
    failure: CollectionFailure,
    *,
    schema: bool,
) -> CollectionFailure:
    if (
        failure.disposition is CollectionDisposition.UNAVAILABLE
        and CollectionReasonCode.RESOURCE_NOT_FOUND in failure.reason_codes
    ):
        return collection_failure(
            CollectionDisposition.INCOMPLETE,
            CollectionReasonCode.SCHEMA_MISSING
            if schema
            else CollectionReasonCode.ARTIFACT_MISSING,
            subject=EvidenceSubject.SCHEMA if schema else EvidenceSubject.ARTIFACT,
            details={"stage": "required_file"},
        )
    return failure


def _parse_package(
    held: _HeldFile,
    request: TrustedDistributionRequest,
    *,
    deadline: MonotonicDeadline,
) -> PackageManifestObservation:
    raw = _read_all(
        held,
        deadline=deadline,
        subject=EvidenceSubject.PACKAGE,
    )
    try:
        value = loads_bounded(
            raw,
            max_bytes=262_144,
            reject_duplicate_keys=True,
        )
    except (UnicodeError, ValueError, RecursionError):
        _abort(
            collection_failure(
                CollectionDisposition.MALFORMED_INPUT,
                CollectionReasonCode.PACKAGE_MANIFEST_INVALID,
                subject=EvidenceSubject.PACKAGE,
                details={"stage": "package_manifest"},
            )
        )
    if not isinstance(value, dict):
        _abort(
            collection_failure(
                CollectionDisposition.MALFORMED_INPUT,
                CollectionReasonCode.PACKAGE_MANIFEST_INVALID,
                subject=EvidenceSubject.PACKAGE,
                details={"stage": "package_manifest"},
            )
        )
    name = value.get("name")
    version = value.get("version")
    package_type = value.get("type")
    binary = value.get("bin")
    if (
        not isinstance(name, str)
        or not isinstance(version, str)
        or not isinstance(package_type, str)
        or type(binary) is not dict
        or set(binary) != {request.expected_bin_name}
        or binary.get(request.expected_bin_name) != request.expected_bin_target
    ):
        _abort(
            collection_failure(
                CollectionDisposition.MISMATCH,
                CollectionReasonCode.PACKAGE_IDENTITY_MISMATCH,
                subject=EvidenceSubject.PACKAGE,
                details={"stage": "package_identity"},
            )
        )
    try:
        observed_version = VersionText(version)
    except ValueError:
        _abort(
            collection_failure(
                CollectionDisposition.MALFORMED_INPUT,
                CollectionReasonCode.PACKAGE_MANIFEST_INVALID,
                subject=EvidenceSubject.PACKAGE,
                details={"stage": "package_identity"},
            )
        )
    if (
        name != request.expected_package_name
        or package_type != request.expected_package_type
    ):
        _abort(
            collection_failure(
                CollectionDisposition.MISMATCH,
                CollectionReasonCode.PACKAGE_IDENTITY_MISMATCH,
                subject=EvidenceSubject.PACKAGE,
                details={"stage": "package_identity"},
            )
        )
    if observed_version != request.expected_version:
        _abort(
            collection_failure(
                CollectionDisposition.MISMATCH,
                CollectionReasonCode.DISTRIBUTION_VERSION_MISMATCH,
                subject=EvidenceSubject.PACKAGE,
                details={"stage": "package_identity"},
            )
        )
    return PackageManifestObservation(
        file=_finalize_held_file(held, subject=EvidenceSubject.PACKAGE),
        name=name,
        version=observed_version,
        package_type=package_type,
        bin_name=request.expected_bin_name,
        bin_target=request.expected_bin_target,
    )


def _find_payload(
    container: _HeldFile,
    payload: bytes,
    *,
    deadline: MonotonicDeadline,
) -> EmbeddedPayloadObservation:
    if not payload:
        _abort(
            collection_failure(
                CollectionDisposition.INCOMPLETE,
                CollectionReasonCode.EMBEDDED_PAYLOAD_MISSING,
                subject=EvidenceSubject.FRONTEND,
                details={"stage": "embedded_payload"},
            )
        )
    count = 0
    first_offset = -1
    offset = 0
    carry = b""
    while offset < container.stable_stat.st_size:
        _check_deadline(deadline, EvidenceSubject.FRONTEND)
        try:
            chunk = _PREAD(
                container.reader_fd,
                min(1_048_576, container.stable_stat.st_size - offset),
                offset,
            )
        except OSError as exc:
            _abort(
                collection_failure(
                    CollectionDisposition.UNAVAILABLE,
                    CollectionReasonCode.IO_ERROR,
                    subject=EvidenceSubject.FRONTEND,
                    details={
                        "stage": "embedded_payload",
                        "errno_class": errno_class(exc.errno),
                    },
                )
            )
        if not chunk:
            _abort(
                collection_failure(
                    CollectionDisposition.MALFORMED_INPUT,
                    CollectionReasonCode.SHORT_READ,
                    subject=EvidenceSubject.FRONTEND,
                    details={"stage": "embedded_payload", "bytes": offset},
                )
            )
        window = carry + chunk
        base_offset = offset - len(carry)
        search_from = 0
        while True:
            found = window.find(payload, search_from)
            if found < 0:
                break
            count += 1
            if first_offset < 0:
                first_offset = base_offset + found
            if count > 1:
                _abort(
                    collection_failure(
                        CollectionDisposition.AMBIGUOUS,
                        CollectionReasonCode.EMBEDDED_PAYLOAD_AMBIGUOUS,
                        subject=EvidenceSubject.FRONTEND,
                        details={"stage": "embedded_payload", "count": count},
                    )
                )
            search_from = found + 1
        carry = window[-(len(payload) - 1) :] if len(payload) > 1 else b""
        offset += len(chunk)
    try:
        extra = _PREAD(container.reader_fd, 1, container.stable_stat.st_size)
    except OSError as exc:
        _abort(
            collection_failure(
                CollectionDisposition.UNAVAILABLE,
                CollectionReasonCode.IO_ERROR,
                subject=EvidenceSubject.FRONTEND,
                details={
                    "stage": "embedded_payload",
                    "errno_class": errno_class(exc.errno),
                },
            )
        )
    if extra:
        _abort(
            collection_failure(
                CollectionDisposition.CHANGED_DURING_COLLECTION,
                CollectionReasonCode.FILE_MUTATED,
                subject=EvidenceSubject.FRONTEND,
                details={"stage": "embedded_payload"},
            )
        )
    if count == 0:
        _abort(
            collection_failure(
                CollectionDisposition.INCOMPLETE,
                CollectionReasonCode.EMBEDDED_PAYLOAD_MISSING,
                subject=EvidenceSubject.FRONTEND,
                details={"stage": "embedded_payload"},
            )
        )
    return EmbeddedPayloadObservation(
        offset=first_offset,
        sha256=Sha256(sha256_hex(payload)),
    )


def _tree_manifest(
    root: _HeldDirectory,
    inventory: tuple[_InventoryEntry, ...],
    critical: dict[str, _HeldFile],
    request: TrustedDistributionRequest,
    *,
    limits: CollectorLimits,
    deadline: MonotonicDeadline,
) -> tuple[TreeManifestObservation, int, int]:
    rows: list[TreeEntryObservation] = []
    files_hashed = 0
    bytes_hashed = 0
    for entry in inventory:
        if entry.entry_type == "d":
            rows.append(
                TreeEntryObservation(
                    entry_type="d",
                    mode_octal=entry.mode_octal,
                    size_bytes=0,
                    sha256=sha256_hex(b""),
                    relative_path=entry.relative_path,
                )
            )
            continue
        held = critical.get(entry.relative_path)
        if held is not None:
            if _stat_tuple(held.stable_stat) != entry.stable_tuple:
                _abort(
                    collection_failure(
                        CollectionDisposition.CHANGED_DURING_COLLECTION,
                        CollectionReasonCode.DISTRIBUTION_TREE_CHANGED,
                        subject=EvidenceSubject.DISTRIBUTION,
                        details={"stage": "tree_hash"},
                    )
                )
            digest = held.descriptor.sha256
            size = held.stable_stat.st_size
        else:
            file_request = FileCollectionRequest(
                role=FileRole.DISTRIBUTION_ARTIFACT,
                absolute_path=AbsolutePath(
                    request.source_directory.value + "/" + entry.relative_path
                ),
                expected_owner_uid=request.expected_owner_uid,
                allow_root_owner=True,
                require_executable=False,
                policy_id=PathPolicyId.DISTRIBUTION_REGULAR_NO_SYMLINK_V1,
                max_bytes=min(limits.generic_file_bytes, entry.size_bytes),
                format_id=FormatId.OPAQUE,
            )
            nested_base = _BaseAnchor(
                fd=root.guard_fd,
                path=request.source_directory.value,
                close_fd=False,
                asserted_prefix_components=len(
                    request.source_directory.value.split("/")
                )
                - 1,
                identity=_component_identity(root.stable_stat),
            )
            nested = _open_held_file_from_base(
                nested_base,
                entry.relative_path,
                file_request,
                limits=limits,
                deadline=deadline,
                subject=EvidenceSubject.DISTRIBUTION,
            )
            try:
                evidence = _finalize_held_file(
                    nested,
                    subject=EvidenceSubject.DISTRIBUTION,
                )
            finally:
                nested.close()
            if _stat_tuple(nested.stable_stat) != entry.stable_tuple:
                _abort(
                    collection_failure(
                        CollectionDisposition.CHANGED_DURING_COLLECTION,
                        CollectionReasonCode.DISTRIBUTION_TREE_CHANGED,
                        subject=EvidenceSubject.DISTRIBUTION,
                        details={"stage": "tree_hash"},
                    )
                )
            digest = evidence.descriptor.sha256
            size = evidence.descriptor.stat.size_bytes
        files_hashed += 1
        bytes_hashed += size
        rows.append(
            TreeEntryObservation(
                entry_type="f",
                mode_octal=entry.mode_octal,
                size_bytes=size,
                sha256=digest,
                relative_path=entry.relative_path,
            )
        )
    manifest_rows = tuple(
        TreeManifestRow(
            entry_type=row.entry_type,
            mode_octal=row.mode_octal,
            size_bytes=row.size_bytes,
            sha256=row.sha256,
            relative_path=row.relative_path,
        )
        for row in rows
    )
    encoded = manifest_bytes(manifest_rows)
    return (
        TreeManifestObservation(
            algorithm="sha256-tree-v1",
            sha256=Sha256(sha256_hex(encoded)),
            entry_count=len(rows),
            total_regular_file_bytes=bytes_hashed,
            rows=tuple(rows),
        ),
        files_hashed,
        bytes_hashed,
    )


def _collect_distribution(
    request: TrustedDistributionRequest,
    *,
    limits: CollectorLimits,
    deadline: MonotonicDeadline,
    frontend: _HeldFile | None,
) -> tuple[DistributionEvidence, EmbeddedPayloadObservation | None]:
    _validate_distribution_request(request, limits)
    try:
        root = _open_distribution_root(request, limits=limits)
    except _CollectorAbort as exc:
        if (
            exc.failure.disposition is CollectionDisposition.UNAVAILABLE
            and CollectionReasonCode.RESOURCE_NOT_FOUND in exc.failure.reason_codes
        ):
            _abort(
                collection_failure(
                    CollectionDisposition.MISMATCH,
                    CollectionReasonCode.PACKAGE_IDENTITY_MISMATCH,
                    subject=EvidenceSubject.DISTRIBUTION,
                    details={"stage": "distribution_root"},
                )
            )
        raise
    held_files: list[_HeldFile] = []
    try:
        root_before = _FSTAT(root.guard_fd)
        inventory_a = _inventory(
            root,
            expected_uid=request.expected_owner_uid,
            limits=limits,
        )
        _after_inventory_a()
        nested_base = _BaseAnchor(
            fd=root.guard_fd,
            path=request.source_directory.value,
            close_fd=False,
            asserted_prefix_components=len(request.source_directory.value.split("/"))
            - 1,
            identity=_component_identity(root.stable_stat),
        )
        package_request = _package_file_request(request)
        try:
            package_held = _open_held_file_from_base(
                nested_base,
                "package.json",
                package_request,
                limits=limits,
                deadline=deadline,
                subject=EvidenceSubject.PACKAGE,
            )
        except _CollectorAbort as exc:
            _abort(_map_missing(exc.failure, schema=False))
        held_files.append(package_held)
        _check_format(
            package_held,
            FormatId.JSON_UTF8,
            deadline=deadline,
            subject=EvidenceSubject.PACKAGE,
            artifact_semantics=True,
        )

        artifact_held: dict[ArtifactName, _HeldFile] = {}
        for artifact in sorted(
            request.artifacts,
            key=lambda item: item.role.value.encode("utf-8"),
        ):
            try:
                held = _open_held_file_from_base(
                    nested_base,
                    artifact.relative_path,
                    _artifact_file_request(request, artifact),
                    limits=limits,
                    deadline=deadline,
                    subject=EvidenceSubject.ARTIFACT,
                )
            except _CollectorAbort as exc:
                _abort(
                    _map_missing(
                        exc.failure,
                        schema=artifact.role
                        in {
                            ArtifactName.SESSION_EVENTS_SCHEMA,
                            ArtifactName.API_SCHEMA,
                        },
                    )
                )
            held_files.append(held)
            _check_format(
                held,
                artifact.expected_format,
                deadline=deadline,
                subject=EvidenceSubject.ARTIFACT,
                artifact_semantics=True,
            )
            artifact_held[artifact.role] = held

        payload_raw = _read_all(
            artifact_held[ArtifactName.SEA_LOADER_JS],
            deadline=deadline,
            subject=EvidenceSubject.ARTIFACT,
        )
        embedded = (
            _find_payload(frontend, payload_raw, deadline=deadline)
            if frontend is not None
            else None
        )

        critical = {"package.json": package_held}
        critical.update({name.value: held for name, held in artifact_held.items()})
        content_manifest, files_hashed, bytes_hashed = _tree_manifest(
            root,
            inventory_a,
            critical,
            request,
            limits=limits,
            deadline=deadline,
        )
        inventory_b = _inventory(
            root,
            expected_uid=request.expected_owner_uid,
            limits=limits,
        )
        root_after = _FSTAT(root.guard_fd)
        if inventory_a != inventory_b or _root_stability(
            root_before
        ) != _root_stability(root_after):
            _abort(
                collection_failure(
                    CollectionDisposition.CHANGED_DURING_COLLECTION,
                    CollectionReasonCode.DISTRIBUTION_TREE_CHANGED,
                    subject=EvidenceSubject.DISTRIBUTION,
                    details={"stage": "tree_recheck"},
                )
            )
        _verify_directory_binding(root)

        package = _parse_package(package_held, request, deadline=deadline)
        artifacts: list[ArtifactEvidence] = []
        for name in sorted(artifact_held, key=lambda item: item.value.encode("utf-8")):
            evidence = _finalize_held_file(
                artifact_held[name],
                subject=EvidenceSubject.ARTIFACT,
            )
            artifacts.append(ArtifactEvidence(name=name, file=evidence))
        artifact_evidence = {item.name: item for item in artifacts}
        schemas: list[SchemaEvidence] = []
        for trusted in sorted(request.schemas, key=lambda item: item.name.value):
            schema_artifact = artifact_evidence[_SCHEMA_ARTIFACT[trusted.name]]
            if (
                schema_artifact.file.descriptor.sha256
                != trusted.expected_file_sha256.value
            ):
                _abort(
                    collection_failure(
                        CollectionDisposition.MISMATCH,
                        CollectionReasonCode.SCHEMA_DIGEST_MISMATCH,
                        subject=EvidenceSubject.SCHEMA,
                        details={
                            "stage": "schema_digest",
                            "expected_sha256": trusted.expected_file_sha256.value,
                            "observed_sha256": (schema_artifact.file.descriptor.sha256),
                        },
                    )
                )
            schemas.append(
                SchemaEvidence(
                    name=trusted.name,
                    file=schema_artifact.file,
                    source_record_sha256=trusted.source_record_sha256,
                    definition_count=trusted.definition_count,
                    property_count=trusted.property_count,
                    event_type_literal_count=trusted.event_type_literal_count,
                    event_variant_count=trusted.event_variant_count,
                    definition_names_sha256=trusted.definition_names_sha256,
                    property_names_sha256=trusted.property_names_sha256,
                    event_type_literals_sha256=trusted.event_type_literals_sha256,
                )
            )
        result = DistributionEvidence(
            source=ObservedDistributionSource(root=root.path),
            version=request.expected_version,
            platform_directory=request.platform_directory,
            package_manifest=package,
            artifacts=tuple(artifacts),
            schemas=tuple(schemas),
            grammar=request.grammar,
            help_contract=request.help_contract,
            content_manifest=content_manifest,
            files_hashed=files_hashed,
            bytes_hashed=bytes_hashed,
        )
        return result, embedded
    finally:
        for held in reversed(held_files):
            held.close()
        root.close()


def collect_distribution_evidence(
    request: TrustedDistributionRequest,
    *,
    limits: CollectorLimits = DEFAULT_COLLECTOR_LIMITS,
    deadline: MonotonicDeadline | None = None,
) -> DistributionEvidence | CollectionFailure:
    """Collect one explicitly named distribution root without ambient selection."""

    if not isinstance(request, TrustedDistributionRequest) or not isinstance(
        limits, CollectorLimits
    ):
        raise TypeError("invalid distribution collection argument type")
    unsupported = _platform_failure()
    if unsupported is not None:
        return unsupported
    actual_deadline = _deadline_or_default(
        deadline,
        limits.distribution_deadline_seconds,
    )
    try:
        evidence, _ = _collect_distribution(
            request,
            limits=limits,
            deadline=actual_deadline,
            frontend=None,
        )
        return evidence
    except (OSError, UnicodeError, ValueError, RecursionError, OverflowError) as exc:
        if isinstance(exc, _CollectorAbort):
            return exc.failure
        if isinstance(exc, OSError):
            return _open_error(
                exc,
                subject=EvidenceSubject.DISTRIBUTION,
                stage="distribution_collection",
            )
        return collection_failure(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.PACKAGE_MANIFEST_INVALID,
            subject=EvidenceSubject.DISTRIBUTION,
            details={"stage": "distribution_collection"},
        )


def _normalize_link_target(
    resolved_parent: list[str],
    target: str,
) -> list[str] | None:
    output = [] if target.startswith("/") else list(resolved_parent)
    for component in target.split("/"):
        if component in {"", "."}:
            continue
        if component == "..":
            if not output:
                return None
            output.pop()
            continue
        if not component.isprintable() or "\x00" in component:
            return None
        try:
            if len(component.encode("utf-8")) > 255:
                return None
        except UnicodeEncodeError:
            return None
        output.append(component)
    return output


def _resolve_interpreter(
    requested: AbsolutePath,
    request: OfflineRuntimeCollectionRequest,
    *,
    limits: CollectorLimits,
    deadline: MonotonicDeadline,
) -> tuple[_HeldFile, tuple[PathComponentObservation, ...]]:
    base = _prepare_base(
        expected_uid=request.interpreter_expected_owner_uid,
        allow_root=request.interpreter_allow_root_owner,
        anchor_fd=request.anchor_fd,
        anchor_path=request.anchor_path,
        subject=EvidenceSubject.INTERPRETER,
    )
    pending = requested.value[1:].split("/")
    resolved: list[str] = []
    chain: list[PathComponentObservation] = []
    seen_links: set[tuple[int, int]] = set()
    hops = 0
    try:
        while pending:
            _check_deadline(deadline, EvidenceSubject.INTERPRETER)
            component = pending.pop(0)
            parent_fd, parent_owned, _ = _traverse_directories(
                base,
                tuple(resolved),
                expected_uid=request.interpreter_expected_owner_uid,
                allow_root=request.interpreter_allow_root_owner,
                subject=EvidenceSubject.INTERPRETER,
            )
            guard = -1
            try:
                guard = _OS_OPEN(
                    component,
                    os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent_fd,
                )
                value = _FSTAT(guard)
            except OSError as exc:
                if guard >= 0:
                    _safe_close(guard)
                if parent_owned:
                    _safe_close(parent_fd)
                _abort(
                    _open_error(
                        exc,
                        subject=EvidenceSubject.INTERPRETER,
                        stage="interpreter_resolve",
                    )
                )
            actual_path = _absolute_join(base.path, [*resolved, component])
            if stat.S_ISLNK(value.st_mode):
                if not _allowed_owner(
                    value,
                    request.interpreter_expected_owner_uid,
                    request.interpreter_allow_root_owner,
                ):
                    _safe_close(guard)
                    if parent_owned:
                        _safe_close(parent_fd)
                    _abort(
                        collection_failure(
                            CollectionDisposition.POLICY_REJECTED,
                            CollectionReasonCode.OWNER_MISMATCH,
                            subject=EvidenceSubject.INTERPRETER,
                            details={"stage": "interpreter_symlink"},
                        )
                    )
                identity = (value.st_dev, value.st_ino)
                if identity in seen_links:
                    _safe_close(guard)
                    if parent_owned:
                        _safe_close(parent_fd)
                    _abort(
                        collection_failure(
                            CollectionDisposition.POLICY_REJECTED,
                            CollectionReasonCode.PATH_POLICY_VIOLATION,
                            subject=EvidenceSubject.INTERPRETER,
                            details={"stage": "interpreter_loop"},
                        )
                    )
                seen_links.add(identity)
                hops += 1
                if hops > 40:
                    _safe_close(guard)
                    if parent_owned:
                        _safe_close(parent_fd)
                    _abort(
                        collection_failure(
                            CollectionDisposition.LIMIT_EXCEEDED,
                            CollectionReasonCode.DEPTH_LIMIT_EXCEEDED,
                            subject=EvidenceSubject.INTERPRETER,
                            details={
                                "stage": "interpreter_symlink",
                                "count": hops,
                                "limit": 40,
                            },
                        )
                    )
                try:
                    target = _READLINK(component, dir_fd=parent_fd)
                    target_raw = target.encode("utf-8", errors="strict")
                except (OSError, UnicodeError) as exc:
                    _safe_close(guard)
                    if parent_owned:
                        _safe_close(parent_fd)
                    if isinstance(exc, OSError):
                        _abort(
                            _open_error(
                                exc,
                                subject=EvidenceSubject.INTERPRETER,
                                stage="interpreter_symlink",
                            )
                        )
                    _abort(
                        collection_failure(
                            CollectionDisposition.MALFORMED_INPUT,
                            CollectionReasonCode.ELF_INTERPRETER_PATH_INVALID,
                            subject=EvidenceSubject.INTERPRETER,
                            details={"stage": "interpreter_symlink"},
                        )
                    )
                if (
                    not target_raw
                    or len(target_raw) > 4096
                    or b"\0" in target_raw
                    or any(byte < 0x20 or byte == 0x7F for byte in target_raw)
                ):
                    _safe_close(guard)
                    if parent_owned:
                        _safe_close(parent_fd)
                    _abort(
                        collection_failure(
                            CollectionDisposition.MALFORMED_INPUT,
                            CollectionReasonCode.ELF_INTERPRETER_PATH_INVALID,
                            subject=EvidenceSubject.INTERPRETER,
                            details={"stage": "interpreter_symlink"},
                        )
                    )
                chain.append(
                    _record_component(
                        actual_path,
                        base.asserted_prefix_components + len(resolved),
                        value,
                        link_text_sha256=sha256_hex(target_raw),
                    ).observation
                )
                normalized = _normalize_link_target(resolved, target)
                _safe_close(guard)
                if parent_owned:
                    _safe_close(parent_fd)
                if normalized is None:
                    _abort(
                        collection_failure(
                            CollectionDisposition.POLICY_REJECTED,
                            CollectionReasonCode.PATH_POLICY_VIOLATION,
                            subject=EvidenceSubject.INTERPRETER,
                            details={"stage": "interpreter_symlink"},
                        )
                    )
                pending = [*normalized, *pending]
                resolved = []
                continue
            _safe_close(guard)
            if parent_owned:
                _safe_close(parent_fd)
            if pending:
                if not stat.S_ISDIR(value.st_mode):
                    _abort(
                        collection_failure(
                            CollectionDisposition.POLICY_REJECTED,
                            CollectionReasonCode.PATH_POLICY_VIOLATION,
                            subject=EvidenceSubject.INTERPRETER,
                            details={"stage": "interpreter_resolve"},
                        )
                    )
                _validate_directory_policy(
                    value,
                    expected_uid=request.interpreter_expected_owner_uid,
                    allow_root=request.interpreter_allow_root_owner,
                    subject=EvidenceSubject.INTERPRETER,
                    stage="interpreter_resolve",
                )
                resolved.append(component)
                continue
            resolved.append(component)
            relative = "/".join(resolved)
            actual = AbsolutePath(_absolute_join(base.path, resolved))
            file_request = FileCollectionRequest(
                role=FileRole.ELF_INTERPRETER,
                absolute_path=actual,
                expected_owner_uid=request.interpreter_expected_owner_uid,
                allow_root_owner=request.interpreter_allow_root_owner,
                require_executable=True,
                policy_id=PathPolicyId.RESOLVED_INTERPRETER_V1,
                max_bytes=16_777_216,
                format_id=FormatId.ELF64_X86_64_DYN,
            )
            held = _open_held_file_from_base(
                base,
                relative,
                file_request,
                limits=limits,
                deadline=deadline,
                subject=EvidenceSubject.INTERPRETER,
                requested_path=requested,
                resolved_path=actual,
                max_components=limits.absolute_path_components,
            )
            return held, tuple(chain)
    except _CollectorAbort:
        if base.close_fd:
            _safe_close(base.fd)
            base.close_fd = False
        raise
    _abort(
        collection_failure(
            CollectionDisposition.INCOMPLETE,
            CollectionReasonCode.ELF_INTERPRETER_MISSING,
            subject=EvidenceSubject.INTERPRETER,
            details={"stage": "interpreter_resolve"},
        )
    )


def collect_offline_runtime_evidence(
    request: OfflineRuntimeCollectionRequest,
    *,
    limits: CollectorLimits = DEFAULT_COLLECTOR_LIMITS,
    deadline: MonotonicDeadline | None = None,
) -> OfflineRuntimeEvidence | CollectionFailure:
    """Collect frontend, interpreter, and one explicit distribution."""

    if not isinstance(request, OfflineRuntimeCollectionRequest) or not isinstance(
        limits, CollectorLimits
    ):
        raise TypeError("invalid offline collection argument type")
    unsupported = _platform_failure()
    if unsupported is not None:
        return unsupported
    actual_deadline = _deadline_or_default(
        deadline,
        limits.distribution_deadline_seconds,
    )
    frontend_held: _HeldFile | None = None
    interpreter_held: _HeldFile | None = None
    try:
        frontend_base = _prepare_base(
            expected_uid=request.frontend.expected_owner_uid,
            allow_root=request.frontend.allow_root_owner,
            anchor_fd=request.anchor_fd,
            anchor_path=request.anchor_path,
            subject=EvidenceSubject.FRONTEND,
        )
        frontend_relative = _relative_from_absolute(
            request.frontend.absolute_path.value,
            frontend_base.path,
        )
        if frontend_relative is None:
            if frontend_base.close_fd:
                _safe_close(frontend_base.fd)
            _abort(
                collection_failure(
                    CollectionDisposition.INVALID_REQUEST,
                    CollectionReasonCode.INVALID_PATH,
                    subject=EvidenceSubject.FRONTEND,
                    details={"stage": "frontend_path"},
                )
            )
        frontend_held = _open_held_file_from_base(
            frontend_base,
            frontend_relative,
            request.frontend,
            limits=limits,
            deadline=actual_deadline,
            subject=EvidenceSubject.FRONTEND,
            max_components=limits.absolute_path_components,
        )
        frontend_elf = _inspect_expected_elf(
            frontend_held,
            request.frontend.format_id,
            subject=EvidenceSubject.FRONTEND,
            artifact_semantics=False,
        )
        if (
            frontend_elf.elf_class is not CollectorElfClass.ELF64
            or frontend_elf.endianness is not Endianness.LITTLE
            or frontend_elf.machine != _EM_X86_64
            or frontend_elf.elf_type not in {_ET_EXEC, _ET_DYN}
        ):
            _abort(
                collection_failure(
                    CollectionDisposition.UNSUPPORTED_PLATFORM,
                    CollectionReasonCode.ELF_MACHINE_UNSUPPORTED,
                    subject=EvidenceSubject.FRONTEND,
                    details={"stage": "frontend_elf"},
                )
            )
        if isinstance(frontend_elf.interpreter, ElfInterpreterAbsent):
            _abort(
                collection_failure(
                    CollectionDisposition.INCOMPLETE,
                    CollectionReasonCode.ELF_INTERPRETER_MISSING,
                    subject=EvidenceSubject.FRONTEND,
                    details={"stage": "frontend_elf"},
                )
            )
        interpreter_observation = frontend_elf.interpreter
        distribution, embedded = _collect_distribution(
            request.distribution,
            limits=limits,
            deadline=actual_deadline,
            frontend=frontend_held,
        )
        if embedded is None:
            _abort(
                collection_failure(
                    CollectionDisposition.INCOMPLETE,
                    CollectionReasonCode.EMBEDDED_PAYLOAD_MISSING,
                    subject=EvidenceSubject.FRONTEND,
                    details={"stage": "embedded_payload"},
                )
            )
        interpreter_held, symlink_chain = _resolve_interpreter(
            interpreter_observation.path,
            request,
            limits=limits,
            deadline=actual_deadline,
        )
        interpreter_elf = _inspect_expected_elf(
            interpreter_held,
            FormatId.ELF64_X86_64_DYN,
            subject=EvidenceSubject.INTERPRETER,
            artifact_semantics=False,
        )
        if not isinstance(interpreter_elf.interpreter, ElfInterpreterAbsent):
            _abort(
                collection_failure(
                    CollectionDisposition.MISMATCH,
                    CollectionReasonCode.ARTIFACT_FORMAT_MISMATCH,
                    subject=EvidenceSubject.INTERPRETER,
                    details={"stage": "interpreter_elf"},
                )
            )
        frontend = _finalize_held_file(
            frontend_held,
            subject=EvidenceSubject.FRONTEND,
        )
        interpreter_file = _finalize_held_file(
            interpreter_held,
            subject=EvidenceSubject.INTERPRETER,
        )
        maximum_held = 31
        if maximum_held > MAX_HELD_DESCRIPTORS:
            _abort(
                collection_failure(
                    CollectionDisposition.LIMIT_EXCEEDED,
                    CollectionReasonCode.ENTRY_LIMIT_EXCEEDED,
                    subject=EvidenceSubject.REQUEST,
                    details={
                        "stage": "descriptor_budget",
                        "count": maximum_held,
                        "limit": MAX_HELD_DESCRIPTORS,
                    },
                )
            )
        return OfflineRuntimeEvidence(
            collector_schema=COLLECTOR_SCHEMA,
            collector_schema_version=COLLECTOR_SCHEMA_VERSION,
            frontend=frontend,
            frontend_elf=frontend_elf,
            interpreter=ResolvedInterpreterEvidence(
                requested_path=interpreter_observation.path,
                file=interpreter_file,
                symlink_chain=symlink_chain,
            ),
            interpreter_elf=interpreter_elf,
            distribution=distribution,
            embedded_sea_loader=embedded,
            counters=OperationCounters(
                files_hashed=distribution.files_hashed + 2,
                bytes_hashed=(
                    distribution.bytes_hashed
                    + frontend.descriptor.bytes_hashed
                    + interpreter_file.descriptor.bytes_hashed
                ),
                tree_entries=distribution.content_manifest.entry_count,
                maximum_held_descriptors=maximum_held,
            ),
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        RecursionError,
        OverflowError,
    ) as exc:
        if isinstance(exc, _CollectorAbort):
            return exc.failure
        if isinstance(exc, OSError):
            return _open_error(
                exc,
                subject=EvidenceSubject.REQUEST,
                stage="offline_collection",
            )
        return collection_failure(
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_INVALID,
            subject=EvidenceSubject.REQUEST,
            details={"stage": "offline_collection"},
        )
    finally:
        if interpreter_held is not None:
            interpreter_held.close()
        if frontend_held is not None:
            frontend_held.close()


__all__ = [
    "collect_distribution_evidence",
    "collect_file_identity",
    "collect_file_identity_at",
    "collect_offline_runtime_evidence",
]
