"""Private owned-fake runtime launch and receipt-finalization machinery.

This module is intentionally not exported by :mod:`core.startup.runtime_receipt`.
It can execute only a process-local capability minted for the checked-in native
test fixture. It is not a general executable launcher.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import hmac
import os
import re
import secrets
import select
import signal
import socket
import stat
import struct
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Iterator, Literal, Mapping, NoReturn, Sequence

from core.json.utils import dumps_canonical

from .canonical import canonical_bytes, sha256_hex
from .collector import collect_file_identity, collect_offline_runtime_evidence
from .collector_types import (
    ArtifactRequest,
    CollectionDisposition,
    CollectionFailure,
    CollectionReasonCode,
    EvidenceSubject,
    ExpectedMappedObject,
    ExpectedMappedObjects,
    FileCollectionRequest,
    FileEvidence,
    FileRole,
    MappedObjectRole,
    MonotonicDeadline,
    OfflineRuntimeCollectionRequest,
    OfflineRuntimeEvidence,
    PathPolicyId,
    TrustedDistributionRequest,
    TrustedGrammarDigestInput,
    TrustedHelpContractDigestInput,
    TrustedProcessScope,
    TrustedSchemaInventoryInput,
    collection_failure,
)
from .issuance import (
    BindingIssuanceInputs,
    LaunchIssuanceInputs,
    PendingReceiptIssued,
    RejectedReceiptIssued,
    StableIssuanceInputs,
    VerifiedReceiptIssued,
    build_pending_receipt,
    build_rejected_from_collection,
    build_rejected_receipt,
    build_verified_receipt,
    default_linux_x86_64_platform,
)
from .plumbing_types import (
    CasApplied,
    CleanupApplied,
    PlumbingFailure,
    PlumbingReason,
    ReceiptState,
    SessionToken,
    StoredReceipt,
)
from .profile import (
    DEFAULT_PROFILE_DIRECTORY,
    PROFILE_SCHEMA_NAME,
    PROFILE_SCHEMA_VERSION,
    ProfileArtifactDigest,
    ProfileDigestBasis,
    ProfileLookupKey,
    ProfileStore,
    StaticProfile,
)
from .procfs import collect_linux_process_evidence
from .reasons import ReasonCode
from .schema import (
    AbsolutePath,
    ArtifactName,
    DistributionSource,
    FormatId,
    Frontend as ReceiptFrontend,
    Identifier,
    NonceHex,
    ProfileStatus,
    SchemaDocumentName,
    SelectionObservation,
    SemanticName,
    Sha1,
    Sha256,
    UtcTimestamp,
    UuidText,
    VersionText,
    VersionObservation,
    to_json_value,
)

OWNED_RUNTIME_FAKE_FACTORY_ID = "core.testing.runtime_receipt_fake:v1"

_CAPABILITY_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_FACTORY_NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FRAME = struct.Struct("<IHHIIIIIII")
_EXEC_STATUS = struct.Struct("<Ii")
_FRAME_MAGIC = 0x52525054
_FRAME_VERSION = 1
_FRAME_PAYLOAD_BYTES = 24
_EXEC_STATUS_MAGIC = 0x52524558
_BOOTSTRAP_ARGV = ("owned-runtime-host", "--bootstrap")
_MAX_DIAGNOSTIC_FIELDS = 16
_MAX_DIAGNOSTIC_BYTES = 128
_MAX_BUILD_MANIFEST_BYTES = 1_048_576
_POLL_QUANTUM_SECONDS = 0.05
_CONTROL_CHANNEL_EOF_ERRNOS = frozenset(
    {
        errno.ECONNABORTED,
        errno.ECONNRESET,
        errno.ENOTCONN,
        errno.EPIPE,
        errno.ESHUTDOWN,
    }
)
_ISSUER_KEY = secrets.token_bytes(32)
_HANDLE_KEY = secrets.token_bytes(32)
_STATE_LOCK = threading.RLock()
_READY_CLOCK = time.monotonic
_CollectionDisposition = CollectionDisposition
_CollectionReasonCode = CollectionReasonCode
_EvidenceSubject = EvidenceSubject
_collection_failure = collection_failure


class LaunchPhase(str, Enum):
    NEW = "new"
    CAPABILITY_VERIFIED = "capability_verified"
    STABLE_EVIDENCE_COLLECTED = "stable_evidence_collected"
    CHILD_FORKED = "child_forked"
    BOOTSTRAP_EXEC_CONFIRMED = "bootstrap_exec_confirmed"
    NATIVE_BOOTSTRAP_BLOCKED = "native_bootstrap_blocked"
    PENDING_ISSUED = "pending_issued"
    PENDING_COMMITTED = "pending_committed"
    ACTIVATION_EXEC_CONFIRMED = "activation_exec_confirmed"
    READY_OBSERVED = "ready_observed"
    POST_EXEC_STABLE_RECOLLECTED = "post_exec_stable_recollected"
    PROCESS_EVIDENCE_COLLECTED = "process_evidence_collected"
    STATIC_VERIFIED = "static_verified"
    VERIFIED_COMMITTED = "verified_committed"
    SUPERVISED = "supervised"
    REJECTED_COMMITTED = "rejected_committed"
    REVOKED = "revoked"
    GROUP_DRAINED = "group_drained"
    CHILD_REAPED = "child_reaped"
    CLEANED = "cleaned"


class LaunchDisposition(str, Enum):
    INVALID_REQUEST = "invalid_request"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    COLLECTION_FAILED = "collection_failed"
    SPAWN_FAILED = "spawn_failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    PROCESS_LOST = "process_lost"
    BINDING_FAILED = "binding_failed"
    STATE_CONFLICT = "state_conflict"
    RECEIPT_REJECTED = "receipt_rejected"
    PERSISTENCE_FAILED = "persistence_failed"
    CLEANUP_FAILED = "cleanup_failed"


class LaunchReason(str, Enum):
    INVALID_CAPABILITY = "invalid_capability"
    CAPABILITY_REUSED = "capability_reused"
    REGISTRY_ROOT_MISMATCH = "registry_root_mismatch"
    REQUIRED_PRIMITIVE_MISSING = "required_primitive_missing"
    STABLE_COLLECTION_FAILED = "stable_collection_failed"
    STABLE_EVIDENCE_CHANGED = "stable_evidence_changed"
    FORK_FAILED = "fork_failed"
    BOOTSTRAP_EXEC_FAILED = "bootstrap_exec_failed"
    BOOTSTRAP_PROTOCOL_FAILED = "bootstrap_protocol_failed"
    PENDING_COMMIT_FAILED = "pending_commit_failed"
    ACTIVATION_EXEC_FAILED = "activation_exec_failed"
    READY_MALFORMED = "ready_malformed"
    READY_EOF = "ready_eof"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    CANCELLED = "cancelled"
    CHILD_EXITED = "child_exited"
    PROCESS_SCOPE_CHANGED = "process_scope_changed"
    PROCESS_GROUP_MISMATCH = "process_group_mismatch"
    DIFFERENT_IMAGE_REEXEC = "different_image_reexec"
    SAME_IMAGE_REEXEC_OR_WITNESS_LOSS = "same_image_reexec_or_witness_loss"
    PROCESS_COLLECTION_FAILED = "process_collection_failed"
    STATIC_VERIFICATION_FAILED = "static_verification_failed"
    FINAL_CAS_CONFLICT = "final_cas_conflict"
    SESSION_REPLACED = "session_replaced"
    REJECTION_CAS_FAILED = "rejection_cas_failed"
    REVOKE_FAILED = "revoke_failed"
    TERM_FAILED = "term_failed"
    KILL_FAILED = "kill_failed"
    REAP_FAILED = "reap_failed"
    DESCENDANTS_REMAIN = "descendants_remain"
    FD_CLEANUP_FAILED = "fd_cleanup_failed"
    BUNDLE_CLEANUP_FAILED = "bundle_cleanup_failed"


class _FrameType(int, Enum):
    BOOTSTRAP_READY = 1
    ACTIVE_WAITING_READY = 2
    READY = 3
    SHAPE = 4
    CONTROLLED_EXITING = 5
    PROTOCOL_ERROR = 6
    ACTIVATE = 101
    RELEASE_READY = 102
    CONTROLLED_EXIT = 103
    REEXEC_SAME = 104
    REEXEC_DIFFERENT = 105


class _ReexecMode(int, Enum):
    NONE = 0
    SAME_BEFORE_CAS = 1
    DIFFERENT_BEFORE_CAS = 2
    SAME_AFTER_CAS = 3
    DIFFERENT_AFTER_CAS = 4


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    relative_path: str
    device: int
    inode: int
    uid: int
    mode: int


@dataclass(frozen=True, slots=True)
class _LeafIdentity:
    relative_path: str
    role: str
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int
    sha256: str
    elf_build_id: str | None


@dataclass(frozen=True, slots=True)
class _CompilerIdentity:
    real_path: str
    device: int
    inode: int
    size: int
    sha256: str
    family: str


@dataclass(frozen=True, slots=True)
class _ProcessIdentity:
    pid: int
    parent_pid: int
    process_group: int
    starttime_ticks: int
    boot_id: str
    pid_namespace_inode: int
    mount_namespace_inode: int
    euid: int
    executable_device: int
    executable_inode: int
    executable_size: int
    executable_sha256: str


@dataclass(slots=True)
class _CapabilityRecord:
    capability_id: str
    factory_nonce: str
    issuer_pid: int
    test_root: Path
    bundle_root: Path
    registry_root: Path
    behavior_code: int
    descendant_code: int
    ready_delay_seconds: int
    reexec_mode: _ReexecMode
    compiler: _CompilerIdentity
    compiler_argv: tuple[tuple[str, ...], ...]
    source_hashes: tuple[str, str]
    inventory: tuple[str, ...]
    directories: tuple[_DirectoryIdentity, ...]
    leaves: tuple[_LeafIdentity, ...]
    cleanup_directories: tuple[str, ...]
    profile: StaticProfile
    offline_request: OfflineRuntimeCollectionRequest
    launcher_request: FileCollectionRequest
    baseline_evidence_signature: object
    baseline_launcher_signature: object
    proof_sha256: str
    consumed: bool = False


@dataclass(slots=True)
class _HandleRecord:
    handle_id: str
    capability: _CapabilityRecord
    parent_pid: int
    child_pid: int
    process_group: int
    group_verified: bool
    process_identity: _ProcessIdentity
    control: socket.socket
    liveness_write_fd: int
    witness_read_fd: int
    baseline_evidence: OfflineRuntimeEvidence
    launcher_evidence: FileEvidence
    stable_inputs: StableIssuanceInputs | None
    launch_inputs: LaunchIssuanceInputs | None
    binding_inputs: BindingIssuanceInputs | None
    token: SessionToken
    token_hex: str
    pending: PendingReceiptIssued | None
    current_receipt: (
        PendingReceiptIssued | VerifiedReceiptIssued | RejectedReceiptIssued | None
    )
    phase: LaunchPhase
    trace: list[str]
    reference_names: set[str]
    operation: str | None = None
    verified_result: OwnedFakeVerified | None = None
    close_result: LaunchClosed | None = None
    failure_result: LaunchFailure | None = None
    child_status: int | None = None
    child_reaped: bool = False
    fds_closed: bool = False


@dataclass(frozen=True, slots=True, init=False, repr=False)
class OwnedFakeRuntimeCapability:
    factory_id: str
    bundle_sha256: str
    compiler_sha256: str
    _capability_id: str = field(repr=False)
    _factory_nonce: str = field(repr=False)
    _issuer_mac: str = field(repr=False)

    def __repr__(self) -> str:
        return (
            "OwnedFakeRuntimeCapability("
            f"factory_id={self.factory_id!r}, bundle_sha256={self.bundle_sha256!r})"
        )

    def __bool__(self) -> bool:
        raise TypeError("owned fake runtime capabilities are not truth values")

    def __copy__(self) -> OwnedFakeRuntimeCapability:
        return _new_capability(
            factory_id=self.factory_id,
            bundle_sha256=self.bundle_sha256,
            compiler_sha256=self.compiler_sha256,
            capability_id=self._capability_id,
            factory_nonce=self._factory_nonce,
            issuer_mac=self._issuer_mac,
        )

    def __deepcopy__(self, memo: dict[int, object]) -> OwnedFakeRuntimeCapability:
        del memo
        return self.__copy__()

    def __reduce__(self) -> NoReturn:
        raise TypeError("OwnedFakeRuntimeCapability cannot be pickled")

    def __init_subclass__(cls) -> None:
        raise TypeError("OwnedFakeRuntimeCapability cannot be subclassed")


@dataclass(frozen=True, slots=True, init=False, repr=False)
class OwnedFakeLaunchHandle:
    _handle_id: str = field(repr=False)
    _handle_mac: str = field(repr=False)

    def __repr__(self) -> str:
        return "OwnedFakeLaunchHandle(<redacted>)"

    def __bool__(self) -> bool:
        raise TypeError("owned fake launch handles are not truth values")

    def __reduce__(self) -> NoReturn:
        raise TypeError("OwnedFakeLaunchHandle cannot be pickled")

    def __init_subclass__(cls) -> None:
        raise TypeError("OwnedFakeLaunchHandle cannot be subclassed")


@dataclass(frozen=True, slots=True, init=False, repr=False)
class OwnedFakeVerified:
    state: Literal["verified"]
    profile_id: str
    stable_identity_sha256: str
    receipt_sha256: str
    reason_codes: tuple[str, ...]
    trace: tuple[str, ...]
    authoritative: Literal[False] = field(default=False, init=False)

    def __repr__(self) -> str:
        return (
            "OwnedFakeVerified("
            f"state={self.state!r}, profile_id={self.profile_id!r}, "
            "authoritative=False)"
        )

    def __bool__(self) -> bool:
        raise TypeError("owned fake verification is not an authority value")

    def __reduce__(self) -> NoReturn:
        raise TypeError("OwnedFakeVerified cannot be pickled")

    def __init_subclass__(cls) -> None:
        raise TypeError("OwnedFakeVerified cannot be subclassed")


@dataclass(frozen=True, slots=True, init=False, repr=False)
class LaunchClosed:
    state: Literal["cleaned"]
    receipt_removed: bool
    child_exit_code: int | None
    trace: tuple[str, ...]
    authoritative: Literal[False] = field(default=False, init=False)

    def __repr__(self) -> str:
        return (
            "LaunchClosed("
            f"state={self.state!r}, receipt_removed={self.receipt_removed!r}, "
            "authoritative=False)"
        )

    def __bool__(self) -> bool:
        raise TypeError("owned fake close results are not truth values")

    def __reduce__(self) -> NoReturn:
        raise TypeError("LaunchClosed cannot be pickled")

    def __init_subclass__(cls) -> None:
        raise TypeError("LaunchClosed cannot be subclassed")


@dataclass(frozen=True, slots=True, init=False, repr=False)
class LaunchFailure:
    disposition: LaunchDisposition
    reason_codes: tuple[LaunchReason, ...]
    phase: LaunchPhase
    receipt_state: str
    diagnostics: Mapping[str, str]
    trace: tuple[str, ...]
    authoritative: Literal[False] = field(default=False, init=False)

    def __repr__(self) -> str:
        reasons = tuple(reason.value for reason in self.reason_codes)
        return (
            "LaunchFailure("
            f"disposition={self.disposition.value!r}, reason_codes={reasons!r}, "
            f"phase={self.phase.value!r}, authoritative=False)"
        )

    def __bool__(self) -> bool:
        raise TypeError("owned fake launch failures are not truth values")

    def __reduce__(self) -> NoReturn:
        raise TypeError("LaunchFailure cannot be pickled")

    def __init_subclass__(cls) -> None:
        raise TypeError("LaunchFailure cannot be subclassed")


class LaunchCancellation:
    """Idempotent poll-waking cancellation with no launch authority."""

    __slots__ = ("_read_fd", "_write_fd", "_closed", "_lock")

    def __init__(self) -> None:
        flags = getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        read_fd, write_fd = os.pipe2(flags)
        self._read_fd = read_fd
        self._write_fd = write_fd
        self._closed = False
        self._lock = threading.Lock()

    def cancel(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                os.write(self._write_fd, b"x")
            except BlockingIOError:
                pass
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for fd in (self._write_fd, self._read_fd):
                with contextlib.suppress(OSError):
                    os.close(fd)

    def __enter__(self) -> LaunchCancellation:
        return self

    def __exit__(self, *unused: object) -> None:
        del unused
        self.close()

    def __repr__(self) -> str:
        return "LaunchCancellation(<redacted>)"

    def __reduce__(self) -> NoReturn:
        raise TypeError("LaunchCancellation cannot be pickled")

    def __init_subclass__(cls) -> None:
        raise TypeError("LaunchCancellation cannot be subclassed")


_CAPABILITIES: dict[str, _CapabilityRecord] = {}
_HANDLES: dict[str, _HandleRecord] = {}


def _new_capability(
    *,
    factory_id: str,
    bundle_sha256: str,
    compiler_sha256: str,
    capability_id: str,
    factory_nonce: str,
    issuer_mac: str,
) -> OwnedFakeRuntimeCapability:
    value = object.__new__(OwnedFakeRuntimeCapability)
    object.__setattr__(value, "factory_id", factory_id)
    object.__setattr__(value, "bundle_sha256", bundle_sha256)
    object.__setattr__(value, "compiler_sha256", compiler_sha256)
    object.__setattr__(value, "_capability_id", capability_id)
    object.__setattr__(value, "_factory_nonce", factory_nonce)
    object.__setattr__(value, "_issuer_mac", issuer_mac)
    return value


def _new_handle(handle_id: str, handle_mac: str) -> OwnedFakeLaunchHandle:
    value = object.__new__(OwnedFakeLaunchHandle)
    object.__setattr__(value, "_handle_id", handle_id)
    object.__setattr__(value, "_handle_mac", handle_mac)
    return value


def _new_verified(record: _HandleRecord) -> OwnedFakeVerified:
    current = record.current_receipt
    assert isinstance(current, VerifiedReceiptIssued)
    value = object.__new__(OwnedFakeVerified)
    object.__setattr__(value, "state", "verified")
    object.__setattr__(value, "profile_id", current.reference.profile_id.value)
    object.__setattr__(
        value,
        "stable_identity_sha256",
        current.reference.stable_identity_sha256.value,
    )
    object.__setattr__(value, "receipt_sha256", current.reference.receipt_sha256.value)
    object.__setattr__(
        value,
        "reason_codes",
        tuple(reason.value for reason in current.reason_codes),
    )
    object.__setattr__(value, "trace", tuple(record.trace))
    object.__setattr__(value, "authoritative", False)
    return value


def _new_closed(record: _HandleRecord, *, receipt_removed: bool) -> LaunchClosed:
    value = object.__new__(LaunchClosed)
    object.__setattr__(value, "state", "cleaned")
    object.__setattr__(value, "receipt_removed", receipt_removed)
    object.__setattr__(
        value,
        "child_exit_code",
        _exit_code(record.child_status),
    )
    object.__setattr__(value, "trace", tuple(record.trace))
    object.__setattr__(value, "authoritative", False)
    return value


def _bounded_diagnostics(values: Mapping[str, object] | None) -> Mapping[str, str]:
    bounded: dict[str, str] = {}
    for key, value in (values or {}).items():
        if len(bounded) >= _MAX_DIAGNOSTIC_FIELDS:
            break
        text_key = str(key)
        text_value = value.value if isinstance(value, Enum) else str(value)
        if (
            text_key
            and text_key.isascii()
            and text_key.isprintable()
            and len(text_key) <= 64
            and text_value
            and text_value.isascii()
            and text_value.isprintable()
            and len(text_value) <= _MAX_DIAGNOSTIC_BYTES
            and not _CAPABILITY_ID_RE.fullmatch(text_value)
            and not _SHA256_RE.fullmatch(text_value)
        ):
            bounded[text_key] = text_value
    return MappingProxyType(bounded)


def _failure(
    disposition: LaunchDisposition,
    reason: LaunchReason,
    *,
    phase: LaunchPhase,
    receipt_state: str = ReceiptState.ABSENT.value,
    diagnostics: Mapping[str, object] | None = None,
    trace: Sequence[str] = (),
    additional_reasons: Sequence[LaunchReason] = (),
) -> LaunchFailure:
    value = object.__new__(LaunchFailure)
    object.__setattr__(value, "disposition", disposition)
    object.__setattr__(
        value,
        "reason_codes",
        tuple(dict.fromkeys((reason, *additional_reasons))),
    )
    object.__setattr__(value, "phase", phase)
    object.__setattr__(value, "receipt_state", receipt_state)
    object.__setattr__(value, "diagnostics", _bounded_diagnostics(diagnostics))
    object.__setattr__(value, "trace", tuple(trace))
    object.__setattr__(value, "authoritative", False)
    return value


def _identity_tuple(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _directory_identity(path: Path) -> tuple[int, int, int, int]:
    value = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(value.st_mode):
        raise ValueError("owned fake directory is not a direct directory")
    return value.st_dev, value.st_ino, value.st_uid, stat.S_IMODE(value.st_mode)


def _ancestor_identities(path: Path) -> set[tuple[int, int]]:
    identities: set[tuple[int, int]] = set()
    current = path
    while True:
        value = current.stat()
        identities.add(_identity_tuple(value))
        if current.parent == current:
            return identities
        current = current.parent


def _forbidden_test_root(test_root: Path) -> bool:
    from core.project.sessions import SESSIONS_DIR

    test_identity = _identity_tuple(test_root.stat())
    temporary = Path(tempfile.gettempdir())
    if temporary.exists() and _identity_tuple(temporary.stat()) == test_identity:
        return True
    test_ancestors = _ancestor_identities(test_root)
    forbidden_paths = (
        Path(__file__).resolve().parents[3],
        DEFAULT_PROFILE_DIRECTORY,
        SESSIONS_DIR,
    )
    for forbidden in forbidden_paths:
        try:
            identity = _identity_tuple(forbidden.stat())
        except OSError:
            continue
        if identity in test_ancestors:
            return True
    return False


def _read_fd_bytes(fd: int, size: int) -> bytes:
    digest_input = bytearray()
    offset = 0
    while offset < size:
        chunk = os.pread(fd, min(1_048_576, size - offset), offset)
        if not chunk:
            raise ValueError("owned fake file changed during verification")
        digest_input.extend(chunk)
        offset += len(chunk)
    return bytes(digest_input)


def _open_relative_directory(root_fd: int, relative: str) -> int:
    current = os.dup(root_fd)
    try:
        if relative:
            for component in relative.split("/"):
                next_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=current,
                )
                os.close(current)
                current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


def _open_relative_leaf(root_fd: int, relative: str) -> int:
    parent, _, name = relative.rpartition("/")
    directory_fd = _open_relative_directory(root_fd, parent)
    try:
        return os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
    finally:
        os.close(directory_fd)


def _read_stable_relative_bytes(
    root_fd: int,
    relative: str,
    *,
    max_bytes: int,
) -> bytes:
    fd = _open_relative_leaf(root_fd, relative)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size > max_bytes
        ):
            raise ValueError("owned fake leaf is outside its read contract")
        raw = _read_fd_bytes(fd, before.st_size)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if _leaf_fingerprint(before) != _leaf_fingerprint(after):
        raise ValueError("owned fake leaf changed during read")
    return raw


def _leaf_fingerprint(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_gid,
        stat.S_IMODE(value.st_mode),
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _verify_leaf(root_fd: int, expected: _LeafIdentity) -> None:
    fd = _open_relative_leaf(root_fd, expected.relative_path)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("owned fake leaf is not regular")
        raw = _read_fd_bytes(fd, before.st_size)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    expected_fingerprint = (
        expected.device,
        expected.inode,
        expected.uid,
        expected.gid,
        expected.mode,
        expected.nlink,
        expected.size,
        expected.mtime_ns,
        expected.ctime_ns,
    )
    if (
        _leaf_fingerprint(before) != expected_fingerprint
        or _leaf_fingerprint(after) != expected_fingerprint
        or expected.nlink != 1
        or expected.uid != os.geteuid()
        or expected.mode & 0o022
        or hashlib.sha256(raw).hexdigest() != expected.sha256
    ):
        raise ValueError("owned fake leaf identity changed")


def _inventory(root: Path) -> tuple[str, ...]:
    found: list[str] = []
    stack = [(root, "")]
    while stack:
        directory, prefix = stack.pop()
        entries = sorted(os.scandir(directory), key=lambda item: item.name)
        for entry in entries:
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            value = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(value.st_mode):
                raise ValueError("owned fake inventory contains a symlink")
            found.append(relative)
            if stat.S_ISDIR(value.st_mode):
                stack.append((Path(entry.path), relative))
            elif not stat.S_ISREG(value.st_mode):
                raise ValueError("owned fake inventory contains a special file")
    return tuple(sorted(found))


def _verify_record_filesystem(record: _CapabilityRecord) -> None:
    test_value = _directory_identity(record.test_root)
    bundle_value = _directory_identity(record.bundle_root)
    if record.bundle_root.parent != record.test_root:
        raise ValueError("owned fake bundle is not a direct child")
    test_expected = next(
        item for item in record.directories if item.relative_path == ".."
    )
    root_expected = next(
        item for item in record.directories if item.relative_path == ""
    )
    if test_value != (
        test_expected.device,
        test_expected.inode,
        test_expected.uid,
        test_expected.mode,
    ) or bundle_value != (
        root_expected.device,
        root_expected.inode,
        root_expected.uid,
        root_expected.mode,
    ):
        raise ValueError("owned fake root identity changed")
    if _inventory(record.bundle_root) != record.inventory:
        raise ValueError("owned fake closed inventory changed")
    manifest_leaf = next(
        item for item in record.leaves if item.relative_path == "build-manifest.json"
    )
    root_fd = os.open(
        record.bundle_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        manifest_raw = _read_stable_relative_bytes(
            root_fd,
            "build-manifest.json",
            max_bytes=_MAX_BUILD_MANIFEST_BYTES,
        )
        if hashlib.sha256(manifest_raw).hexdigest() != manifest_leaf.sha256:
            raise ValueError("owned fake build manifest changed")
        for directory in record.directories:
            if directory.relative_path in {"..", ""}:
                continue
            fd = _open_relative_directory(root_fd, directory.relative_path)
            try:
                value = os.fstat(fd)
            finally:
                os.close(fd)
            if (
                (
                    value.st_dev,
                    value.st_ino,
                    value.st_uid,
                    stat.S_IMODE(value.st_mode),
                )
                != (
                    directory.device,
                    directory.inode,
                    directory.uid,
                    directory.mode,
                )
                or directory.uid != os.geteuid()
                or directory.mode & 0o022
            ):
                raise ValueError("owned fake component identity changed")
        for leaf in record.leaves:
            _verify_leaf(root_fd, leaf)
    finally:
        os.close(root_fd)


def _descriptor_signature(evidence: FileEvidence) -> tuple[object, ...]:
    value = evidence.descriptor
    file_stat = value.stat
    return (
        file_stat.device,
        file_stat.inode,
        file_stat.size_bytes,
        file_stat.mtime_ns,
        file_stat.ctime_ns,
        value.sha256,
        value.elf_build_id_sha1,
    )


def _evidence_signature(evidence: OfflineRuntimeEvidence) -> tuple[object, ...]:
    artifacts = tuple(
        (item.name.value, _descriptor_signature(item.file))
        for item in sorted(
            evidence.distribution.artifacts, key=lambda item: item.name.value
        )
    )
    return (
        _descriptor_signature(evidence.frontend),
        _descriptor_signature(evidence.interpreter.file),
        _descriptor_signature(evidence.distribution.package_manifest.file),
        artifacts,
        evidence.distribution.content_manifest.sha256.value,
    )


def _proof_payload(record: _CapabilityRecord) -> bytes:
    value = {
        "identity": {
            "factory_id": OWNED_RUNTIME_FAKE_FACTORY_ID,
            "capability_id": record.capability_id,
            "factory_nonce": record.factory_nonce,
            "issuer_pid": record.issuer_pid,
        },
        "roots": {
            "test_root": str(record.test_root),
            "bundle_root": str(record.bundle_root),
            "registry_root": str(record.registry_root),
        },
        "behavior": {
            "behavior_code": record.behavior_code,
            "descendant_code": record.descendant_code,
            "ready_delay_seconds": record.ready_delay_seconds,
            "reexec_mode": record.reexec_mode.value,
        },
        "compiler": {
            "real_path": record.compiler.real_path,
            "device": record.compiler.device,
            "inode": record.compiler.inode,
            "size": record.compiler.size,
            "sha256": record.compiler.sha256,
            "family": record.compiler.family,
            "argv": record.compiler_argv,
            "source_hashes": record.source_hashes,
        },
        "filesystem": {
            "inventory": record.inventory,
            "directories": tuple(
                (
                    item.relative_path,
                    item.device,
                    item.inode,
                    item.uid,
                    item.mode,
                )
                for item in record.directories
            ),
            "leaves": tuple(
                (
                    item.relative_path,
                    item.role,
                    item.device,
                    item.inode,
                    item.uid,
                    item.gid,
                    item.mode,
                    item.nlink,
                    item.size,
                    item.mtime_ns,
                    item.ctime_ns,
                    item.sha256,
                    item.elf_build_id,
                )
                for item in record.leaves
            ),
            "cleanup_directories": record.cleanup_directories,
        },
        "evidence": {
            "profile": to_json_value(record.profile),
            "stable": record.baseline_evidence_signature,
            "launcher": record.baseline_launcher_signature,
        },
    }
    return dumps_canonical(value).encode("utf-8")


def _capability_mac(record: _CapabilityRecord) -> str:
    return hmac.new(_ISSUER_KEY, _proof_payload(record), hashlib.sha256).hexdigest()


def _handle_mac(record: _HandleRecord) -> str:
    raw = (
        f"{record.handle_id}:{record.capability.factory_nonce}:"
        f"{record.child_pid}:{record.process_identity.starttime_ticks}"
    ).encode("ascii")
    return hmac.new(_HANDLE_KEY, raw, hashlib.sha256).hexdigest()


def _artifact_format(relative: str) -> FormatId:
    if relative.endswith(".node"):
        return FormatId.ELF64_X86_64_DYN
    if relative.endswith(".json"):
        return FormatId.JSON_UTF8
    if relative.endswith(".js") and relative != "sdk/index.js":
        return FormatId.JAVASCRIPT_UTF8
    if relative == ".extraction-complete":
        return FormatId.EMPTY
    return FormatId.OPAQUE


def _artifact_limit(relative: str) -> int:
    if relative == "index.js":
        return 4_194_304
    if relative in {"npm-loader.js", "sea-loader.js"}:
        return 1_048_576
    if relative == "app.js":
        return 33_554_432
    if relative == "sdk/index.js":
        return 16_777_216
    if relative == "changelog.json":
        return 8_388_608
    if relative == "prebuilds/linux-x64/runtime.node":
        return 268_435_456
    if relative == "prebuilds/linux-x64/cli-native.node":
        return 67_108_864
    if relative.startswith("schemas/"):
        return 8_388_608
    if relative == ".extraction-complete":
        return 4_096
    raise ValueError("unknown owned fake artifact limit")


def _collection_requests(
    bundle_root: Path,
) -> tuple[OfflineRuntimeCollectionRequest, FileCollectionRequest]:
    dist = bundle_root / "dist"
    artifacts = tuple(
        ArtifactRequest(
            role=name,
            relative_path=name.value,
            expected_format=_artifact_format(name.value),
            max_bytes=_artifact_limit(name.value),
        )
        for name in ArtifactName
    )
    record_sha = Sha256(
        hashlib.sha256(b"raptor-owned-runtime-fake-record-v1").hexdigest()
    )
    root_fd = os.open(
        bundle_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        schemas = tuple(
            TrustedSchemaInventoryInput(
                name=name,
                source_record_sha256=record_sha,
                expected_file_sha256=Sha256(
                    hashlib.sha256(
                        _read_stable_relative_bytes(
                            root_fd,
                            (
                                "dist/schemas/session-events.schema.json"
                                if name is SchemaDocumentName.SESSION_EVENTS
                                else "dist/schemas/api.schema.json"
                            ),
                            max_bytes=8_388_608,
                        )
                    ).hexdigest()
                ),
                definition_count=0,
                property_count=1,
                event_type_literal_count=0,
                event_variant_count=None,
                definition_names_sha256=Sha256(
                    hashlib.sha256(b"definitions").hexdigest()
                ),
                property_names_sha256=Sha256(
                    hashlib.sha256(name.value.encode("ascii")).hexdigest()
                ),
                event_type_literals_sha256=Sha256(
                    hashlib.sha256(b"event-types").hexdigest()
                ),
            )
            for name in SchemaDocumentName
        )
    finally:
        os.close(root_fd)
    distribution = TrustedDistributionRequest(
        source_directory=AbsolutePath(str(dist)),
        expected_owner_uid=os.geteuid(),
        expected_package_name="@github/copilot",
        expected_version=VersionText("0.0.0-owned"),
        expected_package_type="module",
        expected_bin_name="copilot",
        expected_bin_target="npm-loader.js",
        platform_directory="linux-x64",
        artifacts=artifacts,
        schemas=schemas,
        grammar=TrustedGrammarDigestInput(
            source_record_sha256=record_sha,
            source="completion_bash_review_record",
            sha256=Sha256(hashlib.sha256(b"owned-runtime-fake-grammar").hexdigest()),
            root_flag_count=0,
            advertised_root_flag_count=0,
            hidden_root_flag_count=0,
        ),
        help_contract=TrustedHelpContractDigestInput(
            source_record_sha256=record_sha,
            manifest_algorithm="sha256-help-surfaces-v1",
            manifest_sha256=Sha256(
                hashlib.sha256(b"owned-runtime-fake-help").hexdigest()
            ),
            surface_count=0,
        ),
    )
    frontend = FileCollectionRequest(
        role=FileRole.FRONTEND_EXECUTABLE,
        absolute_path=AbsolutePath(str(bundle_root / "bin/owned-runtime-host")),
        expected_owner_uid=os.geteuid(),
        allow_root_owner=True,
        require_executable=True,
        policy_id=PathPolicyId.DIRECT_REGULAR_NO_SYMLINK_V1,
        max_bytes=16_777_216,
        format_id=FormatId.ELF64_X86_64_DYN,
    )
    launcher = FileCollectionRequest(
        role=FileRole.CONTRACT_INPUT,
        absolute_path=AbsolutePath(str(bundle_root / "issuer/launcher-marker")),
        expected_owner_uid=os.geteuid(),
        allow_root_owner=True,
        require_executable=False,
        policy_id=PathPolicyId.DIRECT_REGULAR_NO_SYMLINK_V1,
        max_bytes=4096,
        format_id=FormatId.OPAQUE,
    )
    return (
        OfflineRuntimeCollectionRequest(
            frontend=frontend,
            distribution=distribution,
            interpreter_expected_owner_uid=os.geteuid(),
            interpreter_allow_root_owner=True,
        ),
        launcher,
    )


def _profile_for_evidence(
    evidence: OfflineRuntimeEvidence,
    launcher: FileEvidence,
) -> StaticProfile:
    artifacts = tuple(
        ProfileArtifactDigest(
            name=item.name,
            sha256=Sha256(item.file.descriptor.sha256),
        )
        for item in sorted(
            evidence.distribution.artifacts,
            key=lambda item: item.name.value,
        )
    )
    schema_files = {
        item.name: item.file.descriptor.sha256 for item in evidence.distribution.schemas
    }
    platform_identity = default_linux_x86_64_platform()
    profile_id = Identifier("raptor-owned-runtime-fake-v1")
    lookup = ProfileLookupKey(
        frontend=ReceiptFrontend.COPILOT,
        profile_id=profile_id,
        cli_version=evidence.distribution.version,
        platform_system=platform_identity.system,
        architecture=platform_identity.architecture,
        elf_class=platform_identity.elf_class,
        launcher_sha256=Sha256(launcher.descriptor.sha256),
        frontend_executable_sha256=Sha256(evidence.frontend.descriptor.sha256),
        elf_interpreter_sha256=Sha256(evidence.interpreter.file.descriptor.sha256),
        distribution_source=DistributionSource.SEALED_CACHE_SNAPSHOT,
        distribution_manifest_sha256=evidence.distribution.content_manifest.sha256,
        package_manifest_sha256=Sha256(
            evidence.distribution.package_manifest.file.descriptor.sha256
        ),
        artifacts=artifacts,
        session_events_schema_sha256=Sha256(
            schema_files[SchemaDocumentName.SESSION_EVENTS]
        ),
        api_schema_sha256=Sha256(schema_files[SchemaDocumentName.API]),
        cli_grammar_sha256=evidence.distribution.grammar.sha256,
        help_contract_manifest_sha256=(
            evidence.distribution.help_contract.manifest_sha256
        ),
    )
    basis = ProfileDigestBasis(
        profile_id=profile_id,
        profile_schema_version=PROFILE_SCHEMA_VERSION,
        status=ProfileStatus.STATIC_CANDIDATE_NOT_AUTHORIZED,
        live_evidence_id=None,
        live_evidence_sha256=None,
        lookup_key=lookup,
    )
    return StaticProfile(
        schema=PROFILE_SCHEMA_NAME,
        schema_version=PROFILE_SCHEMA_VERSION,
        profile_digest_basis=basis,
        profile_sha256=Sha256(sha256_hex(canonical_bytes(to_json_value(basis)))),
    )


def _directory_proofs(
    test_root: Path,
    bundle_root: Path,
) -> tuple[_DirectoryIdentity, ...]:
    rows = []
    for relative, path in (("..", test_root), ("", bundle_root)):
        value = path.lstat()
        rows.append(
            _DirectoryIdentity(
                relative,
                value.st_dev,
                value.st_ino,
                value.st_uid,
                stat.S_IMODE(value.st_mode),
            )
        )
    directories = [
        path for path in bundle_root.rglob("*") if stat.S_ISDIR(path.lstat().st_mode)
    ]
    for path in sorted(
        directories,
        key=lambda item: item.relative_to(bundle_root).as_posix(),
    ):
        value = path.lstat()
        rows.append(
            _DirectoryIdentity(
                path.relative_to(bundle_root).as_posix(),
                value.st_dev,
                value.st_ino,
                value.st_uid,
                stat.S_IMODE(value.st_mode),
            )
        )
    return tuple(rows)


def _additional_elf_build_id(path: Path, *, frontend: bool) -> str | None:
    collected = collect_file_identity(
        FileCollectionRequest(
            role=(
                FileRole.FRONTEND_EXECUTABLE
                if frontend
                else FileRole.DISTRIBUTION_ARTIFACT
            ),
            absolute_path=AbsolutePath(str(path)),
            expected_owner_uid=os.geteuid(),
            allow_root_owner=True,
            require_executable=True,
            policy_id=PathPolicyId.DIRECT_REGULAR_NO_SYMLINK_V1,
            max_bytes=16_777_216,
            format_id=FormatId.ELF64_X86_64_DYN,
        )
    )
    if isinstance(collected, CollectionFailure):
        raise ValueError("owned fake ELF identity collection failed")
    return collected.descriptor.elf_build_id_sha1


def _leaf_proofs(
    bundle_root: Path,
    evidence: OfflineRuntimeEvidence,
    launcher: FileEvidence,
) -> tuple[_LeafIdentity, ...]:
    known_build_ids = {
        "bin/owned-runtime-host": evidence.frontend.descriptor.elf_build_id_sha1,
        "issuer/launcher-marker": launcher.descriptor.elf_build_id_sha1,
    }
    for item in evidence.distribution.artifacts:
        known_build_ids[f"dist/{item.name.value}"] = (
            item.file.descriptor.elf_build_id_sha1
        )
    alternate = bundle_root / "bin/owned-runtime-host-alt"
    known_build_ids["bin/owned-runtime-host-alt"] = _additional_elf_build_id(
        alternate,
        frontend=True,
    )
    extra = bundle_root / "dist/prebuilds/linux-x64/extra-owned.node"
    if extra.exists():
        known_build_ids["dist/prebuilds/linux-x64/extra-owned.node"] = (
            _additional_elf_build_id(extra, frontend=False)
        )
    rows = []
    for path in sorted(bundle_root.rglob("*")):
        value = path.lstat()
        if not stat.S_ISREG(value.st_mode):
            continue
        relative = path.relative_to(bundle_root).as_posix()
        rows.append(
            _LeafIdentity(
                relative_path=relative,
                role="fixture_leaf",
                device=value.st_dev,
                inode=value.st_ino,
                uid=value.st_uid,
                gid=value.st_gid,
                mode=stat.S_IMODE(value.st_mode),
                nlink=value.st_nlink,
                size=value.st_size,
                mtime_ns=value.st_mtime_ns,
                ctime_ns=value.st_ctime_ns,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                elf_build_id=known_build_ids.get(relative),
            )
        )
    return tuple(rows)


def _cleanup_directory_names(bundle_root: Path) -> tuple[str, ...]:
    directories = [
        path.relative_to(bundle_root).as_posix()
        for path in bundle_root.rglob("*")
        if path.is_dir()
    ]
    return tuple(
        sorted(
            directories,
            key=lambda item: (item.count("/"), item),
            reverse=True,
        )
    )


def _issue_owned_fake_runtime_capability(
    *,
    test_root: Path,
    bundle_root: Path,
    registry_root: Path,
    behavior_code: int,
    descendant_code: int,
    ready_delay_seconds: int,
    reexec_mode: int,
    compiler_identity: tuple[str, int, int, int, str, str],
    compiler_argv: tuple[tuple[str, ...], ...],
    source_hashes: tuple[str, str],
) -> OwnedFakeRuntimeCapability:
    """Issue one exact, process-local capability for the checked-in fixture."""

    test_root = Path(test_root)
    bundle_root = Path(bundle_root)
    registry_root = Path(registry_root)
    if (
        not test_root.is_absolute()
        or not bundle_root.is_absolute()
        or not registry_root.is_absolute()
        or _forbidden_test_root(test_root)
    ):
        raise ValueError("owned fake test root is forbidden")
    test_value = test_root.lstat()
    if (
        test_root.is_symlink()
        or not stat.S_ISDIR(test_value.st_mode)
        or test_value.st_uid != os.geteuid()
        or stat.S_IMODE(test_value.st_mode) & 0o022
    ):
        raise ValueError("owned fake test root is unsafe")
    if (
        type(behavior_code) is not int
        or not 1 <= behavior_code <= 11
        or type(descendant_code) is not int
        or not 0 <= descendant_code <= 2
        or type(ready_delay_seconds) is not int
        or not 0 <= ready_delay_seconds <= 3600
    ):
        raise ValueError("owned fake behavior is invalid")
    try:
        parsed_reexec = _ReexecMode(reexec_mode)
    except ValueError as exc:
        raise ValueError("owned fake re-exec mode is invalid") from exc
    if parsed_reexec is not _ReexecMode.NONE and descendant_code != 0:
        raise ValueError("owned fake re-exec fixtures cannot retain descendants")
    real_path, device, inode, size, compiler_sha256, family = compiler_identity
    compiler = _CompilerIdentity(
        real_path=real_path,
        device=device,
        inode=inode,
        size=size,
        sha256=compiler_sha256,
        family=family,
    )
    capability_id = secrets.token_hex(16)
    factory_nonce = bundle_root.name.removeprefix("runtime-receipt-fake-")
    if (
        not _CAPABILITY_ID_RE.fullmatch(capability_id)
        or not _FACTORY_NONCE_RE.fullmatch(factory_nonce)
        or len(source_hashes) != 2
        or any(_SHA256_RE.fullmatch(item) is None for item in source_hashes)
    ):
        raise ValueError("owned fake issuance material is invalid")
    offline_request, launcher_request = _collection_requests(bundle_root)
    baseline_evidence = collect_offline_runtime_evidence(offline_request)
    baseline_launcher = collect_file_identity(launcher_request)
    if isinstance(baseline_evidence, CollectionFailure) or isinstance(
        baseline_launcher,
        CollectionFailure,
    ):
        raise ValueError("owned fake accepted evidence collection failed")
    profile = _profile_for_evidence(baseline_evidence, baseline_launcher)
    directories = _directory_proofs(test_root, bundle_root)
    leaves = _leaf_proofs(bundle_root, baseline_evidence, baseline_launcher)
    record = _CapabilityRecord(
        capability_id=capability_id,
        factory_nonce=factory_nonce,
        issuer_pid=os.getpid(),
        test_root=test_root,
        bundle_root=bundle_root,
        registry_root=registry_root,
        behavior_code=behavior_code,
        descendant_code=descendant_code,
        ready_delay_seconds=ready_delay_seconds,
        reexec_mode=parsed_reexec,
        compiler=compiler,
        compiler_argv=compiler_argv,
        source_hashes=source_hashes,
        inventory=_inventory(bundle_root),
        directories=directories,
        leaves=leaves,
        cleanup_directories=_cleanup_directory_names(bundle_root),
        profile=profile,
        offline_request=offline_request,
        launcher_request=launcher_request,
        baseline_evidence_signature=_evidence_signature(baseline_evidence),
        baseline_launcher_signature=_descriptor_signature(baseline_launcher),
        proof_sha256="",
    )
    _verify_record_filesystem(record)
    proof_sha256 = hashlib.sha256(_proof_payload(record)).hexdigest()
    record.proof_sha256 = proof_sha256
    issuer_mac = _capability_mac(record)
    with _STATE_LOCK:
        _CAPABILITIES[capability_id] = record
    return _new_capability(
        factory_id=OWNED_RUNTIME_FAKE_FACTORY_ID,
        bundle_sha256=proof_sha256,
        compiler_sha256=compiler.sha256,
        capability_id=capability_id,
        factory_nonce=factory_nonce,
        issuer_mac=issuer_mac,
    )


def _consume_capability(
    capability: object,
) -> _CapabilityRecord | LaunchFailure:
    with _STATE_LOCK:
        if type(capability) is not OwnedFakeRuntimeCapability:
            return _failure(
                LaunchDisposition.INVALID_REQUEST,
                LaunchReason.INVALID_CAPABILITY,
                phase=LaunchPhase.NEW,
            )
        record = _CAPABILITIES.get(capability._capability_id)
        if (
            record is None
            or record.issuer_pid != os.getpid()
            or capability.factory_id != OWNED_RUNTIME_FAKE_FACTORY_ID
            or capability._factory_nonce != record.factory_nonce
            or capability.bundle_sha256 != record.proof_sha256
            or capability.compiler_sha256 != record.compiler.sha256
            or not hmac.compare_digest(capability._issuer_mac, _capability_mac(record))
        ):
            return _failure(
                LaunchDisposition.INVALID_REQUEST,
                LaunchReason.INVALID_CAPABILITY,
                phase=LaunchPhase.NEW,
            )
        if record.consumed:
            return _failure(
                LaunchDisposition.STATE_CONFLICT,
                LaunchReason.CAPABILITY_REUSED,
                phase=LaunchPhase.NEW,
            )
        record.consumed = True
        return record


def _record_for_handle(
    handle: object,
) -> _HandleRecord | LaunchFailure:
    if type(handle) is not OwnedFakeLaunchHandle:
        return _failure(
            LaunchDisposition.INVALID_REQUEST,
            LaunchReason.INVALID_CAPABILITY,
            phase=LaunchPhase.NEW,
        )
    with _STATE_LOCK:
        record = _HANDLES.get(handle._handle_id)
        if record is None or not hmac.compare_digest(
            handle._handle_mac,
            _handle_mac(record),
        ):
            return _failure(
                LaunchDisposition.INVALID_REQUEST,
                LaunchReason.INVALID_CAPABILITY,
                phase=LaunchPhase.NEW,
            )
        return record


def _claim_operation(
    handle: object,
    operation: str,
) -> tuple[_HandleRecord, bool] | LaunchFailure:
    found = _record_for_handle(handle)
    if isinstance(found, LaunchFailure):
        return found
    with _STATE_LOCK:
        if found.operation is not None:
            return _failure(
                LaunchDisposition.STATE_CONFLICT,
                LaunchReason.FINAL_CAS_CONFLICT,
                phase=found.phase,
                receipt_state=_receipt_state(found),
                diagnostics={"stage": "operation_in_progress"},
                trace=found.trace,
            )
        if operation == "finalize":
            if found.verified_result is not None:
                return found, False
            if found.failure_result is not None:
                return found, False
            if found.phase is not LaunchPhase.ACTIVATION_EXEC_CONFIRMED:
                return _failure(
                    LaunchDisposition.STATE_CONFLICT,
                    LaunchReason.FINAL_CAS_CONFLICT,
                    phase=found.phase,
                    receipt_state=_receipt_state(found),
                    diagnostics={"stage": "finalize_state"},
                    trace=found.trace,
                )
        elif operation == "close":
            if found.close_result is not None:
                return found, False
        else:
            raise ValueError("unknown owned fake operation")
        found.operation = operation
        return found, True


def _release_operation(record: _HandleRecord) -> None:
    with _STATE_LOCK:
        record.operation = None


def _phase_hook(phase: LaunchPhase, handle_id: str) -> None:
    """Deterministic test seam after a recorded phase transition."""


def _set_phase(record: _HandleRecord, phase: LaunchPhase) -> None:
    record.phase = phase
    record.trace.append(phase.value)
    _phase_hook(phase, record.handle_id)


def _registry_matches(record: _CapabilityRecord) -> bool:
    from core.project.sessions import SESSIONS_DIR

    try:
        expected = record.registry_root.stat()
        current = Path(SESSIONS_DIR).stat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(expected.st_mode)
        and stat.S_ISDIR(current.st_mode)
        and _identity_tuple(expected) == _identity_tuple(current)
        and expected.st_uid == os.geteuid()
        and current.st_uid == os.geteuid()
        and stat.S_IMODE(expected.st_mode) & 0o022 == 0
        and stat.S_IMODE(current.st_mode) & 0o022 == 0
    )


def _deadline_remaining(deadline: MonotonicDeadline) -> float:
    return max(0.0, deadline.expires_at - time.monotonic())


def _cancelled(cancellation: LaunchCancellation) -> bool:
    poller = select.poll()
    poller.register(cancellation._read_fd, select.POLLIN | select.POLLHUP)
    return bool(poller.poll(0))


def _poll_timeout(deadline: MonotonicDeadline) -> int:
    remaining = _deadline_remaining(deadline)
    if remaining <= 0:
        return 0
    return max(1, int(min(remaining, _POLL_QUANTUM_SECONDS) * 1000))


def _utc_timestamp() -> UtcTimestamp:
    value = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    return UtcTimestamp(value.replace("+00:00", "Z"))


def _read_process_euid(pid: int) -> int:
    raw = Path(f"/proc/{pid}/status").read_text(
        encoding="utf-8",
        errors="strict",
    )
    for line in raw.splitlines():
        if line.startswith("Uid:"):
            fields = line.split()
            if len(fields) >= 3:
                return int(fields[2])
    raise ValueError("process effective uid unavailable")


def _namespace_inode(pid: int, name: str) -> int:
    value = os.stat(f"/proc/{pid}/ns/{name}", follow_symlinks=True)
    return value.st_ino


def _hash_open_file(fd: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(fd, min(1_048_576, size - offset), offset)
        if not chunk:
            raise ValueError("short executable read")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _capture_process_identity(
    pid: int,
    *,
    parent_pid: int,
) -> _ProcessIdentity:
    from core.project.sessions import boot_id, proc_starttime

    start = proc_starttime(pid)
    current_boot = boot_id()
    if start is None or current_boot is None:
        raise ValueError("process identity unavailable")
    process_group = os.getpgid(pid)
    exe_fd = os.open(
        f"/proc/{pid}/exe",
        os.O_RDONLY | os.O_CLOEXEC,
    )
    try:
        before = os.fstat(exe_fd)
        digest = _hash_open_file(exe_fd, before.st_size)
        after = os.fstat(exe_fd)
    finally:
        os.close(exe_fd)
    if _leaf_fingerprint(before) != _leaf_fingerprint(after):
        raise ValueError("process executable changed")
    return _ProcessIdentity(
        pid=pid,
        parent_pid=parent_pid,
        process_group=process_group,
        starttime_ticks=int(start),
        boot_id=current_boot,
        pid_namespace_inode=_namespace_inode(pid, "pid"),
        mount_namespace_inode=_namespace_inode(pid, "mnt"),
        euid=_read_process_euid(pid),
        executable_device=before.st_dev,
        executable_inode=before.st_ino,
        executable_size=before.st_size,
        executable_sha256=digest,
    )


def _identity_matches(
    observed: _ProcessIdentity,
    expected: _ProcessIdentity,
) -> bool:
    return observed == expected


def _primary_leaf(record: _CapabilityRecord) -> _LeafIdentity:
    return next(
        item for item in record.leaves if item.relative_path == "bin/owned-runtime-host"
    )


def _process_matches_primary(
    identity: _ProcessIdentity,
    capability: _CapabilityRecord,
) -> bool:
    expected = _primary_leaf(capability)
    return (
        identity.executable_device,
        identity.executable_inode,
        identity.executable_size,
        identity.executable_sha256,
    ) == (
        expected.device,
        expected.inode,
        expected.size,
        expected.sha256,
    )


def _child_waitable(record: _HandleRecord) -> bool:
    if record.child_reaped:
        return True
    options = os.WEXITED | os.WNOHANG | os.WNOWAIT
    try:
        result = os.waitid(os.P_PID, record.child_pid, options)
    except ChildProcessError as exc:
        raise ValueError("direct child was reaped elsewhere") from exc
    return result is not None


def _frame_bytes(
    frame_type: _FrameType,
    record: _HandleRecord,
    *,
    argument0: int = 0,
    argument1: int = 0,
    argument2: int = 0,
) -> bytes:
    return _FRAME.pack(
        _FRAME_MAGIC,
        _FRAME_VERSION,
        frame_type.value,
        _FRAME_PAYLOAD_BYTES,
        record.child_pid,
        record.parent_pid,
        record.process_group,
        argument0,
        argument1,
        argument2,
    )


def _send_frame(
    record: _HandleRecord,
    frame_type: _FrameType,
    *,
    argument0: int = 0,
    argument1: int = 0,
    argument2: int = 0,
) -> bool:
    try:
        sent = record.control.send(
            _frame_bytes(
                frame_type,
                record,
                argument0=argument0,
                argument1=argument1,
                argument2=argument2,
            )
        )
    except OSError:
        return False
    return sent == _FRAME.size


def _decode_frame(
    raw: bytes, record: _HandleRecord
) -> tuple[_FrameType, int, int, int]:
    if len(raw) != _FRAME.size:
        raise ValueError("protocol frame length mismatch")
    (
        magic,
        version,
        frame_type,
        payload_bytes,
        pid,
        parent_pid,
        process_group,
        argument0,
        argument1,
        argument2,
    ) = _FRAME.unpack(raw)
    if (
        magic != _FRAME_MAGIC
        or version != _FRAME_VERSION
        or payload_bytes != _FRAME_PAYLOAD_BYTES
        or pid != record.child_pid
        or parent_pid != record.parent_pid
        or process_group != record.process_group
    ):
        raise ValueError("protocol frame identity mismatch")
    return _FrameType(frame_type), argument0, argument1, argument2


def _receive_control_packet(
    record: _HandleRecord,
    *,
    flags: int = 0,
) -> bytes | None:
    while True:
        try:
            if flags:
                return record.control.recv(_FRAME.size + 1, flags)
            return record.control.recv(_FRAME.size + 1)
        except InterruptedError:
            continue
        except BlockingIOError:
            return None
        except OSError as exc:
            if exc.errno in _CONTROL_CHANNEL_EOF_ERRNOS:
                raise EOFError("control channel closed") from exc
            raise


def _control_channel_state(
    record: _HandleRecord,
) -> Literal["open", "data", "closed"]:
    try:
        raw = _receive_control_packet(record, flags=socket.MSG_PEEK)
    except EOFError:
        return "closed"
    if raw is None:
        return "open"
    return "closed" if raw == b"" else "data"


def _receive_frame(record: _HandleRecord) -> tuple[_FrameType, int, int, int] | None:
    raw = _receive_control_packet(record)
    if raw is None:
        return None
    if raw == b"":
        raise EOFError("control channel closed")
    return _decode_frame(raw, record)


def _control_or_child_failure(
    record: _HandleRecord,
    *,
    control_eof_reason: LaunchReason,
) -> LaunchFailure | None:
    control_state = _control_channel_state(record)
    if control_state == "closed":
        return _failure(
            LaunchDisposition.PROCESS_LOST,
            control_eof_reason,
            phase=record.phase,
            receipt_state=_receipt_state(record),
            diagnostics={"stage": "control_eof"},
            trace=record.trace,
        )
    if control_state == "data":
        return None
    try:
        child_waitable = _child_waitable(record)
    except ValueError:
        return _failure(
            LaunchDisposition.PROCESS_LOST,
            LaunchReason.REAP_FAILED,
            phase=record.phase,
            receipt_state=_receipt_state(record),
            trace=record.trace,
        )
    if child_waitable:
        control_state = _control_channel_state(record)
        if control_state == "closed":
            return _failure(
                LaunchDisposition.PROCESS_LOST,
                control_eof_reason,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                diagnostics={"stage": "control_eof"},
                trace=record.trace,
            )
        if control_state == "data":
            return None
        return _failure(
            LaunchDisposition.PROCESS_LOST,
            LaunchReason.CHILD_EXITED,
            phase=record.phase,
            receipt_state=_receipt_state(record),
            trace=record.trace,
        )
    return None


def _post_frame_process_check(
    record: _HandleRecord,
    *,
    establish_identity: bool,
    control_eof_reason: LaunchReason,
) -> LaunchFailure | None:
    termination = _control_or_child_failure(
        record,
        control_eof_reason=control_eof_reason,
    )
    if termination is not None:
        return termination
    try:
        observed = _capture_process_identity(
            record.child_pid,
            parent_pid=record.parent_pid,
        )
    except (OSError, UnicodeError, ValueError):
        termination = _control_or_child_failure(
            record,
            control_eof_reason=control_eof_reason,
        )
        if termination is not None:
            return termination
        return _failure(
            LaunchDisposition.BINDING_FAILED,
            LaunchReason.PROCESS_SCOPE_CHANGED,
            phase=record.phase,
            receipt_state=_receipt_state(record),
            trace=record.trace,
        )
    identity_valid = _process_matches_primary(observed, record.capability)
    if establish_identity:
        identity_valid = identity_valid and (
            observed.process_group == record.child_pid
            and observed.parent_pid == record.parent_pid
            and observed.euid == os.geteuid()
        )
    else:
        identity_valid = identity_valid and _identity_matches(
            observed,
            record.process_identity,
        )
    if not identity_valid:
        termination = _control_or_child_failure(
            record,
            control_eof_reason=control_eof_reason,
        )
        if termination is not None:
            return termination
        return _failure(
            LaunchDisposition.BINDING_FAILED,
            LaunchReason.PROCESS_SCOPE_CHANGED,
            phase=record.phase,
            receipt_state=_receipt_state(record),
            trace=record.trace,
        )
    termination = _control_or_child_failure(
        record,
        control_eof_reason=control_eof_reason,
    )
    if termination is not None:
        return termination
    if establish_identity:
        record.process_identity = observed
    return None


def _read_exec_status(fd: int, buffer: bytearray) -> tuple[bool, int | None] | None:
    try:
        chunk = os.read(fd, _EXEC_STATUS.size + 1)
    except BlockingIOError:
        return None
    if chunk:
        buffer.extend(chunk)
        if len(buffer) > _EXEC_STATUS.size:
            raise ValueError("exec status frame exceeded its bound")
        return None
    if not buffer:
        return True, None
    if len(buffer) != _EXEC_STATUS.size:
        raise ValueError("partial exec status frame")
    magic, error_number = _EXEC_STATUS.unpack(buffer)
    if magic != _EXEC_STATUS_MAGIC or error_number <= 0:
        raise ValueError("invalid exec status frame")
    return False, error_number


def _await_exec_confirmation(
    record: _HandleRecord,
    *,
    status_fd: int,
    expected_frame: _FrameType,
    establish_identity: bool,
    deadline: MonotonicDeadline,
    cancellation: LaunchCancellation,
    exec_failure_reason: LaunchReason,
    protocol_failure_reason: LaunchReason,
    post_frame_control_failure_reason: LaunchReason,
) -> LaunchFailure | None:
    status = bytearray()
    exec_succeeded = False
    frame_seen = False
    poller = select.poll()
    poller.register(status_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    poller.register(
        record.control.fileno(),
        select.POLLIN | select.POLLHUP | select.POLLERR,
    )
    poller.register(
        cancellation._read_fd,
        select.POLLIN | select.POLLHUP | select.POLLERR,
    )
    while not (exec_succeeded and frame_seen):
        if _cancelled(cancellation):
            return _failure(
                LaunchDisposition.CANCELLED,
                LaunchReason.CANCELLED,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                trace=record.trace,
            )
        if deadline.expired():
            return _failure(
                LaunchDisposition.TIMED_OUT,
                LaunchReason.DEADLINE_EXCEEDED,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                trace=record.trace,
            )
        try:
            events = poller.poll(_poll_timeout(deadline))
        except InterruptedError:
            continue
        for fd, flags in events:
            if fd == cancellation._read_fd:
                return _failure(
                    LaunchDisposition.CANCELLED,
                    LaunchReason.CANCELLED,
                    phase=record.phase,
                    receipt_state=_receipt_state(record),
                    trace=record.trace,
                )
            if fd == status_fd and flags & (
                select.POLLIN | select.POLLHUP | select.POLLERR
            ):
                try:
                    result = _read_exec_status(status_fd, status)
                except ValueError:
                    return _failure(
                        LaunchDisposition.SPAWN_FAILED,
                        exec_failure_reason,
                        phase=record.phase,
                        diagnostics={"stage": "exec_status_protocol"},
                        trace=record.trace,
                    )
                if result is not None:
                    succeeded, error_number = result
                    if not succeeded:
                        return _failure(
                            LaunchDisposition.SPAWN_FAILED,
                            exec_failure_reason,
                            phase=record.phase,
                            diagnostics={
                                "stage": "exec",
                                "errno_class": errno.errorcode.get(
                                    error_number or 0,
                                    "other",
                                ).lower(),
                            },
                            trace=record.trace,
                        )
                    exec_succeeded = True
            if fd == record.control.fileno() and flags & select.POLLIN:
                try:
                    frame = _receive_frame(record)
                except (EOFError, ValueError):
                    return _failure(
                        LaunchDisposition.SPAWN_FAILED,
                        protocol_failure_reason,
                        phase=record.phase,
                        diagnostics={"stage": "control_frame"},
                        trace=record.trace,
                    )
                if frame is None or frame[0] is not expected_frame:
                    return _failure(
                        LaunchDisposition.SPAWN_FAILED,
                        protocol_failure_reason,
                        phase=record.phase,
                        diagnostics={"stage": "unexpected_frame"},
                        trace=record.trace,
                    )
                frame_seen = True
            if fd == record.control.fileno() and flags & (
                select.POLLHUP | select.POLLERR
            ):
                return _failure(
                    LaunchDisposition.PROCESS_LOST,
                    post_frame_control_failure_reason
                    if frame_seen
                    else protocol_failure_reason,
                    phase=record.phase,
                    diagnostics={"stage": "control_eof"},
                    trace=record.trace,
                )
        termination = _control_or_child_failure(
            record,
            control_eof_reason=(
                post_frame_control_failure_reason
                if frame_seen
                else protocol_failure_reason
            ),
        )
        if termination is not None:
            return termination
    return _post_frame_process_check(
        record,
        establish_identity=establish_identity,
        control_eof_reason=post_frame_control_failure_reason,
    )


def _open_child_files(
    capability: _CapabilityRecord,
) -> tuple[int, int, int, int]:
    root_fd = os.open(
        capability.bundle_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        distribution_fd = os.open(
            "dist",
            os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
        primary_fd = _open_relative_leaf(root_fd, "bin/owned-runtime-host")
        alternate_fd = _open_relative_leaf(root_fd, "bin/owned-runtime-host-alt")
        null_fd = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
    except BaseException:
        os.close(root_fd)
        for fd in (
            locals().get("distribution_fd", -1),
            locals().get("primary_fd", -1),
            locals().get("alternate_fd", -1),
            locals().get("null_fd", -1),
        ):
            if isinstance(fd, int) and fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(fd)
        raise
    os.close(root_fd)
    return distribution_fd, primary_fd, alternate_fd, null_fd


def _child_launch(
    *,
    control_fd: int,
    liveness_fd: int,
    activation_status_fd: int,
    witness_fd: int,
    distribution_fd: int,
    primary_fd: int,
    alternate_fd: int,
    bootstrap_status_fd: int,
    null_fd: int,
    close_limit: int,
) -> None:
    sources = (
        null_fd,
        null_fd,
        null_fd,
        control_fd,
        liveness_fd,
        activation_status_fd,
        witness_fd,
        distribution_fd,
        primary_fd,
        alternate_fd,
        bootstrap_status_fd,
    )
    high_base = max((*sources, 10)) + 16
    try:
        for index, source in enumerate(sources):
            os.dup2(source, high_base + index, inheritable=True)
        for target, index in enumerate(range(11)):
            os.dup2(
                high_base + index,
                target,
                inheritable=target != 10,
            )
        os.closerange(11, close_limit)
        os.setpgid(0, 0)
        os.execve(8, _BOOTSTRAP_ARGV, {})
    except OSError as exc:
        error_number = exc.errno if 0 < (exc.errno or 0) < 2**31 else errno.EIO
        with contextlib.suppress(OSError):
            os.write(10, _EXEC_STATUS.pack(_EXEC_STATUS_MAGIC, error_number))
    os._exit(127)


def _set_parent_process_group(pid: int) -> bool:
    try:
        os.setpgid(pid, pid)
    except OSError as exc:
        if exc.errno != errno.EACCES:
            return False
        try:
            return os.getpgid(pid) == pid
        except OSError:
            return False
    try:
        return os.getpgid(pid) == pid
    except OSError:
        return False


def _collect_stable(
    capability: _CapabilityRecord,
    deadline: MonotonicDeadline,
) -> tuple[OfflineRuntimeEvidence, FileEvidence] | LaunchFailure:
    evidence = collect_offline_runtime_evidence(
        capability.offline_request,
        deadline=deadline,
    )
    if isinstance(evidence, CollectionFailure):
        return _failure(
            LaunchDisposition.COLLECTION_FAILED,
            LaunchReason.STABLE_COLLECTION_FAILED,
            phase=LaunchPhase.CAPABILITY_VERIFIED,
            diagnostics={"stage": "offline_collection"},
        )
    launcher = collect_file_identity(
        capability.launcher_request,
        deadline=deadline,
    )
    if isinstance(launcher, CollectionFailure):
        return _failure(
            LaunchDisposition.COLLECTION_FAILED,
            LaunchReason.STABLE_COLLECTION_FAILED,
            phase=LaunchPhase.CAPABILITY_VERIFIED,
            diagnostics={"stage": "launcher_collection"},
        )
    if (
        _evidence_signature(evidence) != capability.baseline_evidence_signature
        or _descriptor_signature(launcher) != capability.baseline_launcher_signature
    ):
        return _failure(
            LaunchDisposition.COLLECTION_FAILED,
            LaunchReason.STABLE_EVIDENCE_CHANGED,
            phase=LaunchPhase.CAPABILITY_VERIFIED,
            diagnostics={"stage": "capability_recheck"},
        )
    return evidence, launcher


def _spawn_record(
    capability: _CapabilityRecord,
    evidence: OfflineRuntimeEvidence,
    launcher: FileEvidence,
) -> tuple[_HandleRecord, int, int] | LaunchFailure:
    if (
        os.execve not in os.supports_fd
        or not hasattr(os, "O_PATH")
        or not hasattr(socket, "SOCK_SEQPACKET")
        or not hasattr(os, "waitid")
        or not hasattr(os, "WNOWAIT")
    ):
        return _failure(
            LaunchDisposition.UNSUPPORTED_PLATFORM,
            LaunchReason.REQUIRED_PRIMITIVE_MISSING,
            phase=LaunchPhase.STABLE_EVIDENCE_COLLECTED,
        )
    try:
        distribution_fd, primary_fd, alternate_fd, null_fd = _open_child_files(
            capability
        )
        parent_control, child_control = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET,
        )
        liveness_read, liveness_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        activation_read, activation_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        witness_read, witness_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        bootstrap_read, bootstrap_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        for fd in tuple(
            item
            for item in (
                locals().get("distribution_fd"),
                locals().get("primary_fd"),
                locals().get("alternate_fd"),
                locals().get("null_fd"),
                locals().get("liveness_read"),
                locals().get("liveness_write"),
                locals().get("activation_read"),
                locals().get("activation_write"),
                locals().get("witness_read"),
                locals().get("witness_write"),
                locals().get("bootstrap_read"),
                locals().get("bootstrap_write"),
            )
            if isinstance(item, int)
        ):
            with contextlib.suppress(OSError):
                os.close(fd)
        for channel in (
            locals().get("parent_control"),
            locals().get("child_control"),
        ):
            if isinstance(channel, socket.socket):
                channel.close()
        return _failure(
            LaunchDisposition.SPAWN_FAILED,
            LaunchReason.FORK_FAILED,
            phase=LaunchPhase.STABLE_EVIDENCE_COLLECTED,
        )
    parent_control.setblocking(False)
    child_control.setblocking(False)
    close_limit = min(int(os.sysconf("SC_OPEN_MAX")), 1_048_576)
    try:
        child_pid = os.fork()
    except OSError:
        for fd in (
            distribution_fd,
            primary_fd,
            alternate_fd,
            null_fd,
            liveness_read,
            liveness_write,
            activation_read,
            activation_write,
            witness_read,
            witness_write,
            bootstrap_read,
            bootstrap_write,
        ):
            with contextlib.suppress(OSError):
                os.close(fd)
        parent_control.close()
        child_control.close()
        return _failure(
            LaunchDisposition.SPAWN_FAILED,
            LaunchReason.FORK_FAILED,
            phase=LaunchPhase.STABLE_EVIDENCE_COLLECTED,
        )
    if child_pid == 0:
        _child_launch(
            control_fd=child_control.fileno(),
            liveness_fd=liveness_read,
            activation_status_fd=activation_write,
            witness_fd=witness_write,
            distribution_fd=distribution_fd,
            primary_fd=primary_fd,
            alternate_fd=alternate_fd,
            bootstrap_status_fd=bootstrap_write,
            null_fd=null_fd,
            close_limit=close_limit,
        )
    child_control.close()
    for fd in (
        distribution_fd,
        primary_fd,
        alternate_fd,
        null_fd,
        liveness_read,
        activation_write,
        witness_write,
        bootstrap_write,
    ):
        with contextlib.suppress(OSError):
            os.close(fd)
    group_verified = _set_parent_process_group(child_pid)
    try:
        process_identity = _capture_process_identity(
            child_pid,
            parent_pid=os.getpid(),
        )
    except (OSError, UnicodeError, ValueError):
        process_identity = _ProcessIdentity(
            pid=child_pid,
            parent_pid=os.getpid(),
            process_group=child_pid if group_verified else 0,
            starttime_ticks=0,
            boot_id="",
            pid_namespace_inode=0,
            mount_namespace_inode=0,
            euid=os.geteuid(),
            executable_device=0,
            executable_inode=0,
            executable_size=0,
            executable_sha256="0" * 64,
        )
    token = SessionToken(secrets.token_bytes(16))
    handle_id = secrets.token_hex(16)
    record = _HandleRecord(
        handle_id=handle_id,
        capability=capability,
        parent_pid=os.getpid(),
        child_pid=child_pid,
        process_group=child_pid,
        group_verified=group_verified,
        process_identity=process_identity,
        control=parent_control,
        liveness_write_fd=liveness_write,
        witness_read_fd=witness_read,
        baseline_evidence=evidence,
        launcher_evidence=launcher,
        stable_inputs=None,
        launch_inputs=None,
        binding_inputs=None,
        token=token,
        token_hex=token._hex_for_static_verifier(),
        pending=None,
        current_receipt=None,
        phase=LaunchPhase.CHILD_FORKED,
        trace=[
            LaunchPhase.NEW.value,
            LaunchPhase.CAPABILITY_VERIFIED.value,
            LaunchPhase.STABLE_EVIDENCE_COLLECTED.value,
            LaunchPhase.CHILD_FORKED.value,
        ],
        reference_names=set(),
    )
    with _STATE_LOCK:
        _HANDLES[handle_id] = record
    return record, bootstrap_read, activation_read


def _receipt_state(record: _HandleRecord) -> str:
    current = record.current_receipt
    if isinstance(
        current,
        (PendingReceiptIssued, VerifiedReceiptIssued, RejectedReceiptIssued),
    ):
        return current.reference.state.value
    return ReceiptState.ABSENT.value


def _record_failure(
    record: _HandleRecord,
    failure: LaunchFailure,
) -> LaunchFailure:
    record.failure_result = failure
    return failure


def _initial_identity_valid(record: _HandleRecord) -> bool:
    return (
        record.group_verified
        and record.process_identity.starttime_ticks > 0
        and record.process_identity.process_group == record.child_pid
        and record.process_identity.euid == os.geteuid()
        and _process_matches_primary(record.process_identity, record.capability)
    )


def _make_issuance_inputs(
    record: _HandleRecord,
) -> tuple[StableIssuanceInputs, LaunchIssuanceInputs, BindingIssuanceInputs]:
    evidence = record.baseline_evidence
    capability = record.capability
    stable = StableIssuanceInputs(
        profile=capability.profile,
        launcher=record.launcher_evidence,
        platform=default_linux_x86_64_platform(),
        distribution_source=DistributionSource.SEALED_CACHE_SNAPSHOT,
        required_semantics=(
            SemanticName("session.receipt.snapshot"),
            SemanticName("session.receipt.non_authorizing"),
        ),
    )
    version_bytes = b"raptor-owned-runtime-fake 1.0.0\n"
    version_sha256 = Sha256(hashlib.sha256(version_bytes).hexdigest())
    launch = LaunchIssuanceInputs(
        session_id=UuidText(str(uuid.uuid4())),
        launch_id=UuidText(str(uuid.uuid4())),
        repository_head=Sha1(
            hashlib.sha1(b"raptor-owned-runtime-fake-repository").hexdigest()
        ),
        source_directory=evidence.distribution.source.root.requested_path,
        sealed_directory=evidence.distribution.source.root.resolved_path,
        selection=SelectionObservation(
            ambient_copilot_cli_dist_dir_present=False,
            ambient_copilot_pkg_cache_home_present=False,
            ambient_copilot_cache_home_present=False,
            ambient_xdg_cache_home_present=False,
            ambient_copilot_auto_update_present=False,
            all_ambient_selectors_stripped=True,
            launcher_set_dist_dir_from_receipt=True,
            launcher_disabled_auto_update=True,
            user_prefer_version_rejected=True,
        ),
        version_observation=VersionObservation(
            reported_version=evidence.distribution.version,
            version_stdout_sha256=version_sha256,
            version_exit_code=0,
            binary_version_stdout_sha256=version_sha256,
            binary_version_exit_code=0,
            stderr_empty=True,
            network_disabled=True,
            stdin_dev_null=True,
            auto_update_disabled=True,
        ),
    )
    identity = record.process_identity
    binding = BindingIssuanceInputs(
        session_pid=record.child_pid,
        session_starttime_ticks=identity.starttime_ticks,
        boot_id=UuidText(identity.boot_id),
        pid_namespace_inode=identity.pid_namespace_inode,
        launcher_euid=identity.euid,
        session_token=record.token,
        launch_nonce=NonceHex(secrets.token_hex(16)),
        issued_at_utc=_utc_timestamp(),
        freshness_not_after_utc=None,
    )
    return stable, launch, binding


def _install_pending(
    record: _HandleRecord,
    pending: PendingReceiptIssued,
) -> StoredReceipt | PlumbingFailure | LaunchFailure:
    from core.project.sessions import install_pending_session_receipt
    from core.startup.host import Frontend, SessionHostClaim

    if not _registry_matches(record.capability):
        return _failure(
            LaunchDisposition.BINDING_FAILED,
            LaunchReason.REGISTRY_ROOT_MISMATCH,
            phase=record.phase,
            trace=record.trace,
        )
    host = SessionHostClaim(
        frontend=Frontend.COPILOT,
        uid=record.process_identity.euid,
        executable=Path(record.baseline_evidence.frontend.path.resolved_path.value),
        executable_device=record.process_identity.executable_device,
        executable_inode=record.process_identity.executable_inode,
    )
    return install_pending_session_receipt(
        pending,
        token_hex=record.token_hex,
        expected_host=host,
    )


def _cas_receipt(
    record: _HandleRecord,
    replacement: VerifiedReceiptIssued | RejectedReceiptIssued,
) -> CasApplied | PlumbingFailure | LaunchFailure:
    from core.project.sessions import compare_and_swap_session_receipt

    if not _registry_matches(record.capability):
        return _failure(
            LaunchDisposition.BINDING_FAILED,
            LaunchReason.REGISTRY_ROOT_MISMATCH,
            phase=record.phase,
            receipt_state=_receipt_state(record),
            trace=record.trace,
        )
    current = record.current_receipt
    if current is None:
        return _failure(
            LaunchDisposition.STATE_CONFLICT,
            LaunchReason.FINAL_CAS_CONFLICT,
            phase=record.phase,
            trace=record.trace,
        )
    return compare_and_swap_session_receipt(
        current.reference,
        replacement.reference,
        replacement.receipt,
        token_hex=record.token_hex,
    )


def _remove_receipt(
    record: _HandleRecord,
) -> CleanupApplied | PlumbingFailure | LaunchFailure | None:
    from core.project.sessions import remove_session_receipt

    current = record.current_receipt
    if current is None or record.phase is LaunchPhase.REVOKED:
        return None
    if not _registry_matches(record.capability):
        return _failure(
            LaunchDisposition.BINDING_FAILED,
            LaunchReason.REGISTRY_ROOT_MISMATCH,
            phase=record.phase,
            receipt_state=_receipt_state(record),
            trace=record.trace,
        )
    return remove_session_receipt(
        current.reference,
        token_hex=record.token_hex,
    )


def _close_fd(fd: int) -> bool:
    if fd < 0:
        return True
    try:
        os.close(fd)
    except OSError as exc:
        return exc.errno == errno.EBADF
    return True


def _close_parent_channels(record: _HandleRecord) -> bool:
    if record.fds_closed:
        return True
    ok = True
    try:
        record.control.close()
    except OSError:
        ok = False
    for name in ("liveness_write_fd", "witness_read_fd"):
        fd = getattr(record, name)
        if not _close_fd(fd):
            ok = False
        setattr(record, name, -1)
    record.fds_closed = True
    return ok


def _signal_identity_valid(record: _HandleRecord) -> bool:
    if record.child_reaped:
        return False
    try:
        if _child_waitable(record):
            return False
        observed = _capture_process_identity(
            record.child_pid,
            parent_pid=record.parent_pid,
        )
    except (OSError, UnicodeError, ValueError):
        return False
    return _identity_matches(observed, record.process_identity)


def _liveness_readers_gone(record: _HandleRecord) -> bool:
    if record.liveness_write_fd < 0:
        return False
    poller = select.poll()
    poller.register(
        record.liveness_write_fd,
        select.POLLERR | select.POLLHUP,
    )
    return any(
        flags & (select.POLLERR | select.POLLHUP) for _fd, flags in poller.poll(0)
    )


def _wait_for_drain_until(record: _HandleRecord, expires_at: float) -> bool:
    if record.liveness_write_fd < 0:
        return False
    poller = select.poll()
    poller.register(
        record.liveness_write_fd,
        select.POLLERR | select.POLLHUP,
    )
    while time.monotonic() < expires_at:
        try:
            waitable = _child_waitable(record)
        except ValueError:
            return False
        if waitable and _liveness_readers_gone(record):
            return True
        remaining = max(0.0, expires_at - time.monotonic())
        try:
            poller.poll(max(1, int(min(remaining, _POLL_QUANTUM_SECONDS) * 1000)))
        except InterruptedError:
            continue
    try:
        return _child_waitable(record) and _liveness_readers_gone(record)
    except ValueError:
        return False


def _signal_owned(record: _HandleRecord, signum: int) -> LaunchReason | None:
    if not _signal_identity_valid(record):
        try:
            if _child_waitable(record):
                return None
        except ValueError:
            return LaunchReason.REAP_FAILED
        return LaunchReason.PROCESS_SCOPE_CHANGED
    try:
        if record.group_verified:
            os.killpg(record.process_group, signum)
        else:
            os.kill(record.child_pid, signum)
    except ProcessLookupError:
        return None
    except OSError:
        return (
            LaunchReason.TERM_FAILED
            if signum == signal.SIGTERM
            else LaunchReason.KILL_FAILED
        )
    return None


def _reap_child(record: _HandleRecord) -> LaunchReason | None:
    if record.child_reaped:
        return None
    while True:
        try:
            pid, status = os.waitpid(record.child_pid, 0)
        except InterruptedError:
            continue
        except ChildProcessError:
            return LaunchReason.REAP_FAILED
        if pid != record.child_pid:
            return LaunchReason.REAP_FAILED
        record.child_status = status
        record.child_reaped = True
        return None


def _teardown_process(
    record: _HandleRecord,
    deadline: MonotonicDeadline,
) -> tuple[LaunchReason, ...]:
    reasons: list[LaunchReason] = []
    if record.child_reaped:
        if not record.fds_closed and not _close_parent_channels(record):
            reasons.append(LaunchReason.FD_CLEANUP_FAILED)
        return tuple(reasons)
    _send_frame(record, _FrameType.CONTROLLED_EXIT)
    remaining = _deadline_remaining(deadline)
    first = time.monotonic() + remaining / 3.0
    second = time.monotonic() + remaining * 2.0 / 3.0
    drained = _wait_for_drain_until(record, first)
    if not drained:
        failure = _signal_owned(record, signal.SIGTERM)
        if failure is not None:
            reasons.append(failure)
        drained = _wait_for_drain_until(record, second)
    if not drained:
        failure = _signal_owned(record, signal.SIGKILL)
        if failure is not None:
            reasons.append(failure)
        drained = _wait_for_drain_until(record, deadline.expires_at)
    if not drained and not record.group_verified:
        _close_fd(record.liveness_write_fd)
        record.liveness_write_fd = -1
        end = deadline.expires_at
        while time.monotonic() < end:
            try:
                if _child_waitable(record):
                    drained = record.capability.descendant_code == 0
                    break
            except ValueError:
                reasons.append(LaunchReason.REAP_FAILED)
                break
            select.select(
                (), (), (), min(_POLL_QUANTUM_SECONDS, end - time.monotonic())
            )
    try:
        waitable = _child_waitable(record)
    except ValueError:
        waitable = False
        reasons.append(LaunchReason.REAP_FAILED)
    if not drained and waitable and record.capability.descendant_code == 0:
        drained = True
    if drained:
        _set_phase(record, LaunchPhase.GROUP_DRAINED)
    else:
        reasons.append(LaunchReason.DESCENDANTS_REMAIN)
    if waitable:
        reap_reason = _reap_child(record)
        if reap_reason is None:
            _set_phase(record, LaunchPhase.CHILD_REAPED)
        else:
            reasons.append(reap_reason)
    elif not drained:
        reasons.append(LaunchReason.REAP_FAILED)
    if record.child_reaped:
        if drained:
            reasons = [
                item
                for item in reasons
                if item
                not in {
                    LaunchReason.PROCESS_SCOPE_CHANGED,
                    LaunchReason.TERM_FAILED,
                    LaunchReason.KILL_FAILED,
                }
            ]
        if not _close_parent_channels(record):
            reasons.append(LaunchReason.FD_CLEANUP_FAILED)
    return tuple(dict.fromkeys(reasons))


def _exit_code(status: int | None) -> int | None:
    if status is None:
        return None
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return None


def _registry_artifact_names(record: _HandleRecord) -> set[str]:
    names = {
        str(record.child_pid),
        f"{record.child_pid}.run",
        f"{record.child_pid}.run.lock",
        f"{record.child_pid}.receipt.lock",
        f".{record.child_pid}.receipt-entry.tmp",
    }
    current = record.current_receipt
    if current is not None:
        record.reference_names.add(current.reference.sidecar_name)
        record.reference_names.add(current.reference.sidecar_temporary_name)
    names.update(record.reference_names)
    return names


def _cleanup_registry_artifacts(record: _HandleRecord) -> bool:
    allowed = _registry_artifact_names(record)
    try:
        entries = {
            item.name: item for item in os.scandir(record.capability.registry_root)
        }
    except OSError:
        return False
    if set(entries) - allowed:
        return False
    entry_name = str(record.child_pid)
    if entry_name in entries or any(
        name in entries for name in record.reference_names if not name.endswith(".tmp")
    ):
        return False
    removable = {
        f"{record.child_pid}.run",
        f"{record.child_pid}.run.lock",
        f"{record.child_pid}.receipt.lock",
        f".{record.child_pid}.receipt-entry.tmp",
        *(name for name in record.reference_names if name.endswith(".tmp")),
    }
    root_fd = os.open(
        record.capability.registry_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        for name in sorted(set(entries) & removable):
            value = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(value.st_mode)
                or value.st_uid != os.geteuid()
                or value.st_nlink != 1
                or stat.S_IMODE(value.st_mode) & 0o022
            ):
                return False
            os.unlink(name, dir_fd=root_fd)
    except OSError:
        return False
    finally:
        os.close(root_fd)
    try:
        return not any(os.scandir(record.capability.registry_root))
    except OSError:
        return False


def _bundle_cleanup(record: _HandleRecord) -> bool:
    capability = record.capability
    if not record.child_reaped or not record.fds_closed:
        return False
    if not _cleanup_registry_artifacts(record):
        return False
    try:
        _verify_record_filesystem(capability)
    except (OSError, ValueError):
        return False
    root_fd = os.open(
        capability.bundle_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        for leaf in sorted(
            capability.leaves,
            key=lambda item: (item.relative_path.count("/"), item.relative_path),
            reverse=True,
        ):
            os.unlink(leaf.relative_path, dir_fd=root_fd)
        for relative in capability.cleanup_directories:
            os.rmdir(relative, dir_fd=root_fd)
    except OSError:
        os.close(root_fd)
        return False
    os.close(root_fd)
    try:
        test_root_fd = os.open(
            capability.test_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            os.rmdir(capability.bundle_root.name, dir_fd=test_root_fd)
        finally:
            os.close(test_root_fd)
    except OSError:
        return False
    _set_phase(record, LaunchPhase.CLEANED)
    return True


def _receipt_reason(reason: LaunchReason) -> ReasonCode:
    if reason is LaunchReason.SAME_IMAGE_REEXEC_OR_WITNESS_LOSS:
        return ReasonCode.REEXEC_UNVERIFIED
    if reason in {
        LaunchReason.DIFFERENT_IMAGE_REEXEC,
        LaunchReason.STABLE_EVIDENCE_CHANGED,
        LaunchReason.PROCESS_SCOPE_CHANGED,
    }:
        return ReasonCode.MAPPED_DISK_DIVERGENCE
    if reason is LaunchReason.SESSION_REPLACED:
        return ReasonCode.OWNERSHIP_REGISTRY_MISMATCH
    if reason in {
        LaunchReason.CHILD_EXITED,
        LaunchReason.DEADLINE_EXCEEDED,
        LaunchReason.CANCELLED,
        LaunchReason.READY_EOF,
    }:
        return ReasonCode.MAPPED_IMAGE_UNAVAILABLE
    return ReasonCode.OWNERSHIP_CHANGED


def _plumbing_failure_reason(
    failure: PlumbingFailure,
    fallback: LaunchReason,
) -> LaunchReason:
    reasons = set(failure.reason_codes)
    if PlumbingReason.SESSION_REPLACED in reasons:
        return LaunchReason.SESSION_REPLACED
    if PlumbingReason.CONCURRENT_FINALIZER in reasons:
        return LaunchReason.FINAL_CAS_CONFLICT
    if PlumbingReason.CAS_CONFLICT in reasons:
        return LaunchReason.FINAL_CAS_CONFLICT
    return fallback


def _commit_rejection(
    record: _HandleRecord,
    reason: LaunchReason,
    *,
    collection_failure: CollectionFailure | None = None,
) -> LaunchFailure | None:
    current = record.current_receipt
    if current is None or current.reference.state is ReceiptState.REJECTED:
        return None
    if collection_failure is None:
        rejected = build_rejected_receipt(
            current,
            reason_codes=(_receipt_reason(reason),),
            observed_at_utc=_utc_timestamp(),
        )
    else:
        rejected = build_rejected_from_collection(
            current,
            failure=collection_failure,
            observed_at_utc=_utc_timestamp(),
        )
    if isinstance(rejected, PlumbingFailure):
        return _failure(
            LaunchDisposition.RECEIPT_REJECTED,
            LaunchReason.REJECTION_CAS_FAILED,
            phase=record.phase,
            receipt_state=_receipt_state(record),
            diagnostics={"stage": "rejection_build"},
            trace=record.trace,
        )
    result = _cas_receipt(record, rejected)
    if isinstance(result, LaunchFailure):
        return result
    if isinstance(result, PlumbingFailure):
        mapped = _plumbing_failure_reason(
            result,
            LaunchReason.REJECTION_CAS_FAILED,
        )
        return _failure(
            LaunchDisposition.STATE_CONFLICT
            if mapped
            in {
                LaunchReason.SESSION_REPLACED,
                LaunchReason.FINAL_CAS_CONFLICT,
            }
            else LaunchDisposition.PERSISTENCE_FAILED,
            mapped,
            phase=record.phase,
            receipt_state=_receipt_state(record),
            diagnostics={"stage": "rejection_cas"},
            trace=record.trace,
        )
    record.current_receipt = rejected
    record.reference_names.add(rejected.reference.sidecar_name)
    record.reference_names.add(rejected.reference.sidecar_temporary_name)
    _set_phase(record, LaunchPhase.REJECTED_COMMITTED)
    return None


def _revoke_current(record: _HandleRecord) -> LaunchFailure | None:
    result = _remove_receipt(record)
    if result is None:
        return None
    if isinstance(result, LaunchFailure):
        return result
    if isinstance(result, PlumbingFailure):
        return _failure(
            LaunchDisposition.CLEANUP_FAILED,
            _plumbing_failure_reason(result, LaunchReason.REVOKE_FAILED),
            phase=record.phase,
            receipt_state=_receipt_state(record),
            diagnostics={"stage": "receipt_remove"},
            trace=record.trace,
        )
    record.current_receipt = None
    _set_phase(record, LaunchPhase.REVOKED)
    return None


def _settle_failure(
    record: _HandleRecord,
    failure: LaunchFailure,
    *,
    deadline: MonotonicDeadline,
    collection_failure: CollectionFailure | None = None,
) -> LaunchFailure:
    extra: list[LaunchReason] = []
    replacement_seen = failure.reason_codes[0] is LaunchReason.SESSION_REPLACED
    if record.current_receipt is not None and not replacement_seen:
        rejected_failure = _commit_rejection(
            record,
            failure.reason_codes[0],
            collection_failure=collection_failure,
        )
        if rejected_failure is not None:
            extra.extend(rejected_failure.reason_codes)
            replacement_seen = (
                LaunchReason.SESSION_REPLACED in rejected_failure.reason_codes
            )
        if not replacement_seen:
            revoked_failure = _revoke_current(record)
            if revoked_failure is not None:
                extra.extend(revoked_failure.reason_codes)
    extra.extend(_teardown_process(record, deadline))
    if (
        record.child_reaped
        and record.fds_closed
        and record.current_receipt is None
        and _bundle_cleanup(record)
    ):
        receipt_state = ReceiptState.CLEANED.value
        record.close_result = _new_closed(record, receipt_removed=True)
    else:
        receipt_state = _receipt_state(record)
        if LaunchReason.BUNDLE_CLEANUP_FAILED not in extra:
            extra.append(LaunchReason.BUNDLE_CLEANUP_FAILED)
    final = _failure(
        LaunchDisposition.CLEANUP_FAILED
        if any(
            item
            in {
                LaunchReason.REVOKE_FAILED,
                LaunchReason.REAP_FAILED,
                LaunchReason.DESCENDANTS_REMAIN,
                LaunchReason.FD_CLEANUP_FAILED,
                LaunchReason.BUNDLE_CLEANUP_FAILED,
            }
            for item in extra
        )
        else failure.disposition,
        failure.reason_codes[0],
        phase=record.phase,
        receipt_state=receipt_state,
        diagnostics=failure.diagnostics,
        trace=record.trace,
        additional_reasons=(*failure.reason_codes[1:], *extra),
    )
    return _record_failure(record, final)


def _launch_owned_runtime_fake(
    capability: object,
    *,
    deadline: MonotonicDeadline,
    cancellation: LaunchCancellation,
) -> OwnedFakeLaunchHandle | LaunchFailure:
    if (
        type(deadline) is not MonotonicDeadline
        or type(cancellation) is not LaunchCancellation
    ):
        return _failure(
            LaunchDisposition.INVALID_REQUEST,
            LaunchReason.INVALID_CAPABILITY,
            phase=LaunchPhase.NEW,
        )
    if os.name != "posix" or not Path("/proc/self").is_dir():
        return _failure(
            LaunchDisposition.UNSUPPORTED_PLATFORM,
            LaunchReason.REQUIRED_PRIMITIVE_MISSING,
            phase=LaunchPhase.NEW,
        )
    consumed = _consume_capability(capability)
    if isinstance(consumed, LaunchFailure):
        return consumed
    if not _registry_matches(consumed):
        return _failure(
            LaunchDisposition.BINDING_FAILED,
            LaunchReason.REGISTRY_ROOT_MISMATCH,
            phase=LaunchPhase.CAPABILITY_VERIFIED,
        )
    try:
        _verify_record_filesystem(consumed)
    except (OSError, ValueError):
        return _failure(
            LaunchDisposition.INVALID_REQUEST,
            LaunchReason.INVALID_CAPABILITY,
            phase=LaunchPhase.CAPABILITY_VERIFIED,
        )
    collected = _collect_stable(consumed, deadline)
    if isinstance(collected, LaunchFailure):
        return collected
    evidence, launcher = collected
    spawned = _spawn_record(consumed, evidence, launcher)
    if isinstance(spawned, LaunchFailure):
        return spawned
    record, bootstrap_status_fd, activation_status_fd = spawned
    try:
        if not record.group_verified:
            failure = _failure(
                LaunchDisposition.BINDING_FAILED,
                LaunchReason.PROCESS_GROUP_MISMATCH,
                phase=record.phase,
                trace=record.trace,
            )
            return _settle_failure(record, failure, deadline=deadline)
        bootstrap_failure = _await_exec_confirmation(
            record,
            status_fd=bootstrap_status_fd,
            expected_frame=_FrameType.BOOTSTRAP_READY,
            establish_identity=True,
            deadline=deadline,
            cancellation=cancellation,
            exec_failure_reason=LaunchReason.BOOTSTRAP_EXEC_FAILED,
            protocol_failure_reason=LaunchReason.BOOTSTRAP_PROTOCOL_FAILED,
            post_frame_control_failure_reason=LaunchReason.BOOTSTRAP_PROTOCOL_FAILED,
        )
        _close_fd(bootstrap_status_fd)
        bootstrap_status_fd = -1
        if bootstrap_failure is not None:
            return _settle_failure(record, bootstrap_failure, deadline=deadline)
        if not _initial_identity_valid(record):
            failure = _failure(
                LaunchDisposition.BINDING_FAILED,
                LaunchReason.PROCESS_SCOPE_CHANGED,
                phase=record.phase,
                trace=record.trace,
            )
            return _settle_failure(record, failure, deadline=deadline)
        _set_phase(record, LaunchPhase.BOOTSTRAP_EXEC_CONFIRMED)
        _set_phase(record, LaunchPhase.NATIVE_BOOTSTRAP_BLOCKED)
        stable, launch, binding = _make_issuance_inputs(record)
        record.stable_inputs = stable
        record.launch_inputs = launch
        record.binding_inputs = binding
        pending = build_pending_receipt(
            evidence,
            stable_inputs=stable,
            launch_inputs=launch,
            binding_inputs=binding,
        )
        if isinstance(pending, PlumbingFailure):
            failure = _failure(
                LaunchDisposition.RECEIPT_REJECTED,
                LaunchReason.STATIC_VERIFICATION_FAILED,
                phase=record.phase,
                diagnostics={"stage": "pending_build"},
                trace=record.trace,
            )
            return _settle_failure(record, failure, deadline=deadline)
        record.pending = pending
        record.current_receipt = pending
        record.reference_names.add(pending.reference.sidecar_name)
        record.reference_names.add(pending.reference.sidecar_temporary_name)
        _set_phase(record, LaunchPhase.PENDING_ISSUED)
        installed = _install_pending(record, pending)
        if isinstance(installed, LaunchFailure):
            return _settle_failure(record, installed, deadline=deadline)
        if isinstance(installed, PlumbingFailure):
            failure = _failure(
                LaunchDisposition.PERSISTENCE_FAILED,
                _plumbing_failure_reason(
                    installed,
                    LaunchReason.PENDING_COMMIT_FAILED,
                ),
                phase=record.phase,
                diagnostics={"stage": "pending_install"},
                trace=record.trace,
            )
            return _settle_failure(record, failure, deadline=deadline)
        _set_phase(record, LaunchPhase.PENDING_COMMITTED)
        try:
            observed = _capture_process_identity(
                record.child_pid,
                parent_pid=record.parent_pid,
            )
        except (OSError, UnicodeError, ValueError):
            observed = None
        if observed is None or not _identity_matches(
            observed,
            record.process_identity,
        ):
            failure = _failure(
                LaunchDisposition.BINDING_FAILED,
                LaunchReason.PROCESS_SCOPE_CHANGED,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                trace=record.trace,
            )
            return _settle_failure(record, failure, deadline=deadline)
        if not _send_frame(
            record,
            _FrameType.ACTIVATE,
            argument0=consumed.behavior_code,
            argument1=consumed.descendant_code,
            argument2=consumed.ready_delay_seconds,
        ):
            failure = _failure(
                LaunchDisposition.PROCESS_LOST,
                LaunchReason.ACTIVATION_EXEC_FAILED,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                trace=record.trace,
            )
            return _settle_failure(record, failure, deadline=deadline)
        activation_failure = _await_exec_confirmation(
            record,
            status_fd=activation_status_fd,
            expected_frame=_FrameType.ACTIVE_WAITING_READY,
            establish_identity=False,
            deadline=deadline,
            cancellation=cancellation,
            exec_failure_reason=LaunchReason.ACTIVATION_EXEC_FAILED,
            protocol_failure_reason=LaunchReason.BOOTSTRAP_PROTOCOL_FAILED,
            post_frame_control_failure_reason=LaunchReason.READY_EOF,
        )
        _close_fd(activation_status_fd)
        activation_status_fd = -1
        if activation_failure is not None:
            return _settle_failure(record, activation_failure, deadline=deadline)
        _set_phase(record, LaunchPhase.ACTIVATION_EXEC_CONFIRMED)
        handle = _new_handle(record.handle_id, _handle_mac(record))
        return handle
    except BaseException:
        _settle_failure(
            record,
            _failure(
                LaunchDisposition.CLEANUP_FAILED,
                LaunchReason.PROCESS_SCOPE_CHANGED,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                diagnostics={"stage": "unexpected_exception"},
                trace=record.trace,
            ),
            deadline=deadline,
        )
        raise
    finally:
        _close_fd(bootstrap_status_fd)
        _close_fd(activation_status_fd)


def _wait_for_ready(
    record: _HandleRecord,
    *,
    deadline: MonotonicDeadline,
    cancellation: LaunchCancellation,
) -> LaunchFailure | None:
    released = False
    shape_seen = False
    activation_time = _READY_CLOCK()
    poller = select.poll()
    poller.register(
        record.control.fileno(),
        select.POLLIN | select.POLLHUP | select.POLLERR,
    )
    poller.register(
        record.witness_read_fd,
        select.POLLIN | select.POLLHUP | select.POLLERR,
    )
    poller.register(
        cancellation._read_fd,
        select.POLLIN | select.POLLHUP | select.POLLERR,
    )
    while True:
        if _cancelled(cancellation):
            return _failure(
                LaunchDisposition.CANCELLED,
                LaunchReason.CANCELLED,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                trace=record.trace,
            )
        if deadline.expired():
            return _failure(
                LaunchDisposition.TIMED_OUT,
                LaunchReason.DEADLINE_EXCEEDED,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                trace=record.trace,
            )
        if (
            not released
            and _READY_CLOCK() - activation_time
            >= record.capability.ready_delay_seconds
        ):
            if not _send_frame(record, _FrameType.RELEASE_READY):
                return _failure(
                    LaunchDisposition.PROCESS_LOST,
                    LaunchReason.READY_EOF,
                    phase=record.phase,
                    receipt_state=_receipt_state(record),
                    trace=record.trace,
                )
            released = True
        try:
            events = poller.poll(_poll_timeout(deadline))
        except InterruptedError:
            continue
        for fd, flags in events:
            if fd == cancellation._read_fd:
                return _failure(
                    LaunchDisposition.CANCELLED,
                    LaunchReason.CANCELLED,
                    phase=record.phase,
                    receipt_state=_receipt_state(record),
                    trace=record.trace,
                )
            if fd == record.witness_read_fd and flags & (
                select.POLLIN | select.POLLHUP | select.POLLERR
            ):
                control_state = _control_channel_state(record)
                if control_state == "closed":
                    return _failure(
                        LaunchDisposition.PROCESS_LOST,
                        LaunchReason.READY_EOF,
                        phase=record.phase,
                        receipt_state=_receipt_state(record),
                        diagnostics={"stage": "control_eof"},
                        trace=record.trace,
                    )
                if control_state == "data":
                    continue
                state = _witness_state(record)
                if state != "open":
                    termination = _control_or_child_failure(
                        record,
                        control_eof_reason=LaunchReason.READY_EOF,
                    )
                    if termination is not None:
                        return termination
                    return _failure(
                        LaunchDisposition.PROCESS_LOST,
                        LaunchReason.SAME_IMAGE_REEXEC_OR_WITNESS_LOSS,
                        phase=record.phase,
                        receipt_state=_receipt_state(record),
                        trace=record.trace,
                    )
            if fd == record.control.fileno() and flags & select.POLLIN:
                try:
                    frame = _receive_frame(record)
                except ValueError:
                    return _failure(
                        LaunchDisposition.PROCESS_LOST,
                        LaunchReason.READY_MALFORMED,
                        phase=record.phase,
                        receipt_state=_receipt_state(record),
                        trace=record.trace,
                    )
                except EOFError:
                    return _failure(
                        LaunchDisposition.PROCESS_LOST,
                        LaunchReason.READY_EOF,
                        phase=record.phase,
                        receipt_state=_receipt_state(record),
                        trace=record.trace,
                    )
                if frame is None:
                    continue
                if frame[0] is _FrameType.PROTOCOL_ERROR:
                    return _failure(
                        LaunchDisposition.PROCESS_LOST,
                        LaunchReason.READY_MALFORMED,
                        phase=record.phase,
                        receipt_state=_receipt_state(record),
                        diagnostics={"stage": "native_protocol"},
                        trace=record.trace,
                    )
                if not shape_seen:
                    if (
                        frame[0] is not _FrameType.SHAPE
                        or frame[1] != record.capability.descendant_code
                    ):
                        return _failure(
                            LaunchDisposition.PROCESS_LOST,
                            LaunchReason.READY_MALFORMED,
                            phase=record.phase,
                            receipt_state=_receipt_state(record),
                            diagnostics={"stage": "shape"},
                            trace=record.trace,
                        )
                    shape_seen = True
                    continue
                if frame[0] is not _FrameType.READY:
                    return _failure(
                        LaunchDisposition.PROCESS_LOST,
                        LaunchReason.READY_MALFORMED,
                        phase=record.phase,
                        receipt_state=_receipt_state(record),
                        diagnostics={"stage": "ready_type"},
                        trace=record.trace,
                    )
                if frame[1] != record.capability.descendant_code:
                    return _failure(
                        LaunchDisposition.PROCESS_LOST,
                        LaunchReason.READY_MALFORMED,
                        phase=record.phase,
                        receipt_state=_receipt_state(record),
                        diagnostics={"stage": "ready_shape"},
                        trace=record.trace,
                    )
                control_closed_after_ready = False
                try:
                    extra = _receive_control_packet(
                        record,
                        flags=socket.MSG_PEEK,
                    )
                except EOFError:
                    extra = None
                    control_closed_after_ready = True
                if extra == b"":
                    control_closed_after_ready = True
                elif extra is not None:
                    return _failure(
                        LaunchDisposition.PROCESS_LOST,
                        LaunchReason.READY_MALFORMED,
                        phase=record.phase,
                        receipt_state=_receipt_state(record),
                        diagnostics={"stage": "duplicate_ready"},
                        trace=record.trace,
                    )
                if record.capability.behavior_code == 4:
                    while not deadline.expired():
                        try:
                            if _child_waitable(record):
                                return _failure(
                                    LaunchDisposition.PROCESS_LOST,
                                    LaunchReason.CHILD_EXITED,
                                    phase=record.phase,
                                    receipt_state=_receipt_state(record),
                                    trace=record.trace,
                                )
                        except ValueError:
                            break
                        try:
                            poller.poll(_poll_timeout(deadline))
                        except InterruptedError:
                            continue
                if control_closed_after_ready:
                    return _failure(
                        LaunchDisposition.PROCESS_LOST,
                        LaunchReason.READY_EOF,
                        phase=record.phase,
                        receipt_state=_receipt_state(record),
                        diagnostics={"stage": "control_eof"},
                        trace=record.trace,
                    )
                return _post_frame_process_check(
                    record,
                    establish_identity=False,
                    control_eof_reason=LaunchReason.READY_EOF,
                )
            if fd == record.control.fileno() and flags & (
                select.POLLHUP | select.POLLERR
            ):
                return _failure(
                    LaunchDisposition.PROCESS_LOST,
                    LaunchReason.READY_EOF,
                    phase=record.phase,
                    receipt_state=_receipt_state(record),
                    trace=record.trace,
                )
        termination = _control_or_child_failure(
            record,
            control_eof_reason=LaunchReason.READY_EOF,
        )
        if termination is not None:
            return termination


def _witness_state(record: _HandleRecord) -> str:
    try:
        raw = os.read(record.witness_read_fd, 1)
    except BlockingIOError:
        return "open"
    except OSError:
        return "error"
    return "eof" if raw == b"" else "data"


def _recollect(
    record: _HandleRecord,
    deadline: MonotonicDeadline,
) -> OfflineRuntimeEvidence | CollectionFailure | LaunchFailure:
    evidence = collect_offline_runtime_evidence(
        record.capability.offline_request,
        deadline=deadline,
    )
    if isinstance(evidence, CollectionFailure):
        return evidence
    launcher = collect_file_identity(
        record.capability.launcher_request,
        deadline=deadline,
    )
    if isinstance(launcher, CollectionFailure):
        return launcher
    if _evidence_signature(evidence) != _evidence_signature(
        record.baseline_evidence
    ) or _descriptor_signature(launcher) != _descriptor_signature(
        record.launcher_evidence
    ):
        return _failure(
            LaunchDisposition.COLLECTION_FAILED,
            LaunchReason.STABLE_EVIDENCE_CHANGED,
            phase=record.phase,
            receipt_state=_receipt_state(record),
            diagnostics={"stage": "stable_recollection"},
            trace=record.trace,
        )
    if (
        record.stable_inputs is None
        or record.launch_inputs is None
        or record.binding_inputs is None
        or record.pending is None
    ):
        return _failure(
            LaunchDisposition.STATE_CONFLICT,
            LaunchReason.FINAL_CAS_CONFLICT,
            phase=record.phase,
            receipt_state=_receipt_state(record),
            trace=record.trace,
        )
    candidate = build_pending_receipt(
        evidence,
        stable_inputs=record.stable_inputs,
        launch_inputs=record.launch_inputs,
        binding_inputs=record.binding_inputs,
    )
    if (
        isinstance(candidate, PlumbingFailure)
        or candidate.reference.stable_identity_sha256
        != record.pending.reference.stable_identity_sha256
    ):
        return _failure(
            LaunchDisposition.COLLECTION_FAILED,
            LaunchReason.STABLE_EVIDENCE_CHANGED,
            phase=record.phase,
            receipt_state=_receipt_state(record),
            diagnostics={"stage": "stable_digest"},
            trace=record.trace,
        )
    return evidence


def _native_file(
    evidence: OfflineRuntimeEvidence,
    role: MappedObjectRole,
) -> FileEvidence:
    wanted = (
        "prebuilds/linux-x64/runtime.node"
        if role is MappedObjectRole.RUNTIME_NODE
        else "prebuilds/linux-x64/cli-native.node"
    )
    return next(
        item.file
        for item in evidence.distribution.artifacts
        if item.name.value == wanted
    )


def _process_collection(
    record: _HandleRecord,
    evidence: OfflineRuntimeEvidence,
    deadline: MonotonicDeadline,
):
    scope = TrustedProcessScope(
        pid=record.child_pid,
        expected_starttime_ticks=record.process_identity.starttime_ticks,
        expected_euid=record.process_identity.euid,
        expected_pid_namespace_inode=record.process_identity.pid_namespace_inode,
        expected_mount_namespace_inode=record.process_identity.mount_namespace_inode,
    )
    expected = ExpectedMappedObjects(
        loader=ExpectedMappedObject(
            role=MappedObjectRole.LOADER,
            trusted_file=evidence.frontend,
        ),
        native_modules=(
            ExpectedMappedObject(
                role=MappedObjectRole.RUNTIME_NODE,
                trusted_file=_native_file(evidence, MappedObjectRole.RUNTIME_NODE),
            ),
            ExpectedMappedObject(
                role=MappedObjectRole.CLI_NATIVE_NODE,
                trusted_file=_native_file(evidence, MappedObjectRole.CLI_NATIVE_NODE),
            ),
        ),
        distribution_root=evidence.distribution.source.root,
    )
    return collect_linux_process_evidence(
        scope,
        expected,
        deadline=deadline,
    )


def _wait_for_witness_eof(
    record: _HandleRecord,
    deadline: MonotonicDeadline,
) -> LaunchFailure | _ProcessIdentity:
    poller = select.poll()
    poller.register(
        record.witness_read_fd,
        select.POLLIN | select.POLLHUP | select.POLLERR,
    )
    while not deadline.expired():
        state = _witness_state(record)
        if state == "eof":
            try:
                if _child_waitable(record):
                    return _failure(
                        LaunchDisposition.PROCESS_LOST,
                        LaunchReason.CHILD_EXITED,
                        phase=record.phase,
                        receipt_state=_receipt_state(record),
                        trace=record.trace,
                    )
                return _capture_process_identity(
                    record.child_pid,
                    parent_pid=record.parent_pid,
                )
            except (OSError, UnicodeError, ValueError):
                return _failure(
                    LaunchDisposition.BINDING_FAILED,
                    LaunchReason.PROCESS_SCOPE_CHANGED,
                    phase=record.phase,
                    receipt_state=_receipt_state(record),
                    trace=record.trace,
                )
        if state != "open":
            return _failure(
                LaunchDisposition.PROCESS_LOST,
                LaunchReason.SAME_IMAGE_REEXEC_OR_WITNESS_LOSS,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                trace=record.trace,
            )
        try:
            poller.poll(_poll_timeout(deadline))
        except InterruptedError:
            continue
    return _failure(
        LaunchDisposition.TIMED_OUT,
        LaunchReason.DEADLINE_EXCEEDED,
        phase=record.phase,
        receipt_state=_receipt_state(record),
        trace=record.trace,
    )


def _perform_image_change(
    record: _HandleRecord,
    *,
    different: bool,
    deadline: MonotonicDeadline,
) -> LaunchFailure:
    command = _FrameType.REEXEC_DIFFERENT if different else _FrameType.REEXEC_SAME
    if not _send_frame(record, command):
        return _failure(
            LaunchDisposition.PROCESS_LOST,
            LaunchReason.READY_EOF,
            phase=record.phase,
            receipt_state=_receipt_state(record),
            trace=record.trace,
        )
    observed = _wait_for_witness_eof(record, deadline)
    if isinstance(observed, LaunchFailure):
        return observed
    primary = _process_matches_primary(observed, record.capability)
    if different and primary:
        return _failure(
            LaunchDisposition.BINDING_FAILED,
            LaunchReason.PROCESS_SCOPE_CHANGED,
            phase=record.phase,
            receipt_state=_receipt_state(record),
            trace=record.trace,
        )
    if not different and not primary:
        return _failure(
            LaunchDisposition.BINDING_FAILED,
            LaunchReason.PROCESS_SCOPE_CHANGED,
            phase=record.phase,
            receipt_state=_receipt_state(record),
            trace=record.trace,
        )
    record.process_identity = observed
    return _failure(
        LaunchDisposition.RECEIPT_REJECTED,
        LaunchReason.DIFFERENT_IMAGE_REEXEC
        if different
        else LaunchReason.SAME_IMAGE_REEXEC_OR_WITNESS_LOSS,
        phase=record.phase,
        receipt_state=_receipt_state(record),
        trace=record.trace,
    )


def _finalize_owned_runtime_fake(
    handle: object,
    *,
    deadline: MonotonicDeadline,
    cancellation: LaunchCancellation,
) -> OwnedFakeVerified | LaunchFailure:
    if (
        type(deadline) is not MonotonicDeadline
        or type(cancellation) is not LaunchCancellation
    ):
        return _failure(
            LaunchDisposition.INVALID_REQUEST,
            LaunchReason.INVALID_CAPABILITY,
            phase=LaunchPhase.NEW,
        )
    claimed = _claim_operation(handle, "finalize")
    if isinstance(claimed, LaunchFailure):
        return claimed
    record, owns_operation = claimed
    if not owns_operation:
        if record.verified_result is not None:
            return record.verified_result
        assert record.failure_result is not None
        return record.failure_result
    try:
        ready_failure = _wait_for_ready(
            record,
            deadline=deadline,
            cancellation=cancellation,
        )
        if ready_failure is not None:
            return _settle_failure(record, ready_failure, deadline=deadline)
        _set_phase(record, LaunchPhase.READY_OBSERVED)
        if record.capability.reexec_mode in {
            _ReexecMode.SAME_BEFORE_CAS,
            _ReexecMode.DIFFERENT_BEFORE_CAS,
        }:
            failure = _perform_image_change(
                record,
                different=(
                    record.capability.reexec_mode is _ReexecMode.DIFFERENT_BEFORE_CAS
                ),
                deadline=deadline,
            )
            return _settle_failure(record, failure, deadline=deadline)
        first = _recollect(record, deadline)
        if isinstance(first, CollectionFailure):
            failure = _failure(
                LaunchDisposition.COLLECTION_FAILED,
                LaunchReason.STABLE_COLLECTION_FAILED,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                diagnostics={"stage": "e1"},
                trace=record.trace,
            )
            return _settle_failure(
                record,
                failure,
                deadline=deadline,
                collection_failure=first,
            )
        if isinstance(first, LaunchFailure):
            return _settle_failure(record, first, deadline=deadline)
        _set_phase(record, LaunchPhase.POST_EXEC_STABLE_RECOLLECTED)
        process = _process_collection(record, first, deadline)
        if isinstance(process, CollectionFailure):
            failure = _failure(
                LaunchDisposition.COLLECTION_FAILED,
                LaunchReason.PROCESS_COLLECTION_FAILED,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                diagnostics={"stage": "procfs"},
                trace=record.trace,
            )
            return _settle_failure(
                record,
                failure,
                deadline=deadline,
                collection_failure=process,
            )
        _set_phase(record, LaunchPhase.PROCESS_EVIDENCE_COLLECTED)
        second = _recollect(record, deadline)
        if isinstance(second, CollectionFailure):
            failure = _failure(
                LaunchDisposition.COLLECTION_FAILED,
                LaunchReason.STABLE_COLLECTION_FAILED,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                diagnostics={"stage": "e2"},
                trace=record.trace,
            )
            return _settle_failure(
                record,
                failure,
                deadline=deadline,
                collection_failure=second,
            )
        if isinstance(second, LaunchFailure):
            return _settle_failure(record, second, deadline=deadline)
        if _witness_state(record) != "open":
            failure = _failure(
                LaunchDisposition.RECEIPT_REJECTED,
                LaunchReason.SAME_IMAGE_REEXEC_OR_WITNESS_LOSS,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                trace=record.trace,
            )
            return _settle_failure(record, failure, deadline=deadline)
        try:
            observed = _capture_process_identity(
                record.child_pid,
                parent_pid=record.parent_pid,
            )
        except (OSError, UnicodeError, ValueError):
            observed = None
        if observed is None or not _identity_matches(
            observed,
            record.process_identity,
        ):
            failure = _failure(
                LaunchDisposition.BINDING_FAILED,
                LaunchReason.PROCESS_SCOPE_CHANGED,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                trace=record.trace,
            )
            return _settle_failure(record, failure, deadline=deadline)
        if record.pending is None:
            failure = _failure(
                LaunchDisposition.STATE_CONFLICT,
                LaunchReason.FINAL_CAS_CONFLICT,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                trace=record.trace,
            )
            return _settle_failure(record, failure, deadline=deadline)
        verified = build_verified_receipt(
            record.pending,
            process_evidence=process,
            observed_at_utc=_utc_timestamp(),
            profiles=ProfileStore((record.capability.profile,)),
            session_token=record.token,
            now=datetime.now(timezone.utc),
        )
        if isinstance(verified, PlumbingFailure):
            failure = _failure(
                LaunchDisposition.RECEIPT_REJECTED,
                LaunchReason.STATIC_VERIFICATION_FAILED,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                diagnostics={"stage": "static_verify"},
                trace=record.trace,
            )
            return _settle_failure(record, failure, deadline=deadline)
        _set_phase(record, LaunchPhase.STATIC_VERIFIED)
        if not _registry_matches(record.capability):
            failure = _failure(
                LaunchDisposition.BINDING_FAILED,
                LaunchReason.REGISTRY_ROOT_MISMATCH,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                trace=record.trace,
            )
            return _settle_failure(record, failure, deadline=deadline)
        swapped = _cas_receipt(record, verified)
        if isinstance(swapped, LaunchFailure):
            return _settle_failure(record, swapped, deadline=deadline)
        if isinstance(swapped, PlumbingFailure):
            reason = _plumbing_failure_reason(
                swapped,
                LaunchReason.FINAL_CAS_CONFLICT,
            )
            failure = _failure(
                LaunchDisposition.STATE_CONFLICT,
                reason,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                diagnostics={"stage": "verified_cas"},
                trace=record.trace,
            )
            return _settle_failure(record, failure, deadline=deadline)
        record.current_receipt = verified
        record.reference_names.add(verified.reference.sidecar_name)
        record.reference_names.add(verified.reference.sidecar_temporary_name)
        _set_phase(record, LaunchPhase.VERIFIED_COMMITTED)
        if record.capability.reexec_mode in {
            _ReexecMode.SAME_AFTER_CAS,
            _ReexecMode.DIFFERENT_AFTER_CAS,
        }:
            failure = _perform_image_change(
                record,
                different=(
                    record.capability.reexec_mode is _ReexecMode.DIFFERENT_AFTER_CAS
                ),
                deadline=deadline,
            )
            return _settle_failure(record, failure, deadline=deadline)
        if _witness_state(record) != "open":
            failure = _failure(
                LaunchDisposition.RECEIPT_REJECTED,
                LaunchReason.SAME_IMAGE_REEXEC_OR_WITNESS_LOSS,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                trace=record.trace,
            )
            return _settle_failure(record, failure, deadline=deadline)
        try:
            observed = _capture_process_identity(
                record.child_pid,
                parent_pid=record.parent_pid,
            )
        except (OSError, UnicodeError, ValueError):
            observed = None
        if observed is None or not _identity_matches(
            observed,
            record.process_identity,
        ):
            failure = _failure(
                LaunchDisposition.BINDING_FAILED,
                LaunchReason.PROCESS_SCOPE_CHANGED,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                trace=record.trace,
            )
            return _settle_failure(record, failure, deadline=deadline)
        _set_phase(record, LaunchPhase.SUPERVISED)
        result = _new_verified(record)
        record.verified_result = result
        return result
    except BaseException:
        _settle_failure(
            record,
            _failure(
                LaunchDisposition.CLEANUP_FAILED,
                LaunchReason.PROCESS_SCOPE_CHANGED,
                phase=record.phase,
                receipt_state=_receipt_state(record),
                diagnostics={"stage": "unexpected_exception"},
                trace=record.trace,
            ),
            deadline=deadline,
        )
        raise
    finally:
        _release_operation(record)


def _close_owned_runtime_fake(
    handle: object,
    *,
    deadline: MonotonicDeadline,
) -> LaunchClosed | LaunchFailure:
    if type(deadline) is not MonotonicDeadline:
        return _failure(
            LaunchDisposition.INVALID_REQUEST,
            LaunchReason.INVALID_CAPABILITY,
            phase=LaunchPhase.NEW,
        )
    claimed = _claim_operation(handle, "close")
    if isinstance(claimed, LaunchFailure):
        return claimed
    record, owns_operation = claimed
    if not owns_operation:
        assert record.close_result is not None
        return record.close_result
    try:
        receipt_removed = record.current_receipt is None
        if record.current_receipt is not None:
            removed = _revoke_current(record)
            if removed is not None:
                teardown_reasons = _teardown_process(record, deadline)
                return _record_failure(
                    record,
                    _failure(
                        LaunchDisposition.CLEANUP_FAILED,
                        removed.reason_codes[0],
                        phase=record.phase,
                        receipt_state=_receipt_state(record),
                        diagnostics=removed.diagnostics,
                        trace=record.trace,
                        additional_reasons=(
                            *removed.reason_codes[1:],
                            *teardown_reasons,
                        ),
                    ),
                )
            receipt_removed = True
        teardown_reasons = _teardown_process(record, deadline)
        if teardown_reasons:
            return _record_failure(
                record,
                _failure(
                    LaunchDisposition.CLEANUP_FAILED,
                    teardown_reasons[0],
                    phase=record.phase,
                    receipt_state=_receipt_state(record),
                    trace=record.trace,
                    additional_reasons=teardown_reasons[1:],
                ),
            )
        if not _bundle_cleanup(record):
            return _record_failure(
                record,
                _failure(
                    LaunchDisposition.CLEANUP_FAILED,
                    LaunchReason.BUNDLE_CLEANUP_FAILED,
                    phase=record.phase,
                    receipt_state=_receipt_state(record),
                    trace=record.trace,
                ),
            )
        result = _new_closed(record, receipt_removed=receipt_removed)
        record.close_result = result
        return result
    finally:
        _release_operation(record)


@contextlib.contextmanager
def _owned_runtime_fake_session_binding(
    handle: object,
) -> Iterator[None]:
    """Bind only the handle's test registry and opaque session credential."""

    from core.project.sessions import (
        ENV_SESSION_PID,
        ENV_SESSION_TOKEN,
    )

    record = _record_for_handle(handle)
    if isinstance(record, LaunchFailure):
        raise ValueError("invalid owned fake launch handle")
    if not _registry_matches(record.capability):
        raise ValueError("owned fake registry root mismatch")
    previous_pid = os.environ.get(ENV_SESSION_PID)
    previous_token = os.environ.get(ENV_SESSION_TOKEN)
    os.environ[ENV_SESSION_PID] = str(record.child_pid)
    os.environ[ENV_SESSION_TOKEN] = record.token_hex
    try:
        yield
    finally:
        if previous_pid is None:
            os.environ.pop(ENV_SESSION_PID, None)
        else:
            os.environ[ENV_SESSION_PID] = previous_pid
        if previous_token is None:
            os.environ.pop(ENV_SESSION_TOKEN, None)
        else:
            os.environ[ENV_SESSION_TOKEN] = previous_token


def _owned_runtime_fake_profile_store(handle: object) -> ProfileStore:
    record = _record_for_handle(handle)
    if isinstance(record, LaunchFailure):
        raise ValueError("invalid owned fake launch handle")
    return ProfileStore((record.capability.profile,))


def _owned_runtime_fake_parent_channels(handle: object) -> frozenset[str]:
    record = _record_for_handle(handle)
    if isinstance(record, LaunchFailure):
        raise ValueError("invalid owned fake launch handle")
    channels = set()
    if record.control.fileno() >= 0:
        channels.add("control")
    if record.liveness_write_fd >= 0:
        channels.add("liveness")
    if record.witness_read_fd >= 0:
        channels.add("witness")
    return frozenset(channels)


def _owned_runtime_fake_registry_artifacts(handle: object) -> frozenset[str]:
    record = _record_for_handle(handle)
    if isinstance(record, LaunchFailure):
        raise ValueError("invalid owned fake launch handle")
    return frozenset(_registry_artifact_names(record))


__all__: tuple[str, ...] = ()
