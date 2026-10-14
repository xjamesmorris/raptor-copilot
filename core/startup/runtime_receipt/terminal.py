"""Private terminal channel for the verified owned runtime-receipt fake.

The capability and its sockets exist only in the issuing process.  This
module does not import run metadata or invoke lifecycle effects.
"""

from __future__ import annotations

import array
import contextlib
import errno
import fcntl
import hashlib
import hmac
import os
import select
import secrets
import socket
import stat
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Literal, Mapping, NoReturn, Sequence

from core.json.utils import dumps_canonical

from .collector_types import MonotonicDeadline
from .issuance import VerifiedReceiptIssued
from .launch import (
    LaunchCancellation,
    LaunchFailure,
    LaunchPhase,
    LaunchReason,
    OwnedFakeLaunchHandle,
    _FrameType,
    _HandleRecord,
    _ProcessIdentity,
    _capture_process_identity,
    _child_waitable,
    _claim_operation,
    _control_channel_state,
    _frame_bytes,
    _identity_matches,
    _process_matches_primary,
    _receive_frame,
    _record_for_handle,
    _registry_matches,
    _release_operation,
    _witness_state,
)
from .plumbing_types import ReceiptState, serialize_reference, serialize_snapshot

_TERMINAL_MAGIC = 0x5254544D
_TERMINAL_VERSION = 1
_TERMINAL_FRAME = struct.Struct("<IHHIII16s")
_TERMINAL_MAX_WORK_COUNT = 64
_TERMINAL_CAPABILITY_ID_BYTES = 16
_TERMINAL_NONCE_BYTES = 16
_LINUX_SO_COOKIE = 57
_UCRED = struct.Struct("=iii")
_INT = struct.Struct("=i")
_ANCILLARY_BYTES = socket.CMSG_SPACE(_UCRED.size) + socket.CMSG_SPACE(_INT.size * 2)
_POLL_QUANTUM_SECONDS = 0.05
_SOCKET_EOF_ERRNOS = frozenset(
    {
        errno.ECONNABORTED,
        errno.ECONNRESET,
        errno.ENOTCONN,
        errno.EPIPE,
        errno.ESHUTDOWN,
    }
)


class TerminalDisposition(str, Enum):
    INVALID_REQUEST = "invalid_request"
    BINDING_FAILED = "binding_failed"
    PROTOCOL_FAILED = "protocol_failed"
    TIMED_OUT = "timed_out"
    WAIT_CANCELLED = "wait_cancelled"
    STATE_CONFLICT = "state_conflict"


class TerminalReason(str, Enum):
    INVALID_CAPABILITY = "invalid_capability"
    CAPABILITY_REUSED = "capability_reused"
    ISSUER_PROCESS_CHANGED = "issuer_process_changed"
    LAUNCH_NOT_SUPERVISED = "launch_not_supervised"
    LAUNCH_OPERATION_BUSY = "launch_operation_busy"
    PROCESS_BINDING_CHANGED = "process_binding_changed"
    CHILD_EXITED = "child_exited"
    SUPERVISOR_LOST = "supervisor_lost"
    REGISTRY_ROOT_MISMATCH = "registry_root_mismatch"
    RECEIPT_NOT_VERIFIED = "receipt_not_verified"
    RECEIPT_CHANGED = "receipt_changed"
    TERMINAL_ATTACH_FAILED = "terminal_attach_failed"
    TERMINAL_EVENT_MALFORMED = "terminal_event_malformed"
    TERMINAL_EVENT_WRONG_CREDENTIALS = "terminal_event_wrong_credentials"
    TERMINAL_EVENT_WRONG_NONCE = "terminal_event_wrong_nonce"
    TERMINAL_EVENT_WRONG_KIND = "terminal_event_wrong_kind"
    TERMINAL_EVENT_OUT_OF_ORDER = "terminal_event_out_of_order"
    TERMINAL_EVENT_CONFLICT = "terminal_event_conflict"
    PENDING_WORK = "pending_work"
    TERMINAL_EVENT_EOF = "terminal_event_eof"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    WAIT_CANCELLED = "wait_cancelled"


class TerminalPhase(str, Enum):
    NEW = "new"
    ISSUED = "issued"
    CLAIMED = "claimed"
    ATTACHED = "attached"
    ARMED = "armed"
    STARTED = "started"
    WORK_STARTED = "work_started"
    WORK_DRAINED = "work_drained"
    READY = "ready"
    ACKED = "acked"
    REFUSED = "refused"


class _TerminalFrameType(int, Enum):
    ARM = 1
    ARMED = 2
    START = 3
    WORK_STARTED = 4
    TERMINAL_REQUESTED = 5
    RELEASE_WORK = 6
    WORK_DRAINED = 7
    TERMINAL_READY = 8
    ACK = 9
    ACKED = 10


class _TerminalEvent(int, Enum):
    COMPLETE = 1
    FAIL = 2
    INTERRUPT = 3
    CANCEL = 4


class _TerminalSequence(int, Enum):
    IMMEDIATE = 1
    BACKGROUND_DRAIN = 2
    EXACT_DUPLICATE = 3
    CONFLICTING_DUPLICATE = 4
    OUT_OF_ORDER = 5
    FOREIGN_NONCE = 6
    WRONG_KIND = 7
    MALFORMED = 8
    TIMEOUT = 9
    CHILD_EXIT_BEFORE_EVENT = 10
    CONTROL_EOF = 11
    EXIT_AFTER_ACK = 12


class _ClaimState(str, Enum):
    ISSUED = "issued"
    CLAIMED = "claimed"
    APPLIED = "applied"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class _SocketIdentity:
    device: int
    inode: int
    uid: int
    family: int
    socket_type: int
    cookie: int
    passcred: int


@dataclass(frozen=True, slots=True, init=False, repr=False)
class OwnedFakeTerminalCapability:
    _capability_id: str = field(repr=False)
    _capability_mac: str = field(repr=False)

    def __init__(self) -> None:
        raise TypeError("OwnedFakeTerminalCapability cannot be constructed")

    def __repr__(self) -> str:
        return "OwnedFakeTerminalCapability(<redacted>)"

    def __bool__(self) -> bool:
        raise TypeError("owned fake terminal capabilities are not truth values")

    def __copy__(self) -> NoReturn:
        raise TypeError("OwnedFakeTerminalCapability cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        del memo
        raise TypeError("OwnedFakeTerminalCapability cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("OwnedFakeTerminalCapability cannot be pickled")

    def __init_subclass__(cls) -> None:
        raise TypeError("OwnedFakeTerminalCapability cannot be subclassed")


@dataclass(frozen=True, slots=True, init=False, repr=False)
class OwnedFakeTerminalResult:
    state: Literal["acked"]
    event_kind: str
    sequence_mode: str
    work_count: int
    duplicate_count: int
    event_digest_sha256: str
    trace: tuple[str, ...]
    authoritative: Literal[False] = field(default=False, init=False)

    def __repr__(self) -> str:
        return (
            "OwnedFakeTerminalResult("
            f"state={self.state!r}, event_kind={self.event_kind!r}, "
            f"sequence_mode={self.sequence_mode!r}, authoritative=False)"
        )

    def __bool__(self) -> bool:
        raise TypeError("owned fake terminal results are not truth values")

    def __reduce__(self) -> NoReturn:
        raise TypeError("OwnedFakeTerminalResult cannot be pickled")

    def __init_subclass__(cls) -> None:
        raise TypeError("OwnedFakeTerminalResult cannot be subclassed")


@dataclass(frozen=True, slots=True, init=False, repr=False)
class OwnedFakeTerminalFailure:
    disposition: TerminalDisposition
    reason_codes: tuple[TerminalReason, ...]
    phase: TerminalPhase
    diagnostics: Mapping[str, str]
    trace: tuple[str, ...]
    authoritative: Literal[False] = field(default=False, init=False)

    def __repr__(self) -> str:
        reasons = tuple(reason.value for reason in self.reason_codes)
        return (
            "OwnedFakeTerminalFailure("
            f"disposition={self.disposition.value!r}, "
            f"reason_codes={reasons!r}, phase={self.phase.value!r}, "
            "authoritative=False)"
        )

    def __bool__(self) -> bool:
        raise TypeError("owned fake terminal failures are not truth values")

    def __reduce__(self) -> NoReturn:
        raise TypeError("OwnedFakeTerminalFailure cannot be pickled")

    def __init_subclass__(cls) -> None:
        raise TypeError("OwnedFakeTerminalFailure cannot be subclassed")


@dataclass(slots=True)
class _TerminalRecord:
    capability_id: str
    capability_mac: str
    capability_object: OwnedFakeTerminalCapability | None
    issuer_pid: int
    module_generation: str
    handle: OwnedFakeLaunchHandle
    handle_id: str
    handle_mac: str
    launch_record_id: int
    launch_capability_id: str
    launch_factory_nonce: str
    launch_bundle_sha256: str
    verified_result_id: int
    process_identity: _ProcessIdentity
    registry_identity: tuple[int, int, int, int]
    control_identity: _SocketIdentity
    receipt_reference_sha256: str
    receipt_snapshot_sha256: str
    event: _TerminalEvent
    sequence: _TerminalSequence
    work_count: int
    event_nonce: bytes
    parent_socket: socket.socket | None
    child_socket: socket.socket | None
    parent_socket_identity: _SocketIdentity
    child_socket_identity: _SocketIdentity
    binding_bytes: bytes
    state: _ClaimState = _ClaimState.ISSUED
    phase: TerminalPhase = TerminalPhase.ISSUED
    trace: list[str] = field(default_factory=lambda: [TerminalPhase.ISSUED.value])
    cached: OwnedFakeTerminalResult | OwnedFakeTerminalFailure | None = None


class _PacketError(Exception):
    def __init__(self, reason: TerminalReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


_ISSUER_KEY = secrets.token_bytes(32)
_MODULE_GENERATION = secrets.token_hex(16)
_STATE_LOCK = threading.RLock()
_CAPABILITIES: dict[str, _TerminalRecord] = {}
_HANDLE_CAPABILITIES: dict[str, str] = {}


def _bounded_diagnostics(values: Mapping[str, object] | None) -> Mapping[str, str]:
    bounded: dict[str, str] = {}
    for key, value in (values or {}).items():
        if len(bounded) >= 8:
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
            and len(text_value) <= 128
            and len(text_value) not in {32, 64}
            and "/" not in text_value
        ):
            bounded[text_key] = text_value
    return MappingProxyType(bounded)


def _failure(
    disposition: TerminalDisposition,
    reason: TerminalReason,
    *,
    phase: TerminalPhase,
    diagnostics: Mapping[str, object] | None = None,
    trace: Sequence[str] = (),
) -> OwnedFakeTerminalFailure:
    value = object.__new__(OwnedFakeTerminalFailure)
    object.__setattr__(value, "disposition", disposition)
    object.__setattr__(value, "reason_codes", (reason,))
    object.__setattr__(value, "phase", phase)
    object.__setattr__(value, "diagnostics", _bounded_diagnostics(diagnostics))
    object.__setattr__(value, "trace", tuple(trace))
    object.__setattr__(value, "authoritative", False)
    return value


def _new_capability(
    capability_id: str,
    capability_mac: str,
) -> OwnedFakeTerminalCapability:
    value = object.__new__(OwnedFakeTerminalCapability)
    object.__setattr__(value, "_capability_id", capability_id)
    object.__setattr__(value, "_capability_mac", capability_mac)
    return value


def _new_result(
    record: _TerminalRecord,
    *,
    duplicate_count: int,
    ready_frame: bytes,
) -> OwnedFakeTerminalResult:
    value = object.__new__(OwnedFakeTerminalResult)
    object.__setattr__(value, "state", "acked")
    object.__setattr__(value, "event_kind", record.event.name.lower())
    object.__setattr__(value, "sequence_mode", record.sequence.name.lower())
    object.__setattr__(value, "work_count", record.work_count)
    object.__setattr__(value, "duplicate_count", duplicate_count)
    object.__setattr__(
        value,
        "event_digest_sha256",
        hashlib.sha256(ready_frame).hexdigest(),
    )
    object.__setattr__(value, "trace", tuple(record.trace))
    object.__setattr__(value, "authoritative", False)
    return value


def _socket_identity(
    channel: socket.socket, *, require_passcred: bool
) -> _SocketIdentity:
    value = os.fstat(channel.fileno())
    if not stat.S_ISSOCK(value.st_mode) or value.st_uid != os.geteuid():
        raise ValueError("terminal endpoint identity is invalid")
    socket_type = channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
    if socket_type != socket.SOCK_SEQPACKET:
        raise ValueError("terminal endpoint is not sequenced-packet")
    raw_cookie = channel.getsockopt(socket.SOL_SOCKET, _LINUX_SO_COOKIE, 8)
    if not isinstance(raw_cookie, bytes) or len(raw_cookie) != 8:
        raise ValueError("terminal endpoint cookie is unavailable")
    passcred = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED)
    if require_passcred and passcred != 1:
        raise ValueError("terminal endpoint credentials are disabled")
    return _SocketIdentity(
        device=value.st_dev,
        inode=value.st_ino,
        uid=value.st_uid,
        family=channel.family,
        socket_type=socket_type,
        cookie=struct.unpack("=Q", raw_cookie)[0],
        passcred=passcred,
    )


def _socket_identity_value(identity: _SocketIdentity) -> dict[str, int]:
    return {
        "device": identity.device,
        "inode": identity.inode,
        "uid": identity.uid,
        "family": identity.family,
        "socket_type": identity.socket_type,
        "cookie": identity.cookie,
        "passcred": identity.passcred,
    }


def _registry_identity(record: _HandleRecord) -> tuple[int, int, int, int]:
    value = record.capability.registry_root.stat()
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != os.geteuid()
        or stat.S_IMODE(value.st_mode) & 0o022
    ):
        raise ValueError("owned fake registry identity is invalid")
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        stat.S_IMODE(value.st_mode),
    )


def _receipt_digests(record: _HandleRecord) -> tuple[str, str]:
    current = record.current_receipt
    if not isinstance(current, VerifiedReceiptIssued):
        raise ValueError("owned fake receipt is not verified")
    if current.reference.state is not ReceiptState.VERIFIED:
        raise ValueError("owned fake receipt reference is not verified")
    return (
        hashlib.sha256(serialize_reference(current.reference)).hexdigest(),
        hashlib.sha256(serialize_snapshot(current.snapshot)).hexdigest(),
    )


def _binding_bytes(
    record: _HandleRecord,
    *,
    handle: OwnedFakeLaunchHandle,
    event: _TerminalEvent,
    sequence: _TerminalSequence,
    work_count: int,
    event_nonce: bytes,
    parent_socket_identity: _SocketIdentity,
    child_socket_identity: _SocketIdentity,
) -> bytes:
    current = record.current_receipt
    if not isinstance(current, VerifiedReceiptIssued):
        raise ValueError("owned fake receipt is not verified")
    reference = current.reference
    identity = record.process_identity
    reference_digest, snapshot_digest = _receipt_digests(record)
    control_identity = _socket_identity(record.control, require_passcred=False)
    registry_identity = _registry_identity(record)
    value = {
        "schema": "raptor.owned_fake_terminal_capability/v1",
        "issuer": {
            "pid": os.getpid(),
            "generation": _MODULE_GENERATION,
        },
        "launch": {
            "handle_id": handle._handle_id,
            "handle_mac": handle._handle_mac,
            "handle_record_id": id(record),
            "capability_id": record.capability.capability_id,
            "factory_nonce": record.capability.factory_nonce,
            "bundle_sha256": record.capability.proof_sha256,
            "verified_result_id": id(record.verified_result),
            "phase": record.phase.value,
        },
        "process": {
            "identity": {
                "pid": identity.pid,
                "parent_pid": identity.parent_pid,
                "process_group": identity.process_group,
                "starttime_ticks": identity.starttime_ticks,
                "boot_id": identity.boot_id,
                "pid_namespace_inode": identity.pid_namespace_inode,
                "mount_namespace_inode": identity.mount_namespace_inode,
                "euid": identity.euid,
            },
            "executable": {
                "device": identity.executable_device,
                "inode": identity.executable_inode,
                "size": identity.executable_size,
                "sha256": identity.executable_sha256,
            },
            "witness": "open",
        },
        "receipt": {
            "identity": {
                "state": reference.state.value,
                "session_id": reference.session_id.value,
                "launch_id": reference.launch_id.value,
                "session_pid": reference.session_pid.text,
                "session_starttime_ticks": reference.session_starttime_ticks.text,
                "boot_id": reference.boot_id.value,
                "pid_namespace_inode": reference.pid_namespace_inode.text,
                "launcher_euid": reference.launcher_euid.text,
                "profile_id": reference.profile_id.value,
            },
            "generation": {
                "launch_nonce": reference.launch_nonce.value,
                "attempt": reference.attempt,
                "stable_identity_sha256": reference.stable_identity_sha256.value,
                "launch_instance_sha256": reference.launch_instance_sha256.value,
                "launch_binding_sha256": reference.launch_binding_sha256.value,
            },
            "digests": {
                "process_corroboration_sha256": (
                    reference.process_corroboration_sha256.value
                ),
                "receipt_sha256": reference.receipt_sha256.value,
                "reference_sha256": reference_digest,
                "snapshot_sha256": snapshot_digest,
                "sidecar_name": reference.sidecar_name,
            },
        },
        "registry": {
            "device": registry_identity[0],
            "inode": registry_identity[1],
            "uid": registry_identity[2],
            "mode": registry_identity[3],
        },
        "sockets": {
            "control": _socket_identity_value(control_identity),
            "terminal_parent": _socket_identity_value(parent_socket_identity),
            "terminal_child": _socket_identity_value(child_socket_identity),
        },
        "event": {
            "kind": event.value,
            "sequence_mode": sequence.value,
            "work_count": work_count,
            "nonce": event_nonce.hex(),
        },
    }
    return dumps_canonical(value).encode("utf-8")


def _capability_mac(capability_id: str, binding: bytes) -> str:
    payload = capability_id.encode("ascii") + b"\0" + binding
    return hmac.new(_ISSUER_KEY, payload, hashlib.sha256).hexdigest()


def _close_sockets(record: _TerminalRecord) -> bool:
    ok = True
    for name in ("child_socket", "parent_socket"):
        channel = getattr(record, name)
        if channel is None:
            continue
        try:
            channel.close()
        except OSError:
            ok = False
        setattr(record, name, None)
    return ok


def _after_fork_child() -> None:
    global _CAPABILITIES
    global _HANDLE_CAPABILITIES
    global _ISSUER_KEY
    global _MODULE_GENERATION
    global _STATE_LOCK

    records = tuple(_CAPABILITIES.values())
    _CAPABILITIES = {}
    _HANDLE_CAPABILITIES = {}
    _ISSUER_KEY = secrets.token_bytes(32)
    _MODULE_GENERATION = secrets.token_hex(16)
    _STATE_LOCK = threading.RLock()
    for record in records:
        _close_sockets(record)


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_child)


def _launch_failure_reason(failure: LaunchFailure) -> TerminalReason:
    if failure.reason_codes == (LaunchReason.INVALID_CAPABILITY,):
        return TerminalReason.INVALID_CAPABILITY
    if failure.diagnostics.get("stage") == "operation_in_progress":
        return TerminalReason.LAUNCH_OPERATION_BUSY
    return TerminalReason.LAUNCH_NOT_SUPERVISED


def _issue_owned_fake_terminal_capability(
    handle: object,
    *,
    event_code: int,
    sequence_code: int,
    work_count: int,
) -> OwnedFakeTerminalCapability | OwnedFakeTerminalFailure:
    if (
        type(event_code) is not int
        or type(sequence_code) is not int
        or type(work_count) is not int
    ):
        return _failure(
            TerminalDisposition.INVALID_REQUEST,
            TerminalReason.INVALID_CAPABILITY,
            phase=TerminalPhase.NEW,
        )
    try:
        event = _TerminalEvent(event_code)
        sequence = _TerminalSequence(sequence_code)
    except ValueError:
        return _failure(
            TerminalDisposition.INVALID_REQUEST,
            TerminalReason.INVALID_CAPABILITY,
            phase=TerminalPhase.NEW,
        )
    if (
        not 0 <= work_count <= _TERMINAL_MAX_WORK_COUNT
        or (sequence is _TerminalSequence.BACKGROUND_DRAIN and work_count == 0)
        or (sequence is not _TerminalSequence.BACKGROUND_DRAIN and work_count != 0)
    ):
        return _failure(
            TerminalDisposition.INVALID_REQUEST,
            TerminalReason.INVALID_CAPABILITY,
            phase=TerminalPhase.NEW,
        )
    if (
        os.name != "posix"
        or not hasattr(socket, "SOCK_SEQPACKET")
        or not hasattr(socket, "SO_PASSCRED")
        or not hasattr(socket, "SCM_CREDENTIALS")
        or not hasattr(socket, "MSG_CMSG_CLOEXEC")
    ):
        return _failure(
            TerminalDisposition.INVALID_REQUEST,
            TerminalReason.TERMINAL_ATTACH_FAILED,
            phase=TerminalPhase.NEW,
        )

    launch_record: _HandleRecord | None = None
    parent_socket: socket.socket | None = None
    child_socket: socket.socket | None = None
    sockets_transferred = False
    with _STATE_LOCK:
        found = _record_for_handle(handle)
        if (
            isinstance(found, LaunchFailure)
            or type(handle) is not OwnedFakeLaunchHandle
        ):
            return _failure(
                TerminalDisposition.INVALID_REQUEST,
                TerminalReason.INVALID_CAPABILITY,
                phase=TerminalPhase.NEW,
            )
        if found.handle_id in _HANDLE_CAPABILITIES:
            return _failure(
                TerminalDisposition.STATE_CONFLICT,
                TerminalReason.CAPABILITY_REUSED,
                phase=TerminalPhase.NEW,
            )
        claimed = _claim_operation(handle, "terminal")
        if isinstance(claimed, LaunchFailure):
            return _failure(
                TerminalDisposition.STATE_CONFLICT,
                _launch_failure_reason(claimed),
                phase=TerminalPhase.NEW,
            )
        launch_record, owns_operation = claimed
        if not owns_operation:
            return _failure(
                TerminalDisposition.STATE_CONFLICT,
                TerminalReason.LAUNCH_OPERATION_BUSY,
                phase=TerminalPhase.NEW,
            )
        try:
            if (
                launch_record.close_result is not None
                or launch_record.failure_result is not None
                or launch_record.phase is not LaunchPhase.SUPERVISED
                or launch_record.verified_result is None
                or not isinstance(
                    launch_record.current_receipt,
                    VerifiedReceiptIssued,
                )
            ):
                return _failure(
                    TerminalDisposition.BINDING_FAILED,
                    TerminalReason.LAUNCH_NOT_SUPERVISED,
                    phase=TerminalPhase.NEW,
                )
            if not _registry_matches(launch_record.capability):
                return _failure(
                    TerminalDisposition.BINDING_FAILED,
                    TerminalReason.REGISTRY_ROOT_MISMATCH,
                    phase=TerminalPhase.NEW,
                )
            if _witness_state(launch_record) != "open":
                return _failure(
                    TerminalDisposition.BINDING_FAILED,
                    TerminalReason.PROCESS_BINDING_CHANGED,
                    phase=TerminalPhase.NEW,
                )
            observed = _capture_process_identity(
                launch_record.child_pid,
                parent_pid=launch_record.parent_pid,
            )
            if not _identity_matches(
                observed, launch_record.process_identity
            ) or not _process_matches_primary(observed, launch_record.capability):
                return _failure(
                    TerminalDisposition.BINDING_FAILED,
                    TerminalReason.PROCESS_BINDING_CHANGED,
                    phase=TerminalPhase.NEW,
                )
            socket_type = socket.SOCK_SEQPACKET | getattr(
                socket,
                "SOCK_CLOEXEC",
                0,
            )
            parent_socket, child_socket = socket.socketpair(
                socket.AF_UNIX,
                socket_type,
            )
            parent_socket.setblocking(False)
            child_socket.setblocking(False)
            parent_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            for created_channel in (parent_socket, child_socket):
                flags = fcntl.fcntl(created_channel.fileno(), fcntl.F_GETFD)
                if not flags & fcntl.FD_CLOEXEC:
                    raise ValueError("terminal endpoint is not close-on-exec")
            parent_identity = _socket_identity(
                parent_socket,
                require_passcred=True,
            )
            child_identity = _socket_identity(
                child_socket,
                require_passcred=False,
            )
            event_nonce = secrets.token_bytes(_TERMINAL_NONCE_BYTES)
            if event_nonce == bytes(_TERMINAL_NONCE_BYTES):
                raise ValueError("terminal nonce is invalid")
            binding = _binding_bytes(
                launch_record,
                handle=handle,
                event=event,
                sequence=sequence,
                work_count=work_count,
                event_nonce=event_nonce,
                parent_socket_identity=parent_identity,
                child_socket_identity=child_identity,
            )
            capability_id = secrets.token_hex(_TERMINAL_CAPABILITY_ID_BYTES)
            capability_mac = _capability_mac(capability_id, binding)
            reference_digest, snapshot_digest = _receipt_digests(launch_record)
            terminal_record = _TerminalRecord(
                capability_id=capability_id,
                capability_mac=capability_mac,
                capability_object=None,
                issuer_pid=os.getpid(),
                module_generation=_MODULE_GENERATION,
                handle=handle,
                handle_id=handle._handle_id,
                handle_mac=handle._handle_mac,
                launch_record_id=id(launch_record),
                launch_capability_id=launch_record.capability.capability_id,
                launch_factory_nonce=launch_record.capability.factory_nonce,
                launch_bundle_sha256=launch_record.capability.proof_sha256,
                verified_result_id=id(launch_record.verified_result),
                process_identity=launch_record.process_identity,
                registry_identity=_registry_identity(launch_record),
                control_identity=_socket_identity(
                    launch_record.control,
                    require_passcred=False,
                ),
                receipt_reference_sha256=reference_digest,
                receipt_snapshot_sha256=snapshot_digest,
                event=event,
                sequence=sequence,
                work_count=work_count,
                event_nonce=event_nonce,
                parent_socket=parent_socket,
                child_socket=child_socket,
                parent_socket_identity=parent_identity,
                child_socket_identity=child_identity,
                binding_bytes=binding,
            )
            capability = _new_capability(capability_id, capability_mac)
            terminal_record.capability_object = capability
            _CAPABILITIES[capability_id] = terminal_record
            _HANDLE_CAPABILITIES[launch_record.handle_id] = capability_id
            sockets_transferred = True
            return capability
        except (OSError, UnicodeError, ValueError):
            return _failure(
                TerminalDisposition.BINDING_FAILED,
                TerminalReason.TERMINAL_ATTACH_FAILED,
                phase=TerminalPhase.NEW,
            )
        finally:
            if not sockets_transferred:
                for pending_channel in (child_socket, parent_socket):
                    if pending_channel is not None:
                        with contextlib.suppress(OSError):
                            pending_channel.close()
            _release_operation(launch_record)


def _record_for_capability(
    capability: object,
) -> _TerminalRecord | OwnedFakeTerminalFailure:
    if type(capability) is not OwnedFakeTerminalCapability:
        return _failure(
            TerminalDisposition.INVALID_REQUEST,
            TerminalReason.INVALID_CAPABILITY,
            phase=TerminalPhase.NEW,
        )
    record = _CAPABILITIES.get(capability._capability_id)
    if (
        record is None
        or capability is not record.capability_object
        or record.issuer_pid != os.getpid()
        or record.module_generation != _MODULE_GENERATION
        or capability._capability_id != record.capability_id
        or not hmac.compare_digest(
            capability._capability_mac,
            record.capability_mac,
        )
        or not hmac.compare_digest(
            record.capability_mac,
            _capability_mac(record.capability_id, record.binding_bytes),
        )
    ):
        return _failure(
            TerminalDisposition.INVALID_REQUEST,
            TerminalReason.INVALID_CAPABILITY,
            phase=TerminalPhase.NEW,
        )
    return record


def _current_receipt_digests(record: _HandleRecord) -> tuple[str, str] | None:
    try:
        return _receipt_digests(record)
    except (TypeError, ValueError):
        return None


def _initial_binding_matches(
    record: _TerminalRecord,
    launch_record: _HandleRecord,
) -> bool:
    child_socket = record.child_socket
    parent_socket = record.parent_socket
    if child_socket is None or parent_socket is None:
        return False
    try:
        child_identity = _socket_identity(
            child_socket,
            require_passcred=False,
        )
        if child_identity != record.child_socket_identity:
            return False
        current = _binding_bytes(
            launch_record,
            handle=record.handle,
            event=record.event,
            sequence=record.sequence,
            work_count=record.work_count,
            event_nonce=record.event_nonce,
            parent_socket_identity=_socket_identity(
                parent_socket,
                require_passcred=True,
            ),
            child_socket_identity=child_identity,
        )
    except (OSError, UnicodeError, ValueError):
        return False
    return hmac.compare_digest(current, record.binding_bytes)


def _validate_live_binding(
    record: _TerminalRecord,
    launch_record: _HandleRecord,
) -> TerminalReason | None:
    if (
        record.issuer_pid != os.getpid()
        or record.module_generation != _MODULE_GENERATION
    ):
        return TerminalReason.ISSUER_PROCESS_CHANGED
    if (
        id(launch_record) != record.launch_record_id
        or launch_record.handle_id != record.handle_id
        or record.handle._handle_id != record.handle_id
        or record.handle._handle_mac != record.handle_mac
        or launch_record.capability.capability_id != record.launch_capability_id
        or launch_record.capability.factory_nonce != record.launch_factory_nonce
        or launch_record.capability.proof_sha256 != record.launch_bundle_sha256
    ):
        return TerminalReason.INVALID_CAPABILITY
    if (
        launch_record.close_result is not None
        or launch_record.failure_result is not None
        or launch_record.phase is not LaunchPhase.SUPERVISED
        or launch_record.verified_result is None
        or id(launch_record.verified_result) != record.verified_result_id
    ):
        return TerminalReason.LAUNCH_NOT_SUPERVISED
    if (
        not isinstance(launch_record.current_receipt, VerifiedReceiptIssued)
        or launch_record.current_receipt.reference.state is not ReceiptState.VERIFIED
    ):
        return TerminalReason.RECEIPT_NOT_VERIFIED
    if _current_receipt_digests(launch_record) != (
        record.receipt_reference_sha256,
        record.receipt_snapshot_sha256,
    ):
        return TerminalReason.RECEIPT_CHANGED
    if not _registry_matches(launch_record.capability):
        return TerminalReason.REGISTRY_ROOT_MISMATCH
    try:
        if _registry_identity(launch_record) != record.registry_identity:
            return TerminalReason.REGISTRY_ROOT_MISMATCH
        if (
            _socket_identity(
                launch_record.control,
                require_passcred=False,
            )
            != record.control_identity
        ):
            return TerminalReason.PROCESS_BINDING_CHANGED
        parent_socket = record.parent_socket
        if parent_socket is None:
            return TerminalReason.TERMINAL_ATTACH_FAILED
        parent_identity = _socket_identity(parent_socket, require_passcred=False)
        if (
            parent_identity.device,
            parent_identity.inode,
            parent_identity.uid,
            parent_identity.family,
            parent_identity.socket_type,
            parent_identity.cookie,
        ) != (
            record.parent_socket_identity.device,
            record.parent_socket_identity.inode,
            record.parent_socket_identity.uid,
            record.parent_socket_identity.family,
            record.parent_socket_identity.socket_type,
            record.parent_socket_identity.cookie,
        ):
            return TerminalReason.TERMINAL_ATTACH_FAILED
        if parent_identity.passcred != 1:
            return TerminalReason.TERMINAL_EVENT_WRONG_CREDENTIALS
        observed = _capture_process_identity(
            launch_record.child_pid,
            parent_pid=launch_record.parent_pid,
        )
    except (OSError, UnicodeError, ValueError):
        try:
            if _child_waitable(launch_record):
                return (
                    TerminalReason.TERMINAL_EVENT_EOF
                    if record.sequence is _TerminalSequence.CONTROL_EOF
                    else TerminalReason.CHILD_EXITED
                )
        except ValueError:
            return TerminalReason.SUPERVISOR_LOST
        return TerminalReason.PROCESS_BINDING_CHANGED
    if (
        not _identity_matches(observed, record.process_identity)
        or not _identity_matches(observed, launch_record.process_identity)
        or not _process_matches_primary(observed, launch_record.capability)
        or _witness_state(launch_record) != "open"
    ):
        return TerminalReason.PROCESS_BINDING_CHANGED
    return None


def _set_phase(record: _TerminalRecord, phase: TerminalPhase) -> None:
    record.phase = phase
    record.trace.append(phase.value)
    _terminal_phase_hook(phase, record.capability_id)


def _terminal_phase_hook(phase: TerminalPhase, capability_id: str) -> None:
    """Deterministic test seam after a terminal phase transition."""


def _terminal_frame_bytes(
    frame_type: _TerminalFrameType,
    *,
    event: _TerminalEvent,
    sequence: int,
    work_count: int,
    nonce: bytes,
) -> bytes:
    if (
        type(sequence) is not int
        or not 1 <= sequence <= 0xFFFFFFFF
        or type(work_count) is not int
        or not 0 <= work_count <= _TERMINAL_MAX_WORK_COUNT
        or type(nonce) is not bytes
        or len(nonce) != _TERMINAL_NONCE_BYTES
    ):
        raise ValueError("terminal frame field is invalid")
    return _TERMINAL_FRAME.pack(
        _TERMINAL_MAGIC,
        _TERMINAL_VERSION,
        frame_type.value,
        event.value,
        sequence,
        work_count,
        nonce,
    )


def _decode_terminal_frame(
    raw: bytes,
) -> tuple[_TerminalFrameType, _TerminalEvent, int, int, bytes]:
    if len(raw) != _TERMINAL_FRAME.size:
        raise _PacketError(TerminalReason.TERMINAL_EVENT_MALFORMED)
    magic, version, frame_type, event, sequence, work_count, nonce = (
        _TERMINAL_FRAME.unpack(raw)
    )
    if (
        magic != _TERMINAL_MAGIC
        or version != _TERMINAL_VERSION
        or not 1 <= sequence <= 0xFFFFFFFF
        or not 0 <= work_count <= _TERMINAL_MAX_WORK_COUNT
        or nonce == bytes(_TERMINAL_NONCE_BYTES)
    ):
        raise _PacketError(TerminalReason.TERMINAL_EVENT_MALFORMED)
    try:
        parsed_type = _TerminalFrameType(frame_type)
        parsed_event = _TerminalEvent(event)
    except ValueError as exc:
        raise _PacketError(TerminalReason.TERMINAL_EVENT_MALFORMED) from exc
    return parsed_type, parsed_event, sequence, work_count, nonce


def _close_received_rights(ancillary: Sequence[tuple[int, int, bytes]]) -> bool:
    ok = True
    for level, item_type, raw in ancillary:
        if level != socket.SOL_SOCKET or item_type != socket.SCM_RIGHTS:
            continue
        usable = len(raw) - (len(raw) % _INT.size)
        values = array.array("i")
        values.frombytes(raw[:usable])
        for fd in values:
            try:
                flags = fcntl.fcntl(fd, fcntl.F_GETFD)
                if not flags & fcntl.FD_CLOEXEC:
                    ok = False
            except OSError:
                ok = False
            finally:
                with contextlib.suppress(OSError):
                    os.close(fd)
    return ok


def _receive_terminal_packet(
    channel: socket.socket,
    *,
    expected_pid: int,
    expected_uid: int,
) -> bytes | None:
    while True:
        try:
            raw, ancillary, flags, _address = channel.recvmsg(
                _TERMINAL_FRAME.size + 1,
                _ANCILLARY_BYTES,
                socket.MSG_CMSG_CLOEXEC,
            )
            break
        except InterruptedError:
            continue
        except BlockingIOError:
            return None
        except OSError as exc:
            if exc.errno in _SOCKET_EOF_ERRNOS:
                raise _PacketError(TerminalReason.TERMINAL_EVENT_EOF) from exc
            raise
    rights_ok = _close_received_rights(ancillary)
    if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) or not rights_ok:
        raise _PacketError(TerminalReason.TERMINAL_EVENT_MALFORMED)
    if raw == b"":
        raise _PacketError(TerminalReason.TERMINAL_EVENT_EOF)
    if len(raw) != _TERMINAL_FRAME.size or len(ancillary) > 2:
        raise _PacketError(TerminalReason.TERMINAL_EVENT_MALFORMED)
    credentials: list[tuple[int, int, int]] = []
    for level, item_type, value in ancillary:
        if level == socket.SOL_SOCKET and item_type == socket.SCM_CREDENTIALS:
            if len(value) != _UCRED.size:
                raise _PacketError(TerminalReason.TERMINAL_EVENT_MALFORMED)
            credentials.append(_UCRED.unpack(value))
        elif level == socket.SOL_SOCKET and item_type == socket.SCM_RIGHTS:
            raise _PacketError(TerminalReason.TERMINAL_EVENT_MALFORMED)
        else:
            raise _PacketError(TerminalReason.TERMINAL_EVENT_MALFORMED)
    if len(credentials) != 1:
        raise _PacketError(TerminalReason.TERMINAL_EVENT_WRONG_CREDENTIALS)
    pid, uid, _gid = credentials[0]
    if pid != expected_pid or uid != expected_uid:
        raise _PacketError(TerminalReason.TERMINAL_EVENT_WRONG_CREDENTIALS)
    return raw


def _deadline_timeout(deadline: MonotonicDeadline) -> int:
    remaining = max(0.0, deadline.expires_at - time.monotonic())
    if remaining <= 0:
        return 0
    return max(1, int(min(remaining, _POLL_QUANTUM_SECONDS) * 1000))


def _cancelled(cancellation: LaunchCancellation) -> bool:
    poller = select.poll()
    poller.register(cancellation._read_fd, select.POLLIN | select.POLLHUP)
    return bool(poller.poll(0))


def _control_sendmsg(
    channel: socket.socket,
    raw: bytes,
    ancillary: list[tuple[int, int, array.array[int]]],
) -> int:
    return channel.sendmsg([raw], ancillary)


def _terminal_send(channel: socket.socket, raw: bytes) -> int:
    return channel.send(raw, getattr(socket, "MSG_NOSIGNAL", 0))


def _control_failure(
    launch_record: _HandleRecord,
    *,
    attach_phase: bool,
    sequence: _TerminalSequence,
) -> TerminalReason | None:
    state = _control_channel_state(launch_record)
    if state == "closed":
        if sequence is _TerminalSequence.CHILD_EXIT_BEFORE_EVENT:
            try:
                if _child_waitable(launch_record):
                    return TerminalReason.CHILD_EXITED
            except ValueError:
                return TerminalReason.SUPERVISOR_LOST
        return TerminalReason.TERMINAL_EVENT_EOF
    if state == "data":
        try:
            frame = _receive_frame(launch_record)
        except (EOFError, ValueError):
            return TerminalReason.TERMINAL_EVENT_EOF
        if frame is not None and frame[0] is _FrameType.PROTOCOL_ERROR:
            return (
                TerminalReason.TERMINAL_ATTACH_FAILED
                if attach_phase
                else TerminalReason.TERMINAL_EVENT_MALFORMED
            )
        return TerminalReason.TERMINAL_EVENT_OUT_OF_ORDER
    try:
        if _child_waitable(launch_record):
            if sequence is _TerminalSequence.CONTROL_EOF:
                return TerminalReason.TERMINAL_EVENT_EOF
            state = _control_channel_state(launch_record)
            if state == "closed":
                return (
                    TerminalReason.CHILD_EXITED
                    if sequence is _TerminalSequence.CHILD_EXIT_BEFORE_EVENT
                    else TerminalReason.TERMINAL_EVENT_EOF
                )
            return TerminalReason.CHILD_EXITED
    except ValueError:
        return TerminalReason.SUPERVISOR_LOST
    if _witness_state(launch_record) != "open":
        return TerminalReason.PROCESS_BINDING_CHANGED
    return None


def _wait_for_packet(
    record: _TerminalRecord,
    launch_record: _HandleRecord,
    *,
    deadline: MonotonicDeadline,
    cancellation: LaunchCancellation,
    attach_phase: bool = False,
) -> bytes | TerminalReason:
    channel = record.parent_socket
    if channel is None:
        return TerminalReason.TERMINAL_EVENT_EOF
    poller = select.poll()
    poller.register(
        channel.fileno(),
        select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
    )
    poller.register(
        launch_record.control.fileno(),
        select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
    )
    poller.register(
        launch_record.witness_read_fd,
        select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
    )
    poller.register(
        cancellation._read_fd,
        select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
    )
    while True:
        if _cancelled(cancellation):
            return TerminalReason.WAIT_CANCELLED
        if deadline.expired():
            return TerminalReason.DEADLINE_EXCEEDED
        control_reason = _control_failure(
            launch_record,
            attach_phase=attach_phase,
            sequence=record.sequence,
        )
        if control_reason is not None:
            return control_reason
        binding_reason = _validate_live_binding(record, launch_record)
        if binding_reason is not None:
            return binding_reason
        try:
            events = poller.poll(_deadline_timeout(deadline))
        except InterruptedError:
            continue
        for fd, flags in events:
            if fd == cancellation._read_fd:
                return TerminalReason.WAIT_CANCELLED
            if fd == launch_record.control.fileno():
                reason = _control_failure(
                    launch_record,
                    attach_phase=attach_phase,
                    sequence=record.sequence,
                )
                if reason is not None:
                    return reason
            if fd == launch_record.witness_read_fd:
                reason = _control_failure(
                    launch_record,
                    attach_phase=attach_phase,
                    sequence=record.sequence,
                )
                if reason is not None:
                    return reason
            if fd == channel.fileno() and flags & (
                select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL
            ):
                try:
                    raw = _receive_terminal_packet(
                        channel,
                        expected_pid=launch_record.child_pid,
                        expected_uid=launch_record.process_identity.euid,
                    )
                except _PacketError as exc:
                    return exc.reason
                if raw is None:
                    continue
                binding_reason = _validate_live_binding(record, launch_record)
                if binding_reason is not None:
                    return binding_reason
                return raw


def _send_terminal_packet(
    record: _TerminalRecord,
    launch_record: _HandleRecord,
    raw: bytes,
    *,
    deadline: MonotonicDeadline,
    cancellation: LaunchCancellation,
) -> TerminalReason | None:
    channel = record.parent_socket
    if channel is None:
        return TerminalReason.TERMINAL_EVENT_EOF
    poller = select.poll()
    poller.register(
        channel.fileno(),
        select.POLLOUT | select.POLLHUP | select.POLLERR | select.POLLNVAL,
    )
    poller.register(
        cancellation._read_fd,
        select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
    )
    while True:
        if _cancelled(cancellation):
            return TerminalReason.WAIT_CANCELLED
        if deadline.expired():
            return TerminalReason.DEADLINE_EXCEEDED
        control_reason = _control_failure(
            launch_record,
            attach_phase=False,
            sequence=record.sequence,
        )
        if control_reason is not None:
            return control_reason
        binding_reason = _validate_live_binding(record, launch_record)
        if binding_reason is not None:
            return binding_reason
        try:
            sent = _terminal_send(channel, raw)
        except InterruptedError:
            continue
        except BlockingIOError:
            try:
                poller.poll(_deadline_timeout(deadline))
            except InterruptedError:
                continue
            continue
        except OSError as exc:
            if exc.errno in _SOCKET_EOF_ERRNOS:
                return TerminalReason.TERMINAL_EVENT_EOF
            raise
        return None if sent == len(raw) else TerminalReason.TERMINAL_EVENT_MALFORMED


def _send_frame(
    record: _TerminalRecord,
    launch_record: _HandleRecord,
    frame_type: _TerminalFrameType,
    *,
    sequence: int,
    work_count: int,
    deadline: MonotonicDeadline,
    cancellation: LaunchCancellation,
) -> TerminalReason | None:
    return _send_terminal_packet(
        record,
        launch_record,
        _terminal_frame_bytes(
            frame_type,
            event=record.event,
            sequence=sequence,
            work_count=work_count,
            nonce=record.event_nonce,
        ),
        deadline=deadline,
        cancellation=cancellation,
    )


def _expect_frame(
    record: _TerminalRecord,
    launch_record: _HandleRecord,
    frame_type: _TerminalFrameType,
    *,
    sequence: int,
    work_count: int,
    deadline: MonotonicDeadline,
    cancellation: LaunchCancellation,
    attach_phase: bool = False,
) -> bytes | TerminalReason:
    received = _wait_for_packet(
        record,
        launch_record,
        deadline=deadline,
        cancellation=cancellation,
        attach_phase=attach_phase,
    )
    if isinstance(received, TerminalReason):
        return received
    try:
        actual_type, actual_event, actual_sequence, actual_work, nonce = (
            _decode_terminal_frame(received)
        )
    except _PacketError as exc:
        return exc.reason
    if nonce != record.event_nonce:
        return TerminalReason.TERMINAL_EVENT_WRONG_NONCE
    if actual_event is not record.event:
        return TerminalReason.TERMINAL_EVENT_WRONG_KIND
    if actual_type is not frame_type or actual_sequence != sequence:
        return TerminalReason.TERMINAL_EVENT_OUT_OF_ORDER
    if actual_work != work_count:
        return (
            TerminalReason.PENDING_WORK
            if actual_type is _TerminalFrameType.TERMINAL_READY
            else TerminalReason.TERMINAL_EVENT_OUT_OF_ORDER
        )
    return received


def _send_terminal_attach(
    record: _TerminalRecord,
    launch_record: _HandleRecord,
    *,
    deadline: MonotonicDeadline,
    cancellation: LaunchCancellation,
) -> TerminalReason | None:
    child = record.child_socket
    if child is None:
        return TerminalReason.TERMINAL_ATTACH_FAILED
    raw = _frame_bytes(
        _FrameType.TERMINAL_ATTACH,
        launch_record,
        argument0=record.event.value,
        argument1=record.sequence.value,
        argument2=record.work_count,
    )
    ancillary = [
        (
            socket.SOL_SOCKET,
            socket.SCM_RIGHTS,
            array.array("i", [child.fileno()]),
        )
    ]
    poller = select.poll()
    poller.register(
        launch_record.control.fileno(),
        select.POLLOUT | select.POLLHUP | select.POLLERR | select.POLLNVAL,
    )
    poller.register(
        cancellation._read_fd,
        select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
    )
    while True:
        if _cancelled(cancellation):
            return TerminalReason.WAIT_CANCELLED
        if deadline.expired():
            return TerminalReason.DEADLINE_EXCEEDED
        binding_reason = _validate_live_binding(record, launch_record)
        if binding_reason is not None:
            return binding_reason
        try:
            sent = _control_sendmsg(launch_record.control, raw, ancillary)
        except InterruptedError:
            continue
        except BlockingIOError:
            try:
                poller.poll(_deadline_timeout(deadline))
            except InterruptedError:
                continue
            continue
        except OSError as exc:
            if exc.errno in _SOCKET_EOF_ERRNOS:
                return TerminalReason.TERMINAL_ATTACH_FAILED
            raise
        return None if sent == len(raw) else TerminalReason.TERMINAL_ATTACH_FAILED


def _failure_for_reason(
    record: _TerminalRecord,
    reason: TerminalReason,
) -> OwnedFakeTerminalFailure:
    if reason is TerminalReason.DEADLINE_EXCEEDED:
        disposition = TerminalDisposition.TIMED_OUT
    elif reason is TerminalReason.WAIT_CANCELLED:
        disposition = TerminalDisposition.WAIT_CANCELLED
    elif reason in {
        TerminalReason.INVALID_CAPABILITY,
        TerminalReason.CAPABILITY_REUSED,
    }:
        disposition = TerminalDisposition.INVALID_REQUEST
    elif reason in {
        TerminalReason.LAUNCH_OPERATION_BUSY,
        TerminalReason.LAUNCH_NOT_SUPERVISED,
    }:
        disposition = TerminalDisposition.STATE_CONFLICT
    elif reason in {
        TerminalReason.PROCESS_BINDING_CHANGED,
        TerminalReason.CHILD_EXITED,
        TerminalReason.SUPERVISOR_LOST,
        TerminalReason.REGISTRY_ROOT_MISMATCH,
        TerminalReason.RECEIPT_NOT_VERIFIED,
        TerminalReason.RECEIPT_CHANGED,
    }:
        disposition = TerminalDisposition.BINDING_FAILED
    else:
        disposition = TerminalDisposition.PROTOCOL_FAILED
    return _failure(
        disposition,
        reason,
        phase=record.phase,
        trace=record.trace,
    )


def _run_terminal_protocol(
    record: _TerminalRecord,
    launch_record: _HandleRecord,
    *,
    deadline: MonotonicDeadline,
    cancellation: LaunchCancellation,
) -> OwnedFakeTerminalResult | OwnedFakeTerminalFailure:
    try:
        attach_reason = _send_terminal_attach(
            record,
            launch_record,
            deadline=deadline,
            cancellation=cancellation,
        )
    except (OSError, ValueError):
        return _failure_for_reason(
            record,
            TerminalReason.TERMINAL_ATTACH_FAILED,
        )
    if attach_reason is not None:
        return _failure_for_reason(record, attach_reason)
    child = record.child_socket
    record.child_socket = None
    if child is not None:
        with contextlib.suppress(OSError):
            child.close()
    _set_phase(record, TerminalPhase.ATTACHED)

    reason = _send_frame(
        record,
        launch_record,
        _TerminalFrameType.ARM,
        sequence=1,
        work_count=record.work_count,
        deadline=deadline,
        cancellation=cancellation,
    )
    if reason is not None:
        return _failure_for_reason(record, reason)
    armed = _expect_frame(
        record,
        launch_record,
        _TerminalFrameType.ARMED,
        sequence=2,
        work_count=record.work_count,
        deadline=deadline,
        cancellation=cancellation,
        attach_phase=True,
    )
    if isinstance(armed, TerminalReason):
        return _failure_for_reason(record, armed)
    _set_phase(record, TerminalPhase.ARMED)

    reason = _send_frame(
        record,
        launch_record,
        _TerminalFrameType.START,
        sequence=3,
        work_count=record.work_count,
        deadline=deadline,
        cancellation=cancellation,
    )
    if reason is not None:
        return _failure_for_reason(record, reason)
    _set_phase(record, TerminalPhase.STARTED)

    ready_sequence = 4
    if record.sequence is _TerminalSequence.BACKGROUND_DRAIN:
        work_started = _expect_frame(
            record,
            launch_record,
            _TerminalFrameType.WORK_STARTED,
            sequence=4,
            work_count=record.work_count,
            deadline=deadline,
            cancellation=cancellation,
        )
        if isinstance(work_started, TerminalReason):
            return _failure_for_reason(record, work_started)
        requested = _expect_frame(
            record,
            launch_record,
            _TerminalFrameType.TERMINAL_REQUESTED,
            sequence=5,
            work_count=record.work_count,
            deadline=deadline,
            cancellation=cancellation,
        )
        if isinstance(requested, TerminalReason):
            return _failure_for_reason(record, requested)
        _set_phase(record, TerminalPhase.WORK_STARTED)
        reason = _send_frame(
            record,
            launch_record,
            _TerminalFrameType.RELEASE_WORK,
            sequence=6,
            work_count=record.work_count,
            deadline=deadline,
            cancellation=cancellation,
        )
        if reason is not None:
            return _failure_for_reason(record, reason)
        drained = _expect_frame(
            record,
            launch_record,
            _TerminalFrameType.WORK_DRAINED,
            sequence=7,
            work_count=0,
            deadline=deadline,
            cancellation=cancellation,
        )
        if isinstance(drained, TerminalReason):
            return _failure_for_reason(record, drained)
        _set_phase(record, TerminalPhase.WORK_DRAINED)
        ready_sequence = 8

    ready = _expect_frame(
        record,
        launch_record,
        _TerminalFrameType.TERMINAL_READY,
        sequence=ready_sequence,
        work_count=0,
        deadline=deadline,
        cancellation=cancellation,
    )
    if isinstance(ready, TerminalReason):
        return _failure_for_reason(record, ready)
    duplicate_count = 0
    if record.sequence in {
        _TerminalSequence.EXACT_DUPLICATE,
        _TerminalSequence.CONFLICTING_DUPLICATE,
    }:
        duplicate = _wait_for_packet(
            record,
            launch_record,
            deadline=deadline,
            cancellation=cancellation,
        )
        if isinstance(duplicate, TerminalReason):
            return _failure_for_reason(record, duplicate)
        if duplicate != ready:
            return _failure_for_reason(
                record,
                TerminalReason.TERMINAL_EVENT_CONFLICT,
            )
        duplicate_count = 1
    _set_phase(record, TerminalPhase.READY)

    reason = _send_frame(
        record,
        launch_record,
        _TerminalFrameType.ACK,
        sequence=ready_sequence + 1,
        work_count=0,
        deadline=deadline,
        cancellation=cancellation,
    )
    if reason is not None:
        return _failure_for_reason(record, reason)
    acked = _expect_frame(
        record,
        launch_record,
        _TerminalFrameType.ACKED,
        sequence=ready_sequence + 2,
        work_count=0,
        deadline=deadline,
        cancellation=cancellation,
    )
    if isinstance(acked, TerminalReason):
        return _failure_for_reason(record, acked)
    _set_phase(record, TerminalPhase.ACKED)
    return _new_result(
        record,
        duplicate_count=duplicate_count,
        ready_frame=ready,
    )


def _apply_owned_fake_terminal_capability(
    capability: object,
    *,
    deadline: MonotonicDeadline,
    cancellation: LaunchCancellation,
) -> OwnedFakeTerminalResult | OwnedFakeTerminalFailure:
    if (
        type(deadline) is not MonotonicDeadline
        or type(cancellation) is not LaunchCancellation
    ):
        return _failure(
            TerminalDisposition.INVALID_REQUEST,
            TerminalReason.INVALID_CAPABILITY,
            phase=TerminalPhase.NEW,
        )
    launch_record: _HandleRecord | None = None
    record: _TerminalRecord | None = None
    owns_operation = False
    with _STATE_LOCK:
        found = _record_for_capability(capability)
        if isinstance(found, OwnedFakeTerminalFailure):
            return found
        record = found
        if record.state in {_ClaimState.APPLIED, _ClaimState.REFUSED}:
            assert record.cached is not None
            return record.cached
        if record.state is _ClaimState.CLAIMED:
            return _failure(
                TerminalDisposition.STATE_CONFLICT,
                TerminalReason.LAUNCH_OPERATION_BUSY,
                phase=record.phase,
                trace=record.trace,
            )
        claimed = _claim_operation(record.handle, "terminal")
        if isinstance(claimed, LaunchFailure):
            failure = _failure(
                TerminalDisposition.STATE_CONFLICT,
                _launch_failure_reason(claimed),
                phase=record.phase,
                trace=record.trace,
            )
            record.state = _ClaimState.REFUSED
            record.phase = TerminalPhase.REFUSED
            record.trace.append(TerminalPhase.REFUSED.value)
            record.cached = failure
            _close_sockets(record)
            return failure
        launch_record, owns_operation = claimed
        if not owns_operation:
            failure = _failure(
                TerminalDisposition.STATE_CONFLICT,
                TerminalReason.LAUNCH_OPERATION_BUSY,
                phase=record.phase,
                trace=record.trace,
            )
            record.state = _ClaimState.REFUSED
            record.phase = TerminalPhase.REFUSED
            record.trace.append(TerminalPhase.REFUSED.value)
            record.cached = failure
            _close_sockets(record)
            return failure
        record.state = _ClaimState.CLAIMED
        record.phase = TerminalPhase.CLAIMED
        record.trace.append(TerminalPhase.CLAIMED.value)

    assert record is not None
    assert launch_record is not None
    outcome: OwnedFakeTerminalResult | OwnedFakeTerminalFailure | None = None
    raised: BaseException | None = None
    try:
        _terminal_phase_hook(TerminalPhase.CLAIMED, record.capability_id)
        binding_reason = _validate_live_binding(record, launch_record)
        if binding_reason is not None:
            outcome = _failure_for_reason(record, binding_reason)
        elif not _initial_binding_matches(record, launch_record):
            outcome = _failure_for_reason(
                record,
                TerminalReason.INVALID_CAPABILITY,
            )
        elif not hmac.compare_digest(
            record.capability_mac,
            _capability_mac(record.capability_id, record.binding_bytes),
        ):
            outcome = _failure_for_reason(
                record,
                TerminalReason.INVALID_CAPABILITY,
            )
        else:
            outcome = _run_terminal_protocol(
                record,
                launch_record,
                deadline=deadline,
                cancellation=cancellation,
            )
    except (OSError, UnicodeError, ValueError) as exc:
        del exc
        outcome = _failure_for_reason(
            record,
            TerminalReason.TERMINAL_EVENT_MALFORMED,
        )
    except BaseException as exc:
        raised = exc
    finally:
        sockets_closed = _close_sockets(record)
        if owns_operation:
            _release_operation(launch_record)
    if raised is not None:
        with _STATE_LOCK:
            record.state = _ClaimState.REFUSED
            record.phase = TerminalPhase.REFUSED
            record.trace.append(TerminalPhase.REFUSED.value)
            record.cached = _failure(
                TerminalDisposition.PROTOCOL_FAILED,
                TerminalReason.TERMINAL_EVENT_MALFORMED,
                phase=record.phase,
                trace=record.trace,
            )
        raise raised
    assert outcome is not None
    if not sockets_closed:
        outcome = _failure_for_reason(record, TerminalReason.TERMINAL_EVENT_EOF)
    with _STATE_LOCK:
        if isinstance(outcome, OwnedFakeTerminalResult):
            record.state = _ClaimState.APPLIED
        else:
            record.state = _ClaimState.REFUSED
            if record.phase is not TerminalPhase.REFUSED:
                record.phase = TerminalPhase.REFUSED
                record.trace.append(TerminalPhase.REFUSED.value)
                outcome = _failure(
                    outcome.disposition,
                    outcome.reason_codes[0],
                    phase=record.phase,
                    diagnostics=outcome.diagnostics,
                    trace=record.trace,
                )
        record.cached = outcome
    return outcome


__all__: tuple[str, ...] = ()
