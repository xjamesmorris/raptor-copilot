"""Closed, non-authorizing model types for runtime-receipt plumbing."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field, fields
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Literal, Mapping, cast

from core.json.bounded import JsonBudgetExceededError, loads_bounded

from .canonical import (
    MAX_RECEIPT_BYTES,
    TOKEN_COMMITMENT_DOMAIN,
    CanonicalValueError,
    JsonValue,
    canonical_bytes,
    validate_json_value,
)
from .reasons import ReasonCode, ReceiptRejection
from .schema import (
    ExpectedBinding,
    Identifier,
    NonceHex,
    RuntimeReceipt,
    Sha256,
    U64Decimal,
    UuidText,
    to_json_value,
)
from .profile import ProfileStore
from .verify import (
    StaticallyVerifiedReceipt,
    parse_receipt,
    serialize_receipt,
    verify_receipt_static,
)

REFERENCE_SCHEMA = "raptor.runtime_receipt_reference/v1"
REFERENCE_SCHEMA_VERSION = 1
SNAPSHOT_SCHEMA = "raptor.run_runtime_receipt_snapshot/v1"
SNAPSHOT_SCHEMA_VERSION = 1
MAX_REFERENCE_BYTES = 4_096
MAX_SNAPSHOT_BYTES = 73_728
MAX_DIAGNOSTIC_FIELDS = 16
MAX_DIAGNOSTIC_VALUE_BYTES = 128
MAX_POINTER_BYTES = 8_192
_MISSING_AUTHORITY = object()


class ReceiptState(str, Enum):
    """Closed persistent receipt state."""

    ABSENT = "absent"
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"
    CLEANED = "cleaned"


class PlumbingDisposition(str, Enum):
    """Closed non-success categories for the Stage 2 plumbing model."""

    INVALID_REQUEST = "invalid_request"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    COLLECTION_FAILED = "collection_failed"
    BINDING_FAILED = "binding_failed"
    STATE_CONFLICT = "state_conflict"
    PERSISTENCE_FAILED = "persistence_failed"
    RECEIPT_REJECTED = "receipt_rejected"
    CLEANUP_FAILED = "cleanup_failed"


class PlumbingReason(str, Enum):
    """Closed failure reasons for model, persistence, and comparison operations."""

    INVALID_TRANSITION = "invalid_transition"
    REPLAYED_TRANSITION = "replayed_transition"
    SKIPPED_TRANSITION = "skipped_transition"
    AUTHORITY_INVARIANT_VIOLATION = "authority_invariant_violation"
    INVALID_RECEIPT_REFERENCE = "invalid_receipt_reference"
    INVALID_COMPARATOR_INPUT = "invalid_comparator_input"
    REQUIRED_OS_PRIMITIVE_MISSING = "required_os_primitive_missing"
    STRICT_LOCK_UNAVAILABLE = "strict_lock_unavailable"
    ROOT_UNAVAILABLE = "root_unavailable"
    ROOT_POLICY_VIOLATION = "root_policy_violation"
    LOCK_POLICY_VIOLATION = "lock_policy_violation"
    LOCK_REPLACED = "lock_replaced"
    SIDECAR_MISSING = "sidecar_missing"
    SIDECAR_WRITE_FAILED = "sidecar_write_failed"
    SIDECAR_READ_FAILED = "sidecar_read_failed"
    SIDECAR_POLICY_VIOLATION = "sidecar_policy_violation"
    SIDECAR_PARSE_FAILED = "sidecar_parse_failed"
    SIDECAR_DIGEST_MISMATCH = "sidecar_digest_mismatch"
    POINTER_MISSING = "pointer_missing"
    POINTER_INVALID = "pointer_invalid"
    POINTER_WRITE_FAILED = "pointer_write_failed"
    TOKEN_MISMATCH = "token_mismatch"
    LAUNCH_NONCE_MISMATCH = "launch_nonce_mismatch"
    PID_MISMATCH = "pid_mismatch"
    STARTTIME_MISMATCH = "starttime_mismatch"
    SESSION_MISMATCH = "session_mismatch"
    LAUNCH_MISMATCH = "launch_mismatch"
    PROCESS_BINDING_MISMATCH = "process_binding_mismatch"
    PROFILE_MISMATCH = "profile_mismatch"
    STABLE_IDENTITY_MISMATCH = "stable_identity_mismatch"
    DIGEST_MISMATCH = "digest_mismatch"
    STATE_NOT_FINAL = "state_not_final"
    CAS_CONFLICT = "cas_conflict"
    CONCURRENT_FINALIZER = "concurrent_finalizer"
    STATIC_VERIFICATION_FAILED = "static_verification_failed"
    COLLECTION_ADAPTATION_FAILED = "collection_adaptation_failed"
    SIDECAR_STILL_REFERENCED = "sidecar_still_referenced"
    SIDECAR_CLEANUP_INCOMPLETE = "sidecar_cleanup_incomplete"
    POINTER_CLEANUP_INCOMPLETE = "pointer_cleanup_incomplete"


class ReceiptComparisonResult(str, Enum):
    """Deny-only comparison outcomes; no value grants authority."""

    ABSENT_BOTH = "absent_both"
    MATCH_NON_AUTHORIZING = "match_non_authorizing"
    AUTHORITY_INVALID = "authority_invalid"
    METADATA_INVALID = "metadata_invalid"
    REGISTRY_INVALID = "registry_invalid"
    STATE_NOT_FINAL = "state_not_final"
    RECEIPT_MISSING = "receipt_missing"
    DIGEST_MISMATCH = "digest_mismatch"
    PROFILE_MISMATCH = "profile_mismatch"
    STABLE_IDENTITY_MISMATCH = "stable_identity_mismatch"
    LAUNCH_NONCE_MISMATCH = "launch_nonce_mismatch"
    SESSION_BINDING_MISMATCH = "session_binding_mismatch"


_REASONS_BY_DISPOSITION = {
    PlumbingDisposition.INVALID_REQUEST: frozenset(
        {
            PlumbingReason.INVALID_TRANSITION,
            PlumbingReason.REPLAYED_TRANSITION,
            PlumbingReason.SKIPPED_TRANSITION,
            PlumbingReason.AUTHORITY_INVARIANT_VIOLATION,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
            PlumbingReason.INVALID_COMPARATOR_INPUT,
        }
    ),
    PlumbingDisposition.UNSUPPORTED_PLATFORM: frozenset(
        {
            PlumbingReason.REQUIRED_OS_PRIMITIVE_MISSING,
            PlumbingReason.STRICT_LOCK_UNAVAILABLE,
        }
    ),
    PlumbingDisposition.COLLECTION_FAILED: frozenset(
        {PlumbingReason.COLLECTION_ADAPTATION_FAILED}
    ),
    PlumbingDisposition.BINDING_FAILED: frozenset(
        {
            PlumbingReason.TOKEN_MISMATCH,
            PlumbingReason.LAUNCH_NONCE_MISMATCH,
            PlumbingReason.PID_MISMATCH,
            PlumbingReason.STARTTIME_MISMATCH,
            PlumbingReason.SESSION_MISMATCH,
            PlumbingReason.LAUNCH_MISMATCH,
            PlumbingReason.PROCESS_BINDING_MISMATCH,
            PlumbingReason.PROFILE_MISMATCH,
            PlumbingReason.STABLE_IDENTITY_MISMATCH,
            PlumbingReason.DIGEST_MISMATCH,
            PlumbingReason.STATE_NOT_FINAL,
        }
    ),
    PlumbingDisposition.STATE_CONFLICT: frozenset(
        {
            PlumbingReason.CAS_CONFLICT,
            PlumbingReason.CONCURRENT_FINALIZER,
        }
    ),
    PlumbingDisposition.PERSISTENCE_FAILED: frozenset(
        {
            PlumbingReason.ROOT_UNAVAILABLE,
            PlumbingReason.ROOT_POLICY_VIOLATION,
            PlumbingReason.LOCK_POLICY_VIOLATION,
            PlumbingReason.LOCK_REPLACED,
            PlumbingReason.SIDECAR_MISSING,
            PlumbingReason.SIDECAR_WRITE_FAILED,
            PlumbingReason.SIDECAR_READ_FAILED,
            PlumbingReason.SIDECAR_POLICY_VIOLATION,
            PlumbingReason.SIDECAR_PARSE_FAILED,
            PlumbingReason.SIDECAR_DIGEST_MISMATCH,
            PlumbingReason.POINTER_MISSING,
            PlumbingReason.POINTER_INVALID,
            PlumbingReason.POINTER_WRITE_FAILED,
            PlumbingReason.AUTHORITY_INVARIANT_VIOLATION,
        }
    ),
    PlumbingDisposition.RECEIPT_REJECTED: frozenset(
        {PlumbingReason.STATIC_VERIFICATION_FAILED}
    ),
    PlumbingDisposition.CLEANUP_FAILED: frozenset(
        {
            PlumbingReason.SIDECAR_STILL_REFERENCED,
            PlumbingReason.SIDECAR_CLEANUP_INCOMPLETE,
            PlumbingReason.POINTER_CLEANUP_INCOMPLETE,
        }
    ),
}


class AuthorityInvariantError(CanonicalValueError):
    """A non-authorizing wrapper violated its runtime authority ceiling."""

    disposition = PlumbingDisposition.INVALID_REQUEST
    reason_codes = (PlumbingReason.AUTHORITY_INVARIANT_VIOLATION,)


_SAFE_DETAIL_KEYS = frozenset(
    {
        "stage",
        "state",
        "pid",
        "attempt",
        "errno_class",
        "reason",
        "expected_sha256",
        "observed_sha256",
        "profile_id",
    }
)


def _empty_details() -> Mapping[str, str]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class PlumbingFailure:
    """A bounded failure that cannot contain raw token or path material."""

    disposition: PlumbingDisposition
    reason_codes: tuple[PlumbingReason, ...]
    details: Mapping[str, str] = field(default_factory=_empty_details)
    source_reason_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        reasons = tuple(dict.fromkeys(self.reason_codes))
        if not reasons or len(reasons) > 32:
            raise ValueError("plumbing failure requires 1..32 reason codes")
        allowed = _REASONS_BY_DISPOSITION[self.disposition]
        if any(reason not in allowed for reason in reasons):
            raise ValueError("reason code is invalid for plumbing disposition")
        bounded: dict[str, str] = {}
        for key, value in self.details.items():
            if key not in _SAFE_DETAIL_KEYS:
                raise ValueError("plumbing failure detail key is not allowed")
            try:
                key_bytes = key.encode("ascii")
                value_bytes = value.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ValueError("plumbing failure details must be ASCII") from exc
            if (
                len(key_bytes) > 64
                or not key.isprintable()
                or len(value_bytes) > MAX_DIAGNOSTIC_VALUE_BYTES
                or not value.isprintable()
                or (
                    len(value) == 32
                    and all(character in "0123456789abcdef" for character in value)
                )
            ):
                raise ValueError("plumbing failure detail is outside its bound")
            bounded[key] = value
        if len(bounded) > MAX_DIAGNOSTIC_FIELDS:
            raise ValueError("plumbing failure has too many detail fields")
        source_reasons = tuple(dict.fromkeys(self.source_reason_codes))
        if len(source_reasons) > 32:
            raise ValueError("plumbing failure has too many source reason codes")
        for reason in source_reasons:
            if (
                not reason
                or not reason.isascii()
                or not reason.isprintable()
                or len(reason) > MAX_DIAGNOSTIC_VALUE_BYTES
                or (
                    len(reason) == 32
                    and all(character in "0123456789abcdef" for character in reason)
                )
            ):
                raise ValueError("source reason code is outside its bound")
        object.__setattr__(self, "reason_codes", reasons)
        object.__setattr__(self, "details", MappingProxyType(bounded))
        object.__setattr__(self, "source_reason_codes", source_reasons)


def plumbing_failure(
    disposition: PlumbingDisposition,
    *reason_codes: PlumbingReason,
    details: Mapping[str, str] | None = None,
    source_reason_codes: tuple[str, ...] = (),
) -> PlumbingFailure:
    """Build one canonical plumbing failure."""

    return PlumbingFailure(
        disposition=disposition,
        reason_codes=reason_codes,
        details=details or {},
        source_reason_codes=source_reason_codes,
    )


def authority_invariant_failure(
    value: object,
    expected_type: type[object],
    *,
    disposition: PlumbingDisposition = PlumbingDisposition.INVALID_REQUEST,
    details: Mapping[str, str] | None = None,
) -> PlumbingFailure | None:
    """Return a typed failure unless an exact wrapper remains non-authoritative."""

    if (
        type(value) is expected_type
        and getattr(value, "authoritative", _MISSING_AUTHORITY) is False
    ):
        return None
    return plumbing_failure(
        disposition,
        PlumbingReason.AUTHORITY_INVARIANT_VIOLATION,
        details=details,
    )


def require_authority_invariant(
    value: object,
    expected_type: type[object],
) -> None:
    """Raise a typed canonical error unless an exact wrapper is non-authoritative."""

    if authority_invariant_failure(value, expected_type) is not None:
        raise AuthorityInvariantError("non-authorizing authority invariant violated")


@dataclass(frozen=True, slots=True)
class CanonicalPid:
    """A positive u64 PID with one canonical decimal representation."""

    value: int

    def __post_init__(self) -> None:
        if type(self.value) is not int or not 1 <= self.value <= 2**64 - 1:
            raise ValueError("PID must be a positive u64 integer")

    @classmethod
    def parse(cls, text: str) -> "CanonicalPid":
        if (
            not isinstance(text, str)
            or not text
            or not text.isascii()
            or not text.isdecimal()
            or (len(text) > 1 and text.startswith("0"))
            or len(text) > 20
        ):
            raise ValueError("PID must be canonical positive decimal text")
        return cls(int(text))

    @property
    def text(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True, repr=False)
class SessionToken:
    """In-memory 16-byte session token with deliberately redacted repr."""

    _value: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self._value) is not bytes or len(self._value) != 16:
            raise ValueError("session token must be exactly 16 bytes")

    def __repr__(self) -> str:
        return "SessionToken(<redacted>)"

    def commitment(self) -> Sha256:
        return token_commitment_from_bytes(self._value)

    def matches_commitment(self, expected: Sha256 | str) -> bool:
        return token_commitment_matches(self._value, expected)

    def _hex_for_static_verifier(self) -> str:
        return self._value.hex()


def token_commitment_from_bytes(token: bytes) -> Sha256:
    """Commit to exactly 16 token bytes without serializing the token."""

    if type(token) is not bytes or len(token) != 16:
        raise ValueError("session token must be exactly 16 bytes")
    return Sha256(hashlib.sha256(TOKEN_COMMITMENT_DOMAIN + token).hexdigest())


def token_commitment_matches(token: bytes, expected: Sha256 | str) -> bool:
    """Compare a token commitment in constant time."""

    actual = token_commitment_from_bytes(token).value
    expected_text = expected.value if isinstance(expected, Sha256) else expected
    if not isinstance(expected_text, str):
        raise TypeError("expected commitment must be Sha256 or str")
    try:
        expected_bytes = bytes.fromhex(expected_text)
    except ValueError:
        expected_bytes = b""
    if len(expected_bytes) != 32 or expected_text != expected_text.lower():
        expected_bytes = b"\0" * 32
        valid = False
    else:
        valid = True
    matched = hmac.compare_digest(bytes.fromhex(actual), expected_bytes)
    return bool(valid & matched)


@dataclass(frozen=True, slots=True)
class ReceiptReference:
    """Complete immutable reference used by Stage 2 sidecar and CAS helpers."""

    state: ReceiptState
    session_id: UuidText
    launch_id: UuidText
    session_pid: CanonicalPid
    session_starttime_ticks: U64Decimal
    boot_id: UuidText
    pid_namespace_inode: U64Decimal
    launcher_euid: U64Decimal
    session_token_commitment_sha256: Sha256
    launch_nonce: NonceHex
    attempt: int
    profile_id: Identifier
    stable_identity_sha256: Sha256
    launch_instance_sha256: Sha256
    launch_binding_sha256: Sha256
    process_corroboration_sha256: Sha256
    receipt_sha256: Sha256

    def __post_init__(self) -> None:
        if self.state not in {
            ReceiptState.PENDING,
            ReceiptState.VERIFIED,
            ReceiptState.REJECTED,
        }:
            raise ValueError("receipt reference must name a persisted receipt state")
        if type(self.attempt) is not int or not 0 <= self.attempt <= 65_535:
            raise ValueError("receipt attempt is outside its bound")
        if self.state is ReceiptState.PENDING and self.attempt != 0:
            raise ValueError("pending receipt attempt must be zero")
        if self.state in {ReceiptState.VERIFIED, ReceiptState.REJECTED}:
            if self.attempt == 0:
                raise ValueError("final receipt attempt must be positive")

    @property
    def sidecar_name(self) -> str:
        return f"{self.session_pid.text}.receipt.{self.receipt_sha256.value}.json"

    @property
    def sidecar_temporary_name(self) -> str:
        return f"{self.sidecar_name}.tmp"

    @property
    def pointer_name(self) -> str:
        return f"{self.session_pid.text}.receipt-pointer-model.json"

    @property
    def pointer_temporary_name(self) -> str:
        return (
            f"{self.session_pid.text}.receipt-pointer-model."
            f"{self.receipt_sha256.value}.tmp"
        )

    @property
    def lock_name(self) -> str:
        return f"{self.session_pid.text}.receipt.lock"


@dataclass(frozen=True, slots=True)
class ReceiptStateRecord:
    """State-machine record; absent and cleaned states carry no reference."""

    state: ReceiptState
    reference: ReceiptReference | None

    def __post_init__(self) -> None:
        persisted = {
            ReceiptState.PENDING,
            ReceiptState.VERIFIED,
            ReceiptState.REJECTED,
        }
        if self.state in persisted:
            if self.reference is None or self.reference.state is not self.state:
                raise ValueError("persisted state requires a matching reference")
        elif self.reference is not None:
            raise ValueError("absent and cleaned states cannot carry a reference")


@dataclass(frozen=True, slots=True)
class TransitionApplied:
    """Successful pure state transition."""

    prior: ReceiptStateRecord
    current: ReceiptStateRecord


@dataclass(frozen=True, slots=True)
class StoredReceipt:
    """A safely read or written immutable sidecar."""

    reference: ReceiptReference
    receipt: RuntimeReceipt
    file_name: str
    created: bool
    authoritative: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        require_authority_invariant(self, StoredReceipt)

    def __init_subclass__(cls) -> None:
        raise TypeError("StoredReceipt cannot be subclassed")


@dataclass(frozen=True, slots=True)
class ModeledPointer:
    """Test-owned pointer plus the complete selected sidecar."""

    reference: ReceiptReference
    receipt: RuntimeReceipt
    file_name: str
    authoritative: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        require_authority_invariant(self, ModeledPointer)

    def __init_subclass__(cls) -> None:
        raise TypeError("ModeledPointer cannot be subclassed")


@dataclass(frozen=True, slots=True)
class CasApplied:
    """Successful modeled pointer compare-and-swap."""

    prior: ReceiptReference
    current: ReceiptReference
    authoritative: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        require_authority_invariant(self, CasApplied)

    def __init_subclass__(cls) -> None:
        raise TypeError("CasApplied cannot be subclassed")


@dataclass(frozen=True, slots=True)
class CleanupApplied:
    """Successful exact-path cleanup."""

    reference: ReceiptReference
    pointer_removed: bool
    sidecar_removed: bool
    temporary_removed: bool = False
    authoritative: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        require_authority_invariant(self, CleanupApplied)

    def __init_subclass__(cls) -> None:
        raise TypeError("CleanupApplied cannot be subclassed")


@dataclass(frozen=True, slots=True)
class RuntimeReceiptSnapshot:
    """Immutable audit snapshot of one statically verified receipt."""

    reference: ReceiptReference
    receipt: RuntimeReceipt
    reason_codes: tuple[ReasonCode, ...] = (
        ReasonCode.PROFILE_UNSUPPORTED,
        ReasonCode.LIVE_CONTRACT_MISSING,
    )
    authoritative: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        require_authority_invariant(self, RuntimeReceiptSnapshot)
        if self.reference.state is not ReceiptState.VERIFIED:
            raise ValueError("run snapshots require a verified static receipt")
        if self.reason_codes != (
            ReasonCode.PROFILE_UNSUPPORTED,
            ReasonCode.LIVE_CONTRACT_MISSING,
        ):
            raise ValueError(
                "snapshot reasons must retain the static authority ceiling"
            )
        mismatch = reference_receipt_mismatch(self.reference, self.receipt)
        if mismatch is not None:
            raise ValueError("snapshot reference and receipt disagree")

    def __init_subclass__(cls) -> None:
        raise TypeError("RuntimeReceiptSnapshot cannot be subclassed")


@dataclass(frozen=True, slots=True)
class ReceiptComparatorInput:
    """Bounded explicit comparator input with no ambient lookup."""

    metadata_snapshot: RuntimeReceiptSnapshot | None
    current_reference: ReceiptReference | None
    current_receipt: RuntimeReceipt | None

    def __post_init__(self) -> None:
        if self.current_receipt is not None and self.current_reference is None:
            raise ValueError("current receipt requires an explicit reference")


_LEGAL_TRANSITIONS = {
    ReceiptState.ABSENT: frozenset({ReceiptState.PENDING}),
    ReceiptState.PENDING: frozenset(
        {ReceiptState.VERIFIED, ReceiptState.REJECTED, ReceiptState.CLEANED}
    ),
    ReceiptState.VERIFIED: frozenset({ReceiptState.REJECTED, ReceiptState.CLEANED}),
    ReceiptState.REJECTED: frozenset({ReceiptState.CLEANED}),
    ReceiptState.CLEANED: frozenset(),
}


def _is_transitively_reachable(prior: ReceiptState, target: ReceiptState) -> bool:
    frontier = list(_LEGAL_TRANSITIONS[prior])
    visited = {prior}
    while frontier:
        state = frontier.pop()
        if state is target:
            return True
        if state in visited:
            continue
        visited.add(state)
        frontier.extend(_LEGAL_TRANSITIONS[state])
    return False


def transition_state(
    prior: ReceiptStateRecord,
    target: ReceiptState,
    *,
    reference: ReceiptReference | None = None,
) -> TransitionApplied | PlumbingFailure:
    """Apply the closed transition table without repair or fallback."""

    if prior.state is target:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.REPLAYED_TRANSITION,
            details={"state": target.value},
        )
    if target not in _LEGAL_TRANSITIONS[prior.state]:
        reason = (
            PlumbingReason.SKIPPED_TRANSITION
            if _is_transitively_reachable(prior.state, target)
            else PlumbingReason.INVALID_TRANSITION
        )
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            reason,
            details={"state": target.value},
        )
    if target in {
        ReceiptState.PENDING,
        ReceiptState.VERIFIED,
        ReceiptState.REJECTED,
    } and (reference is None or reference.state is not target):
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
            details={"state": target.value},
        )
    if target in {ReceiptState.ABSENT, ReceiptState.CLEANED} and reference is not None:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
            details={"state": target.value},
        )
    current = ReceiptStateRecord(state=target, reference=reference)
    return TransitionApplied(prior=prior, current=current)


def _constant_time_sha_equal(left: Sha256, right: Sha256) -> bool:
    return hmac.compare_digest(bytes.fromhex(left.value), bytes.fromhex(right.value))


def reference_transition_mismatch(
    prior: ReceiptReference,
    current: ReceiptReference,
) -> PlumbingFailure | None:
    """Validate the complete trusted prior/current tuple for a CAS transition."""

    transition = transition_state(
        ReceiptStateRecord(prior.state, prior),
        current.state,
        reference=current,
    )
    if isinstance(transition, PlumbingFailure):
        return transition
    if prior.session_id != current.session_id:
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.SESSION_MISMATCH,
        )
    if prior.launch_id != current.launch_id:
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.LAUNCH_MISMATCH,
        )
    if prior.session_pid != current.session_pid:
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.PID_MISMATCH,
        )
    if prior.session_starttime_ticks != current.session_starttime_ticks:
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.STARTTIME_MISMATCH,
        )
    if (
        prior.boot_id != current.boot_id
        or prior.pid_namespace_inode != current.pid_namespace_inode
        or prior.launcher_euid != current.launcher_euid
    ):
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.PROCESS_BINDING_MISMATCH,
        )
    if not _constant_time_sha_equal(
        prior.session_token_commitment_sha256,
        current.session_token_commitment_sha256,
    ):
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.TOKEN_MISMATCH,
        )
    if prior.launch_nonce != current.launch_nonce:
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.LAUNCH_NONCE_MISMATCH,
        )
    if prior.profile_id != current.profile_id:
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.PROFILE_MISMATCH,
        )
    if not _constant_time_sha_equal(
        prior.stable_identity_sha256,
        current.stable_identity_sha256,
    ):
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.STABLE_IDENTITY_MISMATCH,
        )
    for before, after in (
        (prior.launch_instance_sha256, current.launch_instance_sha256),
        (prior.launch_binding_sha256, current.launch_binding_sha256),
    ):
        if not _constant_time_sha_equal(before, after):
            return plumbing_failure(
                PlumbingDisposition.BINDING_FAILED,
                PlumbingReason.DIGEST_MISMATCH,
            )
    if current.attempt != prior.attempt + 1:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.SKIPPED_TRANSITION,
            details={"attempt": str(current.attempt)},
        )
    return None


def _receipt_state(receipt: RuntimeReceipt) -> ReceiptState:
    return ReceiptState(receipt.decision.state.value)


def _unchecked_reference(receipt: RuntimeReceipt) -> ReceiptReference:
    binding = receipt.launch_binding
    return ReceiptReference(
        state=_receipt_state(receipt),
        session_id=binding.session_id,
        launch_id=binding.launch_id,
        session_pid=CanonicalPid(binding.session_pid.value),
        session_starttime_ticks=binding.session_starttime_ticks,
        boot_id=binding.boot_id,
        pid_namespace_inode=binding.pid_namespace_inode,
        launcher_euid=binding.launcher_euid,
        session_token_commitment_sha256=binding.session_token_commitment_sha256,
        launch_nonce=binding.receipt_nonce,
        attempt=receipt.process_corroboration.attempt,
        profile_id=receipt.stable_identity.profile_id,
        stable_identity_sha256=receipt.stable_identity_sha256,
        launch_instance_sha256=receipt.launch_instance_sha256,
        launch_binding_sha256=receipt.launch_binding_sha256,
        process_corroboration_sha256=receipt.process_corroboration_sha256,
        receipt_sha256=receipt.receipt_sha256,
    )


def reference_from_receipt(
    receipt: RuntimeReceipt,
) -> ReceiptReference | PlumbingFailure:
    """Create a reference only from a canonically self-consistent receipt."""

    if not isinstance(receipt, RuntimeReceipt):
        raise TypeError("receipt must be RuntimeReceipt")
    try:
        parsed = parse_receipt(serialize_receipt(receipt))
    except CanonicalValueError:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
        )
    if isinstance(parsed, ReceiptRejection):
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
            source_reason_codes=tuple(code.value for code in parsed.reason_codes),
        )
    try:
        return _unchecked_reference(parsed)
    except ValueError:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
        )


def reference_receipt_mismatch(
    reference: ReceiptReference,
    receipt: RuntimeReceipt,
) -> PlumbingFailure | None:
    """Compare every reference field against one already-parsed receipt."""

    try:
        actual = _unchecked_reference(receipt)
    except ValueError:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
        )
    if reference.state is not actual.state or reference.attempt != actual.attempt:
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.STATE_NOT_FINAL,
            details={"state": actual.state.value, "attempt": str(actual.attempt)},
        )
    if reference.session_id != actual.session_id:
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.SESSION_MISMATCH,
        )
    if reference.launch_id != actual.launch_id:
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.LAUNCH_MISMATCH,
        )
    if reference.session_pid != actual.session_pid:
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.PID_MISMATCH,
        )
    if reference.session_starttime_ticks != actual.session_starttime_ticks:
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.STARTTIME_MISMATCH,
        )
    if (
        reference.boot_id != actual.boot_id
        or reference.pid_namespace_inode != actual.pid_namespace_inode
        or reference.launcher_euid != actual.launcher_euid
    ):
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.PROCESS_BINDING_MISMATCH,
        )
    if not _constant_time_sha_equal(
        reference.session_token_commitment_sha256,
        actual.session_token_commitment_sha256,
    ):
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.TOKEN_MISMATCH,
        )
    if reference.launch_nonce != actual.launch_nonce:
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.LAUNCH_NONCE_MISMATCH,
        )
    if reference.profile_id != actual.profile_id:
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.PROFILE_MISMATCH,
        )
    if not _constant_time_sha_equal(
        reference.stable_identity_sha256,
        actual.stable_identity_sha256,
    ):
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.STABLE_IDENTITY_MISMATCH,
        )
    for expected, observed in (
        (reference.launch_instance_sha256, actual.launch_instance_sha256),
        (reference.launch_binding_sha256, actual.launch_binding_sha256),
        (
            reference.process_corroboration_sha256,
            actual.process_corroboration_sha256,
        ),
        (reference.receipt_sha256, actual.receipt_sha256),
    ):
        if not _constant_time_sha_equal(expected, observed):
            return plumbing_failure(
                PlumbingDisposition.BINDING_FAILED,
                PlumbingReason.DIGEST_MISMATCH,
            )
    return None


def _reference_value(reference: ReceiptReference) -> dict[str, object]:
    result: dict[str, object] = {}
    scalar_types = (UuidText, Identifier, NonceHex, Sha256)
    for item in fields(reference):
        value = getattr(reference, item.name)
        if isinstance(value, ReceiptState):
            encoded: object = value.value
        elif isinstance(value, CanonicalPid):
            encoded = value.text
        elif isinstance(value, U64Decimal):
            encoded = value.text
        elif isinstance(value, scalar_types):
            encoded = value.value
        elif type(value) is int:
            encoded = value
        else:
            raise TypeError(f"unsupported reference field: {item.name}")
        result[item.name] = encoded
    return result


_REFERENCE_VALUE_KEYS = frozenset(item.name for item in fields(ReceiptReference))


def _closed_dict(
    value: object,
    required: frozenset[str],
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("expected object")
    if set(value) != required:
        raise ValueError("object fields are not exact")
    return value


def _bounded_text(value: object, *, max_bytes: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or not value.isprintable()
        or len(value.encode("utf-8")) > max_bytes
    ):
        raise ValueError("invalid text")
    return value


def _canonical_decimal(value: object, *, positive: bool = False) -> int:
    text = _bounded_text(value, max_bytes=20)
    if (
        not text.isascii()
        or not text.isdecimal()
        or (len(text) > 1 and text.startswith("0"))
    ):
        raise ValueError("invalid canonical decimal")
    parsed = int(text)
    if parsed > 2**64 - 1 or (positive and parsed == 0):
        raise ValueError("decimal is outside range")
    return parsed


def _plain_int(value: object, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("integer is outside range")
    return value


def _parse_reference_value(value: object) -> ReceiptReference:
    obj = _closed_dict(value, _REFERENCE_VALUE_KEYS)
    return ReceiptReference(
        state=ReceiptState(_bounded_text(obj["state"], max_bytes=16)),
        session_id=UuidText(_bounded_text(obj["session_id"], max_bytes=36)),
        launch_id=UuidText(_bounded_text(obj["launch_id"], max_bytes=36)),
        session_pid=CanonicalPid.parse(_bounded_text(obj["session_pid"], max_bytes=20)),
        session_starttime_ticks=U64Decimal(
            _canonical_decimal(obj["session_starttime_ticks"], positive=True)
        ),
        boot_id=UuidText(_bounded_text(obj["boot_id"], max_bytes=36)),
        pid_namespace_inode=U64Decimal(
            _canonical_decimal(obj["pid_namespace_inode"], positive=True)
        ),
        launcher_euid=U64Decimal(_canonical_decimal(obj["launcher_euid"])),
        session_token_commitment_sha256=Sha256(
            _bounded_text(
                obj["session_token_commitment_sha256"],
                max_bytes=64,
            )
        ),
        launch_nonce=NonceHex(_bounded_text(obj["launch_nonce"], max_bytes=32)),
        attempt=_plain_int(obj["attempt"], minimum=0, maximum=65_535),
        profile_id=Identifier(_bounded_text(obj["profile_id"], max_bytes=128)),
        stable_identity_sha256=Sha256(
            _bounded_text(obj["stable_identity_sha256"], max_bytes=64)
        ),
        launch_instance_sha256=Sha256(
            _bounded_text(obj["launch_instance_sha256"], max_bytes=64)
        ),
        launch_binding_sha256=Sha256(
            _bounded_text(obj["launch_binding_sha256"], max_bytes=64)
        ),
        process_corroboration_sha256=Sha256(
            _bounded_text(
                obj["process_corroboration_sha256"],
                max_bytes=64,
            )
        ),
        receipt_sha256=Sha256(_bounded_text(obj["receipt_sha256"], max_bytes=64)),
    )


def serialize_reference(reference: ReceiptReference) -> bytes:
    """Serialize one bounded canonical reference."""

    if not isinstance(reference, ReceiptReference):
        raise TypeError("reference must be ReceiptReference")
    raw = canonical_bytes(
        {
            "schema": REFERENCE_SCHEMA,
            "schema_version": REFERENCE_SCHEMA_VERSION,
            "reference": _reference_value(reference),
        }
    )
    if len(raw) > MAX_REFERENCE_BYTES:
        raise CanonicalValueError("receipt reference exceeds its byte limit")
    return raw


def parse_reference(raw: bytes | None) -> ReceiptReference | PlumbingFailure:
    """Parse a bounded canonical receipt reference."""

    if raw is None:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
        )
    try:
        value = loads_bounded(
            raw,
            max_bytes=MAX_REFERENCE_BYTES,
            reject_duplicate_keys=True,
        )
        validate_json_value(value)
        obj = _closed_dict(
            value,
            frozenset({"schema", "schema_version", "reference"}),
        )
        if (
            obj["schema"] != REFERENCE_SCHEMA
            or obj["schema_version"] != REFERENCE_SCHEMA_VERSION
        ):
            raise ValueError("unsupported reference schema")
        reference = _parse_reference_value(obj["reference"])
        if canonical_bytes(value) != raw:
            raise ValueError("reference is not canonical")
        return reference
    except (
        CanonicalValueError,
        JsonBudgetExceededError,
        UnicodeError,
        ValueError,
    ):
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_RECEIPT_REFERENCE,
        )


def snapshot_from_static_verification(
    verified: StaticallyVerifiedReceipt,
) -> RuntimeReceiptSnapshot:
    """Build the only Stage 2 snapshot: an exact, non-authorizing static match."""

    if not isinstance(verified, StaticallyVerifiedReceipt):
        raise TypeError("verified must be StaticallyVerifiedReceipt")
    require_authority_invariant(verified, StaticallyVerifiedReceipt)
    if verified.reason_codes != (
        ReasonCode.PROFILE_UNSUPPORTED,
        ReasonCode.LIVE_CONTRACT_MISSING,
    ):
        raise ValueError("static verification authority ceiling changed")
    reference = reference_from_receipt(verified.receipt)
    if isinstance(reference, PlumbingFailure):
        raise ValueError("verified receipt could not produce a reference")
    return RuntimeReceiptSnapshot(reference=reference, receipt=verified.receipt)


def _snapshot_identity_value(
    reference: ReceiptReference,
) -> dict[str, object]:
    return {
        "state": reference.state.value,
        "profile_id": reference.profile_id.value,
        "stable_identity_sha256": reference.stable_identity_sha256.value,
        "launch_instance_sha256": reference.launch_instance_sha256.value,
        "process_corroboration_sha256": (reference.process_corroboration_sha256.value),
    }


def _snapshot_binding_value(
    reference: ReceiptReference,
) -> dict[str, object]:
    return {
        "launch_binding_sha256": reference.launch_binding_sha256.value,
        "receipt_sha256": reference.receipt_sha256.value,
        "launch_nonce": reference.launch_nonce.value,
        "session_pid": reference.session_pid.text,
        "session_starttime_ticks": reference.session_starttime_ticks.text,
    }


def _snapshot_value(snapshot: RuntimeReceiptSnapshot) -> dict[str, object]:
    value = {
        "schema": SNAPSHOT_SCHEMA,
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "receipt": to_json_value(snapshot.receipt),
    }
    value.update(_snapshot_identity_value(snapshot.reference))
    value.update(_snapshot_binding_value(snapshot.reference))
    return value


_SNAPSHOT_ENVELOPE_KEYS = frozenset({"schema", "schema_version", "receipt"})
_SNAPSHOT_IDENTITY_KEYS = frozenset(
    {
        "state",
        "profile_id",
        "stable_identity_sha256",
        "launch_instance_sha256",
        "process_corroboration_sha256",
    }
)
_SNAPSHOT_BINDING_KEYS = frozenset(
    {
        "launch_binding_sha256",
        "receipt_sha256",
        "launch_nonce",
        "session_pid",
        "session_starttime_ticks",
    }
)
_SNAPSHOT_KEYS = (
    _SNAPSHOT_ENVELOPE_KEYS | _SNAPSHOT_IDENTITY_KEYS | _SNAPSHOT_BINDING_KEYS
)


def serialize_snapshot(snapshot: RuntimeReceiptSnapshot) -> bytes:
    """Serialize a non-authorizing run-snapshot model."""

    if not isinstance(snapshot, RuntimeReceiptSnapshot):
        raise TypeError("snapshot must be RuntimeReceiptSnapshot")
    require_authority_invariant(snapshot, RuntimeReceiptSnapshot)
    raw = canonical_bytes(_snapshot_value(snapshot))
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise CanonicalValueError("receipt snapshot exceeds its byte limit")
    return raw


def parse_snapshot(
    raw: bytes | None,
    *,
    profiles: ProfileStore,
    expected: ExpectedBinding,
    now: datetime,
) -> RuntimeReceiptSnapshot | PlumbingFailure:
    """Parse a strict snapshot using only explicit static-verifier context."""

    if raw is None:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_COMPARATOR_INPUT,
        )
    try:
        value = loads_bounded(
            raw,
            max_bytes=MAX_SNAPSHOT_BYTES,
            reject_duplicate_keys=True,
        )
        validate_json_value(value)
        obj = _closed_dict(value, _SNAPSHOT_KEYS)
        if (
            obj["schema"] != SNAPSHOT_SCHEMA
            or obj["schema_version"] != SNAPSHOT_SCHEMA_VERSION
            or obj["state"] != ReceiptState.VERIFIED.value
        ):
            raise ValueError("unsupported snapshot schema or state")
        receipt_raw = canonical_bytes(cast(JsonValue, obj["receipt"]))
        if len(receipt_raw) > MAX_RECEIPT_BYTES:
            raise ValueError("nested receipt exceeds its byte limit")
        parsed = parse_receipt(receipt_raw)
        if isinstance(parsed, ReceiptRejection):
            raise ValueError("nested receipt is invalid")
        reference = _unchecked_reference(parsed)
        duplicates = {
            "profile_id": reference.profile_id.value,
            "stable_identity_sha256": reference.stable_identity_sha256.value,
            "launch_instance_sha256": reference.launch_instance_sha256.value,
            "launch_binding_sha256": reference.launch_binding_sha256.value,
            "process_corroboration_sha256": (
                reference.process_corroboration_sha256.value
            ),
            "receipt_sha256": reference.receipt_sha256.value,
            "launch_nonce": reference.launch_nonce.value,
            "session_pid": reference.session_pid.text,
            "session_starttime_ticks": reference.session_starttime_ticks.text,
        }
        if any(obj[key] != expected for key, expected in duplicates.items()):
            raise ValueError("snapshot duplicate field mismatch")
        if canonical_bytes(value) != raw:
            raise ValueError("snapshot is not canonical")
    except (
        CanonicalValueError,
        JsonBudgetExceededError,
        UnicodeError,
        ValueError,
    ):
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_COMPARATOR_INPUT,
        )
    try:
        token_bytes = bytes.fromhex(expected.token_hex)
    except ValueError:
        token_bytes = b""
    if (
        len(token_bytes) != 16
        or expected.token_hex != expected.token_hex.lower()
        or not token_commitment_matches(
            token_bytes,
            parsed.launch_binding.session_token_commitment_sha256,
        )
    ):
        return plumbing_failure(
            PlumbingDisposition.RECEIPT_REJECTED,
            PlumbingReason.STATIC_VERIFICATION_FAILED,
            source_reason_codes=(ReasonCode.RECEIPT_TOKEN_COMMITMENT_MISMATCH.value,),
        )
    verified = verify_receipt_static(
        parsed,
        profiles=profiles,
        expected=expected,
        now=now,
    )
    if isinstance(verified, ReceiptRejection):
        return plumbing_failure(
            PlumbingDisposition.RECEIPT_REJECTED,
            PlumbingReason.STATIC_VERIFICATION_FAILED,
            source_reason_codes=tuple(reason.value for reason in verified.reason_codes),
        )
    try:
        snapshot = snapshot_from_static_verification(verified)
    except AuthorityInvariantError:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.AUTHORITY_INVARIANT_VIOLATION,
        )
    invariant_failure = authority_invariant_failure(
        snapshot,
        RuntimeReceiptSnapshot,
    )
    return invariant_failure or snapshot


def _comparison_for_mismatch(
    mismatch: PlumbingFailure,
) -> ReceiptComparisonResult:
    reason = mismatch.reason_codes[0]
    if reason is PlumbingReason.INVALID_RECEIPT_REFERENCE:
        return ReceiptComparisonResult.REGISTRY_INVALID
    if reason is PlumbingReason.PROFILE_MISMATCH:
        return ReceiptComparisonResult.PROFILE_MISMATCH
    if reason is PlumbingReason.STABLE_IDENTITY_MISMATCH:
        return ReceiptComparisonResult.STABLE_IDENTITY_MISMATCH
    if reason is PlumbingReason.LAUNCH_NONCE_MISMATCH:
        return ReceiptComparisonResult.LAUNCH_NONCE_MISMATCH
    if reason in {
        PlumbingReason.DIGEST_MISMATCH,
        PlumbingReason.SIDECAR_DIGEST_MISMATCH,
    }:
        return ReceiptComparisonResult.DIGEST_MISMATCH
    if reason is PlumbingReason.STATE_NOT_FINAL:
        return ReceiptComparisonResult.STATE_NOT_FINAL
    return ReceiptComparisonResult.SESSION_BINDING_MISMATCH


def compare_receipt_snapshot(
    comparison: ReceiptComparatorInput,
) -> ReceiptComparisonResult:
    """Compare explicit state as a veto-only operation."""

    if not isinstance(comparison, ReceiptComparatorInput):
        raise TypeError("comparison must be ReceiptComparatorInput")
    if type(comparison) is not ReceiptComparatorInput:
        return ReceiptComparisonResult.METADATA_INVALID
    snapshot = comparison.metadata_snapshot
    current_reference = comparison.current_reference
    current_receipt = comparison.current_receipt
    if snapshot is None and current_reference is None and current_receipt is None:
        return ReceiptComparisonResult.ABSENT_BOTH
    if snapshot is None:
        return ReceiptComparisonResult.METADATA_INVALID
    if authority_invariant_failure(snapshot, RuntimeReceiptSnapshot) is not None:
        return ReceiptComparisonResult.AUTHORITY_INVALID
    if current_reference is None:
        return ReceiptComparisonResult.REGISTRY_INVALID
    if current_receipt is None:
        return ReceiptComparisonResult.RECEIPT_MISSING
    if current_reference.state is not ReceiptState.VERIFIED:
        return ReceiptComparisonResult.STATE_NOT_FINAL
    mismatch = reference_receipt_mismatch(current_reference, current_receipt)
    if mismatch is not None:
        return _comparison_for_mismatch(mismatch)
    expected = snapshot.reference
    if expected.profile_id != current_reference.profile_id:
        return ReceiptComparisonResult.PROFILE_MISMATCH
    if not _constant_time_sha_equal(
        expected.stable_identity_sha256,
        current_reference.stable_identity_sha256,
    ):
        return ReceiptComparisonResult.STABLE_IDENTITY_MISMATCH
    if expected.launch_nonce != current_reference.launch_nonce:
        return ReceiptComparisonResult.LAUNCH_NONCE_MISMATCH
    if (
        expected.session_id != current_reference.session_id
        or expected.launch_id != current_reference.launch_id
        or expected.session_pid != current_reference.session_pid
        or expected.session_starttime_ticks != current_reference.session_starttime_ticks
        or expected.boot_id != current_reference.boot_id
        or expected.pid_namespace_inode != current_reference.pid_namespace_inode
        or expected.launcher_euid != current_reference.launcher_euid
        or not _constant_time_sha_equal(
            expected.session_token_commitment_sha256,
            current_reference.session_token_commitment_sha256,
        )
    ):
        return ReceiptComparisonResult.SESSION_BINDING_MISMATCH
    for left, right in (
        (expected.launch_instance_sha256, current_reference.launch_instance_sha256),
        (expected.launch_binding_sha256, current_reference.launch_binding_sha256),
        (
            expected.process_corroboration_sha256,
            current_reference.process_corroboration_sha256,
        ),
        (expected.receipt_sha256, current_reference.receipt_sha256),
    ):
        if not _constant_time_sha_equal(left, right):
            return ReceiptComparisonResult.DIGEST_MISMATCH
    return ReceiptComparisonResult.MATCH_NON_AUTHORIZING


__all__ = [
    "MAX_POINTER_BYTES",
    "MAX_REFERENCE_BYTES",
    "MAX_SNAPSHOT_BYTES",
    "REFERENCE_SCHEMA",
    "REFERENCE_SCHEMA_VERSION",
    "SNAPSHOT_SCHEMA",
    "SNAPSHOT_SCHEMA_VERSION",
    "AuthorityInvariantError",
    "CanonicalPid",
    "CasApplied",
    "CleanupApplied",
    "ModeledPointer",
    "PlumbingDisposition",
    "PlumbingFailure",
    "PlumbingReason",
    "ReceiptComparatorInput",
    "ReceiptComparisonResult",
    "ReceiptReference",
    "ReceiptState",
    "ReceiptStateRecord",
    "RuntimeReceiptSnapshot",
    "SessionToken",
    "StoredReceipt",
    "TransitionApplied",
    "authority_invariant_failure",
    "compare_receipt_snapshot",
    "parse_reference",
    "parse_snapshot",
    "plumbing_failure",
    "reference_from_receipt",
    "reference_receipt_mismatch",
    "reference_transition_mismatch",
    "require_authority_invariant",
    "serialize_reference",
    "serialize_snapshot",
    "snapshot_from_static_verification",
    "token_commitment_from_bytes",
    "token_commitment_matches",
    "transition_state",
]
