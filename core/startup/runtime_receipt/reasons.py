"""Typed outcomes for runtime-receipt parsing and verification."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping


class VerificationDisposition(str, Enum):
    """High-level result classes returned by the pure verifier."""

    EXACT_MATCH = "exact_match"
    MISSING = "missing"
    PARTIAL = "partial"
    VERIFICATION_CONTEXT_MISSING = "verification_context_missing"
    STALE = "stale"
    VERSION_MISMATCH = "version_mismatch"
    PROFILE_MISMATCH = "profile_mismatch"
    PLATFORM_MISMATCH = "platform_mismatch"
    ARTIFACT_MISMATCH = "artifact_mismatch"
    SCHEMA_MISMATCH = "schema_mismatch"
    GRAMMAR_MISMATCH = "grammar_mismatch"
    MAPPED_IMAGE_MISMATCH = "mapped_image_mismatch"
    SESSION_BINDING_MISMATCH = "session_binding_mismatch"
    UNSUPPORTED_EVIDENCE = "unsupported_evidence"
    COPIED_OR_REPLAYED_LAUNCH_INSTANCE = "copied_or_replayed_launch_instance"
    DIGEST_MISMATCH = "digest_mismatch"
    MALFORMED = "malformed"


class ReasonCode(str, Enum):
    """Closed fail-closed vocabulary for schema v1."""

    RECEIPT_MISSING = "receipt_missing"
    RECEIPT_OVERSIZED = "receipt_oversized"
    RECEIPT_MALFORMED = "receipt_malformed"
    RECEIPT_DUPLICATE_KEY = "receipt_duplicate_key"
    RECEIPT_DEPTH_EXCEEDED = "receipt_depth_exceeded"
    RECEIPT_MEMBER_LIMIT_EXCEEDED = "receipt_member_limit_exceeded"
    RECEIPT_SCHEMA_UNSUPPORTED = "receipt_schema_unsupported"
    RECEIPT_VERSION_UNSUPPORTED = "receipt_version_unsupported"
    RECEIPT_PARTIAL = "receipt_partial"
    RECEIPT_DIGEST_MISMATCH = "receipt_digest_mismatch"
    RECEIPT_STATE_NOT_VERIFIED = "receipt_state_not_verified"
    EXPECTED_BINDING_MISSING = "expected_binding_missing"
    FRESHNESS_EVALUATION_MISSING = "freshness_evaluation_missing"
    RECEIPT_SESSION_BINDING_MISMATCH = "receipt_session_binding_mismatch"
    RECEIPT_TOKEN_COMMITMENT_MISMATCH = "receipt_token_commitment_mismatch"
    RECEIPT_TIMESTAMP_STALE = "receipt_timestamp_stale"
    RECEIPT_LAUNCH_INSTANCE_REPLAYED = "receipt_launch_instance_replayed"
    FRONTEND_MISMATCH = "frontend_mismatch"
    PLATFORM_UNSUPPORTED = "platform_unsupported"
    ARCHITECTURE_UNSUPPORTED = "architecture_unsupported"
    PATH_POLICY_VIOLATION = "path_policy_violation"
    SYMLINK_HOP_LIMIT = "symlink_hop_limit"
    EXECUTABLE_OPEN_FAILED = "executable_open_failed"
    EXECUTABLE_NOT_REGULAR = "executable_not_regular"
    EXECUTABLE_NOT_EXECUTABLE = "executable_not_executable"
    EXECUTABLE_OWNER_MISMATCH = "executable_owner_mismatch"
    EXECUTABLE_IDENTITY_MISMATCH = "executable_identity_mismatch"
    EXECUTABLE_HASH_MISMATCH = "executable_hash_mismatch"
    ELF_INVALID = "elf_invalid"
    ELF_INTERPRETER_MISSING = "elf_interpreter_missing"
    ELF_INTERPRETER_IDENTITY_MISMATCH = "elf_interpreter_identity_mismatch"
    DISTRIBUTION_UNRESOLVED = "distribution_unresolved"
    DISTRIBUTION_AMBIGUOUS = "distribution_ambiguous"
    DISTRIBUTION_SOURCE_FORBIDDEN = "distribution_source_forbidden"
    DISTRIBUTION_MANIFEST_MISMATCH = "distribution_manifest_mismatch"
    PACKAGE_MANIFEST_INVALID = "package_manifest_invalid"
    PACKAGE_NAME_MISMATCH = "package_name_mismatch"
    DISTRIBUTION_VERSION_MISMATCH = "distribution_version_mismatch"
    ARTIFACT_MISSING = "artifact_missing"
    ARTIFACT_IDENTITY_MISMATCH = "artifact_identity_mismatch"
    RUNTIME_IMAGE_MISMATCH = "runtime_image_mismatch"
    CLI_NATIVE_IMAGE_MISMATCH = "cli_native_image_mismatch"
    SCHEMA_HASH_MISMATCH = "schema_hash_mismatch"
    SCHEMA_INVENTORY_MISMATCH = "schema_inventory_mismatch"
    GRAMMAR_DIGEST_MISMATCH = "grammar_digest_mismatch"
    HELP_CONTRACT_DIGEST_MISMATCH = "help_contract_digest_mismatch"
    PROFILE_MISSING = "profile_missing"
    PROFILE_AMBIGUOUS = "profile_ambiguous"
    PROFILE_UNSUPPORTED = "profile_unsupported"
    PROFILE_REVOKED = "profile_revoked"
    PROFILE_DIGEST_MISMATCH = "profile_digest_mismatch"
    LIVE_CONTRACT_MISSING = "live_contract_missing"
    PROCESS_STAMP_MISMATCH = "process_stamp_mismatch"
    PROCESS_UID_MISMATCH = "process_uid_mismatch"
    MAPPED_IMAGE_UNAVAILABLE = "mapped_image_unavailable"
    MAPPED_IMAGE_MISMATCH = "mapped_image_mismatch"
    MAPPED_RUNTIME_IMAGE_UNAVAILABLE = "mapped_runtime_image_unavailable"
    MAPPED_RUNTIME_IMAGE_MISMATCH = "mapped_runtime_image_mismatch"
    MAPPED_NATIVE_IMAGE_UNEXPECTED = "mapped_native_image_unexpected"
    MAPPED_DEVICE_UNVERIFIABLE = "mapped_device_unverifiable"
    MAPPED_EVIDENCE_UNSUPPORTED = "mapped_evidence_unsupported"
    MAPPED_DISK_DIVERGENCE = "mapped_disk_divergence"
    REEXEC_UNVERIFIED = "reexec_unverified"
    OWNERSHIP_TOKEN_MISMATCH = "ownership_token_mismatch"
    OWNERSHIP_REGISTRY_MISMATCH = "ownership_registry_mismatch"
    OWNERSHIP_CHANGED = "ownership_changed"
    RESUME_RUNTIME_IDENTITY_MISMATCH = "resume_runtime_identity_mismatch"
    EVENT_PROFILE_MISMATCH = "event_profile_mismatch"
    EVENT_SCHEMA_MISMATCH = "event_schema_mismatch"
    EVENT_AUTHORIZATION_ESCALATION = "event_authorization_escalation"
    EVENT_TRANSPORT_UNSUPPORTED = "event_transport_unsupported"


def _empty_details() -> Mapping[str, str]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class ReceiptRejection:
    """A bounded, typed denial result.

    ``details`` is diagnostic-only and intentionally limited to short identifiers,
    hashes, and numeric identities by the constructors in this package.
    """

    disposition: VerificationDisposition
    reason_codes: tuple[ReasonCode, ...]
    details: Mapping[str, str] = field(default_factory=_empty_details)

    def __post_init__(self) -> None:
        if not self.reason_codes:
            raise ValueError("ReceiptRejection requires at least one reason code")
        if len(self.reason_codes) > 32:
            raise ValueError("ReceiptRejection exceeds the 32-code limit")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("ReceiptRejection reason codes must be unique")
        bounded: dict[str, str] = {}
        for key, value in self.details.items():
            if len(key) > 128 or len(value) > 256:
                raise ValueError("ReceiptRejection detail exceeds its bound")
            if not key.isascii() or not key.isprintable():
                raise ValueError("ReceiptRejection detail key is not printable ASCII")
            if not value.isprintable():
                raise ValueError("ReceiptRejection detail value is not printable")
            bounded[key] = value
        object.__setattr__(self, "details", MappingProxyType(bounded))


def rejection(
    disposition: VerificationDisposition,
    *codes: ReasonCode,
    details: Mapping[str, str] | None = None,
) -> ReceiptRejection:
    """Build a rejection while preserving the first occurrence of each code."""

    unique = tuple(dict.fromkeys(codes))
    return ReceiptRejection(
        disposition=disposition,
        reason_codes=unique,
        details=details or {},
    )
