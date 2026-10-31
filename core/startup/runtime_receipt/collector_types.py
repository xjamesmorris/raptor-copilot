"""Immutable, non-authorizing types for offline runtime evidence collection."""

from __future__ import annotations

import errno
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Literal, Mapping

from .schema import (
    AbsolutePath,
    ArtifactName,
    DeviceMajorMinor,
    Endianness,
    FormatId,
    SchemaDocumentName,
    Sha1,
    Sha256,
    VersionText,
)

COLLECTOR_SCHEMA = "raptor.runtime_receipt_collector/v1"
COLLECTOR_SCHEMA_VERSION = 1
MAX_HELD_DESCRIPTORS = 33


class CollectionDisposition(str, Enum):
    INVALID_REQUEST = "invalid_request"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    UNAVAILABLE = "unavailable"
    POLICY_REJECTED = "policy_rejected"
    LIMIT_EXCEEDED = "limit_exceeded"
    MALFORMED_INPUT = "malformed_input"
    CHANGED_DURING_COLLECTION = "changed_during_collection"
    INCOMPLETE = "incomplete"
    AMBIGUOUS = "ambiguous"
    MISMATCH = "mismatch"


class CollectionReasonCode(str, Enum):
    INVALID_PATH = "invalid_path"
    INVALID_RELATIVE_PATH = "invalid_relative_path"
    INVALID_ROLE_SET = "invalid_role_set"
    DUPLICATE_ARTIFACT_ROLE = "duplicate_artifact_role"
    DUPLICATE_CONTRACT_INPUT = "duplicate_contract_input"
    TRUSTED_SCOPE_INVALID = "trusted_scope_invalid"

    PLATFORM_UNSUPPORTED = "platform_unsupported"
    OS_PRIMITIVE_UNAVAILABLE = "os_primitive_unavailable"
    ELF_LAYOUT_UNSUPPORTED = "elf_layout_unsupported"
    ELF_MACHINE_UNSUPPORTED = "elf_machine_unsupported"
    ELF_TYPE_UNSUPPORTED = "elf_type_unsupported"
    ELF_BUILD_ID_UNSUPPORTED = "elf_build_id_unsupported"

    RESOURCE_NOT_FOUND = "resource_not_found"
    PERMISSION_DENIED = "permission_denied"
    IO_ERROR = "io_error"
    PROC_MAPS_UNAVAILABLE = "proc_maps_unavailable"
    MOUNTINFO_UNAVAILABLE = "mountinfo_unavailable"
    PROC_EXE_UNAVAILABLE = "proc_exe_unavailable"

    PATH_POLICY_VIOLATION = "path_policy_violation"
    OWNER_MISMATCH = "owner_mismatch"
    UNSAFE_MODE = "unsafe_mode"
    NOT_REGULAR = "not_regular"
    NOT_EXECUTABLE = "not_executable"
    LINK_COUNT_INVALID = "link_count_invalid"

    SIZE_LIMIT_EXCEEDED = "size_limit_exceeded"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    ENTRY_LIMIT_EXCEEDED = "entry_limit_exceeded"
    DEPTH_LIMIT_EXCEEDED = "depth_limit_exceeded"
    TOTAL_BYTE_LIMIT_EXCEEDED = "total_byte_limit_exceeded"
    PROC_MAPS_LIMIT_EXCEEDED = "proc_maps_limit_exceeded"
    MOUNTINFO_LIMIT_EXCEEDED = "mountinfo_limit_exceeded"

    SHORT_READ = "short_read"
    PACKAGE_MANIFEST_INVALID = "package_manifest_invalid"
    ELF_INVALID = "elf_invalid"
    ELF_BOUNDS_INVALID = "elf_bounds_invalid"
    ELF_INTERPRETER_PATH_INVALID = "elf_interpreter_path_invalid"
    ELF_NOTE_MALFORMED = "elf_note_malformed"
    PROC_MAPS_MALFORMED = "proc_maps_malformed"
    PROC_STAT_MALFORMED = "proc_stat_malformed"
    MOUNTINFO_MALFORMED = "mountinfo_malformed"
    PATHNAME_ESCAPE_UNSUPPORTED = "pathname_escape_unsupported"

    FILE_MUTATED = "file_mutated"
    PATH_REPLACED = "path_replaced"
    ANCESTOR_REPLACED = "ancestor_replaced"
    DISTRIBUTION_TREE_CHANGED = "distribution_tree_changed"
    PROCESS_CHANGED = "process_changed"

    ARTIFACT_MISSING = "artifact_missing"
    SCHEMA_MISSING = "schema_missing"
    ELF_INTERPRETER_MISSING = "elf_interpreter_missing"
    EMBEDDED_PAYLOAD_MISSING = "embedded_payload_missing"
    MAPPED_MODULE_MISSING = "mapped_module_missing"
    MAPPED_MODULE_NOT_EXECUTABLE = "mapped_module_not_executable"

    ELF_INTERPRETER_AMBIGUOUS = "elf_interpreter_ambiguous"
    EMBEDDED_PAYLOAD_AMBIGUOUS = "embedded_payload_ambiguous"
    MOUNT_AMBIGUOUS = "mount_ambiguous"
    MAPPED_MODULE_AMBIGUOUS = "mapped_module_ambiguous"

    ARTIFACT_FORMAT_MISMATCH = "artifact_format_mismatch"
    PACKAGE_IDENTITY_MISMATCH = "package_identity_mismatch"
    DISTRIBUTION_VERSION_MISMATCH = "distribution_version_mismatch"
    SCHEMA_DIGEST_MISMATCH = "schema_digest_mismatch"
    TRUSTED_DIGEST_INPUT_INVALID = "trusted_digest_input_invalid"
    PROCESS_SCOPE_MISMATCH = "process_scope_mismatch"
    MAPPED_DEVICE_UNVERIFIABLE = "mapped_device_unverifiable"
    MAPPED_FILE_DELETED = "mapped_file_deleted"
    MAPPED_MODULE_IDENTITY_MISMATCH = "mapped_module_identity_mismatch"
    MAPPED_NATIVE_IMAGE_UNEXPECTED = "mapped_native_image_unexpected"


class EvidenceTier(str, Enum):
    DESCRIPTOR_STRONG = "descriptor_strong"
    TRUSTED_RECORD = "trusted_record"
    PROCFS_CORROBORATED = "procfs_corroborated"
    DIAGNOSTIC_ONLY = "diagnostic_only"
    UNSUPPORTED = "unsupported"


class EvidenceSubject(str, Enum):
    REQUEST = "request"
    FILE = "file"
    FRONTEND = "frontend"
    ELF = "elf"
    INTERPRETER = "interpreter"
    DISTRIBUTION = "distribution"
    PACKAGE = "package"
    ARTIFACT = "artifact"
    SCHEMA = "schema"
    CONTRACT = "contract"
    PROCESS = "process"
    PROC_STAT = "proc_stat"
    PROC_MAPS = "proc_maps"
    MOUNTINFO = "mountinfo"
    PROC_EXE = "proc_exe"


class FileRole(str, Enum):
    FRONTEND_EXECUTABLE = "frontend_executable"
    ELF_INTERPRETER = "elf_interpreter"
    PACKAGE_MANIFEST = "package_manifest"
    DISTRIBUTION_ARTIFACT = "distribution_artifact"
    CONTRACT_INPUT = "contract_input"
    PROC_EXE = "proc_exe"


class PathPolicyId(str, Enum):
    DIRECT_REGULAR_NO_SYMLINK_V1 = "direct-regular-no-symlink-v1"
    DISTRIBUTION_REGULAR_NO_SYMLINK_V1 = "distribution-regular-no-symlink-v1"
    RESOLVED_INTERPRETER_V1 = "resolved-interpreter-v1"
    PROC_EXE_MAGICLINK_V1 = "proc-exe-magiclink-v1"


class PathBindingState(str, Enum):
    STABLE = "stable"
    MISSING_AFTER_OPEN = "missing_after_open"
    REPLACED_AFTER_OPEN = "replaced_after_open"
    ANCESTOR_REPLACED = "ancestor_replaced"


class CollectorElfClass(str, Enum):
    ELF32 = "ELF32"
    ELF64 = "ELF64"


class MappedObjectRole(str, Enum):
    LOADER = "loader"
    RUNTIME_NODE = "runtime.node"
    CLI_NATIVE_NODE = "cli-native.node"


class ProcMapKind(str, Enum):
    ANONYMOUS = "anonymous"
    SPECIAL = "special"
    FILE = "file"
    OTHER = "other"


class SafeDetailKey(str, Enum):
    STAGE = "stage"
    ROLE = "role"
    LIMIT = "limit"
    COUNT = "count"
    BYTES = "bytes"
    PID = "pid"
    ERRNO_CLASS = "errno_class"
    PATH_SHA256 = "path_sha256"
    EXPECTED_SHA256 = "expected_sha256"
    OBSERVED_SHA256 = "observed_sha256"


_REASONS_BY_DISPOSITION = {
    CollectionDisposition.INVALID_REQUEST: frozenset(
        {
            CollectionReasonCode.INVALID_PATH,
            CollectionReasonCode.INVALID_RELATIVE_PATH,
            CollectionReasonCode.INVALID_ROLE_SET,
            CollectionReasonCode.DUPLICATE_ARTIFACT_ROLE,
            CollectionReasonCode.DUPLICATE_CONTRACT_INPUT,
            CollectionReasonCode.TRUSTED_SCOPE_INVALID,
        }
    ),
    CollectionDisposition.UNSUPPORTED_PLATFORM: frozenset(
        {
            CollectionReasonCode.PLATFORM_UNSUPPORTED,
            CollectionReasonCode.OS_PRIMITIVE_UNAVAILABLE,
            CollectionReasonCode.ELF_LAYOUT_UNSUPPORTED,
            CollectionReasonCode.ELF_MACHINE_UNSUPPORTED,
            CollectionReasonCode.ELF_TYPE_UNSUPPORTED,
            CollectionReasonCode.ELF_BUILD_ID_UNSUPPORTED,
        }
    ),
    CollectionDisposition.UNAVAILABLE: frozenset(
        {
            CollectionReasonCode.RESOURCE_NOT_FOUND,
            CollectionReasonCode.PERMISSION_DENIED,
            CollectionReasonCode.IO_ERROR,
            CollectionReasonCode.PROC_MAPS_UNAVAILABLE,
            CollectionReasonCode.MOUNTINFO_UNAVAILABLE,
            CollectionReasonCode.PROC_EXE_UNAVAILABLE,
        }
    ),
    CollectionDisposition.POLICY_REJECTED: frozenset(
        {
            CollectionReasonCode.PATH_POLICY_VIOLATION,
            CollectionReasonCode.OWNER_MISMATCH,
            CollectionReasonCode.UNSAFE_MODE,
            CollectionReasonCode.NOT_REGULAR,
            CollectionReasonCode.NOT_EXECUTABLE,
            CollectionReasonCode.LINK_COUNT_INVALID,
        }
    ),
    CollectionDisposition.LIMIT_EXCEEDED: frozenset(
        {
            CollectionReasonCode.SIZE_LIMIT_EXCEEDED,
            CollectionReasonCode.DEADLINE_EXCEEDED,
            CollectionReasonCode.ENTRY_LIMIT_EXCEEDED,
            CollectionReasonCode.DEPTH_LIMIT_EXCEEDED,
            CollectionReasonCode.TOTAL_BYTE_LIMIT_EXCEEDED,
            CollectionReasonCode.PROC_MAPS_LIMIT_EXCEEDED,
            CollectionReasonCode.MOUNTINFO_LIMIT_EXCEEDED,
        }
    ),
    CollectionDisposition.MALFORMED_INPUT: frozenset(
        {
            CollectionReasonCode.SHORT_READ,
            CollectionReasonCode.PACKAGE_MANIFEST_INVALID,
            CollectionReasonCode.ELF_INVALID,
            CollectionReasonCode.ELF_BOUNDS_INVALID,
            CollectionReasonCode.ELF_INTERPRETER_PATH_INVALID,
            CollectionReasonCode.ELF_NOTE_MALFORMED,
            CollectionReasonCode.PROC_MAPS_MALFORMED,
            CollectionReasonCode.PROC_STAT_MALFORMED,
            CollectionReasonCode.MOUNTINFO_MALFORMED,
            CollectionReasonCode.PATHNAME_ESCAPE_UNSUPPORTED,
        }
    ),
    CollectionDisposition.CHANGED_DURING_COLLECTION: frozenset(
        {
            CollectionReasonCode.FILE_MUTATED,
            CollectionReasonCode.PATH_REPLACED,
            CollectionReasonCode.ANCESTOR_REPLACED,
            CollectionReasonCode.DISTRIBUTION_TREE_CHANGED,
            CollectionReasonCode.PROCESS_CHANGED,
        }
    ),
    CollectionDisposition.INCOMPLETE: frozenset(
        {
            CollectionReasonCode.ARTIFACT_MISSING,
            CollectionReasonCode.SCHEMA_MISSING,
            CollectionReasonCode.ELF_INTERPRETER_MISSING,
            CollectionReasonCode.EMBEDDED_PAYLOAD_MISSING,
            CollectionReasonCode.MAPPED_MODULE_MISSING,
            CollectionReasonCode.MAPPED_MODULE_NOT_EXECUTABLE,
        }
    ),
    CollectionDisposition.AMBIGUOUS: frozenset(
        {
            CollectionReasonCode.ELF_INTERPRETER_AMBIGUOUS,
            CollectionReasonCode.EMBEDDED_PAYLOAD_AMBIGUOUS,
            CollectionReasonCode.MOUNT_AMBIGUOUS,
            CollectionReasonCode.MAPPED_MODULE_AMBIGUOUS,
        }
    ),
    CollectionDisposition.MISMATCH: frozenset(
        {
            CollectionReasonCode.ARTIFACT_FORMAT_MISMATCH,
            CollectionReasonCode.PACKAGE_IDENTITY_MISMATCH,
            CollectionReasonCode.DISTRIBUTION_VERSION_MISMATCH,
            CollectionReasonCode.SCHEMA_DIGEST_MISMATCH,
            CollectionReasonCode.TRUSTED_DIGEST_INPUT_INVALID,
            CollectionReasonCode.PROCESS_SCOPE_MISMATCH,
            CollectionReasonCode.MAPPED_DEVICE_UNVERIFIABLE,
            CollectionReasonCode.MAPPED_FILE_DELETED,
            CollectionReasonCode.MAPPED_MODULE_IDENTITY_MISMATCH,
            CollectionReasonCode.MAPPED_NATIVE_IMAGE_UNEXPECTED,
        }
    ),
}
_REASON_ORDER = {reason: index for index, reason in enumerate(CollectionReasonCode)}
_SAFE_DETAIL_KEYS = frozenset(item.value for item in SafeDetailKey)


def _empty_details() -> Mapping[str, str]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class DescriptorStat:
    device: int
    inode: int
    mode_octal: str
    uid: int
    gid: int
    size_bytes: int
    nlink: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True, slots=True)
class DescriptorIdentity:
    stat: DescriptorStat
    sha256: str
    format_id: FormatId
    elf_build_id_sha1: str | None
    bytes_hashed: int


@dataclass(frozen=True, slots=True)
class PathComponentObservation:
    absolute_path: AbsolutePath
    component_index: int
    file_type: Literal["directory", "regular", "symlink"]
    device: int
    inode: int
    uid: int
    gid: int
    mode_octal: str
    link_text_sha256: str | None


@dataclass(frozen=True, slots=True)
class PathObservation:
    requested_path: AbsolutePath
    resolved_path: AbsolutePath
    policy_id: PathPolicyId
    components: tuple[PathComponentObservation, ...]
    binding_state: PathBindingState
    asserted_prefix_components: int

    def __post_init__(self) -> None:
        if self.binding_state is not PathBindingState.STABLE:
            raise ValueError("successful path observations must be stable")
        if self.asserted_prefix_components < 0:
            raise ValueError("asserted prefix count cannot be negative")


@dataclass(frozen=True, slots=True)
class FileEvidence:
    role: FileRole
    descriptor: DescriptorIdentity
    path: PathObservation
    evidence_tier: EvidenceTier = EvidenceTier.DESCRIPTOR_STRONG

    def __post_init__(self) -> None:
        if self.evidence_tier is not EvidenceTier.DESCRIPTOR_STRONG:
            raise ValueError("file evidence must be descriptor-strong")


@dataclass(frozen=True, slots=True)
class CollectionFailure:
    disposition: CollectionDisposition
    reason_codes: tuple[CollectionReasonCode, ...]
    subject: EvidenceSubject
    details: Mapping[str, str] = field(default_factory=_empty_details)
    partial_descriptor: DescriptorIdentity | None = None
    path_binding_state: PathBindingState | None = None

    def __post_init__(self) -> None:
        reasons = tuple(
            sorted(set(self.reason_codes), key=lambda item: _REASON_ORDER[item])
        )
        if not reasons or len(reasons) > 32:
            raise ValueError("collection failure requires 1..32 reason codes")
        allowed = _REASONS_BY_DISPOSITION[self.disposition]
        if any(reason not in allowed for reason in reasons):
            raise ValueError("reason code is invalid for collection disposition")
        bounded: dict[str, str] = {}
        for key, value in self.details.items():
            if key not in _SAFE_DETAIL_KEYS:
                raise ValueError("collection failure detail key is not allowed")
            if (
                len(key.encode("ascii", errors="ignore")) != len(key)
                or not key.isprintable()
                or len(key) > 64
            ):
                raise ValueError("collection failure detail key is invalid")
            if (
                len(value.encode("ascii", errors="ignore")) != len(value)
                or not value.isprintable()
                or len(value) > 128
            ):
                raise ValueError("collection failure detail value is invalid")
            bounded[key] = value
        if len(bounded) > 16:
            raise ValueError("collection failure has too many detail entries")
        object.__setattr__(self, "reason_codes", reasons)
        object.__setattr__(self, "details", MappingProxyType(bounded))


@dataclass(frozen=True, slots=True)
class CollectorLimits:
    absolute_path_bytes: int = 4096
    absolute_path_components: int = 256
    path_component_bytes: int = 255
    relative_path_components: int = 16
    hash_chunk_bytes: int = 1_048_576
    generic_file_bytes: int = 268_435_456
    tree_entries: int = 4096
    tree_depth: int = 16
    tree_total_regular_bytes: int = 536_870_912
    artifact_requests_hard_max: int = 16
    file_deadline_seconds: float = 30.0
    distribution_deadline_seconds: float = 120.0
    max_held_descriptors: int = MAX_HELD_DESCRIPTORS


@dataclass(frozen=True, slots=True)
class ElfLimits:
    program_headers: int = 1024
    program_header_table_bytes: int = 1_048_576
    interpreter_bytes: int = 4096
    note_count: int = 256
    note_bytes: int = 1_048_576


@dataclass(frozen=True, slots=True)
class ProcfsLimits:
    maps_bytes: int = 8_388_608
    maps_lines: int = 8192
    maps_line_bytes: int = 16_384
    mountinfo_bytes: int = 4_194_304
    mountinfo_lines: int = 4096
    mountinfo_line_bytes: int = 16_384
    unique_mapped_files: int = 256
    mapping_segments_per_file: int = 128
    comm_bytes: int = 64
    proc_deadline_seconds: float = 2.0
    file_deadline_seconds: float = 30.0


DEFAULT_COLLECTOR_LIMITS = CollectorLimits()
DEFAULT_ELF_LIMITS = ElfLimits()
DEFAULT_PROCFS_LIMITS = ProcfsLimits()


@dataclass(frozen=True, slots=True)
class MonotonicDeadline:
    expires_at: float

    @classmethod
    def after(cls, seconds: float) -> "MonotonicDeadline":
        if seconds <= 0:
            raise ValueError("deadline duration must be positive")
        return cls(time.monotonic() + seconds)

    def expired(self) -> bool:
        return time.monotonic() >= self.expires_at


@dataclass(frozen=True, slots=True)
class FileCollectionRequest:
    role: FileRole
    absolute_path: AbsolutePath
    expected_owner_uid: int
    allow_root_owner: bool
    require_executable: bool
    policy_id: PathPolicyId
    max_bytes: int
    format_id: FormatId = FormatId.OPAQUE


@dataclass(frozen=True, slots=True)
class ElfInterpreterPresent:
    path: AbsolutePath
    offset: int
    size_bytes: int


@dataclass(frozen=True, slots=True)
class ElfInterpreterAbsent:
    present: Literal[False] = False

    def __post_init__(self) -> None:
        if self.present is not False:
            raise ValueError("absent interpreter marker must be false")


@dataclass(frozen=True, slots=True)
class ElfInspection:
    elf_class: CollectorElfClass
    endianness: Endianness
    osabi: int
    elf_type: int
    machine: int
    program_header_count: int
    interpreter: ElfInterpreterPresent | ElfInterpreterAbsent
    build_id_sha1: Sha1 | None
    format_id: FormatId | None


@dataclass(frozen=True, slots=True)
class ArtifactRequest:
    role: ArtifactName
    relative_path: str
    expected_format: FormatId
    max_bytes: int


@dataclass(frozen=True, slots=True)
class TrustedSchemaInventoryInput:
    name: SchemaDocumentName
    source_record_sha256: Sha256
    expected_file_sha256: Sha256
    definition_count: int
    property_count: int
    event_type_literal_count: int
    event_variant_count: int | None
    definition_names_sha256: Sha256
    property_names_sha256: Sha256
    event_type_literals_sha256: Sha256


@dataclass(frozen=True, slots=True)
class TrustedGrammarDigestInput:
    source_record_sha256: Sha256
    source: str
    sha256: Sha256
    root_flag_count: int
    advertised_root_flag_count: int
    hidden_root_flag_count: int


@dataclass(frozen=True, slots=True)
class TrustedHelpContractDigestInput:
    source_record_sha256: Sha256
    manifest_algorithm: str
    manifest_sha256: Sha256
    surface_count: int


@dataclass(frozen=True, slots=True)
class TrustedDistributionRequest:
    source_directory: AbsolutePath
    expected_owner_uid: int
    expected_package_name: str
    expected_version: VersionText
    expected_package_type: str
    expected_bin_name: str
    expected_bin_target: str
    platform_directory: str
    artifacts: tuple[ArtifactRequest, ...]
    schemas: tuple[TrustedSchemaInventoryInput, ...]
    grammar: TrustedGrammarDigestInput
    help_contract: TrustedHelpContractDigestInput
    anchor_fd: int | None = None
    anchor_path: AbsolutePath | None = None


@dataclass(frozen=True, slots=True)
class PackageManifestObservation:
    file: FileEvidence
    name: str
    version: VersionText
    package_type: str
    bin_name: str
    bin_target: str


@dataclass(frozen=True, slots=True)
class ArtifactEvidence:
    name: ArtifactName
    file: FileEvidence


@dataclass(frozen=True, slots=True)
class SchemaEvidence:
    name: SchemaDocumentName
    file: FileEvidence
    source_record_sha256: Sha256
    definition_count: int
    property_count: int
    event_type_literal_count: int
    event_variant_count: int | None
    definition_names_sha256: Sha256
    property_names_sha256: Sha256
    event_type_literals_sha256: Sha256
    evidence_tier: EvidenceTier = EvidenceTier.TRUSTED_RECORD

    def __post_init__(self) -> None:
        if self.evidence_tier is not EvidenceTier.TRUSTED_RECORD:
            raise ValueError("schema inventory evidence must be a trusted record")


@dataclass(frozen=True, slots=True)
class TreeEntryObservation:
    entry_type: Literal["f", "d"]
    mode_octal: str
    size_bytes: int
    sha256: str
    relative_path: str


@dataclass(frozen=True, slots=True)
class TreeManifestObservation:
    algorithm: Literal["sha256-tree-v1"]
    sha256: Sha256
    entry_count: int
    total_regular_file_bytes: int
    rows: tuple[TreeEntryObservation, ...]


@dataclass(frozen=True, slots=True)
class ObservedDistributionSource:
    root: PathObservation
    seal_performed: Literal[False] = False

    def __post_init__(self) -> None:
        if self.seal_performed is not False:
            raise ValueError("the offline collector never seals a distribution")


@dataclass(frozen=True, slots=True)
class DistributionEvidence:
    source: ObservedDistributionSource
    version: VersionText
    platform_directory: str
    package_manifest: PackageManifestObservation
    artifacts: tuple[ArtifactEvidence, ...]
    schemas: tuple[SchemaEvidence, ...]
    grammar: TrustedGrammarDigestInput
    help_contract: TrustedHelpContractDigestInput
    content_manifest: TreeManifestObservation
    files_hashed: int
    bytes_hashed: int


@dataclass(frozen=True, slots=True)
class EmbeddedPayloadObservation:
    offset: int
    sha256: Sha256
    match_count: Literal[1] = 1

    def __post_init__(self) -> None:
        if self.offset < 0 or self.match_count != 1:
            raise ValueError("embedded payload observation must be one exact match")


@dataclass(frozen=True, slots=True)
class ResolvedInterpreterEvidence:
    requested_path: AbsolutePath
    file: FileEvidence
    symlink_chain: tuple[PathComponentObservation, ...]


@dataclass(frozen=True, slots=True)
class OfflineRuntimeCollectionRequest:
    frontend: FileCollectionRequest
    distribution: TrustedDistributionRequest
    interpreter_expected_owner_uid: int
    interpreter_allow_root_owner: bool = True
    anchor_fd: int | None = None
    anchor_path: AbsolutePath | None = None


@dataclass(frozen=True, slots=True)
class OperationCounters:
    files_hashed: int
    bytes_hashed: int
    tree_entries: int
    maximum_held_descriptors: int


@dataclass(frozen=True, slots=True)
class OfflineRuntimeEvidence:
    collector_schema: str
    collector_schema_version: int
    frontend: FileEvidence
    frontend_elf: ElfInspection
    interpreter: ResolvedInterpreterEvidence
    interpreter_elf: ElfInspection
    distribution: DistributionEvidence
    embedded_sea_loader: EmbeddedPayloadObservation
    counters: OperationCounters

    def __post_init__(self) -> None:
        if (
            self.collector_schema != COLLECTOR_SCHEMA
            or self.collector_schema_version != COLLECTOR_SCHEMA_VERSION
        ):
            raise ValueError("collector schema marker mismatch")


@dataclass(frozen=True, slots=True)
class ProcStatObservation:
    pid: int
    comm: bytes
    state: str
    parent_pid: int
    starttime_ticks: int


@dataclass(frozen=True, slots=True)
class ProcMapRow:
    start: int
    end: int
    perms: str
    offset: int
    major: int
    minor: int
    inode: int
    pathname: bytes | None
    deleted: bool
    kind: ProcMapKind


@dataclass(frozen=True, slots=True)
class ParsedProcMaps:
    rows: tuple[ProcMapRow, ...]
    byte_count: int
    line_count: int
    sha256: Sha256


@dataclass(frozen=True, slots=True)
class MountInfoRow:
    mount_id: int
    parent_id: int
    major: int
    minor: int
    root: bytes
    mount_point: bytes
    filesystem_type: str


@dataclass(frozen=True, slots=True)
class ParsedMountInfo:
    rows: tuple[MountInfoRow, ...]
    byte_count: int
    line_count: int
    sha256: Sha256


@dataclass(frozen=True, slots=True)
class TrustedProcessScope:
    pid: int
    expected_starttime_ticks: int
    expected_euid: int
    expected_pid_namespace_inode: int
    expected_mount_namespace_inode: int


@dataclass(frozen=True, slots=True)
class ExpectedMappedObject:
    role: MappedObjectRole
    trusted_file: FileEvidence
    anchor_fd: int | None = None
    anchor_path: AbsolutePath | None = None


@dataclass(frozen=True, slots=True)
class ExpectedMappedObjects:
    loader: ExpectedMappedObject
    native_modules: tuple[ExpectedMappedObject, ExpectedMappedObject]
    distribution_root: PathObservation


@dataclass(frozen=True, slots=True)
class MappingSegmentObservation:
    start: int
    end: int
    offset: int
    perms: str


@dataclass(frozen=True, slots=True)
class MappedObjectEvidence:
    role: MappedObjectRole
    observed_path: AbsolutePath
    mapped_inode: int
    maps_device: DeviceMajorMinor
    mount_device: DeviceMajorMinor
    mount_id: int
    parent_mount_id: int
    fdinfo_mount_id: int | None
    filesystem_type: str
    executable_mapping: bool
    deleted: bool
    segments: tuple[MappingSegmentObservation, ...]
    evidence_tier: EvidenceTier = EvidenceTier.PROCFS_CORROBORATED

    def __post_init__(self) -> None:
        if self.evidence_tier is not EvidenceTier.PROCFS_CORROBORATED:
            raise ValueError("mapped objects are procfs-corroborated only")


@dataclass(frozen=True, slots=True)
class LinuxProcessEvidence:
    observed_pid: int
    starttime_before: int
    starttime_after: int
    observed_euid: int
    pid_namespace_inode: int
    mount_namespace_inode: int
    comm_observed: str
    comm_truncated: bool
    comm_authoritative: Literal[False]
    proc_exe: FileEvidence
    loader_mapping: MappedObjectEvidence
    native_mappings: tuple[MappedObjectEvidence, MappedObjectEvidence]
    maps_sha256: Sha256
    maps_bytes: int
    maps_lines: int
    mountinfo_sha256: Sha256
    mountinfo_bytes: int
    mountinfo_lines: int

    def __post_init__(self) -> None:
        if self.comm_authoritative is not False:
            raise ValueError("comm is diagnostic-only")


def errno_class(error_number: int | None) -> str:
    if error_number == errno.ENOENT:
        return "not_found"
    if error_number in {errno.EACCES, errno.EPERM}:
        return "permission_denied"
    if error_number == errno.ELOOP:
        return "loop"
    if error_number == errno.ENOTDIR:
        return "not_directory"
    if error_number in {errno.EMFILE, errno.ENFILE}:
        return "too_many_open_files"
    if error_number == errno.EIO:
        return "io"
    return "other"


def path_sha256(path: str | bytes) -> str:
    raw = path if isinstance(path, bytes) else path.encode("utf-8", "surrogateescape")
    return hashlib.sha256(raw).hexdigest()


def collection_failure(
    disposition: CollectionDisposition,
    *reason_codes: CollectionReasonCode,
    subject: EvidenceSubject,
    details: Mapping[str, object] | None = None,
    partial_descriptor: DescriptorIdentity | None = None,
    path_binding_state: PathBindingState | None = None,
) -> CollectionFailure:
    safe: dict[str, str] = {}
    for key, value in (details or {}).items():
        if key not in _SAFE_DETAIL_KEYS:
            continue
        if isinstance(value, Enum):
            text = str(value.value)
        elif type(value) in {int, str}:
            text = str(value)
        else:
            continue
        if text.isascii() and text.isprintable() and len(text) <= 128:
            safe[key] = text
    return CollectionFailure(
        disposition=disposition,
        reason_codes=tuple(reason_codes),
        subject=subject,
        details=safe,
        partial_descriptor=partial_descriptor,
        path_binding_state=path_binding_state,
    )


__all__ = [
    "COLLECTOR_SCHEMA",
    "COLLECTOR_SCHEMA_VERSION",
    "DEFAULT_COLLECTOR_LIMITS",
    "DEFAULT_ELF_LIMITS",
    "DEFAULT_PROCFS_LIMITS",
    "MAX_HELD_DESCRIPTORS",
    "ArtifactEvidence",
    "ArtifactRequest",
    "CollectionDisposition",
    "CollectionFailure",
    "CollectionReasonCode",
    "CollectorElfClass",
    "CollectorLimits",
    "DescriptorIdentity",
    "DescriptorStat",
    "DistributionEvidence",
    "ElfInspection",
    "ElfInterpreterAbsent",
    "ElfInterpreterPresent",
    "ElfLimits",
    "EmbeddedPayloadObservation",
    "EvidenceSubject",
    "EvidenceTier",
    "ExpectedMappedObject",
    "ExpectedMappedObjects",
    "FileCollectionRequest",
    "FileEvidence",
    "FileRole",
    "LinuxProcessEvidence",
    "MappedObjectEvidence",
    "MappedObjectRole",
    "MappingSegmentObservation",
    "MonotonicDeadline",
    "MountInfoRow",
    "ObservedDistributionSource",
    "OfflineRuntimeCollectionRequest",
    "OfflineRuntimeEvidence",
    "OperationCounters",
    "PackageManifestObservation",
    "ParsedMountInfo",
    "ParsedProcMaps",
    "PathBindingState",
    "PathComponentObservation",
    "PathObservation",
    "PathPolicyId",
    "ProcMapKind",
    "ProcMapRow",
    "ProcStatObservation",
    "ProcfsLimits",
    "ResolvedInterpreterEvidence",
    "SchemaEvidence",
    "SafeDetailKey",
    "TreeEntryObservation",
    "TreeManifestObservation",
    "TrustedDistributionRequest",
    "TrustedGrammarDigestInput",
    "TrustedHelpContractDigestInput",
    "TrustedProcessScope",
    "TrustedSchemaInventoryInput",
    "collection_failure",
    "errno_class",
    "path_sha256",
]
