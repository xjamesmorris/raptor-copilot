"""Immutable typed schema for ``raptor.runtime_receipt/v1``."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any, TypeVar, cast
from uuid import UUID

from .canonical import JsonValue
from .reasons import ReasonCode, VerificationDisposition

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SEMANTIC_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
_MODE_RE = re.compile(r"^[0-7]{4}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
_DEVICE_RE = re.compile(r"^(0|[1-9][0-9]*):(0|[1-9][0-9]*)$")

MAX_U64 = 2**64 - 1
MAX_PATH_BYTES = 4096
MAX_PATH_COMPONENTS = 256
MAX_PATH_COMPONENT_BYTES = 255
MAX_REASON_CODES = 32
MAX_ARTIFACTS = 16
MAX_REQUIRED_SEMANTICS = 32
MAX_MAPPED_IMAGES = 16
MAX_MISMATCH_OBSERVATIONS = 32


class _SchemaViolation(ValueError):
    def __init__(
        self,
        reason_code: ReasonCode,
        disposition: VerificationDisposition,
        message: str,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.disposition = disposition


@dataclass(frozen=True, slots=True)
class Sha256:
    value: str

    def __post_init__(self) -> None:
        if _SHA256_RE.fullmatch(self.value) is None:
            raise ValueError("invalid SHA-256")


@dataclass(frozen=True, slots=True)
class Sha1:
    value: str

    def __post_init__(self) -> None:
        if _SHA1_RE.fullmatch(self.value) is None:
            raise ValueError("invalid SHA-1")


@dataclass(frozen=True, slots=True)
class Identifier:
    value: str

    def __post_init__(self) -> None:
        if _IDENTIFIER_RE.fullmatch(self.value) is None:
            raise ValueError("invalid identifier")


@dataclass(frozen=True, slots=True)
class SemanticName:
    value: str

    def __post_init__(self) -> None:
        if _SEMANTIC_RE.fullmatch(self.value) is None:
            raise ValueError("invalid semantic name")


@dataclass(frozen=True, slots=True)
class VersionText:
    value: str

    def __post_init__(self) -> None:
        if _VERSION_RE.fullmatch(self.value) is None:
            raise ValueError("invalid version")


@dataclass(frozen=True, slots=True)
class U64Decimal:
    value: int

    def __post_init__(self) -> None:
        if not 0 <= self.value <= MAX_U64:
            raise ValueError("u64 value out of range")

    @property
    def text(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AbsolutePath:
    value: str

    def __post_init__(self) -> None:
        encoded = self.value.encode("utf-8")
        if not self.value.startswith("/") or self.value == "/":
            raise ValueError("path must be an absolute non-root path")
        if len(encoded) > MAX_PATH_BYTES:
            raise ValueError("path exceeds byte limit")
        if not self.value.isprintable():
            raise ValueError("path contains a control character")
        if posixpath.normpath(self.value) != self.value:
            raise ValueError("path is not canonical")
        components = self.value.split("/")[1:]
        if len(components) > MAX_PATH_COMPONENTS:
            raise ValueError("path has too many components")
        if any(
            not component
            or component in {".", ".."}
            or len(component.encode("utf-8")) > MAX_PATH_COMPONENT_BYTES
            for component in components
        ):
            raise ValueError("path contains an invalid component")


@dataclass(frozen=True, slots=True)
class UtcTimestamp:
    value: str

    def __post_init__(self) -> None:
        if len(self.value.encode("ascii", errors="ignore")) != len(self.value):
            raise ValueError("timestamp must be ASCII")
        if _TIMESTAMP_RE.fullmatch(self.value) is None:
            raise ValueError("timestamp must be UTC RFC 3339")
        try:
            datetime.fromisoformat(self.value[:-1] + "+00:00")
        except ValueError as exc:
            raise ValueError("timestamp is invalid") from exc

    def as_datetime(self) -> datetime:
        return datetime.fromisoformat(self.value[:-1] + "+00:00")


@dataclass(frozen=True, slots=True)
class UuidText:
    value: str

    def __post_init__(self) -> None:
        try:
            parsed = UUID(self.value)
        except ValueError as exc:
            raise ValueError("invalid UUID") from exc
        if str(parsed) != self.value:
            raise ValueError("UUID must use canonical lowercase text")


@dataclass(frozen=True, slots=True)
class NonceHex:
    value: str

    def __post_init__(self) -> None:
        if _NONCE_RE.fullmatch(self.value) is None:
            raise ValueError("nonce must be 16 bytes of lowercase hexadecimal")


@dataclass(frozen=True, slots=True)
class DeviceMajorMinor:
    value: str

    def __post_init__(self) -> None:
        match = _DEVICE_RE.fullmatch(self.value)
        if match is None:
            raise ValueError("device must be canonical major:minor decimal")
        if int(match.group(1)) > 2**32 - 1 or int(match.group(2)) > 2**32 - 1:
            raise ValueError("device major/minor is out of range")


class Frontend(str, Enum):
    COPILOT = "copilot"
    CLAUDE = "claude"


class PlatformSystem(str, Enum):
    LINUX = "linux"
    DARWIN = "darwin"
    WINDOWS = "windows"


class Architecture(str, Enum):
    X86_64 = "x86_64"
    AARCH64 = "aarch64"


class ElfClass(str, Enum):
    ELF64 = "ELF64"
    NOT_APPLICABLE = "not_applicable"


class Endianness(str, Enum):
    LITTLE = "little"
    BIG = "big"


class LibcFamily(str, Enum):
    GLIBC = "glibc"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class FormatId(str, Enum):
    ELF64_X86_64_EXEC = "elf64-x86_64-exec"
    ELF64_X86_64_DYN = "elf64-x86_64-dyn"
    JSON_UTF8 = "json-utf8"
    JAVASCRIPT_UTF8 = "javascript-utf8"
    SHELL_SCRIPT = "shell-script"
    EMPTY = "empty"
    OPAQUE = "opaque"


class DistributionSource(str, Enum):
    SEALED_CACHE_SNAPSHOT = "sealed_cache_snapshot"
    SEALED_EMBEDDED_SNAPSHOT = "sealed_embedded_snapshot"


class ProfileStatus(str, Enum):
    STATIC_CANDIDATE_NOT_AUTHORIZED = "static_candidate_not_authorized"
    LIVE_VERIFIED = "live_verified"
    REVOKED = "revoked"


class ArtifactName(str, Enum):
    INDEX_JS = "index.js"
    NPM_LOADER_JS = "npm-loader.js"
    SEA_LOADER_JS = "sea-loader.js"
    APP_JS = "app.js"
    SDK_INDEX_JS = "sdk/index.js"
    CHANGELOG_JSON = "changelog.json"
    RUNTIME_NODE = "prebuilds/linux-x64/runtime.node"
    CLI_NATIVE_NODE = "prebuilds/linux-x64/cli-native.node"
    SESSION_EVENTS_SCHEMA = "schemas/session-events.schema.json"
    API_SCHEMA = "schemas/api.schema.json"
    EXTRACTION_COMPLETE = ".extraction-complete"


REQUIRED_ARTIFACT_NAMES = frozenset(ArtifactName)
REQUIRED_NATIVE_MODULE_NAMES = frozenset(
    {ArtifactName.RUNTIME_NODE, ArtifactName.CLI_NATIVE_NODE}
)


class SchemaDocumentName(str, Enum):
    SESSION_EVENTS = "session-events"
    API = "api"


class PathKind(str, Enum):
    DIRECT_REGULAR = "direct_regular"
    RESOLVED_INTERPRETER = "resolved_interpreter"
    SEALED_REGULAR = "sealed_regular"
    PROC_EXE_DESCRIPTOR = "proc_exe_descriptor"


class DecisionState(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"


class CorroborationState(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"


class EvidenceStrength(str, Enum):
    STRONG = "strong"
    CORROBORATED = "corroborated"
    WEAK = "weak"
    UNSUPPORTED = "unsupported"


class ExecutableEvidenceSource(str, Enum):
    PROC_PID_EXE = "proc_pid_exe"


class PathnameEvidenceSource(str, Enum):
    PROC_MAPS = "proc_maps"
    PROC_MAP_FILES_READLINK = "proc_map_files_readlink"


class InodeEvidenceSource(str, Enum):
    PROC_MAPS = "proc_maps"


class DeviceEvidenceSource(str, Enum):
    PROC_MAPS = "proc_maps"
    PROC_SELF_MOUNTINFO = "proc_self_mountinfo"


class HashEvidenceSource(str, Enum):
    SEALED_PATH_REOPEN = "sealed_path_reopen"


@dataclass(frozen=True, slots=True)
class ContentIdentity:
    sha256: Sha256
    size_bytes: U64Decimal
    format_id: FormatId
    elf_build_id_sha1: Sha1 | None


@dataclass(frozen=True, slots=True)
class PlatformIdentity:
    system: PlatformSystem
    architecture: Architecture
    elf_class: ElfClass
    endianness: Endianness
    pointer_bits: int
    libc_family: LibcFamily


@dataclass(frozen=True, slots=True)
class InterpreterContentIdentity:
    required: bool
    requested_path: AbsolutePath
    content: ContentIdentity


@dataclass(frozen=True, slots=True)
class TreeManifestIdentity:
    algorithm: Identifier
    sha256: Sha256
    entry_count: int
    total_regular_file_bytes: U64Decimal


@dataclass(frozen=True, slots=True)
class PackageManifestIdentity:
    content: ContentIdentity
    name: str
    version: VersionText
    package_type: str
    bin_name: str
    bin_target: str


@dataclass(frozen=True, slots=True)
class ArtifactIdentity:
    name: ArtifactName
    content: ContentIdentity


@dataclass(frozen=True, slots=True)
class EmbeddedSeaLoaderIdentity:
    matched: bool
    match_count: int
    offset: U64Decimal
    sha256: Sha256


@dataclass(frozen=True, slots=True)
class DistributionIdentity:
    source: DistributionSource
    version: VersionText
    platform_directory: str
    content_manifest: TreeManifestIdentity
    package_manifest: PackageManifestIdentity
    artifacts: tuple[ArtifactIdentity, ...]
    embedded_sea_loader: EmbeddedSeaLoaderIdentity


@dataclass(frozen=True, slots=True)
class SchemaIdentity:
    name: SchemaDocumentName
    sha256: Sha256
    size_bytes: U64Decimal
    definition_count: int
    property_count: int
    event_type_literal_count: int
    event_variant_count: int | None
    definition_names_sha256: Sha256
    property_names_sha256: Sha256
    event_type_literals_sha256: Sha256


@dataclass(frozen=True, slots=True)
class CliGrammarIdentity:
    source: str
    sha256: Sha256
    root_flag_count: int
    advertised_root_flag_count: int
    hidden_root_flag_count: int


@dataclass(frozen=True, slots=True)
class HelpContractIdentity:
    manifest_algorithm: str
    manifest_sha256: Sha256
    surface_count: int


@dataclass(frozen=True, slots=True)
class ContractIdentity:
    profile_schema_version: int
    profile_status: ProfileStatus
    profile_sha256: Sha256
    live_evidence_id: Identifier | None
    live_evidence_sha256: Sha256 | None
    schemas: tuple[SchemaIdentity, ...]
    cli_grammar: CliGrammarIdentity
    help_contract: HelpContractIdentity
    required_semantics: tuple[SemanticName, ...]


@dataclass(frozen=True, slots=True)
class StableIdentity:
    selected_frontend: Frontend
    profile_id: Identifier
    cli_version: VersionText
    platform: PlatformIdentity
    launcher: ContentIdentity
    frontend_executable: ContentIdentity
    elf_interpreter: InterpreterContentIdentity
    distribution: DistributionIdentity
    contract: ContractIdentity


@dataclass(frozen=True, slots=True)
class FileObservation:
    path: AbsolutePath
    path_kind: PathKind
    is_symlink: bool
    device: U64Decimal
    inode: U64Decimal
    mode_octal: str
    uid: U64Decimal
    gid: U64Decimal
    size_bytes: U64Decimal
    nlink: U64Decimal
    mtime_ns: U64Decimal
    ctime_ns: U64Decimal
    sha256: Sha256
    format_id: FormatId


@dataclass(frozen=True, slots=True)
class ArtifactObservation:
    name: ArtifactName
    file: FileObservation


@dataclass(frozen=True, slots=True)
class IssuerObservation:
    repository_head: Sha1
    receipt_implementation_id: Identifier
    launcher_file: FileObservation


@dataclass(frozen=True, slots=True)
class SelectionObservation:
    ambient_copilot_cli_dist_dir_present: bool
    ambient_copilot_pkg_cache_home_present: bool
    ambient_copilot_cache_home_present: bool
    ambient_xdg_cache_home_present: bool
    ambient_copilot_auto_update_present: bool
    all_ambient_selectors_stripped: bool
    launcher_set_dist_dir_from_receipt: bool
    launcher_disabled_auto_update: bool
    user_prefer_version_rejected: bool


@dataclass(frozen=True, slots=True)
class VersionObservation:
    reported_version: VersionText
    version_stdout_sha256: Sha256
    version_exit_code: int
    binary_version_stdout_sha256: Sha256
    binary_version_exit_code: int
    stderr_empty: bool
    network_disabled: bool
    stdin_dev_null: bool
    auto_update_disabled: bool


@dataclass(frozen=True, slots=True)
class LaunchInstance:
    session_id: UuidText
    launch_id: UuidText
    issuer: IssuerObservation
    frontend_executable: FileObservation
    elf_interpreter: FileObservation
    source_directory: AbsolutePath
    sealed_directory: AbsolutePath
    package_manifest_file: FileObservation
    artifacts: tuple[ArtifactObservation, ...]
    selection: SelectionObservation
    version_observation: VersionObservation


@dataclass(frozen=True, slots=True)
class LaunchBinding:
    session_id: UuidText
    launch_id: UuidText
    session_pid: U64Decimal
    session_starttime_ticks: U64Decimal
    boot_id: UuidText
    pid_namespace_inode: U64Decimal
    launcher_euid: U64Decimal
    session_token_commitment_sha256: Sha256
    receipt_nonce: NonceHex
    issued_at_utc: UtcTimestamp
    freshness_not_after_utc: UtcTimestamp | None
    stable_identity_sha256: Sha256
    launch_instance_sha256: Sha256


@dataclass(frozen=True, slots=True)
class MismatchObservation:
    subject: Identifier
    reason_code: ReasonCode
    expected_sha256: Sha256 | None
    observed_sha256: Sha256 | None


@dataclass(frozen=True, slots=True)
class MappedExecutableEvidence:
    evidence_strength: EvidenceStrength
    source: ExecutableEvidenceSource
    mapped_file: FileObservation
    current_disk_file: FileObservation


@dataclass(frozen=True, slots=True)
class MappedNativeImageEvidence:
    module_name: ArtifactName
    observed_path: AbsolutePath
    pathname_source: PathnameEvidenceSource
    mapped_inode: U64Decimal
    inode_source: InodeEvidenceSource
    maps_device: DeviceMajorMinor
    maps_device_source: DeviceEvidenceSource
    mount_device: DeviceMajorMinor
    mount_device_source: DeviceEvidenceSource
    sealed_path_recheck_sha256: Sha256
    sealed_path_recheck_source: HashEvidenceSource
    evidence_strength: EvidenceStrength
    executable_mapping: bool
    deleted: bool


@dataclass(frozen=True, slots=True)
class ProcessCorroboration:
    state: CorroborationState
    verification_policy_id: Identifier
    attempt: int
    observed_at_utc: UtcTimestamp | None
    pid: U64Decimal | None
    starttime_before: U64Decimal | None
    starttime_after: U64Decimal | None
    process_uid: U64Decimal | None
    comm_observed: str | None
    comm_authoritative: bool
    mapped_executable: MappedExecutableEvidence | None
    mapped_native_images: tuple[MappedNativeImageEvidence, ...]
    mismatch_observations: tuple[MismatchObservation, ...]


@dataclass(frozen=True, slots=True)
class ReceiptDecision:
    state: DecisionState
    reason_codes: tuple[ReasonCode, ...]


@dataclass(frozen=True, slots=True)
class RuntimeReceipt:
    schema: str
    schema_version: int
    stable_identity: StableIdentity
    stable_identity_sha256: Sha256
    launch_instance: LaunchInstance
    launch_instance_sha256: Sha256
    launch_binding: LaunchBinding
    launch_binding_sha256: Sha256
    process_corroboration: ProcessCorroboration
    process_corroboration_sha256: Sha256
    receipt_sha256: Sha256
    decision: ReceiptDecision


@dataclass(frozen=True, slots=True)
class ExpectedBinding:
    session_id: str
    launch_id: str
    session_pid: int
    session_starttime_ticks: int
    boot_id: str
    pid_namespace_inode: int
    launcher_euid: int
    token_hex: str


_SCALAR_VALUE_TYPES = (
    Sha256,
    Sha1,
    Identifier,
    SemanticName,
    VersionText,
    AbsolutePath,
    UtcTimestamp,
    UuidText,
    NonceHex,
    DeviceMajorMinor,
)


def to_json_value(value: object) -> JsonValue:
    """Convert an immutable schema object into a strict JSON value."""

    if isinstance(value, Enum):
        return cast(str, value.value)
    if value is None or isinstance(value, (str, int, bool)):
        return cast(JsonValue, value)
    if isinstance(value, U64Decimal):
        return value.text
    if isinstance(value, _SCALAR_VALUE_TYPES):
        return value.value
    if isinstance(value, tuple):
        return [to_json_value(item) for item in value]
    if is_dataclass(value):
        return {
            field.name: to_json_value(getattr(value, field.name))
            for field in fields(value)
        }
    raise TypeError(f"unsupported schema value: {type(value).__name__}")


def _violation(
    reason: ReasonCode,
    disposition: VerificationDisposition,
    message: str,
) -> _SchemaViolation:
    return _SchemaViolation(reason, disposition, message)


def _closed_object(
    value: object,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "expected object",
        )
    keys = set(value)
    missing = required - keys
    if missing:
        raise _violation(
            ReasonCode.RECEIPT_PARTIAL,
            VerificationDisposition.PARTIAL,
            "required field missing",
        )
    if keys - required - optional:
        raise _violation(
            ReasonCode.RECEIPT_SCHEMA_UNSUPPORTED,
            VerificationDisposition.VERSION_MISMATCH,
            "unknown field",
        )
    return value


def _bounded_text(
    value: object,
    *,
    max_bytes: int,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "expected string",
        )
    if not allow_empty and not value:
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "empty string",
        )
    if len(value.encode("utf-8")) > max_bytes or not value.isprintable():
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "invalid printable string",
        )
    return value


def _plain_int(value: object, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "integer outside range",
        )
    return value


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "expected boolean",
        )
    return value


def _optional(value: object, parser: Any) -> Any:
    if value is None:
        return None
    return parser(value)


TEnum = TypeVar("TEnum", bound=Enum)


def _enum(value: object, enum_type: type[TEnum]) -> TEnum:
    text = _bounded_text(value, max_bytes=128)
    try:
        return enum_type(text)
    except ValueError as exc:
        raise _violation(
            ReasonCode.RECEIPT_SCHEMA_UNSUPPORTED,
            VerificationDisposition.VERSION_MISMATCH,
            "unknown enum value",
        ) from exc


def _value_object(value: object, value_type: type[Any]) -> Any:
    text = _bounded_text(value, max_bytes=MAX_PATH_BYTES)
    try:
        return value_type(text)
    except ValueError as exc:
        reason = (
            ReasonCode.PATH_POLICY_VIOLATION
            if value_type is AbsolutePath
            else ReasonCode.RECEIPT_MALFORMED
        )
        disposition = (
            VerificationDisposition.ARTIFACT_MISMATCH
            if value_type is AbsolutePath
            else VerificationDisposition.MALFORMED
        )
        raise _violation(reason, disposition, str(exc)) from exc


def _u64(value: object, *, positive: bool = False) -> U64Decimal:
    text = _bounded_text(value, max_bytes=20)
    if not text.isascii() or not text.isdecimal():
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "invalid decimal identity",
        )
    if len(text) > 1 and text.startswith("0"):
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "non-canonical decimal identity",
        )
    number = int(text)
    if number > MAX_U64 or (positive and number == 0):
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "decimal identity outside range",
        )
    return U64Decimal(number)


def _sha256(value: object) -> Sha256:
    return _value_object(value, Sha256)


def _sha1(value: object) -> Sha1:
    return _value_object(value, Sha1)


def _identifier(value: object) -> Identifier:
    return _value_object(value, Identifier)


def _semantic(value: object) -> SemanticName:
    return _value_object(value, SemanticName)


def _version(value: object) -> VersionText:
    return _value_object(value, VersionText)


def _path(value: object) -> AbsolutePath:
    return _value_object(value, AbsolutePath)


def _timestamp(value: object) -> UtcTimestamp:
    return _value_object(value, UtcTimestamp)


def _uuid(value: object) -> UuidText:
    return _value_object(value, UuidText)


def _nonce(value: object) -> NonceHex:
    return _value_object(value, NonceHex)


def _device(value: object) -> DeviceMajorMinor:
    return _value_object(value, DeviceMajorMinor)


def _mode(value: object) -> str:
    text = _bounded_text(value, max_bytes=4)
    if _MODE_RE.fullmatch(text) is None:
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "invalid mode",
        )
    return text


def _parse_content_identity(value: object) -> ContentIdentity:
    obj = _closed_object(
        value,
        required=frozenset({"sha256", "size_bytes", "format_id", "elf_build_id_sha1"}),
    )
    return ContentIdentity(
        sha256=_sha256(obj["sha256"]),
        size_bytes=_u64(obj["size_bytes"]),
        format_id=_enum(obj["format_id"], FormatId),
        elf_build_id_sha1=_optional(obj["elf_build_id_sha1"], _sha1),
    )


def _parse_platform(value: object) -> PlatformIdentity:
    obj = _closed_object(
        value,
        required=frozenset(
            {
                "system",
                "architecture",
                "elf_class",
                "endianness",
                "pointer_bits",
                "libc_family",
            }
        ),
    )
    return PlatformIdentity(
        system=_enum(obj["system"], PlatformSystem),
        architecture=_enum(obj["architecture"], Architecture),
        elf_class=_enum(obj["elf_class"], ElfClass),
        endianness=_enum(obj["endianness"], Endianness),
        pointer_bits=_plain_int(obj["pointer_bits"], minimum=1, maximum=128),
        libc_family=_enum(obj["libc_family"], LibcFamily),
    )


def _parse_interpreter(value: object) -> InterpreterContentIdentity:
    obj = _closed_object(
        value,
        required=frozenset({"required", "requested_path", "content"}),
    )
    return InterpreterContentIdentity(
        required=_boolean(obj["required"]),
        requested_path=_path(obj["requested_path"]),
        content=_parse_content_identity(obj["content"]),
    )


def _parse_tree_manifest(value: object) -> TreeManifestIdentity:
    obj = _closed_object(
        value,
        required=frozenset(
            {"algorithm", "sha256", "entry_count", "total_regular_file_bytes"}
        ),
    )
    return TreeManifestIdentity(
        algorithm=_identifier(obj["algorithm"]),
        sha256=_sha256(obj["sha256"]),
        entry_count=_plain_int(obj["entry_count"], minimum=0, maximum=4096),
        total_regular_file_bytes=_u64(obj["total_regular_file_bytes"]),
    )


def _parse_package_manifest(value: object) -> PackageManifestIdentity:
    obj = _closed_object(
        value,
        required=frozenset(
            {
                "content",
                "name",
                "version",
                "package_type",
                "bin_name",
                "bin_target",
            }
        ),
    )
    return PackageManifestIdentity(
        content=_parse_content_identity(obj["content"]),
        name=_bounded_text(obj["name"], max_bytes=128),
        version=_version(obj["version"]),
        package_type=_bounded_text(obj["package_type"], max_bytes=32),
        bin_name=_bounded_text(obj["bin_name"], max_bytes=64),
        bin_target=_bounded_text(obj["bin_target"], max_bytes=256),
    )


def _parse_artifact_identity(value: object) -> ArtifactIdentity:
    obj = _closed_object(
        value,
        required=frozenset({"name", "content"}),
    )
    return ArtifactIdentity(
        name=_enum(obj["name"], ArtifactName),
        content=_parse_content_identity(obj["content"]),
    )


def _parse_artifact_identities(value: object) -> tuple[ArtifactIdentity, ...]:
    if not isinstance(value, list) or len(value) > MAX_ARTIFACTS:
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "invalid artifact inventory",
        )
    parsed = tuple(_parse_artifact_identity(item) for item in value)
    names = tuple(item.name for item in parsed)
    if len(set(names)) != len(names):
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "duplicate artifact name",
        )
    return parsed


def _parse_embedded_sea(value: object) -> EmbeddedSeaLoaderIdentity:
    obj = _closed_object(
        value,
        required=frozenset({"matched", "match_count", "offset", "sha256"}),
    )
    return EmbeddedSeaLoaderIdentity(
        matched=_boolean(obj["matched"]),
        match_count=_plain_int(obj["match_count"], minimum=0, maximum=2**31 - 1),
        offset=_u64(obj["offset"]),
        sha256=_sha256(obj["sha256"]),
    )


def _parse_distribution(value: object) -> DistributionIdentity:
    obj = _closed_object(
        value,
        required=frozenset(
            {
                "source",
                "version",
                "platform_directory",
                "content_manifest",
                "package_manifest",
                "artifacts",
                "embedded_sea_loader",
            }
        ),
    )
    return DistributionIdentity(
        source=_enum(obj["source"], DistributionSource),
        version=_version(obj["version"]),
        platform_directory=_bounded_text(obj["platform_directory"], max_bytes=64),
        content_manifest=_parse_tree_manifest(obj["content_manifest"]),
        package_manifest=_parse_package_manifest(obj["package_manifest"]),
        artifacts=_parse_artifact_identities(obj["artifacts"]),
        embedded_sea_loader=_parse_embedded_sea(obj["embedded_sea_loader"]),
    )


def _parse_schema_identity(value: object) -> SchemaIdentity:
    obj = _closed_object(
        value,
        required=frozenset(field.name for field in fields(SchemaIdentity)),
    )
    event_variant = obj["event_variant_count"]
    return SchemaIdentity(
        name=_enum(obj["name"], SchemaDocumentName),
        sha256=_sha256(obj["sha256"]),
        size_bytes=_u64(obj["size_bytes"]),
        definition_count=_plain_int(
            obj["definition_count"], minimum=0, maximum=1_000_000
        ),
        property_count=_plain_int(obj["property_count"], minimum=0, maximum=1_000_000),
        event_type_literal_count=_plain_int(
            obj["event_type_literal_count"], minimum=0, maximum=1_000_000
        ),
        event_variant_count=(
            None
            if event_variant is None
            else _plain_int(event_variant, minimum=0, maximum=1_000_000)
        ),
        definition_names_sha256=_sha256(obj["definition_names_sha256"]),
        property_names_sha256=_sha256(obj["property_names_sha256"]),
        event_type_literals_sha256=_sha256(obj["event_type_literals_sha256"]),
    )


def _parse_schemas(value: object) -> tuple[SchemaIdentity, ...]:
    if not isinstance(value, list) or len(value) > 4:
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "invalid schema inventory",
        )
    parsed = tuple(_parse_schema_identity(item) for item in value)
    names = tuple(item.name for item in parsed)
    if len(set(names)) != len(names):
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "duplicate schema identity",
        )
    return parsed


def _parse_cli_grammar(value: object) -> CliGrammarIdentity:
    obj = _closed_object(
        value,
        required=frozenset(
            {
                "source",
                "sha256",
                "root_flag_count",
                "advertised_root_flag_count",
                "hidden_root_flag_count",
            }
        ),
    )
    return CliGrammarIdentity(
        source=_bounded_text(obj["source"], max_bytes=64),
        sha256=_sha256(obj["sha256"]),
        root_flag_count=_plain_int(obj["root_flag_count"], minimum=0, maximum=4096),
        advertised_root_flag_count=_plain_int(
            obj["advertised_root_flag_count"], minimum=0, maximum=4096
        ),
        hidden_root_flag_count=_plain_int(
            obj["hidden_root_flag_count"], minimum=0, maximum=4096
        ),
    )


def _parse_help_contract(value: object) -> HelpContractIdentity:
    obj = _closed_object(
        value,
        required=frozenset({"manifest_algorithm", "manifest_sha256", "surface_count"}),
    )
    return HelpContractIdentity(
        manifest_algorithm=_bounded_text(
            obj["manifest_algorithm"],
            max_bytes=128,
        ),
        manifest_sha256=_sha256(obj["manifest_sha256"]),
        surface_count=_plain_int(obj["surface_count"], minimum=0, maximum=64),
    )


def _parse_semantics(value: object) -> tuple[SemanticName, ...]:
    if not isinstance(value, list) or len(value) > MAX_REQUIRED_SEMANTICS:
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "invalid required-semantics list",
        )
    parsed = tuple(_semantic(item) for item in value)
    if len(set(parsed)) != len(parsed):
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "duplicate required semantic",
        )
    return parsed


def _parse_contract(value: object) -> ContractIdentity:
    obj = _closed_object(
        value,
        required=frozenset(
            {
                "profile_schema_version",
                "profile_status",
                "profile_sha256",
                "live_evidence_id",
                "live_evidence_sha256",
                "schemas",
                "cli_grammar",
                "help_contract",
                "required_semantics",
            }
        ),
    )
    return ContractIdentity(
        profile_schema_version=_plain_int(
            obj["profile_schema_version"], minimum=0, maximum=2**31 - 1
        ),
        profile_status=_enum(obj["profile_status"], ProfileStatus),
        profile_sha256=_sha256(obj["profile_sha256"]),
        live_evidence_id=_optional(obj["live_evidence_id"], _identifier),
        live_evidence_sha256=_optional(obj["live_evidence_sha256"], _sha256),
        schemas=_parse_schemas(obj["schemas"]),
        cli_grammar=_parse_cli_grammar(obj["cli_grammar"]),
        help_contract=_parse_help_contract(obj["help_contract"]),
        required_semantics=_parse_semantics(obj["required_semantics"]),
    )


def _parse_stable_identity(value: object) -> StableIdentity:
    obj = _closed_object(
        value,
        required=frozenset(
            {
                "selected_frontend",
                "profile_id",
                "cli_version",
                "platform",
                "launcher",
                "frontend_executable",
                "elf_interpreter",
                "distribution",
                "contract",
            }
        ),
    )
    return StableIdentity(
        selected_frontend=_enum(obj["selected_frontend"], Frontend),
        profile_id=_identifier(obj["profile_id"]),
        cli_version=_version(obj["cli_version"]),
        platform=_parse_platform(obj["platform"]),
        launcher=_parse_content_identity(obj["launcher"]),
        frontend_executable=_parse_content_identity(obj["frontend_executable"]),
        elf_interpreter=_parse_interpreter(obj["elf_interpreter"]),
        distribution=_parse_distribution(obj["distribution"]),
        contract=_parse_contract(obj["contract"]),
    )


def _parse_file_observation(value: object) -> FileObservation:
    obj = _closed_object(
        value,
        required=frozenset(field.name for field in fields(FileObservation)),
    )
    return FileObservation(
        path=_path(obj["path"]),
        path_kind=_enum(obj["path_kind"], PathKind),
        is_symlink=_boolean(obj["is_symlink"]),
        device=_u64(obj["device"]),
        inode=_u64(obj["inode"], positive=True),
        mode_octal=_mode(obj["mode_octal"]),
        uid=_u64(obj["uid"]),
        gid=_u64(obj["gid"]),
        size_bytes=_u64(obj["size_bytes"]),
        nlink=_u64(obj["nlink"], positive=True),
        mtime_ns=_u64(obj["mtime_ns"]),
        ctime_ns=_u64(obj["ctime_ns"]),
        sha256=_sha256(obj["sha256"]),
        format_id=_enum(obj["format_id"], FormatId),
    )


def _parse_artifact_observation(value: object) -> ArtifactObservation:
    obj = _closed_object(
        value,
        required=frozenset({"name", "file"}),
    )
    return ArtifactObservation(
        name=_enum(obj["name"], ArtifactName),
        file=_parse_file_observation(obj["file"]),
    )


def _parse_artifact_observations(
    value: object,
) -> tuple[ArtifactObservation, ...]:
    if not isinstance(value, list) or len(value) > MAX_ARTIFACTS:
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "invalid artifact-observation inventory",
        )
    parsed = tuple(_parse_artifact_observation(item) for item in value)
    names = tuple(item.name for item in parsed)
    if len(set(names)) != len(names):
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "duplicate artifact observation",
        )
    return parsed


def _parse_issuer(value: object) -> IssuerObservation:
    obj = _closed_object(
        value,
        required=frozenset(
            {"repository_head", "receipt_implementation_id", "launcher_file"}
        ),
    )
    return IssuerObservation(
        repository_head=_sha1(obj["repository_head"]),
        receipt_implementation_id=_identifier(obj["receipt_implementation_id"]),
        launcher_file=_parse_file_observation(obj["launcher_file"]),
    )


def _parse_selection(value: object) -> SelectionObservation:
    names = frozenset(
        {
            "ambient_copilot_cli_dist_dir_present",
            "ambient_copilot_pkg_cache_home_present",
            "ambient_copilot_cache_home_present",
            "ambient_xdg_cache_home_present",
            "ambient_copilot_auto_update_present",
            "all_ambient_selectors_stripped",
            "launcher_set_dist_dir_from_receipt",
            "launcher_disabled_auto_update",
            "user_prefer_version_rejected",
        }
    )
    obj = _closed_object(value, required=names)
    return SelectionObservation(
        ambient_copilot_cli_dist_dir_present=_boolean(
            obj["ambient_copilot_cli_dist_dir_present"]
        ),
        ambient_copilot_pkg_cache_home_present=_boolean(
            obj["ambient_copilot_pkg_cache_home_present"]
        ),
        ambient_copilot_cache_home_present=_boolean(
            obj["ambient_copilot_cache_home_present"]
        ),
        ambient_xdg_cache_home_present=_boolean(obj["ambient_xdg_cache_home_present"]),
        ambient_copilot_auto_update_present=_boolean(
            obj["ambient_copilot_auto_update_present"]
        ),
        all_ambient_selectors_stripped=_boolean(obj["all_ambient_selectors_stripped"]),
        launcher_set_dist_dir_from_receipt=_boolean(
            obj["launcher_set_dist_dir_from_receipt"]
        ),
        launcher_disabled_auto_update=_boolean(obj["launcher_disabled_auto_update"]),
        user_prefer_version_rejected=_boolean(obj["user_prefer_version_rejected"]),
    )


def _parse_version_observation(value: object) -> VersionObservation:
    obj = _closed_object(
        value,
        required=frozenset(
            {
                "reported_version",
                "version_stdout_sha256",
                "version_exit_code",
                "binary_version_stdout_sha256",
                "binary_version_exit_code",
                "stderr_empty",
                "network_disabled",
                "stdin_dev_null",
                "auto_update_disabled",
            }
        ),
    )
    return VersionObservation(
        reported_version=_version(obj["reported_version"]),
        version_stdout_sha256=_sha256(obj["version_stdout_sha256"]),
        version_exit_code=_plain_int(obj["version_exit_code"], minimum=0, maximum=255),
        binary_version_stdout_sha256=_sha256(obj["binary_version_stdout_sha256"]),
        binary_version_exit_code=_plain_int(
            obj["binary_version_exit_code"], minimum=0, maximum=255
        ),
        stderr_empty=_boolean(obj["stderr_empty"]),
        network_disabled=_boolean(obj["network_disabled"]),
        stdin_dev_null=_boolean(obj["stdin_dev_null"]),
        auto_update_disabled=_boolean(obj["auto_update_disabled"]),
    )


def _parse_launch_instance(value: object) -> LaunchInstance:
    obj = _closed_object(
        value,
        required=frozenset(field.name for field in fields(LaunchInstance)),
    )
    return LaunchInstance(
        session_id=_uuid(obj["session_id"]),
        launch_id=_uuid(obj["launch_id"]),
        issuer=_parse_issuer(obj["issuer"]),
        frontend_executable=_parse_file_observation(obj["frontend_executable"]),
        elf_interpreter=_parse_file_observation(obj["elf_interpreter"]),
        source_directory=_path(obj["source_directory"]),
        sealed_directory=_path(obj["sealed_directory"]),
        package_manifest_file=_parse_file_observation(obj["package_manifest_file"]),
        artifacts=_parse_artifact_observations(obj["artifacts"]),
        selection=_parse_selection(obj["selection"]),
        version_observation=_parse_version_observation(obj["version_observation"]),
    )


def _parse_launch_binding(value: object) -> LaunchBinding:
    obj = _closed_object(
        value,
        required=frozenset(field.name for field in fields(LaunchBinding)),
    )
    return LaunchBinding(
        session_id=_uuid(obj["session_id"]),
        launch_id=_uuid(obj["launch_id"]),
        session_pid=_u64(obj["session_pid"], positive=True),
        session_starttime_ticks=_u64(obj["session_starttime_ticks"], positive=True),
        boot_id=_uuid(obj["boot_id"]),
        pid_namespace_inode=_u64(obj["pid_namespace_inode"], positive=True),
        launcher_euid=_u64(obj["launcher_euid"]),
        session_token_commitment_sha256=_sha256(obj["session_token_commitment_sha256"]),
        receipt_nonce=_nonce(obj["receipt_nonce"]),
        issued_at_utc=_timestamp(obj["issued_at_utc"]),
        freshness_not_after_utc=_optional(obj["freshness_not_after_utc"], _timestamp),
        stable_identity_sha256=_sha256(obj["stable_identity_sha256"]),
        launch_instance_sha256=_sha256(obj["launch_instance_sha256"]),
    )


def _parse_mismatch(value: object) -> MismatchObservation:
    obj = _closed_object(
        value,
        required=frozenset(
            {
                "subject",
                "reason_code",
                "expected_sha256",
                "observed_sha256",
            }
        ),
    )
    return MismatchObservation(
        subject=_identifier(obj["subject"]),
        reason_code=_enum(obj["reason_code"], ReasonCode),
        expected_sha256=_optional(obj["expected_sha256"], _sha256),
        observed_sha256=_optional(obj["observed_sha256"], _sha256),
    )


def _parse_mismatches(value: object) -> tuple[MismatchObservation, ...]:
    if not isinstance(value, list) or len(value) > MAX_MISMATCH_OBSERVATIONS:
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "invalid mismatch-observation list",
        )
    return tuple(_parse_mismatch(item) for item in value)


def _parse_mapped_executable(value: object) -> MappedExecutableEvidence:
    obj = _closed_object(
        value,
        required=frozenset(
            {
                "evidence_strength",
                "source",
                "mapped_file",
                "current_disk_file",
            }
        ),
    )
    return MappedExecutableEvidence(
        evidence_strength=_enum(obj["evidence_strength"], EvidenceStrength),
        source=_enum(obj["source"], ExecutableEvidenceSource),
        mapped_file=_parse_file_observation(obj["mapped_file"]),
        current_disk_file=_parse_file_observation(obj["current_disk_file"]),
    )


def _parse_mapped_native(value: object) -> MappedNativeImageEvidence:
    obj = _closed_object(
        value,
        required=frozenset(field.name for field in fields(MappedNativeImageEvidence)),
    )
    return MappedNativeImageEvidence(
        module_name=_enum(obj["module_name"], ArtifactName),
        observed_path=_path(obj["observed_path"]),
        pathname_source=_enum(obj["pathname_source"], PathnameEvidenceSource),
        mapped_inode=_u64(obj["mapped_inode"], positive=True),
        inode_source=_enum(obj["inode_source"], InodeEvidenceSource),
        maps_device=_device(obj["maps_device"]),
        maps_device_source=_enum(obj["maps_device_source"], DeviceEvidenceSource),
        mount_device=_device(obj["mount_device"]),
        mount_device_source=_enum(obj["mount_device_source"], DeviceEvidenceSource),
        sealed_path_recheck_sha256=_sha256(obj["sealed_path_recheck_sha256"]),
        sealed_path_recheck_source=_enum(
            obj["sealed_path_recheck_source"], HashEvidenceSource
        ),
        evidence_strength=_enum(obj["evidence_strength"], EvidenceStrength),
        executable_mapping=_boolean(obj["executable_mapping"]),
        deleted=_boolean(obj["deleted"]),
    )


def _parse_mapped_native_images(
    value: object,
) -> tuple[MappedNativeImageEvidence, ...]:
    if not isinstance(value, list) or len(value) > MAX_MAPPED_IMAGES:
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "invalid mapped-image list",
        )
    parsed = tuple(_parse_mapped_native(item) for item in value)
    names = tuple(item.module_name for item in parsed)
    if len(set(names)) != len(names):
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "duplicate mapped native image",
        )
    return parsed


def _parse_process_corroboration(value: object) -> ProcessCorroboration:
    obj = _closed_object(
        value,
        required=frozenset(field.name for field in fields(ProcessCorroboration)),
    )
    comm = obj["comm_observed"]
    parsed_comm = (
        None if comm is None else _bounded_text(comm, max_bytes=64, allow_empty=True)
    )
    return ProcessCorroboration(
        state=_enum(obj["state"], CorroborationState),
        verification_policy_id=_identifier(obj["verification_policy_id"]),
        attempt=_plain_int(obj["attempt"], minimum=0, maximum=65_535),
        observed_at_utc=_optional(obj["observed_at_utc"], _timestamp),
        pid=_optional(obj["pid"], lambda item: _u64(item, positive=True)),
        starttime_before=_optional(
            obj["starttime_before"], lambda item: _u64(item, positive=True)
        ),
        starttime_after=_optional(
            obj["starttime_after"], lambda item: _u64(item, positive=True)
        ),
        process_uid=_optional(obj["process_uid"], _u64),
        comm_observed=parsed_comm,
        comm_authoritative=_boolean(obj["comm_authoritative"]),
        mapped_executable=_optional(obj["mapped_executable"], _parse_mapped_executable),
        mapped_native_images=_parse_mapped_native_images(obj["mapped_native_images"]),
        mismatch_observations=_parse_mismatches(obj["mismatch_observations"]),
    )


def _parse_reason_codes(value: object) -> tuple[ReasonCode, ...]:
    if not isinstance(value, list) or len(value) > MAX_REASON_CODES:
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "invalid reason-code list",
        )
    parsed = tuple(_enum(item, ReasonCode) for item in value)
    if len(set(parsed)) != len(parsed):
        raise _violation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "duplicate reason code",
        )
    return parsed


def _parse_decision(value: object) -> ReceiptDecision:
    obj = _closed_object(
        value,
        required=frozenset({"state", "reason_codes"}),
    )
    return ReceiptDecision(
        state=_enum(obj["state"], DecisionState),
        reason_codes=_parse_reason_codes(obj["reason_codes"]),
    )


def parse_runtime_receipt_document(value: object) -> RuntimeReceipt:
    """Parse a strict already-decoded receipt document.

    Callers should first apply the bounded duplicate-key rejecting JSON parser and
    the canonical tree walk. ``_SchemaViolation`` is intentionally package-private;
    the public parse API translates it into :class:`ReceiptRejection`.
    """

    obj = _closed_object(
        value,
        required=frozenset(field.name for field in fields(RuntimeReceipt)),
    )
    schema = _bounded_text(obj["schema"], max_bytes=128)
    schema_version = _plain_int(obj["schema_version"], minimum=0, maximum=2**31 - 1)
    return RuntimeReceipt(
        schema=schema,
        schema_version=schema_version,
        stable_identity=_parse_stable_identity(obj["stable_identity"]),
        stable_identity_sha256=_sha256(obj["stable_identity_sha256"]),
        launch_instance=_parse_launch_instance(obj["launch_instance"]),
        launch_instance_sha256=_sha256(obj["launch_instance_sha256"]),
        launch_binding=_parse_launch_binding(obj["launch_binding"]),
        launch_binding_sha256=_sha256(obj["launch_binding_sha256"]),
        process_corroboration=_parse_process_corroboration(
            obj["process_corroboration"]
        ),
        process_corroboration_sha256=_sha256(obj["process_corroboration_sha256"]),
        receipt_sha256=_sha256(obj["receipt_sha256"]),
        decision=_parse_decision(obj["decision"]),
    )
