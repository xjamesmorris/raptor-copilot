"""Static profile parsing and exact lookup for runtime receipt v1."""

from __future__ import annotations

import json
import stat
from dataclasses import dataclass, fields
from pathlib import Path

from core.json.bounded import JsonBudgetExceededError, loads_bounded

from .canonical import (
    CanonicalValueError,
    canonical_bytes,
    sha256_hex,
    validate_json_value,
)
from .reasons import (
    ReasonCode,
    ReceiptRejection,
    VerificationDisposition,
    rejection,
)
from .schema import (
    Architecture,
    ArtifactName,
    DistributionSource,
    ElfClass,
    Frontend,
    Identifier,
    PlatformSystem,
    ProfileStatus,
    Sha256,
    StableIdentity,
    VersionText,
    _SchemaViolation,
    _closed_object,
    _enum,
    _identifier,
    _optional,
    _plain_int,
    _sha256,
    _version,
    to_json_value,
)

PROFILE_SCHEMA_NAME = "raptor.runtime_receipt_profile/v1"
PROFILE_SCHEMA_VERSION = 1
MAX_PROFILE_BYTES = 32_768
MAX_PROFILES = 8
DEFAULT_PROFILE_DIRECTORY = Path(__file__).with_name("profiles")


@dataclass(frozen=True, slots=True)
class ProfileArtifactDigest:
    name: ArtifactName
    sha256: Sha256


@dataclass(frozen=True, slots=True)
class ProfileLookupKey:
    frontend: Frontend
    profile_id: Identifier
    cli_version: VersionText
    platform_system: PlatformSystem
    architecture: Architecture
    elf_class: ElfClass
    launcher_sha256: Sha256
    frontend_executable_sha256: Sha256
    elf_interpreter_sha256: Sha256
    distribution_source: DistributionSource
    distribution_manifest_sha256: Sha256
    package_manifest_sha256: Sha256
    artifacts: tuple[ProfileArtifactDigest, ...]
    session_events_schema_sha256: Sha256
    api_schema_sha256: Sha256
    cli_grammar_sha256: Sha256
    help_contract_manifest_sha256: Sha256


@dataclass(frozen=True, slots=True)
class ProfileDigestBasis:
    profile_id: Identifier
    profile_schema_version: int
    status: ProfileStatus
    live_evidence_id: Identifier | None
    live_evidence_sha256: Sha256 | None
    lookup_key: ProfileLookupKey


@dataclass(frozen=True, slots=True)
class StaticProfile:
    schema: str
    schema_version: int
    profile_digest_basis: ProfileDigestBasis
    profile_sha256: Sha256

    @property
    def profile_id(self) -> Identifier:
        return self.profile_digest_basis.profile_id

    @property
    def status(self) -> ProfileStatus:
        return self.profile_digest_basis.status

    @property
    def lookup_key(self) -> ProfileLookupKey:
        return self.profile_digest_basis.lookup_key


@dataclass(frozen=True, slots=True)
class ProfileStore:
    profiles: tuple[StaticProfile, ...]


def _parse_profile_artifact(value: object) -> ProfileArtifactDigest:
    obj = _closed_object(
        value,
        required=frozenset({"name", "sha256"}),
    )
    return ProfileArtifactDigest(
        name=_enum(obj["name"], ArtifactName),
        sha256=_sha256(obj["sha256"]),
    )


def _parse_profile_artifacts(
    value: object,
) -> tuple[ProfileArtifactDigest, ...]:
    if not isinstance(value, list) or len(value) > 16:
        raise _SchemaViolation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "invalid profile artifact list",
        )
    parsed = tuple(_parse_profile_artifact(item) for item in value)
    names = tuple(item.name for item in parsed)
    if len(set(names)) != len(names):
        raise _SchemaViolation(
            ReasonCode.RECEIPT_MALFORMED,
            VerificationDisposition.MALFORMED,
            "duplicate profile artifact",
        )
    return parsed


def _parse_lookup_key(value: object) -> ProfileLookupKey:
    obj = _closed_object(
        value,
        required=frozenset(field.name for field in fields(ProfileLookupKey)),
    )
    return ProfileLookupKey(
        frontend=_enum(obj["frontend"], Frontend),
        profile_id=_identifier(obj["profile_id"]),
        cli_version=_version(obj["cli_version"]),
        platform_system=_enum(obj["platform_system"], PlatformSystem),
        architecture=_enum(obj["architecture"], Architecture),
        elf_class=_enum(obj["elf_class"], ElfClass),
        launcher_sha256=_sha256(obj["launcher_sha256"]),
        frontend_executable_sha256=_sha256(obj["frontend_executable_sha256"]),
        elf_interpreter_sha256=_sha256(obj["elf_interpreter_sha256"]),
        distribution_source=_enum(obj["distribution_source"], DistributionSource),
        distribution_manifest_sha256=_sha256(obj["distribution_manifest_sha256"]),
        package_manifest_sha256=_sha256(obj["package_manifest_sha256"]),
        artifacts=_parse_profile_artifacts(obj["artifacts"]),
        session_events_schema_sha256=_sha256(obj["session_events_schema_sha256"]),
        api_schema_sha256=_sha256(obj["api_schema_sha256"]),
        cli_grammar_sha256=_sha256(obj["cli_grammar_sha256"]),
        help_contract_manifest_sha256=_sha256(obj["help_contract_manifest_sha256"]),
    )


def _parse_profile_basis(value: object) -> ProfileDigestBasis:
    obj = _closed_object(
        value,
        required=frozenset(
            {
                "profile_id",
                "profile_schema_version",
                "status",
                "live_evidence_id",
                "live_evidence_sha256",
                "lookup_key",
            }
        ),
    )
    return ProfileDigestBasis(
        profile_id=_identifier(obj["profile_id"]),
        profile_schema_version=_plain_int(
            obj["profile_schema_version"], minimum=0, maximum=2**31 - 1
        ),
        status=_enum(obj["status"], ProfileStatus),
        live_evidence_id=_optional(obj["live_evidence_id"], _identifier),
        live_evidence_sha256=_optional(obj["live_evidence_sha256"], _sha256),
        lookup_key=_parse_lookup_key(obj["lookup_key"]),
    )


def parse_static_profile_document(value: object) -> StaticProfile:
    """Parse and digest-check one already-decoded static profile."""

    obj = _closed_object(
        value,
        required=frozenset(
            {
                "schema",
                "schema_version",
                "profile_digest_basis",
                "profile_sha256",
            }
        ),
    )
    if obj["schema"] != PROFILE_SCHEMA_NAME:
        raise _SchemaViolation(
            ReasonCode.RECEIPT_SCHEMA_UNSUPPORTED,
            VerificationDisposition.VERSION_MISMATCH,
            "unsupported profile schema",
        )
    schema_version = _plain_int(obj["schema_version"], minimum=0, maximum=2**31 - 1)
    if schema_version != PROFILE_SCHEMA_VERSION:
        raise _SchemaViolation(
            ReasonCode.RECEIPT_VERSION_UNSUPPORTED,
            VerificationDisposition.VERSION_MISMATCH,
            "unsupported profile schema version",
        )
    basis = _parse_profile_basis(obj["profile_digest_basis"])
    profile_sha256 = _sha256(obj["profile_sha256"])
    if basis.profile_schema_version != PROFILE_SCHEMA_VERSION:
        raise _SchemaViolation(
            ReasonCode.RECEIPT_VERSION_UNSUPPORTED,
            VerificationDisposition.VERSION_MISMATCH,
            "unsupported profile body version",
        )
    if basis.lookup_key.profile_id != basis.profile_id:
        raise _SchemaViolation(
            ReasonCode.PROFILE_DIGEST_MISMATCH,
            VerificationDisposition.PROFILE_MISMATCH,
            "profile id disagrees with lookup key",
        )
    expected = sha256_hex(canonical_bytes(to_json_value(basis)))
    if expected != profile_sha256.value:
        raise _SchemaViolation(
            ReasonCode.PROFILE_DIGEST_MISMATCH,
            VerificationDisposition.PROFILE_MISMATCH,
            "profile digest mismatch",
        )
    return StaticProfile(
        schema=PROFILE_SCHEMA_NAME,
        schema_version=schema_version,
        profile_digest_basis=basis,
        profile_sha256=profile_sha256,
    )


def _profile_parse_rejection(exc: Exception) -> ReceiptRejection:
    if isinstance(exc, _SchemaViolation):
        return rejection(exc.disposition, exc.reason_code)
    if isinstance(exc, JsonBudgetExceededError):
        return rejection(
            VerificationDisposition.MALFORMED,
            ReasonCode.RECEIPT_OVERSIZED,
        )
    if isinstance(exc, CanonicalValueError):
        return rejection(
            VerificationDisposition.MALFORMED,
            ReasonCode.RECEIPT_MALFORMED,
        )
    if isinstance(exc, UnicodeError):
        return rejection(
            VerificationDisposition.MALFORMED,
            ReasonCode.RECEIPT_MALFORMED,
        )
    if isinstance(exc, json.JSONDecodeError):
        return rejection(
            VerificationDisposition.MALFORMED,
            ReasonCode.RECEIPT_MALFORMED,
        )
    if isinstance(exc, ValueError) and str(exc) == "duplicate JSON object key":
        return rejection(
            VerificationDisposition.MALFORMED,
            ReasonCode.RECEIPT_DUPLICATE_KEY,
        )
    return rejection(
        VerificationDisposition.MALFORMED,
        ReasonCode.RECEIPT_MALFORMED,
    )


def load_profile_store(
    directory: Path = DEFAULT_PROFILE_DIRECTORY,
) -> ProfileStore | ReceiptRejection:
    """Load a bounded, closed profile directory without following symlinks."""

    try:
        entries = sorted(directory.iterdir(), key=lambda item: item.name)
    except OSError:
        return rejection(
            VerificationDisposition.PROFILE_MISMATCH,
            ReasonCode.PROFILE_MISSING,
        )
    json_files = [entry for entry in entries if entry.suffix == ".json"]
    if len(json_files) > MAX_PROFILES:
        return rejection(
            VerificationDisposition.PROFILE_MISMATCH,
            ReasonCode.PROFILE_AMBIGUOUS,
        )

    profiles: list[StaticProfile] = []
    for path in json_files:
        try:
            path_stat = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(path_stat.st_mode):
                return rejection(
                    VerificationDisposition.PROFILE_MISMATCH,
                    ReasonCode.PROFILE_DIGEST_MISMATCH,
                )
            raw = path.read_bytes()
            value = loads_bounded(
                raw,
                max_bytes=MAX_PROFILE_BYTES,
                reject_duplicate_keys=True,
            )
            validate_json_value(value)
            profile = parse_static_profile_document(value)
        except (OSError, UnicodeError, ValueError, CanonicalValueError) as exc:
            return _profile_parse_rejection(exc)
        profiles.append(profile)
    return ProfileStore(tuple(profiles))


def lookup_profile(
    store: ProfileStore,
    key: ProfileLookupKey,
) -> StaticProfile | ReceiptRejection:
    """Require exactly one profile with an exact content lookup key."""

    matches = tuple(profile for profile in store.profiles if profile.lookup_key == key)
    if not matches:
        return rejection(
            VerificationDisposition.PROFILE_MISMATCH,
            ReasonCode.PROFILE_UNSUPPORTED,
        )
    if len(matches) != 1:
        return rejection(
            VerificationDisposition.PROFILE_MISMATCH,
            ReasonCode.PROFILE_AMBIGUOUS,
        )
    return matches[0]


def _schema_sha(
    stable: StableIdentity,
    name: str,
) -> Sha256:
    for schema in stable.contract.schemas:
        if schema.name.value == name:
            return schema.sha256
    raise KeyError(name)


def profile_lookup_key_from_stable(
    stable: StableIdentity,
) -> ProfileLookupKey | ReceiptRejection:
    """Derive the exact profile key from stable content only."""

    try:
        artifacts = tuple(
            ProfileArtifactDigest(
                name=artifact.name,
                sha256=artifact.content.sha256,
            )
            for artifact in sorted(
                stable.distribution.artifacts,
                key=lambda item: item.name.value,
            )
        )
        return ProfileLookupKey(
            frontend=stable.selected_frontend,
            profile_id=stable.profile_id,
            cli_version=stable.cli_version,
            platform_system=stable.platform.system,
            architecture=stable.platform.architecture,
            elf_class=stable.platform.elf_class,
            launcher_sha256=stable.launcher.sha256,
            frontend_executable_sha256=stable.frontend_executable.sha256,
            elf_interpreter_sha256=stable.elf_interpreter.content.sha256,
            distribution_source=stable.distribution.source,
            distribution_manifest_sha256=(stable.distribution.content_manifest.sha256),
            package_manifest_sha256=(
                stable.distribution.package_manifest.content.sha256
            ),
            artifacts=artifacts,
            session_events_schema_sha256=_schema_sha(stable, "session-events"),
            api_schema_sha256=_schema_sha(stable, "api"),
            cli_grammar_sha256=stable.contract.cli_grammar.sha256,
            help_contract_manifest_sha256=(
                stable.contract.help_contract.manifest_sha256
            ),
        )
    except KeyError:
        return rejection(
            VerificationDisposition.PARTIAL,
            ReasonCode.RECEIPT_PARTIAL,
            ReasonCode.ARTIFACT_MISSING,
        )


__all__ = [
    "DEFAULT_PROFILE_DIRECTORY",
    "PROFILE_SCHEMA_NAME",
    "PROFILE_SCHEMA_VERSION",
    "ProfileArtifactDigest",
    "ProfileDigestBasis",
    "ProfileLookupKey",
    "ProfileStore",
    "StaticProfile",
    "load_profile_store",
    "lookup_profile",
    "parse_static_profile_document",
    "profile_lookup_key_from_stable",
]
