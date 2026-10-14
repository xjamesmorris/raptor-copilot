"""Pure parsing and static verification for runtime receipt v1."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from core.json.bounded import JsonBudgetExceededError, loads_bounded

from .canonical import (
    MAX_RECEIPT_BYTES,
    SCHEMA_NAME,
    SCHEMA_VERSION,
    CanonicalValueError,
    canonical_bytes,
    receipt_sha256,
    sha256_hex,
    token_commitment,
    validate_json_value,
)
from .profile import (
    ProfileLookupKey,
    ProfileStore,
    StaticProfile,
    profile_lookup_key_from_stable,
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
    ContentIdentity,
    CorroborationState,
    DecisionState,
    DeviceEvidenceSource,
    EvidenceStrength,
    ExecutableEvidenceSource,
    ExpectedBinding,
    FileObservation,
    Frontend,
    HashEvidenceSource,
    InodeEvidenceSource,
    LibcFamily,
    PathKind,
    PathnameEvidenceSource,
    PlatformSystem,
    ProfileStatus,
    REQUIRED_ARTIFACT_NAMES,
    REQUIRED_NATIVE_MODULE_NAMES,
    RuntimeReceipt,
    SchemaDocumentName,
    StableIdentity,
    _SchemaViolation,
    parse_runtime_receipt_document,
    to_json_value,
)


@dataclass(frozen=True, slots=True)
class StaticallyVerifiedReceipt:
    """An exact static match that cannot authorize a host or any effect."""

    receipt: RuntimeReceipt
    profile: StaticProfile
    stable_identity_sha256: str
    receipt_sha256: str
    disposition: VerificationDisposition = VerificationDisposition.EXACT_MATCH
    reason_codes: tuple[ReasonCode, ...] = (
        ReasonCode.PROFILE_UNSUPPORTED,
        ReasonCode.LIVE_CONTRACT_MISSING,
    )
    authoritative: Literal[False] = False


def serialize_receipt(
    receipt: RuntimeReceipt,
    *,
    max_bytes: int = MAX_RECEIPT_BYTES,
) -> bytes:
    """Serialize a typed receipt using the strict canonical byte form."""

    raw = canonical_bytes(to_json_value(receipt))
    if len(raw) > max_bytes:
        raise CanonicalValueError("receipt exceeds the encoded byte limit")
    return raw


def _parse_error(exc: Exception) -> ReceiptRejection:
    if isinstance(exc, _SchemaViolation):
        return rejection(exc.disposition, exc.reason_code)
    if isinstance(exc, JsonBudgetExceededError):
        return rejection(
            VerificationDisposition.MALFORMED,
            ReasonCode.RECEIPT_OVERSIZED,
        )
    if isinstance(exc, CanonicalValueError):
        message = str(exc)
        if "depth limit" in message:
            code = ReasonCode.RECEIPT_DEPTH_EXCEEDED
        elif "member limit" in message or "item limit" in message:
            code = ReasonCode.RECEIPT_MEMBER_LIMIT_EXCEEDED
        else:
            code = ReasonCode.RECEIPT_MALFORMED
        return rejection(VerificationDisposition.MALFORMED, code)
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


def _section_sha256(value: object) -> str:
    return sha256_hex(canonical_bytes(to_json_value(value)))


def parse_receipt(
    raw: bytes | None,
    *,
    max_bytes: int = MAX_RECEIPT_BYTES,
) -> RuntimeReceipt | ReceiptRejection:
    """Inspect untrusted receipt bytes without returning a verified result."""

    if raw is None:
        return rejection(
            VerificationDisposition.MISSING,
            ReasonCode.RECEIPT_MISSING,
        )
    try:
        decoded = loads_bounded(
            raw,
            max_bytes=max_bytes,
            reject_duplicate_keys=True,
        )
        validate_json_value(decoded)
        receipt = parse_runtime_receipt_document(decoded)
    except (
        CanonicalValueError,
        JsonBudgetExceededError,
        UnicodeError,
        ValueError,
    ) as exc:
        return _parse_error(exc)

    if receipt.schema != SCHEMA_NAME:
        return rejection(
            VerificationDisposition.VERSION_MISMATCH,
            ReasonCode.RECEIPT_SCHEMA_UNSUPPORTED,
        )
    if receipt.schema_version != SCHEMA_VERSION:
        return rejection(
            VerificationDisposition.VERSION_MISMATCH,
            ReasonCode.RECEIPT_VERSION_UNSUPPORTED,
        )

    stable_digest = _section_sha256(receipt.stable_identity)
    instance_digest = _section_sha256(receipt.launch_instance)
    binding_digest = _section_sha256(receipt.launch_binding)
    corroboration_digest = _section_sha256(receipt.process_corroboration)
    digest_mismatches: list[str] = []
    if stable_digest != receipt.stable_identity_sha256.value:
        digest_mismatches.append("stable_identity")
    if instance_digest != receipt.launch_instance_sha256.value:
        digest_mismatches.append("launch_instance")
    if binding_digest != receipt.launch_binding_sha256.value:
        digest_mismatches.append("launch_binding")
    if corroboration_digest != receipt.process_corroboration_sha256.value:
        digest_mismatches.append("process_corroboration")
    expected_receipt_digest = receipt_sha256(
        stable_digest,
        instance_digest,
        binding_digest,
        corroboration_digest,
    )
    if expected_receipt_digest != receipt.receipt_sha256.value:
        digest_mismatches.append("receipt")
    if digest_mismatches:
        return rejection(
            VerificationDisposition.DIGEST_MISMATCH,
            ReasonCode.RECEIPT_DIGEST_MISMATCH,
            details={"sections": ",".join(digest_mismatches)},
        )
    if (
        receipt.launch_binding.stable_identity_sha256.value
        != receipt.stable_identity_sha256.value
        or receipt.launch_binding.launch_instance_sha256.value
        != receipt.launch_instance_sha256.value
    ):
        return rejection(
            VerificationDisposition.DIGEST_MISMATCH,
            ReasonCode.RECEIPT_DIGEST_MISMATCH,
            details={"sections": "launch_binding_cross_digest"},
        )
    return receipt


def _state_consistency(receipt: RuntimeReceipt) -> ReceiptRejection | None:
    decision = receipt.decision
    corroboration = receipt.process_corroboration
    if decision.state is DecisionState.PENDING:
        legal = (
            corroboration.state is CorroborationState.PENDING
            and not decision.reason_codes
        )
    elif decision.state is DecisionState.VERIFIED:
        legal = (
            corroboration.state is CorroborationState.VERIFIED
            and not decision.reason_codes
        )
    else:
        legal = corroboration.state is CorroborationState.REJECTED and bool(
            decision.reason_codes
        )
    if not legal:
        return rejection(
            VerificationDisposition.MALFORMED,
            ReasonCode.RECEIPT_MALFORMED,
        )
    if decision.state is not DecisionState.VERIFIED:
        return rejection(
            VerificationDisposition.PARTIAL,
            ReasonCode.RECEIPT_STATE_NOT_VERIFIED,
        )
    return None


def _binding_consistency(receipt: RuntimeReceipt) -> ReceiptRejection | None:
    instance = receipt.launch_instance
    binding = receipt.launch_binding
    if (
        instance.session_id != binding.session_id
        or instance.launch_id != binding.launch_id
    ):
        return rejection(
            VerificationDisposition.COPIED_OR_REPLAYED_LAUNCH_INSTANCE,
            ReasonCode.RECEIPT_LAUNCH_INSTANCE_REPLAYED,
        )
    return None


def _verify_expected_binding(
    receipt: RuntimeReceipt,
    expected: ExpectedBinding,
) -> ReceiptRejection | None:
    instance = receipt.launch_instance
    binding = receipt.launch_binding
    if (
        instance.session_id.value != expected.session_id
        or binding.session_id.value != expected.session_id
        or instance.launch_id.value != expected.launch_id
        or binding.launch_id.value != expected.launch_id
    ):
        return rejection(
            VerificationDisposition.COPIED_OR_REPLAYED_LAUNCH_INSTANCE,
            ReasonCode.RECEIPT_LAUNCH_INSTANCE_REPLAYED,
        )
    if (
        binding.session_pid.value != expected.session_pid
        or binding.session_starttime_ticks.value != expected.session_starttime_ticks
        or binding.boot_id.value != expected.boot_id
        or binding.pid_namespace_inode.value != expected.pid_namespace_inode
        or binding.launcher_euid.value != expected.launcher_euid
    ):
        return rejection(
            VerificationDisposition.SESSION_BINDING_MISMATCH,
            ReasonCode.RECEIPT_SESSION_BINDING_MISMATCH,
        )
    try:
        expected_commitment = token_commitment(expected.token_hex)
    except CanonicalValueError:
        return rejection(
            VerificationDisposition.SESSION_BINDING_MISMATCH,
            ReasonCode.RECEIPT_TOKEN_COMMITMENT_MISMATCH,
        )
    if binding.session_token_commitment_sha256.value != expected_commitment:
        return rejection(
            VerificationDisposition.SESSION_BINDING_MISMATCH,
            ReasonCode.RECEIPT_TOKEN_COMMITMENT_MISMATCH,
        )
    return None


def _artifact_map(
    stable: StableIdentity,
) -> dict[ArtifactName, ContentIdentity]:
    return {
        artifact.name: artifact.content for artifact in stable.distribution.artifacts
    }


def _launch_artifact_map(
    receipt: RuntimeReceipt,
) -> dict[ArtifactName, FileObservation]:
    return {
        artifact.name: artifact.file for artifact in receipt.launch_instance.artifacts
    }


def _verify_stable_internal(
    stable: StableIdentity,
) -> ReceiptRejection | None:
    if stable.selected_frontend is not Frontend.COPILOT:
        return rejection(
            VerificationDisposition.PROFILE_MISMATCH,
            ReasonCode.FRONTEND_MISMATCH,
        )
    if (
        stable.platform.system is not PlatformSystem.LINUX
        or stable.platform.libc_family is not LibcFamily.GLIBC
        or stable.platform.pointer_bits != 64
    ):
        return rejection(
            VerificationDisposition.PLATFORM_MISMATCH,
            ReasonCode.PLATFORM_UNSUPPORTED,
        )
    if stable.platform.architecture is not Architecture.X86_64:
        return rejection(
            VerificationDisposition.PLATFORM_MISMATCH,
            ReasonCode.ARCHITECTURE_UNSUPPORTED,
        )
    if not stable.elf_interpreter.required:
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.ELF_INTERPRETER_MISSING,
        )
    if stable.distribution.version != stable.cli_version:
        return rejection(
            VerificationDisposition.VERSION_MISMATCH,
            ReasonCode.DISTRIBUTION_VERSION_MISMATCH,
        )
    package = stable.distribution.package_manifest
    if (
        package.name != "@github/copilot"
        or package.package_type != "module"
        or package.bin_name != "copilot"
        or package.bin_target != "npm-loader.js"
    ):
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.PACKAGE_MANIFEST_INVALID,
        )
    if package.version != stable.cli_version:
        return rejection(
            VerificationDisposition.VERSION_MISMATCH,
            ReasonCode.DISTRIBUTION_VERSION_MISMATCH,
        )
    artifact_map = _artifact_map(stable)
    if set(artifact_map) != REQUIRED_ARTIFACT_NAMES:
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.ARTIFACT_MISSING,
        )
    sea = stable.distribution.embedded_sea_loader
    if (
        not sea.matched
        or sea.match_count != 1
        or sea.sha256 != artifact_map[ArtifactName.SEA_LOADER_JS].sha256
    ):
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.ARTIFACT_IDENTITY_MISMATCH,
        )
    schema_map = {schema.name: schema for schema in stable.contract.schemas}
    if set(schema_map) != {
        SchemaDocumentName.SESSION_EVENTS,
        SchemaDocumentName.API,
    }:
        return rejection(
            VerificationDisposition.SCHEMA_MISMATCH,
            ReasonCode.SCHEMA_HASH_MISMATCH,
        )
    if (
        schema_map[SchemaDocumentName.SESSION_EVENTS].sha256
        != artifact_map[ArtifactName.SESSION_EVENTS_SCHEMA].sha256
        or schema_map[SchemaDocumentName.API].sha256
        != artifact_map[ArtifactName.API_SCHEMA].sha256
    ):
        return rejection(
            VerificationDisposition.SCHEMA_MISMATCH,
            ReasonCode.SCHEMA_HASH_MISMATCH,
        )
    if stable.contract.profile_schema_version != SCHEMA_VERSION:
        return rejection(
            VerificationDisposition.VERSION_MISMATCH,
            ReasonCode.RECEIPT_VERSION_UNSUPPORTED,
        )
    return None


def _same_content(
    observed: FileObservation,
    expected: ContentIdentity,
) -> bool:
    return (
        observed.sha256 == expected.sha256
        and observed.size_bytes == expected.size_bytes
        and observed.format_id == expected.format_id
    )


def _verify_launch_instance(
    receipt: RuntimeReceipt,
) -> ReceiptRejection | None:
    stable = receipt.stable_identity
    instance = receipt.launch_instance
    observations = (
        instance.issuer.launcher_file,
        instance.frontend_executable,
        instance.elf_interpreter,
        instance.package_manifest_file,
        *(item.file for item in instance.artifacts),
    )
    if any(observation.is_symlink for observation in observations):
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.PATH_POLICY_VIOLATION,
        )
    if (
        instance.issuer.launcher_file.path_kind is not PathKind.DIRECT_REGULAR
        or instance.frontend_executable.path_kind is not PathKind.DIRECT_REGULAR
        or instance.elf_interpreter.path_kind is not PathKind.RESOLVED_INTERPRETER
        or instance.package_manifest_file.path_kind is not PathKind.SEALED_REGULAR
        or any(
            item.file.path_kind is not PathKind.SEALED_REGULAR
            for item in instance.artifacts
        )
        or any(observation.nlink.value != 1 for observation in observations)
    ):
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.PATH_POLICY_VIOLATION,
        )
    if instance.issuer.receipt_implementation_id.value != (
        "raptor-copilot-runtime-receipt-v1"
    ):
        return rejection(
            VerificationDisposition.PROFILE_MISMATCH,
            ReasonCode.PROFILE_UNSUPPORTED,
        )
    if not _same_content(instance.issuer.launcher_file, stable.launcher):
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.EXECUTABLE_HASH_MISMATCH,
        )
    if not _same_content(
        instance.frontend_executable,
        stable.frontend_executable,
    ):
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.EXECUTABLE_HASH_MISMATCH,
        )
    if not _same_content(
        instance.elf_interpreter,
        stable.elf_interpreter.content,
    ):
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.ELF_INTERPRETER_IDENTITY_MISMATCH,
        )
    if not _same_content(
        instance.package_manifest_file,
        stable.distribution.package_manifest.content,
    ):
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.PACKAGE_MANIFEST_INVALID,
        )
    stable_artifacts = _artifact_map(stable)
    observed_artifacts = _launch_artifact_map(receipt)
    if set(observed_artifacts) != REQUIRED_ARTIFACT_NAMES:
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.ARTIFACT_MISSING,
        )
    sealed_prefix = instance.sealed_directory.value + "/"
    for name, expected in stable_artifacts.items():
        observed = observed_artifacts[name]
        if observed.path.value != sealed_prefix + name.value:
            return rejection(
                VerificationDisposition.ARTIFACT_MISMATCH,
                ReasonCode.PATH_POLICY_VIOLATION,
            )
        if not _same_content(observed, expected):
            if name is ArtifactName.RUNTIME_NODE:
                code = ReasonCode.RUNTIME_IMAGE_MISMATCH
            elif name is ArtifactName.CLI_NATIVE_NODE:
                code = ReasonCode.CLI_NATIVE_IMAGE_MISMATCH
            else:
                code = ReasonCode.ARTIFACT_IDENTITY_MISMATCH
            return rejection(
                VerificationDisposition.ARTIFACT_MISMATCH,
                code,
            )
    selection = instance.selection
    if not (
        selection.all_ambient_selectors_stripped
        and selection.launcher_set_dist_dir_from_receipt
        and selection.launcher_disabled_auto_update
        and selection.user_prefer_version_rejected
    ):
        return rejection(
            VerificationDisposition.PROFILE_MISMATCH,
            ReasonCode.DISTRIBUTION_SOURCE_FORBIDDEN,
        )
    version = instance.version_observation
    if (
        version.reported_version != stable.cli_version
        or version.version_exit_code != 0
        or version.binary_version_exit_code != 0
    ):
        return rejection(
            VerificationDisposition.VERSION_MISMATCH,
            ReasonCode.DISTRIBUTION_VERSION_MISMATCH,
        )
    if not (
        version.stderr_empty
        and version.network_disabled
        and version.stdin_dev_null
        and version.auto_update_disabled
    ):
        return rejection(
            VerificationDisposition.UNSUPPORTED_EVIDENCE,
            ReasonCode.MAPPED_EVIDENCE_UNSUPPORTED,
        )
    return None


def _verify_process(
    receipt: RuntimeReceipt,
) -> ReceiptRejection | None:
    process = receipt.process_corroboration
    binding = receipt.launch_binding
    if process.verification_policy_id.value != "linux-procfs-mapped-v1":
        return rejection(
            VerificationDisposition.UNSUPPORTED_EVIDENCE,
            ReasonCode.MAPPED_EVIDENCE_UNSUPPORTED,
        )
    if process.comm_authoritative:
        return rejection(
            VerificationDisposition.UNSUPPORTED_EVIDENCE,
            ReasonCode.MAPPED_EVIDENCE_UNSUPPORTED,
        )
    if (
        process.pid is None
        or process.starttime_before is None
        or process.starttime_after is None
        or process.process_uid is None
    ):
        return rejection(
            VerificationDisposition.PARTIAL,
            ReasonCode.RECEIPT_PARTIAL,
        )
    if (
        process.pid != binding.session_pid
        or process.starttime_before != binding.session_starttime_ticks
        or process.starttime_after != binding.session_starttime_ticks
    ):
        return rejection(
            VerificationDisposition.SESSION_BINDING_MISMATCH,
            ReasonCode.PROCESS_STAMP_MISMATCH,
        )
    if process.process_uid != binding.launcher_euid:
        return rejection(
            VerificationDisposition.SESSION_BINDING_MISMATCH,
            ReasonCode.PROCESS_UID_MISMATCH,
        )
    executable = process.mapped_executable
    if executable is None:
        return rejection(
            VerificationDisposition.UNSUPPORTED_EVIDENCE,
            ReasonCode.MAPPED_IMAGE_UNAVAILABLE,
        )
    if (
        executable.evidence_strength is not EvidenceStrength.STRONG
        or executable.source is not ExecutableEvidenceSource.PROC_PID_EXE
    ):
        return rejection(
            VerificationDisposition.UNSUPPORTED_EVIDENCE,
            ReasonCode.MAPPED_EVIDENCE_UNSUPPORTED,
        )
    mapped = executable.mapped_file
    disk = executable.current_disk_file
    observed_frontend = receipt.launch_instance.frontend_executable
    if (
        mapped.path_kind is not PathKind.PROC_EXE_DESCRIPTOR
        or disk.path_kind is not PathKind.DIRECT_REGULAR
        or mapped.sha256 != receipt.stable_identity.frontend_executable.sha256
        or disk.sha256 != receipt.stable_identity.frontend_executable.sha256
        or disk.path != observed_frontend.path
        or mapped.inode != disk.inode
        or mapped.device != disk.device
        or mapped.size_bytes != disk.size_bytes
    ):
        return rejection(
            VerificationDisposition.MAPPED_IMAGE_MISMATCH,
            ReasonCode.MAPPED_DISK_DIVERGENCE,
        )

    mapped_native = {
        evidence.module_name: evidence for evidence in process.mapped_native_images
    }
    if set(mapped_native) != REQUIRED_NATIVE_MODULE_NAMES:
        code = (
            ReasonCode.MAPPED_NATIVE_IMAGE_UNEXPECTED
            if set(mapped_native) - REQUIRED_NATIVE_MODULE_NAMES
            else ReasonCode.MAPPED_RUNTIME_IMAGE_UNAVAILABLE
        )
        return rejection(
            VerificationDisposition.MAPPED_IMAGE_MISMATCH,
            code,
        )
    observed_artifacts = _launch_artifact_map(receipt)
    stable_artifacts = _artifact_map(receipt.stable_identity)
    for name in sorted(REQUIRED_NATIVE_MODULE_NAMES, key=lambda item: item.value):
        evidence = mapped_native[name]
        observed = observed_artifacts[name]
        expected = stable_artifacts[name]
        if evidence.evidence_strength is not EvidenceStrength.CORROBORATED:
            return rejection(
                VerificationDisposition.UNSUPPORTED_EVIDENCE,
                ReasonCode.MAPPED_EVIDENCE_UNSUPPORTED,
            )
        if (
            evidence.pathname_source is not PathnameEvidenceSource.PROC_MAPS
            or evidence.inode_source is not InodeEvidenceSource.PROC_MAPS
            or evidence.maps_device_source is not DeviceEvidenceSource.PROC_MAPS
            or evidence.mount_device_source
            is not DeviceEvidenceSource.PROC_SELF_MOUNTINFO
            or evidence.sealed_path_recheck_source
            is not HashEvidenceSource.SEALED_PATH_REOPEN
        ):
            return rejection(
                VerificationDisposition.UNSUPPORTED_EVIDENCE,
                ReasonCode.MAPPED_EVIDENCE_UNSUPPORTED,
            )
        if evidence.maps_device != evidence.mount_device:
            return rejection(
                VerificationDisposition.UNSUPPORTED_EVIDENCE,
                ReasonCode.MAPPED_DEVICE_UNVERIFIABLE,
            )
        if (
            evidence.observed_path != observed.path
            or evidence.mapped_inode != observed.inode
            or evidence.sealed_path_recheck_sha256 != expected.sha256
            or not evidence.executable_mapping
            or evidence.deleted
        ):
            code = (
                ReasonCode.CLI_NATIVE_IMAGE_MISMATCH
                if name is ArtifactName.CLI_NATIVE_NODE
                else ReasonCode.MAPPED_RUNTIME_IMAGE_MISMATCH
            )
            return rejection(
                VerificationDisposition.MAPPED_IMAGE_MISMATCH,
                code,
                ReasonCode.MAPPED_DISK_DIVERGENCE,
            )
    if process.mismatch_observations:
        return rejection(
            VerificationDisposition.MAPPED_IMAGE_MISMATCH,
            *(observation.reason_code for observation in process.mismatch_observations),
        )
    return None


def _profile_key_mismatch(
    actual: ProfileLookupKey,
    expected: ProfileLookupKey,
) -> ReceiptRejection:
    if actual.profile_id != expected.profile_id:
        return rejection(
            VerificationDisposition.PROFILE_MISMATCH,
            ReasonCode.PROFILE_UNSUPPORTED,
        )
    if actual.cli_version != expected.cli_version:
        return rejection(
            VerificationDisposition.VERSION_MISMATCH,
            ReasonCode.DISTRIBUTION_VERSION_MISMATCH,
        )
    if (
        actual.platform_system != expected.platform_system
        or actual.architecture != expected.architecture
        or actual.elf_class != expected.elf_class
    ):
        return rejection(
            VerificationDisposition.PLATFORM_MISMATCH,
            ReasonCode.PLATFORM_UNSUPPORTED,
        )
    if (
        actual.session_events_schema_sha256 != expected.session_events_schema_sha256
        or actual.api_schema_sha256 != expected.api_schema_sha256
    ):
        return rejection(
            VerificationDisposition.SCHEMA_MISMATCH,
            ReasonCode.SCHEMA_HASH_MISMATCH,
        )
    if (
        actual.cli_grammar_sha256 != expected.cli_grammar_sha256
        or actual.help_contract_manifest_sha256
        != expected.help_contract_manifest_sha256
    ):
        codes = [ReasonCode.GRAMMAR_DIGEST_MISMATCH]
        if (
            actual.help_contract_manifest_sha256
            != expected.help_contract_manifest_sha256
        ):
            codes.append(ReasonCode.HELP_CONTRACT_DIGEST_MISMATCH)
        return rejection(
            VerificationDisposition.GRAMMAR_MISMATCH,
            *codes,
        )
    actual_artifacts = {artifact.name: artifact.sha256 for artifact in actual.artifacts}
    expected_artifacts = {
        artifact.name: artifact.sha256 for artifact in expected.artifacts
    }
    if set(actual_artifacts) != set(expected_artifacts):
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.ARTIFACT_MISSING,
        )
    if (
        actual_artifacts[ArtifactName.RUNTIME_NODE]
        != expected_artifacts[ArtifactName.RUNTIME_NODE]
    ):
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.RUNTIME_IMAGE_MISMATCH,
        )
    if (
        actual_artifacts[ArtifactName.CLI_NATIVE_NODE]
        != expected_artifacts[ArtifactName.CLI_NATIVE_NODE]
    ):
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.CLI_NATIVE_IMAGE_MISMATCH,
        )
    if actual_artifacts != expected_artifacts:
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.ARTIFACT_IDENTITY_MISMATCH,
        )
    if (
        actual.frontend != expected.frontend
        or actual.launcher_sha256 != expected.launcher_sha256
        or actual.frontend_executable_sha256 != expected.frontend_executable_sha256
        or actual.elf_interpreter_sha256 != expected.elf_interpreter_sha256
        or actual.distribution_source != expected.distribution_source
        or actual.distribution_manifest_sha256 != expected.distribution_manifest_sha256
        or actual.package_manifest_sha256 != expected.package_manifest_sha256
    ):
        return rejection(
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.ARTIFACT_IDENTITY_MISMATCH,
        )
    return rejection(
        VerificationDisposition.PROFILE_MISMATCH,
        ReasonCode.PROFILE_UNSUPPORTED,
    )


def _match_profile(
    receipt: RuntimeReceipt,
    store: ProfileStore,
) -> StaticProfile | ReceiptRejection:
    key = profile_lookup_key_from_stable(receipt.stable_identity)
    if isinstance(key, ReceiptRejection):
        return key
    candidates = tuple(
        profile
        for profile in store.profiles
        if profile.profile_id == receipt.stable_identity.profile_id
    )
    if not candidates:
        return rejection(
            VerificationDisposition.PROFILE_MISMATCH,
            ReasonCode.PROFILE_UNSUPPORTED,
        )
    exact = tuple(profile for profile in candidates if profile.lookup_key == key)
    if len(exact) > 1:
        return rejection(
            VerificationDisposition.PROFILE_MISMATCH,
            ReasonCode.PROFILE_AMBIGUOUS,
        )
    if not exact:
        return _profile_key_mismatch(key, candidates[0].lookup_key)
    profile = exact[0]
    contract = receipt.stable_identity.contract
    if (
        contract.profile_sha256 != profile.profile_sha256
        or contract.profile_status != profile.status
    ):
        return rejection(
            VerificationDisposition.PROFILE_MISMATCH,
            ReasonCode.PROFILE_DIGEST_MISMATCH,
        )
    return profile


def _freshness(
    receipt: RuntimeReceipt,
    now: datetime,
) -> ReceiptRejection | None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    binding = receipt.launch_binding
    process = receipt.process_corroboration
    issued = binding.issued_at_utc.as_datetime()
    if process.observed_at_utc is not None:
        observed = process.observed_at_utc.as_datetime()
        if observed < issued:
            return rejection(
                VerificationDisposition.STALE,
                ReasonCode.RECEIPT_TIMESTAMP_STALE,
            )
    if binding.freshness_not_after_utc is None:
        return None
    if now.astimezone(timezone.utc) > (binding.freshness_not_after_utc.as_datetime()):
        return rejection(
            VerificationDisposition.STALE,
            ReasonCode.RECEIPT_TIMESTAMP_STALE,
        )
    return None


def verify_receipt_static(
    receipt: RuntimeReceipt,
    *,
    profiles: ProfileStore,
    expected: ExpectedBinding | None = None,
    now: datetime | None = None,
) -> StaticallyVerifiedReceipt | ReceiptRejection:
    """Verify pure v1 invariants with external binding and freshness context."""

    if expected is None and now is None:
        return rejection(
            VerificationDisposition.VERIFICATION_CONTEXT_MISSING,
            ReasonCode.EXPECTED_BINDING_MISSING,
            ReasonCode.FRESHNESS_EVALUATION_MISSING,
        )
    if expected is None:
        return rejection(
            VerificationDisposition.VERIFICATION_CONTEXT_MISSING,
            ReasonCode.EXPECTED_BINDING_MISSING,
        )
    if now is None:
        return rejection(
            VerificationDisposition.VERIFICATION_CONTEXT_MISSING,
            ReasonCode.FRESHNESS_EVALUATION_MISSING,
        )

    for check in (
        _state_consistency(receipt),
        _binding_consistency(receipt),
        _verify_stable_internal(receipt.stable_identity),
        _verify_launch_instance(receipt),
        _verify_process(receipt),
    ):
        if check is not None:
            return check
    expected_failure = _verify_expected_binding(receipt, expected)
    if expected_failure is not None:
        return expected_failure
    profile = _match_profile(receipt, profiles)
    if isinstance(profile, ReceiptRejection):
        return profile
    freshness_failure = _freshness(receipt, now)
    if freshness_failure is not None:
        return freshness_failure
    if profile.status is ProfileStatus.REVOKED:
        return rejection(
            VerificationDisposition.PROFILE_MISMATCH,
            ReasonCode.PROFILE_REVOKED,
        )
    if profile.status is ProfileStatus.LIVE_VERIFIED:
        return rejection(
            VerificationDisposition.PROFILE_MISMATCH,
            ReasonCode.PROFILE_UNSUPPORTED,
            ReasonCode.LIVE_CONTRACT_MISSING,
        )
    return StaticallyVerifiedReceipt(
        receipt=receipt,
        profile=profile,
        stable_identity_sha256=receipt.stable_identity_sha256.value,
        receipt_sha256=receipt.receipt_sha256.value,
    )


__all__ = [
    "StaticallyVerifiedReceipt",
    "parse_receipt",
    "serialize_receipt",
    "verify_receipt_static",
]
