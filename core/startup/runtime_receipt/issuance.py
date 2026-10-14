"""Pure receipt builders over already-collected, explicitly bound evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, TypeVar

from .canonical import (
    SCHEMA_NAME,
    SCHEMA_VERSION,
    CanonicalValueError,
    canonical_bytes,
    receipt_sha256,
    sha256_hex,
)
from .collector_types import (
    CollectionDisposition,
    CollectionFailure,
    CollectionReasonCode,
    DistributionEvidence,
    FileEvidence,
    FileRole,
    LinuxProcessEvidence,
    MappedObjectEvidence,
    MappedObjectRole,
    OfflineRuntimeEvidence,
)
from .plumbing_types import (
    AuthorityInvariantError,
    PlumbingDisposition,
    PlumbingFailure,
    PlumbingReason,
    ReceiptReference,
    ReceiptState,
    RuntimeReceiptSnapshot,
    SessionToken,
    authority_invariant_failure,
    plumbing_failure,
    reference_from_receipt,
    reference_transition_mismatch,
    require_authority_invariant,
    snapshot_from_static_verification,
)
from .profile import ProfileStore, StaticProfile, profile_lookup_key_from_stable
from .reasons import ReasonCode, ReceiptRejection
from .schema import (
    AbsolutePath,
    Architecture,
    ArtifactIdentity,
    ArtifactName,
    ArtifactObservation,
    CliGrammarIdentity,
    ContentIdentity,
    ContractIdentity,
    CorroborationState,
    DecisionState,
    DeviceEvidenceSource,
    DistributionIdentity,
    DistributionSource,
    ElfClass,
    EmbeddedSeaLoaderIdentity,
    Endianness,
    EvidenceStrength,
    ExecutableEvidenceSource,
    ExpectedBinding,
    FileObservation,
    Frontend,
    HashEvidenceSource,
    HelpContractIdentity,
    Identifier,
    InodeEvidenceSource,
    InterpreterContentIdentity,
    IssuerObservation,
    LaunchBinding,
    LaunchInstance,
    LibcFamily,
    MappedExecutableEvidence,
    MappedNativeImageEvidence,
    MismatchObservation,
    NonceHex,
    PackageManifestIdentity,
    PathKind,
    PathnameEvidenceSource,
    PlatformIdentity,
    PlatformSystem,
    ProcessCorroboration,
    ProfileStatus,
    ReceiptDecision,
    RuntimeReceipt,
    SchemaIdentity,
    SelectionObservation,
    SemanticName,
    Sha1,
    Sha256,
    StableIdentity,
    TreeManifestIdentity,
    U64Decimal,
    UtcTimestamp,
    UuidText,
    VersionObservation,
    to_json_value,
)
from .verify import StaticallyVerifiedReceipt, parse_receipt, serialize_receipt

RECEIPT_IMPLEMENTATION_ID = Identifier("raptor-copilot-runtime-receipt-v1")
PROCESS_VERIFICATION_POLICY_ID = Identifier("linux-procfs-mapped-v1")
_IssuedT = TypeVar("_IssuedT")


def _checked_issuance_result(
    value: _IssuedT,
    expected_type: type[_IssuedT],
) -> _IssuedT | PlumbingFailure:
    failure = authority_invariant_failure(value, expected_type)
    return failure or value


@dataclass(frozen=True, slots=True)
class StableIssuanceInputs:
    """Trusted non-ambient values needed to adapt offline evidence."""

    profile: StaticProfile
    launcher: FileEvidence
    platform: PlatformIdentity
    distribution_source: DistributionSource
    required_semantics: tuple[SemanticName, ...]
    selected_frontend: Frontend = Frontend.COPILOT

    def __post_init__(self) -> None:
        if self.selected_frontend is not Frontend.COPILOT:
            raise ValueError("Stage 2 only models the Copilot static candidate")
        if self.profile.status is not ProfileStatus.STATIC_CANDIDATE_NOT_AUTHORIZED:
            raise ValueError("Stage 2 requires a static non-authorizing profile")
        if self.launcher.role is not FileRole.CONTRACT_INPUT:
            raise ValueError("launcher evidence must use the contract-input role")
        if len(self.required_semantics) > 32:
            raise ValueError("required semantics exceed the receipt bound")


@dataclass(frozen=True, slots=True)
class LaunchIssuanceInputs:
    """Explicit launch-instance values that evidence cannot self-select."""

    session_id: UuidText
    launch_id: UuidText
    repository_head: Sha1
    source_directory: AbsolutePath
    sealed_directory: AbsolutePath
    selection: SelectionObservation
    version_observation: VersionObservation


@dataclass(frozen=True, slots=True)
class BindingIssuanceInputs:
    """Explicit process/session binding values; the raw token stays in memory."""

    session_pid: int
    session_starttime_ticks: int
    boot_id: UuidText
    pid_namespace_inode: int
    launcher_euid: int
    session_token: SessionToken
    launch_nonce: NonceHex
    issued_at_utc: UtcTimestamp
    freshness_not_after_utc: UtcTimestamp | None

    def __post_init__(self) -> None:
        for name, value, positive in (
            ("session_pid", self.session_pid, True),
            ("session_starttime_ticks", self.session_starttime_ticks, True),
            ("pid_namespace_inode", self.pid_namespace_inode, True),
            ("launcher_euid", self.launcher_euid, False),
        ):
            if (
                type(value) is not int
                or value < (1 if positive else 0)
                or value > 2**64 - 1
            ):
                raise ValueError(f"{name} is outside the u64 bound")


@dataclass(frozen=True, slots=True)
class PendingReceiptIssued:
    """Canonical pending receipt with no authority."""

    receipt: RuntimeReceipt
    reference: ReceiptReference
    authoritative: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        require_authority_invariant(self, PendingReceiptIssued)

    def __init_subclass__(cls) -> None:
        raise TypeError("PendingReceiptIssued cannot be subclassed")


@dataclass(frozen=True, slots=True)
class VerifiedReceiptIssued:
    """Static verifier success with its deny-only snapshot."""

    receipt: RuntimeReceipt
    reference: ReceiptReference
    verification: StaticallyVerifiedReceipt
    snapshot: RuntimeReceiptSnapshot
    reason_codes: tuple[ReasonCode, ...] = (
        ReasonCode.PROFILE_UNSUPPORTED,
        ReasonCode.LIVE_CONTRACT_MISSING,
    )
    authoritative: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        require_authority_invariant(self, VerifiedReceiptIssued)
        require_authority_invariant(
            self.verification,
            StaticallyVerifiedReceipt,
        )
        require_authority_invariant(self.snapshot, RuntimeReceiptSnapshot)
        if (
            self.reference.state is not ReceiptState.VERIFIED
            or self.reason_codes != self.verification.reason_codes
        ):
            raise ValueError("verified issuance exceeded the static authority ceiling")

    def __init_subclass__(cls) -> None:
        raise TypeError("VerifiedReceiptIssued cannot be subclassed")


@dataclass(frozen=True, slots=True)
class RejectedReceiptIssued:
    """Canonical terminal rejection with no fallback or authority."""

    receipt: RuntimeReceipt
    reference: ReceiptReference
    authoritative: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        require_authority_invariant(self, RejectedReceiptIssued)

    def __init_subclass__(cls) -> None:
        raise TypeError("RejectedReceiptIssued cannot be subclassed")


def _content_identity(evidence: FileEvidence) -> ContentIdentity:
    descriptor = evidence.descriptor
    return ContentIdentity(
        sha256=Sha256(descriptor.sha256),
        size_bytes=U64Decimal(descriptor.stat.size_bytes),
        format_id=descriptor.format_id,
        elf_build_id_sha1=(
            Sha1(descriptor.elf_build_id_sha1)
            if descriptor.elf_build_id_sha1 is not None
            else None
        ),
    )


def _file_observation(
    evidence: FileEvidence,
    *,
    path_kind: PathKind,
) -> FileObservation:
    descriptor = evidence.descriptor
    value = descriptor.stat
    return FileObservation(
        path=evidence.path.resolved_path,
        path_kind=path_kind,
        is_symlink=False,
        device=U64Decimal(value.device),
        inode=U64Decimal(value.inode),
        mode_octal=value.mode_octal,
        uid=U64Decimal(value.uid),
        gid=U64Decimal(value.gid),
        size_bytes=U64Decimal(value.size_bytes),
        nlink=U64Decimal(value.nlink),
        mtime_ns=U64Decimal(value.mtime_ns),
        ctime_ns=U64Decimal(value.ctime_ns),
        sha256=Sha256(descriptor.sha256),
        format_id=descriptor.format_id,
    )


def _distribution_identity(
    evidence: OfflineRuntimeEvidence,
    source: DistributionSource,
) -> DistributionIdentity:
    distribution = evidence.distribution
    package = distribution.package_manifest
    artifacts = tuple(
        ArtifactIdentity(
            name=item.name,
            content=_content_identity(item.file),
        )
        for item in sorted(distribution.artifacts, key=lambda item: item.name.value)
    )
    return DistributionIdentity(
        source=source,
        version=distribution.version,
        platform_directory=distribution.platform_directory,
        content_manifest=TreeManifestIdentity(
            algorithm=Identifier(distribution.content_manifest.algorithm),
            sha256=distribution.content_manifest.sha256,
            entry_count=distribution.content_manifest.entry_count,
            total_regular_file_bytes=U64Decimal(
                distribution.content_manifest.total_regular_file_bytes
            ),
        ),
        package_manifest=PackageManifestIdentity(
            content=_content_identity(package.file),
            name=package.name,
            version=package.version,
            package_type=package.package_type,
            bin_name=package.bin_name,
            bin_target=package.bin_target,
        ),
        artifacts=artifacts,
        embedded_sea_loader=EmbeddedSeaLoaderIdentity(
            matched=True,
            match_count=evidence.embedded_sea_loader.match_count,
            offset=U64Decimal(evidence.embedded_sea_loader.offset),
            sha256=evidence.embedded_sea_loader.sha256,
        ),
    )


def _contract_identity(
    evidence: DistributionEvidence,
    profile: StaticProfile,
    required_semantics: tuple[SemanticName, ...],
) -> ContractIdentity:
    schemas = tuple(
        SchemaIdentity(
            name=item.name,
            sha256=Sha256(item.file.descriptor.sha256),
            size_bytes=U64Decimal(item.file.descriptor.stat.size_bytes),
            definition_count=item.definition_count,
            property_count=item.property_count,
            event_type_literal_count=item.event_type_literal_count,
            event_variant_count=item.event_variant_count,
            definition_names_sha256=item.definition_names_sha256,
            property_names_sha256=item.property_names_sha256,
            event_type_literals_sha256=item.event_type_literals_sha256,
        )
        for item in sorted(evidence.schemas, key=lambda item: item.name.value)
    )
    return ContractIdentity(
        profile_schema_version=profile.schema_version,
        profile_status=profile.status,
        profile_sha256=profile.profile_sha256,
        live_evidence_id=profile.profile_digest_basis.live_evidence_id,
        live_evidence_sha256=profile.profile_digest_basis.live_evidence_sha256,
        schemas=schemas,
        cli_grammar=CliGrammarIdentity(
            source=evidence.grammar.source,
            sha256=evidence.grammar.sha256,
            root_flag_count=evidence.grammar.root_flag_count,
            advertised_root_flag_count=evidence.grammar.advertised_root_flag_count,
            hidden_root_flag_count=evidence.grammar.hidden_root_flag_count,
        ),
        help_contract=HelpContractIdentity(
            manifest_algorithm=evidence.help_contract.manifest_algorithm,
            manifest_sha256=evidence.help_contract.manifest_sha256,
            surface_count=evidence.help_contract.surface_count,
        ),
        required_semantics=required_semantics,
    )


def _stable_identity(
    evidence: OfflineRuntimeEvidence,
    inputs: StableIssuanceInputs,
) -> StableIdentity | PlumbingFailure:
    if evidence.frontend.role is not FileRole.FRONTEND_EXECUTABLE:
        return plumbing_failure(
            PlumbingDisposition.COLLECTION_FAILED,
            PlumbingReason.COLLECTION_ADAPTATION_FAILED,
            source_reason_codes=("frontend_role_mismatch",),
        )
    if evidence.interpreter.file.role is not FileRole.ELF_INTERPRETER:
        return plumbing_failure(
            PlumbingDisposition.COLLECTION_FAILED,
            PlumbingReason.COLLECTION_ADAPTATION_FAILED,
            source_reason_codes=("interpreter_role_mismatch",),
        )
    stable = StableIdentity(
        selected_frontend=inputs.selected_frontend,
        profile_id=inputs.profile.profile_id,
        cli_version=evidence.distribution.version,
        platform=inputs.platform,
        launcher=_content_identity(inputs.launcher),
        frontend_executable=_content_identity(evidence.frontend),
        elf_interpreter=InterpreterContentIdentity(
            required=True,
            requested_path=evidence.interpreter.requested_path,
            content=_content_identity(evidence.interpreter.file),
        ),
        distribution=_distribution_identity(
            evidence,
            inputs.distribution_source,
        ),
        contract=_contract_identity(
            evidence.distribution,
            inputs.profile,
            inputs.required_semantics,
        ),
    )
    key = profile_lookup_key_from_stable(stable)
    if isinstance(key, ReceiptRejection) or key != inputs.profile.lookup_key:
        source_reasons = (
            tuple(reason.value for reason in key.reason_codes)
            if isinstance(key, ReceiptRejection)
            else ("profile_lookup_key_mismatch",)
        )
        return plumbing_failure(
            PlumbingDisposition.RECEIPT_REJECTED,
            PlumbingReason.STATIC_VERIFICATION_FAILED,
            source_reason_codes=source_reasons,
        )
    return stable


def _launch_instance(
    evidence: OfflineRuntimeEvidence,
    stable_inputs: StableIssuanceInputs,
    launch_inputs: LaunchIssuanceInputs,
) -> LaunchInstance:
    selection = launch_inputs.selection
    artifacts = tuple(
        ArtifactObservation(
            name=item.name,
            file=_file_observation(item.file, path_kind=PathKind.SEALED_REGULAR),
        )
        for item in sorted(
            evidence.distribution.artifacts,
            key=lambda item: item.name.value,
        )
    )
    return LaunchInstance(
        session_id=launch_inputs.session_id,
        launch_id=launch_inputs.launch_id,
        issuer=IssuerObservation(
            repository_head=launch_inputs.repository_head,
            receipt_implementation_id=RECEIPT_IMPLEMENTATION_ID,
            launcher_file=_file_observation(
                stable_inputs.launcher,
                path_kind=PathKind.DIRECT_REGULAR,
            ),
        ),
        frontend_executable=_file_observation(
            evidence.frontend,
            path_kind=PathKind.DIRECT_REGULAR,
        ),
        elf_interpreter=_file_observation(
            evidence.interpreter.file,
            path_kind=PathKind.RESOLVED_INTERPRETER,
        ),
        source_directory=launch_inputs.source_directory,
        sealed_directory=launch_inputs.sealed_directory,
        package_manifest_file=_file_observation(
            evidence.distribution.package_manifest.file,
            path_kind=PathKind.SEALED_REGULAR,
        ),
        artifacts=artifacts,
        selection=selection,
        version_observation=launch_inputs.version_observation,
    )


def _section_sha256(value: object) -> Sha256:
    return Sha256(sha256_hex(canonical_bytes(to_json_value(value))))


def _assemble_receipt(
    *,
    stable: StableIdentity,
    instance: LaunchInstance,
    binding_inputs: BindingIssuanceInputs,
    process: ProcessCorroboration,
    decision: ReceiptDecision,
) -> RuntimeReceipt:
    stable_digest = _section_sha256(stable)
    instance_digest = _section_sha256(instance)
    binding = LaunchBinding(
        session_id=instance.session_id,
        launch_id=instance.launch_id,
        session_pid=U64Decimal(binding_inputs.session_pid),
        session_starttime_ticks=U64Decimal(binding_inputs.session_starttime_ticks),
        boot_id=binding_inputs.boot_id,
        pid_namespace_inode=U64Decimal(binding_inputs.pid_namespace_inode),
        launcher_euid=U64Decimal(binding_inputs.launcher_euid),
        session_token_commitment_sha256=binding_inputs.session_token.commitment(),
        receipt_nonce=binding_inputs.launch_nonce,
        issued_at_utc=binding_inputs.issued_at_utc,
        freshness_not_after_utc=binding_inputs.freshness_not_after_utc,
        stable_identity_sha256=stable_digest,
        launch_instance_sha256=instance_digest,
    )
    binding_digest = _section_sha256(binding)
    process_digest = _section_sha256(process)
    return RuntimeReceipt(
        schema=SCHEMA_NAME,
        schema_version=SCHEMA_VERSION,
        stable_identity=stable,
        stable_identity_sha256=stable_digest,
        launch_instance=instance,
        launch_instance_sha256=instance_digest,
        launch_binding=binding,
        launch_binding_sha256=binding_digest,
        process_corroboration=process,
        process_corroboration_sha256=process_digest,
        receipt_sha256=Sha256(
            receipt_sha256(
                stable_digest.value,
                instance_digest.value,
                binding_digest.value,
                process_digest.value,
            )
        ),
        decision=decision,
    )


def _reassemble_receipt(
    prior: RuntimeReceipt,
    *,
    process: ProcessCorroboration,
    decision: ReceiptDecision,
) -> RuntimeReceipt:
    process_digest = _section_sha256(process)
    return RuntimeReceipt(
        schema=prior.schema,
        schema_version=prior.schema_version,
        stable_identity=prior.stable_identity,
        stable_identity_sha256=prior.stable_identity_sha256,
        launch_instance=prior.launch_instance,
        launch_instance_sha256=prior.launch_instance_sha256,
        launch_binding=prior.launch_binding,
        launch_binding_sha256=prior.launch_binding_sha256,
        process_corroboration=process,
        process_corroboration_sha256=process_digest,
        receipt_sha256=Sha256(
            receipt_sha256(
                prior.stable_identity_sha256.value,
                prior.launch_instance_sha256.value,
                prior.launch_binding_sha256.value,
                process_digest.value,
            )
        ),
        decision=decision,
    )


def _canonical_receipt(
    receipt: RuntimeReceipt,
) -> RuntimeReceipt | PlumbingFailure:
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
    return parsed


def build_pending_receipt(
    evidence: OfflineRuntimeEvidence,
    *,
    stable_inputs: StableIssuanceInputs,
    launch_inputs: LaunchIssuanceInputs,
    binding_inputs: BindingIssuanceInputs,
) -> PendingReceiptIssued | PlumbingFailure:
    """Adapt accepted offline evidence into a canonical pending receipt."""

    if not isinstance(evidence, OfflineRuntimeEvidence):
        raise TypeError("evidence must be OfflineRuntimeEvidence")
    if (
        launch_inputs.source_directory
        != evidence.distribution.source.root.requested_path
    ):
        return plumbing_failure(
            PlumbingDisposition.COLLECTION_FAILED,
            PlumbingReason.COLLECTION_ADAPTATION_FAILED,
            source_reason_codes=("source_directory_mismatch",),
        )
    stable = _stable_identity(evidence, stable_inputs)
    if isinstance(stable, PlumbingFailure):
        return stable
    instance = _launch_instance(evidence, stable_inputs, launch_inputs)
    process = ProcessCorroboration(
        state=CorroborationState.PENDING,
        verification_policy_id=PROCESS_VERIFICATION_POLICY_ID,
        attempt=0,
        observed_at_utc=None,
        pid=None,
        starttime_before=None,
        starttime_after=None,
        process_uid=None,
        comm_observed=None,
        comm_authoritative=False,
        mapped_executable=None,
        mapped_native_images=(),
        mismatch_observations=(),
    )
    receipt = _canonical_receipt(
        _assemble_receipt(
            stable=stable,
            instance=instance,
            binding_inputs=binding_inputs,
            process=process,
            decision=ReceiptDecision(
                state=DecisionState.PENDING,
                reason_codes=(),
            ),
        )
    )
    if isinstance(receipt, PlumbingFailure):
        return receipt
    reference = reference_from_receipt(receipt)
    if isinstance(reference, PlumbingFailure):
        return reference
    return _checked_issuance_result(
        PendingReceiptIssued(receipt=receipt, reference=reference),
        PendingReceiptIssued,
    )


def _native_artifact(
    receipt: RuntimeReceipt,
    name: ArtifactName,
) -> FileObservation:
    for item in receipt.launch_instance.artifacts:
        if item.name is name:
            return item.file
    raise ValueError("required native artifact is missing")


def _native_mapping(
    evidence: MappedObjectEvidence,
    receipt: RuntimeReceipt,
) -> MappedNativeImageEvidence:
    role_map = {
        MappedObjectRole.RUNTIME_NODE: ArtifactName.RUNTIME_NODE,
        MappedObjectRole.CLI_NATIVE_NODE: ArtifactName.CLI_NATIVE_NODE,
    }
    try:
        name = role_map[evidence.role]
    except KeyError as exc:
        raise ValueError("loader cannot be adapted as a native image") from exc
    artifact = _native_artifact(receipt, name)
    return MappedNativeImageEvidence(
        module_name=name,
        observed_path=evidence.observed_path,
        pathname_source=PathnameEvidenceSource.PROC_MAPS,
        mapped_inode=U64Decimal(evidence.mapped_inode),
        inode_source=InodeEvidenceSource.PROC_MAPS,
        maps_device=evidence.maps_device,
        maps_device_source=DeviceEvidenceSource.PROC_MAPS,
        mount_device=evidence.mount_device,
        mount_device_source=DeviceEvidenceSource.PROC_SELF_MOUNTINFO,
        sealed_path_recheck_sha256=artifact.sha256,
        sealed_path_recheck_source=HashEvidenceSource.SEALED_PATH_REOPEN,
        evidence_strength=EvidenceStrength.CORROBORATED,
        executable_mapping=evidence.executable_mapping,
        deleted=evidence.deleted,
    )


def _verified_process(
    prior: RuntimeReceipt,
    evidence: LinuxProcessEvidence,
    observed_at_utc: UtcTimestamp,
) -> ProcessCorroboration | PlumbingFailure:
    binding = prior.launch_binding
    if evidence.observed_pid != binding.session_pid.value:
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.PID_MISMATCH,
        )
    if (
        evidence.starttime_before != binding.session_starttime_ticks.value
        or evidence.starttime_after != binding.session_starttime_ticks.value
    ):
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.STARTTIME_MISMATCH,
        )
    if (
        evidence.observed_euid != binding.launcher_euid.value
        or evidence.pid_namespace_inode != binding.pid_namespace_inode.value
    ):
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.PROCESS_BINDING_MISMATCH,
        )
    mapped_executable = MappedExecutableEvidence(
        evidence_strength=EvidenceStrength.STRONG,
        source=ExecutableEvidenceSource.PROC_PID_EXE,
        mapped_file=_file_observation(
            evidence.proc_exe,
            path_kind=PathKind.PROC_EXE_DESCRIPTOR,
        ),
        current_disk_file=prior.launch_instance.frontend_executable,
    )
    try:
        mapped_native_images = tuple(
            _native_mapping(item, prior)
            for item in sorted(
                evidence.native_mappings,
                key=lambda item: item.role.value,
            )
        )
    except ValueError:
        return plumbing_failure(
            PlumbingDisposition.COLLECTION_FAILED,
            PlumbingReason.COLLECTION_ADAPTATION_FAILED,
            source_reason_codes=("native_mapping_role_invalid",),
        )
    return ProcessCorroboration(
        state=CorroborationState.VERIFIED,
        verification_policy_id=PROCESS_VERIFICATION_POLICY_ID,
        attempt=prior.process_corroboration.attempt + 1,
        observed_at_utc=observed_at_utc,
        pid=U64Decimal(evidence.observed_pid),
        starttime_before=U64Decimal(evidence.starttime_before),
        starttime_after=U64Decimal(evidence.starttime_after),
        process_uid=U64Decimal(evidence.observed_euid),
        comm_observed=evidence.comm_observed,
        comm_authoritative=False,
        mapped_executable=mapped_executable,
        mapped_native_images=mapped_native_images,
        mismatch_observations=(),
    )


def build_verified_receipt(
    pending: PendingReceiptIssued,
    *,
    process_evidence: LinuxProcessEvidence,
    observed_at_utc: UtcTimestamp,
    profiles: ProfileStore,
    session_token: SessionToken,
    now: datetime,
) -> VerifiedReceiptIssued | PlumbingFailure:
    """Finalize pending evidence through the accepted static verifier only."""

    if not isinstance(pending, PendingReceiptIssued):
        raise TypeError("pending must be PendingReceiptIssued")
    invariant_failure = authority_invariant_failure(
        pending,
        PendingReceiptIssued,
    )
    if invariant_failure is not None:
        return invariant_failure
    if pending.reference.state is not ReceiptState.PENDING:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_TRANSITION,
        )
    process = _verified_process(
        pending.receipt,
        process_evidence,
        observed_at_utc,
    )
    if isinstance(process, PlumbingFailure):
        return process
    receipt = _canonical_receipt(
        _reassemble_receipt(
            pending.receipt,
            process=process,
            decision=ReceiptDecision(
                state=DecisionState.VERIFIED,
                reason_codes=(),
            ),
        )
    )
    if isinstance(receipt, PlumbingFailure):
        return receipt
    if not session_token.matches_commitment(
        receipt.launch_binding.session_token_commitment_sha256
    ):
        return plumbing_failure(
            PlumbingDisposition.BINDING_FAILED,
            PlumbingReason.TOKEN_MISMATCH,
        )
    expected = ExpectedBinding(
        session_id=receipt.launch_binding.session_id.value,
        launch_id=receipt.launch_binding.launch_id.value,
        session_pid=receipt.launch_binding.session_pid.value,
        session_starttime_ticks=receipt.launch_binding.session_starttime_ticks.value,
        boot_id=receipt.launch_binding.boot_id.value,
        pid_namespace_inode=receipt.launch_binding.pid_namespace_inode.value,
        launcher_euid=receipt.launch_binding.launcher_euid.value,
        token_hex=session_token._hex_for_static_verifier(),
    )
    from .verify import verify_receipt_static

    verified = verify_receipt_static(
        receipt,
        profiles=profiles,
        expected=expected,
        now=now,
    )
    if isinstance(verified, ReceiptRejection):
        return plumbing_failure(
            PlumbingDisposition.RECEIPT_REJECTED,
            PlumbingReason.STATIC_VERIFICATION_FAILED,
            source_reason_codes=tuple(code.value for code in verified.reason_codes),
        )
    reference = reference_from_receipt(verified.receipt)
    if isinstance(reference, PlumbingFailure):
        return reference
    transition_failure = reference_transition_mismatch(
        pending.reference,
        reference,
    )
    if transition_failure is not None:
        return transition_failure
    try:
        snapshot = snapshot_from_static_verification(verified)
        issued = VerifiedReceiptIssued(
            receipt=verified.receipt,
            reference=reference,
            verification=verified,
            snapshot=snapshot,
        )
    except AuthorityInvariantError:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.AUTHORITY_INVARIANT_VIOLATION,
        )
    return _checked_issuance_result(issued, VerifiedReceiptIssued)


_COLLECTION_REASON_MAP = {
    CollectionReasonCode.PATH_POLICY_VIOLATION: ReasonCode.PATH_POLICY_VIOLATION,
    CollectionReasonCode.NOT_REGULAR: ReasonCode.EXECUTABLE_NOT_REGULAR,
    CollectionReasonCode.NOT_EXECUTABLE: ReasonCode.EXECUTABLE_NOT_EXECUTABLE,
    CollectionReasonCode.OWNER_MISMATCH: ReasonCode.EXECUTABLE_OWNER_MISMATCH,
    CollectionReasonCode.FILE_MUTATED: ReasonCode.EXECUTABLE_IDENTITY_MISMATCH,
    CollectionReasonCode.ELF_INVALID: ReasonCode.ELF_INVALID,
    CollectionReasonCode.ELF_INTERPRETER_MISSING: ReasonCode.ELF_INTERPRETER_MISSING,
    CollectionReasonCode.ARTIFACT_MISSING: ReasonCode.ARTIFACT_MISSING,
    CollectionReasonCode.PACKAGE_MANIFEST_INVALID: ReasonCode.PACKAGE_MANIFEST_INVALID,
    CollectionReasonCode.DISTRIBUTION_VERSION_MISMATCH: (
        ReasonCode.DISTRIBUTION_VERSION_MISMATCH
    ),
    CollectionReasonCode.SCHEMA_DIGEST_MISMATCH: ReasonCode.SCHEMA_HASH_MISMATCH,
    CollectionReasonCode.MAPPED_DEVICE_UNVERIFIABLE: (
        ReasonCode.MAPPED_DEVICE_UNVERIFIABLE
    ),
    CollectionReasonCode.MAPPED_NATIVE_IMAGE_UNEXPECTED: (
        ReasonCode.MAPPED_NATIVE_IMAGE_UNEXPECTED
    ),
    CollectionReasonCode.PROCESS_SCOPE_MISMATCH: ReasonCode.PROCESS_STAMP_MISMATCH,
    CollectionReasonCode.MAPPED_MODULE_MISSING: (
        ReasonCode.MAPPED_RUNTIME_IMAGE_UNAVAILABLE
    ),
    CollectionReasonCode.MAPPED_MODULE_NOT_EXECUTABLE: (
        ReasonCode.MAPPED_RUNTIME_IMAGE_MISMATCH
    ),
    CollectionReasonCode.MAPPED_MODULE_IDENTITY_MISMATCH: (
        ReasonCode.MAPPED_RUNTIME_IMAGE_MISMATCH
    ),
    CollectionReasonCode.MAPPED_FILE_DELETED: ReasonCode.MAPPED_DISK_DIVERGENCE,
}

_COLLECTION_DISPOSITION_DEFAULT = {
    CollectionDisposition.INVALID_REQUEST: ReasonCode.RECEIPT_MALFORMED,
    CollectionDisposition.UNSUPPORTED_PLATFORM: ReasonCode.PLATFORM_UNSUPPORTED,
    CollectionDisposition.UNAVAILABLE: ReasonCode.MAPPED_IMAGE_UNAVAILABLE,
    CollectionDisposition.POLICY_REJECTED: ReasonCode.PATH_POLICY_VIOLATION,
    CollectionDisposition.LIMIT_EXCEEDED: ReasonCode.MAPPED_EVIDENCE_UNSUPPORTED,
    CollectionDisposition.MALFORMED_INPUT: ReasonCode.RECEIPT_MALFORMED,
    CollectionDisposition.CHANGED_DURING_COLLECTION: ReasonCode.OWNERSHIP_CHANGED,
    CollectionDisposition.INCOMPLETE: ReasonCode.RECEIPT_PARTIAL,
    CollectionDisposition.AMBIGUOUS: ReasonCode.MAPPED_EVIDENCE_UNSUPPORTED,
    CollectionDisposition.MISMATCH: ReasonCode.MAPPED_IMAGE_MISMATCH,
}


def receipt_reasons_from_collection(
    failure: CollectionFailure,
) -> tuple[ReasonCode, ...]:
    """Map typed collector denials into the existing receipt reason vocabulary."""

    if not isinstance(failure, CollectionFailure):
        raise TypeError("failure must be CollectionFailure")
    mapped = tuple(
        dict.fromkeys(
            _COLLECTION_REASON_MAP.get(
                reason,
                _COLLECTION_DISPOSITION_DEFAULT[failure.disposition],
            )
            for reason in failure.reason_codes
        )
    )
    return mapped


def build_rejected_receipt(
    prior: (
        PendingReceiptIssued
        | VerifiedReceiptIssued
        | RejectedReceiptIssued
        | RuntimeReceipt
    ),
    *,
    reason_codes: tuple[ReasonCode, ...],
    observed_at_utc: UtcTimestamp | None = None,
    mismatch_observations: tuple[MismatchObservation, ...] = (),
) -> RejectedReceiptIssued | PlumbingFailure:
    """Build a terminal rejected receipt without verification fallback."""

    if not reason_codes or len(reason_codes) > 32:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_TRANSITION,
        )
    if len(set(reason_codes)) != len(reason_codes):
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_TRANSITION,
        )
    if isinstance(prior, PendingReceiptIssued):
        invariant_failure = authority_invariant_failure(
            prior,
            PendingReceiptIssued,
        )
        if invariant_failure is not None:
            return invariant_failure
        receipt = prior.receipt
    elif isinstance(prior, VerifiedReceiptIssued):
        invariant_failure = authority_invariant_failure(
            prior,
            VerifiedReceiptIssued,
        )
        if invariant_failure is not None:
            return invariant_failure
        receipt = prior.receipt
    elif isinstance(prior, RejectedReceiptIssued):
        invariant_failure = authority_invariant_failure(
            prior,
            RejectedReceiptIssued,
        )
        if invariant_failure is not None:
            return invariant_failure
        receipt = prior.receipt
    elif isinstance(prior, RuntimeReceipt):
        receipt = prior
    else:
        raise TypeError(
            "prior must be PendingReceiptIssued, VerifiedReceiptIssued, "
            "RejectedReceiptIssued, or RuntimeReceipt"
        )
    prior_reference = reference_from_receipt(receipt)
    if isinstance(prior_reference, PlumbingFailure):
        return prior_reference
    if prior_reference.state not in {ReceiptState.PENDING, ReceiptState.VERIFIED}:
        return plumbing_failure(
            PlumbingDisposition.INVALID_REQUEST,
            PlumbingReason.INVALID_TRANSITION,
            details={"state": prior_reference.state.value},
        )
    previous_process = receipt.process_corroboration
    process = ProcessCorroboration(
        state=CorroborationState.REJECTED,
        verification_policy_id=previous_process.verification_policy_id,
        attempt=previous_process.attempt + 1,
        observed_at_utc=observed_at_utc or previous_process.observed_at_utc,
        pid=previous_process.pid,
        starttime_before=previous_process.starttime_before,
        starttime_after=previous_process.starttime_after,
        process_uid=previous_process.process_uid,
        comm_observed=previous_process.comm_observed,
        comm_authoritative=False,
        mapped_executable=previous_process.mapped_executable,
        mapped_native_images=previous_process.mapped_native_images,
        mismatch_observations=mismatch_observations
        or previous_process.mismatch_observations,
    )
    rejected = _canonical_receipt(
        _reassemble_receipt(
            receipt,
            process=process,
            decision=ReceiptDecision(
                state=DecisionState.REJECTED,
                reason_codes=reason_codes,
            ),
        )
    )
    if isinstance(rejected, PlumbingFailure):
        return rejected
    reference = reference_from_receipt(rejected)
    if isinstance(reference, PlumbingFailure):
        return reference
    transition_failure = reference_transition_mismatch(
        prior_reference,
        reference,
    )
    if transition_failure is not None:
        return transition_failure
    return _checked_issuance_result(
        RejectedReceiptIssued(receipt=rejected, reference=reference),
        RejectedReceiptIssued,
    )


def build_rejected_from_collection(
    prior: (
        PendingReceiptIssued
        | VerifiedReceiptIssued
        | RejectedReceiptIssued
        | RuntimeReceipt
    ),
    *,
    failure: CollectionFailure,
    observed_at_utc: UtcTimestamp | None = None,
) -> RejectedReceiptIssued | PlumbingFailure:
    """Build a rejection while preserving typed collector reason strings."""

    return build_rejected_receipt(
        prior,
        reason_codes=receipt_reasons_from_collection(failure),
        observed_at_utc=observed_at_utc,
    )


def default_linux_x86_64_platform() -> PlatformIdentity:
    """Return the explicit platform value used by the accepted static verifier."""

    return PlatformIdentity(
        system=PlatformSystem.LINUX,
        architecture=Architecture.X86_64,
        elf_class=ElfClass.ELF64,
        endianness=Endianness.LITTLE,
        pointer_bits=64,
        libc_family=LibcFamily.GLIBC,
    )


__all__ = [
    "PROCESS_VERIFICATION_POLICY_ID",
    "RECEIPT_IMPLEMENTATION_ID",
    "BindingIssuanceInputs",
    "LaunchIssuanceInputs",
    "PendingReceiptIssued",
    "RejectedReceiptIssued",
    "StableIssuanceInputs",
    "VerifiedReceiptIssued",
    "build_pending_receipt",
    "build_rejected_from_collection",
    "build_rejected_receipt",
    "build_verified_receipt",
    "default_linux_x86_64_platform",
    "receipt_reasons_from_collection",
]
