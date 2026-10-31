"""Adversarial tests for Stage 2 runtime-receipt model and storage plumbing."""

from __future__ import annotations

import ast
import contextlib
import copy
import dataclasses
import importlib
import json
import os
import socket
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, cast

import pytest

from core.startup.runtime_receipt.canonical import (
    MAX_RECEIPT_BYTES,
    canonical_bytes,
    token_commitment,
)
from core.startup.runtime_receipt.issuance import (
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
)
from core.startup.runtime_receipt.persistence import (
    PersistenceCrashPoint,
    cleanup_pointer_temporary,
    cleanup_selected_receipt,
    cleanup_sidecar_temporary,
    cleanup_unreferenced_sidecar,
    compare_and_swap_modeled_pointer,
    initialize_modeled_pointer,
    read_modeled_pointer,
    read_receipt_sidecar,
    write_receipt_sidecar,
)
from core.startup.runtime_receipt.plumbing_types import (
    MAX_REFERENCE_BYTES,
    MAX_SNAPSHOT_BYTES,
    AuthorityInvariantError,
    CanonicalPid,
    CasApplied,
    CleanupApplied,
    ModeledPointer,
    PlumbingDisposition,
    PlumbingFailure,
    PlumbingReason,
    ReceiptComparatorInput,
    ReceiptComparisonResult,
    ReceiptReference,
    ReceiptState,
    ReceiptStateRecord,
    RuntimeReceiptSnapshot,
    SessionToken,
    StoredReceipt,
    TransitionApplied,
    compare_receipt_snapshot,
    parse_reference,
    parse_snapshot,
    plumbing_failure,
    reference_receipt_mismatch,
    reference_transition_mismatch,
    serialize_reference,
    serialize_snapshot,
    token_commitment_from_bytes,
    token_commitment_matches,
    transition_state,
)
from core.startup.runtime_receipt.profile import (
    ProfileStore,
    load_profile_store,
)
from core.startup.runtime_receipt.reasons import (
    ReasonCode,
    ReceiptRejection,
)
from core.startup.runtime_receipt.schema import (
    AbsolutePath,
    ArtifactName,
    DeviceMajorMinor,
    Endianness,
    ExpectedBinding,
    Identifier,
    NonceHex,
    Sha256,
    U64Decimal,
    UtcTimestamp,
    UuidText,
)
from core.startup.runtime_receipt.verify import (
    parse_receipt,
    serialize_receipt,
    verify_receipt_static,
)
from core.startup.tests.test_runtime_receipt import (
    _receipt_document,
    _seed,
    _verification_now,
)

_collector_types = importlib.import_module(
    "core.startup.runtime_receipt.collector_types"
)
_persistence = importlib.import_module("core.startup.runtime_receipt.persistence")
ArtifactEvidence = _collector_types.ArtifactEvidence
CollectionDisposition = _collector_types.CollectionDisposition
CollectionFailure = _collector_types.CollectionFailure
CollectionReasonCode = _collector_types.CollectionReasonCode
CollectorElfClass = _collector_types.CollectorElfClass
DescriptorIdentity = _collector_types.DescriptorIdentity
DescriptorStat = _collector_types.DescriptorStat
DistributionEvidence = _collector_types.DistributionEvidence
ElfInspection = _collector_types.ElfInspection
ElfInterpreterAbsent = _collector_types.ElfInterpreterAbsent
ElfInterpreterPresent = _collector_types.ElfInterpreterPresent
EmbeddedPayloadObservation = _collector_types.EmbeddedPayloadObservation
EvidenceSubject = _collector_types.EvidenceSubject
FileEvidence = _collector_types.FileEvidence
FileRole = _collector_types.FileRole
LinuxProcessEvidence = _collector_types.LinuxProcessEvidence
MappedObjectEvidence = _collector_types.MappedObjectEvidence
MappedObjectRole = _collector_types.MappedObjectRole
ObservedDistributionSource = _collector_types.ObservedDistributionSource
OfflineRuntimeEvidence = _collector_types.OfflineRuntimeEvidence
OperationCounters = _collector_types.OperationCounters
PackageManifestObservation = _collector_types.PackageManifestObservation
PathBindingState = _collector_types.PathBindingState
PathObservation = _collector_types.PathObservation
PathPolicyId = _collector_types.PathPolicyId
ResolvedInterpreterEvidence = _collector_types.ResolvedInterpreterEvidence
SchemaEvidence = _collector_types.SchemaEvidence
TreeManifestObservation = _collector_types.TreeManifestObservation
TrustedGrammarDigestInput = _collector_types.TrustedGrammarDigestInput
TrustedHelpContractDigestInput = _collector_types.TrustedHelpContractDigestInput

TOKEN_BYTES = bytes.fromhex("00112233445566778899aabbccddeeff")
OTHER_DIGEST = Sha256("f" * 64)


@dataclasses.dataclass(frozen=True, slots=True)
class _IssuedSet:
    pending: PendingReceiptIssued
    verified: VerifiedReceiptIssued
    rejected: RejectedReceiptIssued
    profiles: ProfileStore


def _accepted_receipt():
    parsed = parse_receipt(canonical_bytes(_receipt_document()))
    assert not isinstance(parsed, ReceiptRejection)
    return parsed


def _file_evidence(
    observation,
    *,
    role: FileRole,
    elf_build_id: str | None = None,
) -> FileEvidence:
    descriptor = DescriptorIdentity(
        stat=DescriptorStat(
            device=observation.device.value,
            inode=observation.inode.value,
            mode_octal=observation.mode_octal,
            uid=observation.uid.value,
            gid=observation.gid.value,
            size_bytes=observation.size_bytes.value,
            nlink=observation.nlink.value,
            mtime_ns=observation.mtime_ns.value,
            ctime_ns=observation.ctime_ns.value,
        ),
        sha256=observation.sha256.value,
        format_id=observation.format_id,
        elf_build_id_sha1=elf_build_id,
        bytes_hashed=observation.size_bytes.value,
    )
    policy = (
        PathPolicyId.RESOLVED_INTERPRETER_V1
        if role is FileRole.ELF_INTERPRETER
        else PathPolicyId.PROC_EXE_MAGICLINK_V1
        if role is FileRole.PROC_EXE
        else PathPolicyId.DISTRIBUTION_REGULAR_NO_SYMLINK_V1
        if role in {FileRole.PACKAGE_MANIFEST, FileRole.DISTRIBUTION_ARTIFACT}
        else PathPolicyId.DIRECT_REGULAR_NO_SYMLINK_V1
    )
    return FileEvidence(
        role=role,
        descriptor=descriptor,
        path=PathObservation(
            requested_path=observation.path,
            resolved_path=observation.path,
            policy_id=policy,
            components=(),
            binding_state=PathBindingState.STABLE,
            asserted_prefix_components=0,
        ),
    )


def _offline_evidence(receipt) -> tuple[OfflineRuntimeEvidence, FileEvidence]:
    stable = receipt.stable_identity
    instance = receipt.launch_instance
    stable_artifacts = {
        item.name: item.content for item in stable.distribution.artifacts
    }
    observed_artifacts = {item.name: item.file for item in instance.artifacts}
    launcher = _file_evidence(
        instance.issuer.launcher_file,
        role=FileRole.CONTRACT_INPUT,
        elf_build_id=stable.launcher.elf_build_id_sha1.value
        if stable.launcher.elf_build_id_sha1 is not None
        else None,
    )
    frontend = _file_evidence(
        instance.frontend_executable,
        role=FileRole.FRONTEND_EXECUTABLE,
        elf_build_id=stable.frontend_executable.elf_build_id_sha1.value
        if stable.frontend_executable.elf_build_id_sha1 is not None
        else None,
    )
    interpreter_file = _file_evidence(
        instance.elf_interpreter,
        role=FileRole.ELF_INTERPRETER,
        elf_build_id=stable.elf_interpreter.content.elf_build_id_sha1.value
        if stable.elf_interpreter.content.elf_build_id_sha1 is not None
        else None,
    )
    package = PackageManifestObservation(
        file=_file_evidence(
            instance.package_manifest_file,
            role=FileRole.PACKAGE_MANIFEST,
        ),
        name=stable.distribution.package_manifest.name,
        version=stable.distribution.package_manifest.version,
        package_type=stable.distribution.package_manifest.package_type,
        bin_name=stable.distribution.package_manifest.bin_name,
        bin_target=stable.distribution.package_manifest.bin_target,
    )
    artifacts = tuple(
        ArtifactEvidence(
            name=name,
            file=_file_evidence(
                observed_artifacts[name],
                role=FileRole.DISTRIBUTION_ARTIFACT,
                elf_build_id=(
                    stable_artifacts[name].elf_build_id_sha1.value
                    if stable_artifacts[name].elf_build_id_sha1 is not None
                    else None
                ),
            ),
        )
        for name in sorted(stable_artifacts, key=lambda item: item.value)
    )
    artifact_files = {item.name: item.file for item in artifacts}
    schemas = tuple(
        SchemaEvidence(
            name=schema.name,
            file=artifact_files[
                ArtifactName.SESSION_EVENTS_SCHEMA
                if schema.name.value == "session-events"
                else ArtifactName.API_SCHEMA
            ],
            source_record_sha256=Sha256("a" * 64),
            definition_count=schema.definition_count,
            property_count=schema.property_count,
            event_type_literal_count=schema.event_type_literal_count,
            event_variant_count=schema.event_variant_count,
            definition_names_sha256=schema.definition_names_sha256,
            property_names_sha256=schema.property_names_sha256,
            event_type_literals_sha256=schema.event_type_literals_sha256,
        )
        for schema in stable.contract.schemas
    )
    distribution = DistributionEvidence(
        source=ObservedDistributionSource(
            root=PathObservation(
                requested_path=instance.source_directory,
                resolved_path=instance.source_directory,
                policy_id=PathPolicyId.DISTRIBUTION_REGULAR_NO_SYMLINK_V1,
                components=(),
                binding_state=PathBindingState.STABLE,
                asserted_prefix_components=0,
            )
        ),
        version=stable.distribution.version,
        platform_directory=stable.distribution.platform_directory,
        package_manifest=package,
        artifacts=artifacts,
        schemas=schemas,
        grammar=TrustedGrammarDigestInput(
            source_record_sha256=Sha256("b" * 64),
            source=stable.contract.cli_grammar.source,
            sha256=stable.contract.cli_grammar.sha256,
            root_flag_count=stable.contract.cli_grammar.root_flag_count,
            advertised_root_flag_count=(
                stable.contract.cli_grammar.advertised_root_flag_count
            ),
            hidden_root_flag_count=stable.contract.cli_grammar.hidden_root_flag_count,
        ),
        help_contract=TrustedHelpContractDigestInput(
            source_record_sha256=Sha256("c" * 64),
            manifest_algorithm=stable.contract.help_contract.manifest_algorithm,
            manifest_sha256=stable.contract.help_contract.manifest_sha256,
            surface_count=stable.contract.help_contract.surface_count,
        ),
        content_manifest=TreeManifestObservation(
            algorithm="sha256-tree-v1",
            sha256=stable.distribution.content_manifest.sha256,
            entry_count=stable.distribution.content_manifest.entry_count,
            total_regular_file_bytes=(
                stable.distribution.content_manifest.total_regular_file_bytes.value
            ),
            rows=(),
        ),
        files_hashed=13,
        bytes_hashed=stable.distribution.content_manifest.total_regular_file_bytes.value,
    )
    evidence = OfflineRuntimeEvidence(
        collector_schema="raptor.runtime_receipt_collector/v1",
        collector_schema_version=1,
        frontend=frontend,
        frontend_elf=ElfInspection(
            elf_class=CollectorElfClass.ELF64,
            endianness=Endianness.LITTLE,
            osabi=0,
            elf_type=2,
            machine=62,
            program_header_count=1,
            interpreter=ElfInterpreterPresent(
                path=stable.elf_interpreter.requested_path,
                offset=1,
                size_bytes=2,
            ),
            build_id_sha1=stable.frontend_executable.elf_build_id_sha1,
            format_id=stable.frontend_executable.format_id,
        ),
        interpreter=ResolvedInterpreterEvidence(
            requested_path=stable.elf_interpreter.requested_path,
            file=interpreter_file,
            symlink_chain=(),
        ),
        interpreter_elf=ElfInspection(
            elf_class=CollectorElfClass.ELF64,
            endianness=Endianness.LITTLE,
            osabi=0,
            elf_type=3,
            machine=62,
            program_header_count=1,
            interpreter=ElfInterpreterAbsent(),
            build_id_sha1=stable.elf_interpreter.content.elf_build_id_sha1,
            format_id=stable.elf_interpreter.content.format_id,
        ),
        distribution=distribution,
        embedded_sea_loader=EmbeddedPayloadObservation(
            offset=stable.distribution.embedded_sea_loader.offset.value,
            sha256=stable.distribution.embedded_sea_loader.sha256,
        ),
        counters=OperationCounters(
            files_hashed=15,
            bytes_hashed=1,
            tree_entries=stable.distribution.content_manifest.entry_count,
            maximum_held_descriptors=33,
        ),
    )
    return evidence, launcher


def _process_evidence(receipt) -> LinuxProcessEvidence:
    process = receipt.process_corroboration
    assert process.mapped_executable is not None
    proc_exe = _file_evidence(
        process.mapped_executable.mapped_file,
        role=FileRole.PROC_EXE,
        elf_build_id=receipt.stable_identity.frontend_executable.elf_build_id_sha1.value
        if receipt.stable_identity.frontend_executable.elf_build_id_sha1 is not None
        else None,
    )
    loader_mapping = MappedObjectEvidence(
        role=MappedObjectRole.LOADER,
        observed_path=process.mapped_executable.mapped_file.path,
        mapped_inode=process.mapped_executable.mapped_file.inode.value,
        maps_device=DeviceMajorMinor("0:52"),
        mount_device=DeviceMajorMinor("0:52"),
        mount_id=1,
        parent_mount_id=0,
        fdinfo_mount_id=None,
        filesystem_type="ext4",
        executable_mapping=True,
        deleted=False,
        segments=(),
    )
    role_by_name = {
        ArtifactName.RUNTIME_NODE: MappedObjectRole.RUNTIME_NODE,
        ArtifactName.CLI_NATIVE_NODE: MappedObjectRole.CLI_NATIVE_NODE,
    }
    native = tuple(
        MappedObjectEvidence(
            role=role_by_name[item.module_name],
            observed_path=item.observed_path,
            mapped_inode=item.mapped_inode.value,
            maps_device=item.maps_device,
            mount_device=item.mount_device,
            mount_id=index + 2,
            parent_mount_id=1,
            fdinfo_mount_id=None,
            filesystem_type="ext4",
            executable_mapping=item.executable_mapping,
            deleted=item.deleted,
            segments=(),
        )
        for index, item in enumerate(process.mapped_native_images)
    )
    assert len(native) == 2
    return LinuxProcessEvidence(
        observed_pid=cast(U64Decimal, process.pid).value,
        starttime_before=cast(U64Decimal, process.starttime_before).value,
        starttime_after=cast(U64Decimal, process.starttime_after).value,
        observed_euid=cast(U64Decimal, process.process_uid).value,
        pid_namespace_inode=receipt.launch_binding.pid_namespace_inode.value,
        mount_namespace_inode=4026531840,
        comm_observed=process.comm_observed or "",
        comm_truncated=False,
        comm_authoritative=False,
        proc_exe=proc_exe,
        loader_mapping=loader_mapping,
        native_mappings=cast(
            tuple[MappedObjectEvidence, MappedObjectEvidence],
            native,
        ),
        maps_sha256=Sha256("d" * 64),
        maps_bytes=1,
        maps_lines=1,
        mountinfo_sha256=Sha256("e" * 64),
        mountinfo_bytes=1,
        mountinfo_lines=1,
    )


@pytest.fixture
def issued() -> _IssuedSet:
    accepted = _accepted_receipt()
    evidence, launcher = _offline_evidence(accepted)
    profiles = load_profile_store()
    assert not isinstance(profiles, ReceiptRejection)
    stable_inputs = StableIssuanceInputs(
        profile=profiles.profiles[0],
        launcher=launcher,
        platform=accepted.stable_identity.platform,
        distribution_source=accepted.stable_identity.distribution.source,
        required_semantics=accepted.stable_identity.contract.required_semantics,
    )
    launch_inputs = LaunchIssuanceInputs(
        session_id=accepted.launch_instance.session_id,
        launch_id=accepted.launch_instance.launch_id,
        repository_head=accepted.launch_instance.issuer.repository_head,
        source_directory=accepted.launch_instance.source_directory,
        sealed_directory=accepted.launch_instance.sealed_directory,
        selection=accepted.launch_instance.selection,
        version_observation=accepted.launch_instance.version_observation,
    )
    binding = accepted.launch_binding
    pending = build_pending_receipt(
        evidence,
        stable_inputs=stable_inputs,
        launch_inputs=launch_inputs,
        binding_inputs=BindingIssuanceInputs(
            session_pid=binding.session_pid.value,
            session_starttime_ticks=binding.session_starttime_ticks.value,
            boot_id=binding.boot_id,
            pid_namespace_inode=binding.pid_namespace_inode.value,
            launcher_euid=binding.launcher_euid.value,
            session_token=SessionToken(TOKEN_BYTES),
            launch_nonce=binding.receipt_nonce,
            issued_at_utc=binding.issued_at_utc,
            freshness_not_after_utc=binding.freshness_not_after_utc,
        ),
    )
    assert isinstance(pending, PendingReceiptIssued)
    verified = build_verified_receipt(
        pending,
        process_evidence=_process_evidence(accepted),
        observed_at_utc=cast(
            UtcTimestamp,
            accepted.process_corroboration.observed_at_utc,
        ),
        profiles=profiles,
        session_token=SessionToken(TOKEN_BYTES),
        now=_verification_now(),
    )
    assert isinstance(verified, VerifiedReceiptIssued)
    rejected = build_rejected_receipt(
        pending,
        reason_codes=(ReasonCode.MAPPED_IMAGE_UNAVAILABLE,),
        observed_at_utc=cast(
            UtcTimestamp,
            accepted.process_corroboration.observed_at_utc,
        ),
    )
    assert isinstance(rejected, RejectedReceiptIssued)
    return _IssuedSet(
        pending=pending,
        verified=verified,
        rejected=rejected,
        profiles=profiles,
    )


def _store_root(tmp_path: Path, name: str = "store") -> Path:
    root = tmp_path / name
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def _write_raw_sidecar(
    root: Path,
    reference: ReceiptReference,
    raw: bytes,
) -> Path:
    path = root / reference.sidecar_name
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


def _expected_binding(receipt, token: bytes = TOKEN_BYTES) -> ExpectedBinding:
    binding = receipt.launch_binding
    return ExpectedBinding(
        session_id=binding.session_id.value,
        launch_id=binding.launch_id.value,
        session_pid=binding.session_pid.value,
        session_starttime_ticks=binding.session_starttime_ticks.value,
        boot_id=binding.boot_id.value,
        pid_namespace_inode=binding.pid_namespace_inode.value,
        launcher_euid=binding.launcher_euid.value,
        token_hex=token.hex(),
    )


def _parse_snapshot_with_context(
    raw: bytes,
    issued: _IssuedSet,
    *,
    token: bytes = TOKEN_BYTES,
):
    return parse_snapshot(
        raw,
        profiles=issued.profiles,
        expected=_expected_binding(issued.verified.receipt, token),
        now=_verification_now(),
    )


def test_issuance_builds_pending_verified_and_rejected_without_authority(
    issued: _IssuedSet,
) -> None:
    assert issued.pending.reference.state is ReceiptState.PENDING
    assert issued.rejected.reference.state is ReceiptState.REJECTED
    assert issued.verified.reference.state is ReceiptState.VERIFIED
    assert issued.verified.authoritative is False
    assert issued.verified.verification.authoritative is False
    assert issued.verified.snapshot.authoritative is False
    assert issued.verified.reason_codes == (
        ReasonCode.PROFILE_UNSUPPORTED,
        ReasonCode.LIVE_CONTRACT_MISSING,
    )
    assert issued.pending.receipt.process_corroboration.attempt == 0
    assert issued.verified.receipt.process_corroboration.attempt == 1
    assert issued.rejected.receipt.process_corroboration.attempt == 1


def test_static_verification_is_the_exact_verified_ceiling(
    issued: _IssuedSet,
) -> None:
    result = verify_receipt_static(
        issued.verified.receipt,
        profiles=issued.profiles,
        expected=_expected_binding(issued.verified.receipt),
        now=_verification_now(),
    )
    assert not isinstance(result, ReceiptRejection)
    assert result.authoritative is False
    assert result.reason_codes == (
        ReasonCode.PROFILE_UNSUPPORTED,
        ReasonCode.LIVE_CONTRACT_MISSING,
    )
    for receipt in (issued.pending.receipt, issued.rejected.receipt):
        denied = verify_receipt_static(
            receipt,
            profiles=issued.profiles,
            expected=_expected_binding(receipt),
            now=_verification_now(),
        )
        assert isinstance(denied, ReceiptRejection)
        assert ReasonCode.RECEIPT_STATE_NOT_VERIFIED in denied.reason_codes


def test_pending_issuance_requires_the_explicit_collected_source_directory() -> None:
    accepted = _accepted_receipt()
    evidence, launcher = _offline_evidence(accepted)
    profiles = load_profile_store()
    assert not isinstance(profiles, ReceiptRejection)
    result = build_pending_receipt(
        evidence,
        stable_inputs=StableIssuanceInputs(
            profile=profiles.profiles[0],
            launcher=launcher,
            platform=accepted.stable_identity.platform,
            distribution_source=accepted.stable_identity.distribution.source,
            required_semantics=accepted.stable_identity.contract.required_semantics,
        ),
        launch_inputs=LaunchIssuanceInputs(
            session_id=accepted.launch_instance.session_id,
            launch_id=accepted.launch_instance.launch_id,
            repository_head=accepted.launch_instance.issuer.repository_head,
            source_directory=AbsolutePath("/different/source"),
            sealed_directory=accepted.launch_instance.sealed_directory,
            selection=accepted.launch_instance.selection,
            version_observation=accepted.launch_instance.version_observation,
        ),
        binding_inputs=BindingIssuanceInputs(
            session_pid=accepted.launch_binding.session_pid.value,
            session_starttime_ticks=(
                accepted.launch_binding.session_starttime_ticks.value
            ),
            boot_id=accepted.launch_binding.boot_id,
            pid_namespace_inode=accepted.launch_binding.pid_namespace_inode.value,
            launcher_euid=accepted.launch_binding.launcher_euid.value,
            session_token=SessionToken(TOKEN_BYTES),
            launch_nonce=accepted.launch_binding.receipt_nonce,
            issued_at_utc=accepted.launch_binding.issued_at_utc,
            freshness_not_after_utc=(accepted.launch_binding.freshness_not_after_utc),
        ),
    )
    assert isinstance(result, PlumbingFailure)
    assert result.disposition is PlumbingDisposition.COLLECTION_FAILED
    assert result.reason_codes == (PlumbingReason.COLLECTION_ADAPTATION_FAILED,)


@pytest.mark.parametrize("name", ["pending", "verified", "rejected"])
def test_receipt_reference_and_snapshot_canonical_round_trips_are_stable(
    issued: _IssuedSet,
    name: str,
) -> None:
    value = cast(Any, getattr(issued, name))
    raw = serialize_receipt(value.receipt)
    assert serialize_receipt(parse_receipt(raw)) == raw
    reference_raw = serialize_reference(value.reference)
    parsed_reference = parse_reference(reference_raw)
    assert parsed_reference == value.reference
    assert (
        serialize_reference(cast(ReceiptReference, parsed_reference)) == reference_raw
    )
    assert value.reference.receipt_sha256.value in value.reference.sidecar_name
    assert value.reference.sidecar_name.startswith(
        f"{value.reference.session_pid.text}.receipt."
    )
    if name == "verified":
        snapshot_raw = serialize_snapshot(value.snapshot)
        parsed_snapshot = _parse_snapshot_with_context(snapshot_raw, issued)
        assert parsed_snapshot == value.snapshot
        assert (
            serialize_snapshot(cast(RuntimeReceiptSnapshot, parsed_snapshot))
            == snapshot_raw
        )


def test_reference_parser_rejects_unknown_duplicate_noncanonical_and_partial(
    issued: _IssuedSet,
) -> None:
    raw = serialize_reference(issued.pending.reference)
    value = cast(dict[str, Any], json.loads(raw))
    hostile = []
    unknown = copy.deepcopy(value)
    unknown["authority"] = True
    hostile.append(canonical_bytes(unknown))
    partial = copy.deepcopy(value)
    del partial["reference"]["launch_nonce"]
    hostile.append(canonical_bytes(partial))
    noncanonical = copy.deepcopy(value)
    noncanonical["reference"]["session_pid"] = "04242"
    hostile.append(canonical_bytes(noncanonical))
    hostile.append(
        raw.replace(
            b'"schema_version":1',
            b'"schema_version":1,"schema_version":1',
            1,
        )
    )
    for candidate in hostile:
        result = parse_reference(candidate)
        assert isinstance(result, PlumbingFailure)
        assert result.reason_codes == (PlumbingReason.INVALID_RECEIPT_REFERENCE,)


def test_reference_and_snapshot_parser_bounds_are_strict(issued: _IssuedSet) -> None:
    reference_value = cast(
        dict[str, Any],
        json.loads(serialize_reference(issued.pending.reference)),
    )
    reference_value["reference"]["nested"] = [[[[[[[[[[[[[0]]]]]]]]]]]]]
    too_deep = json.dumps(
        reference_value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    too_many = cast(
        dict[str, Any],
        json.loads(serialize_reference(issued.pending.reference)),
    )
    too_many["reference"].update({f"x{index}": index for index in range(65)})
    too_many_raw = json.dumps(
        too_many,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    for raw in (
        b"x" * (MAX_REFERENCE_BYTES + 1),
        too_deep,
        too_many_raw,
    ):
        result = parse_reference(raw)
        assert isinstance(result, PlumbingFailure)
        assert result.reason_codes == (PlumbingReason.INVALID_RECEIPT_REFERENCE,)

    snapshot_value = cast(
        dict[str, Any],
        json.loads(serialize_snapshot(issued.verified.snapshot)),
    )
    snapshot_value["nested"] = [[[[[[[[[[[[[0]]]]]]]]]]]]]
    snapshot_deep = json.dumps(
        snapshot_value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    for raw in (b"x" * (MAX_SNAPSHOT_BYTES + 1), snapshot_deep):
        result = _parse_snapshot_with_context(raw, issued)
        assert isinstance(result, PlumbingFailure)
        assert result.reason_codes == (PlumbingReason.INVALID_COMPARATOR_INPUT,)


def test_state_transition_matrix_is_closed_and_exhaustive(
    issued: _IssuedSet,
) -> None:
    references = {
        ReceiptState.PENDING: issued.pending.reference,
        ReceiptState.VERIFIED: issued.verified.reference,
        ReceiptState.REJECTED: issued.rejected.reference,
    }
    legal = {
        (ReceiptState.ABSENT, ReceiptState.PENDING),
        (ReceiptState.PENDING, ReceiptState.VERIFIED),
        (ReceiptState.PENDING, ReceiptState.REJECTED),
        (ReceiptState.PENDING, ReceiptState.CLEANED),
        (ReceiptState.VERIFIED, ReceiptState.REJECTED),
        (ReceiptState.VERIFIED, ReceiptState.CLEANED),
        (ReceiptState.REJECTED, ReceiptState.CLEANED),
    }
    for prior_state in ReceiptState:
        prior = ReceiptStateRecord(
            prior_state,
            references.get(prior_state),
        )
        for target in ReceiptState:
            result = transition_state(
                prior,
                target,
                reference=references.get(target),
            )
            if (prior_state, target) in legal:
                assert isinstance(result, TransitionApplied)
                assert result.current.state is target
            else:
                assert isinstance(result, PlumbingFailure)
                assert result.disposition is PlumbingDisposition.INVALID_REQUEST
                if prior_state is target:
                    assert result.reason_codes == (PlumbingReason.REPLAYED_TRANSITION,)
                else:
                    assert result.reason_codes[0] in {
                        PlumbingReason.INVALID_TRANSITION,
                        PlumbingReason.SKIPPED_TRANSITION,
                    }
    missing_reference = transition_state(
        ReceiptStateRecord(ReceiptState.ABSENT, None),
        ReceiptState.PENDING,
    )
    assert isinstance(missing_reference, PlumbingFailure)
    assert missing_reference.reason_codes == (PlumbingReason.INVALID_RECEIPT_REFERENCE,)


def test_token_commitment_uses_exact_bytes_constant_time_and_redacts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[bytes, bytes]] = []
    real_compare = __import__("hmac").compare_digest

    def observed(left: bytes, right: bytes) -> bool:
        calls.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr("hmac.compare_digest", observed)
    commitment = token_commitment_from_bytes(TOKEN_BYTES)
    assert commitment.value == token_commitment(TOKEN_BYTES.hex())
    assert token_commitment_matches(TOKEN_BYTES, commitment)
    assert not token_commitment_matches(b"\xff" * 16, commitment)
    assert len(calls) == 2
    assert all(len(left) == len(right) == 32 for left, right in calls)
    assert TOKEN_BYTES.hex() not in repr(SessionToken(TOKEN_BYTES))
    with pytest.raises(ValueError):
        SessionToken(TOKEN_BYTES + b"x")
    with pytest.raises(ValueError):
        token_commitment_from_bytes(bytearray(TOKEN_BYTES))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        (
            "session_token_commitment_sha256",
            OTHER_DIGEST,
            PlumbingReason.TOKEN_MISMATCH,
        ),
        (
            "launch_nonce",
            NonceHex("f" * 32),
            PlumbingReason.LAUNCH_NONCE_MISMATCH,
        ),
        ("session_pid", CanonicalPid(9999), PlumbingReason.PID_MISMATCH),
        (
            "session_starttime_ticks",
            U64Decimal(9999),
            PlumbingReason.STARTTIME_MISMATCH,
        ),
        (
            "session_id",
            UuidText("99999999-8888-4777-8666-555555555555"),
            PlumbingReason.SESSION_MISMATCH,
        ),
        (
            "launch_id",
            UuidText("01234567-89ab-4cde-8f01-23456789abcd"),
            PlumbingReason.LAUNCH_MISMATCH,
        ),
        (
            "profile_id",
            Identifier("other-profile"),
            PlumbingReason.PROFILE_MISMATCH,
        ),
        (
            "stable_identity_sha256",
            OTHER_DIGEST,
            PlumbingReason.STABLE_IDENTITY_MISMATCH,
        ),
        ("receipt_sha256", OTHER_DIGEST, PlumbingReason.DIGEST_MISMATCH),
    ],
)
def test_reference_binding_mismatches_are_typed(
    issued: _IssuedSet,
    field: str,
    value: object,
    reason: PlumbingReason,
) -> None:
    forged = dataclasses.replace(issued.verified.reference, **{field: value})
    mismatch = reference_receipt_mismatch(forged, issued.verified.receipt)
    assert isinstance(mismatch, PlumbingFailure)
    assert mismatch.reason_codes == (reason,)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        (
            "session_token_commitment_sha256",
            OTHER_DIGEST,
            PlumbingReason.TOKEN_MISMATCH,
        ),
        (
            "launch_nonce",
            NonceHex("f" * 32),
            PlumbingReason.LAUNCH_NONCE_MISMATCH,
        ),
        ("session_pid", CanonicalPid(9999), PlumbingReason.PID_MISMATCH),
        (
            "session_starttime_ticks",
            U64Decimal(9999),
            PlumbingReason.STARTTIME_MISMATCH,
        ),
        (
            "session_id",
            UuidText("99999999-8888-4777-8666-555555555555"),
            PlumbingReason.SESSION_MISMATCH,
        ),
        (
            "launch_id",
            UuidText("01234567-89ab-4cde-8f01-23456789abcd"),
            PlumbingReason.LAUNCH_MISMATCH,
        ),
        (
            "profile_id",
            Identifier("other-profile"),
            PlumbingReason.PROFILE_MISMATCH,
        ),
        (
            "stable_identity_sha256",
            OTHER_DIGEST,
            PlumbingReason.STABLE_IDENTITY_MISMATCH,
        ),
        (
            "launch_instance_sha256",
            OTHER_DIGEST,
            PlumbingReason.DIGEST_MISMATCH,
        ),
    ],
)
def test_cas_transition_compares_the_complete_binding_tuple(
    issued: _IssuedSet,
    field: str,
    value: object,
    reason: PlumbingReason,
) -> None:
    replacement = dataclasses.replace(
        issued.verified.reference,
        **{field: value},
    )
    mismatch = reference_transition_mismatch(
        issued.pending.reference,
        replacement,
    )
    assert isinstance(mismatch, PlumbingFailure)
    assert mismatch.reason_codes == (reason,)


def test_snapshot_comparator_is_closed_and_deny_only(issued: _IssuedSet) -> None:
    exact = ReceiptComparatorInput(
        metadata_snapshot=issued.verified.snapshot,
        current_reference=issued.verified.reference,
        current_receipt=issued.verified.receipt,
    )
    assert (
        compare_receipt_snapshot(exact) is ReceiptComparisonResult.MATCH_NON_AUTHORIZING
    )
    assert (
        compare_receipt_snapshot(ReceiptComparatorInput(None, None, None))
        is ReceiptComparisonResult.ABSENT_BOTH
    )
    assert (
        compare_receipt_snapshot(
            ReceiptComparatorInput(
                None,
                issued.verified.reference,
                issued.verified.receipt,
            )
        )
        is ReceiptComparisonResult.METADATA_INVALID
    )
    assert (
        compare_receipt_snapshot(
            ReceiptComparatorInput(issued.verified.snapshot, None, None)
        )
        is ReceiptComparisonResult.REGISTRY_INVALID
    )
    assert (
        compare_receipt_snapshot(
            ReceiptComparatorInput(
                issued.verified.snapshot,
                issued.verified.reference,
                None,
            )
        )
        is ReceiptComparisonResult.RECEIPT_MISSING
    )
    assert (
        compare_receipt_snapshot(
            ReceiptComparatorInput(
                issued.verified.snapshot,
                issued.pending.reference,
                issued.pending.receipt,
            )
        )
        is ReceiptComparisonResult.STATE_NOT_FINAL
    )
    variants = {
        ReceiptComparisonResult.PROFILE_MISMATCH: dataclasses.replace(
            issued.verified.reference,
            profile_id=Identifier("other-profile"),
        ),
        ReceiptComparisonResult.STABLE_IDENTITY_MISMATCH: dataclasses.replace(
            issued.verified.reference,
            stable_identity_sha256=OTHER_DIGEST,
        ),
        ReceiptComparisonResult.LAUNCH_NONCE_MISMATCH: dataclasses.replace(
            issued.verified.reference,
            launch_nonce=NonceHex("f" * 32),
        ),
        ReceiptComparisonResult.SESSION_BINDING_MISMATCH: dataclasses.replace(
            issued.verified.reference,
            session_pid=CanonicalPid(9999),
        ),
        ReceiptComparisonResult.DIGEST_MISMATCH: dataclasses.replace(
            issued.verified.reference,
            receipt_sha256=OTHER_DIGEST,
        ),
    }
    for expected, reference in variants.items():
        result = compare_receipt_snapshot(
            ReceiptComparatorInput(
                issued.verified.snapshot,
                reference,
                issued.verified.receipt,
            )
        )
        assert result is expected


def test_snapshot_parser_rejects_duplicate_unknown_partial_and_mismatch(
    issued: _IssuedSet,
) -> None:
    raw = serialize_snapshot(issued.verified.snapshot)
    value = cast(dict[str, Any], json.loads(raw))
    cases = []
    unknown = copy.deepcopy(value)
    unknown["owner"] = True
    cases.append(canonical_bytes(unknown))
    authority = copy.deepcopy(value)
    authority["authoritative"] = False
    cases.append(canonical_bytes(authority))
    partial = copy.deepcopy(value)
    del partial["profile_id"]
    cases.append(canonical_bytes(partial))
    mismatch = copy.deepcopy(value)
    mismatch["receipt_sha256"] = "0" * 64
    cases.append(canonical_bytes(mismatch))
    cases.append(
        raw.replace(
            b'"schema_version":1',
            b'"schema_version":1,"schema_version":1',
            1,
        )
    )
    for candidate in cases:
        result = _parse_snapshot_with_context(candidate, issued)
        assert isinstance(result, PlumbingFailure)
        assert result.reason_codes == (PlumbingReason.INVALID_COMPARATOR_INPUT,)
    wrong_token = _parse_snapshot_with_context(
        raw,
        issued,
        token=b"\xff" * 16,
    )
    assert isinstance(wrong_token, PlumbingFailure)
    assert wrong_token.disposition is PlumbingDisposition.RECEIPT_REJECTED
    assert ReasonCode.RECEIPT_TOKEN_COMMITMENT_MISMATCH.value in (
        wrong_token.source_reason_codes
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        parse_snapshot(
            raw,
            profiles=issued.profiles,
            expected=_expected_binding(issued.verified.receipt),
            now=datetime.fromisoformat("2026-09-12T08:30:00"),
        )


def test_sidecar_round_trip_and_idempotent_write(
    tmp_path: Path,
    issued: _IssuedSet,
) -> None:
    root = _store_root(tmp_path)
    first = write_receipt_sidecar(
        root,
        issued.pending.reference,
        issued.pending.receipt,
    )
    assert isinstance(first, StoredReceipt)
    assert first.created is True
    second = write_receipt_sidecar(
        root,
        issued.pending.reference,
        issued.pending.receipt,
    )
    assert isinstance(second, StoredReceipt)
    assert second.created is False
    loaded = read_receipt_sidecar(root, issued.pending.reference)
    assert isinstance(loaded, StoredReceipt)
    assert loaded.receipt == issued.pending.receipt
    value = (root / issued.pending.reference.sidecar_name).stat()
    assert stat.S_IMODE(value.st_mode) == 0o600
    assert value.st_uid == os.geteuid()
    assert value.st_nlink == 1


def test_modeled_pointer_rejects_malformed_and_dangling_references(
    tmp_path: Path,
    issued: _IssuedSet,
) -> None:
    malformed_root = _store_root(tmp_path, "malformed-pointer")
    pointer_path = malformed_root / issued.pending.reference.pointer_name
    pointer_path.write_bytes(b"{}")
    pointer_path.chmod(0o600)
    malformed = read_modeled_pointer(
        malformed_root,
        issued.pending.reference.session_pid,
    )
    assert isinstance(malformed, PlumbingFailure)
    assert malformed.reason_codes == (PlumbingReason.POINTER_INVALID,)

    dangling_root = _store_root(tmp_path, "dangling-pointer")
    pointer_path = dangling_root / issued.pending.reference.pointer_name
    pointer_path.write_bytes(serialize_reference(issued.pending.reference))
    pointer_path.chmod(0o600)
    dangling = read_modeled_pointer(
        dangling_root,
        issued.pending.reference.session_pid,
    )
    assert isinstance(dangling, PlumbingFailure)
    assert dangling.reason_codes == (PlumbingReason.SIDECAR_MISSING,)


def test_sidecar_forgery_and_copied_pid_fail_closed(
    tmp_path: Path,
    issued: _IssuedSet,
) -> None:
    root = _store_root(tmp_path)
    document = cast(dict[str, Any], copy.deepcopy(_receipt_document()))
    document["launch_binding"]["session_pid"] = "9999"
    _write_raw_sidecar(
        root,
        issued.verified.reference,
        canonical_bytes(document),
    )
    forged = read_receipt_sidecar(root, issued.verified.reference)
    assert isinstance(forged, PlumbingFailure)
    assert forged.reason_codes == (PlumbingReason.SIDECAR_PARSE_FAILED,)

    copied_root = _store_root(tmp_path, "copied")
    copied_reference = dataclasses.replace(
        issued.verified.reference,
        session_pid=CanonicalPid(9999),
    )
    _write_raw_sidecar(
        copied_root,
        copied_reference,
        serialize_receipt(issued.verified.receipt),
    )
    copied = read_receipt_sidecar(copied_root, copied_reference)
    assert isinstance(copied, PlumbingFailure)
    assert copied.reason_codes == (PlumbingReason.PID_MISMATCH,)


@pytest.mark.parametrize(
    "kind",
    ["missing", "partial", "oversize", "duplicate", "unknown", "noncanonical"],
)
def test_sidecar_parser_and_size_failures(
    tmp_path: Path,
    issued: _IssuedSet,
    kind: str,
) -> None:
    root = _store_root(tmp_path)
    if kind != "missing":
        raw = serialize_receipt(issued.verified.receipt)
        if kind == "partial":
            raw = raw[: len(raw) // 2]
        elif kind == "oversize":
            raw = b"x" * (MAX_RECEIPT_BYTES + 1)
        elif kind == "duplicate":
            raw = (
                b'{"schema":"raptor.runtime_receipt/v1",'
                b'"schema":"raptor.runtime_receipt/v1"}'
            )
        elif kind == "unknown":
            value = cast(dict[str, Any], json.loads(raw))
            value["authority"] = True
            raw = canonical_bytes(value)
        elif kind == "noncanonical":
            raw = b" " + raw
        _write_raw_sidecar(root, issued.verified.reference, raw)
    result = read_receipt_sidecar(root, issued.verified.reference)
    assert isinstance(result, PlumbingFailure)
    if kind == "missing":
        assert result.reason_codes == (PlumbingReason.SIDECAR_MISSING,)
    elif kind == "oversize":
        assert result.reason_codes == (PlumbingReason.SIDECAR_POLICY_VIOLATION,)
    else:
        assert result.reason_codes == (PlumbingReason.SIDECAR_PARSE_FAILED,)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "socket", "directory", "hardlink"])
def test_sidecar_unsafe_file_types_and_links_are_rejected(
    tmp_path: Path,
    issued: _IssuedSet,
    kind: str,
) -> None:
    root = _store_root(tmp_path)
    path = root / issued.verified.reference.sidecar_name
    peer = root / "peer"
    unix_socket: socket.socket | None = None
    if kind == "symlink":
        peer.write_bytes(serialize_receipt(issued.verified.receipt))
        peer.chmod(0o600)
        path.symlink_to(peer)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    elif kind == "socket":
        unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        short_path = root / "s"
        unix_socket.bind(str(short_path))
        short_path.rename(path)
    elif kind == "directory":
        path.mkdir(mode=0o700)
    else:
        peer.write_bytes(serialize_receipt(issued.verified.receipt))
        peer.chmod(0o600)
        os.link(peer, path)
    try:
        result = read_receipt_sidecar(root, issued.verified.reference)
        assert isinstance(result, PlumbingFailure)
        assert result.reason_codes == (PlumbingReason.SIDECAR_POLICY_VIOLATION,)
    finally:
        if unix_socket is not None:
            unix_socket.close()


def test_sidecar_device_validator_wrong_mode_and_owner(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.startup.runtime_receipt import persistence

    with pytest.raises(persistence._PersistenceAbort) as device:
        persistence._validate_regular_stat(
            os.stat("/dev/null"),
            max_bytes=MAX_RECEIPT_BYTES,
            allow_empty=False,
            reason=PlumbingReason.SIDECAR_POLICY_VIOLATION,
            stage="device",
        )
    assert device.value.failure.reason_codes == (
        PlumbingReason.SIDECAR_POLICY_VIOLATION,
    )

    root = _store_root(tmp_path)
    path = _write_raw_sidecar(
        root,
        issued.verified.reference,
        serialize_receipt(issued.verified.receipt),
    )
    path.chmod(0o640)
    wrong_mode = read_receipt_sidecar(root, issued.verified.reference)
    assert isinstance(wrong_mode, PlumbingFailure)
    assert wrong_mode.reason_codes == (PlumbingReason.SIDECAR_POLICY_VIOLATION,)
    path.chmod(0o600)
    sidecar_inode = path.stat().st_ino
    monkeypatch.setattr(
        persistence,
        "_entry_owner_matches",
        lambda value: value.st_ino != sidecar_inode,
    )
    wrong_owner = read_receipt_sidecar(root, issued.verified.reference)
    assert isinstance(wrong_owner, PlumbingFailure)
    assert wrong_owner.reason_codes == (PlumbingReason.SIDECAR_POLICY_VIOLATION,)


def test_sidecar_mutation_between_fstats_is_rejected(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.startup.runtime_receipt import persistence

    root = _store_root(tmp_path)
    stored = write_receipt_sidecar(
        root,
        issued.verified.reference,
        issued.verified.receipt,
    )
    assert isinstance(stored, StoredReceipt)
    mutated = False

    def mutate(root_fd: int, name: str, _file_fd: int) -> None:
        nonlocal mutated
        if mutated:
            return
        mutated = True
        writer = os.open(name, os.O_WRONLY | os.O_CLOEXEC, dir_fd=root_fd)
        try:
            os.pwrite(writer, b"X", 0)
            os.fsync(writer)
        finally:
            os.close(writer)

    monkeypatch.setattr(persistence, "_after_sidecar_read", mutate)
    result = read_receipt_sidecar(root, issued.verified.reference)
    assert isinstance(result, PlumbingFailure)
    assert result.reason_codes == (PlumbingReason.SIDECAR_READ_FAILED,)


def test_lock_replacement_is_rejected(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.startup.runtime_receipt import persistence

    root = _store_root(tmp_path)
    stored = write_receipt_sidecar(
        root,
        issued.verified.reference,
        issued.verified.receipt,
    )
    assert isinstance(stored, StoredReceipt)
    replaced = False

    def replace(root_fd: int, name: str, _lock_fd: int) -> None:
        nonlocal replaced
        if replaced:
            return
        replaced = True
        os.unlink(name, dir_fd=root_fd)
        replacement = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
            dir_fd=root_fd,
        )
        os.close(replacement)

    monkeypatch.setattr(persistence, "_after_lock_open", replace)
    result = read_receipt_sidecar(root, issued.verified.reference)
    assert isinstance(result, PlumbingFailure)
    assert result.reason_codes == (PlumbingReason.LOCK_REPLACED,)


def test_root_and_lock_policy_fail_closed(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.startup.runtime_receipt import persistence

    unsafe_root = _store_root(tmp_path, "unsafe-root")
    unsafe_root.chmod(0o777)
    result = read_receipt_sidecar(unsafe_root, issued.verified.reference)
    assert isinstance(result, PlumbingFailure)
    assert result.reason_codes == (PlumbingReason.ROOT_POLICY_VIOLATION,)

    real_root = _store_root(tmp_path, "real-root")
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(real_root, target_is_directory=True)
    result = read_receipt_sidecar(linked_root, issued.verified.reference)
    assert isinstance(result, PlumbingFailure)
    assert result.reason_codes[0] in {
        PlumbingReason.ROOT_UNAVAILABLE,
        PlumbingReason.ROOT_POLICY_VIOLATION,
    }

    owned_root = _store_root(tmp_path, "owned-root")
    monkeypatch.setattr(persistence, "_current_euid", lambda: os.geteuid() + 1)
    result = read_receipt_sidecar(owned_root, issued.verified.reference)
    assert isinstance(result, PlumbingFailure)
    assert result.reason_codes == (PlumbingReason.ROOT_POLICY_VIOLATION,)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory", "hardlink", "mode"])
def test_lock_file_policy_rejects_unsafe_shapes(
    tmp_path: Path,
    issued: _IssuedSet,
    kind: str,
) -> None:
    root = _store_root(tmp_path)
    _write_raw_sidecar(
        root,
        issued.verified.reference,
        serialize_receipt(issued.verified.receipt),
    )
    lock = root / issued.verified.reference.lock_name
    peer = root / "lock-peer"
    if kind == "symlink":
        peer.write_bytes(b"")
        peer.chmod(0o600)
        lock.symlink_to(peer)
    elif kind == "fifo":
        os.mkfifo(lock, 0o600)
    elif kind == "directory":
        lock.mkdir(mode=0o700)
    elif kind == "hardlink":
        peer.write_bytes(b"")
        peer.chmod(0o600)
        os.link(peer, lock)
    else:
        lock.write_bytes(b"")
        lock.chmod(0o640)
    result = read_receipt_sidecar(root, issued.verified.reference)
    assert isinstance(result, PlumbingFailure)
    assert result.reason_codes == (PlumbingReason.LOCK_POLICY_VIOLATION,)


class _Crash(RuntimeError):
    pass


@pytest.mark.parametrize(
    ("point", "final_exists", "temporary_exists"),
    [
        (PersistenceCrashPoint.BEFORE_TEMP_CREATE, False, False),
        (PersistenceCrashPoint.AFTER_TEMP_WRITE, False, True),
        (PersistenceCrashPoint.AFTER_TEMP_FSYNC, False, True),
        (PersistenceCrashPoint.AFTER_RENAME, True, False),
        (PersistenceCrashPoint.AFTER_PARENT_FSYNC, True, False),
        (PersistenceCrashPoint.AFTER_REREAD, True, False),
    ],
)
def test_sidecar_crash_points_are_total(
    tmp_path: Path,
    issued: _IssuedSet,
    point: PersistenceCrashPoint,
    final_exists: bool,
    temporary_exists: bool,
) -> None:
    root = _store_root(tmp_path)

    def crash(observed: PersistenceCrashPoint) -> None:
        if observed is point:
            raise _Crash(point.value)

    with pytest.raises(_Crash):
        write_receipt_sidecar(
            root,
            issued.pending.reference,
            issued.pending.receipt,
            fault=crash,
        )
    assert (root / issued.pending.reference.sidecar_name).exists() is final_exists
    assert (
        root / issued.pending.reference.sidecar_temporary_name
    ).exists() is temporary_exists
    if temporary_exists:
        cleaned = cleanup_sidecar_temporary(root, issued.pending.reference)
        assert isinstance(cleaned, CleanupApplied)
    if final_exists:
        loaded = read_receipt_sidecar(root, issued.pending.reference)
        assert isinstance(loaded, StoredReceipt)


def _persist_transition_pair(root: Path, issued: _IssuedSet) -> None:
    for item in (issued.pending, issued.verified):
        stored = write_receipt_sidecar(root, item.reference, item.receipt)
        assert isinstance(stored, StoredReceipt)
    pointer = initialize_modeled_pointer(root, issued.pending.reference)
    assert isinstance(pointer, ModeledPointer)


def _non_authorizing_results(issued: _IssuedSet) -> tuple[object, ...]:
    return (
        issued.pending,
        issued.verified,
        issued.rejected,
        issued.verified.snapshot,
        StoredReceipt(
            reference=issued.pending.reference,
            receipt=issued.pending.receipt,
            file_name=issued.pending.reference.sidecar_name,
            created=False,
        ),
        ModeledPointer(
            reference=issued.pending.reference,
            receipt=issued.pending.receipt,
            file_name=issued.pending.reference.pointer_name,
        ),
        CasApplied(
            prior=issued.pending.reference,
            current=issued.verified.reference,
        ),
        CleanupApplied(
            reference=issued.pending.reference,
            pointer_removed=False,
            sidecar_removed=True,
        ),
    )


def test_authority_is_not_a_constructor_or_replace_input(
    issued: _IssuedSet,
) -> None:
    constructors: tuple[tuple[type[Any], dict[str, Any]], ...] = (
        (
            PendingReceiptIssued,
            {
                "receipt": issued.pending.receipt,
                "reference": issued.pending.reference,
            },
        ),
        (
            VerifiedReceiptIssued,
            {
                "receipt": issued.verified.receipt,
                "reference": issued.verified.reference,
                "verification": issued.verified.verification,
                "snapshot": issued.verified.snapshot,
            },
        ),
        (
            RejectedReceiptIssued,
            {
                "receipt": issued.rejected.receipt,
                "reference": issued.rejected.reference,
            },
        ),
        (
            RuntimeReceiptSnapshot,
            {
                "reference": issued.verified.reference,
                "receipt": issued.verified.receipt,
            },
        ),
        (
            StoredReceipt,
            {
                "reference": issued.pending.reference,
                "receipt": issued.pending.receipt,
                "file_name": issued.pending.reference.sidecar_name,
                "created": False,
            },
        ),
        (
            ModeledPointer,
            {
                "reference": issued.pending.reference,
                "receipt": issued.pending.receipt,
                "file_name": issued.pending.reference.pointer_name,
            },
        ),
        (
            CasApplied,
            {
                "prior": issued.pending.reference,
                "current": issued.verified.reference,
            },
        ),
        (
            CleanupApplied,
            {
                "reference": issued.pending.reference,
                "pointer_removed": False,
                "sidecar_removed": True,
            },
        ),
    )
    for wrapper_type, kwargs in constructors:
        with pytest.raises(TypeError, match="authoritative"):
            wrapper_type(**kwargs, authoritative=True)

    for value in _non_authorizing_results(issued):
        with pytest.raises(TypeError, match="init=False"):
            dataclasses.replace(value, authoritative=True)
        replacement = dataclasses.replace(value)
        assert replacement.authoritative is False


@pytest.mark.parametrize(
    "wrapper_type",
    (
        PendingReceiptIssued,
        VerifiedReceiptIssued,
        RejectedReceiptIssued,
        RuntimeReceiptSnapshot,
        StoredReceipt,
        ModeledPointer,
        CasApplied,
        CleanupApplied,
    ),
)
def test_non_authorizing_result_wrappers_cannot_be_subclassed(
    wrapper_type: type[object],
) -> None:
    with pytest.raises(TypeError, match="cannot be subclassed"):
        type(f"Forged{wrapper_type.__name__}", (wrapper_type,), {})


@pytest.mark.parametrize("authority", (True, 0, 1, "false", None))
def test_snapshot_authority_mutation_never_serializes_or_matches(
    issued: _IssuedSet,
    authority: object,
) -> None:
    snapshot = dataclasses.replace(issued.verified.snapshot)
    canonical = serialize_snapshot(snapshot)
    assert b'"authoritative"' not in canonical
    comparison = ReceiptComparatorInput(
        metadata_snapshot=issued.verified.snapshot,
        current_reference=issued.verified.reference,
        current_receipt=issued.verified.receipt,
    )
    object.__setattr__(snapshot, "authoritative", authority)
    object.__setattr__(comparison, "metadata_snapshot", snapshot)

    with pytest.raises(AuthorityInvariantError) as exc_info:
        serialize_snapshot(snapshot)
    assert exc_info.value.disposition is PlumbingDisposition.INVALID_REQUEST
    assert exc_info.value.reason_codes == (
        PlumbingReason.AUTHORITY_INVARIANT_VIOLATION,
    )
    assert (
        compare_receipt_snapshot(comparison)
        is ReceiptComparisonResult.AUTHORITY_INVALID
    )


def test_handcrafted_snapshot_with_authority_cannot_reach_success(
    issued: _IssuedSet,
) -> None:
    snapshot = object.__new__(RuntimeReceiptSnapshot)
    object.__setattr__(snapshot, "authoritative", True)
    comparison = ReceiptComparatorInput(
        metadata_snapshot=snapshot,
        current_reference=issued.verified.reference,
        current_receipt=issued.verified.receipt,
    )

    with pytest.raises(AuthorityInvariantError):
        serialize_snapshot(snapshot)
    assert (
        compare_receipt_snapshot(comparison)
        is ReceiptComparisonResult.AUTHORITY_INVALID
    )


@pytest.mark.parametrize("authority", (True, 0, "false"))
def test_issuance_rejects_mutated_authority_inputs(
    issued: _IssuedSet,
    authority: object,
) -> None:
    pending = dataclasses.replace(issued.pending)
    object.__setattr__(pending, "authoritative", authority)
    verified = build_verified_receipt(
        pending,
        process_evidence=_process_evidence(issued.verified.receipt),
        observed_at_utc=cast(
            UtcTimestamp,
            issued.verified.receipt.process_corroboration.observed_at_utc,
        ),
        profiles=issued.profiles,
        session_token=SessionToken(TOKEN_BYTES),
        now=_verification_now(),
    )
    assert isinstance(verified, PlumbingFailure)
    assert verified.disposition is PlumbingDisposition.INVALID_REQUEST
    assert verified.reason_codes == (PlumbingReason.AUTHORITY_INVARIANT_VIOLATION,)

    prior = dataclasses.replace(issued.verified)
    object.__setattr__(prior, "authoritative", authority)
    rejected = build_rejected_receipt(
        prior,
        reason_codes=(ReasonCode.MAPPED_IMAGE_UNAVAILABLE,),
    )
    assert isinstance(rejected, PlumbingFailure)
    assert rejected.disposition is PlumbingDisposition.INVALID_REQUEST
    assert rejected.reason_codes == (PlumbingReason.AUTHORITY_INVARIANT_VIOLATION,)


def test_persistence_rejects_mutated_storage_adapter_result(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _store_root(tmp_path)
    stored = write_receipt_sidecar(
        root,
        issued.pending.reference,
        issued.pending.receipt,
    )
    assert isinstance(stored, StoredReceipt)
    original_read = _persistence._read_sidecar_at

    def mutated_read(root_fd: int, reference: ReceiptReference) -> StoredReceipt:
        result = original_read(root_fd, reference)
        object.__setattr__(result, "authoritative", 1)
        return result

    monkeypatch.setattr(_persistence, "_read_sidecar_at", mutated_read)
    for result in (
        read_receipt_sidecar(root, issued.pending.reference),
        write_receipt_sidecar(
            root,
            issued.pending.reference,
            issued.pending.receipt,
        ),
    ):
        assert isinstance(result, PlumbingFailure)
        assert result.disposition is PlumbingDisposition.PERSISTENCE_FAILED
        assert result.reason_codes == (PlumbingReason.AUTHORITY_INVARIANT_VIOLATION,)


def test_cas_rejects_mutated_modeled_pointer_result(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _store_root(tmp_path)
    _persist_transition_pair(root, issued)
    original_read = _persistence._read_modeled_pointer_at

    def mutated_read(root_fd: int, pid: CanonicalPid) -> ModeledPointer:
        result = original_read(root_fd, pid)
        object.__setattr__(result, "authoritative", "false")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(_persistence, "_read_modeled_pointer_at", mutated_read)
        result = compare_and_swap_modeled_pointer(
            root,
            expected=issued.pending.reference,
            replacement=issued.verified.reference,
        )
    assert isinstance(result, PlumbingFailure)
    assert result.disposition is PlumbingDisposition.PERSISTENCE_FAILED
    assert result.reason_codes == (PlumbingReason.AUTHORITY_INVARIANT_VIOLATION,)
    pointer = read_modeled_pointer(root, issued.pending.reference.session_pid)
    assert isinstance(pointer, ModeledPointer)
    assert pointer.reference == issued.pending.reference


def test_valid_false_authority_path_remains_non_authorizing(
    tmp_path: Path,
    issued: _IssuedSet,
) -> None:
    raw = serialize_snapshot(issued.verified.snapshot)
    parsed = _parse_snapshot_with_context(raw, issued)
    assert isinstance(parsed, RuntimeReceiptSnapshot)
    comparison = ReceiptComparatorInput(
        metadata_snapshot=parsed,
        current_reference=issued.verified.reference,
        current_receipt=issued.verified.receipt,
    )
    assert (
        compare_receipt_snapshot(comparison)
        is ReceiptComparisonResult.MATCH_NON_AUTHORIZING
    )
    root = _store_root(tmp_path)
    _persist_transition_pair(root, issued)
    result = compare_and_swap_modeled_pointer(
        root,
        expected=issued.pending.reference,
        replacement=issued.verified.reference,
    )
    assert isinstance(result, CasApplied)
    assert all(
        value.authoritative is False
        for value in (*_non_authorizing_results(issued), parsed, result)
    )
    assert parsed.reason_codes == (
        ReasonCode.PROFILE_UNSUPPORTED,
        ReasonCode.LIVE_CONTRACT_MISSING,
    )


@pytest.mark.parametrize(
    ("point", "expected_state"),
    [
        (PersistenceCrashPoint.BEFORE_CAS, ReceiptState.PENDING),
        (PersistenceCrashPoint.AFTER_CAS, ReceiptState.VERIFIED),
    ],
)
def test_modeled_pointer_cas_crash_boundary(
    tmp_path: Path,
    issued: _IssuedSet,
    point: PersistenceCrashPoint,
    expected_state: ReceiptState,
) -> None:
    root = _store_root(tmp_path)
    _persist_transition_pair(root, issued)

    def crash(observed: PersistenceCrashPoint) -> None:
        if observed is point:
            raise _Crash(point.value)

    with pytest.raises(_Crash):
        compare_and_swap_modeled_pointer(
            root,
            expected=issued.pending.reference,
            replacement=issued.verified.reference,
            fault=crash,
        )
    pointer = read_modeled_pointer(root, issued.pending.reference.session_pid)
    assert isinstance(pointer, ModeledPointer)
    assert pointer.reference.state is expected_state


def test_concurrent_modeled_finalizers_have_one_cas_winner(
    tmp_path: Path,
    issued: _IssuedSet,
) -> None:
    root = _store_root(tmp_path)
    _persist_transition_pair(root, issued)
    barrier = threading.Barrier(2)

    def finalize():
        barrier.wait()
        return compare_and_swap_modeled_pointer(
            root,
            expected=issued.pending.reference,
            replacement=issued.verified.reference,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _index: finalize(), range(2)))
    winners = [result for result in results if isinstance(result, CasApplied)]
    losers = [result for result in results if isinstance(result, PlumbingFailure)]
    assert len(winners) == 1
    assert len(losers) == 1
    assert losers[0].disposition is PlumbingDisposition.STATE_CONFLICT
    assert losers[0].reason_codes[0] in {
        PlumbingReason.CONCURRENT_FINALIZER,
        PlumbingReason.CAS_CONFLICT,
    }
    pointer = read_modeled_pointer(root, issued.pending.reference.session_pid)
    assert isinstance(pointer, ModeledPointer)
    assert pointer.reference == issued.verified.reference


def test_modeled_pointer_rejects_skips_replays_and_conflicting_prior(
    tmp_path: Path,
    issued: _IssuedSet,
) -> None:
    root = _store_root(tmp_path)
    _persist_transition_pair(root, issued)
    skipped = compare_and_swap_modeled_pointer(
        root,
        expected=issued.pending.reference,
        replacement=dataclasses.replace(
            issued.rejected.reference,
            attempt=2,
        ),
    )
    assert isinstance(skipped, PlumbingFailure)
    conflicting = compare_and_swap_modeled_pointer(
        root,
        expected=dataclasses.replace(
            issued.pending.reference,
            launch_nonce=NonceHex("f" * 32),
        ),
        replacement=issued.verified.reference,
    )
    assert isinstance(conflicting, PlumbingFailure)
    assert conflicting.reason_codes == (PlumbingReason.LAUNCH_NONCE_MISMATCH,)
    won = compare_and_swap_modeled_pointer(
        root,
        expected=issued.pending.reference,
        replacement=issued.verified.reference,
    )
    assert isinstance(won, CasApplied)
    replay = compare_and_swap_modeled_pointer(
        root,
        expected=issued.pending.reference,
        replacement=issued.verified.reference,
    )
    assert isinstance(replay, PlumbingFailure)
    assert replay.disposition is PlumbingDisposition.STATE_CONFLICT


def test_exact_reference_aware_cleanup_never_enumerates_or_overdeletes(
    tmp_path: Path,
    issued: _IssuedSet,
) -> None:
    root = _store_root(tmp_path)
    _persist_transition_pair(root, issued)
    sibling = root / "unrelated"
    sibling.write_text("keep", encoding="utf-8")
    sibling.chmod(0o600)
    selected = cleanup_unreferenced_sidecar(root, issued.pending.reference)
    assert isinstance(selected, PlumbingFailure)
    assert selected.reason_codes == (PlumbingReason.SIDECAR_STILL_REFERENCED,)
    swapped = compare_and_swap_modeled_pointer(
        root,
        expected=issued.pending.reference,
        replacement=issued.verified.reference,
    )
    assert isinstance(swapped, CasApplied)
    old = cleanup_unreferenced_sidecar(root, issued.pending.reference)
    assert isinstance(old, CleanupApplied)
    assert old.pointer_removed is False
    assert old.sidecar_removed is True
    assert old.temporary_removed is False
    assert not (root / issued.pending.reference.sidecar_name).exists()
    assert (root / issued.verified.reference.sidecar_name).exists()
    cleaned = cleanup_selected_receipt(root, issued.verified.reference)
    assert isinstance(cleaned, CleanupApplied)
    assert cleaned.pointer_removed is True
    assert cleaned.sidecar_removed is True
    assert cleaned.temporary_removed is False
    assert not (root / issued.verified.reference.pointer_name).exists()
    assert not (root / issued.verified.reference.sidecar_name).exists()
    assert sibling.read_text(encoding="utf-8") == "keep"


def test_cleanup_revokes_pointer_before_a_missing_sidecar(
    tmp_path: Path,
    issued: _IssuedSet,
) -> None:
    root = _store_root(tmp_path)
    stored = write_receipt_sidecar(
        root,
        issued.pending.reference,
        issued.pending.receipt,
    )
    assert isinstance(stored, StoredReceipt)
    pointer = initialize_modeled_pointer(root, issued.pending.reference)
    assert isinstance(pointer, ModeledPointer)
    (root / issued.pending.reference.sidecar_name).unlink()
    result = cleanup_selected_receipt(root, issued.pending.reference)
    assert isinstance(result, PlumbingFailure)
    assert result.disposition is PlumbingDisposition.CLEANUP_FAILED
    assert not (root / issued.pending.reference.pointer_name).exists()


def test_cleanup_crash_after_pointer_revoke_leaves_only_unreferenced_sidecar(
    tmp_path: Path,
    issued: _IssuedSet,
) -> None:
    root = _store_root(tmp_path)
    stored = write_receipt_sidecar(
        root,
        issued.pending.reference,
        issued.pending.receipt,
    )
    assert isinstance(stored, StoredReceipt)
    pointer = initialize_modeled_pointer(root, issued.pending.reference)
    assert isinstance(pointer, ModeledPointer)

    def crash(point: PersistenceCrashPoint) -> None:
        if point is PersistenceCrashPoint.AFTER_POINTER_UNLINK:
            raise _Crash(point.value)

    with pytest.raises(_Crash):
        cleanup_selected_receipt(
            root,
            issued.pending.reference,
            fault=crash,
        )
    assert not (root / issued.pending.reference.pointer_name).exists()
    assert (root / issued.pending.reference.sidecar_name).exists()
    cleaned = cleanup_unreferenced_sidecar(root, issued.pending.reference)
    assert isinstance(cleaned, CleanupApplied)


def test_pointer_temporary_cleanup_is_exact(
    tmp_path: Path,
    issued: _IssuedSet,
) -> None:
    root = _store_root(tmp_path)
    stored = write_receipt_sidecar(
        root,
        issued.pending.reference,
        issued.pending.receipt,
    )
    assert isinstance(stored, StoredReceipt)

    def crash(point: PersistenceCrashPoint) -> None:
        if point is PersistenceCrashPoint.AFTER_TEMP_WRITE:
            raise _Crash(point.value)

    with pytest.raises(_Crash):
        initialize_modeled_pointer(
            root,
            issued.pending.reference,
            fault=crash,
        )
    temporary = root / issued.pending.reference.pointer_temporary_name
    assert temporary.exists()
    cleaned = cleanup_pointer_temporary(root, issued.pending.reference)
    assert isinstance(cleaned, CleanupApplied)
    assert cleaned.pointer_removed is False
    assert cleaned.sidecar_removed is False
    assert cleaned.temporary_removed is True
    assert not temporary.exists()
    assert (root / issued.pending.reference.sidecar_name).exists()


def test_collection_failure_adapter_builds_terminal_rejection(
    issued: _IssuedSet,
) -> None:
    failure = CollectionFailure(
        disposition=CollectionDisposition.MISMATCH,
        reason_codes=(CollectionReasonCode.MAPPED_DEVICE_UNVERIFIABLE,),
        subject=EvidenceSubject.PROCESS,
    )
    rejected = build_rejected_from_collection(
        issued.pending,
        failure=failure,
        observed_at_utc=UtcTimestamp(_seed()["observed_at_utc"]),
    )
    assert isinstance(rejected, RejectedReceiptIssued)
    assert rejected.receipt.decision.reason_codes == (
        ReasonCode.MAPPED_DEVICE_UNVERIFIABLE,
    )
    assert rejected.authoritative is False


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("observed_pid", 9999, PlumbingReason.PID_MISMATCH),
        ("starttime_before", 9999, PlumbingReason.STARTTIME_MISMATCH),
        ("starttime_after", 9999, PlumbingReason.STARTTIME_MISMATCH),
        ("observed_euid", 9999, PlumbingReason.PROCESS_BINDING_MISMATCH),
        ("pid_namespace_inode", 9999, PlumbingReason.PROCESS_BINDING_MISMATCH),
    ],
)
def test_verified_issuance_rejects_process_binding_mismatch(
    issued: _IssuedSet,
    field: str,
    value: int,
    reason: PlumbingReason,
) -> None:
    process = dataclasses.replace(
        _process_evidence(issued.verified.receipt),
        **{field: value},
    )
    result = build_verified_receipt(
        issued.pending,
        process_evidence=process,
        observed_at_utc=cast(
            UtcTimestamp,
            issued.verified.receipt.process_corroboration.observed_at_utc,
        ),
        profiles=issued.profiles,
        session_token=SessionToken(TOKEN_BYTES),
        now=_verification_now(),
    )
    assert isinstance(result, PlumbingFailure)
    assert result.reason_codes == (reason,)


def test_verified_issuance_rejects_wrong_token(issued: _IssuedSet) -> None:
    result = build_verified_receipt(
        issued.pending,
        process_evidence=_process_evidence(issued.verified.receipt),
        observed_at_utc=cast(
            UtcTimestamp,
            issued.verified.receipt.process_corroboration.observed_at_utc,
        ),
        profiles=issued.profiles,
        session_token=SessionToken(b"\xff" * 16),
        now=_verification_now(),
    )
    assert isinstance(result, PlumbingFailure)
    assert result.disposition is PlumbingDisposition.BINDING_FAILED
    assert result.reason_codes == (PlumbingReason.TOKEN_MISMATCH,)


def test_rejected_builder_allows_verified_to_rejected_only_once(
    issued: _IssuedSet,
) -> None:
    rejected = build_rejected_receipt(
        issued.verified,
        reason_codes=(ReasonCode.REEXEC_UNVERIFIED,),
    )
    assert isinstance(rejected, RejectedReceiptIssued)
    assert rejected.reference.attempt == 2
    replay = build_rejected_receipt(
        rejected,
        reason_codes=(ReasonCode.REEXEC_UNVERIFIED,),
    )
    assert isinstance(replay, PlumbingFailure)
    assert replay.reason_codes == (PlumbingReason.INVALID_TRANSITION,)


def test_raw_token_never_reaches_serializers_diagnostics_or_storage(
    tmp_path: Path,
    issued: _IssuedSet,
) -> None:
    root = _store_root(tmp_path)
    for item in (issued.pending, issued.verified, issued.rejected):
        stored = write_receipt_sidecar(root, item.reference, item.receipt)
        assert isinstance(stored, StoredReceipt)
    raw_secret = TOKEN_BYTES.hex()
    values = [
        serialize_reference(issued.pending.reference),
        serialize_snapshot(issued.verified.snapshot),
        repr(SessionToken(TOKEN_BYTES)).encode(),
        repr(
            BindingIssuanceInputs(
                session_pid=4242,
                session_starttime_ticks=9001,
                boot_id=issued.pending.reference.boot_id,
                pid_namespace_inode=4026531836,
                launcher_euid=1000,
                session_token=SessionToken(TOKEN_BYTES),
                launch_nonce=issued.pending.reference.launch_nonce,
                issued_at_utc=issued.pending.receipt.launch_binding.issued_at_utc,
                freshness_not_after_utc=(
                    issued.pending.receipt.launch_binding.freshness_not_after_utc
                ),
            )
        ).encode(),
        repr(
            PlumbingFailure(
                PlumbingDisposition.BINDING_FAILED,
                (PlumbingReason.TOKEN_MISMATCH,),
            )
        ).encode(),
    ]
    values.extend(
        path.read_bytes()
        for path in root.iterdir()
        if path.is_file() and not path.name.endswith(".lock")
    )
    assert all(raw_secret.encode() not in value for value in values)
    with pytest.raises(ValueError):
        PlumbingFailure(
            PlumbingDisposition.BINDING_FAILED,
            (PlumbingReason.TOKEN_MISMATCH,),
            details={"reason": raw_secret},
        )


def test_inputs_and_outputs_are_immutable_and_isolated(issued: _IssuedSet) -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        issued.pending.reference.attempt = 2  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        issued.verified.snapshot.authoritative = True  # type: ignore[misc]
    source = cast(
        dict[str, Any],
        json.loads(serialize_snapshot(issued.verified.snapshot)),
    )
    parsed = _parse_snapshot_with_context(canonical_bytes(source), issued)
    assert isinstance(parsed, RuntimeReceiptSnapshot)
    source["receipt_sha256"] = "0" * 64
    assert parsed.reference.receipt_sha256 == issued.verified.reference.receipt_sha256


def test_no_authority_or_production_wiring_and_no_ambient_discovery() -> None:
    package = Path(__file__).parents[1] / "runtime_receipt"
    modules = tuple(
        package / name
        for name in ("plumbing_types.py", "persistence.py", "issuance.py")
    )
    forbidden_imports = (
        "core.project",
        "core.run",
        "core.coverage",
        "core.llm",
        "core.startup.host",
    )
    forbidden_calls = {
        "getenv",
        "listdir",
        "scandir",
        "glob",
        "rglob",
        "walk",
        "spawn",
        "fork",
        "kill",
    }
    for path in modules:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(
                    not alias.name.startswith(forbidden_imports) for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith(forbidden_imports)
            elif isinstance(node, ast.Call):
                name = (
                    node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else node.func.id
                    if isinstance(node.func, ast.Name)
                    else ""
                )
                assert name not in forbidden_calls
            elif isinstance(node, ast.Attribute):
                assert not (
                    isinstance(node.value, ast.Name)
                    and node.value.id == "os"
                    and node.attr == "environ"
                )

    repository = Path(__file__).parents[3]
    allowed = {
        path.resolve()
        for path in (
            *modules,
            Path(__file__),
            repository / "core/project/sessions.py",
            repository / "core/project/tests/test_sessions.py",
        )
    }
    for path in repository.rglob("*.py"):
        if path.resolve() in allowed or any(
            part in {".git", ".venv", "__pycache__", "out", ".out"}
            for part in path.parts
        ):
            continue
        source = path.read_text(encoding="utf-8", errors="surrogateescape")
        assert "runtime_receipt.plumbing_types" not in source
        assert "runtime_receipt.persistence" not in source
        assert "runtime_receipt.issuance" not in source


def test_no_generic_registry_or_authority_surface_is_exposed(
    issued: _IssuedSet,
) -> None:
    for value in (
        issued.pending,
        issued.verified,
        issued.rejected,
        issued.verified.snapshot,
    ):
        assert value.authoritative is False
        assert not hasattr(value, "session_owner")
        assert not hasattr(value, "project")
        assert not hasattr(value, "provider")
        assert not hasattr(value, "model")
        assert not hasattr(value, "effects_enabled")


def _registry_setup(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
):
    from core.project import sessions
    from core.startup.host import Frontend as HostFrontend
    from core.startup.host import SessionHostClaim

    root = tmp_path / "sessions.d"
    root.mkdir(mode=0o700)
    reference = issued.pending.reference
    host = SessionHostClaim(
        frontend=HostFrontend.COPILOT,
        uid=reference.launcher_euid.value,
        executable=Path("/owned/copilot"),
        executable_device=10,
        executable_inode=20,
    )
    monkeypatch.setattr(sessions, "SESSIONS_DIR", root)
    monkeypatch.setattr(sessions, "_pid_running", lambda _pid: True)
    monkeypatch.setattr(
        sessions,
        "proc_starttime",
        lambda _pid: reference.session_starttime_ticks.text,
    )
    monkeypatch.setattr(sessions, "boot_id", lambda: reference.boot_id.value)
    monkeypatch.setattr(
        sessions,
        "pidns_id",
        lambda: reference.pid_namespace_inode.text,
    )
    monkeypatch.setattr(
        sessions,
        "_current_euid",
        lambda: reference.launcher_euid.value,
    )
    monkeypatch.setattr(
        sessions,
        "_process_uid",
        lambda _pid: reference.launcher_euid.value,
    )
    monkeypatch.setattr(
        sessions,
        "_process_executable_identity",
        lambda _pid: (host.executable_device, host.executable_inode),
    )
    return sessions, root, host


def _install_registry_pending(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
):
    sessions, root, host = _registry_setup(tmp_path, issued, monkeypatch)
    result = sessions.install_pending_session_receipt(
        issued.pending,
        token_hex=TOKEN_BYTES.hex(),
        expected_host=host,
    )
    assert isinstance(result, StoredReceipt)
    return sessions, root, host


def test_real_registry_entry_is_exact_projectless_and_non_authorizing(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, root, _host = _install_registry_pending(
        tmp_path,
        issued,
        monkeypatch,
    )
    entry_path = root / issued.pending.reference.session_pid.text
    raw = entry_path.read_bytes()
    assert (
        tuple(line.partition(b"=")[0].decode("ascii") for line in raw[:-1].split(b"\n"))
        == sessions._HOST_V2_ENTRY_KEYS
    )
    parsed = sessions._parse_session_receipt_entry(
        raw,
        pid=issued.pending.reference.session_pid.value,
    )
    assert not isinstance(parsed, PlumbingFailure)
    assert parsed.reference == issued.pending.reference
    assert sessions._host_claim_state(
        sessions._parse_entry(entry_path),
        pid=issued.pending.reference.session_pid.value,
    ) == ("invalid", None)
    with monkeypatch.context() as env_patch:
        env_patch.setenv(
            sessions.ENV_SESSION_PID,
            issued.pending.reference.session_pid.text,
        )
        env_patch.setenv(sessions.ENV_SESSION_TOKEN, TOKEN_BYTES.hex())
        assert sessions._env_session_pid() is None
        assert sessions.resolve_session_pid() is None
        assert sessions.resolve_session_owner() is None
        assert sessions.session_binding() == (None, "none")
    assert (
        sessions.session_host_claim(issued.pending.reference.session_pid.value) is None
    )
    assert sessions.read_sessions() == {}


def _mutate_registry_entry(raw: bytes, case: str) -> bytes:
    lines = raw[:-1].split(b"\n")
    if case == "bom":
        return b"\xef\xbb\xbf" + raw
    if case == "cr":
        return raw.replace(b"\n", b"\r\n", 1)
    if case == "duplicate":
        return b"\n".join((lines[0], lines[0], *lines[1:])) + b"\n"
    if case == "reordered":
        lines[0], lines[1] = lines[1], lines[0]
        return b"\n".join(lines) + b"\n"
    if case == "unknown":
        return b"\n".join((*lines, b"host_receipt_extra=x")) + b"\n"
    if case == "missing":
        return (
            b"\n".join(
                line for line in lines if not line.startswith(b"host_receipt_v=")
            )
            + b"\n"
        )
    if case == "blank":
        return b"\n".join((*lines[:5], b"", *lines[5:])) + b"\n"
    if case == "no-final-newline":
        return raw[:-1]
    if case == "non-utf8":
        return raw[:-2] + b"\xff\n"
    if case == "oversized":
        return raw + b"x" * 16_385
    if case == "long-line":
        return (
            b"\n".join(
                b"host_exe=/" + b"x" * 8_192 if line.startswith(b"host_exe=") else line
                for line in lines
            )
            + b"\n"
        )
    if case == "bad-since":
        return (
            b"\n".join(
                b"since=2026-09-12T00:00:00Z" if line.startswith(b"since=") else line
                for line in lines
            )
            + b"\n"
        )
    raise AssertionError(case)


@pytest.mark.parametrize(
    "case",
    (
        "bom",
        "cr",
        "duplicate",
        "reordered",
        "unknown",
        "missing",
        "blank",
        "no-final-newline",
        "non-utf8",
        "oversized",
        "long-line",
        "bad-since",
    ),
)
def test_matching_token_invalid_host_v2_is_projectless_without_walk(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    sessions, root, _host = _install_registry_pending(
        tmp_path,
        issued,
        monkeypatch,
    )
    pid = issued.pending.reference.session_pid.value
    entry = root / str(pid)
    entry.write_bytes(_mutate_registry_entry(entry.read_bytes(), case))
    entry.chmod(0o600)
    walked = False

    def walk() -> int | None:
        nonlocal walked
        walked = True
        return 7

    monkeypatch.setattr(sessions, "_walk_session_pid", walk)
    monkeypatch.setenv(sessions.ENV_SESSION_PID, str(pid))
    monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, TOKEN_BYTES.hex())
    from core.startup.host import HostClaimError, parse_session_host_claim

    try:
        old_reader_claim = parse_session_host_claim(sessions._parse_entry(entry))
    except HostClaimError:
        old_reader_claim = None
    assert old_reader_claim is None
    assert sessions.resolve_session_pid() is None
    assert sessions.resolve_session_owner() is None
    assert sessions.session_binding() == (None, "none")
    assert walked is False


def test_wrong_host_v2_token_keeps_legacy_walk_behavior(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, _root, _host = _install_registry_pending(
        tmp_path,
        issued,
        monkeypatch,
    )
    monkeypatch.setenv(
        sessions.ENV_SESSION_PID,
        issued.pending.reference.session_pid.text,
    )
    monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, "ff" * 16)
    monkeypatch.setattr(sessions, "_walk_session_pid", lambda: 77)
    assert sessions.resolve_session_pid() == 77


def test_missing_host_v2_token_never_authorizes(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, root, _host = _install_registry_pending(
        tmp_path,
        issued,
        monkeypatch,
    )
    pid = issued.pending.reference.session_pid.value
    entry = root / str(pid)
    entry.write_bytes(
        b"\n".join(
            line
            for line in entry.read_bytes().splitlines()
            if not line.startswith(b"token=")
        )
        + b"\n"
    )
    entry.chmod(0o600)
    monkeypatch.setenv(sessions.ENV_SESSION_PID, str(pid))
    monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, TOKEN_BYTES.hex())
    assert sessions._env_session_pid() is None
    assert sessions.resolve_session_owner() is None
    assert sessions.session_binding(pid=pid) == (None, "none")
    assert (
        sessions.read_current_session_runtime_receipt(
            profiles=issued.profiles,
            now=_verification_now(),
        )
        is None
    )


@pytest.mark.parametrize(
    ("state", "expected_reason"),
    (
        (ReceiptState.PENDING, PlumbingReason.STATE_NOT_FINAL),
        (ReceiptState.REJECTED, PlumbingReason.RECEIPT_STATE_REJECTED),
    ),
)
def test_registry_nonfinal_states_are_typed_and_non_authorizing(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
    state: ReceiptState,
    expected_reason: PlumbingReason,
) -> None:
    sessions, _root, _host = _install_registry_pending(
        tmp_path,
        issued,
        monkeypatch,
    )
    if state is ReceiptState.REJECTED:
        result = sessions.compare_and_swap_session_receipt(
            issued.pending.reference,
            issued.rejected.reference,
            issued.rejected.receipt,
            token_hex=TOKEN_BYTES.hex(),
        )
        assert isinstance(result, CasApplied)
    monkeypatch.setenv(
        sessions.ENV_SESSION_PID,
        issued.pending.reference.session_pid.text,
    )
    monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, TOKEN_BYTES.hex())
    result = sessions.read_current_session_runtime_receipt(
        profiles=issued.profiles,
        now=_verification_now(),
    )
    assert isinstance(result, PlumbingFailure)
    assert result.reason_codes == (expected_reason,)
    listed = sessions.read_sessions(prune=False, include_stale=True)
    assert listed[issued.pending.reference.session_pid.value]["_state"] == (
        f"receipt-{state.value}"
    )
    assert sessions.read_sessions(prune=False) == {}
    assert sessions.resolve_session_owner() is None
    assert sessions.session_binding() == (None, "none")


def test_registry_verified_read_returns_only_non_authorizing_snapshot(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, _root, _host = _install_registry_pending(
        tmp_path,
        issued,
        monkeypatch,
    )
    swapped = sessions.compare_and_swap_session_receipt(
        issued.pending.reference,
        issued.verified.reference,
        issued.verified.receipt,
        token_hex=TOKEN_BYTES.hex(),
    )
    assert isinstance(swapped, CasApplied)
    monkeypatch.setenv(
        sessions.ENV_SESSION_PID,
        issued.pending.reference.session_pid.text,
    )
    monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, TOKEN_BYTES.hex())
    snapshot = sessions.read_current_session_runtime_receipt(
        profiles=issued.profiles,
        now=_verification_now(),
    )
    assert isinstance(snapshot, RuntimeReceiptSnapshot)
    assert snapshot.authoritative is False
    listed = sessions.read_sessions(prune=False, include_stale=True)
    assert listed[issued.pending.reference.session_pid.value]["_state"] == (
        "receipt-verified"
    )
    assert sessions.read_sessions(prune=False) == {}
    assert sessions.resolve_session_owner() is None
    assert sessions.session_binding() == (None, "none")


def test_registry_install_replay_is_rejected_without_rewriting(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, root, host = _install_registry_pending(
        tmp_path,
        issued,
        monkeypatch,
    )
    entry = root / issued.pending.reference.session_pid.text
    before = entry.read_bytes()
    result = sessions.install_pending_session_receipt(
        issued.pending,
        token_hex=TOKEN_BYTES.hex(),
        expected_host=host,
    )
    assert isinstance(result, PlumbingFailure)
    assert result.reason_codes == (PlumbingReason.REPLAYED_TRANSITION,)
    assert entry.read_bytes() == before


@pytest.mark.parametrize(
    "shape",
    (
        "missing",
        "malformed",
        "oversized",
        "symlink",
        "fifo",
        "directory",
        "hardlink",
        "wrong-mode",
        "wrong-owner",
    ),
)
def test_registry_sidecar_policy_failures_are_typed(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
    shape: str,
) -> None:
    sessions, root, _host = _install_registry_pending(
        tmp_path,
        issued,
        monkeypatch,
    )
    reference = issued.pending.reference
    sidecar = root / reference.sidecar_name
    original = sidecar.read_bytes()
    if shape == "missing":
        sidecar.unlink()
    elif shape == "malformed":
        sidecar.write_bytes(b"{}")
    elif shape == "oversized":
        sidecar.write_bytes(b"x" * (MAX_RECEIPT_BYTES + 1))
    elif shape == "symlink":
        sidecar.unlink()
        peer = root / "peer"
        peer.write_bytes(original)
        peer.chmod(0o600)
        sidecar.symlink_to(peer)
    elif shape == "fifo":
        sidecar.unlink()
        os.mkfifo(sidecar, 0o600)
    elif shape == "directory":
        sidecar.unlink()
        sidecar.mkdir(mode=0o700)
    elif shape == "hardlink":
        sidecar.unlink()
        peer = root / "peer"
        peer.write_bytes(original)
        peer.chmod(0o600)
        os.link(peer, sidecar)
    elif shape == "wrong-mode":
        sidecar.chmod(0o644)
    elif shape == "wrong-owner":
        sidecar_inode = sidecar.stat().st_ino
        original_owner = _persistence._entry_owner_matches
        monkeypatch.setattr(
            _persistence,
            "_entry_owner_matches",
            lambda value: (
                False if value.st_ino == sidecar_inode else original_owner(value)
            ),
        )
    monkeypatch.setenv(sessions.ENV_SESSION_PID, reference.session_pid.text)
    monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, TOKEN_BYTES.hex())
    result = sessions.read_current_session_runtime_receipt(
        profiles=issued.profiles,
        now=_verification_now(),
    )
    assert isinstance(result, PlumbingFailure)
    assert sessions.session_binding() == (None, "none")


def test_registry_copied_or_forged_sidecar_fails_closed(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, root, _host = _install_registry_pending(
        tmp_path,
        issued,
        monkeypatch,
    )
    sidecar = root / issued.pending.reference.sidecar_name
    sidecar.write_bytes(serialize_receipt(issued.verified.receipt))
    sidecar.chmod(0o600)
    monkeypatch.setenv(
        sessions.ENV_SESSION_PID,
        issued.pending.reference.session_pid.text,
    )
    monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, TOKEN_BYTES.hex())
    result = sessions.read_current_session_runtime_receipt(
        profiles=issued.profiles,
        now=_verification_now(),
    )
    assert isinstance(result, PlumbingFailure)
    assert result.reason_codes[0] in {
        PlumbingReason.STATE_NOT_FINAL,
        PlumbingReason.SIDECAR_DIGEST_MISMATCH,
    }


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("session_id", UuidText("22222222-2222-4222-8222-222222222222")),
        ("launch_id", UuidText("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")),
        ("session_pid", CanonicalPid(4243)),
        ("session_starttime_ticks", U64Decimal(9002)),
        ("boot_id", UuidText("87654321-4321-4321-8321-cba987654321")),
        ("pid_namespace_inode", U64Decimal(4026531837)),
        ("launcher_euid", U64Decimal(1001)),
        ("session_token_commitment_sha256", Sha256("d" * 64)),
        ("launch_nonce", NonceHex("f" * 32)),
        ("profile_id", Identifier("other-profile")),
        ("stable_identity_sha256", Sha256("e" * 64)),
        ("process_corroboration_sha256", Sha256("c" * 64)),
    ),
)
def test_registry_reference_entry_or_sidecar_mismatch_is_rejected(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    sessions, root, _host = _install_registry_pending(
        tmp_path,
        issued,
        monkeypatch,
    )
    pid = issued.pending.reference.session_pid.value
    entry = root / str(pid)
    fields = sessions._parse_entry(entry)
    forged = dataclasses.replace(
        issued.pending.reference,
        **{field: value},
    )
    fields["host_receipt_reference"] = serialize_reference(forged).decode("ascii")
    entry.write_text(
        "".join(f"{key}={fields[key]}\n" for key in sessions._HOST_V2_ENTRY_KEYS),
        encoding="utf-8",
    )
    entry.chmod(0o600)
    monkeypatch.setenv(sessions.ENV_SESSION_PID, str(pid))
    monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, TOKEN_BYTES.hex())
    result = sessions.read_current_session_runtime_receipt(
        profiles=issued.profiles,
        now=_verification_now(),
    )
    assert isinstance(result, PlumbingFailure)
    assert sessions.session_binding() == (None, "none")


def test_registry_full_byte_cas_detects_in_lock_entry_mutation(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, root, _host = _install_registry_pending(
        tmp_path,
        issued,
        monkeypatch,
    )
    entry = root / issued.pending.reference.session_pid.text
    original = entry.read_bytes()
    lines = original[:-1].split(b"\n")
    changed = (
        b"\n".join(
            b"since=2026-09-12T00:00:00.000000+00:00"
            if line.startswith(b"since=")
            else line
            for line in lines
        )
        + b"\n"
    )
    assert changed != original
    fired = False

    def mutate(_pid: int, _fd: int) -> None:
        nonlocal fired
        if not fired:
            fired = True
            entry.write_bytes(changed)
            entry.chmod(0o600)

    monkeypatch.setattr(sessions, "_after_session_lock_open", mutate)
    result = sessions.compare_and_swap_session_receipt(
        issued.pending.reference,
        issued.verified.reference,
        issued.verified.receipt,
        token_hex=TOKEN_BYTES.hex(),
    )
    assert isinstance(result, PlumbingFailure)
    assert result.reason_codes == (PlumbingReason.SESSION_REPLACED,)
    assert entry.read_bytes() == changed
    assert not (root / issued.verified.reference.sidecar_name).exists()


def test_registry_takeover_token_is_refused_without_mutation(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, root, _host = _install_registry_pending(
        tmp_path,
        issued,
        monkeypatch,
    )
    entry = root / issued.pending.reference.session_pid.text
    before = entry.read_bytes()
    result = sessions.compare_and_swap_session_receipt(
        issued.pending.reference,
        issued.verified.reference,
        issued.verified.receipt,
        token_hex="ff" * 16,
    )
    assert isinstance(result, PlumbingFailure)
    assert result.reason_codes == (PlumbingReason.TOKEN_MISMATCH,)
    assert entry.read_bytes() == before
    assert not (root / issued.verified.reference.sidecar_name).exists()


def test_registry_liveness_bracket_blocks_executable_replacement(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, root, host = _registry_setup(tmp_path, issued, monkeypatch)
    identities = iter(((10, 20), (30, 40)))
    monkeypatch.setattr(
        sessions,
        "_process_executable_identity",
        lambda _pid: next(identities),
    )
    result = sessions.install_pending_session_receipt(
        issued.pending,
        token_hex=TOKEN_BYTES.hex(),
        expected_host=host,
    )
    assert isinstance(result, PlumbingFailure)
    assert result.reason_codes == (PlumbingReason.PROCESS_BINDING_MISMATCH,)
    assert not (root / issued.pending.reference.session_pid.text).exists()
    assert not (root / issued.pending.reference.sidecar_name).exists()


@pytest.mark.parametrize(
    "probe",
    (
        "dead",
        "starttime",
        "boot",
        "pidns",
        "euid",
        "process-uid",
        "executable",
    ),
)
def test_registry_install_requires_complete_live_binding(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
    probe: str,
) -> None:
    sessions, root, host = _registry_setup(tmp_path, issued, monkeypatch)
    reference = issued.pending.reference
    if probe == "dead":
        monkeypatch.setattr(sessions, "_pid_running", lambda _pid: False)
    elif probe == "starttime":
        monkeypatch.setattr(sessions, "proc_starttime", lambda _pid: "1")
    elif probe == "boot":
        monkeypatch.setattr(
            sessions,
            "boot_id",
            lambda: "87654321-4321-4321-8321-cba987654321",
        )
    elif probe == "pidns":
        monkeypatch.setattr(sessions, "pidns_id", lambda: "1")
    elif probe == "euid":
        monkeypatch.setattr(
            sessions,
            "_current_euid",
            lambda: reference.launcher_euid.value + 1,
        )
    elif probe == "process-uid":
        monkeypatch.setattr(
            sessions,
            "_process_uid",
            lambda _pid: reference.launcher_euid.value + 1,
        )
    else:
        monkeypatch.setattr(
            sessions,
            "_process_executable_identity",
            lambda _pid: (30, 40),
        )
    result = sessions.install_pending_session_receipt(
        issued.pending,
        token_hex=TOKEN_BYTES.hex(),
        expected_host=host,
    )
    assert isinstance(result, PlumbingFailure)
    assert result.reason_codes == (PlumbingReason.PROCESS_BINDING_MISMATCH,)
    assert not (root / reference.session_pid.text).exists()
    assert not (root / reference.sidecar_name).exists()


def test_concurrent_real_registry_finalizers_have_one_winner(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, root, _host = _install_registry_pending(
        tmp_path,
        issued,
        monkeypatch,
    )
    barrier = threading.Barrier(2)

    def finalize(item):
        barrier.wait()
        return sessions.compare_and_swap_session_receipt(
            issued.pending.reference,
            item.reference,
            item.receipt,
            token_hex=TOKEN_BYTES.hex(),
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(finalize, (issued.verified, issued.rejected)))
    assert sum(isinstance(result, CasApplied) for result in results) == 1
    assert sum(isinstance(result, PlumbingFailure) for result in results) == 1
    parsed = sessions._parse_session_receipt_entry(
        (root / issued.pending.reference.session_pid.text).read_bytes(),
        pid=issued.pending.reference.session_pid.value,
    )
    assert not isinstance(parsed, PlumbingFailure)
    assert parsed.reference.state in {ReceiptState.VERIFIED, ReceiptState.REJECTED}
    sidecars = tuple(
        root.glob(f"{issued.pending.reference.session_pid.text}.receipt.*.json")
    )
    assert len(sidecars) == 1
    assert sidecars[0].name == parsed.reference.sidecar_name


def test_registry_crash_boundaries_leave_only_inert_orphans(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, root, host = _registry_setup(tmp_path, issued, monkeypatch)

    def crash_write(*_args, **_kwargs):
        raise _Crash("entry-write")

    monkeypatch.setattr(_persistence, "write_session_entry_bytes", crash_write)
    with pytest.raises(_Crash):
        sessions.install_pending_session_receipt(
            issued.pending,
            token_hex=TOKEN_BYTES.hex(),
            expected_host=host,
        )
    assert not (root / issued.pending.reference.session_pid.text).exists()
    assert (root / issued.pending.reference.sidecar_name).exists()


def test_registry_cas_crash_seams_keep_a_complete_generation(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, root, _host = _install_registry_pending(
        tmp_path,
        issued,
        monkeypatch,
    )
    entry = root / issued.pending.reference.session_pid.text
    pending_raw = entry.read_bytes()

    def crash_write(*_args, **_kwargs):
        raise _Crash("before-entry-swing")

    with monkeypatch.context() as patcher:
        patcher.setattr(
            _persistence,
            "write_session_entry_bytes",
            crash_write,
        )
        with pytest.raises(_Crash):
            sessions.compare_and_swap_session_receipt(
                issued.pending.reference,
                issued.verified.reference,
                issued.verified.receipt,
                token_hex=TOKEN_BYTES.hex(),
            )
    assert entry.read_bytes() == pending_raw
    assert (root / issued.pending.reference.sidecar_name).exists()
    assert not (root / issued.verified.reference.sidecar_name).exists()
    orphan = write_receipt_sidecar(
        root,
        issued.verified.reference,
        issued.verified.receipt,
    )
    assert isinstance(orphan, StoredReceipt)
    parsed = sessions._parse_session_receipt_entry(
        entry.read_bytes(),
        pid=issued.pending.reference.session_pid.value,
    )
    assert not isinstance(parsed, PlumbingFailure)
    assert parsed.reference == issued.pending.reference

    def crash_cleanup(*_args, **_kwargs):
        raise _Crash("after-entry-swing")

    monkeypatch.setattr(
        sessions,
        "_cleanup_exact_receipt_file",
        crash_cleanup,
    )
    with pytest.raises(_Crash):
        sessions.compare_and_swap_session_receipt(
            issued.pending.reference,
            issued.verified.reference,
            issued.verified.receipt,
            token_hex=TOKEN_BYTES.hex(),
        )
    parsed = sessions._parse_session_receipt_entry(
        entry.read_bytes(),
        pid=issued.pending.reference.session_pid.value,
    )
    assert not isinstance(parsed, PlumbingFailure)
    assert parsed.reference is issued.verified.reference or (
        parsed.reference == issued.verified.reference
    )
    assert (root / issued.pending.reference.sidecar_name).exists()
    assert (root / issued.verified.reference.sidecar_name).exists()


def test_registry_remove_revokes_before_cleanup_failure(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, root, _host = _install_registry_pending(
        tmp_path,
        issued,
        monkeypatch,
    )
    monkeypatch.setattr(
        sessions,
        "_cleanup_exact_receipt_file",
        lambda *_args, **_kwargs: plumbing_failure(
            PlumbingDisposition.CLEANUP_FAILED,
            PlumbingReason.SIDECAR_CLEANUP_INCOMPLETE,
        ),
    )
    result = sessions.remove_session_receipt(
        issued.pending.reference,
        token_hex=TOKEN_BYTES.hex(),
    )
    assert isinstance(result, PlumbingFailure)
    assert result.disposition is PlumbingDisposition.CLEANUP_FAILED
    assert not (root / issued.pending.reference.session_pid.text).exists()
    assert (root / issued.pending.reference.sidecar_name).exists()


def test_registry_install_enforces_bounded_sidecar_population(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, root, host = _registry_setup(tmp_path, issued, monkeypatch)
    pid = issued.pending.reference.session_pid.text
    for digit in "0123":
        path = root / f"{pid}.receipt.{digit * 64}.json"
        path.write_bytes(b"x")
        path.chmod(0o600)
    result = sessions.install_pending_session_receipt(
        issued.pending,
        token_hex=TOKEN_BYTES.hex(),
        expected_host=host,
    )
    assert isinstance(result, PlumbingFailure)
    assert result.reason_codes == (PlumbingReason.SIDECAR_LIMIT_EXCEEDED,)
    assert TOKEN_BYTES.hex() not in repr(result)
    assert "/owned/copilot" not in repr(result)


def test_persistence_entry_policy_rejects_unsafe_shapes(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.startup.runtime_receipt.persistence import (
        read_session_entry_bytes,
    )

    root = _store_root(tmp_path)
    pid = issued.pending.reference.session_pid
    entry = root / pid.text
    peer = root / "peer"
    peer.write_bytes(b"x")
    peer.chmod(0o600)
    cases = ("symlink", "fifo", "directory", "hardlink", "mode", "oversize")
    for case in cases:
        if entry.exists() or entry.is_symlink():
            if entry.is_dir():
                entry.rmdir()
            else:
                entry.unlink()
        if case == "symlink":
            entry.symlink_to(peer)
        elif case == "fifo":
            os.mkfifo(entry, 0o600)
        elif case == "directory":
            entry.mkdir(mode=0o700)
        elif case == "hardlink":
            os.link(peer, entry)
        elif case == "mode":
            entry.write_bytes(b"x")
            entry.chmod(0o644)
        else:
            entry.write_bytes(b"x" * 16_385)
            entry.chmod(0o600)
        result = read_session_entry_bytes(root, pid)
        assert isinstance(result, PlumbingFailure), case
    if entry.exists() or entry.is_symlink():
        if entry.is_dir():
            entry.rmdir()
        else:
            entry.unlink()
    entry.write_bytes(b"x")
    entry.chmod(0o600)
    entry_inode = entry.stat().st_ino
    original_owner = _persistence._entry_owner_matches
    monkeypatch.setattr(
        _persistence,
        "_entry_owner_matches",
        lambda value: False if value.st_ino == entry_inode else original_owner(value),
    )
    result = read_session_entry_bytes(root, pid)
    assert isinstance(result, PlumbingFailure)


@pytest.mark.parametrize(
    ("point", "final_exists", "temporary_exists"),
    (
        (PersistenceCrashPoint.BEFORE_ENTRY_TEMP_CREATE, False, False),
        (PersistenceCrashPoint.AFTER_ENTRY_TEMP_WRITE, False, True),
        (PersistenceCrashPoint.AFTER_ENTRY_TEMP_FSYNC, False, True),
        (PersistenceCrashPoint.AFTER_ENTRY_RENAME, True, False),
        (PersistenceCrashPoint.AFTER_ENTRY_PARENT_FSYNC, True, False),
        (PersistenceCrashPoint.AFTER_ENTRY_REREAD, True, False),
    ),
)
def test_session_entry_write_crash_points_are_total(
    tmp_path: Path,
    issued: _IssuedSet,
    point: PersistenceCrashPoint,
    final_exists: bool,
    temporary_exists: bool,
) -> None:
    from core.startup.runtime_receipt.persistence import (
        session_entry_temporary_name,
        write_session_entry_bytes,
    )

    root = _store_root(tmp_path)
    pid = issued.pending.reference.session_pid
    raw = b"v=2\n"

    def crash(observed: PersistenceCrashPoint) -> None:
        if observed is point:
            raise _Crash(point.value)

    with pytest.raises(_Crash):
        write_session_entry_bytes(root, pid, raw, fault=crash)
    assert (root / pid.text).exists() is final_exists
    assert (root / session_entry_temporary_name(pid)).exists() is temporary_exists


@pytest.mark.parametrize(
    ("point", "entry_exists"),
    (
        (PersistenceCrashPoint.BEFORE_ENTRY_UNLINK, True),
        (PersistenceCrashPoint.AFTER_ENTRY_UNLINK, False),
    ),
)
def test_session_entry_unlink_crash_points_are_total(
    tmp_path: Path,
    issued: _IssuedSet,
    point: PersistenceCrashPoint,
    entry_exists: bool,
) -> None:
    from core.startup.runtime_receipt.persistence import (
        unlink_session_entry_if_bytes,
        write_session_entry_bytes,
    )

    root = _store_root(tmp_path)
    pid = issued.pending.reference.session_pid
    raw = b"v=2\n"
    assert write_session_entry_bytes(root, pid, raw) == raw

    def crash(observed: PersistenceCrashPoint) -> None:
        if observed is point:
            raise _Crash(point.value)

    with pytest.raises(_Crash):
        unlink_session_entry_if_bytes(root, pid, raw, fault=crash)
    assert (root / pid.text).exists() is entry_exists


def test_hashing_and_receipt_parsing_stay_outside_storage_locks(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _store_root(tmp_path)
    depth = 0
    original_lock = _persistence._strict_lock

    @contextlib.contextmanager
    def tracked_lock(*args, **kwargs):
        nonlocal depth
        with original_lock(*args, **kwargs):
            depth += 1
            try:
                yield
            finally:
                depth -= 1

    monkeypatch.setattr(_persistence, "_strict_lock", tracked_lock)
    for name in (
        "parse_receipt",
        "serialize_receipt",
        "parse_reference",
        "serialize_reference",
        "reference_receipt_mismatch",
        "reference_transition_mismatch",
    ):
        original = getattr(_persistence, name)

        def checked(*args, __original=original, **kwargs):
            assert depth == 0
            return __original(*args, **kwargs)

        monkeypatch.setattr(_persistence, name, checked)
    assert isinstance(
        write_receipt_sidecar(
            root,
            issued.pending.reference,
            issued.pending.receipt,
        ),
        StoredReceipt,
    )
    assert isinstance(
        read_receipt_sidecar(root, issued.pending.reference),
        StoredReceipt,
    )
    assert isinstance(
        initialize_modeled_pointer(root, issued.pending.reference),
        ModeledPointer,
    )
    assert isinstance(
        write_receipt_sidecar(
            root,
            issued.verified.reference,
            issued.verified.receipt,
        ),
        StoredReceipt,
    )
    assert isinstance(
        compare_and_swap_modeled_pointer(
            root,
            expected=issued.pending.reference,
            replacement=issued.verified.reference,
        ),
        CasApplied,
    )


def test_registry_lock_domains_never_nest_and_parsing_stays_outside(
    tmp_path: Path,
    issued: _IssuedSet,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions, _root, host = _registry_setup(tmp_path, issued, monkeypatch)
    depth = {"run": 0, "receipt": 0}
    original_run_lock = sessions._strict_session_lock
    original_receipt_lock = _persistence._strict_lock

    @contextlib.contextmanager
    def tracked_run_lock(*args, **kwargs):
        assert depth["receipt"] == 0
        with original_run_lock(*args, **kwargs):
            depth["run"] += 1
            try:
                yield
            finally:
                depth["run"] -= 1

    @contextlib.contextmanager
    def tracked_receipt_lock(*args, **kwargs):
        assert depth["run"] == 0
        with original_receipt_lock(*args, **kwargs):
            depth["receipt"] += 1
            try:
                yield
            finally:
                depth["receipt"] -= 1

    monkeypatch.setattr(sessions, "_strict_session_lock", tracked_run_lock)
    monkeypatch.setattr(_persistence, "_strict_lock", tracked_receipt_lock)
    types_module = importlib.import_module(
        "core.startup.runtime_receipt.plumbing_types"
    )
    original_sha256 = types_module.hashlib.sha256

    def checked_sha256(*args, **kwargs):
        assert depth["run"] == 0
        assert depth["receipt"] == 0
        return original_sha256(*args, **kwargs)

    monkeypatch.setattr(types_module.hashlib, "sha256", checked_sha256)
    for name in (
        "_parse_session_receipt_entry",
        "_serialize_session_receipt_entry",
    ):
        original = getattr(sessions, name)

        def checked(*args, __original=original, **kwargs):
            assert depth["run"] == 0
            assert depth["receipt"] == 0
            return __original(*args, **kwargs)

        monkeypatch.setattr(sessions, name, checked)
    installed = sessions.install_pending_session_receipt(
        issued.pending,
        token_hex=TOKEN_BYTES.hex(),
        expected_host=host,
    )
    assert isinstance(installed, StoredReceipt)
    swapped = sessions.compare_and_swap_session_receipt(
        issued.pending.reference,
        issued.verified.reference,
        issued.verified.receipt,
        token_hex=TOKEN_BYTES.hex(),
    )
    assert isinstance(swapped, CasApplied)
    removed = sessions.remove_session_receipt(
        issued.verified.reference,
        token_hex=TOKEN_BYTES.hex(),
    )
    assert isinstance(removed, CleanupApplied)
    assert depth == {"run": 0, "receipt": 0}
