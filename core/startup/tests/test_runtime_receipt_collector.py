"""Adversarial tests for the non-authorizing runtime evidence collector."""

from __future__ import annotations

import ast
import dataclasses
import errno
import fcntl
import hashlib
import json
import mmap
import os
import socket
import stat
import struct
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType

import pytest

from core.startup.runtime_receipt import collector as collector_module
from core.startup.runtime_receipt import collector_types, procfs as procfs_module
from core.startup.runtime_receipt.collector import (
    collect_distribution_evidence,
    collect_file_identity,
    collect_file_identity_at,
    collect_offline_runtime_evidence,
)
from core.startup.runtime_receipt.collector_types import (
    COLLECTOR_SCHEMA,
    COLLECTOR_SCHEMA_VERSION,
    DEFAULT_COLLECTOR_LIMITS,
    DEFAULT_PROCFS_LIMITS,
    MAX_HELD_DESCRIPTORS,
    ArtifactRequest,
    CollectionDisposition,
    CollectionFailure,
    CollectionReasonCode,
    CollectorElfClass,
    DescriptorIdentity,
    DescriptorStat,
    ElfInterpreterAbsent,
    ElfInterpreterPresent,
    EvidenceSubject,
    ExpectedMappedObject,
    ExpectedMappedObjects,
    FileCollectionRequest,
    FileEvidence,
    FileRole,
    MappedObjectRole,
    ObservedDistributionSource,
    OfflineRuntimeCollectionRequest,
    PathBindingState,
    PathObservation,
    PathPolicyId,
    ProcMapKind,
    ProcfsLimits,
    TrustedDistributionRequest,
    TrustedGrammarDigestInput,
    TrustedHelpContractDigestInput,
    TrustedProcessScope,
    TrustedSchemaInventoryInput,
    collection_failure,
)
from core.startup.runtime_receipt.elf import inspect_elf, parse_elf_interpreter
from core.startup.runtime_receipt.identity import TreeManifestRow, manifest_bytes
from core.startup.runtime_receipt.procfs import (
    collect_linux_process_evidence,
    parse_mountinfo,
    parse_proc_maps,
    parse_proc_stat,
)
from core.startup.runtime_receipt.reasons import ReceiptRejection
from core.startup.runtime_receipt.schema import (
    AbsolutePath,
    ArtifactName,
    Endianness,
    FormatId,
    ReceiptDecision,
    RuntimeReceipt,
    SchemaDocumentName,
    Sha256,
    VersionText,
)
from core.startup.runtime_receipt.verify import StaticallyVerifiedReceipt

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "runtime_receipt"


def _assert_failure(
    value: object,
    disposition: CollectionDisposition,
    reason: CollectionReasonCode,
) -> CollectionFailure:
    assert isinstance(value, CollectionFailure)
    assert value.disposition is disposition
    assert reason in value.reason_codes
    return value


def _fd_count() -> int:
    return len(tuple(Path("/proc/self/fd").iterdir()))


def _absolute(path: Path) -> AbsolutePath:
    return AbsolutePath(str(path.absolute()))


def _file_request(
    path: Path,
    *,
    role: FileRole = FileRole.DISTRIBUTION_ARTIFACT,
    owner: int | None = None,
    allow_root: bool = True,
    executable: bool = False,
    max_bytes: int = 1_048_576,
    format_id: FormatId = FormatId.OPAQUE,
    policy: PathPolicyId = PathPolicyId.DIRECT_REGULAR_NO_SYMLINK_V1,
) -> FileCollectionRequest:
    return FileCollectionRequest(
        role=role,
        absolute_path=_absolute(path),
        expected_owner_uid=os.geteuid() if owner is None else owner,
        allow_root_owner=allow_root,
        require_executable=executable,
        policy_id=policy,
        max_bytes=max_bytes,
        format_id=format_id,
    )


def _collect_at(root: Path, relative: str, request: FileCollectionRequest):
    fd = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        return collect_file_identity_at(fd, _absolute(root), relative, request)
    finally:
        os.close(fd)


def _note_blob(description: bytes, *, malformed: bool = False) -> bytes:
    name = b"GNU\0"
    declared_description_size = len(description) + (1000 if malformed else 0)
    header = struct.pack("<III", len(name), declared_description_size, 3)
    return (
        header
        + name
        + b"\0" * ((-len(name)) % 4)
        + description
        + b"\0" * ((-len(description)) % 4)
    )


def _elf_bytes(
    *,
    bits: int = 64,
    endian: str = "<",
    elf_type: int = 3,
    machine: int | None = None,
    interpreters: tuple[bytes, ...] = (),
    note_blobs: tuple[bytes, ...] = (),
    null_headers: int = 0,
    ident_class: int | None = None,
    ident_data: int | None = None,
    ident_version: int = 1,
    header_version: int = 1,
    declared_phentsize: int | None = None,
    declared_phnum: int | None = None,
    declared_phoff: int | None = None,
    declared_ehsize: int | None = None,
) -> bytes:
    if bits == 64:
        elf_class = 2
        header_size = 64
        program_header_size = 56
        header_format = "HHIQQQIHHHHHH"
        program_header_format = "IIQQQQQQ"
        default_machine = 62
    else:
        elf_class = 1
        header_size = 52
        program_header_size = 32
        header_format = "HHIIIIIHHHHHH"
        program_header_format = "IIIIIIII"
        default_machine = 3
    data_encoding = 1 if endian == "<" else 2
    ident = (
        b"\x7fELF"
        + bytes(
            [
                elf_class if ident_class is None else ident_class,
                data_encoding if ident_data is None else ident_data,
                ident_version,
                0,
            ]
        )
        + b"\0" * 8
    )
    payloads = [(3, value) for value in interpreters]
    payloads.extend((4, value) for value in note_blobs)
    payloads.extend((0, b"") for _ in range(null_headers))
    phnum = len(payloads) if declared_phnum is None else declared_phnum
    phentsize = (
        program_header_size if declared_phentsize is None else declared_phentsize
    )
    phoff = header_size if declared_phoff is None else declared_phoff
    payload_offset = header_size + program_header_size * len(payloads)
    program_headers = bytearray()
    payload = bytearray()
    for segment_type, segment_data in payloads:
        offset = payload_offset + len(payload)
        if bits == 64:
            program_headers.extend(
                struct.pack(
                    endian + program_header_format,
                    segment_type,
                    4,
                    offset,
                    0,
                    0,
                    len(segment_data),
                    len(segment_data),
                    4,
                )
            )
        else:
            program_headers.extend(
                struct.pack(
                    endian + program_header_format,
                    segment_type,
                    offset,
                    0,
                    0,
                    len(segment_data),
                    len(segment_data),
                    4,
                    4,
                )
            )
        payload.extend(segment_data)
    if bits == 64:
        header = struct.pack(
            endian + header_format,
            elf_type,
            default_machine if machine is None else machine,
            header_version,
            0,
            phoff,
            0,
            0,
            header_size if declared_ehsize is None else declared_ehsize,
            phentsize,
            phnum,
            0,
            0,
            0,
        )
    else:
        header = struct.pack(
            endian + header_format,
            elf_type,
            default_machine if machine is None else machine,
            header_version,
            0,
            phoff,
            0,
            0,
            header_size if declared_ehsize is None else declared_ehsize,
            phentsize,
            phnum,
            0,
            0,
            0,
        )
    return ident + header + bytes(program_headers) + bytes(payload)


def _inspect_bytes(tmp_path: Path, data: bytes):
    path = tmp_path / "sample.elf"
    path.write_bytes(data)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        return inspect_elf(fd, file_size=len(data))
    finally:
        os.close(fd)


_ARTIFACT_FORMATS = {
    ArtifactName.INDEX_JS: FormatId.JAVASCRIPT_UTF8,
    ArtifactName.NPM_LOADER_JS: FormatId.JAVASCRIPT_UTF8,
    ArtifactName.SEA_LOADER_JS: FormatId.JAVASCRIPT_UTF8,
    ArtifactName.APP_JS: FormatId.JAVASCRIPT_UTF8,
    ArtifactName.SDK_INDEX_JS: FormatId.OPAQUE,
    ArtifactName.CHANGELOG_JSON: FormatId.JSON_UTF8,
    ArtifactName.RUNTIME_NODE: FormatId.ELF64_X86_64_DYN,
    ArtifactName.CLI_NATIVE_NODE: FormatId.ELF64_X86_64_DYN,
    ArtifactName.SESSION_EVENTS_SCHEMA: FormatId.JSON_UTF8,
    ArtifactName.API_SCHEMA: FormatId.JSON_UTF8,
    ArtifactName.EXTRACTION_COMPLETE: FormatId.EMPTY,
}
_ARTIFACT_LIMITS = {
    ArtifactName.INDEX_JS: 4_194_304,
    ArtifactName.NPM_LOADER_JS: 1_048_576,
    ArtifactName.SEA_LOADER_JS: 1_048_576,
    ArtifactName.APP_JS: 33_554_432,
    ArtifactName.SDK_INDEX_JS: 16_777_216,
    ArtifactName.CHANGELOG_JSON: 8_388_608,
    ArtifactName.RUNTIME_NODE: 268_435_456,
    ArtifactName.CLI_NATIVE_NODE: 67_108_864,
    ArtifactName.SESSION_EVENTS_SCHEMA: 8_388_608,
    ArtifactName.API_SCHEMA: 8_388_608,
    ArtifactName.EXTRACTION_COMPLETE: 4_096,
}


@dataclass
class _DistributionBundle:
    anchor: Path
    anchor_fd: int
    root: Path
    request: TrustedDistributionRequest
    contents: dict[ArtifactName, bytes]
    payload: bytes


def _trusted_sha(byte: str) -> Sha256:
    return Sha256(byte * 64)


def _make_distribution(
    tmp_path: Path,
    *,
    version: str = "1.2.3",
    payload: bytes = b"SEA-PAYLOAD",
) -> _DistributionBundle:
    root = tmp_path / "dist"
    root.mkdir(parents=True)
    contents = {
        ArtifactName.INDEX_JS: b"export default 1;\n",
        ArtifactName.NPM_LOADER_JS: b"import './index.js';\n",
        ArtifactName.SEA_LOADER_JS: payload,
        ArtifactName.APP_JS: b"export const app = true;\n",
        ArtifactName.SDK_INDEX_JS: b"\xff\x00opaque",
        ArtifactName.CHANGELOG_JSON: b'{"version":"1.2.3"}\n',
        ArtifactName.RUNTIME_NODE: _elf_bytes(),
        ArtifactName.CLI_NATIVE_NODE: _elf_bytes(),
        ArtifactName.SESSION_EVENTS_SCHEMA: b'{"type":"object"}\n',
        ArtifactName.API_SCHEMA: b'{"type":"object"}\n',
        ArtifactName.EXTRACTION_COMPLETE: b"",
    }
    for name, content in contents.items():
        path = root / name.value
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(
            0o755
            if name in {ArtifactName.RUNTIME_NODE, ArtifactName.CLI_NATIVE_NODE}
            else 0o600
        )
    package = root / "package.json"
    package.write_text(
        json.dumps(
            {
                "name": "@github/copilot",
                "version": version,
                "type": "module",
                "bin": {"copilot": "npm-loader.js"},
            }
        ),
        encoding="utf-8",
    )
    package.chmod(0o600)
    artifacts = tuple(
        ArtifactRequest(
            role=name,
            relative_path=name.value,
            expected_format=_ARTIFACT_FORMATS[name],
            max_bytes=_ARTIFACT_LIMITS[name],
        )
        for name in ArtifactName
    )
    record = _trusted_sha("a")
    schemas = tuple(
        TrustedSchemaInventoryInput(
            name=schema_name,
            source_record_sha256=record,
            expected_file_sha256=Sha256(
                hashlib.sha256(contents[artifact_name]).hexdigest()
            ),
            definition_count=1,
            property_count=2,
            event_type_literal_count=3,
            event_variant_count=None,
            definition_names_sha256=_trusted_sha("b"),
            property_names_sha256=_trusted_sha("c"),
            event_type_literals_sha256=_trusted_sha("d"),
        )
        for schema_name, artifact_name in (
            (
                SchemaDocumentName.SESSION_EVENTS,
                ArtifactName.SESSION_EVENTS_SCHEMA,
            ),
            (SchemaDocumentName.API, ArtifactName.API_SCHEMA),
        )
    )
    anchor_fd = os.open(
        tmp_path,
        os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC,
    )
    request = TrustedDistributionRequest(
        source_directory=_absolute(root),
        expected_owner_uid=os.geteuid(),
        expected_package_name="@github/copilot",
        expected_version=VersionText(version),
        expected_package_type="module",
        expected_bin_name="copilot",
        expected_bin_target="npm-loader.js",
        platform_directory="linux-x64",
        artifacts=artifacts,
        schemas=schemas,
        grammar=TrustedGrammarDigestInput(
            source_record_sha256=record,
            source="completion_bash_review_record",
            sha256=_trusted_sha("e"),
            root_flag_count=5,
            advertised_root_flag_count=4,
            hidden_root_flag_count=1,
        ),
        help_contract=TrustedHelpContractDigestInput(
            source_record_sha256=record,
            manifest_algorithm="sha256-help-surfaces-v1",
            manifest_sha256=_trusted_sha("f"),
            surface_count=41,
        ),
        anchor_fd=anchor_fd,
        anchor_path=_absolute(tmp_path),
    )
    return _DistributionBundle(
        anchor=tmp_path,
        anchor_fd=anchor_fd,
        root=root,
        request=request,
        contents=contents,
        payload=payload,
    )


def _close_bundle(bundle: _DistributionBundle) -> None:
    os.close(bundle.anchor_fd)


def _make_offline_request(
    bundle: _DistributionBundle,
    *,
    interpreter_path: str = "/lib/ld.so",
    frontend_payload: bytes | None = None,
    payload_offset: int | None = None,
) -> OfflineRuntimeCollectionRequest:
    interpreter = bundle.anchor / interpreter_path.lstrip("/")
    interpreter.parent.mkdir(parents=True, exist_ok=True)
    if not interpreter.exists() and not interpreter.is_symlink():
        interpreter.write_bytes(_elf_bytes())
        interpreter.chmod(0o755)
    base = _elf_bytes(
        elf_type=2,
        interpreters=(interpreter_path.encode("utf-8") + b"\0",),
    )
    payload = bundle.payload if frontend_payload is None else frontend_payload
    if payload_offset is None:
        frontend_bytes = base + b"prefix-" + payload + b"-suffix"
    else:
        assert payload_offset >= len(base)
        frontend_bytes = base + b"X" * (payload_offset - len(base)) + payload
    frontend = bundle.anchor / "frontend"
    frontend.write_bytes(frontend_bytes)
    frontend.chmod(0o755)
    return OfflineRuntimeCollectionRequest(
        frontend=_file_request(
            frontend,
            role=FileRole.FRONTEND_EXECUTABLE,
            executable=True,
            max_bytes=268_435_456,
            format_id=FormatId.ELF64_X86_64_EXEC,
        ),
        distribution=bundle.request,
        interpreter_expected_owner_uid=os.geteuid(),
        interpreter_allow_root_owner=True,
        anchor_fd=bundle.anchor_fd,
        anchor_path=_absolute(bundle.anchor),
    )


def _namespace_inode(name: str) -> int:
    return int(os.readlink(f"/proc/self/ns/{name}").split("[", 1)[1][:-1])


def _collect_running_executable() -> FileEvidence:
    path = Path(os.readlink("/proc/self/exe"))
    owner = path.stat().st_uid
    for format_id in (FormatId.ELF64_X86_64_DYN, FormatId.ELF64_X86_64_EXEC):
        result = collect_file_identity(
            _file_request(
                path,
                role=FileRole.FRONTEND_EXECUTABLE,
                owner=owner,
                executable=True,
                max_bytes=268_435_456,
                format_id=format_id,
            )
        )
        if isinstance(result, FileEvidence):
            return result
    pytest.skip(f"running Python executable did not satisfy collector policy: {result}")


def _owned_process_fixture(
    tmp_path: Path,
    *,
    third_mapping: bool = False,
) -> tuple[TrustedProcessScope, ExpectedMappedObjects, list[mmap.mmap], int]:
    anchor_fd = os.open(tmp_path, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    mappings: list[mmap.mmap] = []
    expected_native: list[ExpectedMappedObject] = []
    names = [
        (MappedObjectRole.RUNTIME_NODE, "runtime.node"),
        (MappedObjectRole.CLI_NATIVE_NODE, "cli-native.node"),
    ]
    if third_mapping:
        names.append((None, "unexpected.node"))
    for role, name in names:
        path = tmp_path / name
        path.write_bytes(b"X" * mmap.PAGESIZE)
        path.chmod(0o755)
        file_fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            mappings.append(
                mmap.mmap(
                    file_fd,
                    mmap.PAGESIZE,
                    flags=mmap.MAP_PRIVATE,
                    prot=mmap.PROT_READ | mmap.PROT_EXEC,
                )
            )
        finally:
            os.close(file_fd)
        if role is not None:
            evidence = collect_file_identity_at(
                anchor_fd,
                _absolute(tmp_path),
                name,
                _file_request(
                    path,
                    executable=True,
                    max_bytes=mmap.PAGESIZE,
                    format_id=FormatId.OPAQUE,
                    policy=PathPolicyId.DISTRIBUTION_REGULAR_NO_SYMLINK_V1,
                ),
            )
            assert isinstance(evidence, FileEvidence)
            expected_native.append(
                ExpectedMappedObject(
                    role=role,
                    trusted_file=evidence,
                    anchor_fd=anchor_fd,
                    anchor_path=_absolute(tmp_path),
                )
            )
    parsed_stat = parse_proc_stat(Path("/proc/self/stat").read_bytes())
    assert not isinstance(parsed_stat, CollectionFailure)
    scope = TrustedProcessScope(
        pid=os.getpid(),
        expected_starttime_ticks=parsed_stat.starttime_ticks,
        expected_euid=os.geteuid(),
        expected_pid_namespace_inode=_namespace_inode("pid"),
        expected_mount_namespace_inode=_namespace_inode("mnt"),
    )
    root_observation = PathObservation(
        requested_path=_absolute(tmp_path),
        resolved_path=_absolute(tmp_path),
        policy_id=PathPolicyId.DISTRIBUTION_REGULAR_NO_SYMLINK_V1,
        components=(),
        binding_state=PathBindingState.STABLE,
        asserted_prefix_components=len(str(tmp_path).split("/")) - 1,
    )
    expected = ExpectedMappedObjects(
        loader=ExpectedMappedObject(
            role=MappedObjectRole.LOADER,
            trusted_file=_collect_running_executable(),
        ),
        native_modules=(expected_native[0], expected_native[1]),
        distribution_root=root_observation,
    )
    return scope, expected, mappings, anchor_fd


def test_collector_schema_and_descriptor_budget_are_pinned() -> None:
    assert COLLECTOR_SCHEMA == "raptor.runtime_receipt_collector/v1"
    assert COLLECTOR_SCHEMA_VERSION == 1
    assert MAX_HELD_DESCRIPTORS == 33
    assert DEFAULT_COLLECTOR_LIMITS.max_held_descriptors == 33
    assert DEFAULT_COLLECTOR_LIMITS.absolute_path_bytes == 4096


def test_collection_failure_is_ordered_immutable_and_redacted() -> None:
    failure = collection_failure(
        CollectionDisposition.INVALID_REQUEST,
        CollectionReasonCode.INVALID_ROLE_SET,
        CollectionReasonCode.INVALID_PATH,
        CollectionReasonCode.INVALID_ROLE_SET,
        subject=EvidenceSubject.REQUEST,
        details={
            "stage": "request",
            "path_sha256": "a" * 64,
            "not_allowed": "/hostile/raw/path",
        },
    )
    assert failure.reason_codes == (
        CollectionReasonCode.INVALID_PATH,
        CollectionReasonCode.INVALID_ROLE_SET,
    )
    assert isinstance(failure.details, MappingProxyType)
    assert "not_allowed" not in failure.details
    assert "/hostile/raw/path" not in repr(failure)
    with pytest.raises(TypeError):
        failure.details["stage"] = "changed"  # type: ignore[index]


def test_collector_types_are_frozen_slot_backed_and_non_authorizing() -> None:
    forbidden_fields = {
        "profile_id",
        "profile_status",
        "profile_sha256",
        "live_evidence_id",
        "live_evidence_sha256",
        "decision",
        "authoritative",
        "effects_enabled",
        "provider",
        "model",
        "selected_frontend",
        "owner",
        "session_id",
        "launch_id",
        "session_token_commitment_sha256",
        "receipt_nonce",
        "registry",
        "run_id",
        "run_binding",
    }
    forbidden_bases = (
        RuntimeReceipt,
        ReceiptDecision,
        ReceiptRejection,
        StaticallyVerifiedReceipt,
    )
    for value in vars(collector_types).values():
        if not isinstance(value, type) or not dataclasses.is_dataclass(value):
            continue
        assert value.__dataclass_params__.frozen
        assert hasattr(value, "__slots__")
        assert forbidden_fields.isdisjoint(
            field.name for field in dataclasses.fields(value)
        )
        assert not issubclass(value, forbidden_bases)


def test_collector_modules_have_no_authority_or_effect_wiring() -> None:
    package = Path(collector_module.__file__).parent
    paths = tuple(
        package / name
        for name in ("collector_types.py", "collector.py", "elf.py", "procfs.py")
    )
    forbidden_imports = (
        "core.startup.runtime_receipt.verify",
        "core.startup.runtime_receipt.profile",
        "core.startup.runtime_receipt.reasons",
        "core.startup.host",
        "core.project",
        "core.run",
        "core.coverage",
        "core.llm",
        "packages",
        "subprocess",
        "socket",
        "urllib",
        "http",
        "ctypes",
        "multiprocessing",
    )
    forbidden_os_attributes = {
        "environ",
        "system",
        "fork",
        "posix_spawn",
        "rename",
        "unlink",
        "remove",
        "rmdir",
        "mkdir",
        "chmod",
        "chown",
        "link",
        "symlink",
        "O_WRONLY",
        "O_RDWR",
        "O_CREAT",
        "O_TRUNC",
        "O_APPEND",
    }
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(
                    not alias.name.startswith(forbidden_imports) for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert not module.startswith(forbidden_imports)
                assert module not in {"verify", "profile", "reasons"}
            elif (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "os"
            ):
                assert node.attr not in forbidden_os_attributes
                assert not node.attr.startswith(("exec", "spawn"))
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "open"
            ):
                pytest.fail(f"collector uses built-in open(): {path}:{node.lineno}")


def test_no_production_importer_or_map_files_dependency() -> None:
    repository = Path(__file__).parents[3]
    allowed = {
        Path(__file__).resolve(),
        (repository / "core/startup/runtime_receipt/collector.py").resolve(),
        (repository / "core/startup/runtime_receipt/procfs.py").resolve(),
    }
    collector_modules = {
        "core.startup.runtime_receipt.collector",
        "core.startup.runtime_receipt.collector_types",
        "core.startup.runtime_receipt.elf",
        "core.startup.runtime_receipt.procfs",
    }
    importers: list[Path] = []
    for path in repository.rglob("*.py"):
        if path.resolve() in allowed or "runtime_receipt" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(
                alias.name in collector_modules for alias in node.names
            ):
                importers.append(path)
            if isinstance(node, ast.ImportFrom) and node.module in collector_modules:
                importers.append(path)
    assert not importers
    source = Path(procfs_module.__file__).read_text(encoding="utf-8")
    assert "map_files" not in source


def test_anchor_accepts_owned_tmp_path_and_rejects_false_claim(tmp_path: Path) -> None:
    path = tmp_path / "payload"
    path.write_bytes(b"payload")
    path.chmod(0o600)
    fd = os.open(tmp_path, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        result = collect_file_identity_at(
            fd,
            _absolute(tmp_path),
            "payload",
            _file_request(path),
        )
        assert isinstance(result, FileEvidence)
        assert result.path.asserted_prefix_components > 0

        wrong = tmp_path / "not-the-anchor"
        wrong.mkdir()
        rejected = collect_file_identity_at(
            fd,
            _absolute(wrong),
            "payload",
            _file_request(path),
        )
        _assert_failure(
            rejected,
            CollectionDisposition.INVALID_REQUEST,
            CollectionReasonCode.INVALID_PATH,
        )
    finally:
        os.close(fd)


def test_file_collection_hashes_complete_content_and_leaks_no_fd(
    tmp_path: Path,
) -> None:
    path = tmp_path / "payload"
    content = b"A" * (DEFAULT_COLLECTOR_LIMITS.hash_chunk_bytes + 17)
    path.write_bytes(content)
    path.chmod(0o600)
    before = _fd_count()
    result = _collect_at(
        tmp_path,
        "payload",
        _file_request(path, max_bytes=len(content)),
    )
    after = _fd_count()
    assert isinstance(result, FileEvidence)
    assert result.descriptor.sha256 == hashlib.sha256(content).hexdigest()
    assert result.descriptor.bytes_hashed == len(content)
    assert result.path.components[0].component_index > 0
    assert before == after


@pytest.mark.parametrize(
    "case",
    (
        "success",
        "missing_component",
        "symlink_refusal",
        "owner_mismatch",
        "unsafe_mode",
        "non_directory",
        "unexpected_error",
    ),
)
def test_traverse_directories_closes_every_opened_fd_across_outcome_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    parent.chmod(0o700)
    target = parent / case
    if case == "symlink_refusal":
        real = parent / "real"
        real.mkdir()
        real.chmod(0o700)
        target.symlink_to(real.name, target_is_directory=True)
    elif case == "non_directory":
        target.write_bytes(b"x")
        target.chmod(0o600)
    elif case != "missing_component":
        target.mkdir()
        target.chmod(0o770 if case == "unsafe_mode" else 0o700)

    outside_before = _fd_count()
    base_fd = os.open(tmp_path, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    base_stat = os.fstat(base_fd)
    base = collector_module._BaseAnchor(
        fd=base_fd,
        path=str(tmp_path.absolute()),
        close_fd=False,
        asserted_prefix_components=len(str(tmp_path.absolute()).split("/")) - 1,
        identity=collector_module._component_identity(base_stat),
    )

    original_open = collector_module._OS_OPEN
    opened_in_call: list[int] = []

    def tracked_open(path, flags, *args, **kwargs):
        fd = original_open(path, flags, *args, **kwargs)
        opened_in_call.append(fd)
        return fd

    monkeypatch.setattr(collector_module, "_OS_OPEN", tracked_open)

    original_close = collector_module._CLOSE
    closed_in_call: list[int] = []

    def tracked_close(fd: int) -> None:
        assert fd not in closed_in_call
        closed_in_call.append(fd)
        original_close(fd)

    monkeypatch.setattr(collector_module, "_CLOSE", tracked_close)

    if case == "owner_mismatch":
        original_fstat = collector_module._FSTAT

        def foreign_owner(fd: int) -> os.stat_result:
            value = original_fstat(fd)
            if os.readlink(f"/proc/self/fd/{fd}") == str(target):
                fields = list(value)
                fields[4] = os.geteuid() + 1
                return os.stat_result(fields)
            return value

        monkeypatch.setattr(collector_module, "_FSTAT", foreign_owner)
    elif case == "unexpected_error":
        original_record_component = collector_module._record_component

        def injected_error(
            absolute: str,
            index: int,
            value: os.stat_result,
            *,
            link_text_sha256: str | None = None,
        ):
            if absolute == str(target):
                raise RuntimeError("injected traversal error")
            return original_record_component(
                absolute,
                index,
                value,
                link_text_sha256=link_text_sha256,
            )

        monkeypatch.setattr(
            collector_module,
            "_record_component",
            injected_error,
        )

    failures = {
        "missing_component": (
            CollectionDisposition.UNAVAILABLE,
            CollectionReasonCode.RESOURCE_NOT_FOUND,
        ),
        "symlink_refusal": (
            CollectionDisposition.POLICY_REJECTED,
            CollectionReasonCode.PATH_POLICY_VIOLATION,
        ),
        "owner_mismatch": (
            CollectionDisposition.POLICY_REJECTED,
            CollectionReasonCode.OWNER_MISMATCH,
        ),
        "unsafe_mode": (
            CollectionDisposition.POLICY_REJECTED,
            CollectionReasonCode.UNSAFE_MODE,
        ),
        "non_directory": (
            CollectionDisposition.POLICY_REJECTED,
            CollectionReasonCode.PATH_POLICY_VIOLATION,
        ),
    }
    baseline = _fd_count()
    try:
        for _ in range(32):
            opened_in_call.clear()
            closed_in_call.clear()
            if case == "success":
                returned_fd, returned_owned, observed = (
                    collector_module._traverse_directories(
                        base,
                        ("parent", case),
                        expected_uid=os.geteuid(),
                        allow_root=False,
                        subject=EvidenceSubject.DISTRIBUTION,
                    )
                )
                assert returned_owned
                assert returned_fd != base_fd
                assert returned_fd in opened_in_call
                assert len(observed) == 2
                assert sorted(closed_in_call) == sorted(
                    fd for fd in opened_in_call if fd != returned_fd
                )
                os.fstat(returned_fd)
                os.close(returned_fd)
                with pytest.raises(OSError) as closed_error:
                    os.fstat(returned_fd)
                assert closed_error.value.errno == errno.EBADF
            elif case == "unexpected_error":
                with pytest.raises(RuntimeError, match="injected traversal error"):
                    collector_module._traverse_directories(
                        base,
                        ("parent", case),
                        expected_uid=os.geteuid(),
                        allow_root=False,
                        subject=EvidenceSubject.DISTRIBUTION,
                    )
                assert sorted(closed_in_call) == sorted(opened_in_call)
            else:
                with pytest.raises(collector_module._CollectorAbort) as exc_info:
                    collector_module._traverse_directories(
                        base,
                        ("parent", case),
                        expected_uid=os.geteuid(),
                        allow_root=False,
                        subject=EvidenceSubject.DISTRIBUTION,
                    )
                disposition, reason = failures[case]
                assert exc_info.value.failure.disposition is disposition
                assert exc_info.value.failure.reason_codes == (reason,)
                assert sorted(closed_in_call) == sorted(opened_in_call)
            assert len(opened_in_call) == len(set(opened_in_call))
            assert len(closed_in_call) == len(set(closed_in_call))
            os.fstat(base_fd)
        assert _fd_count() == baseline
    finally:
        os.close(base_fd)
    assert _fd_count() == outside_before


def test_anchored_file_collection_allows_absolute_path_depth(
    tmp_path: Path,
) -> None:
    directory = tmp_path
    components = [f"d{index}" for index in range(20)]
    for component in components:
        directory = directory / component
        directory.mkdir()
    path = directory / "payload"
    path.write_bytes(b"x")
    path.chmod(0o600)
    result = _collect_at(
        tmp_path,
        "/".join([*components, "payload"]),
        _file_request(path),
    )
    assert isinstance(result, FileEvidence)


def test_leaf_symlink_never_opens_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"secret")
    target.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(target.name)
    content_reopens = 0
    original = collector_module._OS_OPEN

    def counted(path, flags, *args, **kwargs):
        nonlocal content_reopens
        if isinstance(path, str) and path.startswith("/proc/self/fd/"):
            content_reopens += 1
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(collector_module, "_OS_OPEN", counted)
    result = _collect_at(tmp_path, "link", _file_request(link))
    _assert_failure(
        result,
        CollectionDisposition.POLICY_REJECTED,
        CollectionReasonCode.PATH_POLICY_VIOLATION,
    )
    assert content_reopens == 0


def test_symlink_ancestor_is_never_followed(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    target = real / "payload"
    target.write_bytes(b"x")
    target.chmod(0o600)
    (tmp_path / "alias").symlink_to("real", target_is_directory=True)
    result = _collect_at(
        tmp_path,
        "alias/payload",
        _file_request(tmp_path / "alias/payload"),
    )
    _assert_failure(
        result,
        CollectionDisposition.POLICY_REJECTED,
        CollectionReasonCode.PATH_POLICY_VIOLATION,
    )


@pytest.mark.parametrize("kind", ["fifo", "socket"])
def test_special_leaf_is_rejected_without_blocking(tmp_path: Path, kind: str) -> None:
    path = tmp_path / kind
    sock: socket.socket | None = None
    if kind == "fifo":
        os.mkfifo(path)
    else:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(path))
    try:
        result = _collect_at(tmp_path, kind, _file_request(path))
    finally:
        if sock is not None:
            sock.close()
    _assert_failure(
        result,
        CollectionDisposition.POLICY_REJECTED,
        CollectionReasonCode.NOT_REGULAR,
    )


def test_device_hardlink_owner_mode_and_size_policies(tmp_path: Path) -> None:
    device = collect_file_identity(
        _file_request(
            Path("/dev/null"),
            owner=0,
            allow_root=True,
            max_bytes=1,
        )
    )
    _assert_failure(
        device,
        CollectionDisposition.POLICY_REJECTED,
        CollectionReasonCode.NOT_REGULAR,
    )

    original = tmp_path / "original"
    original.write_bytes(b"x")
    original.chmod(0o600)
    linked = tmp_path / "linked"
    os.link(original, linked)
    hardlink = _collect_at(tmp_path, "original", _file_request(original))
    _assert_failure(
        hardlink,
        CollectionDisposition.POLICY_REJECTED,
        CollectionReasonCode.LINK_COUNT_INVALID,
    )

    owner = tmp_path / "owner"
    owner.write_bytes(b"x")
    owner.chmod(0o600)
    wrong_owner = _collect_at(
        tmp_path,
        "owner",
        _file_request(owner, owner=os.geteuid() + 1, allow_root=False),
    )
    _assert_failure(
        wrong_owner,
        CollectionDisposition.POLICY_REJECTED,
        CollectionReasonCode.OWNER_MISMATCH,
    )

    unsafe = tmp_path / "unsafe"
    unsafe.write_bytes(b"x")
    unsafe.chmod(0o660)
    unsafe_result = _collect_at(tmp_path, "unsafe", _file_request(unsafe))
    _assert_failure(
        unsafe_result,
        CollectionDisposition.POLICY_REJECTED,
        CollectionReasonCode.UNSAFE_MODE,
    )

    special = tmp_path / "setid"
    special.write_bytes(b"x")
    special.chmod(0o4600)
    special_result = _collect_at(tmp_path, "setid", _file_request(special))
    _assert_failure(
        special_result,
        CollectionDisposition.POLICY_REJECTED,
        CollectionReasonCode.UNSAFE_MODE,
    )

    oversized = tmp_path / "oversized"
    oversized.write_bytes(b"xx")
    oversized.chmod(0o600)
    oversized_result = _collect_at(
        tmp_path,
        "oversized",
        _file_request(oversized, max_bytes=1),
    )
    _assert_failure(
        oversized_result,
        CollectionDisposition.LIMIT_EXCEEDED,
        CollectionReasonCode.SIZE_LIMIT_EXCEEDED,
    )


def test_unsafe_anchor_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "payload"
    path.write_bytes(b"x")
    path.chmod(0o600)
    tmp_path.chmod(0o770)
    result = _collect_at(tmp_path, "payload", _file_request(path))
    _assert_failure(
        result,
        CollectionDisposition.POLICY_REJECTED,
        CollectionReasonCode.UNSAFE_MODE,
    )


def test_short_read_and_in_place_mutation_are_typed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "payload"
    path.write_bytes(b"abcdef")
    path.chmod(0o600)
    original_pread = collector_module._PREAD

    def short_read(fd: int, size: int, offset: int) -> bytes:
        if offset == 0:
            return b""
        return original_pread(fd, size, offset)

    monkeypatch.setattr(collector_module, "_PREAD", short_read)
    result = _collect_at(tmp_path, "payload", _file_request(path))
    _assert_failure(
        result,
        CollectionDisposition.MALFORMED_INPUT,
        CollectionReasonCode.SHORT_READ,
    )

    monkeypatch.setattr(collector_module, "_PREAD", original_pread)

    def mutate() -> None:
        path.write_bytes(b"ABCDEF")

    monkeypatch.setattr(collector_module, "_after_file_hash", mutate)
    result = _collect_at(tmp_path, "payload", _file_request(path))
    _assert_failure(
        result,
        CollectionDisposition.CHANGED_DURING_COLLECTION,
        CollectionReasonCode.FILE_MUTATED,
    )


@pytest.mark.parametrize(
    ("operation", "binding"),
    [
        ("unlink", PathBindingState.MISSING_AFTER_OPEN),
        ("replace", PathBindingState.REPLACED_AFTER_OPEN),
        ("ancestor", PathBindingState.ANCESTOR_REPLACED),
    ],
)
def test_path_replacement_preserves_only_partial_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    binding: PathBindingState,
) -> None:
    directory = tmp_path / "dir"
    directory.mkdir()
    path = directory / "payload"
    path.write_bytes(b"before")
    path.chmod(0o600)

    def mutate() -> None:
        monkeypatch.setattr(collector_module, "_before_file_finalize", lambda: None)
        if operation == "unlink":
            path.unlink()
        elif operation == "replace":
            path.unlink()
            path.write_bytes(b"after!")
            path.chmod(0o600)
        else:
            directory.rename(tmp_path / "old")
            directory.mkdir()

    monkeypatch.setattr(collector_module, "_before_file_finalize", mutate)
    result = _collect_at(
        tmp_path,
        "dir/payload",
        _file_request(path),
    )
    failure = _assert_failure(
        result,
        CollectionDisposition.CHANGED_DURING_COLLECTION,
        CollectionReasonCode.ANCESTOR_REPLACED
        if operation == "ancestor"
        else CollectionReasonCode.PATH_REPLACED,
    )
    assert failure.partial_descriptor is not None
    assert failure.path_binding_state is binding


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("endian", ["<", ">"])
def test_elf_parser_supports_32_64_and_both_endiannesses(
    tmp_path: Path,
    bits: int,
    endian: str,
) -> None:
    result = _inspect_bytes(
        tmp_path,
        _elf_bytes(
            bits=bits,
            endian=endian,
            interpreters=(b"/lib/ld.so\0",),
        ),
    )
    assert not isinstance(result, CollectionFailure)
    assert result.elf_class is (
        CollectorElfClass.ELF32 if bits == 32 else CollectorElfClass.ELF64
    )
    assert result.osabi == 0
    assert result.endianness is (Endianness.LITTLE if endian == "<" else Endianness.BIG)
    assert isinstance(result.interpreter, ElfInterpreterPresent)


@pytest.mark.parametrize(
    ("data", "disposition", "reason"),
    [
        (
            b"not-elf",
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_BOUNDS_INVALID,
        ),
        (
            b"NOPE" + b"\0" * 60,
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_INVALID,
        ),
        (
            _elf_bytes(ident_class=3),
            CollectionDisposition.UNSUPPORTED_PLATFORM,
            CollectionReasonCode.ELF_LAYOUT_UNSUPPORTED,
        ),
        (
            _elf_bytes(ident_data=3),
            CollectionDisposition.UNSUPPORTED_PLATFORM,
            CollectionReasonCode.ELF_LAYOUT_UNSUPPORTED,
        ),
        (
            _elf_bytes(ident_version=0),
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_INVALID,
        ),
        (
            _elf_bytes(header_version=0),
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_INVALID,
        ),
        (
            _elf_bytes(declared_ehsize=1),
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_INVALID,
        ),
        (
            _elf_bytes(declared_phentsize=55, interpreters=(b"/ld.so\0",)),
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_INVALID,
        ),
        (
            _elf_bytes(declared_phentsize=57, interpreters=(b"/ld.so\0",)),
            CollectionDisposition.UNSUPPORTED_PLATFORM,
            CollectionReasonCode.ELF_LAYOUT_UNSUPPORTED,
        ),
        (
            _elf_bytes(declared_phnum=0xFFFF),
            CollectionDisposition.UNSUPPORTED_PLATFORM,
            CollectionReasonCode.ELF_LAYOUT_UNSUPPORTED,
        ),
        (
            _elf_bytes(declared_phnum=1025),
            CollectionDisposition.LIMIT_EXCEEDED,
            CollectionReasonCode.ENTRY_LIMIT_EXCEEDED,
        ),
        (
            _elf_bytes(declared_phnum=1),
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_BOUNDS_INVALID,
        ),
        (
            _elf_bytes(declared_phoff=2**63, interpreters=(b"/ld.so\0",)),
            CollectionDisposition.MALFORMED_INPUT,
            CollectionReasonCode.ELF_BOUNDS_INVALID,
        ),
    ],
)
def test_elf_rejects_malformed_and_unsupported_layouts(
    tmp_path: Path,
    data: bytes,
    disposition: CollectionDisposition,
    reason: CollectionReasonCode,
) -> None:
    _assert_failure(_inspect_bytes(tmp_path, data), disposition, reason)


def test_elf_program_header_limit_boundary(tmp_path: Path) -> None:
    accepted = _inspect_bytes(tmp_path, _elf_bytes(null_headers=1024))
    assert not isinstance(accepted, CollectionFailure)
    assert accepted.program_header_count == 1024
    rejected = _inspect_bytes(tmp_path, _elf_bytes(null_headers=1025))
    _assert_failure(
        rejected,
        CollectionDisposition.LIMIT_EXCEEDED,
        CollectionReasonCode.ENTRY_LIMIT_EXCEEDED,
    )


@pytest.mark.parametrize(
    "interpreter",
    [
        b"/unterminated",
        b"/inside\0nul\0",
        b"relative\0",
        b"/\xff\0",
        b"/" + b"a" * 4095 + b"\0",
    ],
)
def test_elf_interpreter_validation(tmp_path: Path, interpreter: bytes) -> None:
    result = _inspect_bytes(
        tmp_path,
        _elf_bytes(interpreters=(interpreter,)),
    )
    _assert_failure(
        result,
        CollectionDisposition.MALFORMED_INPUT,
        CollectionReasonCode.ELF_INTERPRETER_PATH_INVALID,
    )


def test_elf_interpreter_absent_and_ambiguous(tmp_path: Path) -> None:
    path = tmp_path / "elf"
    data = _elf_bytes()
    path.write_bytes(data)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        absent = parse_elf_interpreter(fd, file_size=len(data))
    finally:
        os.close(fd)
    assert isinstance(absent, ElfInterpreterAbsent)

    ambiguous = _inspect_bytes(
        tmp_path,
        _elf_bytes(interpreters=(b"/one\0", b"/two\0")),
    )
    _assert_failure(
        ambiguous,
        CollectionDisposition.AMBIGUOUS,
        CollectionReasonCode.ELF_INTERPRETER_AMBIGUOUS,
    )


def test_elf_build_id_rules(tmp_path: Path) -> None:
    build_id = bytes(range(20))
    accepted = _inspect_bytes(
        tmp_path,
        _elf_bytes(note_blobs=(_note_blob(build_id),)),
    )
    assert not isinstance(accepted, CollectionFailure)
    assert accepted.build_id_sha1 is not None
    assert accepted.build_id_sha1.value == build_id.hex()

    unsupported = _inspect_bytes(
        tmp_path,
        _elf_bytes(note_blobs=(_note_blob(bytes(range(16))),)),
    )
    _assert_failure(
        unsupported,
        CollectionDisposition.UNSUPPORTED_PLATFORM,
        CollectionReasonCode.ELF_BUILD_ID_UNSUPPORTED,
    )
    malformed = _inspect_bytes(
        tmp_path,
        _elf_bytes(note_blobs=(_note_blob(build_id, malformed=True),)),
    )
    _assert_failure(
        malformed,
        CollectionDisposition.MALFORMED_INPUT,
        CollectionReasonCode.ELF_NOTE_MALFORMED,
    )
    conflicting = _inspect_bytes(
        tmp_path,
        _elf_bytes(
            note_blobs=(
                _note_blob(build_id),
                _note_blob(bytes(reversed(build_id))),
            )
        ),
    )
    _assert_failure(
        conflicting,
        CollectionDisposition.MALFORMED_INPUT,
        CollectionReasonCode.ELF_NOTE_MALFORMED,
    )
    too_many = _inspect_bytes(
        tmp_path,
        _elf_bytes(note_blobs=(_note_blob(build_id) * 257,)),
    )
    _assert_failure(
        too_many,
        CollectionDisposition.LIMIT_EXCEEDED,
        CollectionReasonCode.ENTRY_LIMIT_EXCEEDED,
    )


def test_real_running_elf_parses() -> None:
    path = os.readlink("/proc/self/exe")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        result = inspect_elf(fd, file_size=os.fstat(fd).st_size)
    finally:
        os.close(fd)
    assert not isinstance(result, CollectionFailure)
    assert result.elf_class is CollectorElfClass.ELF64


def test_real_host_interpreter_resolution_when_available(tmp_path: Path) -> None:
    executable = Path(os.readlink("/proc/self/exe"))
    fd = os.open(executable, os.O_RDONLY | os.O_CLOEXEC)
    try:
        inspection = inspect_elf(fd, file_size=os.fstat(fd).st_size)
    finally:
        os.close(fd)
    if isinstance(inspection, CollectionFailure) or isinstance(
        inspection.interpreter, ElfInterpreterAbsent
    ):
        pytest.skip("running executable has no supported PT_INTERP")
    bundle = _make_distribution(tmp_path)
    request = replace(
        _make_offline_request(bundle),
        anchor_fd=None,
        anchor_path=None,
        interpreter_expected_owner_uid=0,
        interpreter_allow_root_owner=True,
    )
    try:
        try:
            held, chain = collector_module._resolve_interpreter(
                inspection.interpreter.path,
                request,
                limits=DEFAULT_COLLECTOR_LIMITS,
                deadline=collector_types.MonotonicDeadline.after(30),
            )
        except collector_module._CollectorAbort as exc:
            pytest.skip(f"host interpreter path did not satisfy policy: {exc.failure}")
        try:
            evidence = collector_module._finalize_held_file(
                held,
                subject=EvidenceSubject.INTERPRETER,
            )
        finally:
            held.close()
    finally:
        _close_bundle(bundle)
    assert evidence.path.resolved_path.value.startswith("/")
    assert len(chain) <= 40


def test_distribution_collects_all_roles_with_readable_inventory_fds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _make_distribution(tmp_path)
    observed_access_modes: list[int] = []
    original = collector_module._SCANDIR

    def checked(fd: int):
        observed_access_modes.append(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE)
        return original(fd)

    monkeypatch.setattr(collector_module, "_SCANDIR", checked)
    try:
        result = collect_distribution_evidence(bundle.request)
    finally:
        _close_bundle(bundle)
    assert not isinstance(result, CollectionFailure)
    assert len(result.artifacts) == 11
    assert {item.name for item in result.artifacts} == set(ArtifactName)
    assert all(mode == os.O_RDONLY for mode in observed_access_modes)
    rows = tuple(
        TreeManifestRow(
            entry_type=row.entry_type,
            mode_octal=row.mode_octal,
            size_bytes=row.size_bytes,
            sha256=row.sha256,
            relative_path=row.relative_path,
        )
        for row in result.content_manifest.rows
    )
    assert (
        result.content_manifest.sha256.value
        == hashlib.sha256(manifest_bytes(rows)).hexdigest()
    )
    assert result.source.seal_performed is False
    with pytest.raises(ValueError):
        ObservedDistributionSource(root=result.source.root, seal_performed=True)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        (ArtifactName.RUNTIME_NODE, CollectionReasonCode.ARTIFACT_MISSING),
        (ArtifactName.CLI_NATIVE_NODE, CollectionReasonCode.ARTIFACT_MISSING),
        (ArtifactName.SESSION_EVENTS_SCHEMA, CollectionReasonCode.SCHEMA_MISSING),
        (ArtifactName.API_SCHEMA, CollectionReasonCode.SCHEMA_MISSING),
    ],
)
def test_distribution_missing_required_files(
    tmp_path: Path,
    name: ArtifactName,
    reason: CollectionReasonCode,
) -> None:
    bundle = _make_distribution(tmp_path)
    (bundle.root / name.value).unlink()
    try:
        result = collect_distribution_evidence(bundle.request)
    finally:
        _close_bundle(bundle)
    _assert_failure(result, CollectionDisposition.INCOMPLETE, reason)


def test_distribution_rejects_duplicate_alias_and_missing_roles_before_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _make_distribution(tmp_path)
    opened = False

    def forbidden(*args, **kwargs):
        nonlocal opened
        opened = True
        raise AssertionError("filesystem access occurred")

    monkeypatch.setattr(collector_module, "_open_distribution_root", forbidden)
    duplicate = replace(
        bundle.request,
        artifacts=(*bundle.request.artifacts, bundle.request.artifacts[0]),
    )
    _assert_failure(
        collect_distribution_evidence(duplicate),
        CollectionDisposition.INVALID_REQUEST,
        CollectionReasonCode.DUPLICATE_ARTIFACT_ROLE,
    )
    missing = replace(bundle.request, artifacts=bundle.request.artifacts[:-1])
    _assert_failure(
        collect_distribution_evidence(missing),
        CollectionDisposition.INVALID_REQUEST,
        CollectionReasonCode.INVALID_ROLE_SET,
    )
    alias = replace(
        bundle.request,
        artifacts=(
            replace(bundle.request.artifacts[0], relative_path="alias"),
            *bundle.request.artifacts[1:],
        ),
    )
    _assert_failure(
        collect_distribution_evidence(alias),
        CollectionDisposition.INVALID_REQUEST,
        CollectionReasonCode.INVALID_ROLE_SET,
    )
    duplicate_schema = replace(
        bundle.request,
        schemas=(bundle.request.schemas[0], bundle.request.schemas[0]),
    )
    _assert_failure(
        collect_distribution_evidence(duplicate_schema),
        CollectionDisposition.INVALID_REQUEST,
        CollectionReasonCode.DUPLICATE_CONTRACT_INPUT,
    )
    assert opened is False
    _close_bundle(bundle)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("name", "wrong", CollectionReasonCode.PACKAGE_IDENTITY_MISMATCH),
        ("type", "commonjs", CollectionReasonCode.PACKAGE_IDENTITY_MISMATCH),
        (
            "bin",
            {"copilot": "other.js"},
            CollectionReasonCode.PACKAGE_IDENTITY_MISMATCH,
        ),
        ("version", "9.9.9", CollectionReasonCode.DISTRIBUTION_VERSION_MISMATCH),
    ],
)
def test_distribution_package_identity_mismatch(
    tmp_path: Path,
    field: str,
    value: object,
    reason: CollectionReasonCode,
) -> None:
    bundle = _make_distribution(tmp_path)
    package = {
        "name": "@github/copilot",
        "version": "1.2.3",
        "type": "module",
        "bin": {"copilot": "npm-loader.js"},
    }
    package[field] = value
    (bundle.root / "package.json").write_text(json.dumps(package), encoding="utf-8")
    try:
        result = collect_distribution_evidence(bundle.request)
    finally:
        _close_bundle(bundle)
    _assert_failure(result, CollectionDisposition.MISMATCH, reason)


def test_distribution_wrong_root_format_schema_and_deep_json(
    tmp_path: Path,
) -> None:
    bundle = _make_distribution(tmp_path)
    wrong_root = tmp_path / "missing"
    wrong = replace(bundle.request, source_directory=_absolute(wrong_root))
    _assert_failure(
        collect_distribution_evidence(wrong),
        CollectionDisposition.MISMATCH,
        CollectionReasonCode.PACKAGE_IDENTITY_MISMATCH,
    )

    (bundle.root / ArtifactName.INDEX_JS.value).write_bytes(b"\xff")
    _assert_failure(
        collect_distribution_evidence(bundle.request),
        CollectionDisposition.MISMATCH,
        CollectionReasonCode.ARTIFACT_FORMAT_MISMATCH,
    )
    (bundle.root / ArtifactName.INDEX_JS.value).write_bytes(b"ok")

    wrong_schema = replace(
        bundle.request.schemas[0],
        expected_file_sha256=_trusted_sha("0"),
    )
    schema_request = replace(
        bundle.request,
        schemas=(wrong_schema, bundle.request.schemas[1]),
    )
    _assert_failure(
        collect_distribution_evidence(schema_request),
        CollectionDisposition.MISMATCH,
        CollectionReasonCode.SCHEMA_DIGEST_MISMATCH,
    )

    deep = "[" * 1200 + "0" + "]" * 1200
    (bundle.root / "package.json").write_text(deep, encoding="utf-8")
    _assert_failure(
        collect_distribution_evidence(bundle.request),
        CollectionDisposition.MALFORMED_INPUT,
        CollectionReasonCode.PACKAGE_MANIFEST_INVALID,
    )
    _close_bundle(bundle)


def test_distribution_tree_total_bound_and_non_utf8_name_are_typed(
    tmp_path: Path,
) -> None:
    bundle = _make_distribution(tmp_path)
    tiny_limits = replace(DEFAULT_COLLECTOR_LIMITS, tree_total_regular_bytes=1)
    _assert_failure(
        collect_distribution_evidence(bundle.request, limits=tiny_limits),
        CollectionDisposition.LIMIT_EXCEEDED,
        CollectionReasonCode.TOTAL_BYTE_LIMIT_EXCEEDED,
    )
    root_fd = os.open(bundle.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        bad_fd = os.open(
            b"\xff",
            os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC,
            0o600,
            dir_fd=root_fd,
        )
        os.close(bad_fd)
    finally:
        os.close(root_fd)
    invalid = collect_distribution_evidence(bundle.request)
    assert isinstance(invalid, CollectionFailure)
    _close_bundle(bundle)


def test_distribution_depth_and_trusted_record_bounds(tmp_path: Path) -> None:
    bundle = _make_distribution(tmp_path)
    directory = bundle.root
    for index in range(DEFAULT_COLLECTOR_LIMITS.tree_depth + 1):
        directory = directory / f"d{index}"
        directory.mkdir()
    _assert_failure(
        collect_distribution_evidence(bundle.request),
        CollectionDisposition.LIMIT_EXCEEDED,
        CollectionReasonCode.DEPTH_LIMIT_EXCEEDED,
    )
    bad_schema = replace(bundle.request.schemas[0], definition_count=-1)
    bad_request = replace(
        bundle.request,
        schemas=(bad_schema, bundle.request.schemas[1]),
    )
    _assert_failure(
        collect_distribution_evidence(bad_request),
        CollectionDisposition.MISMATCH,
        CollectionReasonCode.TRUSTED_DIGEST_INPUT_INVALID,
    )
    _close_bundle(bundle)


def test_shell_script_format_is_rejected_before_content_read(tmp_path: Path) -> None:
    path = tmp_path / "script"
    path.write_bytes(b"#!/bin/sh\n")
    path.chmod(0o700)
    result = _collect_at(
        tmp_path,
        "script",
        _file_request(
            path,
            executable=True,
            format_id=FormatId.SHELL_SCRIPT,
        ),
    )
    _assert_failure(
        result,
        CollectionDisposition.INVALID_REQUEST,
        CollectionReasonCode.INVALID_ROLE_SET,
    )


def test_distribution_tree_change_and_root_lock_churn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _make_distribution(tmp_path)

    def add_lock() -> None:
        (bundle.root / f"inuse.{os.getpid()}.lock").write_bytes(b"")

    monkeypatch.setattr(collector_module, "_after_inventory_a", add_lock)
    try:
        result = collect_distribution_evidence(bundle.request)
    finally:
        _close_bundle(bundle)
    assert not isinstance(result, CollectionFailure)

    other = _make_distribution(tmp_path / "other")

    def add_artifact() -> None:
        path = other.root / "unexpected.txt"
        path.write_bytes(b"x")
        path.chmod(0o600)

    monkeypatch.setattr(collector_module, "_after_inventory_a", add_artifact)
    try:
        changed = collect_distribution_evidence(other.request)
    finally:
        _close_bundle(other)
    _assert_failure(
        changed,
        CollectionDisposition.CHANGED_DURING_COLLECTION,
        CollectionReasonCode.DISTRIBUTION_TREE_CHANGED,
    )


@pytest.mark.parametrize(
    ("copies", "disposition", "reason"),
    [
        (
            0,
            CollectionDisposition.INCOMPLETE,
            CollectionReasonCode.EMBEDDED_PAYLOAD_MISSING,
        ),
        (
            2,
            CollectionDisposition.AMBIGUOUS,
            CollectionReasonCode.EMBEDDED_PAYLOAD_AMBIGUOUS,
        ),
    ],
)
def test_offline_embedded_payload_cardinality(
    tmp_path: Path,
    copies: int,
    disposition: CollectionDisposition,
    reason: CollectionReasonCode,
) -> None:
    bundle = _make_distribution(tmp_path)
    request = _make_offline_request(
        bundle,
        frontend_payload=bundle.payload * copies,
    )
    try:
        result = collect_offline_runtime_evidence(request)
    finally:
        _close_bundle(bundle)
    _assert_failure(result, disposition, reason)


def test_offline_payload_crosses_chunk_boundary_and_interpreter_absence_is_role_scoped(
    tmp_path: Path,
) -> None:
    bundle = _make_distribution(tmp_path)
    start = DEFAULT_COLLECTOR_LIMITS.hash_chunk_bytes - len(bundle.payload) // 2
    request = _make_offline_request(bundle, payload_offset=start)
    try:
        result = collect_offline_runtime_evidence(request)
    finally:
        _close_bundle(bundle)
    assert not isinstance(result, CollectionFailure)
    assert result.embedded_sea_loader.offset == start
    assert result.counters.maximum_held_descriptors <= MAX_HELD_DESCRIPTORS
    assert isinstance(result.interpreter_elf.interpreter, ElfInterpreterAbsent)
    assert all(
        item.file.descriptor.format_id is FormatId.ELF64_X86_64_DYN
        for item in result.distribution.artifacts
        if item.name in {ArtifactName.RUNTIME_NODE, ArtifactName.CLI_NATIVE_NODE}
    )


def test_offline_collection_stays_within_descriptor_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _make_distribution(tmp_path)
    request = _make_offline_request(bundle)
    original_open = collector_module._OS_OPEN
    original_close = collector_module._CLOSE
    original_dup = collector_module._DUP
    active: set[int] = set()
    peak = 0

    def track(fd: int) -> int:
        nonlocal peak
        active.add(fd)
        peak = max(peak, len(active))
        return fd

    def tracked_open(*args, **kwargs):
        return track(original_open(*args, **kwargs))

    def tracked_dup(fd: int) -> int:
        return track(original_dup(fd))

    def tracked_close(fd: int) -> None:
        active.discard(fd)
        original_close(fd)

    monkeypatch.setattr(collector_module, "_OS_OPEN", tracked_open)
    monkeypatch.setattr(collector_module, "_DUP", tracked_dup)
    monkeypatch.setattr(collector_module, "_CLOSE", tracked_close)
    try:
        result = collect_offline_runtime_evidence(request)
    finally:
        _close_bundle(bundle)
    assert not isinstance(result, CollectionFailure)
    assert peak <= MAX_HELD_DESCRIPTORS
    assert not active


def test_frontend_without_interpreter_fails_but_native_objects_do_not(
    tmp_path: Path,
) -> None:
    bundle = _make_distribution(tmp_path)
    request = _make_offline_request(bundle)
    frontend = Path(request.frontend.absolute_path.value)
    frontend.write_bytes(_elf_bytes(elf_type=2) + bundle.payload)
    frontend.chmod(0o755)
    try:
        result = collect_offline_runtime_evidence(request)
    finally:
        _close_bundle(bundle)
    _assert_failure(
        result,
        CollectionDisposition.INCOMPLETE,
        CollectionReasonCode.ELF_INTERPRETER_MISSING,
    )


def test_distribution_native_with_interpreter_is_a_format_mismatch(
    tmp_path: Path,
) -> None:
    bundle = _make_distribution(tmp_path)
    native = bundle.root / ArtifactName.RUNTIME_NODE.value
    native.write_bytes(_elf_bytes(interpreters=(b"/lib/ld.so\0",)))
    native.chmod(0o755)
    try:
        result = collect_distribution_evidence(bundle.request)
    finally:
        _close_bundle(bundle)
    _assert_failure(
        result,
        CollectionDisposition.MISMATCH,
        CollectionReasonCode.ARTIFACT_FORMAT_MISMATCH,
    )


def test_interpreter_symlink_resolution_loop_and_hop_limit(tmp_path: Path) -> None:
    success_root = tmp_path / "success"
    success_root.mkdir()
    success = _make_distribution(success_root)
    real = success.anchor / "lib" / "ld-real.so"
    real.parent.mkdir()
    real.write_bytes(_elf_bytes())
    real.chmod(0o755)
    link_dir = success.anchor / "lib64"
    link_dir.mkdir()
    (link_dir / "ld.so").symlink_to("../lib/ld-real.so")
    request = _make_offline_request(success, interpreter_path="/lib64/ld.so")
    try:
        result = collect_offline_runtime_evidence(request)
    finally:
        _close_bundle(success)
    assert not isinstance(result, CollectionFailure)
    assert len(result.interpreter.symlink_chain) == 1
    assert result.interpreter.symlink_chain[0].link_text_sha256 is not None

    loop_root = tmp_path / "loop"
    loop_root.mkdir()
    loop = _make_distribution(loop_root)
    (loop.anchor / "a").symlink_to("b")
    (loop.anchor / "b").symlink_to("a")
    loop_request = _make_offline_request(loop, interpreter_path="/a")
    try:
        loop_result = collect_offline_runtime_evidence(loop_request)
    finally:
        _close_bundle(loop)
    _assert_failure(
        loop_result,
        CollectionDisposition.POLICY_REJECTED,
        CollectionReasonCode.PATH_POLICY_VIOLATION,
    )

    chain_root = tmp_path / "chain"
    chain_root.mkdir()
    chain = _make_distribution(chain_root)
    target = chain.anchor / "target"
    target.write_bytes(_elf_bytes())
    target.chmod(0o755)
    for index in range(41):
        destination = "target" if index == 40 else f"hop{index + 1}"
        (chain.anchor / f"hop{index}").symlink_to(destination)
    chain_request = _make_offline_request(chain, interpreter_path="/hop0")
    try:
        chain_result = collect_offline_runtime_evidence(chain_request)
    finally:
        _close_bundle(chain)
    _assert_failure(
        chain_result,
        CollectionDisposition.LIMIT_EXCEEDED,
        CollectionReasonCode.DEPTH_LIMIT_EXCEEDED,
    )


def test_interpreter_40_hops_succeeds_and_unsafe_parent_fails(tmp_path: Path) -> None:
    chain_root = tmp_path / "forty"
    chain_root.mkdir()
    bundle = _make_distribution(chain_root)
    target = bundle.anchor / "target"
    target.write_bytes(_elf_bytes())
    target.chmod(0o755)
    for index in range(40):
        destination = "target" if index == 39 else f"hop{index + 1}"
        (bundle.anchor / f"hop{index}").symlink_to(destination)
    request = _make_offline_request(bundle, interpreter_path="/hop0")
    try:
        result = collect_offline_runtime_evidence(request)
    finally:
        _close_bundle(bundle)
    assert not isinstance(result, CollectionFailure)
    assert len(result.interpreter.symlink_chain) == 40

    unsafe_root = tmp_path / "unsafe-interpreter"
    unsafe_root.mkdir()
    unsafe = _make_distribution(unsafe_root)
    request = _make_offline_request(unsafe)
    (unsafe.anchor / "lib").chmod(0o775)
    try:
        unsafe_result = collect_offline_runtime_evidence(request)
    finally:
        _close_bundle(unsafe)
    _assert_failure(
        unsafe_result,
        CollectionDisposition.POLICY_REJECTED,
        CollectionReasonCode.UNSAFE_MODE,
    )


def test_interpreter_symlink_owner_mismatch_is_typed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _make_distribution(tmp_path)
    real = bundle.anchor / "lib" / "ld-real.so"
    real.parent.mkdir()
    real.write_bytes(_elf_bytes())
    real.chmod(0o755)
    link_dir = bundle.anchor / "lib64"
    link_dir.mkdir()
    (link_dir / "ld.so").symlink_to("../lib/ld-real.so")
    request = _make_offline_request(bundle, interpreter_path="/lib64/ld.so")
    original_fstat = collector_module._FSTAT

    def foreign_symlink(fd: int):
        value = original_fstat(fd)
        if stat.S_ISLNK(value.st_mode):
            items = list(value)
            items[4] = os.geteuid() + 1
            return os.stat_result(items)
        return value

    monkeypatch.setattr(collector_module, "_FSTAT", foreign_symlink)
    request = replace(request, interpreter_allow_root_owner=False)
    try:
        result = collect_offline_runtime_evidence(request)
    finally:
        _close_bundle(bundle)
    _assert_failure(
        result,
        CollectionDisposition.POLICY_REJECTED,
        CollectionReasonCode.OWNER_MISMATCH,
    )


def test_post_secondary_read_mutation_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _make_distribution(tmp_path)
    request = _make_offline_request(bundle)
    frontend = Path(request.frontend.absolute_path.value)
    mutated = False

    def mutate_once() -> None:
        nonlocal mutated
        if not mutated:
            mutated = True
            raw = frontend.read_bytes()
            frontend.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))

    monkeypatch.setattr(collector_module, "_before_file_finalize", mutate_once)
    try:
        result = collect_offline_runtime_evidence(request)
    finally:
        _close_bundle(bundle)
    _assert_failure(
        result,
        CollectionDisposition.CHANGED_DURING_COLLECTION,
        CollectionReasonCode.FILE_MUTATED,
    )


def test_request_mutation_cannot_change_distribution_result(tmp_path: Path) -> None:
    bundle = _make_distribution(tmp_path)
    mutable = list(bundle.request.artifacts)
    request = replace(bundle.request, artifacts=tuple(mutable))
    try:
        result = collect_distribution_evidence(request)
        mutable.clear()
    finally:
        _close_bundle(bundle)
    assert not isinstance(result, CollectionFailure)
    assert len(result.artifacts) == 11


def test_proc_stat_parser_handles_spaces_parentheses_and_mainthread() -> None:
    fields = [b"S", b"1", *([b"0"] * 17), b"424242", *([b"0"] * 8)]
    raw = b"123 (name with ) spaces MainThread) " + b" ".join(fields) + b"\n"
    result = parse_proc_stat(raw)
    assert not isinstance(result, CollectionFailure)
    assert result.pid == 123
    assert result.parent_pid == 1
    assert result.starttime_ticks == 424242
    assert result.comm == b"name with ) spaces MainThread"
    _assert_failure(
        parse_proc_stat(b"123 (unterminated"),
        CollectionDisposition.MALFORMED_INPUT,
        CollectionReasonCode.PROC_STAT_MALFORMED,
    )


def test_proc_maps_btrfs_duplicate_deleted_and_escape_cases() -> None:
    raw = (FIXTURE_DIR / "collector-maps-btrfs.txt").read_bytes()
    parsed = parse_proc_maps(raw)
    assert not isinstance(parsed, CollectionFailure)
    assert parsed.rows[0].major == 0
    assert parsed.rows[0].minor == 0x34
    duplicate = parse_proc_maps(raw + raw.splitlines(keepends=True)[-1])
    assert not isinstance(duplicate, CollectionFailure)
    assert len(duplicate.rows) == len(parsed.rows)

    deleted = parse_proc_maps(
        b"1000-2000 r-xp 00000000 00:34 7 /tmp/module (deleted)\n"
    )
    assert not isinstance(deleted, CollectionFailure)
    assert deleted.rows[0].deleted is True
    assert deleted.rows[0].pathname == b"/tmp/module"
    assert deleted.rows[0].kind is ProcMapKind.FILE

    escaped = parse_proc_maps(
        (FIXTURE_DIR / "collector-maps-adversarial.txt").read_bytes()
    )
    failure = _assert_failure(
        escaped,
        CollectionDisposition.MALFORMED_INPUT,
        CollectionReasonCode.PATHNAME_ESCAPE_UNSUPPORTED,
    )
    assert b"escaped" not in repr(failure).encode()


def test_proc_maps_limits_and_malformed_rows() -> None:
    overlap = b"1000-3000 r-xp 0 00:01 1 /a\n2000-4000 r-xp 0 00:01 2 /b\n"
    _assert_failure(
        parse_proc_maps(overlap),
        CollectionDisposition.MALFORMED_INPUT,
        CollectionReasonCode.PROC_MAPS_MALFORMED,
    )
    malformed = b"zzzz-2000 r-xp 0 00:01 1 /a\n"
    _assert_failure(
        parse_proc_maps(malformed),
        CollectionDisposition.MALFORMED_INPUT,
        CollectionReasonCode.PROC_MAPS_MALFORMED,
    )
    limits = ProcfsLimits(maps_lines=1)
    _assert_failure(
        parse_proc_maps(
            b"1000-2000 r-xp 0 00:01 1 /a\n3000-4000 r-xp 0 00:01 2 /b\n",
            limits=limits,
        ),
        CollectionDisposition.LIMIT_EXCEEDED,
        CollectionReasonCode.PROC_MAPS_LIMIT_EXCEEDED,
    )
    _assert_failure(
        parse_proc_maps(
            b"1000-2000 r-xp 0 00:01 1 " + b"a" * 20 + b"\n",
            limits=ProcfsLimits(maps_line_bytes=16),
        ),
        CollectionDisposition.LIMIT_EXCEEDED,
        CollectionReasonCode.PROC_MAPS_LIMIT_EXCEEDED,
    )
    _assert_failure(
        parse_proc_maps(
            b"1000-2000 r-xp 0 00:01 1 /a\n",
            limits=ProcfsLimits(maps_bytes=4),
        ),
        CollectionDisposition.LIMIT_EXCEEDED,
        CollectionReasonCode.PROC_MAPS_LIMIT_EXCEEDED,
    )
    exact_line_flood = b"".join(
        f"{index * 0x2000 + 0x1000:x}-{index * 0x2000 + 0x2000:x} "
        "r-xp 0 00:01 1 /a\n".encode()
        for index in range(DEFAULT_PROCFS_LIMITS.maps_lines + 1)
    )
    _assert_failure(
        parse_proc_maps(exact_line_flood),
        CollectionDisposition.LIMIT_EXCEEDED,
        CollectionReasonCode.PROC_MAPS_LIMIT_EXCEEDED,
    )
    _assert_failure(
        parse_proc_maps(b"A" * (DEFAULT_PROCFS_LIMITS.maps_bytes + 1)),
        CollectionDisposition.LIMIT_EXCEEDED,
        CollectionReasonCode.PROC_MAPS_LIMIT_EXCEEDED,
    )


def test_mountinfo_decoding_btrfs_and_ambiguity() -> None:
    parsed = parse_mountinfo(
        (FIXTURE_DIR / "collector-mountinfo-btrfs.txt").read_bytes()
    )
    assert not isinstance(parsed, CollectionFailure)
    assert {(row.major, row.minor) for row in parsed.rows} == {(0, 52)}
    escaped = parse_mountinfo(b"1 0 0:1 / /with\\040space rw - tmpfs tmpfs rw\n")
    assert not isinstance(escaped, CollectionFailure)
    assert escaped.rows[0].mount_point == b"/with space"
    malformed = parse_mountinfo(
        (FIXTURE_DIR / "collector-mountinfo-adversarial.txt").read_bytes()
    )
    _assert_failure(
        malformed,
        CollectionDisposition.MALFORMED_INPUT,
        CollectionReasonCode.MOUNTINFO_MALFORMED,
    )
    duplicate = parse_mountinfo(
        b"1 0 0:1 / /same rw - tmpfs one rw\n2 0 0:2 / /same rw - tmpfs two rw\n"
    )
    assert not isinstance(duplicate, CollectionFailure)
    with pytest.raises(procfs_module._ProcAbort) as exc_info:
        procfs_module._mount_for_path(b"/same/file", duplicate)
    assert CollectionReasonCode.MOUNT_AMBIGUOUS in exc_info.value.failure.reason_codes


def _synthetic_file_evidence(
    path: str,
    *,
    inode: int,
    device: int,
) -> FileEvidence:
    absolute = AbsolutePath(path)
    return FileEvidence(
        role=FileRole.DISTRIBUTION_ARTIFACT,
        descriptor=DescriptorIdentity(
            stat=DescriptorStat(
                device=device,
                inode=inode,
                mode_octal="0755",
                uid=os.geteuid(),
                gid=os.getegid(),
                size_bytes=1,
                nlink=1,
                mtime_ns=1,
                ctime_ns=1,
            ),
            sha256="a" * 64,
            format_id=FormatId.OPAQUE,
            elf_build_id_sha1=None,
            bytes_hashed=1,
        ),
        path=PathObservation(
            requested_path=absolute,
            resolved_path=absolute,
            policy_id=PathPolicyId.DISTRIBUTION_REGULAR_NO_SYMLINK_V1,
            components=(),
            binding_state=PathBindingState.STABLE,
            asserted_prefix_components=0,
        ),
    )


def test_btrfs_maps_device_compares_to_mountinfo_not_st_dev(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = "/home/runner/dist/prebuilds/linux-x64/runtime.node"
    trusted = _synthetic_file_evidence(path, inode=101, device=53)
    expected = ExpectedMappedObject(MappedObjectRole.RUNTIME_NODE, trusted)
    maps = parse_proc_maps((FIXTURE_DIR / "collector-maps-btrfs.txt").read_bytes())
    mountinfo = parse_mountinfo(
        (FIXTURE_DIR / "collector-mountinfo-btrfs.txt").read_bytes()
    )
    assert not isinstance(maps, CollectionFailure)
    assert not isinstance(mountinfo, CollectionFailure)
    monkeypatch.setattr(procfs_module, "_recollect_expected", lambda item: trusted)
    result = procfs_module._mapped_evidence(
        expected,
        maps,
        mountinfo,
        limits=DEFAULT_PROCFS_LIMITS,
    )
    assert result.maps_device.value == "0:52"
    assert result.mount_device.value == "0:52"
    assert result.parent_mount_id == 72
    assert trusted.descriptor.stat.device == 53


@pytest.mark.parametrize(
    ("raw", "disposition", "reason"),
    [
        (
            b"",
            CollectionDisposition.INCOMPLETE,
            CollectionReasonCode.MAPPED_MODULE_MISSING,
        ),
        (
            b"1000-2000 r--p 0 00:34 101 /home/runner/dist/prebuilds/linux-x64/runtime.node\n",
            CollectionDisposition.INCOMPLETE,
            CollectionReasonCode.MAPPED_MODULE_NOT_EXECUTABLE,
        ),
        (
            b"1000-2000 r-xp 0 00:34 101 /home/runner/dist/prebuilds/linux-x64/runtime.node (deleted)\n",
            CollectionDisposition.MISMATCH,
            CollectionReasonCode.MAPPED_FILE_DELETED,
        ),
        (
            b"1000-2000 r-xp 0 00:34 101 /home/runner/dist/prebuilds/linux-x64/runtime.node\n"
            b"3000-4000 r-xp 0 00:34 202 /home/runner/dist/prebuilds/linux-x64/runtime.node\n",
            CollectionDisposition.AMBIGUOUS,
            CollectionReasonCode.MAPPED_MODULE_AMBIGUOUS,
        ),
    ],
)
def test_mapped_object_missing_nonexec_deleted_and_ambiguous(
    raw: bytes,
    disposition: CollectionDisposition,
    reason: CollectionReasonCode,
) -> None:
    trusted = _synthetic_file_evidence(
        "/home/runner/dist/prebuilds/linux-x64/runtime.node",
        inode=101,
        device=53,
    )
    maps = parse_proc_maps(raw)
    mountinfo = parse_mountinfo(
        (FIXTURE_DIR / "collector-mountinfo-btrfs.txt").read_bytes()
    )
    assert not isinstance(maps, CollectionFailure)
    assert not isinstance(mountinfo, CollectionFailure)
    with pytest.raises(procfs_module._ProcAbort) as exc_info:
        procfs_module._mapped_evidence(
            ExpectedMappedObject(MappedObjectRole.RUNTIME_NODE, trusted),
            maps,
            mountinfo,
            limits=DEFAULT_PROCFS_LIMITS,
        )
    _assert_failure(exc_info.value.failure, disposition, reason)


def test_owned_process_collection_succeeds_without_map_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, expected, mappings, anchor_fd = _owned_process_fixture(tmp_path)
    original_open = procfs_module._OS_OPEN
    map_files_attempted = False
    original_read_proc = procfs_module._read_proc_file

    def guarded_open(path, flags, *args, **kwargs):
        nonlocal map_files_attempted
        if "map_files" in str(path):
            map_files_attempted = True
            raise PermissionError(errno.EPERM, "blocked")
        if "/proc/self/fdinfo/" in str(path):
            raise PermissionError(errno.EPERM, "fdinfo unavailable")
        return original_open(path, flags, *args, **kwargs)

    def mainthread_comm(proc_fd, name, **kwargs):
        if name == "comm":
            return b"MainThread\n"
        return original_read_proc(proc_fd, name, **kwargs)

    monkeypatch.setattr(procfs_module, "_OS_OPEN", guarded_open)
    monkeypatch.setattr(procfs_module, "_read_proc_file", mainthread_comm)
    try:
        result = collect_linux_process_evidence(scope, expected)
    finally:
        for mapping in mappings:
            mapping.close()
        os.close(anchor_fd)
    assert not isinstance(result, CollectionFailure)
    assert result.observed_pid == os.getpid()
    assert result.observed_euid == os.geteuid()
    assert result.mount_namespace_inode == scope.expected_mount_namespace_inode
    assert result.proc_exe is not None
    assert result.comm_observed == "MainThread"
    assert result.comm_truncated is False
    assert result.comm_authoritative is False
    assert result.loader_mapping.role is MappedObjectRole.LOADER
    assert len(result.maps_sha256.value) == 64
    assert len(result.mountinfo_sha256.value) == 64
    assert all(item.fdinfo_mount_id is None for item in result.native_mappings)
    assert tuple(item.role for item in result.native_mappings) == (
        MappedObjectRole.RUNTIME_NODE,
        MappedObjectRole.CLI_NATIVE_NODE,
    )
    assert map_files_attempted is False


def test_owned_process_unexpected_mapping_is_rejected(tmp_path: Path) -> None:
    scope, expected, mappings, anchor_fd = _owned_process_fixture(
        tmp_path,
        third_mapping=True,
    )
    try:
        result = collect_linux_process_evidence(scope, expected)
    finally:
        for mapping in mappings:
            mapping.close()
        os.close(anchor_fd)
    _assert_failure(
        result,
        CollectionDisposition.MISMATCH,
        CollectionReasonCode.MAPPED_NATIVE_IMAGE_UNEXPECTED,
    )


def test_owned_process_scope_exe_change_dead_pid_and_permission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, expected, mappings, anchor_fd = _owned_process_fixture(tmp_path)
    wrong_scope = replace(
        scope,
        expected_mount_namespace_inode=scope.expected_mount_namespace_inode + 1,
    )
    try:
        _assert_failure(
            collect_linux_process_evidence(wrong_scope, expected),
            CollectionDisposition.MISMATCH,
            CollectionReasonCode.PROCESS_SCOPE_MISMATCH,
        )

        changed = False
        original_stat = procfs_module._STAT

        def flip() -> None:
            nonlocal changed
            changed = True

        def changed_stat(path, *args, **kwargs):
            value = original_stat(path, *args, **kwargs)
            if changed and path == "exe":
                items = list(value)
                items[1] += 1
                return os.stat_result(items)
            return value

        monkeypatch.setattr(procfs_module, "_after_proc_snapshot", flip)
        monkeypatch.setattr(procfs_module, "_STAT", changed_stat)
        _assert_failure(
            collect_linux_process_evidence(scope, expected),
            CollectionDisposition.CHANGED_DURING_COLLECTION,
            CollectionReasonCode.PROCESS_CHANGED,
        )
    finally:
        for mapping in mappings:
            mapping.close()
        os.close(anchor_fd)

    dead = replace(scope, pid=2**31 - 1)
    dead_result = collect_linux_process_evidence(dead, expected)
    assert isinstance(dead_result, CollectionFailure)
    assert dead_result.disposition is CollectionDisposition.UNAVAILABLE

    original_open = procfs_module._OS_OPEN

    def denied(path, flags, *args, **kwargs):
        if str(path).startswith("/proc/"):
            raise PermissionError(errno.EACCES, "denied")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(procfs_module, "_OS_OPEN", denied)
    denied_result = collect_linux_process_evidence(scope, expected)
    _assert_failure(
        denied_result,
        CollectionDisposition.UNAVAILABLE,
        CollectionReasonCode.PERMISSION_DENIED,
    )


def test_platform_and_missing_primitive_degrade_to_typed_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "payload"
    path.write_bytes(b"x")
    path.chmod(0o600)
    monkeypatch.setattr(collector_module.sys, "platform", "darwin")
    _assert_failure(
        collect_file_identity(_file_request(path)),
        CollectionDisposition.UNSUPPORTED_PLATFORM,
        CollectionReasonCode.PLATFORM_UNSUPPORTED,
    )
    bundle = _make_distribution(tmp_path / "distribution")
    _assert_failure(
        collect_distribution_evidence(bundle.request),
        CollectionDisposition.UNSUPPORTED_PLATFORM,
        CollectionReasonCode.PLATFORM_UNSUPPORTED,
    )
    trusted = _synthetic_file_evidence("/tmp/fake", inode=1, device=1)
    process_expected = ExpectedMappedObjects(
        loader=ExpectedMappedObject(MappedObjectRole.LOADER, trusted),
        native_modules=(
            ExpectedMappedObject(MappedObjectRole.RUNTIME_NODE, trusted),
            ExpectedMappedObject(MappedObjectRole.CLI_NATIVE_NODE, trusted),
        ),
        distribution_root=trusted.path,
    )
    _assert_failure(
        collect_linux_process_evidence(
            TrustedProcessScope(1, 1, os.geteuid(), 1, 1),
            process_expected,
        ),
        CollectionDisposition.UNSUPPORTED_PLATFORM,
        CollectionReasonCode.PLATFORM_UNSUPPORTED,
    )
    _close_bundle(bundle)
    monkeypatch.setattr(collector_module.sys, "platform", "linux")
    monkeypatch.delattr(collector_module.os, "O_PATH")
    _assert_failure(
        collect_file_identity(_file_request(path)),
        CollectionDisposition.UNSUPPORTED_PLATFORM,
        CollectionReasonCode.OS_PRIMITIVE_UNAVAILABLE,
    )


def test_mountinfo_unavailable_is_typed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, expected, mappings, anchor_fd = _owned_process_fixture(tmp_path)
    original_open = procfs_module._OS_OPEN

    def unavailable(path, flags, *args, **kwargs):
        if path == "/proc/self/mountinfo":
            raise FileNotFoundError(errno.ENOENT, "missing")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(procfs_module, "_OS_OPEN", unavailable)
    try:
        result = collect_linux_process_evidence(scope, expected)
    finally:
        for mapping in mappings:
            mapping.close()
        os.close(anchor_fd)
    _assert_failure(
        result,
        CollectionDisposition.UNAVAILABLE,
        CollectionReasonCode.MOUNTINFO_UNAVAILABLE,
    )


def test_public_entry_points_convert_expected_hostile_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "payload"
    path.write_bytes(b"x")
    path.chmod(0o600)

    def eio(*args, **kwargs):
        raise OSError(errno.EIO, "hostile raw value")

    monkeypatch.setattr(collector_module, "_PREAD", eio)
    result = _collect_at(tmp_path, "payload", _file_request(path))
    failure = _assert_failure(
        result,
        CollectionDisposition.UNAVAILABLE,
        CollectionReasonCode.IO_ERROR,
    )
    assert "hostile raw value" not in repr(failure)


def test_collector_case_fixture_matches_closed_role_set() -> None:
    value = json.loads(
        (FIXTURE_DIR / "collector-cases.json").read_text(encoding="utf-8")
    )
    assert value["collector_schema"] == COLLECTOR_SCHEMA
    assert set(value["expected_artifacts"]) == {item.value for item in ArtifactName}
