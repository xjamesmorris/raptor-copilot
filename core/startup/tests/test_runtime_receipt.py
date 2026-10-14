"""Focused tests for the non-authorizing runtime-receipt slice."""

from __future__ import annotations

import ast
import copy
import dataclasses
from datetime import datetime
from pathlib import Path
from typing import Any, cast

import pytest

from core.json.utils import dumps_artifact, load_json
from core.startup.runtime_receipt import (
    DEFAULT_PROFILE_DIRECTORY,
    MAX_RECEIPT_BYTES,
    ArtifactName,
    ExpectedBinding,
    Frontend,
    Identifier,
    ProfileStore,
    ProfileStatus,
    ReasonCode,
    ReceiptRejection,
    StaticallyVerifiedReceipt,
    StaticProfile,
    TreeManifestRow,
    VerificationDisposition,
    build_tree_manifest,
    canonical_bytes,
    find_embedded_payload,
    load_profile_store,
    manifest_bytes,
    parse_receipt,
    receipt_sha256,
    serialize_receipt,
    Sha256,
    sha256_hex,
    to_json_value,
    token_commitment,
    verify_receipt_static,
)
from core.startup.runtime_receipt.canonical import CanonicalValueError

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "runtime_receipt"
CASES_PATH = FIXTURE_DIR / "cases.json"
BAD_HASH = "0" * 64


def _seed() -> dict[str, Any]:
    value = load_json(CASES_PATH)
    assert isinstance(value, dict)
    return cast(dict[str, Any], copy.deepcopy(value))


def _content(
    sha256: str,
    size_bytes: int,
    format_id: str,
    *,
    elf_build_id_sha1: str | None = None,
) -> dict[str, Any]:
    return {
        "sha256": sha256,
        "size_bytes": str(size_bytes),
        "format_id": format_id,
        "elf_build_id_sha1": elf_build_id_sha1,
    }


def _observation(
    path: str,
    content: dict[str, Any],
    *,
    inode: int,
    path_kind: str,
    mode: str = "0755",
) -> dict[str, Any]:
    return {
        "path": path,
        "path_kind": path_kind,
        "is_symlink": False,
        "device": "53",
        "inode": str(inode),
        "mode_octal": mode,
        "uid": "1000",
        "gid": "1000",
        "size_bytes": content["size_bytes"],
        "nlink": "1",
        "mtime_ns": "1789200000000000000",
        "ctime_ns": "1789200000000000001",
        "sha256": content["sha256"],
        "format_id": content["format_id"],
    }


def _artifact_index(document: dict[str, Any], name: str) -> int:
    artifacts = document["stable_identity"]["distribution"]["artifacts"]
    return next(
        index for index, artifact in enumerate(artifacts) if artifact["name"] == name
    )


def _observed_artifact_index(document: dict[str, Any], name: str) -> int:
    artifacts = document["launch_instance"]["artifacts"]
    return next(
        index for index, artifact in enumerate(artifacts) if artifact["name"] == name
    )


def _mapped_index(document: dict[str, Any], name: str) -> int:
    images = document["process_corroboration"]["mapped_native_images"]
    return next(
        index for index, image in enumerate(images) if image["module_name"] == name
    )


def _resign(document: dict[str, Any]) -> dict[str, Any]:
    document["stable_identity_sha256"] = sha256_hex(
        canonical_bytes(document["stable_identity"])
    )
    document["launch_instance_sha256"] = sha256_hex(
        canonical_bytes(document["launch_instance"])
    )
    document["launch_binding"]["stable_identity_sha256"] = document[
        "stable_identity_sha256"
    ]
    document["launch_binding"]["launch_instance_sha256"] = document[
        "launch_instance_sha256"
    ]
    document["launch_binding_sha256"] = sha256_hex(
        canonical_bytes(document["launch_binding"])
    )
    document["process_corroboration_sha256"] = sha256_hex(
        canonical_bytes(document["process_corroboration"])
    )
    document["receipt_sha256"] = receipt_sha256(
        document["stable_identity_sha256"],
        document["launch_instance_sha256"],
        document["launch_binding_sha256"],
        document["process_corroboration_sha256"],
    )
    return document


def _receipt_document() -> dict[str, Any]:
    seed = _seed()
    store = load_profile_store()
    assert not isinstance(store, ReceiptRejection)
    profile = store.profiles[0]
    identity = seed["identity"]
    paths = seed["paths"]

    launcher = _content(**identity["launcher"])
    frontend = _content(**identity["frontend"])
    interpreter = _content(**identity["interpreter"])
    package = _content(**identity["package"])
    artifacts = [
        {
            "name": name,
            "content": _content(digest, size, format_id),
        }
        for name, size, digest, format_id in seed["artifacts"]
    ]
    artifact_by_name = {artifact["name"]: artifact["content"] for artifact in artifacts}
    stable = {
        "selected_frontend": "copilot",
        "profile_id": profile.profile_id.value,
        "cli_version": "1.0.84-5",
        "platform": {
            "system": "linux",
            "architecture": "x86_64",
            "elf_class": "ELF64",
            "endianness": "little",
            "pointer_bits": 64,
            "libc_family": "glibc",
        },
        "launcher": launcher,
        "frontend_executable": frontend,
        "elf_interpreter": {
            "required": True,
            "requested_path": "/lib64/ld-linux-x86-64.so.2",
            "content": interpreter,
        },
        "distribution": {
            "source": "sealed_cache_snapshot",
            "version": "1.0.84-5",
            "platform_directory": "linux-x64",
            "content_manifest": {
                "algorithm": "sha256-tree-v1",
                "sha256": (
                    "13991c84e49bbf6da4cf095bf5f0c8d8c1fca95c7a732946dedf8e396a3fd400"
                ),
                "entry_count": 216,
                "total_regular_file_bytes": "161443579",
            },
            "package_manifest": {
                "content": package,
                "name": "@github/copilot",
                "version": "1.0.84-5",
                "package_type": "module",
                "bin_name": "copilot",
                "bin_target": "npm-loader.js",
            },
            "artifacts": artifacts,
            "embedded_sea_loader": {
                "matched": True,
                "match_count": 1,
                "offset": "108659166",
                "sha256": artifact_by_name["sea-loader.js"]["sha256"],
            },
        },
        "contract": {
            "profile_schema_version": 1,
            "profile_status": "static_candidate_not_authorized",
            "profile_sha256": profile.profile_sha256.value,
            "live_evidence_id": None,
            "live_evidence_sha256": None,
            "schemas": [
                {
                    "name": "session-events",
                    "sha256": artifact_by_name["schemas/session-events.schema.json"][
                        "sha256"
                    ],
                    "size_bytes": artifact_by_name[
                        "schemas/session-events.schema.json"
                    ]["size_bytes"],
                    "definition_count": 576,
                    "property_count": 688,
                    "event_type_literal_count": 180,
                    "event_variant_count": 144,
                    "definition_names_sha256": (
                        "21e92237ac86ce0a8e6a2e1554369b83a413f9a6006c03d4"
                        "0f0709a409758ffc"
                    ),
                    "property_names_sha256": (
                        "2669b652e311dc49b231c90f8b8f2f60acc3ea02b9993474"
                        "704b8c060be958bd"
                    ),
                    "event_type_literals_sha256": (
                        "ce0c305e035c8f56f108adcdad468edbb76b6ec8a76979a2"
                        "1aa180cf6c9e9e34"
                    ),
                },
                {
                    "name": "api",
                    "sha256": artifact_by_name["schemas/api.schema.json"]["sha256"],
                    "size_bytes": artifact_by_name["schemas/api.schema.json"][
                        "size_bytes"
                    ],
                    "definition_count": 1293,
                    "property_count": 1286,
                    "event_type_literal_count": 43,
                    "event_variant_count": None,
                    "definition_names_sha256": (
                        "374f18544d37959a909d1852524008b95b656b1db7f53890"
                        "abc606cee8120077"
                    ),
                    "property_names_sha256": (
                        "ccc3efcdf5a8108571e690e4420884972bee676aa031a2409"
                        "c53dc861bce37dd"
                    ),
                    "event_type_literals_sha256": (
                        "fd1630cf95823260086673b5a017f05b4d40a675530b63ea"
                        "5712aad0231973c0"
                    ),
                },
            ],
            "cli_grammar": {
                "source": "completion_bash",
                "sha256": (
                    "98a0941afe15b03d3ed6397f1c30c77597fee46045902871710a6e6f47142b10"
                ),
                "root_flag_count": 107,
                "advertised_root_flag_count": 78,
                "hidden_root_flag_count": 29,
            },
            "help_contract": {
                "manifest_algorithm": "canonical-map-of-surface-sha256-v1",
                "manifest_sha256": (
                    "a91b6df6cd711d1dfd03be95ad02738799df21ffe05417a8981be30408d5f375"
                ),
                "surface_count": 41,
            },
            "required_semantics": [
                "permission.carriedForward",
                "permission.messageAuthorization",
                "permission.messageAuthorizationDegraded",
                "permission.messageAuthorizationRead",
                "permission.completed.data.decisionSource",
                "tool.execution_start.data.mcpTransport",
                "session.start.resume_semantics",
            ],
        },
    }

    launcher_observation = _observation(
        paths["launcher"],
        launcher,
        inode=1001,
        path_kind="direct_regular",
    )
    frontend_observation = _observation(
        paths["frontend"],
        frontend,
        inode=1002,
        path_kind="direct_regular",
    )
    interpreter_observation = _observation(
        paths["interpreter"],
        interpreter,
        inode=1003,
        path_kind="resolved_interpreter",
    )
    package_observation = _observation(
        f"{paths['sealed_directory']}/package.json",
        package,
        inode=1100,
        path_kind="sealed_regular",
        mode="0644",
    )
    artifact_observations = []
    for index, artifact in enumerate(artifacts, start=1):
        mode = (
            "0755"
            if artifact["content"]["format_id"]
            in {
                "elf64-x86_64-dyn",
                "javascript-utf8",
            }
            else "0644"
        )
        artifact_observations.append(
            {
                "name": artifact["name"],
                "file": _observation(
                    f"{paths['sealed_directory']}/{artifact['name']}",
                    artifact["content"],
                    inode=1200 + index,
                    path_kind="sealed_regular",
                    mode=mode,
                ),
            }
        )
    instance = {
        "session_id": seed["session_id"],
        "launch_id": seed["launch_id"],
        "issuer": {
            "repository_head": "7eb559ab941fa24a759bdf4c059c081153f0a41f",
            "receipt_implementation_id": ("raptor-copilot-runtime-receipt-v1"),
            "launcher_file": launcher_observation,
        },
        "frontend_executable": frontend_observation,
        "elf_interpreter": interpreter_observation,
        "source_directory": paths["source_directory"],
        "sealed_directory": paths["sealed_directory"],
        "package_manifest_file": package_observation,
        "artifacts": artifact_observations,
        "selection": {
            "ambient_copilot_cli_dist_dir_present": False,
            "ambient_copilot_pkg_cache_home_present": False,
            "ambient_copilot_cache_home_present": False,
            "ambient_xdg_cache_home_present": False,
            "ambient_copilot_auto_update_present": False,
            "all_ambient_selectors_stripped": True,
            "launcher_set_dist_dir_from_receipt": True,
            "launcher_disabled_auto_update": True,
            "user_prefer_version_rejected": True,
        },
        "version_observation": {
            "reported_version": "1.0.84-5",
            "version_stdout_sha256": sha256_hex(b"GitHub Copilot CLI 1.0.84-5.\n"),
            "version_exit_code": 0,
            "binary_version_stdout_sha256": sha256_hex(
                b"Copilot binary version: 1.0.84-5\n"
            ),
            "binary_version_exit_code": 0,
            "stderr_empty": True,
            "network_disabled": True,
            "stdin_dev_null": True,
            "auto_update_disabled": True,
        },
    }

    document: dict[str, Any] = {
        "schema": "raptor.runtime_receipt/v1",
        "schema_version": 1,
        "stable_identity": stable,
        "stable_identity_sha256": BAD_HASH,
        "launch_instance": instance,
        "launch_instance_sha256": BAD_HASH,
        "launch_binding": {
            "session_id": seed["session_id"],
            "launch_id": seed["launch_id"],
            "session_pid": "4242",
            "session_starttime_ticks": "9001",
            "boot_id": seed["boot_id"],
            "pid_namespace_inode": "4026531836",
            "launcher_euid": "1000",
            "session_token_commitment_sha256": token_commitment(seed["token_hex"]),
            "receipt_nonce": "0123456789abcdef0123456789abcdef",
            "issued_at_utc": seed["issued_at_utc"],
            "freshness_not_after_utc": seed["freshness_not_after_utc"],
            "stable_identity_sha256": BAD_HASH,
            "launch_instance_sha256": BAD_HASH,
        },
        "launch_binding_sha256": BAD_HASH,
        "process_corroboration": {
            "state": "verified",
            "verification_policy_id": "linux-procfs-mapped-v1",
            "attempt": 1,
            "observed_at_utc": seed["observed_at_utc"],
            "pid": "4242",
            "starttime_before": "9001",
            "starttime_after": "9001",
            "process_uid": "1000",
            "comm_observed": "MainThread",
            "comm_authoritative": False,
            "mapped_executable": {
                "evidence_strength": "strong",
                "source": "proc_pid_exe",
                "mapped_file": {
                    **frontend_observation,
                    "path_kind": "proc_exe_descriptor",
                },
                "current_disk_file": frontend_observation,
            },
            "mapped_native_images": [],
            "mismatch_observations": [],
        },
        "process_corroboration_sha256": BAD_HASH,
        "receipt_sha256": BAD_HASH,
        "decision": {"state": "verified", "reason_codes": []},
    }
    for name in (
        "prebuilds/linux-x64/runtime.node",
        "prebuilds/linux-x64/cli-native.node",
    ):
        observed = artifact_observations[_observed_artifact_index(document, name)][
            "file"
        ]
        document["process_corroboration"]["mapped_native_images"].append(
            {
                "module_name": name,
                "observed_path": observed["path"],
                "pathname_source": "proc_maps",
                "mapped_inode": observed["inode"],
                "inode_source": "proc_maps",
                "maps_device": "0:52",
                "maps_device_source": "proc_maps",
                "mount_device": "0:52",
                "mount_device_source": "proc_self_mountinfo",
                "sealed_path_recheck_sha256": observed["sha256"],
                "sealed_path_recheck_source": "sealed_path_reopen",
                "evidence_strength": "corroborated",
                "executable_mapping": True,
                "deleted": False,
            }
        )
    return _resign(document)


def _parse_document(document: dict[str, Any]):
    return parse_receipt(canonical_bytes(document))


def _expected(
    *,
    session_id: str | None = None,
    launch_id: str | None = None,
    pid: int = 4242,
    token_hex: str | None = None,
) -> ExpectedBinding:
    seed = _seed()
    return ExpectedBinding(
        session_id=session_id or seed["session_id"],
        launch_id=launch_id or seed["launch_id"],
        session_pid=pid,
        session_starttime_ticks=9001,
        boot_id=seed["boot_id"],
        pid_namespace_inode=4026531836,
        launcher_euid=1000,
        token_hex=token_hex or seed["token_hex"],
    )


def _verification_now() -> datetime:
    value = _seed()["verification_now_utc"]
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _verify(document: dict[str, Any], *, now: str | None = None):
    parsed = _parse_document(document)
    assert not isinstance(parsed, ReceiptRejection)
    store = load_profile_store()
    assert not isinstance(store, ReceiptRejection)
    return verify_receipt_static(
        parsed,
        profiles=store,
        expected=_expected(),
        now=(
            datetime.fromisoformat(now.replace("Z", "+00:00"))
            if now is not None
            else _verification_now()
        ),
    )


def _mutate_artifact_hash(
    document: dict[str, Any],
    name: str,
    digest: str = BAD_HASH,
) -> None:
    stable_index = _artifact_index(document, name)
    observed_index = _observed_artifact_index(document, name)
    document["stable_identity"]["distribution"]["artifacts"][stable_index]["content"][
        "sha256"
    ] = digest
    document["launch_instance"]["artifacts"][observed_index]["file"]["sha256"] = digest
    if name in {
        "prebuilds/linux-x64/runtime.node",
        "prebuilds/linux-x64/cli-native.node",
    }:
        mapped_index = _mapped_index(document, name)
        document["process_corroboration"]["mapped_native_images"][mapped_index][
            "sealed_path_recheck_sha256"
        ] = digest


def test_fixture_inventory_names_every_required_case() -> None:
    seed = _seed()
    required = {
        "valid_static_candidate",
        "stale_receipt",
        "missing_artifact",
        "loader_mismatch",
        "distribution_mismatch",
        "runtime_node_mismatch",
        "cli_native_node_mismatch",
        "schema_drift",
        "grammar_drift",
        "copied_session_binding",
        "copied_launch_binding",
        "mapped_vs_disk_disagreement",
        "unsupported_evidence",
        "unsupported_profile",
        "unsupported_version",
        "unsupported_platform",
        "unknown_field",
        "duplicate_key",
        "deep_json",
        "oversize_json",
        "symlink_field",
        "relative_path",
        "control_character_path",
        "mutation_isolation",
    }
    assert set(seed["deterministic_cases"]) == required


def test_shipped_profile_is_single_static_candidate_and_reproducible() -> None:
    store = load_profile_store()
    assert not isinstance(store, ReceiptRejection)
    assert len(store.profiles) == 1
    profile = store.profiles[0]
    assert profile.status is ProfileStatus.STATIC_CANDIDATE_NOT_AUTHORIZED
    assert profile.profile_sha256.value == (
        "43bdfd1726e846d7903005c84a06f66672239c92a13fdbfd56b22c71f78c84f0"
    )
    assert (
        sha256_hex(canonical_bytes(to_json_value(profile.profile_digest_basis)))
        == profile.profile_sha256.value
    )
    artifact_names = {artifact.name for artifact in profile.lookup_key.artifacts}
    assert ArtifactName.RUNTIME_NODE in artifact_names
    assert ArtifactName.CLI_NATIVE_NODE in artifact_names


def test_profile_store_ambiguity_revocation_and_digest_tamper(
    tmp_path: Path,
) -> None:
    store = load_profile_store()
    assert not isinstance(store, ReceiptRejection)
    profile = store.profiles[0]
    parsed = _parse_document(_receipt_document())
    assert not isinstance(parsed, ReceiptRejection)

    ambiguous = verify_receipt_static(
        parsed,
        profiles=ProfileStore((profile, profile)),
        expected=_expected(),
        now=_verification_now(),
    )
    assert isinstance(ambiguous, ReceiptRejection)
    assert ambiguous.reason_codes == (ReasonCode.PROFILE_AMBIGUOUS,)

    revoked_basis = dataclasses.replace(
        profile.profile_digest_basis,
        status=ProfileStatus.REVOKED,
    )
    revoked = StaticProfile(
        schema=profile.schema,
        schema_version=profile.schema_version,
        profile_digest_basis=revoked_basis,
        profile_sha256=Sha256(
            sha256_hex(canonical_bytes(to_json_value(revoked_basis)))
        ),
    )
    document = _receipt_document()
    document["stable_identity"]["contract"]["profile_status"] = "revoked"
    document["stable_identity"]["contract"]["profile_sha256"] = (
        revoked.profile_sha256.value
    )
    _resign(document)
    parsed = _parse_document(document)
    assert not isinstance(parsed, ReceiptRejection)
    rejected = verify_receipt_static(
        parsed,
        profiles=ProfileStore((revoked,)),
        expected=_expected(),
        now=_verification_now(),
    )
    assert isinstance(rejected, ReceiptRejection)
    assert rejected.reason_codes == (ReasonCode.PROFILE_REVOKED,)

    tampered_dir = tmp_path / "profiles"
    tampered_dir.mkdir()
    profile_json = cast(
        dict[str, Any],
        copy.deepcopy(
            load_json(
                DEFAULT_PROFILE_DIRECTORY
                / "copilot-cli-1.0.84-5-linux-x86_64-static-candidate-v1.json"
            )
        ),
    )
    profile_json["profile_sha256"] = BAD_HASH
    (tampered_dir / "profile.json").write_text(
        dumps_artifact(profile_json),
        encoding="utf-8",
    )
    tampered = load_profile_store(tampered_dir)
    assert isinstance(tampered, ReceiptRejection)
    assert tampered.reason_codes == (ReasonCode.PROFILE_DIGEST_MISMATCH,)


def test_valid_static_candidate_is_exact_but_never_authorizing() -> None:
    seed = _seed()
    raw = canonical_bytes(_receipt_document())
    assert len(raw) < MAX_RECEIPT_BYTES
    result = _verify(
        _receipt_document(),
        now=seed["verification_now_utc"],
    )
    assert isinstance(result, StaticallyVerifiedReceipt)
    assert result.disposition is VerificationDisposition.EXACT_MATCH
    assert result.reason_codes == (
        ReasonCode.PROFILE_UNSUPPORTED,
        ReasonCode.LIVE_CONTRACT_MISSING,
    )
    assert result.authoritative is False
    assert not hasattr(result, "effects_enabled")
    assert not hasattr(result, "live_verified")
    assert not hasattr(result, "owner")
    assert not hasattr(result, "provider")
    assert not hasattr(result, "host_registration")
    assert serialize_receipt(result.receipt) == canonical_bytes(
        to_json_value(result.receipt)
    )


def test_parse_receipt_is_inspection_only() -> None:
    parsed = parse_receipt(canonical_bytes(_receipt_document()))
    assert not isinstance(parsed, ReceiptRejection)
    assert not isinstance(parsed, StaticallyVerifiedReceipt)
    assert not hasattr(parsed, "disposition")
    assert not hasattr(parsed, "authoritative")


def test_missing_expected_binding_is_a_typed_rejection() -> None:
    parsed = _parse_document(_receipt_document())
    assert not isinstance(parsed, ReceiptRejection)
    store = load_profile_store()
    assert not isinstance(store, ReceiptRejection)

    omitted = verify_receipt_static(
        parsed,
        profiles=store,
        now=_verification_now(),
    )
    explicit_none = verify_receipt_static(
        parsed,
        profiles=store,
        expected=None,
        now=_verification_now(),
    )
    for result in (omitted, explicit_none):
        assert isinstance(result, ReceiptRejection)
        assert (
            result.disposition is VerificationDisposition.VERIFICATION_CONTEXT_MISSING
        )
        assert result.reason_codes == (ReasonCode.EXPECTED_BINDING_MISSING,)


def test_missing_freshness_evaluation_is_a_typed_rejection() -> None:
    parsed = _parse_document(_receipt_document())
    assert not isinstance(parsed, ReceiptRejection)
    store = load_profile_store()
    assert not isinstance(store, ReceiptRejection)

    omitted = verify_receipt_static(
        parsed,
        profiles=store,
        expected=_expected(),
    )
    explicit_none = verify_receipt_static(
        parsed,
        profiles=store,
        expected=_expected(),
        now=None,
    )
    for result in (omitted, explicit_none):
        assert isinstance(result, ReceiptRejection)
        assert (
            result.disposition is VerificationDisposition.VERIFICATION_CONTEXT_MISSING
        )
        assert result.reason_codes == (ReasonCode.FRESHNESS_EVALUATION_MISSING,)


def test_missing_verification_context_reasons_are_canonical() -> None:
    parsed_receipt = _parse_document(_receipt_document())
    assert not isinstance(parsed_receipt, ReceiptRejection)
    store = load_profile_store()
    assert not isinstance(store, ReceiptRejection)
    missing_both = verify_receipt_static(
        parsed_receipt,
        profiles=store,
    )
    assert isinstance(missing_both, ReceiptRejection)
    assert missing_both.reason_codes == (
        ReasonCode.EXPECTED_BINDING_MISSING,
        ReasonCode.FRESHNESS_EVALUATION_MISSING,
    )

    document = _receipt_document()
    document["decision"] = {
        "state": "rejected",
        "reason_codes": [code.value for code in missing_both.reason_codes],
    }
    document["process_corroboration"]["state"] = "rejected"
    _resign(document)
    parsed = _parse_document(document)
    assert not isinstance(parsed, ReceiptRejection)
    assert parsed.decision.reason_codes == missing_both.reason_codes


def test_no_receipt_field_can_claim_effects_or_registration() -> None:
    forbidden = (
        "effects_enabled",
        "live_verified",
        "ownership",
        "provider_selection",
        "host_registration",
    )
    for field_name in forbidden:
        document = _receipt_document()
        document[field_name] = True
        result = parse_receipt(dumps_artifact(document, indent=None).encode())
        assert isinstance(result, ReceiptRejection)
        assert ReasonCode.RECEIPT_SCHEMA_UNSUPPORTED in result.reason_codes


def test_verified_runtime_receipt_type_is_intentionally_absent() -> None:
    import core.startup.runtime_receipt as runtime_receipt

    assert not hasattr(runtime_receipt, "VerifiedRuntimeReceipt")


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (1.5, "floating-point"),
        (float("nan"), "floating-point"),
        (Path("/tmp/value"), "unsupported"),
        (Frontend.COPILOT, "enum objects"),
        ({1: "value"}, "keys must be strings"),
        ({"text": "bad\nvalue"}, "control character"),
    ],
)
def test_canonical_bytes_rejects_non_schema_values(
    value: object,
    message: str,
) -> None:
    with pytest.raises(CanonicalValueError, match=message):
        canonical_bytes(cast(Any, value))


def test_canonical_bytes_are_sorted_ascii_and_pinned() -> None:
    value = {"z": 1, "é": "café", "a": [True, None]}
    expected = b'{"a":[true,null],"z":1,"\\u00e9":"caf\\u00e9"}'
    assert canonical_bytes(value) == expected
    assert sha256_hex(expected) == (
        "27b74dba99621274c9996dbbf7fb271a39786cfdd8f89d8fb683efaa69157d4e"
    )


def test_canonical_depth_and_member_limits() -> None:
    deep: Any = 0
    for _ in range(13):
        deep = [deep]
    with pytest.raises(CanonicalValueError, match="depth"):
        canonical_bytes(deep)
    with pytest.raises(CanonicalValueError, match="member"):
        canonical_bytes({f"k{index}": index for index in range(65)})


def test_receipt_digest_domain_vector() -> None:
    digest = receipt_sha256("0" * 64, "1" * 64, "2" * 64, "3" * 64)
    assert digest == (
        "228b74c125de93dcb154e83db8321697817179b7b3e4d7e04362cb19ed8deddc"
    )
    assert token_commitment("00112233445566778899aabbccddeeff") == (
        "68b40b455ccc0cabe4ac105dc32aa9da97d12355c90ef2959e265f32dd9af328"
    )


def test_parse_missing_oversize_duplicate_and_deep_json() -> None:
    seed = _seed()
    missing = parse_receipt(None)
    assert isinstance(missing, ReceiptRejection)
    assert missing.disposition is VerificationDisposition.MISSING

    oversize = (
        b'{"padding":"' + (b"x" * seed["raw_cases"]["oversize_padding_bytes"]) + b'"}'
    )
    result = parse_receipt(oversize)
    assert isinstance(result, ReceiptRejection)
    assert result.reason_codes == (ReasonCode.RECEIPT_OVERSIZED,)

    duplicate = parse_receipt(seed["raw_cases"]["duplicate_key"].encode())
    assert isinstance(duplicate, ReceiptRejection)
    assert duplicate.reason_codes == (ReasonCode.RECEIPT_DUPLICATE_KEY,)

    deep = parse_receipt(seed["raw_cases"]["deep_json"].encode())
    assert isinstance(deep, ReceiptRejection)
    assert deep.reason_codes == (ReasonCode.RECEIPT_DEPTH_EXCEEDED,)


def test_nested_duplicate_key_is_rejected() -> None:
    raw = b'{"outer":{"key":1,"key":2}}'
    result = parse_receipt(raw)
    assert isinstance(result, ReceiptRejection)
    assert result.reason_codes == (ReasonCode.RECEIPT_DUPLICATE_KEY,)


@pytest.mark.parametrize(
    "path",
    [
        (),
        ("stable_identity",),
        ("stable_identity", "platform"),
        ("stable_identity", "launcher"),
        ("stable_identity", "distribution"),
        ("stable_identity", "distribution", "content_manifest"),
        ("stable_identity", "distribution", "artifacts", 0),
        ("stable_identity", "contract"),
        ("stable_identity", "contract", "schemas", 0),
        ("launch_instance",),
        ("launch_instance", "issuer"),
        ("launch_instance", "frontend_executable"),
        ("launch_binding",),
        ("process_corroboration",),
        ("process_corroboration", "mapped_executable"),
        ("process_corroboration", "mapped_native_images", 0),
        ("decision",),
    ],
)
def test_unknown_fields_are_rejected_in_every_closed_object(
    path: tuple[object, ...],
) -> None:
    document = _receipt_document()
    target: Any = document
    for component in path:
        target = target[component]
    target["unexpected_field"] = "denied"
    result = parse_receipt(dumps_artifact(document, indent=None).encode())
    assert isinstance(result, ReceiptRejection)
    assert result.reason_codes == (ReasonCode.RECEIPT_SCHEMA_UNSUPPORTED,)


@pytest.mark.parametrize(
    "path",
    [
        ("receipt_sha256",),
        ("stable_identity", "profile_id"),
        ("stable_identity", "platform", "system"),
        ("stable_identity", "distribution", "content_manifest"),
        ("launch_instance", "session_id"),
        ("launch_binding", "session_pid"),
        ("process_corroboration", "state"),
        ("decision", "state"),
    ],
)
def test_missing_required_fields_are_partial(
    path: tuple[object, ...],
) -> None:
    document = _receipt_document()
    target: Any = document
    for component in path[:-1]:
        target = target[component]
    del target[path[-1]]
    result = parse_receipt(dumps_artifact(document, indent=None).encode())
    assert isinstance(result, ReceiptRejection)
    assert result.disposition is VerificationDisposition.PARTIAL
    assert result.reason_codes == (ReasonCode.RECEIPT_PARTIAL,)


def test_digest_tamper_in_every_section_is_rejected() -> None:
    paths = [
        ("stable_identity", "cli_version"),
        ("launch_instance", "session_id"),
        ("launch_binding", "session_pid"),
        ("process_corroboration", "comm_observed"),
    ]
    replacements = [
        "1.0.84-6",
        "99999999-8888-4777-8666-555555555555",
        "4243",
        "not-authoritative",
    ]
    for path, replacement in zip(paths, replacements):
        document = _receipt_document()
        target: Any = document
        for component in path[:-1]:
            target = target[component]
        target[path[-1]] = replacement
        parsed = _parse_document(document)
        assert isinstance(parsed, ReceiptRejection)
        assert parsed.disposition is VerificationDisposition.DIGEST_MISMATCH


def test_stable_identity_is_independent_of_launch_instance() -> None:
    first = _receipt_document()
    second = copy.deepcopy(first)
    second["launch_instance"]["session_id"] = _seed()["other_session_id"]
    second["launch_instance"]["launch_id"] = _seed()["other_launch_id"]
    second["launch_instance"]["sealed_directory"] = "/var/lib/raptor/session/other/dist"
    for index, artifact in enumerate(
        second["launch_instance"]["artifacts"],
        start=1,
    ):
        artifact["file"]["path"] = (
            second["launch_instance"]["sealed_directory"] + "/" + artifact["name"]
        )
        artifact["file"]["inode"] = str(9000 + index)
    second["launch_instance"]["package_manifest_file"]["path"] = (
        second["launch_instance"]["sealed_directory"] + "/package.json"
    )
    second["launch_binding"]["session_id"] = _seed()["other_session_id"]
    second["launch_binding"]["launch_id"] = _seed()["other_launch_id"]
    for image in second["process_corroboration"]["mapped_native_images"]:
        observed = second["launch_instance"]["artifacts"][
            _observed_artifact_index(second, image["module_name"])
        ]["file"]
        image["observed_path"] = observed["path"]
        image["mapped_inode"] = observed["inode"]
    _resign(second)
    assert first["stable_identity_sha256"] == second["stable_identity_sha256"]
    assert first["launch_instance_sha256"] != second["launch_instance_sha256"]


def test_stable_artifact_change_changes_only_stable_content_identity() -> None:
    first = _receipt_document()
    second = copy.deepcopy(first)
    _mutate_artifact_hash(second, "app.js")
    _resign(second)
    assert first["stable_identity_sha256"] != second["stable_identity_sha256"]


@pytest.mark.parametrize(
    ("mutation", "disposition", "reason"),
    [
        (
            "missing_artifact",
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.ARTIFACT_MISSING,
        ),
        (
            "loader_mismatch",
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.ARTIFACT_IDENTITY_MISMATCH,
        ),
        (
            "distribution_mismatch",
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.ARTIFACT_IDENTITY_MISMATCH,
        ),
        (
            "runtime_node_mismatch",
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.RUNTIME_IMAGE_MISMATCH,
        ),
        (
            "cli_native_node_mismatch",
            VerificationDisposition.ARTIFACT_MISMATCH,
            ReasonCode.CLI_NATIVE_IMAGE_MISMATCH,
        ),
        (
            "schema_drift",
            VerificationDisposition.SCHEMA_MISMATCH,
            ReasonCode.SCHEMA_HASH_MISMATCH,
        ),
        (
            "grammar_drift",
            VerificationDisposition.GRAMMAR_MISMATCH,
            ReasonCode.GRAMMAR_DIGEST_MISMATCH,
        ),
    ],
)
def test_profile_and_artifact_mismatch_classes(
    mutation: str,
    disposition: VerificationDisposition,
    reason: ReasonCode,
) -> None:
    document = _receipt_document()
    if mutation == "missing_artifact":
        name = "app.js"
        del document["stable_identity"]["distribution"]["artifacts"][
            _artifact_index(document, name)
        ]
        del document["launch_instance"]["artifacts"][
            _observed_artifact_index(document, name)
        ]
    elif mutation == "loader_mismatch":
        document["stable_identity"]["frontend_executable"]["sha256"] = BAD_HASH
        document["launch_instance"]["frontend_executable"]["sha256"] = BAD_HASH
        mapped = document["process_corroboration"]["mapped_executable"]
        mapped["mapped_file"]["sha256"] = BAD_HASH
        mapped["current_disk_file"]["sha256"] = BAD_HASH
    elif mutation == "distribution_mismatch":
        document["stable_identity"]["distribution"]["content_manifest"]["sha256"] = (
            BAD_HASH
        )
    elif mutation == "runtime_node_mismatch":
        _mutate_artifact_hash(
            document,
            "prebuilds/linux-x64/runtime.node",
        )
    elif mutation == "cli_native_node_mismatch":
        _mutate_artifact_hash(
            document,
            "prebuilds/linux-x64/cli-native.node",
        )
    elif mutation == "schema_drift":
        name = "schemas/session-events.schema.json"
        _mutate_artifact_hash(document, name)
        document["stable_identity"]["contract"]["schemas"][0]["sha256"] = BAD_HASH
    else:
        document["stable_identity"]["contract"]["cli_grammar"]["sha256"] = BAD_HASH
    _resign(document)
    result = _verify(document)
    assert isinstance(result, ReceiptRejection)
    assert result.disposition is disposition
    assert reason in result.reason_codes


def test_stale_receipt_has_a_dedicated_disposition() -> None:
    seed = _seed()
    result = _verify(_receipt_document(), now=seed["stale_now_utc"])
    assert isinstance(result, ReceiptRejection)
    assert result.disposition is VerificationDisposition.STALE
    assert result.reason_codes == (ReasonCode.RECEIPT_TIMESTAMP_STALE,)


def test_no_fixed_first_descendant_deadline_is_inferred() -> None:
    document = _receipt_document()
    document["launch_binding"]["issued_at_utc"] = "2026-09-01T00:00:00Z"
    document["launch_binding"]["freshness_not_after_utc"] = None
    document["process_corroboration"]["observed_at_utc"] = "2026-09-12T08:00:03Z"
    _resign(document)
    result = _verify(document, now="2026-09-12T08:30:00Z")
    assert isinstance(result, StaticallyVerifiedReceipt)


def test_unsupported_version_profile_and_platform_are_distinct() -> None:
    version = _receipt_document()
    version["schema_version"] = 2
    result = _parse_document(version)
    assert isinstance(result, ReceiptRejection)
    assert result.disposition is VerificationDisposition.VERSION_MISMATCH
    assert result.reason_codes == (ReasonCode.RECEIPT_VERSION_UNSUPPORTED,)

    runtime_version = _receipt_document()
    runtime_version["stable_identity"]["cli_version"] = "1.0.84-6"
    runtime_version["stable_identity"]["distribution"]["version"] = "1.0.84-6"
    runtime_version["stable_identity"]["distribution"]["package_manifest"][
        "version"
    ] = "1.0.84-6"
    runtime_version["launch_instance"]["version_observation"]["reported_version"] = (
        "1.0.84-6"
    )
    _resign(runtime_version)
    result = _verify(runtime_version)
    assert isinstance(result, ReceiptRejection)
    assert result.disposition is VerificationDisposition.VERSION_MISMATCH
    assert result.reason_codes == (ReasonCode.DISTRIBUTION_VERSION_MISMATCH,)

    profile = _receipt_document()
    profile["stable_identity"]["profile_id"] = "unreviewed-profile"
    _resign(profile)
    result = _verify(profile)
    assert isinstance(result, ReceiptRejection)
    assert result.disposition is VerificationDisposition.PROFILE_MISMATCH
    assert result.reason_codes == (ReasonCode.PROFILE_UNSUPPORTED,)

    platform = _receipt_document()
    platform["stable_identity"]["platform"]["system"] = "darwin"
    platform["stable_identity"]["platform"]["architecture"] = "aarch64"
    platform["stable_identity"]["platform"]["elf_class"] = "not_applicable"
    platform["stable_identity"]["platform"]["libc_family"] = "not_applicable"
    _resign(platform)
    result = _verify(platform)
    assert isinstance(result, ReceiptRejection)
    assert result.disposition is VerificationDisposition.PLATFORM_MISMATCH
    assert ReasonCode.PLATFORM_UNSUPPORTED in result.reason_codes


def test_session_and_launch_copy_are_replay_dispositions() -> None:
    seed = _seed()
    document = _receipt_document()
    parsed = _parse_document(document)
    assert not isinstance(parsed, ReceiptRejection)
    store = load_profile_store()
    assert not isinstance(store, ReceiptRejection)

    copied_session = verify_receipt_static(
        parsed,
        profiles=store,
        expected=_expected(session_id=seed["other_session_id"]),
        now=_verification_now(),
    )
    assert isinstance(copied_session, ReceiptRejection)
    assert copied_session.disposition is (
        VerificationDisposition.COPIED_OR_REPLAYED_LAUNCH_INSTANCE
    )

    copied_launch = verify_receipt_static(
        parsed,
        profiles=store,
        expected=_expected(launch_id=seed["other_launch_id"]),
        now=_verification_now(),
    )
    assert isinstance(copied_launch, ReceiptRejection)
    assert copied_launch.reason_codes == (ReasonCode.RECEIPT_LAUNCH_INSTANCE_REPLAYED,)


def test_process_identity_and_token_mismatch_are_session_binding_failures() -> None:
    parsed = _parse_document(_receipt_document())
    assert not isinstance(parsed, ReceiptRejection)
    store = load_profile_store()
    assert not isinstance(store, ReceiptRejection)
    wrong_pid = verify_receipt_static(
        parsed,
        profiles=store,
        expected=_expected(pid=4243),
        now=_verification_now(),
    )
    assert isinstance(wrong_pid, ReceiptRejection)
    assert wrong_pid.disposition is VerificationDisposition.SESSION_BINDING_MISMATCH

    wrong_token = verify_receipt_static(
        parsed,
        profiles=store,
        expected=_expected(token_hex="f" * 32),
        now=_verification_now(),
    )
    assert isinstance(wrong_token, ReceiptRejection)
    assert wrong_token.reason_codes == (ReasonCode.RECEIPT_TOKEN_COMMITMENT_MISMATCH,)


def test_mapped_vs_disk_disagreement_is_not_hidden_by_comm_or_basename() -> None:
    document = _receipt_document()
    document["process_corroboration"]["comm_observed"] = "copilot"
    document["process_corroboration"]["mapped_executable"]["current_disk_file"][
        "inode"
    ] = "7777"
    _resign(document)
    result = _verify(document)
    assert isinstance(result, ReceiptRejection)
    assert result.disposition is VerificationDisposition.MAPPED_IMAGE_MISMATCH
    assert result.reason_codes == (ReasonCode.MAPPED_DISK_DIVERGENCE,)


def test_btrfs_device_sources_are_distinct_and_stat_device_is_not_compared() -> None:
    document = _receipt_document()
    for image in document["process_corroboration"]["mapped_native_images"]:
        image["maps_device"] = "0:52"
        image["mount_device"] = "0:52"
    for artifact in document["launch_instance"]["artifacts"]:
        artifact["file"]["device"] = "53"
    _resign(document)
    assert isinstance(_verify(document), StaticallyVerifiedReceipt)


def test_weak_or_incomplete_mapped_evidence_never_matches() -> None:
    document = _receipt_document()
    document["process_corroboration"]["mapped_native_images"][0][
        "evidence_strength"
    ] = "weak"
    _resign(document)
    result = _verify(document)
    assert isinstance(result, ReceiptRejection)
    assert result.disposition is VerificationDisposition.UNSUPPORTED_EVIDENCE
    assert result.reason_codes == (ReasonCode.MAPPED_EVIDENCE_UNSUPPORTED,)

    device = _receipt_document()
    device["process_corroboration"]["mapped_native_images"][0]["mount_device"] = "0:53"
    _resign(device)
    result = _verify(device)
    assert isinstance(result, ReceiptRejection)
    assert result.reason_codes == (ReasonCode.MAPPED_DEVICE_UNVERIFIABLE,)


def test_runtime_and_cli_native_mappings_are_both_required() -> None:
    for module in (
        "prebuilds/linux-x64/runtime.node",
        "prebuilds/linux-x64/cli-native.node",
    ):
        document = _receipt_document()
        del document["process_corroboration"]["mapped_native_images"][
            _mapped_index(document, module)
        ]
        _resign(document)
        result = _verify(document)
        assert isinstance(result, ReceiptRejection)
        assert result.disposition is VerificationDisposition.MAPPED_IMAGE_MISMATCH
        assert result.reason_codes == (ReasonCode.MAPPED_RUNTIME_IMAGE_UNAVAILABLE,)


def test_decision_and_claimed_profile_status_are_deny_only() -> None:
    rejected = _receipt_document()
    rejected["decision"] = {
        "state": "rejected",
        "reason_codes": ["profile_unsupported"],
    }
    rejected["process_corroboration"]["state"] = "rejected"
    _resign(rejected)
    result = _verify(rejected)
    assert isinstance(result, ReceiptRejection)
    assert result.reason_codes == (ReasonCode.RECEIPT_STATE_NOT_VERIFIED,)

    claimed_live = _receipt_document()
    claimed_live["stable_identity"]["contract"]["profile_status"] = "live_verified"
    claimed_live["stable_identity"]["contract"]["live_evidence_id"] = "self-asserted"
    claimed_live["stable_identity"]["contract"]["live_evidence_sha256"] = "1" * 64
    _resign(claimed_live)
    result = _verify(claimed_live)
    assert isinstance(result, ReceiptRejection)
    assert result.reason_codes == (ReasonCode.PROFILE_DIGEST_MISMATCH,)


def test_even_a_matching_live_profile_cannot_authorize_this_slice() -> None:
    store = load_profile_store()
    assert not isinstance(store, ReceiptRejection)
    original = store.profiles[0]
    live_basis = dataclasses.replace(
        original.profile_digest_basis,
        status=ProfileStatus.LIVE_VERIFIED,
        live_evidence_id=Identifier("fixture-evidence"),
        live_evidence_sha256=Sha256("1" * 64),
    )
    live_profile = StaticProfile(
        schema=original.schema,
        schema_version=original.schema_version,
        profile_digest_basis=live_basis,
        profile_sha256=Sha256(sha256_hex(canonical_bytes(to_json_value(live_basis)))),
    )
    document = _receipt_document()
    contract = document["stable_identity"]["contract"]
    contract["profile_status"] = "live_verified"
    contract["profile_sha256"] = live_profile.profile_sha256.value
    contract["live_evidence_id"] = "fixture-evidence"
    contract["live_evidence_sha256"] = "1" * 64
    _resign(document)
    parsed = _parse_document(document)
    assert not isinstance(parsed, ReceiptRejection)
    result = verify_receipt_static(
        parsed,
        profiles=ProfileStore((live_profile,)),
        expected=_expected(),
        now=_verification_now(),
    )
    assert isinstance(result, ReceiptRejection)
    assert result.reason_codes == (
        ReasonCode.PROFILE_UNSUPPORTED,
        ReasonCode.LIVE_CONTRACT_MISSING,
    )


def test_illegal_persisted_state_combinations_are_malformed() -> None:
    combinations = [
        ("pending", "verified", []),
        ("verified", "pending", []),
        ("verified", "verified", ["profile_unsupported"]),
        ("rejected", "rejected", []),
    ]
    for decision_state, process_state, codes in combinations:
        document = _receipt_document()
        document["decision"]["state"] = decision_state
        document["decision"]["reason_codes"] = codes
        document["process_corroboration"]["state"] = process_state
        _resign(document)
        result = _verify(document)
        assert isinstance(result, ReceiptRejection)
        assert result.reason_codes == (ReasonCode.RECEIPT_MALFORMED,)


def test_symlink_relative_and_control_character_paths_fail_closed() -> None:
    symlink = _receipt_document()
    symlink["launch_instance"]["frontend_executable"]["is_symlink"] = True
    _resign(symlink)
    result = _verify(symlink)
    assert isinstance(result, ReceiptRejection)
    assert result.reason_codes == (ReasonCode.PATH_POLICY_VIOLATION,)

    relative = _receipt_document()
    relative["launch_instance"]["frontend_executable"]["path"] = _seed()["raw_cases"][
        "relative_path"
    ]
    _resign(relative)
    result = _parse_document(relative)
    assert isinstance(result, ReceiptRejection)
    assert result.reason_codes == (ReasonCode.PATH_POLICY_VIOLATION,)

    control = _receipt_document()
    control["launch_instance"]["frontend_executable"]["path"] = _seed()["raw_cases"][
        "control_character_path"
    ]
    raw = dumps_artifact(control, indent=None).encode()
    result = parse_receipt(raw)
    assert isinstance(result, ReceiptRejection)
    assert result.reason_codes == (ReasonCode.RECEIPT_MALFORMED,)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("session_pid", True),
        ("session_pid", "01"),
        ("session_pid", str(2**64)),
        ("session_pid", "-1"),
        ("receipt_nonce", "A" * 32),
        ("boot_id", "not-a-uuid"),
    ],
)
def test_scalar_types_and_ranges_are_strict(field: str, value: object) -> None:
    document = _receipt_document()
    document["launch_binding"][field] = value
    result = parse_receipt(dumps_artifact(document, indent=None).encode())
    assert isinstance(result, ReceiptRejection)
    assert result.disposition is VerificationDisposition.MALFORMED


def test_unknown_and_duplicate_reason_codes_are_rejected() -> None:
    for codes in (
        ["unknown_reason"],
        ["profile_unsupported", "profile_unsupported"],
        ["profile_unsupported"] * 33,
    ):
        document = _receipt_document()
        document["decision"]["state"] = "rejected"
        document["decision"]["reason_codes"] = codes
        document["process_corroboration"]["state"] = "rejected"
        raw = dumps_artifact(document, indent=None).encode()
        result = parse_receipt(raw)
        assert isinstance(result, ReceiptRejection)


def test_parsed_receipt_is_deeply_immutable_and_mutation_isolated() -> None:
    document = _receipt_document()
    parsed = _parse_document(document)
    assert not isinstance(parsed, ReceiptRejection)
    original_version = parsed.stable_identity.cli_version.value
    document["stable_identity"]["cli_version"] = "9.9.9"
    document["launch_instance"]["artifacts"].clear()
    assert parsed.stable_identity.cli_version.value == original_version
    assert len(parsed.launch_instance.artifacts) == 11
    assert isinstance(parsed.launch_instance.artifacts, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        parsed.schema_version = 2  # type: ignore[misc]


def test_tree_manifest_canonical_vector_and_exclusions(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (root / "a.txt").write_bytes(b"A")
    (nested / "b.txt").write_bytes(b"BB")
    (root / "inuse.123.lock").write_bytes(b"ignored")
    (root / "inuse.abc.lock").write_bytes(b"included")

    result = build_tree_manifest(root)
    assert not isinstance(result, ReceiptRejection)
    assert {row.relative_path for row in result.rows} == {
        "a.txt",
        "inuse.abc.lock",
        "nested",
        "nested/b.txt",
    }
    assert result.entry_count == 4
    assert result.total_regular_file_bytes == 11
    assert result.sha256 == sha256_hex(manifest_bytes(result.rows))


@pytest.mark.parametrize(
    ("rows", "expected", "digest"),
    [
        (
            (
                TreeManifestRow(
                    "f",
                    "0644",
                    1,
                    "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd",
                    "a.txt",
                ),
                TreeManifestRow(
                    "d",
                    "0755",
                    0,
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "nested",
                ),
            ),
            (
                b"f\t0644\t1\t559aead08264d5795d3909718cdd05abd49572e84fe55590"
                b"eef31a88a08fdffd\ta.txt\n"
                b"d\t0755\t0\te3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934"
                b"ca495991b7852b855\tnested\n"
            ),
            "41642456dfddd933395767158969d5041e9ee13b4a091a56cb5182743fae7777",
        ),
        (
            (
                TreeManifestRow(
                    "f",
                    "0644",
                    1,
                    "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd",
                    "é.txt",
                ),
                TreeManifestRow(
                    "f",
                    "0600",
                    2,
                    "fc686c314491e1f68bf1899fc54b2327353c44dd1ab4ed56538ef623edd1e866",
                    "z.txt",
                ),
            ),
            (
                b"f\t0600\t2\tfc686c314491e1f68bf1899fc54b2327353c44dd1ab4ed5"
                b"6538ef623edd1e866\tz.txt\n"
                b"f\t0644\t1\t559aead08264d5795d3909718cdd05abd49572e84fe55590"
                b"eef31a88a08fdffd\t\xc3\xa9.txt\n"
            ),
            "4e63e39c43115b646ca9c98d0b78b64ca1b164aa13f5340da4ca25077f226409",
        ),
    ],
)
def test_tree_manifest_byte_vectors_are_pinned(
    rows: tuple[TreeManifestRow, ...],
    expected: bytes,
    digest: str,
) -> None:
    assert manifest_bytes(rows) == expected
    assert sha256_hex(expected) == digest


def test_tree_manifest_rejects_symlink_hardlink_and_fifo(
    tmp_path: Path,
) -> None:
    symlink_root = tmp_path / "symlink"
    symlink_root.mkdir()
    (symlink_root / "target").write_text("x")
    (symlink_root / "link").symlink_to("target")
    result = build_tree_manifest(symlink_root)
    assert isinstance(result, ReceiptRejection)
    assert result.reason_codes == (ReasonCode.PATH_POLICY_VIOLATION,)

    hardlink_root = tmp_path / "hardlink"
    hardlink_root.mkdir()
    original = hardlink_root / "original"
    original.write_text("x")
    (hardlink_root / "alias").hardlink_to(original)
    result = build_tree_manifest(hardlink_root)
    assert isinstance(result, ReceiptRejection)
    assert result.reason_codes == (ReasonCode.PATH_POLICY_VIOLATION,)

    fifo_root = tmp_path / "fifo"
    fifo_root.mkdir()
    fifo = fifo_root / "pipe"
    fifo.parent.mkdir(exist_ok=True)
    import os

    os.mkfifo(fifo)
    result = build_tree_manifest(fifo_root)
    assert isinstance(result, ReceiptRejection)
    assert result.reason_codes == (ReasonCode.EXECUTABLE_NOT_REGULAR,)


def test_embedded_payload_requires_exactly_one_match() -> None:
    assert isinstance(find_embedded_payload(b"abc", b"x"), ReceiptRejection)
    result = find_embedded_payload(b"prefix-PAYLOAD-suffix", b"PAYLOAD")
    assert not isinstance(result, ReceiptRejection)
    assert result.offset == 7
    assert result.sha256 == sha256_hex(b"PAYLOAD")
    assert isinstance(
        find_embedded_payload(b"PAYLOAD-PAYLOAD", b"PAYLOAD"),
        ReceiptRejection,
    )


def test_package_has_no_forbidden_runtime_imports_or_frozen_wiring() -> None:
    package_dir = DEFAULT_PROFILE_DIRECTORY.parent
    forbidden_imports = {
        "core.project.sessions",
        "core.run.metadata",
        "core.startup.host",
        "packages",
    }
    for path in package_dir.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module)
        assert not any(
            name == forbidden or name.startswith(forbidden + ".")
            for name in imported
            for forbidden in forbidden_imports
        )

    repository_root = Path(__file__).parents[3]
    for relative in (
        "bin/raptor",
        "core/project/sessions.py",
        "core/run/metadata.py",
        "libexec/raptor-lifecycle-hook",
    ):
        assert "runtime_receipt" not in (repository_root / relative).read_text(
            encoding="utf-8"
        )
