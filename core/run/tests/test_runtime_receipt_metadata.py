"""Stage 3A.2a deny-only run receipt transaction tests."""

from __future__ import annotations

import ast
import copy
import contextlib
import dataclasses
import json
import os
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

import pytest

from core.json import load_json, save_json
from core.project import sessions
from core.run import metadata as md
from core.startup.host import Frontend, RUN_HOST_KEYS, SessionHostClaim
from core.startup.runtime_receipt.canonical import (
    canonical_bytes,
    sha256_hex,
    token_commitment,
)
from core.startup.runtime_receipt.plumbing_types import (
    PlumbingFailure,
    ReceiptState,
    RuntimeReceiptSnapshot,
    reference_from_receipt,
    serialize_reference,
    serialize_snapshot,
)
from core.startup.runtime_receipt.reasons import ReceiptRejection
from core.startup.runtime_receipt.verify import parse_receipt, serialize_receipt
from core.testing.runtime_receipt_fake import (
    RuntimeReceiptRunEnvironment as _ReceiptEnvironment,
    build_runtime_receipt_document as _receipt_document,
    build_runtime_receipt_lineage_fields as _valid_exact_lineage_fields,
    resign_runtime_receipt_document as _resign,
    runtime_receipt_run_environment as _runtime_receipt_run_environment,
    runtime_receipt_verification_now as _verification_now,
    start_runtime_receipt_run as _start,
)

TOKEN = "00112233445566778899aabbccddeeff"


@pytest.fixture
def receipt_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_ReceiptEnvironment]:
    with _runtime_receipt_run_environment(tmp_path, monkeypatch) as environment:
        yield environment


def _snapshot_bytes(meta: dict[str, Any]) -> bytes:
    return canonical_bytes(meta[md.RUN_RUNTIME_RECEIPT_KEY])


def _capture_from_document(
    document: dict[str, Any],
    receipt_env: _ReceiptEnvironment,
) -> sessions.SessionRuntimeReceiptCapture:
    receipt = parse_receipt(canonical_bytes(_resign(document)))
    assert not isinstance(receipt, ReceiptRejection)
    reference = reference_from_receipt(receipt)
    assert not isinstance(reference, PlumbingFailure)
    snapshot = RuntimeReceiptSnapshot(reference=reference, receipt=receipt)
    return sessions.SessionRuntimeReceiptCapture(
        snapshot=snapshot,
        session_pid=reference.session_pid.value,
        reference=reference,
        _entry_sha256=b"\0" * 32,
        _sidecar_sha256=b"\1" * 32,
        _host_uid=reference.launcher_euid.value,
        _host_executable_device=10,
        _host_executable_inode=20,
    )


def _replace_registry_document(
    receipt_env: _ReceiptEnvironment,
    document: dict[str, Any],
) -> None:
    receipt = parse_receipt(canonical_bytes(_resign(document)))
    assert not isinstance(receipt, ReceiptRejection)
    reference = reference_from_receipt(receipt)
    assert not isinstance(reference, PlumbingFailure)
    host = SessionHostClaim(
        frontend=Frontend.COPILOT,
        uid=reference.launcher_euid.value,
        executable=Path("/owned/copilot"),
        executable_device=10,
        executable_inode=20,
    )
    sidecar = receipt_env.root / reference.sidecar_name
    sidecar.write_bytes(serialize_receipt(receipt))
    sidecar.chmod(0o600)
    receipt_env.entry.write_bytes(
        sessions._serialize_session_receipt_entry(
            reference,
            since="2026-09-12T00:00:00.000000+00:00",
            host=host,
            token_hex=TOKEN,
        )
    )
    receipt_env.entry.chmod(0o600)


def _generation_document(
    generation: int,
    *,
    launcher_euid: int = 1000,
) -> dict[str, Any]:
    document = copy.deepcopy(_receipt_document())
    session_id = f"10000000-0000-4000-8000-{generation:012x}"
    launch_id = f"20000000-0000-4000-8000-{generation:012x}"
    session_pid = str(5000 + generation)
    starttime = str(10_000 + generation)
    document["launch_instance"]["session_id"] = session_id
    document["launch_instance"]["launch_id"] = launch_id
    binding = document["launch_binding"]
    binding["session_id"] = session_id
    binding["launch_id"] = launch_id
    binding["session_pid"] = session_pid
    binding["session_starttime_ticks"] = starttime
    binding["launcher_euid"] = str(launcher_euid)
    binding["session_token_commitment_sha256"] = token_commitment(
        _generation_token(generation)
    )
    binding["receipt_nonce"] = f"{generation:032x}"
    corroboration = document["process_corroboration"]
    corroboration["pid"] = session_pid
    corroboration["starttime_before"] = starttime
    corroboration["starttime_after"] = starttime
    corroboration["process_uid"] = str(launcher_euid)
    return _resign(document)


def _generation_token(generation: int) -> str:
    return f"{generation + 1:032x}"


def _generation_capture(
    generation: int,
    receipt_env: _ReceiptEnvironment,
    *,
    launcher_euid: int = 1000,
) -> sessions.SessionRuntimeReceiptCapture:
    return _capture_from_document(
        _generation_document(
            generation,
            launcher_euid=launcher_euid,
        ),
        receipt_env,
    )


def _register_generation_capture(
    generation: int,
    receipt_env: _ReceiptEnvironment,
    monkeypatch: pytest.MonkeyPatch,
) -> sessions.SessionRuntimeReceiptCapture:
    receipt = parse_receipt(canonical_bytes(_generation_document(generation)))
    assert not isinstance(receipt, ReceiptRejection)
    reference = reference_from_receipt(receipt)
    assert not isinstance(reference, PlumbingFailure)
    host = SessionHostClaim(
        frontend=Frontend.COPILOT,
        uid=reference.launcher_euid.value,
        executable=Path("/owned/copilot"),
        executable_device=10,
        executable_inode=20,
    )
    sidecar = receipt_env.root / reference.sidecar_name
    sidecar.write_bytes(serialize_receipt(receipt))
    sidecar.chmod(0o600)
    entry = receipt_env.root / reference.session_pid.text
    entry.write_bytes(
        sessions._serialize_session_receipt_entry(
            reference,
            since="2026-09-12T00:00:00.000000+00:00",
            host=host,
            token_hex=_generation_token(generation),
        )
    )
    entry.chmod(0o600)
    with monkeypatch.context() as scoped:
        scoped.setenv(sessions.ENV_SESSION_PID, reference.session_pid.text)
        scoped.setenv(sessions.ENV_SESSION_TOKEN, _generation_token(generation))
        capture = sessions.capture_current_session_runtime_receipt(
            profiles=receipt_env.profiles,
            now=_verification_now(),
        )
    assert type(capture) is sessions.SessionRuntimeReceiptCapture
    return capture


def _allow_synthetic_capture_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextlib.contextmanager
    def fence(_capture):
        yield

    monkeypatch.setattr(sessions, "session_runtime_receipt_fence", fence)


def _select_capture(
    monkeypatch: pytest.MonkeyPatch,
    capture: sessions.SessionRuntimeReceiptCapture,
) -> None:
    monkeypatch.setattr(
        md,
        "_capture_current_run_receipt",
        lambda **_kwargs: capture,
    )


def _reference_value(reference: Any) -> dict[str, Any]:
    value = json.loads(serialize_reference(reference))
    assert isinstance(value, dict)
    return value


def _lineage(meta: dict[str, Any]) -> dict[str, Any]:
    value = meta[md.RUN_RUNTIME_RECEIPT_LINEAGE_KEY]
    assert isinstance(value, dict)
    return value


def _resume_as(
    output: Path,
    capture: sessions.SessionRuntimeReceiptCapture,
    monkeypatch: pytest.MonkeyPatch,
    *,
    note: str | None = None,
) -> int:
    _select_capture(monkeypatch, capture)
    return md.resume_run(output, note=note)


def _build_lineaged_run(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    generations: tuple[int, ...] = (1,),
    name: str = "lineaged",
) -> tuple[Path, tuple[sessions.SessionRuntimeReceiptCapture, ...]]:
    output = _start(receipt_env, tmp_path, name=name)
    _allow_synthetic_capture_commit(monkeypatch)
    captures = tuple(
        _generation_capture(generation, receipt_env) for generation in generations
    )
    for capture in captures:
        _resume_as(output, capture, monkeypatch)
    return output, captures


def test_t01_legacy_absent_both_keeps_existing_shape(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(sessions.ENV_SESSION_PID, raising=False)
    monkeypatch.delenv(sessions.ENV_SESSION_TOKEN, raising=False)
    monkeypatch.setattr(md, "_get_session_pid", lambda: None)
    output = tmp_path / "legacy" / "scan"
    md.start_run(output, "scan", extra={"legacy": True})
    meta = load_json(output / md.RUN_METADATA_FILE)
    assert meta["status"] == md.STATUS_RUNNING
    assert meta["extra"] == {"legacy": True}
    assert md.RUN_RUNTIME_RECEIPT_KEY not in meta
    assert md.RUN_RUNTIME_RECEIPT_LINEAGE_KEY not in meta


@pytest.mark.parametrize(
    "key",
    (
        md.RUN_RUNTIME_RECEIPT_KEY,
        md.RUN_RUNTIME_RECEIPT_LINEAGE_KEY,
        "runtime_receipt_resumes",
    ),
)
def test_t03_reserved_extra_keys_refuse_before_mutation(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    key: str,
) -> None:
    output = tmp_path / "runs" / key
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.start_run(output, "scan", extra={key: {}})
    assert raised.value.reason is md.RunReceiptReason.RESERVED_KEY_OVERRIDE
    assert not output.exists()


def test_t03_nested_receipt_shaped_values_never_become_top_level(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(
        receipt_env,
        tmp_path,
        extra={"nested": {md.RUN_RUNTIME_RECEIPT_KEY: {"attacker": True}}},
        target_identity={"nested": {md.RUN_RUNTIME_RECEIPT_KEY: {"attacker": True}}},
    )
    meta = load_json(output / md.RUN_METADATA_FILE)
    assert meta[md.RUN_RUNTIME_RECEIPT_KEY] == json.loads(
        serialize_snapshot(receipt_env.snapshot)
    )
    assert meta["extra"]["nested"][md.RUN_RUNTIME_RECEIPT_KEY] == {"attacker": True}


def test_t03_reserved_target_identity_manifest_and_status_extra_refuse(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    for key in (
        md.RUN_RUNTIME_RECEIPT_KEY,
        md.RUN_RUNTIME_RECEIPT_LINEAGE_KEY,
    ):
        output = tmp_path / "runs" / f"target-{key}"
        with pytest.raises(md.RunRuntimeReceiptError) as raised:
            md.start_run(
                output,
                "scan",
                target_identity={key: {}},
            )
        assert raised.value.reason is md.RunReceiptReason.RESERVED_KEY_OVERRIDE
        assert not output.exists()

        with pytest.raises(md.RunRuntimeReceiptError) as raised:
            md.complete_run(
                tmp_path / "missing",
                manifest={key: {}},
            )
        assert raised.value.reason is md.RunReceiptReason.RESERVED_KEY_OVERRIDE

        with pytest.raises(md.RunRuntimeReceiptError) as raised:
            md.fail_run(
                tmp_path / "missing",
                extra={key: {}},
            )
        assert raised.value.reason is md.RunReceiptReason.RESERVED_KEY_OVERRIDE


def test_t04_one_sided_states_refuse_without_mutation(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _start(receipt_env, tmp_path)
    before = (output / md.RUN_METADATA_FILE).read_bytes()
    monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, "ff" * 16)
    for operation in (
        lambda: md.start_run(output, "scan"),
        lambda: md.resume_run(output),
    ):
        with pytest.raises(md.RunRuntimeReceiptError) as raised:
            operation()
        assert raised.value.reason is md.RunReceiptReason.RECEIPT_DOWNGRADE_FORBIDDEN
        assert (output / md.RUN_METADATA_FILE).read_bytes() == before

    monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, TOKEN)
    absent = tmp_path / "runs" / "missing-resume"
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(absent)
    assert raised.value.reason is md.RunReceiptReason.LEGACY_UPGRADE_FORBIDDEN
    assert not absent.exists()


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("unknown", md.RunReceiptReason.METADATA_INVALID),
        ("missing", md.RunReceiptReason.METADATA_INVALID),
        ("wrong-state", md.RunReceiptReason.METADATA_INVALID),
        ("noncanonical", md.RunReceiptReason.METADATA_INVALID),
        ("lineage", md.RunReceiptReason.LINEAGE_INVALID),
    ),
)
def test_t05_invalid_snapshot_shapes_fail_closed(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    mutation: str,
    reason: md.RunReceiptReason,
) -> None:
    output = _start(receipt_env, tmp_path, name=f"invalid-{mutation}")
    meta_path = output / md.RUN_METADATA_FILE
    meta = load_json(meta_path)
    snapshot = meta[md.RUN_RUNTIME_RECEIPT_KEY]
    if mutation == "unknown":
        snapshot["unknown"] = True
    elif mutation == "missing":
        snapshot.pop("receipt_sha256")
    elif mutation == "wrong-state":
        snapshot["state"] = "pending"
    elif mutation == "noncanonical":
        snapshot["session_pid"] = "0" + snapshot["session_pid"]
    else:
        meta[md.RUN_RUNTIME_RECEIPT_LINEAGE_KEY] = {}
    save_json(meta_path, meta, mode=0o600)
    before = meta_path.read_bytes()
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.start_run(output, "scan")
    assert raised.value.reason is reason
    assert meta_path.read_bytes() == before


def test_t05_duplicate_and_oversized_metadata_fail_closed(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    duplicate = _start(receipt_env, tmp_path, name="duplicate")
    duplicate_path = duplicate / md.RUN_METADATA_FILE
    raw = duplicate_path.read_bytes()
    marker = b'"state": "verified",'
    assert marker in raw
    duplicate_raw = raw.replace(marker, marker + b'\n    "state": "verified",', 1)
    duplicate_path.write_bytes(duplicate_raw)
    duplicate_path.chmod(0o600)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.start_run(duplicate, "scan")
    assert raised.value.reason is md.RunReceiptReason.METADATA_INVALID
    assert duplicate_path.read_bytes() == duplicate_raw

    oversized = tmp_path / "runs" / "oversized"
    oversized.mkdir(parents=True)
    oversized_path = oversized / md.RUN_METADATA_FILE
    oversized_raw = (
        b'{"session_runtime_receipt":"' + b"x" * md.MAX_RUN_METADATA_BYTES + b'"}'
    )
    oversized_path.write_bytes(oversized_raw)
    oversized_path.chmod(0o600)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.start_run(oversized, "scan")
    assert raised.value.reason is md.RunReceiptReason.METADATA_OVERSIZED
    assert oversized_path.read_bytes() == oversized_raw


def test_t05_nonfinite_run_metadata_is_rejected(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path, name="nonfinite")
    path = output / md.RUN_METADATA_FILE
    raw = path.read_bytes()
    marker = b'"extra": {}'
    assert marker in raw
    hostile = raw.replace(marker, b'"extra": {"score": NaN}', 1)
    path.write_bytes(hostile)
    path.chmod(0o600)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.start_run(output, "scan")
    assert raised.value.reason is md.RunReceiptReason.METADATA_INVALID
    assert path.read_bytes() == hostile


@pytest.mark.parametrize(
    ("state", "reason"),
    (
        ("pending", md.RunReceiptReason.REGISTRY_PENDING),
        ("rejected", md.RunReceiptReason.REGISTRY_REJECTED),
    ),
)
def test_t05_nonfinal_registry_states_refuse_before_run_creation(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    state: str,
    reason: md.RunReceiptReason,
) -> None:
    document = _receipt_document()
    document["decision"]["state"] = state
    document["process_corroboration"]["state"] = state
    document["process_corroboration"]["attempt"] = 0 if state == "pending" else 1
    document["decision"]["reason_codes"] = (
        [] if state == "pending" else ["profile_unsupported"]
    )
    _replace_registry_document(receipt_env, document)
    output = tmp_path / "runs" / state
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.start_run(output, "scan")
    assert raised.value.reason is reason
    assert not output.exists()


def test_t05_missing_registry_sidecar_refuses_before_run_creation(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    (receipt_env.root / receipt_env.reference.sidecar_name).unlink()
    output = tmp_path / "runs" / "missing-sidecar"
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.start_run(output, "scan")
    assert raised.value.reason is md.RunReceiptReason.RECEIPT_MISSING
    assert not output.exists()


def test_t06_comparator_rejects_snapshot_field_mismatch(
    receipt_env: _ReceiptEnvironment,
) -> None:
    audit = md._parse_run_receipt_snapshot(
        json.loads(serialize_snapshot(receipt_env.snapshot)),
        operation="start",
    )
    document = _receipt_document()
    document["launch_instance"]["launch_id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    document["launch_binding"]["launch_id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    capture = _capture_from_document(document, receipt_env)
    comparison = md.compare_run_runtime_receipt(
        audit,
        capture,
        operation="start",
        lineage=None,
    )
    assert comparison.result is md.RunReceiptComparisonResult.LAUNCH_INSTANCE_MISMATCH
    with pytest.raises(TypeError):
        bool(comparison)


def test_t07_registry_change_after_capture_refuses_before_write(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = tmp_path / "runs" / "registry-race"
    plan = md._prepare_receipt_start_plan(
        output,
        "scan",
        None,
        None,
        None,
    )
    output.parent.mkdir(parents=True)
    output.mkdir()
    receipt_env.entry.write_bytes(
        receipt_env.entry.read_bytes().replace(
            b"since=2026-09-12T00:00:00.000000+00:00",
            b"since=2026-09-12T00:00:01.000000+00:00",
        )
    )
    receipt_env.entry.chmod(0o600)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md._commit_receipt_plan(plan)
    assert raised.value.reason is md.RunReceiptReason.REGISTRY_CHANGED
    assert not (output / md.RUN_METADATA_FILE).exists()


def test_t07_sidecar_change_after_capture_refuses_before_write(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = tmp_path / "runs" / "sidecar-race"
    plan = md._prepare_receipt_start_plan(
        output,
        "scan",
        None,
        None,
        None,
    )
    output.mkdir(parents=True)
    sidecar = receipt_env.root / receipt_env.reference.sidecar_name
    sidecar.write_bytes(sidecar.read_bytes() + b" ")
    sidecar.chmod(0o600)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md._commit_receipt_plan(plan)
    assert raised.value.reason is md.RunReceiptReason.REGISTRY_CHANGED
    assert not (output / md.RUN_METADATA_FILE).exists()


def test_t08_registry_transition_cannot_enter_held_fence(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempted: list[str] = []
    original_write = md._write_prebuilt_metadata_bytes

    def checked_write(*args: Any, **kwargs: Any) -> None:
        attempted.append("write")
        with pytest.raises(sessions._SessionReceiptAbort) as raised:
            with sessions._strict_session_lock(
                receipt_env.reference.session_pid.value,
                attempts=1,
                interval=0,
            ):
                pass
        assert raised.value.failure.reason_codes[0].value == "concurrent_finalizer"
        original_write(*args, **kwargs)

    monkeypatch.setattr(md, "_write_prebuilt_metadata_bytes", checked_write)
    for iteration in range(128):
        output = tmp_path / "runs" / f"held-fence-{iteration}"
        plan = md._prepare_receipt_start_plan(
            output,
            "scan",
            None,
            None,
            None,
        )
        output.mkdir(parents=True)
        md._commit_receipt_plan(plan)
    assert attempted == ["write"] * 128
    with sessions._strict_session_lock(
        receipt_env.reference.session_pid.value,
        attempts=1,
        interval=0,
    ):
        pass


def test_t09_concurrent_starts_in_different_dirs_share_one_snapshot(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    barrier = threading.Barrier(2)
    outputs = [tmp_path / "runs" / "a", tmp_path / "runs" / "b"]

    def start(path: Path) -> object:
        barrier.wait(timeout=10)
        try:
            return md.start_run(path, "scan")
        except md.RunRuntimeReceiptError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(start, outputs))
    successes = [result for result in results if isinstance(result, Path)]
    failures = [
        result for result in results if isinstance(result, md.RunRuntimeReceiptError)
    ]
    assert successes
    assert len(successes) + len(failures) == 2
    assert all(
        failure.reason
        in {md.RunReceiptReason.LOCK_BUSY, md.RunReceiptReason.REGISTRY_CHANGED}
        for failure in failures
    ), [(failure.reason, failure.diagnostics) for failure in failures]
    snapshots = [
        _snapshot_bytes(load_json(path / md.RUN_METADATA_FILE)) for path in successes
    ]
    assert all(
        snapshot == serialize_snapshot(receipt_env.snapshot) for snapshot in snapshots
    )


def test_t10_concurrent_starts_same_dir_have_one_atomic_winner(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = tmp_path / "runs" / "same"
    plans = tuple(
        md._prepare_receipt_start_plan(
            output,
            "scan",
            None,
            None,
            None,
        )
        for _index in range(2)
    )
    output.mkdir(parents=True)
    barrier = threading.Barrier(2)

    def commit(plan: md._ReceiptCommitPlan) -> object:
        barrier.wait(timeout=10)
        try:
            md._commit_receipt_plan(plan)
            return output
        except md.RunRuntimeReceiptError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(commit, plans))
    assert sum(isinstance(result, Path) for result in results) == 1
    errors = [
        result for result in results if isinstance(result, md.RunRuntimeReceiptError)
    ]
    assert len(errors) == 1
    assert errors[0].reason is md.RunReceiptReason.METADATA_CHANGED
    meta = load_json(output / md.RUN_METADATA_FILE)
    assert _snapshot_bytes(meta) == serialize_snapshot(receipt_env.snapshot)


def test_t10_concurrent_exact_resumes_have_one_atomic_winner(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    for iteration in range(128):
        output = _start(
            receipt_env,
            tmp_path,
            name=f"same-resume-{iteration}",
        )
        path = output / md.RUN_METADATA_FILE
        meta = load_json(path)
        meta["status"] = "failed"
        save_json(path, meta, mode=0o600)
        plans = tuple(
            md._prepare_receipt_resume_plan(output, None) for _index in range(2)
        )
        barrier = threading.Barrier(2)

        def commit(plan: md._ReceiptCommitPlan) -> object:
            barrier.wait(timeout=10)
            try:
                md._commit_receipt_plan(plan)
                return plan.segment
            except md.RunRuntimeReceiptError as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = tuple(pool.map(commit, plans))
        assert sum(result == 2 for result in results) == 1
        errors = [
            result
            for result in results
            if isinstance(result, md.RunRuntimeReceiptError)
        ]
        assert len(errors) == 1
        assert errors[0].reason is md.RunReceiptReason.METADATA_CHANGED
        final = load_json(path)
        assert len(final["extra"]["resumes"]) == 1
        assert final["extra"]["resumes"][0]["segment"] == 2
        lineage = _lineage(final)
        assert len(lineage["entries"]) == 1
        assert lineage["entries"][0]["relation"] == "exact"


def test_concurrent_distinct_session_resumes_have_one_cas_winner_128_times(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    starttimes = {
        receipt_env.reference.session_pid.value: (
            receipt_env.reference.session_starttime_ticks.text
        ),
        5001: "10001",
        5002: "10002",
    }
    monkeypatch.setattr(
        sessions,
        "proc_starttime",
        lambda pid: starttimes.get(pid),
    )
    second = _register_generation_capture(1, receipt_env, monkeypatch)
    third = _register_generation_capture(2, receipt_env, monkeypatch)
    for iteration in range(128):
        monkeypatch.setenv(
            sessions.ENV_SESSION_PID,
            receipt_env.reference.session_pid.text,
        )
        monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, TOKEN)
        output = _start(
            receipt_env,
            tmp_path,
            name=f"different-session-resume-{iteration}",
        )
        path = output / md.RUN_METADATA_FILE
        monkeypatch.setenv(
            sessions.ENV_SESSION_PID,
            second.reference.session_pid.text,
        )
        monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, _generation_token(1))
        second_plan = md._prepare_receipt_resume_plan(output, None)
        monkeypatch.setenv(
            sessions.ENV_SESSION_PID,
            third.reference.session_pid.text,
        )
        monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, _generation_token(2))
        third_plan = md._prepare_receipt_resume_plan(output, None)
        monkeypatch.setenv(
            sessions.ENV_SESSION_PID,
            receipt_env.reference.session_pid.text,
        )
        monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, TOKEN)
        barrier = threading.Barrier(2)

        def commit(plan: md._ReceiptCommitPlan) -> object:
            barrier.wait(timeout=10)
            try:
                md._commit_receipt_plan(plan)
                return plan
            except md.RunRuntimeReceiptError as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = tuple(pool.map(commit, (second_plan, third_plan)))
        winners = [
            result for result in results if isinstance(result, md._ReceiptCommitPlan)
        ]
        failures = [
            result
            for result in results
            if isinstance(result, md.RunRuntimeReceiptError)
        ]
        assert len(winners) == 1
        assert len(failures) == 1
        assert failures[0].reason is md.RunReceiptReason.METADATA_CHANGED
        final = load_json(path)
        assert canonical_bytes(final) == canonical_bytes(winners[0].desired_metadata)
        assert len(_lineage(final)["entries"]) == 1


def test_t11_exact_reentrant_start_preserves_snapshot_and_ownerlessness(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path)
    md.resume_run(output, note="lineage")
    before = load_json(output / md.RUN_METADATA_FILE)
    before_snapshot = _snapshot_bytes(before)
    before_lineage = canonical_bytes(before[md.RUN_RUNTIME_RECEIPT_LINEAGE_KEY])
    md.start_run(output, "scan", extra={"second": True})
    after = load_json(output / md.RUN_METADATA_FILE)
    assert _snapshot_bytes(after) == before_snapshot
    assert canonical_bytes(after[md.RUN_RUNTIME_RECEIPT_LINEAGE_KEY]) == before_lineage
    assert len(_lineage(after)["entries"]) == 1
    assert after["extra"]["second"] is True
    assert after["project"] is None
    assert after["project_source"] == "session"
    for key in (
        "session_pid",
        "tool_pid",
        "session_start",
        "session_boot_id",
        "session_pidns",
        *RUN_HOST_KEYS,
    ):
        assert key not in after


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("status", "completed", md.RunReceiptReason.REENTRANT_STATUS_MISMATCH),
        ("command", "audit", md.RunReceiptReason.REENTRANT_COMMAND_MISMATCH),
        ("project", "named", md.RunReceiptReason.PROJECT_PIN_MISMATCH),
        ("project_source", "bookmark", md.RunReceiptReason.PROJECT_PIN_MISMATCH),
    ),
)
def test_t12_reentrant_mismatches_refuse_before_replacement(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    field: str,
    value: object,
    reason: md.RunReceiptReason,
) -> None:
    output = _start(receipt_env, tmp_path, name=f"mismatch-{field}")
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    meta[field] = value
    save_json(path, meta, mode=0o600)
    before = path.read_bytes()
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.start_run(output, "scan")
    assert raised.value.reason is reason
    assert path.read_bytes() == before


def test_t13_exact_resume_is_ownerless_projectless_and_ledgerless(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _start(receipt_env, tmp_path)
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    before_snapshot = _snapshot_bytes(meta)
    meta.update(
        {
            "status": "failed",
            "end_timestamp": "2026-09-12T00:01:00+00:00",
            "duration_seconds": 60.0,
            "session_pid": 7,
            "tool_pid": 8,
            "session_start": "9",
            "session_boot_id": "stale",
            "session_pidns": "10",
            "session_host": "copilot",
        }
    )
    save_json(path, meta, mode=0o600)
    monkeypatch.setattr(
        sessions,
        "ledger_record_resume",
        lambda *_args, **_kwargs: pytest.fail("receipt resume wrote a ledger"),
    )
    monkeypatch.setattr(
        md,
        "_get_session_pid",
        lambda: pytest.fail("receipt resume reached legacy owner resolution"),
    )
    segment = md.resume_run(output, note="exact")
    assert segment == 2
    resumed = load_json(path)
    assert resumed["status"] == "running"
    assert _snapshot_bytes(resumed) == before_snapshot
    assert resumed["extra"]["resumes"][-1]["segment"] == 2
    lineage = _lineage(resumed)
    assert len(lineage["entries"]) == 1
    assert lineage["entries"][0]["relation"] == "exact"
    assert (
        lineage["entries"][0]["prior_snapshot_sha256"]
        == lineage["entries"][0]["current_snapshot_sha256"]
    )
    assert (
        lineage["entries"][0]["prior_reference"]
        == lineage["entries"][0]["current_reference"]
    )
    assert resumed["project"] is None
    assert resumed["project_source"] == "session"
    assert "end_timestamp" not in resumed
    assert "duration_seconds" not in resumed
    for key in (
        "session_pid",
        "tool_pid",
        "session_start",
        "session_boot_id",
        "session_pidns",
        *RUN_HOST_KEYS,
    ):
        assert key not in resumed
    assert not (
        receipt_env.root / f"{receipt_env.reference.session_pid.text}.run"
    ).exists()
    assert (
        md._metadata_owned_by_session(
            resumed,
            receipt_env.reference.session_pid.value,
        )
        is False
    )


def test_t14_cross_launch_resume_replaces_head_and_appends_lineage(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _start(receipt_env, tmp_path)
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    meta.update(
        {
            "status": "failed",
            "session_pid": 7,
            "tool_pid": 8,
            "session_start": "9",
            "session_boot_id": "stale",
            "session_pidns": "10",
            "session_host": "copilot",
        }
    )
    save_json(path, meta, mode=0o600)
    prior_snapshot = meta[md.RUN_RUNTIME_RECEIPT_KEY]
    replacement = _generation_capture(1, receipt_env)
    _select_capture(monkeypatch, replacement)
    _allow_synthetic_capture_commit(monkeypatch)
    for name in (
        "ledger_record_start",
        "ledger_record_resume",
        "ledger_record_finish",
    ):
        monkeypatch.setattr(
            sessions,
            name,
            lambda *_args, __name=name, **_kwargs: pytest.fail(
                f"cross-launch resume called {__name}"
            ),
        )

    assert md.resume_run(output, note="takeover") == 2

    resumed = load_json(path)
    assert resumed["status"] == "running"
    assert _snapshot_bytes(resumed) == serialize_snapshot(replacement.snapshot)
    lineage = _lineage(resumed)
    assert lineage["schema"] == md.RUN_RECEIPT_LINEAGE_SCHEMA
    assert lineage["schema_version"] == md.RUN_RECEIPT_LINEAGE_SCHEMA_VERSION
    assert len(lineage["entries"]) == 1
    row = lineage["entries"][0]
    assert set(row) == {
        "segment",
        "resumed_at_utc",
        "relation",
        "prior_snapshot_sha256",
        "current_snapshot_sha256",
        "prior_reference",
        "current_reference",
    }
    assert row["segment"] == 2
    assert row["relation"] == "new_launch_same_stable"
    assert row["prior_reference"] == _reference_value(receipt_env.reference)
    assert row["current_reference"] == _reference_value(replacement.reference)
    assert row["prior_snapshot_sha256"] == sha256_hex(canonical_bytes(prior_snapshot))
    assert row["current_snapshot_sha256"] == sha256_hex(
        canonical_bytes(resumed[md.RUN_RUNTIME_RECEIPT_KEY])
    )
    assert resumed["extra"]["resumes"][-1]["ts"] == row["resumed_at_utc"]
    assert resumed["extra"]["resumes"][-1]["segment"] == 2
    assert TOKEN not in json.dumps(lineage)
    assert set(row["prior_reference"]) == {
        "schema",
        "schema_version",
        "reference",
    }
    assert resumed["project"] is None
    assert resumed["project_source"] == "session"
    for key in (
        "session_pid",
        "tool_pid",
        "session_start",
        "session_boot_id",
        "session_pidns",
        *RUN_HOST_KEYS,
    ):
        assert key not in resumed


@pytest.mark.parametrize(
    "field",
    (
        "session_id",
        "launch_id",
        "session_pid",
        "session_starttime_ticks",
        "session_token_commitment_sha256",
    ),
)
def test_cross_launch_first_generation_fields_must_all_differ(
    receipt_env: _ReceiptEnvironment,
    field: str,
) -> None:
    prior = receipt_env.reference
    current = _generation_capture(1, receipt_env).reference
    assert md._references_share_lineage_identity(prior, current)
    assert md._reference_generation_is_distinct(prior, current)
    copied = dataclasses.replace(
        current,
        **{field: getattr(prior, field)},
    )
    assert not md._reference_generation_is_distinct(prior, copied)


@pytest.mark.parametrize(
    "field",
    (
        "launch_nonce",
        "launch_instance_sha256",
        "launch_binding_sha256",
        "process_corroboration_sha256",
        "receipt_sha256",
    ),
)
def test_cross_launch_second_generation_fields_must_all_differ(
    receipt_env: _ReceiptEnvironment,
    field: str,
) -> None:
    prior = receipt_env.reference
    current = _generation_capture(1, receipt_env).reference
    assert md._reference_generation_is_distinct(prior, current)
    copied = dataclasses.replace(
        current,
        **{field: getattr(prior, field)},
    )
    assert not md._reference_generation_is_distinct(prior, copied)


def test_receipt_reference_field_classification_is_complete(
    receipt_env: _ReceiptEnvironment,
) -> None:
    prior = receipt_env.reference
    current = _generation_capture(1, receipt_env).reference
    other_boot = type(current.boot_id)("30000000-0000-4000-8000-000000000001")
    unconstrained = dataclasses.replace(
        current,
        boot_id=other_boot,
        pid_namespace_inode=type(current.pid_namespace_inode)(
            current.pid_namespace_inode.value + 1
        ),
        attempt=current.attempt + 1,
    )
    assert md._references_share_lineage_identity(prior, unconstrained)
    assert md._reference_generation_is_distinct(prior, unconstrained)

    different_euid = dataclasses.replace(
        current,
        launcher_euid=type(current.launcher_euid)(current.launcher_euid.value + 1),
    )
    assert not md._references_share_lineage_identity(prior, different_euid)
    pending = dataclasses.replace(
        current,
        state=ReceiptState.PENDING,
        attempt=0,
    )
    assert not md._references_share_lineage_identity(prior, pending)


@pytest.mark.parametrize(
    "field",
    (
        "session_id",
        "launch_id",
        "session_token_commitment_sha256",
        "launch_nonce",
        "receipt_sha256",
    ),
)
def test_each_unique_generation_field_participates_in_replay_detection(
    receipt_env: _ReceiptEnvironment,
    field: str,
) -> None:
    historical = receipt_env.reference
    candidate = _generation_capture(2, receipt_env).reference
    replay = dataclasses.replace(
        candidate,
        **{field: getattr(historical, field)},
    )
    assert md._reference_replays_any(replay, (historical,))
    assert not md._reference_replays_any(candidate, (historical,))


def test_symmetric_replay_refuses_original_and_later_generations(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output, (second,) = _build_lineaged_run(
        receipt_env,
        tmp_path,
        monkeypatch,
        generations=(1,),
        name="symmetric-replay",
    )
    path = output / md.RUN_METADATA_FILE
    original = _capture_from_document(
        copy.deepcopy(_receipt_document()),
        receipt_env,
    )

    before_original = path.read_bytes()
    _select_capture(monkeypatch, original)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.LAUNCH_REPLAY
    rendered = repr(raised.value) + str(raised.value) + repr(raised.value.details)
    assert receipt_env.reference.session_id.value not in rendered
    assert receipt_env.reference.launch_id.value not in rendered
    assert receipt_env.reference.launch_nonce.value not in rendered
    assert str(output) not in rendered
    assert path.read_bytes() == before_original

    third = _generation_capture(2, receipt_env)
    assert _resume_as(output, third, monkeypatch) == 3
    before_second = path.read_bytes()
    _select_capture(monkeypatch, second)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.LAUNCH_REPLAY
    assert path.read_bytes() == before_second

    partial_document = _generation_document(3)
    original_session = receipt_env.reference.session_id.value
    partial_document["launch_instance"]["session_id"] = original_session
    partial_document["launch_binding"]["session_id"] = original_session
    partial = _capture_from_document(
        partial_document,
        receipt_env,
    )
    _select_capture(monkeypatch, partial)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.LAUNCH_REPLAY
    assert path.read_bytes() == before_second


@pytest.mark.parametrize(
    "copied_field",
    ("session_starttime_ticks", "session_token_commitment_sha256"),
)
def test_same_jiffy_or_copied_binding_refuses_before_mutation(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    copied_field: str,
) -> None:
    output = _start(receipt_env, tmp_path, name=f"copied-{copied_field}")
    path = output / md.RUN_METADATA_FILE
    before = path.read_bytes()
    document = _generation_document(1)
    binding = document["launch_binding"]
    if copied_field == "session_starttime_ticks":
        original = receipt_env.reference.session_starttime_ticks.text
        binding[copied_field] = original
        document["process_corroboration"]["starttime_before"] = original
        document["process_corroboration"]["starttime_after"] = original
    else:
        binding[copied_field] = (
            receipt_env.reference.session_token_commitment_sha256.value
        )
    capture = _capture_from_document(_resign(document), receipt_env)
    _select_capture(monkeypatch, capture)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.LAUNCH_INSTANCE_INVALID
    assert path.read_bytes() == before


def test_launcher_euid_drift_refuses_before_mutation(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _start(receipt_env, tmp_path, name="launcher-euid-drift")
    path = output / md.RUN_METADATA_FILE
    before = path.read_bytes()
    capture = _generation_capture(
        1,
        receipt_env,
        launcher_euid=receipt_env.reference.launcher_euid.value + 1,
    )
    _select_capture(monkeypatch, capture)

    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.LAUNCH_INSTANCE_INVALID
    assert path.read_bytes() == before


def test_stale_current_receipt_refuses_before_metadata_parse_or_mutation(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _start(receipt_env, tmp_path, name="stale-current")
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    meta["status"] = "failed"
    meta[md.RUN_RUNTIME_RECEIPT_LINEAGE_KEY] = {"invalid": True}
    save_json(path, meta, mode=0o600)
    before = path.read_bytes()
    _replace_registry_document(receipt_env, _receipt_document())
    stale = datetime.fromisoformat("2026-09-12T10:00:00+00:00")

    class _StaleDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return stale if tz is None else stale.astimezone(tz)

    monkeypatch.setattr(md, "datetime", _StaleDateTime)

    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.REGISTRY_INVALID
    assert path.read_bytes() == before


def test_pending_registry_precedes_invalid_lineage(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path, name="pending-precedence")
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    meta[md.RUN_RUNTIME_RECEIPT_LINEAGE_KEY] = {"invalid": True}
    save_json(path, meta, mode=0o600)
    before = path.read_bytes()
    document = _receipt_document()
    document["decision"]["state"] = "pending"
    document["process_corroboration"]["state"] = "pending"
    document["process_corroboration"]["attempt"] = 0
    document["decision"]["reason_codes"] = []
    _replace_registry_document(receipt_env, document)

    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.REGISTRY_PENDING
    assert path.read_bytes() == before


def test_resume_registry_change_after_capture_refuses_before_write(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path, name="resume-registry-race")
    path = output / md.RUN_METADATA_FILE
    before = path.read_bytes()
    plan = md._prepare_receipt_resume_plan(output, None)
    receipt_env.entry.write_bytes(
        receipt_env.entry.read_bytes().replace(
            b"since=2026-09-12T00:00:00.000000+00:00",
            b"since=2026-09-12T00:00:01.000000+00:00",
        )
    )
    receipt_env.entry.chmod(0o600)

    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md._commit_receipt_plan(plan)
    assert raised.value.reason is md.RunReceiptReason.REGISTRY_CHANGED
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("profile", md.RunReceiptReason.PROFILE_MISMATCH),
        ("stable", md.RunReceiptReason.STABLE_IDENTITY_MISMATCH),
    ),
)
def test_t15_cross_profile_or_stable_resume_refuses(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    reason: md.RunReceiptReason,
) -> None:
    output = _start(receipt_env, tmp_path, name=f"resume-{mutation}")
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    meta["status"] = "failed"
    save_json(path, meta, mode=0o600)
    before = path.read_bytes()
    document = _receipt_document()
    if mutation == "profile":
        document["stable_identity"]["profile_id"] = "other-profile"
    else:
        document["stable_identity"]["launcher"]["sha256"] = "f" * 64
        document["launch_instance"]["issuer"]["launcher_file"]["sha256"] = "f" * 64
    replacement = _capture_from_document(document, receipt_env)
    monkeypatch.setattr(
        md, "_capture_current_run_receipt", lambda **_kwargs: replacement
    )
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is reason
    assert path.read_bytes() == before


def test_t16_wrong_token_and_completed_resume_refuse(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _start(receipt_env, tmp_path)
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    meta["status"] = "failed"
    save_json(path, meta, mode=0o600)
    before = path.read_bytes()
    monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, "ff" * 16)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.RECEIPT_DOWNGRADE_FORBIDDEN
    assert path.read_bytes() == before

    monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, TOKEN)
    meta["status"] = "completed"
    save_json(path, meta, mode=0o600)
    completed = path.read_bytes()
    with pytest.raises(ValueError, match="not resumable"):
        md.resume_run(output)
    assert path.read_bytes() == completed


def test_t17_invalid_lineage_is_refused_without_mutation(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path)
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    meta["status"] = "failed"
    meta[md.RUN_RUNTIME_RECEIPT_LINEAGE_KEY] = {
        "schema": "raptor.run_runtime_receipt_lineage/v1",
        "entries": [],
    }
    save_json(path, meta, mode=0o600)
    before = path.read_bytes()
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.LINEAGE_INVALID
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "mutation",
    (
        "duplicate",
        "reordered",
        "unknown-envelope",
        "unknown-row",
        "partial-row",
        "noncanonical-reference",
        "pending-reference",
        "broken-chain",
        "head-digest",
        "head-rollback",
        "profile-drift",
        "stable-drift",
        "euid-drift",
        "relation",
    ),
)
def test_lineage_unknown_partial_duplicate_and_reordered_forms_refuse(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    output, _captures = _build_lineaged_run(
        receipt_env,
        tmp_path,
        monkeypatch,
        generations=(1, 2),
        name=f"bad-lineage-{mutation}",
    )
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    lineage = _lineage(meta)
    entries = lineage["entries"]
    if mutation == "duplicate":
        entries[1] = copy.deepcopy(entries[0])
    elif mutation == "reordered":
        entries.reverse()
    elif mutation == "unknown-envelope":
        lineage["unknown"] = True
    elif mutation == "unknown-row":
        entries[0]["unknown"] = True
    elif mutation == "partial-row":
        entries[0].pop("current_snapshot_sha256")
    elif mutation == "noncanonical-reference":
        entries[0]["prior_reference"]["reference"]["session_pid"] = "04242"
    elif mutation == "pending-reference":
        reference = entries[0]["prior_reference"]["reference"]
        reference["state"] = "pending"
        reference["attempt"] = 0
    elif mutation == "broken-chain":
        entries[1]["prior_snapshot_sha256"] = "f" * 64
    elif mutation == "head-digest":
        entries[-1]["current_snapshot_sha256"] = "f" * 64
    elif mutation == "head-rollback":
        meta[md.RUN_RUNTIME_RECEIPT_KEY] = json.loads(
            serialize_snapshot(receipt_env.snapshot)
        )
    elif mutation == "profile-drift":
        entries[0]["prior_reference"]["reference"]["profile_id"] = "other-profile"
    elif mutation == "stable-drift":
        entries[0]["prior_reference"]["reference"]["stable_identity_sha256"] = "f" * 64
    elif mutation == "euid-drift":
        entries[0]["prior_reference"]["reference"]["launcher_euid"] = "1001"
    else:
        entries[0]["relation"] = "exact"
    save_json(path, meta, mode=0o600)
    before = path.read_bytes()

    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.LINEAGE_INVALID
    assert path.read_bytes() == before


@pytest.mark.parametrize("segment", ("2", 2.0, True, -1, 34))
def test_lineage_segment_requires_exact_bounded_integer(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    segment: object,
) -> None:
    output = _start(
        receipt_env,
        tmp_path,
        name=f"segment-{type(segment).__name__}-{segment}",
    )
    md.resume_run(output)
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    _lineage(meta)["entries"][0]["segment"] = segment
    save_json(path, meta, mode=0o600)
    before = path.read_bytes()

    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.LINEAGE_INVALID
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema_version", True),
        ("schema_version", 1.0),
        ("entries", []),
    ),
)
def test_lineage_envelope_types_and_empty_history_refuse(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    output = _start(
        receipt_env,
        tmp_path,
        name=f"envelope-{field}-{type(value).__name__}",
    )
    md.resume_run(output)
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    _lineage(meta)[field] = value
    save_json(path, meta, mode=0o600)
    before = path.read_bytes()

    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.LINEAGE_INVALID
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "timestamp",
    (
        "2026-09-13T00:00:00+00:00",
        "2026-09-13T00:00:00.00000+00:00",
        "2026-09-13T00:00:00.000000Z",
        "2026-09-13T00:00:00.000000-00:00",
    ),
)
def test_lineage_timestamp_grammar_is_strict(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    timestamp: str,
) -> None:
    output = _start(
        receipt_env,
        tmp_path,
        name="timestamp-" + sha256_hex(timestamp.encode("ascii"))[:8],
    )
    md.resume_run(output)
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    _lineage(meta)["entries"][0]["resumed_at_utc"] = timestamp
    save_json(path, meta, mode=0o600)
    before = path.read_bytes()

    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.LINEAGE_INVALID
    assert path.read_bytes() == before


def test_lineage_timestamp_writes_zero_microseconds_and_round_trips(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _start(receipt_env, tmp_path, name="zero-microseconds")
    instant = (_verification_now() + timedelta(seconds=1)).replace(microsecond=0)

    class _ZeroMicrosecondDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return instant if tz is None else instant.astimezone(tz)

    monkeypatch.setattr(md, "datetime", _ZeroMicrosecondDateTime)
    md.resume_run(output)
    meta = load_json(output / md.RUN_METADATA_FILE)
    row = _lineage(meta)["entries"][0]
    timestamp = row["resumed_at_utc"]
    assert timestamp.endswith(".000000+00:00")
    assert md._RUN_RECEIPT_LINEAGE_TIMESTAMP_RE.fullmatch(timestamp)
    assert (
        datetime.fromisoformat(timestamp).isoformat(timespec="microseconds")
        == timestamp
    )
    assert meta["extra"]["resumes"][0]["ts"] == timestamp


def test_future_lineage_timestamp_refuses_before_mutation(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path, name="future-lineage")
    md.resume_run(output)
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    _lineage(meta)["entries"][0]["resumed_at_utc"] = "2099-01-01T00:00:00.000000+00:00"
    save_json(path, meta, mode=0o600)
    before = path.read_bytes()

    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.LINEAGE_INVALID
    assert raised.value.details["subordinate"] == "timestamp"
    assert path.read_bytes() == before


def test_extra_resumes_is_output_only_for_segment_selection(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output, (current,) = _build_lineaged_run(
        receipt_env,
        tmp_path,
        monkeypatch,
        name="output-only-resumes",
    )
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    meta["extra"]["resumes"] = [
        {"segment": index + 100, "ts": "attacker"} for index in range(40)
    ]
    save_json(path, meta, mode=0o600)

    assert _resume_as(output, current, monkeypatch) == 3
    resumed = load_json(path)
    assert _lineage(resumed)["entries"][-1]["segment"] == 3
    assert resumed["extra"]["resumes"][-1]["segment"] == 3
    assert len(resumed["extra"]["resumes"]) == 41


def test_legacy_exact_resume_history_is_not_backfilled(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path, name="legacy-resume-history")
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    meta["extra"]["resumes"] = [
        {
            "segment": 2,
            "ts": "2026-09-12T00:00:00+00:00",
            "prior_status": "failed",
        }
    ]
    save_json(path, meta, mode=0o600)
    before = path.read_bytes()

    for operation in (
        lambda: md.start_run(output, "scan"),
        lambda: md.resume_run(output),
    ):
        with pytest.raises(md.RunRuntimeReceiptError) as raised:
            operation()
        assert raised.value.reason is md.RunReceiptReason.LINEAGE_INVALID
        assert raised.value.details["subordinate"] == "legacy_resume_history"
        assert path.read_bytes() == before


def test_lineage_32_entry_boundary_and_33rd_resume_refusal(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path, name="lineage-cap")
    path = output / md.RUN_METADATA_FILE
    for expected_segment in range(2, 34):
        assert md.resume_run(output) == expected_segment
    meta = load_json(path)
    assert len(_lineage(meta)["entries"]) == 32
    assert _lineage(meta)["entries"][-1]["segment"] == 33
    before = path.read_bytes()

    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.LINEAGE_OVERFLOW
    assert raised.value.details["segment"] == "34"
    assert path.read_bytes() == before

    planted = load_json(path)
    entries = _lineage(planted)["entries"]
    extra = copy.deepcopy(entries[-1])
    extra["segment"] = 34
    prior_time = datetime.fromisoformat(extra["resumed_at_utc"])
    extra["resumed_at_utc"] = (prior_time + timedelta(microseconds=1)).isoformat(
        timespec="microseconds"
    )
    entries.append(extra)
    save_json(path, planted, mode=0o600)
    overlong = path.read_bytes()
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.LINEAGE_INVALID
    assert path.read_bytes() == overlong


@pytest.mark.parametrize("bound", ("row", "lineage"))
def test_lineage_byte_bounds_report_metadata_oversized(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bound: str,
) -> None:
    output = _start(receipt_env, tmp_path, name=f"{bound}-bound")
    path = output / md.RUN_METADATA_FILE
    before = path.read_bytes()
    if bound == "row":
        monkeypatch.setattr(md, "MAX_RUN_RECEIPT_LINEAGE_ROW_BYTES", 1)
    else:
        monkeypatch.setattr(md, "MAX_RUN_RECEIPT_LINEAGE_BYTES", 1)

    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.METADATA_OVERSIZED
    assert path.read_bytes() == before


def test_lineage_without_snapshot_is_lineage_invalid(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path, name="lineage-without-head")
    md.resume_run(output)
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    meta.pop(md.RUN_RUNTIME_RECEIPT_KEY)
    save_json(path, meta, mode=0o600)
    before = path.read_bytes()

    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.LINEAGE_INVALID
    assert path.read_bytes() == before


def test_extra_resumes_non_list_is_metadata_invalid(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path, name="resumes-non-list")
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    meta["extra"]["resumes"] = {"segment": 2}
    save_json(path, meta, mode=0o600)
    before = path.read_bytes()

    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.METADATA_INVALID
    assert path.read_bytes() == before


def test_duplicate_lineage_json_key_is_metadata_invalid(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path, name="duplicate-lineage-key")
    md.resume_run(output)
    path = output / md.RUN_METADATA_FILE
    raw = path.read_bytes()
    marker = b'"relation": "exact",'
    assert marker in raw
    duplicate = raw.replace(
        marker,
        marker + b'\n        "relation": "exact",',
        1,
    )
    path.write_bytes(duplicate)
    path.chmod(0o600)

    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.METADATA_INVALID
    assert path.read_bytes() == duplicate


@pytest.mark.parametrize("operation", ("start", "resume"))
def test_t18_legacy_upgrade_under_host_v2_is_forbidden(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    operation: str,
) -> None:
    output = tmp_path / "runs" / f"legacy-{operation}"
    output.mkdir(parents=True)
    save_json(
        output / md.RUN_METADATA_FILE,
        {
            "version": 2,
            "command": "scan",
            "timestamp": "2026-09-12T00:00:00+00:00",
            "status": "failed" if operation == "resume" else "running",
            "extra": {},
        },
        mode=0o600,
    )
    before = (output / md.RUN_METADATA_FILE).read_bytes()
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        if operation == "start":
            md.start_run(output, "scan")
        else:
            md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.LEGACY_UPGRADE_FORBIDDEN
    assert (output / md.RUN_METADATA_FILE).read_bytes() == before


def test_t19_metadata_cas_preserves_the_winner(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = tmp_path / "runs" / "metadata-race"
    plan = md._prepare_receipt_start_plan(
        output,
        "scan",
        None,
        None,
        None,
    )
    output.mkdir(parents=True)
    winner = b'{"status":"winner"}\n'
    path = output / md.RUN_METADATA_FILE
    path.write_bytes(winner)
    path.chmod(0o600)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md._commit_receipt_plan(plan)
    assert raised.value.reason is md.RunReceiptReason.METADATA_CHANGED
    assert path.read_bytes() == winner


def test_post_replace_reread_mismatch_is_explicit_and_not_success(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _start(receipt_env, tmp_path, name="post-replace-reread")
    path = output / md.RUN_METADATA_FILE
    plan = md._prepare_receipt_resume_plan(output, None)
    real_read = md._read_metadata_bytes_for_cas
    calls = 0

    def changed_after_replace(*args: Any, **kwargs: Any):
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_read(*args, **kwargs)
        return b'{"changed":true}\n'

    monkeypatch.setattr(
        md,
        "_read_metadata_bytes_for_cas",
        changed_after_replace,
    )
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md._commit_receipt_plan(plan)
    assert raised.value.reason is md.RunReceiptReason.METADATA_CHANGED
    assert raised.value.details["subordinate"] == "post_replace_verification"
    assert path.read_bytes() == plan.desired_raw
    assert receipt_env.active[-1] == output
    assert len(receipt_env.frozen) == 1


def test_directory_fsync_failure_after_replace_does_not_wedge_resume(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _start(receipt_env, tmp_path, name="dir-fsync-recovery")
    path = output / md.RUN_METADATA_FILE
    real_fsync = md.os.fsync
    calls = 0

    def fail_directory_fsync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("directory fsync failed")
        real_fsync(fd)

    monkeypatch.setattr(md.os, "fsync", fail_directory_fsync)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.METADATA_CHANGED
    assert raised.value.details["subordinate"] == "write_failed"
    committed = load_json(path)
    assert len(_lineage(committed)["entries"]) == 1

    monkeypatch.setattr(md.os, "fsync", real_fsync)
    assert md.resume_run(output) == 3
    recovered = load_json(path)
    assert len(_lineage(recovered)["entries"]) == 2


@pytest.mark.skipif(not md._HAS_FCNTL, reason="fcntl unavailable")
@pytest.mark.parametrize("shape", ("symlink", "hardlink", "mode", "content"))
def test_t20_strict_metadata_lock_refuses_unsafe_shapes(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    shape: str,
) -> None:
    output = tmp_path / "runs" / f"lock-{shape}"
    plan = md._prepare_receipt_start_plan(
        output,
        "scan",
        None,
        None,
        None,
    )
    output.mkdir(parents=True)
    lock = output / f"{md.RUN_METADATA_FILE}.lock"
    peer = output / "peer"
    peer.write_bytes(b"")
    peer.chmod(0o600)
    if shape == "symlink":
        lock.symlink_to(peer)
    elif shape == "hardlink":
        os.link(peer, lock)
    elif shape == "mode":
        lock.write_bytes(b"")
        lock.chmod(0o666)
    else:
        lock.write_bytes(b"x")
        lock.chmod(0o600)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md._commit_receipt_plan(plan)
    assert raised.value.reason is md.RunReceiptReason.STRICT_LOCK_UNAVAILABLE
    assert not (output / md.RUN_METADATA_FILE).exists()


@pytest.mark.skipif(not md._HAS_FCNTL, reason="fcntl unavailable")
def test_t20_strict_metadata_lock_replacement_is_refused_before_write(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "runs" / "lock-replaced"
    plan = md._prepare_receipt_start_plan(
        output,
        "scan",
        None,
        None,
        None,
    )
    output.mkdir(parents=True)
    fired = False

    def replace(path: Path, _fd: int) -> None:
        nonlocal fired
        if fired:
            return
        fired = True
        path.unlink()
        path.write_bytes(b"")
        path.chmod(0o600)

    monkeypatch.setattr(md, "_after_strict_metadata_lock_open", replace)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md._commit_receipt_plan(plan)
    assert raised.value.reason is md.RunReceiptReason.STRICT_LOCK_UNAVAILABLE
    assert not (output / md.RUN_METADATA_FILE).exists()


def test_t20_missing_fcntl_refuses_strict_metadata_mutation(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "runs" / "no-fcntl"
    plan = md._prepare_receipt_start_plan(
        output,
        "scan",
        None,
        None,
        None,
    )
    output.mkdir(parents=True)
    monkeypatch.setattr(md, "_HAS_FCNTL", False)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md._commit_receipt_plan(plan)
    assert raised.value.reason is md.RunReceiptReason.STRICT_LOCK_UNAVAILABLE
    assert not (output / md.RUN_METADATA_FILE).exists()


def test_t21_commit_lock_order_is_session_then_metadata_only(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.startup.runtime_receipt import plumbing_types

    output = _start(receipt_env, tmp_path, name="lock-order")
    plan = md._prepare_receipt_resume_plan(output, None)
    events: list[str] = []
    original_fence = sessions.session_runtime_receipt_fence
    original_metadata_lock = md._strict_metadata_lock
    original_write = md._write_prebuilt_metadata_bytes

    @contextlib.contextmanager
    def tracked_fence(capture):
        events.append("session-enter")
        with original_fence(capture):
            yield
        events.append("session-exit")

    @contextlib.contextmanager
    def tracked_metadata_lock(*args: Any, **kwargs: Any):
        assert events[-1] == "session-enter"
        events.append("metadata-enter")
        with original_metadata_lock(*args, **kwargs):
            yield
        events.append("metadata-exit")

    def tracked_write(*args: Any, **kwargs: Any) -> None:
        assert events[-1] == "metadata-enter"
        events.append("write")
        original_write(*args, **kwargs)

    monkeypatch.setattr(sessions, "session_runtime_receipt_fence", tracked_fence)
    monkeypatch.setattr(md, "_strict_metadata_lock", tracked_metadata_lock)
    monkeypatch.setattr(md, "_write_prebuilt_metadata_bytes", tracked_write)
    monkeypatch.setattr(
        "core.startup.runtime_receipt.persistence._strict_lock",
        lambda *_args, **_kwargs: pytest.fail(
            "receipt storage lock nested inside the commit"
        ),
    )
    for name in (
        "loads_bounded",
        "dumps_artifact",
        "_parse_run_receipt_snapshot",
        "_parse_run_receipt_lineage",
        "_append_receipt_lineage",
        "_reference_json_value",
        "_snapshot_digest",
        "_capture_current_run_receipt",
        "_contention_project_dir",
    ):
        monkeypatch.setattr(
            md,
            name,
            lambda *_args, __name=name, **_kwargs: pytest.fail(
                f"{__name} ran while commit locks were held"
            ),
        )
    for name in ("parse_reference", "serialize_reference"):
        monkeypatch.setattr(
            plumbing_types,
            name,
            lambda *_args, __name=name, **_kwargs: pytest.fail(
                f"{__name} ran while commit locks were held"
            ),
        )
    monkeypatch.setattr(
        md.time,
        "sleep",
        lambda *_args, **_kwargs: pytest.fail("sleep ran while commit locks were held"),
    )
    md._commit_receipt_plan(plan)
    assert events == [
        "session-enter",
        "metadata-enter",
        "write",
        "metadata-exit",
        "session-exit",
    ]


def test_t22_receipt_metadata_never_grants_legacy_owner_or_liveness(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path)
    md.resume_run(output)
    meta = load_json(output / md.RUN_METADATA_FILE)
    meta["session_pid"] = receipt_env.reference.session_pid.value
    meta["session_start"] = receipt_env.reference.session_starttime_ticks.text
    meta["session_boot_id"] = receipt_env.reference.boot_id.value
    assert md._session_alive_for_meta(meta) is False
    assert (
        md._metadata_owned_by_session(
            meta,
            receipt_env.reference.session_pid.value,
        )
        is False
    )


def test_host_v2_credential_never_owns_legacy_metadata(
    receipt_env: _ReceiptEnvironment,
) -> None:
    legacy = {
        "session_pid": receipt_env.reference.session_pid.value,
        "session_start": receipt_env.reference.session_starttime_ticks.text,
        "session_boot_id": receipt_env.reference.boot_id.value,
        "session_pidns": receipt_env.reference.pid_namespace_inode.text,
    }
    assert (
        md._metadata_owned_by_session(
            legacy,
            receipt_env.reference.session_pid.value,
        )
        is False
    )


@pytest.mark.parametrize(
    "operation",
    ("complete", "fail", "cancel", "interrupt", "reopen", "projections", "status"),
)
def test_t23_terminal_and_projection_veto_precedes_side_effects(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    output = _start(receipt_env, tmp_path, name=f"terminal-{operation}")
    md.resume_run(output)
    path = output / md.RUN_METADATA_FILE
    before = path.read_bytes()
    for name in (
        "_finalize_sandbox_summary",
        "_finalize_sandbox_triage",
        "_merge_run_journal",
        "_convert_reads_manifest",
        "_snapshot_run_coverage",
    ):
        monkeypatch.setattr(
            md,
            name,
            lambda *_args, __name=name, **_kwargs: pytest.fail(
                f"{__name} ran before the receipt veto"
            ),
        )
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        if operation == "complete":
            md.complete_run(output)
        elif operation == "fail":
            md.fail_run(output, "x")
        elif operation == "cancel":
            md.cancel_run(output)
        elif operation == "interrupt":
            md.interrupt_run(output)
        elif operation == "reopen":
            md.reopen_run(output)
        elif operation == "projections":
            md.project_run_projections(output)
        else:
            md._update_status(output, md.STATUS_FAILED)
    assert raised.value.reason is md.RunReceiptReason.TERMINAL_TRANSITION_FORBIDDEN
    assert path.read_bytes() == before


def test_t29_candidate_profile_remains_non_authorizing(
    receipt_env: _ReceiptEnvironment,
) -> None:
    capture = sessions.capture_current_session_runtime_receipt(
        profiles=receipt_env.profiles,
        now=_verification_now(),
    )
    assert type(capture) is sessions.SessionRuntimeReceiptCapture
    assert capture.authoritative is False
    assert tuple(reason.value for reason in capture.snapshot.reason_codes) == (
        "profile_unsupported",
        "live_contract_missing",
    )


def test_t31_errors_and_capture_do_not_disclose_secret_material(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _start(receipt_env, tmp_path)
    monkeypatch.setenv(sessions.ENV_SESSION_TOKEN, "ff" * 16)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    rendered = repr(raised.value) + str(raised.value) + repr(raised.value.details)
    assert TOKEN not in rendered
    assert receipt_env.reference.launch_nonce.value not in rendered
    assert receipt_env.reference.session_id.value not in rendered
    assert str(output) not in rendered


def test_t31_hostile_status_is_redacted_from_diagnostics(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path, name="hostile-status")
    path = output / md.RUN_METADATA_FILE
    meta = load_json(path)
    meta["status"] = str(output) + "\nsecret"
    save_json(path, meta, mode=0o600)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.start_run(output, "scan")
    rendered = str(raised.value)
    assert raised.value.reason is md.RunReceiptReason.REENTRANT_STATUS_MISMATCH
    assert "<redacted>" in rendered
    assert str(output) not in rendered


def test_t32_old_readers_see_projectless_ownerless_metadata(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path)
    meta = load_json(output / md.RUN_METADATA_FILE)
    assert meta["project"] is None
    assert meta["status"] == "running"
    assert "session_pid" not in meta
    assert "tool_pid" not in meta
    assert md.load_run_metadata(output)["status"] == "running"


def test_write_run_pin_refuses_receipt_metadata_without_mutation(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path)
    path = output / md.RUN_METADATA_FILE
    before = path.read_bytes()
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.write_run_pin(output, "named", "adopted")
    assert raised.value.reason is md.RunReceiptReason.PIN_REWRITE_FORBIDDEN
    assert path.read_bytes() == before


def test_t34_managed_project_containment_refuses_before_capture_or_mkdir(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "managed" / "run"
    monkeypatch.setattr(md, "_contention_project_dir", lambda _path: tmp_path)
    monkeypatch.setattr(
        md,
        "_capture_current_run_receipt",
        lambda **_kwargs: pytest.fail("capture ran before project refusal"),
    )
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.start_run(output, "scan")
    assert raised.value.reason is md.RunReceiptReason.PROJECT_FORBIDDEN
    assert not output.exists()


def test_t35_comparison_truthiness_and_ast_are_deny_only() -> None:
    for result in (
        md.RunReceiptComparisonResult.MATCH_NON_AUTHORIZING,
        md.RunReceiptComparisonResult.RESUME_MATCH_NON_AUTHORIZING,
    ):
        comparison = md.RunReceiptComparison(result, None)
        with pytest.raises(TypeError):
            bool(comparison)

    source = Path(md.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        tests: tuple[ast.AST, ...] = ()
        if isinstance(node, (ast.If, ast.While, ast.IfExp, ast.Assert)):
            tests = (node.test,)
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            tests = (node.operand,)
        elif isinstance(node, ast.BoolOp):
            tests = tuple(node.values)
        for test in tests:
            assert not (
                isinstance(test, ast.Name) and test.id in {"comparison", "result"}
            )


def test_lineage_model_is_non_authorizing_and_non_boolean(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path, name="lineage-authority")
    md.resume_run(output)
    strict = md._strict_load_run_metadata(
        output / md.RUN_METADATA_FILE,
        operation="test",
        missing_ok=False,
    )
    assert strict is not None
    parsed = md._parse_receipt_metadata(strict, operation="test")
    assert parsed.lineage is not None
    assert parsed.lineage.authoritative is False
    with pytest.raises(TypeError):
        bool(parsed.lineage)


def test_consumer_lineage_fixture_is_strictly_valid() -> None:
    fields = _valid_exact_lineage_fields()
    head = md._parse_run_receipt_snapshot(
        fields[md.RUN_RUNTIME_RECEIPT_KEY],
        operation="test",
    )
    lineage = md._parse_run_receipt_lineage(
        fields[md.RUN_RUNTIME_RECEIPT_LINEAGE_KEY],
        head=head,
        operation="test",
    )
    assert len(lineage.entries) == 1
    assert lineage.entries[0].relation == "exact"


def test_comparator_emits_resume_relation_only_for_explicit_resume(
    receipt_env: _ReceiptEnvironment,
) -> None:
    audit = md._parse_run_receipt_snapshot(
        json.loads(serialize_snapshot(receipt_env.snapshot)),
        operation="test",
    )
    capture = _generation_capture(1, receipt_env)
    resumed = md.compare_run_runtime_receipt(
        audit,
        capture,
        operation="resume",
        lineage=None,
    )
    assert resumed.result is md.RunReceiptComparisonResult.RESUME_MATCH_NON_AUTHORIZING
    started = md.compare_run_runtime_receipt(
        audit,
        capture,
        operation="start",
        lineage=None,
    )
    assert started.result is md.RunReceiptComparisonResult.LAUNCH_INSTANCE_MISMATCH


def test_t36_legacy_start_and_resume_backstops_prevent_downgrade(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(sessions.ENV_SESSION_PID, raising=False)
    monkeypatch.delenv(sessions.ENV_SESSION_TOKEN, raising=False)
    monkeypatch.setattr(md, "_get_session_pid", lambda: None)
    output = tmp_path / "legacy-race" / "run"
    planted = {
        "version": 2,
        "command": "scan",
        "status": "running",
        md.RUN_RUNTIME_RECEIPT_KEY: {},
    }
    planted_raw: bytes | None = None

    @contextlib.contextmanager
    def racing_lock(path: Path):
        nonlocal planted_raw
        save_json(path, planted, mode=0o600)
        planted_raw = path.read_bytes()
        yield

    monkeypatch.setattr(md, "_metadata_lock", racing_lock)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.start_run(output, "scan")
    assert raised.value.reason is md.RunReceiptReason.RECEIPT_DOWNGRADE_FORBIDDEN
    assert (output / md.RUN_METADATA_FILE).read_bytes() == planted_raw

    legacy = tmp_path / "legacy-resume"
    legacy.mkdir()
    save_json(
        legacy / md.RUN_METADATA_FILE,
        {
            "version": 2,
            "command": "scan",
            "status": "failed",
            "extra": {},
        },
        mode=0o600,
    )

    @contextlib.contextmanager
    def racing_resume_lock(path: Path):
        save_json(path, planted, mode=0o600)
        yield

    monkeypatch.setattr(md, "_metadata_lock", racing_resume_lock)
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(legacy)
    assert raised.value.reason is md.RunReceiptReason.RECEIPT_DOWNGRADE_FORBIDDEN


def test_valid_lineage_cannot_downgrade_into_legacy_resume(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _start(receipt_env, tmp_path, name="lineage-downgrade")
    md.resume_run(output)
    path = output / md.RUN_METADATA_FILE
    before = path.read_bytes()
    monkeypatch.delenv(sessions.ENV_SESSION_PID, raising=False)
    monkeypatch.delenv(sessions.ENV_SESSION_TOKEN, raising=False)
    monkeypatch.setattr(md, "_get_session_pid", lambda: None)

    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.resume_run(output)
    assert raised.value.reason is md.RunReceiptReason.RECEIPT_DOWNGRADE_FORBIDDEN
    assert path.read_bytes() == before


@pytest.mark.skipif(not md._HAS_FCNTL, reason="fcntl unavailable")
def test_t37_strict_and_legacy_metadata_locks_share_one_inode(
    tmp_path: Path,
) -> None:
    output = tmp_path / "lock-inode"
    output.mkdir()
    path = output / md.RUN_METADATA_FILE
    lock_path = output / f"{md.RUN_METADATA_FILE}.lock"
    with md._metadata_lock(path):
        first = lock_path.stat()
        with pytest.raises(md.RunRuntimeReceiptError) as raised:
            with md._strict_metadata_lock(
                path,
                operation="test",
                nonblocking=True,
            ):
                pass
        assert raised.value.reason is md.RunReceiptReason.LOCK_BUSY
    with md._strict_metadata_lock(
        path,
        operation="test",
        nonblocking=True,
    ):
        second = lock_path.stat()
    assert (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def test_exact_snapshot_schema_is_bounded_and_closed(
    receipt_env: _ReceiptEnvironment,
) -> None:
    value = json.loads(serialize_snapshot(receipt_env.snapshot))
    audit = md._parse_run_receipt_snapshot(value, operation="test")
    assert audit.authoritative is False
    assert audit.canonical == serialize_snapshot(receipt_env.snapshot)
    assert set(value) == {
        "schema",
        "schema_version",
        "state",
        "profile_id",
        "stable_identity_sha256",
        "launch_instance_sha256",
        "process_corroboration_sha256",
        "launch_binding_sha256",
        "receipt_sha256",
        "launch_nonce",
        "session_pid",
        "session_starttime_ticks",
        "receipt",
    }


def test_receipt_start_writes_no_ledger_or_checklist(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        md,
        "_setup_checklist_symlink",
        lambda *_args: pytest.fail("receipt start touched checklist wiring"),
    )
    monkeypatch.setattr(
        sessions,
        "ledger_record_start",
        lambda *_args, **_kwargs: pytest.fail("receipt start wrote a ledger"),
    )
    monkeypatch.setattr(
        md,
        "_get_session_pid",
        lambda: pytest.fail("receipt start reached legacy owner resolution"),
    )
    monkeypatch.setattr(
        md,
        "_session_stamp",
        lambda *_args, **_kwargs: pytest.fail(
            "receipt start reached legacy owner stamping"
        ),
    )
    output = _start(receipt_env, tmp_path)
    assert output.is_dir()
    assert not (
        receipt_env.root / f"{receipt_env.reference.session_pid.text}.run"
    ).exists()


def test_named_project_override_is_refused_but_explicit_none_is_recorded(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    from core.run.pin import set_process_project

    set_process_project("named")
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        _start(receipt_env, tmp_path, name="named-project")
    assert raised.value.reason is md.RunReceiptReason.PROJECT_FORBIDDEN

    set_process_project("-")
    output = _start(receipt_env, tmp_path, name="explicit-none")
    meta = load_json(output / md.RUN_METADATA_FILE)
    assert meta["project"] is None
    assert meta["project_source"] == "argv"


def test_strict_metadata_reader_rejects_symlink_and_world_writable_file(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    for shape in ("symlink", "world-writable"):
        output = tmp_path / "runs" / f"metadata-{shape}"
        output.mkdir(parents=True)
        path = output / md.RUN_METADATA_FILE
        if shape == "symlink":
            peer = output / "peer"
            save_json(
                peer,
                {md.RUN_RUNTIME_RECEIPT_KEY: {}},
                mode=0o600,
            )
            path.symlink_to(peer)
        else:
            save_json(
                path,
                {md.RUN_RUNTIME_RECEIPT_KEY: {}},
                mode=0o666,
            )
            path.chmod(0o666)
        with pytest.raises(md.RunRuntimeReceiptError) as raised:
            md.start_run(output, "scan")
        assert raised.value.reason is md.RunReceiptReason.METADATA_INVALID


def test_receipt_metadata_file_is_owner_only(
    receipt_env: _ReceiptEnvironment,
    tmp_path: Path,
) -> None:
    output = _start(receipt_env, tmp_path)
    assert stat.S_IMODE((output / md.RUN_METADATA_FILE).stat().st_mode) == 0o600
