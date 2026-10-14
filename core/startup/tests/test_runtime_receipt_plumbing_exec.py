from __future__ import annotations

import errno
import os
import pickle
import select
import socket
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.json import load_json
from core.project import sessions
from core.run import metadata as run_metadata
from core.startup.runtime_receipt import launch as launch_module
from core.startup.runtime_receipt import profile as profile_module
from core.startup.runtime_receipt.launch import (
    LaunchCancellation,
    LaunchClosed,
    LaunchDisposition,
    LaunchFailure,
    LaunchPhase,
    LaunchReason,
    MonotonicDeadline,
    OwnedFakeLaunchHandle,
    OwnedFakeVerified,
    _close_owned_runtime_fake,
    _finalize_owned_runtime_fake,
    _launch_owned_runtime_fake,
    _owned_runtime_fake_parent_channels,
    _owned_runtime_fake_profile_store,
    _owned_runtime_fake_registry_artifacts,
    _owned_runtime_fake_session_binding,
)
from core.testing.runtime_receipt_fake import (
    FakeDescendantShape,
    FakeReexecMode,
    FakeRuntimeBehavior,
    FakeRuntimeScenario,
    FakeRuntimeUnsupported,
    make_owned_runtime_receipt_fake,
)


@pytest.fixture
def owned_root(monkeypatch: pytest.MonkeyPatch):
    with tempfile.TemporaryDirectory(
        prefix=".raptor-stage3b-exec-",
        dir=Path.home(),
    ) as raw:
        outer = Path(raw)
        outer.chmod(0o700)
        root = outer / "caller-root"
        root.mkdir(mode=0o700)
        guard = outer / "real-sessions"
        guard.mkdir(mode=0o700)
        monkeypatch.setattr(sessions, "SESSIONS_DIR", guard)
        yield root


def _make_bound(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: FakeRuntimeBehavior = FakeRuntimeBehavior(),
):
    before = set(root.iterdir())
    capability = make_owned_runtime_receipt_fake(root, behavior=behavior)
    if isinstance(capability, FakeRuntimeUnsupported):
        pytest.skip(capability.reason)
    created = set(root.iterdir()) - before
    assert len(created) == 1
    bundle = created.pop()
    monkeypatch.setattr(
        sessions,
        "SESSIONS_DIR",
        bundle / "registry/sessions.d",
    )
    return capability, bundle


def _launch(
    capability: object,
    cancellation: LaunchCancellation,
    *,
    seconds: float = 10,
):
    return _launch_owned_runtime_fake(
        capability,
        deadline=MonotonicDeadline.after(seconds),
        cancellation=cancellation,
    )


def _finalize(
    handle: object,
    cancellation: LaunchCancellation,
    *,
    seconds: float = 20,
):
    return _finalize_owned_runtime_fake(
        handle,
        deadline=MonotonicDeadline.after(seconds),
        cancellation=cancellation,
    )


def _fd_set() -> set[int]:
    return {int(item) for item in os.listdir("/proc/self/fd")}


def _wait_past_starttime_tick(starttime_ticks: int) -> None:
    ticks_per_second = os.sysconf("SC_CLK_TCK")
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        uptime = float(Path("/proc/uptime").read_text(encoding="ascii").split()[0])
        if int(uptime * ticks_per_second) > starttime_ticks:
            return
        time.sleep(0.001)
    raise AssertionError("kernel starttime tick did not advance")


def test_two_exec_pending_verified_capture_and_exact_cleanup(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability, bundle = _make_bound(owned_root, monkeypatch)
    with LaunchCancellation() as cancellation:
        before = _fd_set()
        handle = _launch(capability, cancellation)
        assert type(handle) is OwnedFakeLaunchHandle
        assert _owned_runtime_fake_parent_channels(handle) == frozenset(
            {"control", "liveness", "witness"}
        )
        registry = bundle / "registry/sessions.d"
        artifact_names = _owned_runtime_fake_registry_artifacts(handle)
        entry_path = next(item for item in registry.iterdir() if item.name.isdecimal())
        entries_name = entry_path.name
        assert entries_name in artifact_names
        assert f"{entries_name}.run.lock" in artifact_names
        assert f"{entries_name}.receipt.lock" in artifact_names
        entries = [entry_path]
        assert len(entries) == 1
        assert b"host_receipt_state=pending\n" in entries[0].read_bytes()

        verified = _finalize(handle, cancellation)
        assert type(verified) is OwnedFakeVerified
        assert verified.authoritative is False
        assert verified.reason_codes == (
            "profile_unsupported",
            "live_contract_missing",
        )
        assert LaunchPhase.VERIFIED_COMMITTED.value in verified.trace
        assert LaunchPhase.SUPERVISED.value in verified.trace
        assert b"host_receipt_state=verified\n" in entries[0].read_bytes()

        with _owned_runtime_fake_session_binding(handle):
            capture = sessions.capture_current_session_runtime_receipt(
                profiles=_owned_runtime_fake_profile_store(handle),
                now=datetime.now(timezone.utc),
            )
            assert type(capture) is sessions.SessionRuntimeReceiptCapture
            assert capture.authoritative is False
            assert capture.snapshot.authoritative is False
            assert sessions.resolve_session_owner() is None

        closed = _close_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline.after(10),
        )
        assert type(closed) is LaunchClosed
        assert closed.authoritative is False
        assert closed.receipt_removed is True
        assert closed.trace.index(LaunchPhase.GROUP_DRAINED.value) < closed.trace.index(
            LaunchPhase.CHILD_REAPED.value
        )
        assert _fd_set() == before
    assert not bundle.exists()
    assert list(owned_root.iterdir()) == []


def test_two_owned_launches_resume_one_run_with_non_authorizing_lineage(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_registry = owned_root.parent / "projects"
    managed_projects = owned_root.parent / "managed-projects"
    monkeypatch.setattr("core.project.project.PROJECTS_DIR", project_registry)
    monkeypatch.setattr(
        "core.project.project.DEFAULT_OUTPUT_BASE",
        managed_projects,
    )
    monkeypatch.setattr(
        "core.run.provenance.build_start_manifest",
        lambda **_kwargs: {"provenance": "owned-fake-lineage-test"},
    )
    monkeypatch.setattr("core.run.tmp_reaper.reap_stale_tmp", lambda: None)
    monkeypatch.setattr("core.run.tmp_reaper.reap_stale_logs", lambda: None)
    monkeypatch.setattr(
        "core.run.tmp_reaper.reap_stale_runs",
        lambda _parent: [],
    )
    monkeypatch.setattr(
        "core.sandbox.summary.set_active_run_dir",
        lambda _value: None,
    )
    monkeypatch.setattr(
        "core.run.pin.freeze_run_pin",
        lambda *_args, **_kwargs: None,
    )
    from core.run.pin import set_process_project

    set_process_project(None)
    current_profiles = [None]

    def load_current_profiles(_directory=None):
        assert current_profiles[0] is not None
        return current_profiles[0]

    monkeypatch.setattr(
        profile_module,
        "load_profile_store",
        load_current_profiles,
    )

    first_capability, first_bundle = _make_bound(owned_root, monkeypatch)
    first_registry = first_bundle / "registry/sessions.d"
    output = owned_root.parent / "lineage-run"
    with LaunchCancellation() as first_cancellation:
        first_handle = _launch(first_capability, first_cancellation)
        assert type(first_handle) is OwnedFakeLaunchHandle
        first_verified = _finalize(first_handle, first_cancellation)
        assert type(first_verified) is OwnedFakeVerified
        current_profiles[0] = _owned_runtime_fake_profile_store(first_handle)
        monkeypatch.setattr(sessions, "SESSIONS_DIR", first_registry)
        with _owned_runtime_fake_session_binding(first_handle):
            first_capture = sessions.capture_current_session_runtime_receipt(
                profiles=current_profiles[0],
                now=datetime.now(timezone.utc),
            )
            assert type(first_capture) is sessions.SessionRuntimeReceiptCapture
            run_metadata.start_run(output, "scan")

        _wait_past_starttime_tick(first_capture.reference.session_starttime_ticks.value)
        second_capability, second_bundle = _make_bound(owned_root, monkeypatch)
        second_registry = second_bundle / "registry/sessions.d"
        with LaunchCancellation() as second_cancellation:
            second_handle = _launch(second_capability, second_cancellation)
            assert type(second_handle) is OwnedFakeLaunchHandle
            second_verified = _finalize(second_handle, second_cancellation)
            assert type(second_verified) is OwnedFakeVerified
            current_profiles[0] = _owned_runtime_fake_profile_store(second_handle)
            monkeypatch.setattr(sessions, "SESSIONS_DIR", second_registry)
            with _owned_runtime_fake_session_binding(second_handle):
                second_capture = sessions.capture_current_session_runtime_receipt(
                    profiles=current_profiles[0],
                    now=datetime.now(timezone.utc),
                )
                assert type(second_capture) is sessions.SessionRuntimeReceiptCapture
                assert run_metadata.resume_run(output) == 2

            assert (
                first_capture.snapshot.receipt.stable_identity
                == second_capture.snapshot.receipt.stable_identity
            )
            assert (
                first_capture.reference.profile_id
                == second_capture.reference.profile_id
            )
            assert (
                first_capture.reference.session_id
                != second_capture.reference.session_id
            )
            assert (
                first_capture.reference.launch_id != second_capture.reference.launch_id
            )
            assert (
                first_capture.reference.session_pid
                != second_capture.reference.session_pid
            )
            assert (
                first_capture.reference.session_starttime_ticks
                != second_capture.reference.session_starttime_ticks
            )
            assert (
                first_capture.reference.session_token_commitment_sha256
                != second_capture.reference.session_token_commitment_sha256
            )
            assert (
                first_capture.reference.launch_nonce
                != second_capture.reference.launch_nonce
            )
            assert (
                first_capture.reference.launch_instance_sha256
                != second_capture.reference.launch_instance_sha256
            )
            assert (
                first_capture.reference.launch_binding_sha256
                != second_capture.reference.launch_binding_sha256
            )
            assert (
                first_capture.reference.process_corroboration_sha256
                != second_capture.reference.process_corroboration_sha256
            )
            assert (
                first_capture.reference.receipt_sha256
                != second_capture.reference.receipt_sha256
            )

            meta = load_json(output / run_metadata.RUN_METADATA_FILE)
            assert meta["status"] == "running"
            lineage = meta[run_metadata.RUN_RUNTIME_RECEIPT_LINEAGE_KEY]
            assert len(lineage["entries"]) == 1
            assert lineage["entries"][0]["relation"] == ("new_launch_same_stable")
            assert (
                lineage["entries"][0]["current_reference"]["reference"][
                    "receipt_sha256"
                ]
                == second_capture.reference.receipt_sha256.value
            )
            assert sessions.resolve_session_owner() is None

            current_profiles[0] = _owned_runtime_fake_profile_store(first_handle)
            monkeypatch.setattr(sessions, "SESSIONS_DIR", first_registry)
            with _owned_runtime_fake_session_binding(first_handle):
                with pytest.raises(run_metadata.RunRuntimeReceiptError) as raised:
                    run_metadata.resume_run(output)
            assert raised.value.reason is run_metadata.RunReceiptReason.LAUNCH_REPLAY

            monkeypatch.setattr(sessions, "SESSIONS_DIR", second_registry)
            second_closed = _close_owned_runtime_fake(
                second_handle,
                deadline=MonotonicDeadline.after(10),
            )
            assert type(second_closed) is LaunchClosed
            assert second_closed.receipt_removed is True

        monkeypatch.setattr(sessions, "SESSIONS_DIR", first_registry)
        first_closed = _close_owned_runtime_fake(
            first_handle,
            deadline=MonotonicDeadline.after(10),
        )
        assert type(first_closed) is LaunchClosed
        assert first_closed.receipt_removed is True
    set_process_project(None)
    assert not first_bundle.exists()
    assert not second_bundle.exists()


def test_delayed_ready_uses_virtual_clock_not_a_fixed_protocol_limit(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    behavior = FakeRuntimeBehavior(
        scenario=FakeRuntimeScenario.DELAYED_READY,
        ready_delay_seconds=31,
        descendants=FakeDescendantShape.CHILD_AND_GRANDCHILD,
    )
    capability, _bundle = _make_bound(owned_root, monkeypatch, behavior)
    clock = iter((0.0, 31.0, 31.0, 31.0))
    monkeypatch.setattr(
        launch_module,
        "_READY_CLOCK",
        lambda: next(clock, 31.0),
    )
    with LaunchCancellation() as cancellation:
        handle = _launch(capability, cancellation)
        assert type(handle) is OwnedFakeLaunchHandle
        verified = _finalize(handle, cancellation, seconds=5)
        assert type(verified) is OwnedFakeVerified
        closed = _close_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline.after(10),
        )
        assert type(closed) is LaunchClosed
    assert list(owned_root.iterdir()) == []


@pytest.mark.parametrize(
    "shape",
    (
        FakeDescendantShape.NONE,
        FakeDescendantShape.ONE_CHILD,
        FakeDescendantShape.CHILD_AND_GRANDCHILD,
    ),
)
def test_descendant_close_ack_precedes_ready_and_group_drain(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    shape: FakeDescendantShape,
) -> None:
    capability, _bundle = _make_bound(
        owned_root,
        monkeypatch,
        FakeRuntimeBehavior(descendants=shape),
    )
    with LaunchCancellation() as cancellation:
        handle = _launch(capability, cancellation)
        assert type(handle) is OwnedFakeLaunchHandle
        verified = _finalize(handle, cancellation)
        assert type(verified) is OwnedFakeVerified
        closed = _close_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline.after(10),
        )
        assert type(closed) is LaunchClosed
        assert LaunchPhase.READY_OBSERVED.value in closed.trace
        assert LaunchPhase.GROUP_DRAINED.value in closed.trace


@pytest.mark.parametrize(
    ("scenario", "expected_reason", "expected_disposition"),
    (
        (
            FakeRuntimeScenario.ACTIVATION_FAILURE,
            LaunchReason.ACTIVATION_EXEC_FAILED,
            LaunchDisposition.SPAWN_FAILED,
        ),
        (
            FakeRuntimeScenario.EXIT_BEFORE_READY,
            LaunchReason.READY_EOF,
            LaunchDisposition.PROCESS_LOST,
        ),
        (
            FakeRuntimeScenario.EXIT_AFTER_READY,
            LaunchReason.CHILD_EXITED,
            LaunchDisposition.PROCESS_LOST,
        ),
        (
            FakeRuntimeScenario.SKIP_RUNTIME_MODULE,
            LaunchReason.PROCESS_COLLECTION_FAILED,
            LaunchDisposition.COLLECTION_FAILED,
        ),
        (
            FakeRuntimeScenario.EXTRA_DISTRIBUTION_MAPPING,
            LaunchReason.PROCESS_COLLECTION_FAILED,
            LaunchDisposition.COLLECTION_FAILED,
        ),
        (
            FakeRuntimeScenario.WRONG_MODULE_ROLE,
            LaunchReason.READY_MALFORMED,
            LaunchDisposition.PROCESS_LOST,
        ),
        (
            FakeRuntimeScenario.MALFORMED_READY,
            LaunchReason.READY_MALFORMED,
            LaunchDisposition.PROCESS_LOST,
        ),
        (
            FakeRuntimeScenario.DUPLICATE_READY,
            LaunchReason.READY_MALFORMED,
            LaunchDisposition.PROCESS_LOST,
        ),
        (
            FakeRuntimeScenario.CONTROL_EOF,
            LaunchReason.READY_EOF,
            LaunchDisposition.PROCESS_LOST,
        ),
    ),
)
def test_native_protocol_and_mapping_failures_are_typed_and_cleaned(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: FakeRuntimeScenario,
    expected_reason: LaunchReason,
    expected_disposition: LaunchDisposition,
) -> None:
    before = _fd_set()
    capability, bundle = _make_bound(
        owned_root,
        monkeypatch,
        FakeRuntimeBehavior(scenario=scenario),
    )
    record = None
    with LaunchCancellation() as cancellation:
        handle = _launch(capability, cancellation)
        if type(handle) is OwnedFakeLaunchHandle:
            record = launch_module._record_for_handle(handle)
            assert not isinstance(record, LaunchFailure)
            result = _finalize(handle, cancellation)
            first_close = _close_owned_runtime_fake(
                handle,
                deadline=MonotonicDeadline.after(10),
            )
            second_close = _close_owned_runtime_fake(
                handle,
                deadline=MonotonicDeadline.after(10),
            )
            assert type(first_close) is LaunchClosed
            assert second_close is first_close
        else:
            result = handle
    assert type(result) is LaunchFailure
    assert result.disposition is expected_disposition
    assert result.reason_codes == (expected_reason,)
    assert result.phase is LaunchPhase.CLEANED
    assert result.receipt_state == "cleaned"
    assert result.authoritative is False
    if record is not None:
        assert record.child_reaped is True
        assert record.fds_closed is True
        assert not Path(f"/proc/{record.child_pid}").exists()
    assert not bundle.exists()
    assert _fd_set() == before


@pytest.mark.parametrize("unread_data", (False, True))
def test_receive_frame_maps_immediate_eof_and_unread_data_reset(
    unread_data: bool,
) -> None:
    before = _fd_set()
    control, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    control.setblocking(False)
    try:
        if unread_data:
            assert control.send(b"RELEASE_READY") == len(b"RELEASE_READY")
        peer.close()
        record = SimpleNamespace(control=control)
        with pytest.raises(EOFError) as caught:
            launch_module._receive_frame(record)
        if unread_data:
            assert isinstance(caught.value.__cause__, ConnectionResetError)
            assert caught.value.__cause__.errno == errno.ECONNRESET
        else:
            assert caught.value.__cause__ is None
    finally:
        control.close()
        peer.close()
    assert _fd_set() == before


@pytest.mark.parametrize(
    "error_number",
    tuple(sorted(launch_module._CONTROL_CHANNEL_EOF_ERRNOS)),
)
def test_receive_frame_maps_only_enumerated_transport_resets(
    error_number: int,
) -> None:
    class RaisingControl:
        def recv(self, _size: int, _flags: int = 0) -> bytes:
            raise OSError(error_number, os.strerror(error_number))

    record = SimpleNamespace(control=RaisingControl())
    with pytest.raises(EOFError) as caught:
        launch_module._receive_frame(record)
    assert isinstance(caught.value.__cause__, OSError)
    assert caught.value.__cause__.errno == error_number


def test_receive_frame_retries_eintr_and_preserves_unrelated_errors() -> None:
    record = SimpleNamespace(
        child_pid=123,
        parent_pid=456,
        process_group=123,
        control=None,
    )
    ready = launch_module._frame_bytes(launch_module._FrameType.READY, record)

    class ScriptedControl:
        def __init__(self, outcomes: list[bytes | BaseException]) -> None:
            self.outcomes = outcomes
            self.calls = 0

        def recv(self, _size: int, _flags: int = 0) -> bytes:
            outcome = self.outcomes[self.calls]
            self.calls += 1
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

    interrupted = ScriptedControl([InterruptedError(errno.EINTR, "interrupted"), ready])
    record.control = interrupted
    assert launch_module._receive_frame(record) == (
        launch_module._FrameType.READY,
        0,
        0,
        0,
    )
    assert interrupted.calls == 2

    unrelated = ScriptedControl([OSError(errno.EIO, "unrelated")])
    record.control = unrelated
    with pytest.raises(OSError) as caught:
        launch_module._receive_frame(record)
    assert caught.value.errno == errno.EIO


def test_post_frame_scope_change_while_alive_remains_binding_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _fd_set()
    control, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    control.setblocking(False)
    expected = launch_module._ProcessIdentity(
        pid=123,
        parent_pid=456,
        process_group=123,
        starttime_ticks=1,
        boot_id="boot",
        pid_namespace_inode=1,
        mount_namespace_inode=2,
        euid=os.geteuid(),
        executable_device=3,
        executable_inode=4,
        executable_size=5,
        executable_sha256="0" * 64,
    )
    observed = replace(expected, starttime_ticks=2)
    record = SimpleNamespace(
        control=control,
        child_reaped=False,
        child_pid=expected.pid,
        parent_pid=expected.parent_pid,
        phase=LaunchPhase.ACTIVATION_EXEC_CONFIRMED,
        current_receipt=None,
        trace=[],
        capability=object(),
        process_identity=expected,
    )
    events: list[str] = []
    try:
        monkeypatch.setattr(
            launch_module,
            "_child_waitable",
            lambda _record: events.append("alive") or False,
        )
        monkeypatch.setattr(
            launch_module,
            "_capture_process_identity",
            lambda *_args, **_kwargs: events.append("identity") or observed,
        )
        monkeypatch.setattr(
            launch_module,
            "_process_matches_primary",
            lambda *_args: True,
        )
        result = launch_module._post_frame_process_check(
            record,
            establish_identity=False,
            control_eof_reason=LaunchReason.READY_EOF,
        )
        assert type(result) is LaunchFailure
        assert result.disposition is LaunchDisposition.BINDING_FAILED
        assert result.reason_codes == (LaunchReason.PROCESS_SCOPE_CHANGED,)
        assert events == ["alive", "identity", "alive"]
    finally:
        control.close()
        peer.close()
    assert _fd_set() == before


def test_512_control_termination_precedence_schedules_under_contention() -> None:
    before = _fd_set()

    def exercise(seed: int) -> tuple[LaunchDisposition, tuple[LaunchReason, ...]]:
        control, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        control.setblocking(False)
        try:
            if seed % 2:
                assert control.send(b"RELEASE_READY") == len(b"RELEASE_READY")
            peer.close()
            record = SimpleNamespace(
                control=control,
                child_reaped=True,
                phase=LaunchPhase.ACTIVATION_EXEC_CONFIRMED,
                current_receipt=None,
                trace=[],
            )
            result = launch_module._control_or_child_failure(
                record,
                control_eof_reason=LaunchReason.READY_EOF,
            )
            assert type(result) is LaunchFailure
            return result.disposition, result.reason_codes
        finally:
            control.close()
            peer.close()

    with ThreadPoolExecutor(max_workers=12) as executor:
        outcomes = tuple(executor.map(exercise, range(512)))
    assert set(outcomes) == {
        (LaunchDisposition.PROCESS_LOST, (LaunchReason.READY_EOF,))
    }
    assert _fd_set() == before


def test_reset_during_finalize_is_typed_clean_and_idempotent(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ResetOnReceiveControl:
        def __init__(self, wrapped: socket.socket) -> None:
            self.wrapped = wrapped
            self.recv_calls = 0

        def fileno(self) -> int:
            return self.wrapped.fileno()

        def send(self, data: bytes) -> int:
            return self.wrapped.send(data)

        def recv(self, _size: int, _flags: int = 0) -> bytes:
            self.recv_calls += 1
            raise ConnectionResetError(errno.ECONNRESET, "reset by peer")

        def close(self) -> None:
            self.wrapped.close()

    before = _fd_set()
    capability, bundle = _make_bound(owned_root, monkeypatch)
    with LaunchCancellation() as cancellation:
        handle = _launch(capability, cancellation)
        assert type(handle) is OwnedFakeLaunchHandle
        record = launch_module._record_for_handle(handle)
        assert not isinstance(record, LaunchFailure)
        child_pid = record.child_pid
        reset_control = ResetOnReceiveControl(record.control)
        record.control = reset_control

        result = _finalize(handle, cancellation)
        assert type(result) is LaunchFailure
        assert result.disposition is LaunchDisposition.PROCESS_LOST
        assert result.reason_codes == (LaunchReason.READY_EOF,)
        assert result.phase is LaunchPhase.CLEANED
        assert result.receipt_state == "cleaned"
        assert result.authoritative is False
        assert reset_control.recv_calls >= 1
        assert record.child_reaped is True
        assert record.fds_closed is True

        first_close = _close_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline.after(10),
        )
        second_close = _close_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline.after(10),
        )
        assert type(first_close) is LaunchClosed
        assert second_close is first_close
    assert not Path(f"/proc/{child_pid}").exists()
    assert not bundle.exists()
    assert _fd_set() == before


@pytest.mark.parametrize(
    "mode",
    (
        FakeReexecMode.SAME_BEFORE_CAS,
        FakeReexecMode.DIFFERENT_BEFORE_CAS,
        FakeReexecMode.SAME_AFTER_CAS,
        FakeReexecMode.DIFFERENT_AFTER_CAS,
    ),
)
def test_same_and_different_image_reexec_are_rejected_before_cleanup(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: FakeReexecMode,
) -> None:
    capability, bundle = _make_bound(
        owned_root,
        monkeypatch,
        FakeRuntimeBehavior(reexec=mode),
    )
    with LaunchCancellation() as cancellation:
        handle = _launch(capability, cancellation)
        assert type(handle) is OwnedFakeLaunchHandle
        result = _finalize(handle, cancellation)
    assert type(result) is LaunchFailure
    expected = (
        LaunchReason.DIFFERENT_IMAGE_REEXEC
        if "DIFFERENT" in mode.name
        else LaunchReason.SAME_IMAGE_REEXEC_OR_WITNESS_LOSS
    )
    assert result.reason_codes[0] is expected
    assert LaunchPhase.REJECTED_COMMITTED.value in result.trace
    if "AFTER" in mode.name:
        assert result.trace.index(
            LaunchPhase.VERIFIED_COMMITTED.value
        ) < result.trace.index(LaunchPhase.REJECTED_COMMITTED.value)
    else:
        assert LaunchPhase.VERIFIED_COMMITTED.value not in result.trace
    assert not bundle.exists()


def test_timeout_and_cancellation_fail_closed_and_allow_cleanup_retry(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability, _bundle = _make_bound(
        owned_root,
        monkeypatch,
        FakeRuntimeBehavior(
            scenario=FakeRuntimeScenario.DELAYED_READY,
            ready_delay_seconds=31,
        ),
    )
    with LaunchCancellation() as cancellation:
        handle = _launch(capability, cancellation)
        assert type(handle) is OwnedFakeLaunchHandle
        timed_out = _finalize_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline(time.monotonic() + 0.01),
            cancellation=cancellation,
        )
        assert type(timed_out) is LaunchFailure
        assert timed_out.reason_codes[0] is LaunchReason.DEADLINE_EXCEEDED
        closed = _close_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline.after(10),
        )
        assert type(closed) is LaunchClosed

    capability, _bundle = _make_bound(
        owned_root,
        monkeypatch,
        FakeRuntimeBehavior(
            scenario=FakeRuntimeScenario.DELAYED_READY,
            ready_delay_seconds=31,
        ),
    )
    with LaunchCancellation() as cancellation:
        handle = _launch(capability, cancellation)
        assert type(handle) is OwnedFakeLaunchHandle
        cancellation.cancel()
        cancelled = _finalize(handle, cancellation)
        assert type(cancelled) is LaunchFailure
        assert cancelled.reason_codes[0] is LaunchReason.CANCELLED
    assert list(owned_root.iterdir()) == []


def test_proc_unavailable_builds_rejected_receipt_and_cleans(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability, bundle = _make_bound(owned_root, monkeypatch)
    unavailable = launch_module._collection_failure(
        launch_module._CollectionDisposition.UNAVAILABLE,
        launch_module._CollectionReasonCode.PROC_MAPS_UNAVAILABLE,
        subject=launch_module._EvidenceSubject.PROCESS,
        details={"stage": "test"},
    )
    monkeypatch.setattr(
        launch_module,
        "collect_linux_process_evidence",
        lambda *_args, **_kwargs: unavailable,
    )
    with LaunchCancellation() as cancellation:
        handle = _launch(capability, cancellation)
        assert type(handle) is OwnedFakeLaunchHandle
        result = _finalize(handle, cancellation)
    assert type(result) is LaunchFailure
    assert result.reason_codes[0] is LaunchReason.PROCESS_COLLECTION_FAILED
    assert LaunchPhase.REJECTED_COMMITTED.value in result.trace
    assert not bundle.exists()


@pytest.mark.parametrize("target", ("loader", "distribution"))
def test_loader_and_distribution_replacement_fail_closed(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    capability, bundle = _make_bound(owned_root, monkeypatch)
    fired = False

    def replace_after_ready(phase: LaunchPhase, handle_id: str) -> None:
        nonlocal fired
        del handle_id
        if phase is not LaunchPhase.READY_OBSERVED or fired:
            return
        fired = True
        if target == "loader":
            primary = bundle / "bin/owned-runtime-host"
            primary.rename(bundle / "bin/owned-runtime-host-original")
            primary.write_bytes((bundle / "bin/owned-runtime-host-alt").read_bytes())
            primary.chmod(0o500)
        else:
            path = bundle / "dist/app.js"
            path.chmod(0o600)
            path.write_bytes(b"replacement\n")
            path.chmod(0o400)

    monkeypatch.setattr(launch_module, "_phase_hook", replace_after_ready)
    with LaunchCancellation() as cancellation:
        handle = _launch(capability, cancellation)
        assert type(handle) is OwnedFakeLaunchHandle
        result = _finalize(handle, cancellation)
    assert type(result) is LaunchFailure
    assert result.reason_codes[0] in {
        LaunchReason.STABLE_COLLECTION_FAILED,
        LaunchReason.STABLE_EVIDENCE_CHANGED,
        LaunchReason.PROCESS_SCOPE_CHANGED,
    }
    record = launch_module._record_for_handle(handle)
    assert not isinstance(record, LaunchFailure)
    assert record.child_reaped is True
    assert record.fds_closed is True


def test_registry_root_is_rechecked_before_final_cas_and_cleanup_can_retry(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability, bundle = _make_bound(owned_root, monkeypatch)
    correct_root = bundle / "registry/sessions.d"
    wrong_root = owned_root.parent / "replacement-sessions"
    wrong_root.mkdir(mode=0o700)
    with LaunchCancellation() as cancellation:
        handle = _launch(capability, cancellation)
        assert type(handle) is OwnedFakeLaunchHandle
        monkeypatch.setattr(sessions, "SESSIONS_DIR", wrong_root)
        result = _finalize(handle, cancellation)
        assert type(result) is LaunchFailure
        assert LaunchReason.REGISTRY_ROOT_MISMATCH in result.reason_codes
        monkeypatch.setattr(sessions, "SESSIONS_DIR", correct_root)
        closed = _close_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline.after(10),
        )
        assert type(closed) is LaunchClosed
    assert not bundle.exists()


def test_supervisor_loss_kills_owned_runtime_and_leaves_no_verifiable_recovery(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_fd, write_fd = os.pipe()
    supervisor_pid = os.fork()
    if supervisor_pid == 0:
        os.close(read_fd)
        capability = make_owned_runtime_receipt_fake(owned_root)
        if isinstance(capability, FakeRuntimeUnsupported):
            os.write(write_fd, f"unsupported:{capability.reason}".encode("ascii"))
            os.close(write_fd)
            os._exit(0)
        bundle = next(owned_root.iterdir())
        sessions.SESSIONS_DIR = bundle / "registry/sessions.d"
        with LaunchCancellation() as cancellation:
            handle = _launch(capability, cancellation)
        if not isinstance(handle, OwnedFakeLaunchHandle):
            os.write(write_fd, b"launch-failed")
            os.close(write_fd)
            os._exit(1)
        record = launch_module._record_for_handle(handle)
        assert not isinstance(record, LaunchFailure)
        payload = f"{bundle.name}\n{record.child_pid}\n".encode("ascii")
        os.write(write_fd, payload)
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    raw = bytearray()
    while True:
        chunk = os.read(read_fd, 4096)
        if not chunk:
            break
        raw.extend(chunk)
    os.close(read_fd)
    waited, status = os.waitpid(supervisor_pid, 0)
    assert waited == supervisor_pid
    assert os.WIFEXITED(status)
    text = raw.decode("ascii")
    if text.startswith("unsupported:"):
        pytest.skip(text.partition(":")[2])
    bundle_name, pid_text = text.splitlines()
    native_pid = int(pid_text)
    try:
        pidfd = os.pidfd_open(native_pid)
    except ProcessLookupError:
        pidfd = -1
    if pidfd >= 0:
        poller = select.poll()
        poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        assert poller.poll(5000)
        os.close(pidfd)
    expires = time.monotonic() + 5
    while Path(f"/proc/{native_pid}").exists() and time.monotonic() < expires:
        select.select((), (), (), 0.01)
    assert not Path(f"/proc/{native_pid}").exists()
    bundle = owned_root / bundle_name
    registry = bundle / "registry/sessions.d"
    monkeypatch.setattr(sessions, "SESSIONS_DIR", registry)
    entry = next(path for path in registry.iterdir() if path.name.isdecimal())
    assert b"host_receipt_state=pending\n" in entry.read_bytes()
    assert sessions.resolve_session_owner() is None


def test_session_takeover_is_never_overwritten_or_removed(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability, bundle = _make_bound(owned_root, monkeypatch)
    registry = bundle / "registry/sessions.d"
    with LaunchCancellation() as cancellation:
        handle = _launch(capability, cancellation)
        assert type(handle) is OwnedFakeLaunchHandle
        entry = next(item for item in registry.iterdir() if item.name.isdecimal())
        original = entry.read_bytes()
        replacement = b"replacement-owned-by-another-finalizer\n"
        fired = False

        def replace_entry(_pid: int, _fd: int) -> None:
            nonlocal fired
            if not fired:
                fired = True
                entry.write_bytes(replacement)
                entry.chmod(0o600)

        monkeypatch.setattr(sessions, "_after_session_lock_open", replace_entry)
        result = _finalize(handle, cancellation)
        assert type(result) is LaunchFailure
        assert LaunchReason.SESSION_REPLACED in result.reason_codes
        assert entry.read_bytes() == replacement
        monkeypatch.setattr(sessions, "_after_session_lock_open", lambda *_args: None)
        entry.write_bytes(original)
        entry.chmod(0o600)
        closed = _close_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline.after(10),
        )
        assert type(closed) is LaunchClosed


def test_concurrent_finalizer_loser_is_non_destructive(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability, _bundle = _make_bound(owned_root, monkeypatch)
    entered = threading.Event()
    release = threading.Event()
    original_hook = launch_module._phase_hook

    def blocking_hook(phase: LaunchPhase, handle_id: str) -> None:
        del handle_id
        if phase is LaunchPhase.READY_OBSERVED:
            entered.set()
            assert release.wait(timeout=10)

    monkeypatch.setattr(launch_module, "_phase_hook", blocking_hook)
    with LaunchCancellation() as cancellation:
        handle = _launch(capability, cancellation)
        assert type(handle) is OwnedFakeLaunchHandle
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_finalize, handle, cancellation)
            assert entered.wait(timeout=10)
            loser = _finalize(handle, cancellation)
            assert type(loser) is LaunchFailure
            assert loser.disposition is LaunchDisposition.STATE_CONFLICT
            release.set()
            winner = future.result(timeout=20)
        assert type(winner) is OwnedFakeVerified
        monkeypatch.setattr(launch_module, "_phase_hook", original_hook)
        closed = _close_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline.after(10),
        )
        assert type(closed) is LaunchClosed


def test_cleanup_failure_retains_bundle_and_same_handle_retries(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability, bundle = _make_bound(owned_root, monkeypatch)
    with LaunchCancellation() as cancellation:
        handle = _launch(capability, cancellation)
        assert type(handle) is OwnedFakeLaunchHandle
        assert type(_finalize(handle, cancellation)) is OwnedFakeVerified
        unexpected = bundle / "registry/sessions.d/unexpected"
        unexpected.write_bytes(b"x")
        unexpected.chmod(0o600)
        failed = _close_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline.after(10),
        )
        assert type(failed) is LaunchFailure
        assert LaunchReason.BUNDLE_CLEANUP_FAILED in failed.reason_codes
        assert unexpected.exists()
        unexpected.unlink()
        closed = _close_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline.after(10),
        )
        assert type(closed) is LaunchClosed
    assert not bundle.exists()


def test_setpgid_eacces_fallback_and_mismatch_never_signal_group(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def eacces(_pid: int, _pgid: int) -> None:
        raise OSError(errno.EACCES, "raced exec")

    original_setpgid = launch_module.os.setpgid
    original_getpgid = launch_module.os.getpgid
    monkeypatch.setattr(launch_module.os, "setpgid", eacces)
    monkeypatch.setattr(launch_module.os, "getpgid", lambda pid: pid)
    assert launch_module._set_parent_process_group(1234) is True
    monkeypatch.setattr(launch_module.os, "setpgid", original_setpgid)
    monkeypatch.setattr(launch_module.os, "getpgid", original_getpgid)

    capability, _bundle = _make_bound(owned_root, monkeypatch)
    monkeypatch.setattr(
        launch_module,
        "_set_parent_process_group",
        lambda _pid: False,
    )
    killpg_calls: list[tuple[int, int]] = []
    monkeypatch.setattr(
        launch_module.os,
        "killpg",
        lambda pgid, signum: killpg_calls.append((pgid, signum)),
    )
    with LaunchCancellation() as cancellation:
        result = _launch(capability, cancellation)
    assert type(result) is LaunchFailure
    assert result.reason_codes[0] is LaunchReason.PROCESS_GROUP_MISMATCH
    assert killpg_calls == []


def test_result_types_are_redacted_non_authorizing_and_non_pickleable(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability, bundle = _make_bound(owned_root, monkeypatch)
    with LaunchCancellation() as cancellation:
        handle = _launch(capability, cancellation)
        assert type(handle) is OwnedFakeLaunchHandle
        verified = _finalize(handle, cancellation)
        assert type(verified) is OwnedFakeVerified
        closed = _close_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline.after(10),
        )
        assert type(closed) is LaunchClosed
    with LaunchCancellation() as invalid_cancellation:
        failure = _launch_owned_runtime_fake(
            object(),
            deadline=MonotonicDeadline.after(1),
            cancellation=invalid_cancellation,
        )
    assert type(failure) is LaunchFailure
    for value in (handle, verified, closed, failure):
        with pytest.raises(TypeError):
            bool(value)
        with pytest.raises(TypeError):
            pickle.dumps(value)
        text = repr(value)
        assert str(bundle) not in text
        assert "token" not in text.lower()
        assert "frame" not in text.lower()
    for base in (
        OwnedFakeLaunchHandle,
        OwnedFakeVerified,
        LaunchClosed,
        LaunchFailure,
    ):
        with pytest.raises(TypeError):
            type("ForbiddenSubclass", (base,), {})


def test_512_seeded_state_and_protocol_interleavings_fail_closed(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability, _bundle = _make_bound(owned_root, monkeypatch)
    with LaunchCancellation() as cancellation:
        handle = _launch(capability, cancellation)
        assert type(handle) is OwnedFakeLaunchHandle
        record = launch_module._record_for_handle(handle)
        assert not isinstance(record, LaunchFailure)
        for seed in range(512):
            bucket = seed // 64
            if bucket == 0:
                raw = bytearray(
                    launch_module._frame_bytes(
                        launch_module._FrameType.RELEASE_READY,
                        record,
                    )
                )
                raw[0] ^= 1
                with pytest.raises(ValueError):
                    launch_module._decode_frame(bytes(raw), record)
            elif bucket == 1:
                raw = launch_module._frame_bytes(
                    launch_module._FrameType.RELEASE_READY,
                    record,
                )
                with pytest.raises(ValueError):
                    launch_module._decode_frame(raw[:-1], record)
            elif bucket == 2:
                forged = object.__new__(OwnedFakeLaunchHandle)
                object.__setattr__(forged, "_handle_id", handle._handle_id)
                object.__setattr__(forged, "_handle_mac", handle._handle_mac)
                object.__setattr__(forged, "_handle_mac", "0" * 64)
                assert isinstance(
                    launch_module._record_for_handle(forged),
                    LaunchFailure,
                )
            elif bucket == 3:
                diagnostics = launch_module._bounded_diagnostics(
                    {
                        "stage": "seed",
                        "reason": "x" * (seed % 129),
                        "token": "0" * 32,
                    }
                )
                assert len(diagnostics) <= 2
                assert "token" not in diagnostics
            elif bucket == 4:
                with LaunchCancellation() as local:
                    local.cancel()
                    local.cancel()
                    assert launch_module._cancelled(local)
            elif bucket == 5:
                with launch_module._STATE_LOCK:
                    record.operation = "stress"
                conflict = launch_module._claim_operation(handle, "finalize")
                assert type(conflict) is LaunchFailure
                with launch_module._STATE_LOCK:
                    record.operation = None
            elif bucket == 6:
                assert launch_module._witness_state(record) == "open"
            else:
                assert launch_module._registry_matches(record.capability)
        closed = _close_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline.after(10),
        )
        assert type(closed) is LaunchClosed
