from __future__ import annotations

import array
import ast
import copy
import dataclasses
import errno
import fcntl
import hashlib
import inspect
import os
import pickle
import random
import select
import socket
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from core.project import sessions
from core.startup.runtime_receipt import launch as launch_module
from core.startup.runtime_receipt import terminal as terminal_module
from core.startup.runtime_receipt.launch import (
    LaunchCancellation,
    LaunchClosed,
    LaunchFailure,
    MonotonicDeadline,
    OwnedFakeLaunchHandle,
    OwnedFakeVerified,
    _close_owned_runtime_fake,
    _finalize_owned_runtime_fake,
    _launch_owned_runtime_fake,
)
from core.startup.runtime_receipt.terminal import (
    OwnedFakeTerminalCapability,
    OwnedFakeTerminalFailure,
    OwnedFakeTerminalResult,
    TerminalDisposition,
    TerminalPhase,
    TerminalReason,
    _apply_owned_fake_terminal_capability,
)
from core.testing.runtime_receipt_fake import (
    FakeDescendantShape,
    FakeRuntimeBehavior,
    FakeRuntimeUnsupported,
    make_owned_runtime_receipt_fake,
)
from core.testing.runtime_receipt_terminal import (
    FakeTerminalEvent,
    FakeTerminalPlan,
    FakeTerminalSequence,
    make_owned_fake_terminal_capability,
)

_ACCEPTED_W1J_METADATA_SHA256 = (
    "798068c724ac33fde467826747902e297ee7cf01fd5275b178e64c314ce79423"
)


@pytest.fixture
def owned_root(monkeypatch: pytest.MonkeyPatch):
    with tempfile.TemporaryDirectory(
        prefix=".raptor-terminal-k1-",
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


def _fd_set() -> set[int]:
    return {int(item) for item in os.listdir("/proc/self/fd")}


@pytest.fixture(autouse=True)
def no_terminal_descriptor_leak():
    before = _fd_set()
    yield
    assert _fd_set() == before


def _process_fd_count(pid: int) -> int:
    return len(tuple(Path(f"/proc/{pid}/fd").iterdir()))


def _wait_for_process_fd_count(pid: int, maximum: int) -> None:
    expires = time.monotonic() + 2
    while time.monotonic() < expires:
        try:
            if _process_fd_count(pid) <= maximum:
                return
        except FileNotFoundError:
            return
        select.select((), (), (), 0.005)
    raise AssertionError("owned fake retained an unexpected descriptor")


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


def _launch_verified(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: FakeRuntimeBehavior = FakeRuntimeBehavior(),
) -> tuple[Path, OwnedFakeLaunchHandle, LaunchCancellation]:
    capability, bundle = _make_bound(root, monkeypatch, behavior)
    cancellation = LaunchCancellation()
    handle = _launch_owned_runtime_fake(
        capability,
        deadline=MonotonicDeadline.after(10),
        cancellation=cancellation,
    )
    assert type(handle) is OwnedFakeLaunchHandle
    verified = _finalize_owned_runtime_fake(
        handle,
        deadline=MonotonicDeadline.after(20),
        cancellation=cancellation,
    )
    assert type(verified) is OwnedFakeVerified
    return bundle, handle, cancellation


def _close_launch(
    bundle: Path,
    handle: OwnedFakeLaunchHandle,
    cancellation: LaunchCancellation,
) -> None:
    closed = _close_owned_runtime_fake(
        handle,
        deadline=MonotonicDeadline.after(10),
    )
    cancellation.close()
    assert type(closed) is LaunchClosed
    assert closed.receipt_removed is True
    assert not bundle.exists()


def _registry_snapshot(bundle: Path) -> dict[str, bytes]:
    registry = bundle / "registry/sessions.d"
    return {
        path.relative_to(registry).as_posix(): path.read_bytes()
        for path in sorted(registry.rglob("*"))
        if path.is_file()
    }


def _terminal_record(
    capability: OwnedFakeTerminalCapability,
) -> terminal_module._TerminalRecord:
    with terminal_module._STATE_LOCK:
        record = terminal_module._CAPABILITIES[capability._capability_id]
        assert record.capability_object is capability
        return record


def _apply(
    capability: object,
    cancellation: LaunchCancellation,
    *,
    seconds: float = 5,
) -> OwnedFakeTerminalResult | OwnedFakeTerminalFailure:
    return _apply_owned_fake_terminal_capability(
        capability,
        deadline=MonotonicDeadline.after(seconds),
        cancellation=cancellation,
    )


def _send_control_attach(
    handle: OwnedFakeLaunchHandle,
    descriptors: list[int],
) -> tuple[launch_module._HandleRecord, tuple[launch_module._HandleRecord, bool]]:
    launch_record = launch_module._record_for_handle(handle)
    assert not isinstance(launch_record, LaunchFailure)
    claimed = launch_module._claim_operation(handle, "terminal")
    assert not isinstance(claimed, LaunchFailure)
    assert claimed == (launch_record, True)
    raw = launch_module._frame_bytes(
        launch_module._FrameType.TERMINAL_ATTACH,
        launch_record,
        argument0=FakeTerminalEvent.COMPLETE.value,
        argument1=FakeTerminalSequence.IMMEDIATE.value,
        argument2=0,
    )
    ancillary = []
    if descriptors:
        ancillary.append(
            (
                socket.SOL_SOCKET,
                socket.SCM_RIGHTS,
                array.array("i", descriptors),
            )
        )
    assert launch_record.control.sendmsg([raw], ancillary) == len(raw)
    return launch_record, claimed


def _receive_control_error(
    launch_record: launch_module._HandleRecord,
) -> tuple[launch_module._FrameType, int, int, int]:
    poller = select.poll()
    poller.register(
        launch_record.control.fileno(),
        select.POLLIN | select.POLLHUP | select.POLLERR,
    )
    assert poller.poll(5000)
    frame = launch_module._receive_frame(launch_record)
    assert frame is not None
    return frame


def test_plan_and_issuer_surface_are_closed() -> None:
    signature = inspect.signature(make_owned_fake_terminal_capability)
    assert tuple(signature.parameters) == ("handle", "plan")
    assert signature.parameters["plan"].kind is inspect.Parameter.KEYWORD_ONLY

    for event in FakeTerminalEvent:
        assert FakeTerminalPlan(event).event is event
    assert (
        FakeTerminalPlan(
            FakeTerminalEvent.COMPLETE,
            FakeTerminalSequence.BACKGROUND_DRAIN,
            1,
        ).work_count
        == 1
    )
    with pytest.raises(TypeError):
        FakeTerminalPlan("complete")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        FakeTerminalPlan(FakeTerminalEvent.COMPLETE, 1)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        FakeTerminalPlan(
            FakeTerminalEvent.COMPLETE,
            FakeTerminalSequence.BACKGROUND_DRAIN,
            0,
        )
    with pytest.raises(ValueError):
        FakeTerminalPlan(FakeTerminalEvent.COMPLETE, work_count=1)
    with pytest.raises(TypeError):
        make_owned_fake_terminal_capability(
            object(),
            plan=object(),  # type: ignore[arg-type]
        )


def test_capability_is_opaque_noncopyable_unforgeable_and_single_use(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _fd_set()
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    record = _terminal_record(capability)
    launch_record = launch_module._record_for_handle(handle)
    assert not isinstance(launch_record, LaunchFailure)
    assert launch_record.current_receipt is not None

    with pytest.raises(TypeError):
        OwnedFakeTerminalCapability()
    with pytest.raises(TypeError):
        bool(capability)
    with pytest.raises(TypeError):
        copy.copy(capability)
    with pytest.raises(TypeError):
        copy.deepcopy(capability)
    with pytest.raises(TypeError):
        pickle.dumps(capability)
    with pytest.raises(TypeError):
        type("ForbiddenTerminalCapability", (OwnedFakeTerminalCapability,), {})
    with pytest.raises(dataclasses.FrozenInstanceError):
        capability._capability_id = "0" * 32  # type: ignore[misc]

    text = repr(capability)
    for secret in (
        capability._capability_id,
        capability._capability_mac,
        record.event_nonce.hex(),
        str(bundle),
        str(launch_record.child_pid),
        launch_record.token_hex,
        launch_record.current_receipt.reference.receipt_sha256.value,
    ):
        assert secret not in text

    forged = object.__new__(OwnedFakeTerminalCapability)
    object.__setattr__(forged, "_capability_id", capability._capability_id)
    object.__setattr__(forged, "_capability_mac", capability._capability_mac)
    rejected = _apply(forged, cancellation)
    assert type(rejected) is OwnedFakeTerminalFailure
    assert rejected.reason_codes == (TerminalReason.INVALID_CAPABILITY,)

    original_id = capability._capability_id
    object.__setattr__(capability, "_capability_id", "0" * 32)
    mutated = _apply(capability, cancellation)
    assert type(mutated) is OwnedFakeTerminalFailure
    assert mutated.reason_codes == (TerminalReason.INVALID_CAPABILITY,)
    object.__setattr__(capability, "_capability_id", original_id)

    original_mac = capability._capability_mac
    object.__setattr__(capability, "_capability_mac", "0" * 64)
    mutated = _apply(capability, cancellation)
    assert type(mutated) is OwnedFakeTerminalFailure
    assert mutated.reason_codes == (TerminalReason.INVALID_CAPABILITY,)
    object.__setattr__(capability, "_capability_mac", original_mac)

    with terminal_module._STATE_LOCK:
        removed = terminal_module._CAPABILITIES.pop(capability._capability_id)
    missing = _apply(capability, cancellation)
    assert type(missing) is OwnedFakeTerminalFailure
    assert missing.reason_codes == (TerminalReason.INVALID_CAPABILITY,)
    with terminal_module._STATE_LOCK:
        terminal_module._CAPABILITIES[capability._capability_id] = removed

    result = _apply(capability, cancellation)
    assert type(result) is OwnedFakeTerminalResult
    assert _apply(capability, cancellation) is result
    assert result.authoritative is False
    for value in (rejected, mutated, missing, result):
        with pytest.raises(TypeError):
            bool(value)
        with pytest.raises(TypeError):
            pickle.dumps(value)
        rendered = repr(value) + str(value)
        assert launch_record.current_receipt is not None
        for secret in (
            capability._capability_id,
            capability._capability_mac,
            record.event_nonce.hex(),
            str(bundle),
            str(launch_record.child_pid),
            launch_record.token_hex,
            launch_record.current_receipt.reference.receipt_sha256.value,
        ):
            assert secret not in rendered
    for base in (OwnedFakeTerminalResult, OwnedFakeTerminalFailure):
        with pytest.raises(TypeError):
            type("ForbiddenTerminalResult", (base,), {})
    _close_launch(bundle, handle, cancellation)
    assert _fd_set() == before


def test_issuance_requires_exact_verified_idle_handle_and_registry(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _fd_set()
    launch_capability, bundle = _make_bound(owned_root, monkeypatch)
    cancellation = LaunchCancellation()
    handle = _launch_owned_runtime_fake(
        launch_capability,
        deadline=MonotonicDeadline.after(10),
        cancellation=cancellation,
    )
    assert type(handle) is OwnedFakeLaunchHandle

    premature = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(premature) is OwnedFakeTerminalFailure
    assert premature.reason_codes == (TerminalReason.LAUNCH_NOT_SUPERVISED,)

    verified = _finalize_owned_runtime_fake(
        handle,
        deadline=MonotonicDeadline.after(20),
        cancellation=cancellation,
    )
    assert type(verified) is OwnedFakeVerified
    launch_record = launch_module._record_for_handle(handle)
    assert not isinstance(launch_record, LaunchFailure)
    claimed = launch_module._claim_operation(handle, "terminal")
    assert not isinstance(claimed, LaunchFailure)
    try:
        busy = make_owned_fake_terminal_capability(
            handle,
            plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
        )
        assert type(busy) is OwnedFakeTerminalFailure
        assert busy.reason_codes == (TerminalReason.LAUNCH_OPERATION_BUSY,)
    finally:
        launch_module._release_operation(launch_record)

    wrong_registry = owned_root.parent / "wrong-registry"
    wrong_registry.mkdir(mode=0o700)
    expected_registry = bundle / "registry/sessions.d"
    monkeypatch.setattr(sessions, "SESSIONS_DIR", wrong_registry)
    mismatched = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(mismatched) is OwnedFakeTerminalFailure
    assert mismatched.reason_codes == (TerminalReason.REGISTRY_ROOT_MISMATCH,)
    monkeypatch.setattr(sessions, "SESSIONS_DIR", expected_registry)

    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    duplicate = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.FAIL),
    )
    assert type(duplicate) is OwnedFakeTerminalFailure
    assert duplicate.reason_codes == (TerminalReason.CAPABILITY_REUSED,)
    assert type(_apply(capability, cancellation)) is OwnedFakeTerminalResult
    _close_launch(bundle, handle, cancellation)

    after_close = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(after_close) is OwnedFakeTerminalFailure
    assert after_close.reason_codes == (TerminalReason.CAPABILITY_REUSED,)
    assert _fd_set() == before


@pytest.mark.parametrize(
    ("tamper", "reason"),
    (
        ("nonce", TerminalReason.INVALID_CAPABILITY),
        ("handle", TerminalReason.INVALID_CAPABILITY),
        ("receipt", TerminalReason.RECEIPT_CHANGED),
        ("process", TerminalReason.PROCESS_BINDING_CHANGED),
        ("registry", TerminalReason.REGISTRY_ROOT_MISMATCH),
    ),
)
def test_generation_receipt_process_and_nonce_binding_cannot_be_retargeted(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
    reason: TerminalReason,
) -> None:
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    terminal_record = _terminal_record(capability)
    launch_record = launch_module._record_for_handle(handle)
    assert not isinstance(launch_record, LaunchFailure)
    original_receipt = launch_record.current_receipt
    original_nonce = terminal_record.event_nonce
    original_handle_mac = terminal_record.handle_mac
    expected_registry = bundle / "registry/sessions.d"

    with monkeypatch.context() as scoped:
        if tamper == "nonce":
            terminal_record.event_nonce = b"z" * 16
        elif tamper == "handle":
            terminal_record.handle_mac = "0" * 64
        elif tamper == "receipt":
            assert original_receipt is not None
            launch_record.current_receipt = dataclasses.replace(
                original_receipt,
                reference=dataclasses.replace(
                    original_receipt.reference,
                    attempt=original_receipt.reference.attempt + 1,
                ),
            )
        elif tamper == "process":
            scoped.setattr(
                terminal_module,
                "_capture_process_identity",
                lambda *_args, **_kwargs: dataclasses.replace(
                    launch_record.process_identity,
                    starttime_ticks=launch_record.process_identity.starttime_ticks + 1,
                ),
            )
        else:
            wrong_registry = owned_root.parent / "retargeted-registry"
            wrong_registry.mkdir(mode=0o700)
            scoped.setattr(sessions, "SESSIONS_DIR", wrong_registry)
        refused = _apply(capability, cancellation)
    assert type(refused) is OwnedFakeTerminalFailure
    assert refused.reason_codes == (reason,)

    launch_record.current_receipt = original_receipt
    terminal_record.event_nonce = original_nonce
    terminal_record.handle_mac = original_handle_mac
    monkeypatch.setattr(sessions, "SESSIONS_DIR", expected_registry)
    _close_launch(bundle, handle, cancellation)


@pytest.mark.parametrize("event", tuple(FakeTerminalEvent))
@pytest.mark.parametrize(
    ("sequence", "work_count"),
    (
        (FakeTerminalSequence.IMMEDIATE, 0),
        (FakeTerminalSequence.BACKGROUND_DRAIN, 3),
    ),
)
def test_all_events_and_drain_modes_are_authenticated_acked_and_ledgerless(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    event: FakeTerminalEvent,
    sequence: FakeTerminalSequence,
    work_count: int,
) -> None:
    before = _fd_set()
    bundle, handle, cancellation = _launch_verified(
        owned_root,
        monkeypatch,
        FakeRuntimeBehavior(descendants=FakeDescendantShape.CHILD_AND_GRANDCHILD),
    )
    registry_before = _registry_snapshot(bundle)

    def forbidden_ledger(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("K1 must remain ledgerless")

    monkeypatch.setattr(sessions, "ledger_record_start", forbidden_ledger)
    monkeypatch.setattr(sessions, "ledger_record_finish", forbidden_ledger)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(event, sequence, work_count),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    result = _apply(capability, cancellation)
    assert type(result) is OwnedFakeTerminalResult
    assert result.state == "acked"
    assert result.event_kind == event.name.lower()
    assert result.sequence_mode == sequence.name.lower()
    assert result.work_count == work_count
    assert result.duplicate_count == 0
    assert len(result.event_digest_sha256) == 64
    assert result.authoritative is False
    if sequence is FakeTerminalSequence.BACKGROUND_DRAIN:
        assert result.trace.index(
            TerminalPhase.WORK_STARTED.value
        ) < result.trace.index(TerminalPhase.WORK_DRAINED.value)
        assert result.trace.index(
            TerminalPhase.WORK_DRAINED.value
        ) < result.trace.index(TerminalPhase.READY.value)
    assert _registry_snapshot(bundle) == registry_before
    assert not any("ledger" in name for name in registry_before)
    _close_launch(bundle, handle, cancellation)
    assert _fd_set() == before


def test_exact_duplicate_is_coalesced_once_and_replay_is_cached(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(
            FakeTerminalEvent.COMPLETE,
            FakeTerminalSequence.EXACT_DUPLICATE,
        ),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    result = _apply(capability, cancellation)
    assert type(result) is OwnedFakeTerminalResult
    assert result.duplicate_count == 1
    assert _apply(capability, cancellation) is result
    _close_launch(bundle, handle, cancellation)


@pytest.mark.parametrize("shape", tuple(FakeDescendantShape))
def test_terminal_fd_stays_with_direct_child_after_descendant_ack(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    shape: FakeDescendantShape,
) -> None:
    before = _fd_set()
    bundle, handle, cancellation = _launch_verified(
        owned_root,
        monkeypatch,
        FakeRuntimeBehavior(descendants=shape),
    )
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    result = _apply(capability, cancellation)
    assert type(result) is OwnedFakeTerminalResult
    assert result.trace[-1] == TerminalPhase.ACKED.value
    _close_launch(bundle, handle, cancellation)
    assert _fd_set() == before


@pytest.mark.parametrize(
    ("sequence", "reason"),
    (
        (
            FakeTerminalSequence.CONFLICTING_DUPLICATE,
            TerminalReason.TERMINAL_EVENT_CONFLICT,
        ),
        (
            FakeTerminalSequence.OUT_OF_ORDER,
            TerminalReason.TERMINAL_EVENT_OUT_OF_ORDER,
        ),
        (
            FakeTerminalSequence.FOREIGN_NONCE,
            TerminalReason.TERMINAL_EVENT_WRONG_NONCE,
        ),
        (
            FakeTerminalSequence.WRONG_KIND,
            TerminalReason.TERMINAL_EVENT_WRONG_KIND,
        ),
        (
            FakeTerminalSequence.MALFORMED,
            TerminalReason.TERMINAL_EVENT_MALFORMED,
        ),
    ),
)
def test_conflicting_foreign_and_malformed_events_refuse_before_ack(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    sequence: FakeTerminalSequence,
    reason: TerminalReason,
) -> None:
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    registry_before = _registry_snapshot(bundle)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.FAIL, sequence),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    failure = _apply(capability, cancellation)
    assert type(failure) is OwnedFakeTerminalFailure
    assert failure.reason_codes == (reason,)
    assert failure.phase is TerminalPhase.REFUSED
    assert TerminalPhase.ACKED.value not in failure.trace
    assert failure.authoritative is False
    assert _apply(capability, cancellation) is failure
    assert _registry_snapshot(bundle) == registry_before
    _close_launch(bundle, handle, cancellation)


def test_timeout_and_wait_cancellation_spend_capability_without_inference(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for cancelled in (False, True):
        bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
        registry_before = _registry_snapshot(bundle)
        capability = make_owned_fake_terminal_capability(
            handle,
            plan=FakeTerminalPlan(
                FakeTerminalEvent.CANCEL,
                FakeTerminalSequence.TIMEOUT,
            ),
        )
        assert type(capability) is OwnedFakeTerminalCapability
        if cancelled:
            cancellation.cancel()
        result = _apply(capability, cancellation, seconds=0.05)
        assert type(result) is OwnedFakeTerminalFailure
        assert result.reason_codes == (
            TerminalReason.WAIT_CANCELLED
            if cancelled
            else TerminalReason.DEADLINE_EXCEEDED,
        )
        assert result.disposition is (
            TerminalDisposition.WAIT_CANCELLED
            if cancelled
            else TerminalDisposition.TIMED_OUT
        )
        assert _apply(capability, cancellation) is result
        assert _registry_snapshot(bundle) == registry_before
        _close_launch(bundle, handle, cancellation)


@pytest.mark.parametrize(
    ("sequence", "expected"),
    (
        (
            FakeTerminalSequence.CHILD_EXIT_BEFORE_EVENT,
            TerminalReason.CHILD_EXITED,
        ),
        (
            FakeTerminalSequence.CONTROL_EOF,
            TerminalReason.TERMINAL_EVENT_EOF,
        ),
    ),
)
def test_exit_and_control_eof_never_synthesize_an_event(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    sequence: FakeTerminalSequence,
    expected: TerminalReason,
) -> None:
    before = _fd_set()
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    registry_before = _registry_snapshot(bundle)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.FAIL, sequence),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    failure = _apply(capability, cancellation)
    assert type(failure) is OwnedFakeTerminalFailure
    assert failure.reason_codes == (expected,)
    assert TerminalPhase.READY.value not in failure.trace
    assert _registry_snapshot(bundle) == registry_before
    _close_launch(bundle, handle, cancellation)
    assert _fd_set() == before


def test_exit_after_ack_is_success_then_exact_stage3b_cleanup(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _fd_set()
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    launch_record = launch_module._record_for_handle(handle)
    assert not isinstance(launch_record, LaunchFailure)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(
            FakeTerminalEvent.INTERRUPT,
            FakeTerminalSequence.EXIT_AFTER_ACK,
        ),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    result = _apply(capability, cancellation)
    assert type(result) is OwnedFakeTerminalResult
    poller = select.poll()
    pidfd = os.pidfd_open(launch_record.child_pid)
    try:
        poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        assert poller.poll(5000)
    finally:
        os.close(pidfd)
    _close_launch(bundle, handle, cancellation)
    assert _fd_set() == before


def test_terminal_claim_blocks_concurrent_apply_and_launch_close_without_locks(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    entered = threading.Event()
    release = threading.Event()
    original_hook = terminal_module._terminal_phase_hook

    def blocking_hook(phase: TerminalPhase, _capability_id: str) -> None:
        if phase is TerminalPhase.ATTACHED:
            assert not getattr(terminal_module._STATE_LOCK, "_is_owned")()
            assert not getattr(launch_module._STATE_LOCK, "_is_owned")()
            entered.set()
            assert release.wait(timeout=10)

    monkeypatch.setattr(terminal_module, "_terminal_phase_hook", blocking_hook)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_apply, capability, cancellation)
        assert entered.wait(timeout=10)
        concurrent = _apply(capability, cancellation)
        assert type(concurrent) is OwnedFakeTerminalFailure
        assert concurrent.reason_codes == (TerminalReason.LAUNCH_OPERATION_BUSY,)
        close_conflict = _close_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline.after(1),
        )
        assert type(close_conflict) is LaunchFailure
        assert close_conflict.diagnostics == {"stage": "operation_in_progress"}
        release.set()
        result = future.result(timeout=10)
    monkeypatch.setattr(terminal_module, "_terminal_phase_hook", original_hook)
    assert type(result) is OwnedFakeTerminalResult
    _close_launch(bundle, handle, cancellation)


def test_issuance_claim_blocks_close_and_close_before_apply_spends_capability(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _fd_set()
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    entered = threading.Event()
    release = threading.Event()
    original_socket_identity = terminal_module._socket_identity

    def blocking_socket_identity(
        channel: socket.socket,
        *,
        require_passcred: bool,
    ):
        if require_passcred and not entered.is_set():
            entered.set()
            assert release.wait(timeout=10)
        return original_socket_identity(
            channel,
            require_passcred=require_passcred,
        )

    monkeypatch.setattr(
        terminal_module,
        "_socket_identity",
        blocking_socket_identity,
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            make_owned_fake_terminal_capability,
            handle,
            plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
        )
        assert entered.wait(timeout=10)
        conflict = _close_owned_runtime_fake(
            handle,
            deadline=MonotonicDeadline.after(1),
        )
        assert type(conflict) is LaunchFailure
        assert conflict.diagnostics == {"stage": "operation_in_progress"}
        release.set()
        capability = future.result(timeout=10)
    assert type(capability) is OwnedFakeTerminalCapability
    monkeypatch.setattr(
        terminal_module,
        "_socket_identity",
        original_socket_identity,
    )

    closed = _close_owned_runtime_fake(
        handle,
        deadline=MonotonicDeadline.after(10),
    )
    assert type(closed) is LaunchClosed
    refused = _apply(capability, cancellation)
    assert type(refused) is OwnedFakeTerminalFailure
    assert refused.reason_codes == (TerminalReason.LAUNCH_NOT_SUPERVISED,)
    cancellation.close()
    assert not bundle.exists()
    assert _fd_set() == before


def test_terminal_registry_lock_precedes_launch_state_lock(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    seen: list[bool] = []
    original_record_for_handle = terminal_module._record_for_handle
    original_claim_operation = terminal_module._claim_operation

    def checked_record_for_handle(value: object):
        seen.append(getattr(terminal_module._STATE_LOCK, "_is_owned")())
        return original_record_for_handle(value)

    def checked_claim_operation(value: object, operation: str):
        seen.append(getattr(terminal_module._STATE_LOCK, "_is_owned")())
        return original_claim_operation(value, operation)

    monkeypatch.setattr(
        terminal_module,
        "_record_for_handle",
        checked_record_for_handle,
    )
    monkeypatch.setattr(
        terminal_module,
        "_claim_operation",
        checked_claim_operation,
    )
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    result = _apply(capability, cancellation)
    assert type(result) is OwnedFakeTerminalResult
    assert seen == [True, True, True]
    _close_launch(bundle, handle, cancellation)


def test_unexpected_phase_failure_closes_fds_releases_claim_and_caches_refusal(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _fd_set()
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(capability) is OwnedFakeTerminalCapability

    def fail_after_attach(phase: TerminalPhase, _capability_id: str) -> None:
        if phase is TerminalPhase.ATTACHED:
            raise RuntimeError("synthetic phase failure")

    monkeypatch.setattr(terminal_module, "_terminal_phase_hook", fail_after_attach)
    with pytest.raises(RuntimeError, match="synthetic phase failure"):
        _apply(capability, cancellation)
    cached = _apply(capability, cancellation)
    assert type(cached) is OwnedFakeTerminalFailure
    assert cached.reason_codes == (TerminalReason.TERMINAL_EVENT_MALFORMED,)
    launch_record = launch_module._record_for_handle(handle)
    assert not isinstance(launch_record, LaunchFailure)
    assert launch_record.operation is None
    _close_launch(bundle, handle, cancellation)
    assert _fd_set() == before


def test_fork_wipes_registry_key_capability_and_terminal_descriptors(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _fd_set()
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    record = _terminal_record(capability)
    assert record.parent_socket is not None
    assert record.child_socket is not None
    issuer_key = terminal_module._ISSUER_KEY
    generation = terminal_module._MODULE_GENERATION
    inherited_fds = (
        record.parent_socket.fileno(),
        record.child_socket.fileno(),
    )
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    child_pid = os.fork()
    if child_pid == 0:
        os.close(read_fd)
        closed = []
        for fd in inherited_fds:
            try:
                fcntl.fcntl(fd, fcntl.F_GETFD)
            except OSError as exc:
                closed.append(exc.errno == errno.EBADF)
            else:
                closed.append(False)
        with LaunchCancellation() as child_cancellation:
            result = _apply(capability, child_cancellation)
        assert type(result) is OwnedFakeTerminalFailure
        payload = (
            f"{int(all(closed))}:"
            f"{int(terminal_module._ISSUER_KEY != issuer_key)}:"
            f"{int(terminal_module._MODULE_GENERATION != generation)}:"
            f"{type(result).__name__}:"
            f"{result.reason_codes[0].value}\n"
        ).encode("ascii")
        os.write(write_fd, payload)
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    raw = os.read(read_fd, 4096)
    os.close(read_fd)
    waited, status = os.waitpid(child_pid, 0)
    assert waited == child_pid
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0
    assert raw == b"1:1:1:OwnedFakeTerminalFailure:invalid_capability\n"
    assert type(_apply(capability, cancellation)) is OwnedFakeTerminalResult
    _close_launch(bundle, handle, cancellation)
    assert _fd_set() == before


def test_received_packets_require_credentials_and_close_unexpected_rights() -> None:
    before = _fd_set()
    event = terminal_module._TerminalEvent.COMPLETE
    nonce = b"x" * 16
    raw = terminal_module._terminal_frame_bytes(
        terminal_module._TerminalFrameType.TERMINAL_READY,
        event=event,
        sequence=4,
        work_count=0,
        nonce=nonce,
    )

    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    receiver.setblocking(False)
    try:
        assert sender.send(raw) == len(raw)
        with pytest.raises(terminal_module._PacketError) as missing:
            terminal_module._receive_terminal_packet(
                receiver,
                expected_pid=os.getpid(),
                expected_uid=os.geteuid(),
            )
        assert missing.value.reason is TerminalReason.TERMINAL_EVENT_WRONG_CREDENTIALS
    finally:
        receiver.close()
        sender.close()

    for descriptor_count in (1, 2, 3):
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        receiver.setblocking(False)
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        descriptors = [os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)]
        descriptors.extend(os.dup(descriptors[0]) for _ in range(descriptor_count - 1))
        try:
            assert sender.sendmsg(
                [raw],
                [
                    (
                        socket.SOL_SOCKET,
                        socket.SCM_RIGHTS,
                        array.array("i", descriptors),
                    )
                ],
            ) == len(raw)
            with pytest.raises(terminal_module._PacketError) as unexpected:
                terminal_module._receive_terminal_packet(
                    receiver,
                    expected_pid=os.getpid(),
                    expected_uid=os.geteuid(),
                )
            assert unexpected.value.reason is TerminalReason.TERMINAL_EVENT_MALFORMED
        finally:
            for fd in descriptors:
                os.close(fd)
            receiver.close()
            sender.close()
    assert _fd_set() == before


def test_received_packet_retries_eintr_and_maps_only_transport_reset() -> None:
    event = terminal_module._TerminalEvent.COMPLETE
    raw = terminal_module._terminal_frame_bytes(
        terminal_module._TerminalFrameType.TERMINAL_READY,
        event=event,
        sequence=4,
        work_count=0,
        nonce=b"x" * 16,
    )
    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    receiver.setblocking(False)
    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    assert sender.send(raw) == len(raw)

    class InterruptedOnce:
        def __init__(self, wrapped: socket.socket) -> None:
            self.wrapped = wrapped
            self.calls = 0

        def recvmsg(
            self,
            bufsize: int,
            ancbufsize: int = 0,
            flags: int = 0,
        ):
            self.calls += 1
            if self.calls == 1:
                raise InterruptedError(errno.EINTR, "interrupted")
            return self.wrapped.recvmsg(bufsize, ancbufsize, flags)

    wrapped = InterruptedOnce(receiver)
    try:
        assert (
            terminal_module._receive_terminal_packet(
                wrapped,  # type: ignore[arg-type]
                expected_pid=os.getpid(),
                expected_uid=os.geteuid(),
            )
            == raw
        )
        assert wrapped.calls == 2
    finally:
        receiver.close()
        sender.close()

    class RaisingSocket:
        def __init__(self, error_number: int) -> None:
            self.error_number = error_number

        def recvmsg(self, *_args: object):
            raise OSError(self.error_number, os.strerror(self.error_number))

    for error_number in terminal_module._SOCKET_EOF_ERRNOS:
        with pytest.raises(terminal_module._PacketError) as reset:
            terminal_module._receive_terminal_packet(
                RaisingSocket(error_number),  # type: ignore[arg-type]
                expected_pid=os.getpid(),
                expected_uid=os.geteuid(),
            )
        assert reset.value.reason is TerminalReason.TERMINAL_EVENT_EOF
    with pytest.raises(OSError) as unrelated:
        terminal_module._receive_terminal_packet(
            RaisingSocket(errno.EIO),  # type: ignore[arg-type]
            expected_pid=os.getpid(),
            expected_uid=os.geteuid(),
        )
    assert unrelated.value.errno == errno.EIO


def test_attach_and_terminal_sends_retry_eintr(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    original_control_sendmsg = terminal_module._control_sendmsg
    original_terminal_send = terminal_module._terminal_send
    calls = {"attach": 0, "terminal": 0}

    def interrupted_control_sendmsg(
        channel: socket.socket,
        raw: bytes,
        ancillary: list[tuple[int, int, array.array[int]]],
    ) -> int:
        calls["attach"] += 1
        if calls["attach"] == 1:
            raise InterruptedError(errno.EINTR, "interrupted")
        return original_control_sendmsg(channel, raw, ancillary)

    def interrupted_terminal_send(channel: socket.socket, raw: bytes) -> int:
        calls["terminal"] += 1
        if calls["terminal"] == 1:
            raise InterruptedError(errno.EINTR, "interrupted")
        return original_terminal_send(channel, raw)

    monkeypatch.setattr(
        terminal_module,
        "_control_sendmsg",
        interrupted_control_sendmsg,
    )
    monkeypatch.setattr(
        terminal_module,
        "_terminal_send",
        interrupted_terminal_send,
    )
    result = _apply(capability, cancellation)
    assert type(result) is OwnedFakeTerminalResult
    assert calls["attach"] == 2
    assert calls["terminal"] >= 2
    _close_launch(bundle, handle, cancellation)


def test_foreign_process_credentials_are_rejected() -> None:
    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    receiver.setblocking(False)
    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    raw = terminal_module._terminal_frame_bytes(
        terminal_module._TerminalFrameType.TERMINAL_READY,
        event=terminal_module._TerminalEvent.COMPLETE,
        sequence=4,
        work_count=0,
        nonce=b"x" * 16,
    )
    child_pid = os.fork()
    if child_pid == 0:
        receiver.close()
        sender.send(raw)
        sender.close()
        os._exit(0)
    sender.close()
    try:
        poller = select.poll()
        poller.register(receiver.fileno(), select.POLLIN | select.POLLHUP)
        assert poller.poll(5000)
        with pytest.raises(terminal_module._PacketError) as foreign:
            terminal_module._receive_terminal_packet(
                receiver,
                expected_pid=os.getpid(),
                expected_uid=os.geteuid(),
            )
        assert foreign.value.reason is TerminalReason.TERMINAL_EVENT_WRONG_CREDENTIALS
    finally:
        receiver.close()
        os.waitpid(child_pid, 0)


@pytest.mark.parametrize("mode", ("missing", "two", "truncated", "wrong_type"))
def test_native_attach_rejects_missing_multiple_truncated_and_wrong_type_fds(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    before = _fd_set()
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    launch_record = launch_module._record_for_handle(handle)
    assert not isinstance(launch_record, LaunchFailure)
    child_fd_baseline = _process_fd_count(launch_record.child_pid)
    channels: list[socket.socket] = []
    if mode == "wrong_type":
        channels.extend(
            socket.socketpair(
                socket.AF_UNIX,
                socket.SOCK_STREAM | getattr(socket, "SOCK_CLOEXEC", 0),
            )
        )
        descriptors = [channels[1].fileno()]
    elif mode == "missing":
        descriptors = []
    else:
        channels.extend(
            socket.socketpair(
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET | getattr(socket, "SOCK_CLOEXEC", 0),
            )
        )
        descriptors = [channels[1].fileno()]
        descriptors.extend(
            os.dup(channels[1].fileno()) for _ in range(1 if mode == "two" else 2)
        )
    try:
        sent_record, _claimed = _send_control_attach(handle, descriptors)
        frame = _receive_control_error(sent_record)
        assert frame[0] is launch_module._FrameType.PROTOCOL_ERROR
        assert frame[1] == 8
    finally:
        launch_module._release_operation(launch_record)
        for fd in descriptors[1:]:
            os.close(fd)
        for channel in channels:
            channel.close()
    _wait_for_process_fd_count(launch_record.child_pid, child_fd_baseline)
    _close_launch(bundle, handle, cancellation)
    assert _fd_set() == before


def test_socket_peer_replacement_and_missing_passcred_are_rejected(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    record = _terminal_record(capability)
    original_parent = record.parent_socket
    replacement_parent, replacement_peer = socket.socketpair(
        socket.AF_UNIX,
        socket.SOCK_SEQPACKET | getattr(socket, "SOCK_CLOEXEC", 0),
    )
    replacement_parent.setblocking(False)
    replacement_parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    record.parent_socket = replacement_parent
    try:
        replaced = _apply(capability, cancellation)
        assert type(replaced) is OwnedFakeTerminalFailure
        assert replaced.reason_codes == (TerminalReason.TERMINAL_ATTACH_FAILED,)
    finally:
        if original_parent is not None:
            original_parent.close()
        replacement_peer.close()
    _close_launch(bundle, handle, cancellation)

    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    record = _terminal_record(capability)
    assert record.parent_socket is not None
    record.parent_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 0)
    missing = _apply(capability, cancellation)
    assert type(missing) is OwnedFakeTerminalFailure
    assert missing.reason_codes == (TerminalReason.TERMINAL_EVENT_WRONG_CREDENTIALS,)
    _close_launch(bundle, handle, cancellation)


@pytest.mark.parametrize(
    "frame_type",
    (
        launch_module._FrameType.REEXEC_SAME,
        launch_module._FrameType.REEXEC_DIFFERENT,
    ),
)
def test_reexec_while_armed_closes_terminal_fd_and_refuses(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    frame_type: launch_module._FrameType,
) -> None:
    before = _fd_set()
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    armed = threading.Event()
    release = threading.Event()

    def blocking_hook(phase: TerminalPhase, _capability_id: str) -> None:
        if phase is TerminalPhase.ARMED:
            armed.set()
            assert release.wait(timeout=10)

    monkeypatch.setattr(terminal_module, "_terminal_phase_hook", blocking_hook)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_apply, capability, cancellation)
        assert armed.wait(timeout=10)
        launch_record = launch_module._record_for_handle(handle)
        assert not isinstance(launch_record, LaunchFailure)
        assert launch_module._send_frame(launch_record, frame_type)
        release.set()
        failure = future.result(timeout=10)
    assert type(failure) is OwnedFakeTerminalFailure
    assert failure.reason_codes[0] in {
        TerminalReason.PROCESS_BINDING_CHANGED,
        TerminalReason.TERMINAL_EVENT_EOF,
    }
    assert TerminalPhase.READY.value not in failure.trace
    _close_launch(bundle, handle, cancellation)
    assert _fd_set() == before


def test_no_installed_copilot_metadata_lifecycle_or_ledger_call_is_reachable(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.CANCEL),
    )
    assert type(capability) is OwnedFakeTerminalCapability

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("forbidden K2 or executable path reached")

    monkeypatch.setattr(sessions, "ledger_record_start", forbidden)
    monkeypatch.setattr(sessions, "ledger_record_finish", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)
    result = _apply(capability, cancellation)
    assert type(result) is OwnedFakeTerminalResult
    source = Path(terminal_module.__file__).read_text(encoding="utf-8")
    helper_source = (
        Path(__file__).parents[2] / "testing/runtime_receipt_terminal.py"
    ).read_text(encoding="utf-8")
    for token in (
        "core.run.metadata",
        "complete_run",
        "fail_run",
        "cancel_run",
        "interrupt_run",
        "ledger_record_start",
        "ledger_record_finish",
        "shutil.which",
        "copilot",
    ):
        assert token not in source
        assert token not in helper_source
    _close_launch(bundle, handle, cancellation)


def test_accepted_w1j_pin_and_cross_launch_capabilities_remain_distinct(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = Path(__file__).parents[3]
    assert (
        hashlib.sha256(
            (repository_root / "core/run/metadata.py").read_bytes()
        ).hexdigest()
        == _ACCEPTED_W1J_METADATA_SHA256
    )

    first_bundle, first_handle, first_cancellation = _launch_verified(
        owned_root,
        monkeypatch,
    )
    first_registry = first_bundle / "registry/sessions.d"
    first_capability = make_owned_fake_terminal_capability(
        first_handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(first_capability) is OwnedFakeTerminalCapability
    first_record = _terminal_record(first_capability)

    second_bundle, second_handle, second_cancellation = _launch_verified(
        owned_root,
        monkeypatch,
    )
    second_registry = second_bundle / "registry/sessions.d"
    second_capability = make_owned_fake_terminal_capability(
        second_handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(second_capability) is OwnedFakeTerminalCapability
    second_record = _terminal_record(second_capability)
    assert first_record.receipt_reference_sha256 != (
        second_record.receipt_reference_sha256
    )
    assert first_record.handle_id != second_record.handle_id
    assert first_record.event_nonce != second_record.event_nonce

    forged = object.__new__(OwnedFakeTerminalCapability)
    object.__setattr__(forged, "_capability_id", second_capability._capability_id)
    object.__setattr__(forged, "_capability_mac", second_capability._capability_mac)
    monkeypatch.setattr(sessions, "SESSIONS_DIR", first_registry)
    refused = _apply(forged, first_cancellation)
    assert type(refused) is OwnedFakeTerminalFailure
    assert refused.reason_codes == (TerminalReason.INVALID_CAPABILITY,)
    assert type(_apply(first_capability, first_cancellation)) is (
        OwnedFakeTerminalResult
    )
    _close_launch(first_bundle, first_handle, first_cancellation)

    monkeypatch.setattr(sessions, "SESSIONS_DIR", second_registry)
    assert type(_apply(second_capability, second_cancellation)) is (
        OwnedFakeTerminalResult
    )
    _close_launch(second_bundle, second_handle, second_cancellation)


def test_supervisor_loss_destroys_capability_and_kills_owned_fake(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
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
            handle = _launch_owned_runtime_fake(
                capability,
                deadline=MonotonicDeadline.after(10),
                cancellation=cancellation,
            )
            if not isinstance(handle, OwnedFakeLaunchHandle):
                os.write(write_fd, b"launch-failed")
                os.close(write_fd)
                os._exit(1)
            verified = _finalize_owned_runtime_fake(
                handle,
                deadline=MonotonicDeadline.after(20),
                cancellation=cancellation,
            )
            if not isinstance(verified, OwnedFakeVerified):
                os.write(write_fd, b"finalize-failed")
                os.close(write_fd)
                os._exit(1)
            terminal_capability = make_owned_fake_terminal_capability(
                handle,
                plan=FakeTerminalPlan(
                    FakeTerminalEvent.FAIL,
                    FakeTerminalSequence.TIMEOUT,
                ),
            )
            if not isinstance(terminal_capability, OwnedFakeTerminalCapability):
                os.write(write_fd, b"terminal-issue-failed")
                os.close(write_fd)
                os._exit(1)
            launch_record = launch_module._record_for_handle(handle)
            assert not isinstance(launch_record, LaunchFailure)
            payload = f"{bundle.name}\n{launch_record.child_pid}\n".encode("ascii")
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
    assert "failed" not in text
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
    assert bundle.exists()
    assert not any("ledger" in path.name for path in bundle.rglob("*"))
    with LaunchCancellation() as invalid_cancellation:
        invalid = _apply_owned_fake_terminal_capability(
            object(),
            deadline=MonotonicDeadline.after(1),
            cancellation=invalid_cancellation,
        )
    assert type(invalid) is OwnedFakeTerminalFailure
    assert invalid.reason_codes == (TerminalReason.INVALID_CAPABILITY,)


def test_512_seeded_no_sleep_terminal_schedules(
    owned_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, handle, cancellation = _launch_verified(owned_root, monkeypatch)
    registry_before = _registry_snapshot(bundle)
    capability = make_owned_fake_terminal_capability(
        handle,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(capability) is OwnedFakeTerminalCapability
    record = _terminal_record(capability)
    launch_record = launch_module._record_for_handle(handle)
    assert not isinstance(launch_record, LaunchFailure)
    rng = random.Random(0x57414B31)
    schedules = list(range(512))
    rng.shuffle(schedules)

    for seed in schedules:
        bucket = seed // 64
        if bucket == 0:
            duplicate = make_owned_fake_terminal_capability(
                handle,
                plan=FakeTerminalPlan(FakeTerminalEvent.FAIL),
            )
            assert type(duplicate) is OwnedFakeTerminalFailure
            assert duplicate.reason_codes == (TerminalReason.CAPABILITY_REUSED,)
        elif bucket == 1:
            frame = terminal_module._terminal_frame_bytes(
                terminal_module._TerminalFrameType.TERMINAL_READY,
                event=record.event,
                sequence=4,
                work_count=0,
                nonce=record.event_nonce,
            )
            if seed % 2:
                frame = frame[:-1]
                with pytest.raises(terminal_module._PacketError):
                    terminal_module._decode_terminal_frame(frame)
            else:
                assert terminal_module._decode_terminal_frame(frame)[2] == 4
        elif bucket == 2:
            work_frame = terminal_module._terminal_frame_bytes(
                terminal_module._TerminalFrameType.WORK_DRAINED,
                event=record.event,
                sequence=7,
                work_count=0,
                nonce=record.event_nonce,
            )
            assert terminal_module._decode_terminal_frame(work_frame)[3] == 0
        elif bucket == 3:
            ready = terminal_module._terminal_frame_bytes(
                terminal_module._TerminalFrameType.TERMINAL_READY,
                event=record.event,
                sequence=4,
                work_count=0,
                nonce=record.event_nonce,
            )
            altered = bytearray(ready)
            altered[12] ^= 1
            assert ready != bytes(altered)
        elif bucket == 4:
            forged = object.__new__(OwnedFakeTerminalCapability)
            object.__setattr__(forged, "_capability_id", capability._capability_id)
            object.__setattr__(forged, "_capability_mac", capability._capability_mac)
            with terminal_module._STATE_LOCK:
                rejected = terminal_module._record_for_capability(forged)
            assert type(rejected) is OwnedFakeTerminalFailure
        elif bucket == 5:
            assert _registry_snapshot(bundle) == registry_before
            assert not any("ledger" in name for name in registry_before)
        elif bucket == 6:
            claimed = launch_module._claim_operation(handle, "terminal")
            assert not isinstance(claimed, LaunchFailure)
            try:
                conflict = _close_owned_runtime_fake(
                    handle,
                    deadline=MonotonicDeadline.after(1),
                )
                assert type(conflict) is LaunchFailure
                assert conflict.diagnostics == {"stage": "operation_in_progress"}
            finally:
                launch_module._release_operation(launch_record)
        else:
            assert terminal_module._validate_live_binding(record, launch_record) is None
            assert terminal_module._initial_binding_matches(record, launch_record)

    stress_tree = ast.parse(
        inspect.getsource(test_512_seeded_no_sleep_terminal_schedules)
    )
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "sleep"
        for node in ast.walk(stress_tree)
    )
    assert type(_apply(capability, cancellation)) is OwnedFakeTerminalResult
    _close_launch(bundle, handle, cancellation)
