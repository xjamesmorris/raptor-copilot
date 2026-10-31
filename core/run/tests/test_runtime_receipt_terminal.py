"""K2 fake-only terminal lifecycle integration tests."""

from __future__ import annotations

import copy
import ast
import hashlib
import inspect
import json
import os
import pickle
import random
import select
import shutil
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import pytest

from core.json import load_json
from core.json.utils import dumps_artifact, dumps_canonical
from core.project import sessions
from core.run import metadata as md
from core.run.pin import set_process_project
from core.sandbox import summary as sandbox_summary
from core.startup.runtime_receipt import launch as launch_module
from core.startup.runtime_receipt import profile as profile_module
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
    _owned_runtime_fake_session_binding,
)
from core.startup.runtime_receipt.profile import ProfileStore, load_profile_store
from core.startup.runtime_receipt.schema import ExpectedBinding, to_json_value
from core.startup.runtime_receipt.terminal import (
    OwnedFakeTerminalCleanupResult,
    OwnedFakeTerminalFailure,
    OwnedFakeTerminalLifecycleResult,
    TerminalDisposition,
    TerminalPhase,
    TerminalReason,
)
from core.startup.runtime_receipt.verify import (
    StaticallyVerifiedReceipt,
    verify_receipt_static,
)
from core.testing.runtime_receipt_fake import (
    FakeDescendantShape,
    FakeRuntimeBehavior,
    FakeRuntimeUnsupported,
    make_owned_runtime_receipt_fake,
)
from core.testing.runtime_receipt_terminal import (
    FakeTerminalEvent,
    FakeTerminalLifecycle,
    FakeTerminalPlan,
    FakeTerminalSequence,
    apply_owned_fake_terminal_lifecycle,
    cleanup_owned_fake_terminal_lifecycle,
    make_owned_fake_terminal_lifecycle,
    resume_owned_fake_terminal_lifecycle,
)

_SHIPPED_PROFILE = (
    Path(__file__).parents[2] / "startup/runtime_receipt/profiles/"
    "copilot-cli-1.0.84-5-linux-x86_64-static-candidate-v1.json"
)
_SHIPPED_PROFILE_SHA256 = (
    "45b72568f902ab229ff40989e5ae616e8a293a0dcf780b5562a61e9cb65e262d"
)
_READ_FILES = [
    "core/run/metadata.py",
    "core/startup/runtime_receipt/terminal.py",
]


@dataclass(slots=True)
class _K2Environment:
    outer: Path
    bundle: Path
    registry: Path
    profile_dir: Path
    profile_path: Path
    handle: OwnedFakeLaunchHandle
    cancellation: LaunchCancellation
    launch_record: launch_module._HandleRecord
    static_verification: StaticallyVerifiedReceipt
    active_calls: list[Path | None]
    frozen_calls: list[tuple[Path, str | None, str]]
    ledger_calls: list[str]
    closed: bool = False


def _fd_set() -> set[int]:
    return {int(item) for item in os.listdir("/proc/self/fd")}


@pytest.fixture(autouse=True)
def no_k2_descriptor_leak():
    before = _fd_set()
    yield
    assert _fd_set() == before


def _remove_fixture_profile(env: _K2Environment) -> None:
    if env.profile_path.exists():
        env.profile_path.unlink()
    if env.profile_dir.exists():
        env.profile_dir.rmdir()


def _remove_run_tree(run_dir: Path) -> None:
    if run_dir.exists():
        shutil.rmtree(run_dir)


def _discard_lifecycle(
    env: _K2Environment,
    lifecycle: FakeTerminalLifecycle | None = None,
) -> None:
    if lifecycle is not None:
        _remove_run_tree(lifecycle.run_dir)
        capability = lifecycle._capability
        with terminal_module._STATE_LOCK:
            record = terminal_module._CAPABILITIES.get(capability._capability_id)
            if record is not None:
                terminal_module._close_sockets(record)
    _remove_fixture_profile(env)
    if env.bundle.exists():
        closed = _close_owned_runtime_fake(
            env.handle,
            deadline=MonotonicDeadline.after(10),
        )
        assert type(closed) is LaunchClosed
    env.closed = True


def _cleanup_result(
    env: _K2Environment,
    result: OwnedFakeTerminalLifecycleResult,
) -> OwnedFakeTerminalCleanupResult:
    _remove_fixture_profile(env)
    cleaned = cleanup_owned_fake_terminal_lifecycle(
        result,
        deadline=MonotonicDeadline.after(10),
    )
    assert type(cleaned) is OwnedFakeTerminalCleanupResult
    assert cleaned.run_removed is True
    assert cleaned.receipt_removed is True
    assert (
        cleanup_owned_fake_terminal_lifecycle(
            result,
            deadline=MonotonicDeadline.after(10),
        )
        is cleaned
    )
    assert not env.bundle.exists()
    env.closed = True
    return cleaned


def _new_lifecycle(
    env: _K2Environment,
    event: FakeTerminalEvent,
    sequence: FakeTerminalSequence = FakeTerminalSequence.IMMEDIATE,
    work_count: int = 0,
) -> FakeTerminalLifecycle:
    lifecycle = make_owned_fake_terminal_lifecycle(
        env.handle,
        plan=FakeTerminalPlan(event, sequence, work_count),
    )
    assert type(lifecycle) is FakeTerminalLifecycle
    return lifecycle


def _apply(
    env: _K2Environment,
    lifecycle: FakeTerminalLifecycle,
    *,
    seconds: float = 10,
) -> OwnedFakeTerminalLifecycleResult | OwnedFakeTerminalFailure:
    return apply_owned_fake_terminal_lifecycle(
        lifecycle,
        deadline=MonotonicDeadline.after(seconds),
        cancellation=env.cancellation,
    )


@pytest.fixture
def k2_env(monkeypatch: pytest.MonkeyPatch):
    original_sessions_dir = sessions.SESSIONS_DIR
    original_profile_dir = profile_module.DEFAULT_PROFILE_DIRECTORY
    original_home = os.environ.get("HOME")
    shipped_before = hashlib.sha256(_SHIPPED_PROFILE.read_bytes()).hexdigest()
    assert shipped_before == _SHIPPED_PROFILE_SHA256

    with tempfile.TemporaryDirectory(
        prefix=".raptor-terminal-k2-",
        dir=Path.home(),
    ) as raw:
        outer = Path(raw)
        outer.chmod(0o700)
        owned_root = outer / "caller-root"
        owned_root.mkdir(mode=0o700)
        guard = outer / "real-sessions"
        guard.mkdir(mode=0o700)

        with monkeypatch.context() as scoped:
            scoped.setattr(sessions, "SESSIONS_DIR", guard)
            before = set(owned_root.iterdir())
            launch_capability = make_owned_runtime_receipt_fake(
                owned_root,
                behavior=FakeRuntimeBehavior(
                    descendants=FakeDescendantShape.CHILD_AND_GRANDCHILD
                ),
            )
            if isinstance(launch_capability, FakeRuntimeUnsupported):
                pytest.skip(launch_capability.reason)
            created = set(owned_root.iterdir()) - before
            assert len(created) == 1
            bundle = created.pop()
            registry = bundle / "registry/sessions.d"
            scoped.setattr(sessions, "SESSIONS_DIR", registry)

            cancellation = LaunchCancellation()
            handle = _launch_owned_runtime_fake(
                launch_capability,
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
            launch_record = launch_module._record_for_handle(handle)
            assert not isinstance(launch_record, LaunchFailure)
            assert launch_record.current_receipt is not None

            profile_dir = bundle / "pytest-profiles"
            profile_dir.mkdir(mode=0o700)
            profile_path = profile_dir / "owned-fake.json"
            profile_path.write_text(
                dumps_artifact(
                    to_json_value(launch_record.capability.profile),
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            profile_path.chmod(0o600)
            store = load_profile_store(profile_dir)
            assert type(store) is ProfileStore
            assert store.profiles == (launch_record.capability.profile,)
            reference = launch_record.current_receipt.reference
            static = verify_receipt_static(
                launch_record.current_receipt.receipt,
                profiles=store,
                expected=ExpectedBinding(
                    session_id=reference.session_id.value,
                    launch_id=reference.launch_id.value,
                    session_pid=reference.session_pid.value,
                    session_starttime_ticks=(reference.session_starttime_ticks.value),
                    boot_id=reference.boot_id.value,
                    pid_namespace_inode=reference.pid_namespace_inode.value,
                    launcher_euid=reference.launcher_euid.value,
                    token_hex=launch_record.token_hex,
                ),
                now=datetime.now(timezone.utc),
            )
            assert type(static) is StaticallyVerifiedReceipt

            fake_home = outer / "home"
            fake_home.mkdir(mode=0o700)
            scoped.setenv("HOME", str(fake_home))
            scoped.setattr(
                profile_module,
                "DEFAULT_PROFILE_DIRECTORY",
                profile_dir,
            )
            scoped.setattr(
                "core.run.provenance.build_start_manifest",
                lambda **_kwargs: {"provenance": "owned-fake-terminal-k2"},
            )
            scoped.setattr(
                "core.run.provenance.standard_completion_provenance",
                lambda *_args, **_kwargs: {
                    "engines": {},
                    "deterministically_reproducible": True,
                },
            )
            scoped.setattr("core.run.tmp_reaper.reap_stale_tmp", lambda: None)
            scoped.setattr("core.run.tmp_reaper.reap_stale_logs", lambda: None)
            scoped.setattr(
                "core.run.tmp_reaper.reap_stale_runs",
                lambda _parent: [],
            )
            active_calls: list[Path | None] = []
            real_set_active = sandbox_summary.set_active_run_dir

            def tracked_active(value: Path | None) -> None:
                active_calls.append(None if value is None else Path(value))
                real_set_active(value)

            scoped.setattr(
                sandbox_summary,
                "set_active_run_dir",
                tracked_active,
            )
            frozen_calls: list[tuple[Path, str | None, str]] = []
            scoped.setattr(
                "core.run.pin.freeze_run_pin",
                lambda run_dir, project, source: frozen_calls.append(
                    (Path(run_dir), project, source)
                ),
            )
            ledger_calls: list[str] = []

            def forbidden_ledger(
                *_args: object,
                __name: str = "",
                **_kwargs: object,
            ) -> None:
                ledger_calls.append(__name)
                raise AssertionError(f"receipt lifecycle called {__name}")

            for name in (
                "ledger_record_start",
                "ledger_record_resume",
                "ledger_record_finish",
            ):
                scoped.setattr(
                    sessions,
                    name,
                    lambda *args, __name=name, **kwargs: forbidden_ledger(
                        *args,
                        __name=__name,
                        **kwargs,
                    ),
                )
            scoped.setattr(
                subprocess,
                "run",
                lambda *_args, **_kwargs: pytest.fail(
                    "K2 lifecycle executed a subprocess"
                ),
            )
            set_process_project(None)
            env = _K2Environment(
                outer=outer,
                bundle=bundle,
                registry=registry,
                profile_dir=profile_dir,
                profile_path=profile_path,
                handle=handle,
                cancellation=cancellation,
                launch_record=launch_record,
                static_verification=static,
                active_calls=active_calls,
                frozen_calls=frozen_calls,
                ledger_calls=ledger_calls,
            )
            try:
                with _owned_runtime_fake_session_binding(handle):
                    yield env
            finally:
                set_process_project(None)
                real_set_active(None)
                if not env.closed:
                    runs_root = bundle / "runs"
                    if runs_root.exists():
                        for child in tuple(runs_root.iterdir()):
                            _remove_run_tree(child)
                    _remove_fixture_profile(env)
                    if bundle.exists():
                        closed = _close_owned_runtime_fake(
                            handle,
                            deadline=MonotonicDeadline.after(10),
                        )
                        assert type(closed) is LaunchClosed
                cancellation.close()
        assert sessions.SESSIONS_DIR == original_sessions_dir
        assert profile_module.DEFAULT_PROFILE_DIRECTORY == original_profile_dir
        assert os.environ.get("HOME") == original_home
        assert hashlib.sha256(_SHIPPED_PROFILE.read_bytes()).hexdigest() == (
            _SHIPPED_PROFILE_SHA256
        )


def test_bc_t2_profile_start_is_projectless_and_non_authorizing(
    k2_env: _K2Environment,
) -> None:
    assert tuple(
        reason.value for reason in k2_env.static_verification.reason_codes
    ) == ("profile_unsupported", "live_contract_missing")
    assert k2_env.static_verification.authoritative is False
    lifecycle = _new_lifecycle(k2_env, FakeTerminalEvent.COMPLETE)
    metadata = load_json(lifecycle.run_dir / md.RUN_METADATA_FILE)
    assert metadata["status"] == md.STATUS_RUNNING
    assert metadata["project"] is None
    assert metadata["project_source"] == "session"
    assert metadata["manifest"] == {"provenance": "owned-fake-terminal-k2"}
    current_receipt = k2_env.launch_record.current_receipt
    assert isinstance(current_receipt, launch_module.VerifiedReceiptIssued)
    assert metadata[md.RUN_RUNTIME_RECEIPT_KEY] == json.loads(
        terminal_module.serialize_snapshot(current_receipt.snapshot)
    )
    assert md.RUN_RUNTIME_RECEIPT_LINEAGE_KEY not in metadata
    assert not any(
        key in metadata
        for key in (
            "session_pid",
            "tool_pid",
            "session_start",
            "session_boot_id",
            "session_pidns",
            "session_host",
        )
    )
    assert not (k2_env.registry / f"{k2_env.launch_record.child_pid}.run").exists()
    assert not (lifecycle.run_dir / "checklist.json").exists()
    assert k2_env.active_calls == [lifecycle.run_dir]
    assert k2_env.frozen_calls == [(lifecycle.run_dir, None, "session")]
    _discard_lifecycle(k2_env, lifecycle)


@pytest.mark.parametrize("event", tuple(FakeTerminalEvent))
@pytest.mark.parametrize(
    ("sequence", "work_count"),
    (
        (FakeTerminalSequence.IMMEDIATE, 0),
        (FakeTerminalSequence.BACKGROUND_DRAIN, 3),
    ),
)
def test_all_terminal_events_drive_exact_ledgerless_lifecycle(
    k2_env: _K2Environment,
    event: FakeTerminalEvent,
    sequence: FakeTerminalSequence,
    work_count: int,
) -> None:
    lifecycle = _new_lifecycle(k2_env, event, sequence, work_count)
    result = _apply(k2_env, lifecycle)
    assert type(result) is OwnedFakeTerminalLifecycleResult
    expected_status = {
        FakeTerminalEvent.COMPLETE: md.STATUS_COMPLETED,
        FakeTerminalEvent.FAIL: md.STATUS_FAILED,
        FakeTerminalEvent.INTERRUPT: md.STATUS_INTERRUPTED,
        FakeTerminalEvent.CANCEL: md.STATUS_CANCELLED,
    }[event]
    assert result.terminal_status == expected_status
    assert result.event_kind == event.name.lower()
    assert result.sequence_mode == sequence.name.lower()
    assert result.work_count == work_count
    assert result.segment == 1
    assert result.authoritative is False
    assert _apply(k2_env, lifecycle) is result
    if sequence is FakeTerminalSequence.BACKGROUND_DRAIN:
        assert result.trace.index(TerminalPhase.WORK_DRAINED.value) < (
            result.trace.index(TerminalPhase.METADATA_APPLIED.value)
        )
    assert result.trace.index(TerminalPhase.READY.value) < result.trace.index(
        TerminalPhase.METADATA_APPLIED.value
    )
    assert result.trace.index(TerminalPhase.EFFECTS_VERIFIED.value) < (
        result.trace.index(TerminalPhase.ACKED.value)
    )

    metadata = load_json(lifecycle.run_dir / md.RUN_METADATA_FILE)
    assert metadata["status"] == expected_status
    assert metadata["project"] is None
    assert metadata["project_source"] == "session"
    assert "session_pid" not in metadata
    if event is FakeTerminalEvent.FAIL:
        assert metadata["extra"]["error"] == "owned_fake_terminal_failure"
    elif event is FakeTerminalEvent.CANCEL:
        assert metadata["extra"]["cancel_reason"] == "owned_fake_terminal_cancel"
    elif event is FakeTerminalEvent.INTERRUPT:
        assert metadata["extra"]["interrupt_reason"] == "owned_fake_terminal_interrupt"
    read_record = load_json(lifecycle.run_dir / "coverage-read.json")
    expected_read_digest = hashlib.sha256(
        dumps_canonical(
            {
                "tool": "read",
                "files_examined": sorted(_READ_FILES),
            }
        ).encode("utf-8")
    ).hexdigest()
    assert result.read_record_sha256 == expected_read_digest
    assert read_record["tool"] == "read"
    assert read_record["files_examined"] == sorted(_READ_FILES)
    assert (lifecycle.run_dir / ".reads-manifest").read_bytes() == (
        terminal_module._TERMINAL_READ_MANIFEST
    )
    assert not (k2_env.bundle / "runs/coverage.json").exists()
    assert not (k2_env.bundle / "runs/checklist.json").exists()
    assert k2_env.ledger_calls == []
    assert sandbox_summary.get_active_run_dir() is None

    direct = {
        FakeTerminalEvent.COMPLETE: lambda: md.complete_run(lifecycle.run_dir),
        FakeTerminalEvent.FAIL: lambda: md.fail_run(lifecycle.run_dir),
        FakeTerminalEvent.INTERRUPT: lambda: md.interrupt_run(lifecycle.run_dir),
        FakeTerminalEvent.CANCEL: lambda: md.cancel_run(lifecycle.run_dir),
    }[event]
    before = (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes()
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        direct()
    assert raised.value.reason is md.RunReceiptReason.TERMINAL_TRANSITION_FORBIDDEN
    assert (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes() == before
    _cleanup_result(k2_env, result)


@pytest.mark.parametrize("event", tuple(FakeTerminalEvent))
def test_exact_wrapper_arguments_are_frozen(
    k2_env: _K2Environment,
    monkeypatch: pytest.MonkeyPatch,
    event: FakeTerminalEvent,
) -> None:
    lifecycle = _new_lifecycle(k2_env, event)
    calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []
    originals: dict[str, Any] = {
        "complete": md.complete_run,
        "fail": md.fail_run,
        "interrupt": md.interrupt_run,
        "cancel": md.cancel_run,
    }

    def wrap(name: str):
        def invoked(*args: object, **kwargs: object) -> None:
            calls.append((name, args, dict(kwargs)))
            originals[name](*args, **kwargs)

        return invoked

    for name in originals:
        monkeypatch.setattr(md, f"{name}_run", wrap(name))
    result = _apply(k2_env, lifecycle)
    assert type(result) is OwnedFakeTerminalLifecycleResult
    assert len(calls) == 1
    name, args, kwargs = calls[0]
    assert args == (lifecycle.run_dir,)
    if event is FakeTerminalEvent.COMPLETE:
        assert (name, kwargs) == (
            "complete",
            {
                "extra": None,
                "expected_command": terminal_module._TERMINAL_RUN_COMMAND,
            },
        )
    elif event is FakeTerminalEvent.FAIL:
        assert (name, kwargs) == (
            "fail",
            {
                "error": "owned_fake_terminal_failure",
                "extra": {},
                "expected_command": terminal_module._TERMINAL_RUN_COMMAND,
            },
        )
    elif event is FakeTerminalEvent.CANCEL:
        assert (name, kwargs) == (
            "cancel",
            {
                "extra": {
                    "cancel_reason": "owned_fake_terminal_cancel",
                },
                "expected_command": terminal_module._TERMINAL_RUN_COMMAND,
            },
        )
    else:
        assert (name, kwargs) == (
            "interrupt",
            {
                "reason": "owned_fake_terminal_interrupt",
                "expected_command": terminal_module._TERMINAL_RUN_COMMAND,
            },
        )
    _cleanup_result(k2_env, result)


@pytest.mark.parametrize(
    "direct",
    (
        lambda run: md.complete_run(run),
        lambda run: md.fail_run(run),
        lambda run: md.interrupt_run(run),
        lambda run: md.cancel_run(run),
    ),
)
def test_unconsumed_capability_is_not_ambient_authority(
    k2_env: _K2Environment,
    direct: Callable[[Path], None],
) -> None:
    lifecycle = _new_lifecycle(k2_env, FakeTerminalEvent.COMPLETE)
    before = (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes()
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        direct(lifecycle.run_dir)
    assert raised.value.reason is md.RunReceiptReason.TERMINAL_TRANSITION_FORBIDDEN
    assert (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes() == before
    result = _apply(k2_env, lifecycle)
    assert type(result) is OwnedFakeTerminalLifecycleResult
    _cleanup_result(k2_env, result)


@pytest.mark.parametrize(
    "case",
    (
        "wrong-target-status",
        "parsed-dict-mismatch",
        "metadata-race",
        "unsafe-lock",
    ),
)
def test_t8_t15_under_lock_permit_checks_fail_closed_and_spend(
    k2_env: _K2Environment,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    lifecycle = _new_lifecycle(k2_env, FakeTerminalEvent.COMPLETE)
    path = lifecycle.run_dir / md.RUN_METADATA_FILE
    original = path.read_bytes()
    mutated: bytes | None = None
    lock_path = path.with_suffix(path.suffix + ".lock")

    if case == "wrong-target-status":

        def wrong_target(record: terminal_module._TerminalRecord) -> None:
            assert terminal_module._query_owned_fake_terminal_permit(
                path,
                load_json(path),
                "complete",
            )
            md._update_status(lifecycle.run_dir, md.STATUS_FAILED)

        monkeypatch.setattr(
            terminal_module,
            "_invoke_lifecycle_wrapper",
            wrong_target,
        )
    elif case == "parsed-dict-mismatch":
        real_load_json = md.load_json

        def parsed_mismatch(record: terminal_module._TerminalRecord) -> None:
            del record
            assert terminal_module._query_owned_fake_terminal_permit(
                path,
                real_load_json(path),
                "complete",
            )

            def altered(*args: object, **kwargs: object):
                value = real_load_json(*args, **kwargs)
                assert isinstance(value, dict)
                changed = copy.deepcopy(value)
                changed["extra"] = {"forged": True}
                return changed

            monkeypatch.setattr(md, "load_json", altered)
            try:
                md._update_status(lifecycle.run_dir, md.STATUS_COMPLETED)
            finally:
                monkeypatch.setattr(md, "load_json", real_load_json)

        monkeypatch.setattr(
            terminal_module,
            "_invoke_lifecycle_wrapper",
            parsed_mismatch,
        )
    elif case == "metadata-race":

        def metadata_race(record: terminal_module._TerminalRecord) -> None:
            del record
            assert terminal_module._query_owned_fake_terminal_permit(
                path,
                load_json(path),
                "complete",
            )
            nonlocal mutated
            mutated = original + b" "
            path.write_bytes(mutated)
            path.chmod(0o600)
            md._update_status(lifecycle.run_dir, md.STATUS_COMPLETED)

        monkeypatch.setattr(
            terminal_module,
            "_invoke_lifecycle_wrapper",
            metadata_race,
        )
    else:
        lock_path.chmod(0o666)

    result = _apply(k2_env, lifecycle)
    assert type(result) is OwnedFakeTerminalFailure
    assert result.disposition is TerminalDisposition.TRANSITION_FAILED
    assert result.reason_codes == (TerminalReason.TERMINAL_TRANSITION_FORBIDDEN,)
    assert _apply(k2_env, lifecycle) is result
    assert load_json(path)["status"] == md.STATUS_RUNNING
    if case == "metadata-race":
        assert mutated is not None
        assert path.read_bytes() == mutated
        path.write_bytes(original)
        path.chmod(0o600)
    else:
        assert path.read_bytes() == original
    if case == "unsafe-lock":
        lock_path.chmod(0o600)
    _discard_lifecycle(k2_env, lifecycle)


def test_t18_session_fence_spans_wrapper_without_python_locks(
    k2_env: _K2Environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = _new_lifecycle(k2_env, FakeTerminalEvent.COMPLETE)
    observed: list[str] = []

    def checked(stage: str, _capability_id: str) -> None:
        if stage != "before_wrapper":
            return
        assert not getattr(terminal_module._STATE_LOCK, "_is_owned")()
        assert not getattr(launch_module._STATE_LOCK, "_is_owned")()
        with pytest.raises(sessions._SessionReceiptAbort) as raised:
            with sessions._strict_session_lock(
                k2_env.launch_record.child_pid,
                attempts=1,
                interval=0,
            ):
                pass
        assert raised.value.failure.reason_codes[0].value == ("concurrent_finalizer")
        observed.append("lock_busy")

    monkeypatch.setattr(terminal_module, "_terminal_lifecycle_hook", checked)
    result = _apply(k2_env, lifecycle)
    assert type(result) is OwnedFakeTerminalLifecycleResult
    assert observed == ["lock_busy"]
    _cleanup_result(k2_env, result)


@pytest.mark.parametrize(
    "first_event",
    (
        FakeTerminalEvent.FAIL,
        FakeTerminalEvent.CANCEL,
        FakeTerminalEvent.INTERRUPT,
    ),
)
def test_t5_same_launch_resume_rearms_fresh_generation(
    k2_env: _K2Environment,
    first_event: FakeTerminalEvent,
) -> None:
    first = _new_lifecycle(k2_env, first_event)
    first_result = _apply(k2_env, first)
    assert type(first_result) is OwnedFakeTerminalLifecycleResult
    first_raw = (first.run_dir / md.RUN_METADATA_FILE).read_bytes()

    resumed = resume_owned_fake_terminal_lifecycle(
        first_result,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(resumed) is FakeTerminalLifecycle
    assert resumed.run_dir == first.run_dir
    resumed_meta = load_json(resumed.run_dir / md.RUN_METADATA_FILE)
    assert resumed_meta["status"] == md.STATUS_RUNNING
    assert resumed_meta["extra"]["resumes"][-1] == {
        "ts": resumed_meta[md.RUN_RUNTIME_RECEIPT_LINEAGE_KEY]["entries"][-1][
            "resumed_at_utc"
        ],
        "prior_status": first_result.terminal_status,
        "segment": 2,
        "note": terminal_module._TERMINAL_RESUME_NOTE,
    }
    lineage = resumed_meta[md.RUN_RUNTIME_RECEIPT_LINEAGE_KEY]
    assert lineage["entries"][-1]["relation"] == "exact"
    assert (
        resumed_meta[md.RUN_RUNTIME_RECEIPT_KEY]
        == load_json(first.run_dir / md.RUN_METADATA_FILE)[md.RUN_RUNTIME_RECEIPT_KEY]
    )
    assert (resumed.run_dir / md.RUN_METADATA_FILE).read_bytes() != first_raw
    assert not (k2_env.registry / f"{k2_env.launch_record.child_pid}.run").exists()
    assert k2_env.ledger_calls == []

    stale = _apply(k2_env, first)
    assert type(stale) is OwnedFakeTerminalFailure
    assert stale.reason_codes == (TerminalReason.METADATA_CHANGED,)
    stale_cleanup = cleanup_owned_fake_terminal_lifecycle(
        first_result,
        deadline=MonotonicDeadline.after(1),
    )
    assert type(stale_cleanup) is OwnedFakeTerminalFailure
    assert stale_cleanup.reason_codes == (TerminalReason.CAPABILITY_REUSED,)

    final_result = _apply(k2_env, resumed)
    assert type(final_result) is OwnedFakeTerminalLifecycleResult
    assert final_result.segment == 2
    assert final_result.terminal_status == md.STATUS_COMPLETED
    _cleanup_result(k2_env, final_result)


def test_completed_result_cannot_resume(
    k2_env: _K2Environment,
) -> None:
    lifecycle = _new_lifecycle(k2_env, FakeTerminalEvent.COMPLETE)
    result = _apply(k2_env, lifecycle)
    assert type(result) is OwnedFakeTerminalLifecycleResult
    refused = resume_owned_fake_terminal_lifecycle(
        result,
        plan=FakeTerminalPlan(FakeTerminalEvent.COMPLETE),
    )
    assert type(refused) is OwnedFakeTerminalFailure
    assert refused.reason_codes == (TerminalReason.TERMINAL_STATUS_CONFLICT,)
    _cleanup_result(k2_env, result)


def test_same_capability_concurrency_has_one_effect_and_busy_loser(
    k2_env: _K2Environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = _new_lifecycle(k2_env, FakeTerminalEvent.COMPLETE)
    entered = threading.Event()
    release = threading.Event()

    def blocked(stage: str, _capability_id: str) -> None:
        if stage == "before_wrapper":
            entered.set()
            assert release.wait(timeout=10)

    monkeypatch.setattr(terminal_module, "_terminal_lifecycle_hook", blocked)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_apply, k2_env, lifecycle)
        assert entered.wait(timeout=10)
        loser = _apply(k2_env, lifecycle)
        assert type(loser) is OwnedFakeTerminalFailure
        assert loser.reason_codes == (TerminalReason.LAUNCH_OPERATION_BUSY,)
        close_loser = _close_owned_runtime_fake(
            k2_env.handle,
            deadline=MonotonicDeadline.after(1),
        )
        assert type(close_loser) is LaunchFailure
        assert close_loser.diagnostics == {"stage": "operation_in_progress"}
        release.set()
        winner = future.result(timeout=10)
    assert type(winner) is OwnedFakeTerminalLifecycleResult
    assert _apply(k2_env, lifecycle) is winner
    _cleanup_result(k2_env, winner)


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
def test_invalid_terminal_events_never_mutate_lifecycle(
    k2_env: _K2Environment,
    sequence: FakeTerminalSequence,
    reason: TerminalReason,
) -> None:
    lifecycle = _new_lifecycle(k2_env, FakeTerminalEvent.FAIL, sequence)
    before = (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes()
    failure = _apply(k2_env, lifecycle)
    assert type(failure) is OwnedFakeTerminalFailure
    if sequence in {
        FakeTerminalSequence.CHILD_EXIT_BEFORE_EVENT,
        FakeTerminalSequence.CONTROL_EOF,
    }:
        assert failure.reason_codes[0] in {
            reason,
            TerminalReason.TERMINAL_EVENT_EOF,
            TerminalReason.PROCESS_BINDING_CHANGED,
        }
    else:
        assert failure.reason_codes == (reason,)
    assert TerminalPhase.METADATA_APPLIED.value not in failure.trace
    assert (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes() == before
    assert load_json(lifecycle.run_dir / md.RUN_METADATA_FILE)["status"] == (
        md.STATUS_RUNNING
    )
    assert not (lifecycle.run_dir / "coverage-read.json").exists()
    assert _apply(k2_env, lifecycle) is failure
    _discard_lifecycle(k2_env, lifecycle)


@pytest.mark.parametrize("cancelled", (False, True))
def test_timeout_and_wait_cancel_spend_without_terminal_inference(
    k2_env: _K2Environment,
    cancelled: bool,
) -> None:
    lifecycle = _new_lifecycle(
        k2_env,
        FakeTerminalEvent.CANCEL,
        FakeTerminalSequence.TIMEOUT,
    )
    before = (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes()
    if cancelled:
        k2_env.cancellation.cancel()
    failure = _apply(k2_env, lifecycle, seconds=0.05)
    assert type(failure) is OwnedFakeTerminalFailure
    assert failure.reason_codes == (
        TerminalReason.WAIT_CANCELLED
        if cancelled
        else TerminalReason.DEADLINE_EXCEEDED,
    )
    assert (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes() == before
    assert _apply(k2_env, lifecycle) is failure
    _discard_lifecycle(k2_env, lifecycle)


def test_exact_duplicate_coalesces_one_lifecycle_effect(
    k2_env: _K2Environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lifecycle = _new_lifecycle(
        k2_env,
        FakeTerminalEvent.COMPLETE,
        FakeTerminalSequence.EXACT_DUPLICATE,
    )
    calls = 0
    real_complete = md.complete_run

    def counted(
        output_dir: Path,
        extra: dict[str, Any] | None = None,
        manifest: dict[str, Any] | None = None,
        expected_command: str | None = None,
    ) -> None:
        nonlocal calls
        calls += 1
        real_complete(
            output_dir,
            extra=extra,
            manifest=manifest,
            expected_command=expected_command,
        )

    monkeypatch.setattr(md, "complete_run", counted)
    result = _apply(k2_env, lifecycle)
    assert type(result) is OwnedFakeTerminalLifecycleResult
    assert result.duplicate_count == 1
    assert calls == 1
    assert _apply(k2_env, lifecycle) is result
    _cleanup_result(k2_env, result)


@pytest.mark.parametrize(
    "shape",
    (
        "unexpected",
        "receipt-temp",
        "symlink",
        "hardlink",
        "metadata-replacement",
    ),
)
def test_t7_cleanup_refuses_tampering_then_repairs_and_retries(
    k2_env: _K2Environment,
    shape: str,
) -> None:
    lifecycle = _new_lifecycle(k2_env, FakeTerminalEvent.COMPLETE)
    result = _apply(k2_env, lifecycle)
    assert type(result) is OwnedFakeTerminalLifecycleResult
    run_dir = lifecycle.run_dir
    coverage = run_dir / "coverage-read.json"
    metadata = run_dir / md.RUN_METADATA_FILE
    repair = lambda: None

    if shape == "unexpected":
        planted = run_dir / "unexpected"
        planted.write_bytes(b"x")
        planted.chmod(0o600)
        repair = planted.unlink
    elif shape == "receipt-temp":
        planted = run_dir / ".raptor-run.json.receipt.1.2.abcdef.tmp"
        planted.write_bytes(b"x")
        planted.chmod(0o600)
        repair = planted.unlink
    elif shape == "symlink":
        retained = k2_env.outer / "retained-coverage"
        coverage.rename(retained)
        target = k2_env.outer / "outside-coverage"
        target.write_bytes(retained.read_bytes())
        target.chmod(0o600)
        coverage.symlink_to(target)

        def repair_symlink() -> None:
            coverage.unlink()
            retained.rename(coverage)
            target.unlink()

        repair = repair_symlink
    elif shape == "hardlink":
        alias = k2_env.outer / "coverage-alias"
        os.link(coverage, alias)
        repair = alias.unlink
    else:
        original = metadata.read_bytes()
        retained = k2_env.outer / "retained-metadata"
        metadata.rename(retained)
        metadata.write_bytes(original)
        metadata.chmod(0o600)

        def repair_replacement() -> None:
            metadata.unlink()
            retained.rename(metadata)

        repair = repair_replacement

    _remove_fixture_profile(k2_env)
    refused = cleanup_owned_fake_terminal_lifecycle(
        result,
        deadline=MonotonicDeadline.after(2),
    )
    assert type(refused) is OwnedFakeTerminalFailure
    assert refused.disposition is TerminalDisposition.CLEANUP_FAILED
    assert refused.reason_codes == (TerminalReason.RUN_CLEANUP_FAILED,)
    assert run_dir.exists()
    repair()
    cleaned = cleanup_owned_fake_terminal_lifecycle(
        result,
        deadline=MonotonicDeadline.after(10),
    )
    assert type(cleaned) is OwnedFakeTerminalCleanupResult
    assert not k2_env.bundle.exists()
    k2_env.closed = True


def test_bound_capability_and_results_are_redacted_noncopyable_and_nonpublic(
    k2_env: _K2Environment,
) -> None:
    lifecycle = _new_lifecycle(k2_env, FakeTerminalEvent.COMPLETE)
    record = terminal_module._CAPABILITIES[lifecycle._capability._capability_id]
    assert record.run_binding is not None
    current_receipt = k2_env.launch_record.current_receipt
    assert isinstance(current_receipt, launch_module.VerifiedReceiptIssued)
    secrets_to_hide = (
        str(lifecycle.run_dir),
        str(k2_env.launch_record.child_pid),
        lifecycle._capability._capability_id,
        lifecycle._capability._capability_mac,
        record.event_nonce.hex(),
        k2_env.launch_record.token_hex,
        current_receipt.reference.receipt_sha256.value,
    )
    assert repr(lifecycle) == "FakeTerminalLifecycle(<redacted>)"
    with pytest.raises(TypeError):
        bool(lifecycle)
    with pytest.raises(TypeError):
        pickle.dumps(lifecycle)

    result = _apply(k2_env, lifecycle)
    assert type(result) is OwnedFakeTerminalLifecycleResult
    with pytest.raises(TypeError):
        bool(result)
    with pytest.raises(TypeError):
        pickle.dumps(result)
    rendered = repr(result) + str(result)
    for secret in secrets_to_hide:
        assert secret not in rendered
    _cleanup_result(k2_env, result)


def test_fork_descendant_cannot_use_bound_lifecycle_capability(
    k2_env: _K2Environment,
) -> None:
    lifecycle = _new_lifecycle(k2_env, FakeTerminalEvent.COMPLETE)
    before = (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes()
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    child_pid = os.fork()
    if child_pid == 0:
        os.close(read_fd)
        with LaunchCancellation() as cancellation:
            result = apply_owned_fake_terminal_lifecycle(
                lifecycle,
                deadline=MonotonicDeadline.after(1),
                cancellation=cancellation,
            )
        assert type(result) is OwnedFakeTerminalFailure
        os.write(
            write_fd,
            f"{result.reason_codes[0].value}\n".encode("ascii"),
        )
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    raw = os.read(read_fd, 4096)
    os.close(read_fd)
    waited, status = os.waitpid(child_pid, 0)
    assert waited == child_pid
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0
    assert raw == b"invalid_capability\n"
    assert (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes() == before
    result = _apply(k2_env, lifecycle)
    assert type(result) is OwnedFakeTerminalLifecycleResult
    _cleanup_result(k2_env, result)


def test_raw_path_payload_pid_env_model_and_receipt_objects_cannot_retarget(
    k2_env: _K2Environment,
) -> None:
    lifecycle = _new_lifecycle(k2_env, FakeTerminalEvent.COMPLETE)
    metadata = load_json(lifecycle.run_dir / md.RUN_METADATA_FILE)
    assert (
        terminal_module._query_owned_fake_terminal_permit(
            lifecycle.run_dir / md.RUN_METADATA_FILE,
            metadata,
            "complete",
        )
        is False
    )
    for value in (
        lifecycle.run_dir,
        k2_env.launch_record.child_pid,
        dict(os.environ),
        {"event": "complete"},
        {"payload": metadata},
        "model-output",
        k2_env.launch_record.current_receipt,
    ):
        refused = terminal_module._apply_owned_fake_terminal_lifecycle(
            value,
            deadline=MonotonicDeadline.after(1),
            cancellation=k2_env.cancellation,
        )
        assert type(refused) is OwnedFakeTerminalFailure
        assert refused.reason_codes == (TerminalReason.INVALID_CAPABILITY,)
    forged = object.__new__(FakeTerminalLifecycle)
    object.__setattr__(forged, "_capability", lifecycle._capability)
    object.__setattr__(forged, "_run_dir", k2_env.outer / "foreign-run")
    result = _apply(k2_env, forged)
    assert type(result) is OwnedFakeTerminalLifecycleResult
    assert result.terminal_status == md.STATUS_COMPLETED
    assert not (k2_env.outer / "foreign-run").exists()
    _cleanup_result(k2_env, result)


def test_run_lifecycle_subprocess_cannot_inherit_process_local_permit(
    k2_env: _K2Environment,
) -> None:
    lifecycle = _new_lifecycle(k2_env, FakeTerminalEvent.COMPLETE)
    before = (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes()
    script = Path(__file__).parents[3] / "libexec/raptor-run-lifecycle"
    result = subprocess.Popen(
        [
            os.environ.get("PYTHON", "python3"),
            str(script),
            "complete",
            str(lifecycle.run_dir),
            "--command",
            terminal_module._TERMINAL_RUN_COMMAND,
        ],
        cwd=Path(__file__).parents[3],
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(k2_env.outer / "home"),
            "_RAPTOR_TRUSTED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = result.communicate(timeout=30)
    assert result.returncode == 1
    assert stdout == ""
    assert "terminal_transition_forbidden" in stderr
    assert (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes() == before
    applied = _apply(k2_env, lifecycle)
    assert type(applied) is OwnedFakeTerminalLifecycleResult
    _cleanup_result(k2_env, applied)


def test_512_seeded_no_sleep_k2_invariant_schedules(
    k2_env: _K2Environment,
) -> None:
    lifecycle = _new_lifecycle(k2_env, FakeTerminalEvent.COMPLETE)
    capability = lifecycle._capability
    record = terminal_module._CAPABILITIES[capability._capability_id]
    binding = record.run_binding
    assert binding is not None
    raw = (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes()
    metadata = load_json(lifecycle.run_dir / md.RUN_METADATA_FILE)
    schedules = list(range(512))
    random.Random(0x57414B32).shuffle(schedules)

    for seed in schedules:
        bucket = seed // 64
        if bucket == 0:
            assert terminal_module._bound_run_reason(record) is None
        elif bucket == 1:
            assert hashlib.sha256(raw).hexdigest() == binding.metadata_raw_sha256
        elif bucket == 2:
            assert terminal_module._metadata_snapshot_sha256(metadata) == (
                binding.receipt_snapshot_sha256
            )
        elif bucket == 3:
            assert terminal_module._metadata_segment_value(metadata) == 1
        elif bucket == 4:
            assert not (
                k2_env.registry / f"{k2_env.launch_record.child_pid}.run"
            ).exists()
            assert not (binding.runs_root / "coverage.json").exists()
        elif bucket == 5:
            assert (
                terminal_module._query_owned_fake_terminal_permit(
                    lifecycle.run_dir / md.RUN_METADATA_FILE,
                    metadata,
                    "complete",
                )
                is False
            )
        elif bucket == 6:
            claimed = launch_module._claim_operation(k2_env.handle, "terminal")
            assert not isinstance(claimed, LaunchFailure)
            try:
                conflict = _close_owned_runtime_fake(
                    k2_env.handle,
                    deadline=MonotonicDeadline.after(1),
                )
                assert type(conflict) is LaunchFailure
                assert conflict.diagnostics == {"stage": "operation_in_progress"}
            finally:
                launch_module._release_operation(k2_env.launch_record)
        else:
            assert (
                terminal_module._validate_live_binding(
                    record,
                    k2_env.launch_record,
                )
                is None
            )
            assert terminal_module._initial_binding_matches(
                record,
                k2_env.launch_record,
            )

    tree = ast.parse(inspect.getsource(test_512_seeded_no_sleep_k2_invariant_schedules))
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "sleep"
        for node in ast.walk(tree)
    )
    result = _apply(k2_env, lifecycle)
    assert type(result) is OwnedFakeTerminalLifecycleResult
    _cleanup_result(k2_env, result)


def test_accepted_cross_launch_lineage_stays_non_authorizing(
    k2_env: _K2Environment,
) -> None:
    lifecycle = _new_lifecycle(k2_env, FakeTerminalEvent.FAIL)
    first_result = _apply(k2_env, lifecycle)
    assert type(first_result) is OwnedFakeTerminalLifecycleResult
    first_receipt = k2_env.launch_record.current_receipt
    assert isinstance(first_receipt, launch_module.VerifiedReceiptIssued)
    first_reference = first_receipt.reference

    second_root = k2_env.outer / "second-caller-root"
    second_root.mkdir(mode=0o700)
    second_capability = make_owned_runtime_receipt_fake(second_root)
    if isinstance(second_capability, FakeRuntimeUnsupported):
        pytest.skip(second_capability.reason)
    second_bundle = next(second_root.iterdir())
    second_registry = second_bundle / "registry/sessions.d"
    cross_patch = pytest.MonkeyPatch()
    cross_patch.setattr(sessions, "SESSIONS_DIR", second_registry)
    second_cancellation = LaunchCancellation()
    second_handle = _launch_owned_runtime_fake(
        second_capability,
        deadline=MonotonicDeadline.after(10),
        cancellation=second_cancellation,
    )
    assert type(second_handle) is OwnedFakeLaunchHandle
    second_verified = _finalize_owned_runtime_fake(
        second_handle,
        deadline=MonotonicDeadline.after(20),
        cancellation=second_cancellation,
    )
    assert type(second_verified) is OwnedFakeVerified
    second_record = launch_module._record_for_handle(second_handle)
    assert not isinstance(second_record, LaunchFailure)
    assert second_record.current_receipt is not None
    second_reference = second_record.current_receipt.reference
    assert first_reference.profile_id == second_reference.profile_id
    assert (
        first_reference.stable_identity_sha256
        == second_reference.stable_identity_sha256
    )
    assert first_reference.receipt_sha256 != second_reference.receipt_sha256

    second_profile_dir = second_bundle / "pytest-profiles"
    second_profile_dir.mkdir(mode=0o700)
    second_profile_path = second_profile_dir / "owned-fake.json"
    second_profile_path.write_text(
        dumps_artifact(
            to_json_value(second_record.capability.profile),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    second_profile_path.chmod(0o600)
    cross_patch.setattr(
        profile_module,
        "DEFAULT_PROFILE_DIRECTORY",
        second_profile_dir,
    )
    with _owned_runtime_fake_session_binding(second_handle):
        assert (
            md.resume_run(
                lifecycle.run_dir,
                note=terminal_module._TERMINAL_RESUME_NOTE,
            )
            == 2
        )
    resumed = load_json(lifecycle.run_dir / md.RUN_METADATA_FILE)
    assert resumed["status"] == md.STATUS_RUNNING
    lineage = resumed[md.RUN_RUNTIME_RECEIPT_LINEAGE_KEY]
    assert lineage["entries"][-1]["relation"] == "new_launch_same_stable"
    assert (
        resumed[md.RUN_RUNTIME_RECEIPT_KEY]["receipt_sha256"]
        == second_reference.receipt_sha256.value
    )
    refused = cleanup_owned_fake_terminal_lifecycle(
        first_result,
        deadline=MonotonicDeadline.after(1),
    )
    assert type(refused) is OwnedFakeTerminalFailure
    assert refused.reason_codes == (TerminalReason.RUN_CLEANUP_FAILED,)
    before = (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes()
    with pytest.raises(md.RunRuntimeReceiptError) as raised:
        md.complete_run(lifecycle.run_dir)
    assert raised.value.reason is md.RunReceiptReason.TERMINAL_TRANSITION_FORBIDDEN
    assert (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes() == before
    assert k2_env.ledger_calls == []

    _remove_run_tree(lifecycle.run_dir)
    _remove_fixture_profile(k2_env)
    cross_patch.setattr(sessions, "SESSIONS_DIR", k2_env.registry)
    first_closed = _close_owned_runtime_fake(
        k2_env.handle,
        deadline=MonotonicDeadline.after(10),
    )
    assert type(first_closed) is LaunchClosed
    second_profile_path.unlink()
    second_profile_dir.rmdir()
    cross_patch.setattr(sessions, "SESSIONS_DIR", second_registry)
    second_closed = _close_owned_runtime_fake(
        second_handle,
        deadline=MonotonicDeadline.after(10),
    )
    assert type(second_closed) is LaunchClosed
    second_cancellation.close()
    cross_patch.undo()
    k2_env.closed = True


def test_supervisor_loss_leaves_running_receipt_run_without_recoverable_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with tempfile.TemporaryDirectory(
        prefix=".raptor-terminal-k2-supervisor-",
        dir=Path.home(),
    ) as raw:
        outer = Path(raw)
        outer.chmod(0o700)
        owned_root = outer / "caller-root"
        owned_root.mkdir(mode=0o700)
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        supervisor_pid = os.fork()
        if supervisor_pid == 0:
            os.close(read_fd)
            local_patch = pytest.MonkeyPatch()
            try:
                guard = outer / "guard"
                guard.mkdir(mode=0o700)
                local_patch.setattr(sessions, "SESSIONS_DIR", guard)
                launch_capability = make_owned_runtime_receipt_fake(owned_root)
                if isinstance(launch_capability, FakeRuntimeUnsupported):
                    os.write(
                        write_fd,
                        f"unsupported:{launch_capability.reason}".encode("ascii"),
                    )
                    os.close(write_fd)
                    os._exit(0)
                bundle = next(owned_root.iterdir())
                registry = bundle / "registry/sessions.d"
                local_patch.setattr(sessions, "SESSIONS_DIR", registry)
                cancellation = LaunchCancellation()
                handle = _launch_owned_runtime_fake(
                    launch_capability,
                    deadline=MonotonicDeadline.after(10),
                    cancellation=cancellation,
                )
                if type(handle) is not OwnedFakeLaunchHandle:
                    os.write(write_fd, b"launch-failed")
                    os.close(write_fd)
                    os._exit(1)
                verified = _finalize_owned_runtime_fake(
                    handle,
                    deadline=MonotonicDeadline.after(20),
                    cancellation=cancellation,
                )
                if type(verified) is not OwnedFakeVerified:
                    os.write(write_fd, b"verify-failed")
                    os.close(write_fd)
                    os._exit(1)
                record = launch_module._record_for_handle(handle)
                assert not isinstance(record, LaunchFailure)
                profile_dir = bundle / "pytest-profiles"
                profile_dir.mkdir(mode=0o700)
                profile_path = profile_dir / "owned-fake.json"
                profile_path.write_text(
                    dumps_artifact(
                        to_json_value(record.capability.profile),
                        indent=2,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                profile_path.chmod(0o600)
                local_patch.setattr(
                    profile_module,
                    "DEFAULT_PROFILE_DIRECTORY",
                    profile_dir,
                )
                local_patch.setenv("HOME", str(outer))
                local_patch.setattr(
                    "core.run.provenance.build_start_manifest",
                    lambda **_kwargs: {"provenance": "supervisor-loss"},
                )
                local_patch.setattr(
                    "core.run.tmp_reaper.reap_stale_tmp",
                    lambda: None,
                )
                local_patch.setattr(
                    "core.run.tmp_reaper.reap_stale_logs",
                    lambda: None,
                )
                local_patch.setattr(
                    "core.run.tmp_reaper.reap_stale_runs",
                    lambda _parent: [],
                )
                with _owned_runtime_fake_session_binding(handle):
                    lifecycle = make_owned_fake_terminal_lifecycle(
                        handle,
                        plan=FakeTerminalPlan(
                            FakeTerminalEvent.FAIL,
                            FakeTerminalSequence.TIMEOUT,
                        ),
                    )
                    assert type(lifecycle) is FakeTerminalLifecycle
                    payload = (
                        f"{bundle.name}\n"
                        f"{record.child_pid}\n"
                        f"{lifecycle.run_dir.relative_to(bundle).as_posix()}\n"
                    ).encode("ascii")
                    os.write(write_fd, payload)
                    os.close(write_fd)
                    os._exit(0)
            finally:
                local_patch.undo()
        os.close(write_fd)
        raw_payload = bytearray()
        while True:
            chunk = os.read(read_fd, 4096)
            if not chunk:
                break
            raw_payload.extend(chunk)
        os.close(read_fd)
        waited, status = os.waitpid(supervisor_pid, 0)
        assert waited == supervisor_pid
        assert os.WIFEXITED(status)
        text = raw_payload.decode("ascii")
        if text.startswith("unsupported:"):
            pytest.skip(text.partition(":")[2])
        assert "failed" not in text
        bundle_name, pid_text, run_relative = text.splitlines()
        native_pid = int(pid_text)
        try:
            pidfd = os.pidfd_open(native_pid)
        except ProcessLookupError:
            pidfd = -1
        if pidfd >= 0:
            poller = select.poll()
            poller.register(
                pidfd,
                select.POLLIN | select.POLLHUP | select.POLLERR,
            )
            assert poller.poll(5000)
            os.close(pidfd)
        expires = time.monotonic() + 5
        while Path(f"/proc/{native_pid}").exists() and time.monotonic() < expires:
            select.select((), (), (), 0.01)
        assert not Path(f"/proc/{native_pid}").exists()
        bundle = owned_root / bundle_name
        run_dir = bundle / run_relative
        metadata = load_json(run_dir / md.RUN_METADATA_FILE)
        assert metadata["status"] == md.STATUS_RUNNING
        assert not (run_dir / "coverage-read.json").exists()
        assert not any("ledger" in path.name for path in bundle.rglob("*"))
        with LaunchCancellation() as cancellation:
            invalid = terminal_module._apply_owned_fake_terminal_lifecycle(
                object(),
                deadline=MonotonicDeadline.after(1),
                cancellation=cancellation,
            )
        assert type(invalid) is OwnedFakeTerminalFailure
        assert invalid.reason_codes == (TerminalReason.INVALID_CAPABILITY,)
        shutil.rmtree(bundle)


def test_t17_private_api_signatures_exports_and_import_failure_are_closed(
    k2_env: _K2Environment,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for function in (
        make_owned_fake_terminal_lifecycle,
        apply_owned_fake_terminal_lifecycle,
        resume_owned_fake_terminal_lifecycle,
        cleanup_owned_fake_terminal_lifecycle,
    ):
        names = set(inspect.signature(function).parameters)
        assert not names.intersection(
            {
                "path",
                "run_path",
                "pid",
                "pgid",
                "env",
                "payload",
                "receipt",
                "model",
                "reason",
                "callback",
            }
        )
    import core.startup.runtime_receipt as facade

    assert terminal_module.__all__ == ()
    for name in (
        "OwnedFakeTerminalCapability",
        "OwnedFakeTerminalLifecycleResult",
        "_apply_owned_fake_terminal_lifecycle",
        "_query_owned_fake_terminal_permit",
        "_verify_owned_fake_terminal_permit",
    ):
        assert not hasattr(facade, name)

    lifecycle = _new_lifecycle(k2_env, FakeTerminalEvent.COMPLETE)
    before = (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes()
    monkeypatch.setattr(
        terminal_module,
        "_query_owned_fake_terminal_permit",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("synthetic permit import failure")
        ),
    )
    failure = _apply(k2_env, lifecycle)
    assert type(failure) is OwnedFakeTerminalFailure
    assert failure.reason_codes == (TerminalReason.TERMINAL_TRANSITION_FORBIDDEN,)
    assert (lifecycle.run_dir / md.RUN_METADATA_FILE).read_bytes() == before
    assert _apply(k2_env, lifecycle) is failure
    _discard_lifecycle(k2_env, lifecycle)


def test_t20_documented_fake_only_authority_boundary() -> None:
    repository_root = Path(__file__).parents[3]
    environment = (repository_root / "docs/environment.md").read_text(encoding="utf-8")
    security = (repository_root / "docs/security.md").read_text(encoding="utf-8")
    for source in (environment, security):
        for phrase in (
            "process-local",
            "thread-bound",
            "test-only",
            "owned runtime fake",
            "ledgerless",
            "projectless",
            "no environment",
            "live frontend",
        ):
            assert phrase in source
