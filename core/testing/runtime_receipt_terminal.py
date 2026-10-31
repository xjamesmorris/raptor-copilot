"""Closed test plans for the private owned-fake terminal channel."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.startup.runtime_receipt.terminal import (
        OwnedFakeTerminalCapability,
        OwnedFakeTerminalCleanupResult,
        OwnedFakeTerminalFailure,
        OwnedFakeTerminalLifecycleResult,
    )


class FakeTerminalEvent(int, Enum):
    COMPLETE = 1
    FAIL = 2
    INTERRUPT = 3
    CANCEL = 4


class FakeTerminalSequence(int, Enum):
    IMMEDIATE = 1
    BACKGROUND_DRAIN = 2
    EXACT_DUPLICATE = 3
    CONFLICTING_DUPLICATE = 4
    OUT_OF_ORDER = 5
    FOREIGN_NONCE = 6
    WRONG_KIND = 7
    MALFORMED = 8
    TIMEOUT = 9
    CHILD_EXIT_BEFORE_EVENT = 10
    CONTROL_EOF = 11
    EXIT_AFTER_ACK = 12


@dataclass(frozen=True, slots=True)
class FakeTerminalPlan:
    event: FakeTerminalEvent
    sequence: FakeTerminalSequence = FakeTerminalSequence.IMMEDIATE
    work_count: int = 0

    def __post_init__(self) -> None:
        if type(self.event) is not FakeTerminalEvent:
            raise TypeError("event must be FakeTerminalEvent")
        if type(self.sequence) is not FakeTerminalSequence:
            raise TypeError("sequence must be FakeTerminalSequence")
        if type(self.work_count) is not int or not 0 <= self.work_count <= 64:
            raise ValueError("work count must be an integer from 0 to 64")
        if (
            self.sequence is FakeTerminalSequence.BACKGROUND_DRAIN
            and self.work_count == 0
        ):
            raise ValueError("background drain requires pending work")
        if (
            self.sequence is not FakeTerminalSequence.BACKGROUND_DRAIN
            and self.work_count != 0
        ):
            raise ValueError("only background drain carries pending work")


@dataclass(frozen=True, slots=True, init=False, repr=False)
class FakeTerminalLifecycle:
    _capability: OwnedFakeTerminalCapability
    _run_dir: Path

    def __init__(self) -> None:
        raise TypeError("FakeTerminalLifecycle cannot be constructed")

    @property
    def run_dir(self) -> Path:
        return self._run_dir

    def __repr__(self) -> str:
        return "FakeTerminalLifecycle(<redacted>)"

    def __bool__(self) -> bool:
        raise TypeError("fake terminal lifecycles are not truth values")

    def __reduce__(self):
        raise TypeError("FakeTerminalLifecycle cannot be pickled")

    def __init_subclass__(cls) -> None:
        raise TypeError("FakeTerminalLifecycle cannot be subclassed")


def _new_lifecycle(
    capability: OwnedFakeTerminalCapability,
    run_dir: Path,
) -> FakeTerminalLifecycle:
    value = object.__new__(FakeTerminalLifecycle)
    object.__setattr__(value, "_capability", capability)
    object.__setattr__(value, "_run_dir", Path(run_dir))
    return value


def _remove_unbound_run(run_dir: Path) -> None:
    allowed = {
        ".raptor-run.json",
        ".raptor-run.json.lock",
        ".reads-manifest",
    }
    entries = {entry.name for entry in run_dir.iterdir()}
    if not entries.issubset(allowed):
        raise RuntimeError("owned fake terminal setup left unexpected files")
    for name in sorted(entries):
        (run_dir / name).unlink()
    run_dir.rmdir()


def make_owned_fake_terminal_capability(
    handle: object,
    *,
    plan: FakeTerminalPlan,
) -> OwnedFakeTerminalCapability | OwnedFakeTerminalFailure:
    """Issue one process-local capability for an exact verified fake handle."""

    from core.startup.runtime_receipt.terminal import (
        _issue_owned_fake_terminal_capability,
    )

    if type(plan) is not FakeTerminalPlan:
        raise TypeError("plan must be FakeTerminalPlan")
    return _issue_owned_fake_terminal_capability(
        handle,
        event_code=plan.event.value,
        sequence_code=plan.sequence.value,
        work_count=plan.work_count,
    )


def make_owned_fake_terminal_lifecycle(
    handle: object,
    *,
    plan: FakeTerminalPlan,
) -> FakeTerminalLifecycle | OwnedFakeTerminalFailure:
    """Create one fixed receipt-backed run and bind a terminal capability."""

    from core.run.metadata import start_run
    from core.startup.runtime_receipt.terminal import (
        OwnedFakeTerminalFailure,
        _TERMINAL_READ_MANIFEST,
        _TERMINAL_RUN_COMMAND,
        _bind_owned_fake_terminal_run,
        _owned_fake_terminal_runs_root,
    )

    if type(plan) is not FakeTerminalPlan:
        raise TypeError("plan must be FakeTerminalPlan")
    runs_root = _owned_fake_terminal_runs_root(handle)
    if isinstance(runs_root, OwnedFakeTerminalFailure):
        return runs_root
    run_dir = runs_root / f"terminal-k2-{secrets.token_hex(16)}"
    try:
        start_run(run_dir, _TERMINAL_RUN_COMMAND)
        manifest = run_dir / ".reads-manifest"
        manifest.write_bytes(_TERMINAL_READ_MANIFEST)
        manifest.chmod(0o600)
        capability = make_owned_fake_terminal_capability(handle, plan=plan)
        if isinstance(capability, OwnedFakeTerminalFailure):
            _remove_unbound_run(run_dir)
            return capability
        bound = _bind_owned_fake_terminal_run(capability)
        if isinstance(bound, OwnedFakeTerminalFailure):
            _remove_unbound_run(run_dir)
            return bound
    except BaseException:
        if run_dir.exists():
            _remove_unbound_run(run_dir)
        raise
    return _new_lifecycle(bound, run_dir)


def apply_owned_fake_terminal_lifecycle(
    lifecycle: object,
    *,
    deadline: Any,
    cancellation: Any,
) -> OwnedFakeTerminalLifecycleResult | OwnedFakeTerminalFailure:
    from core.startup.runtime_receipt.terminal import (
        _apply_owned_fake_terminal_lifecycle,
    )

    capability = (
        lifecycle._capability if type(lifecycle) is FakeTerminalLifecycle else lifecycle
    )
    return _apply_owned_fake_terminal_lifecycle(
        capability,
        deadline=deadline,
        cancellation=cancellation,
    )


def resume_owned_fake_terminal_lifecycle(
    result: object,
    *,
    plan: FakeTerminalPlan,
) -> FakeTerminalLifecycle | OwnedFakeTerminalFailure:
    from core.run.metadata import resume_run
    from core.startup.runtime_receipt.terminal import (
        OwnedFakeTerminalFailure,
        _TERMINAL_RESUME_NOTE,
        _owned_fake_terminal_resume_directory,
        _rearm_owned_fake_terminal_capability,
    )

    if type(plan) is not FakeTerminalPlan:
        raise TypeError("plan must be FakeTerminalPlan")
    run_dir = _owned_fake_terminal_resume_directory(result)
    if isinstance(run_dir, OwnedFakeTerminalFailure):
        return run_dir
    resume_run(run_dir, note=_TERMINAL_RESUME_NOTE)
    capability = _rearm_owned_fake_terminal_capability(
        result,
        event_code=plan.event.value,
        sequence_code=plan.sequence.value,
        work_count=plan.work_count,
    )
    if isinstance(capability, OwnedFakeTerminalFailure):
        return capability
    return _new_lifecycle(capability, run_dir)


def cleanup_owned_fake_terminal_lifecycle(
    result: object,
    *,
    deadline: Any,
) -> OwnedFakeTerminalCleanupResult | OwnedFakeTerminalFailure:
    from core.startup.runtime_receipt.terminal import (
        _cleanup_owned_fake_terminal_lifecycle,
    )

    return _cleanup_owned_fake_terminal_lifecycle(
        result,
        deadline=deadline,
    )


__all__ = [
    "FakeTerminalEvent",
    "FakeTerminalLifecycle",
    "FakeTerminalPlan",
    "FakeTerminalSequence",
    "apply_owned_fake_terminal_lifecycle",
    "cleanup_owned_fake_terminal_lifecycle",
    "make_owned_fake_terminal_capability",
    "make_owned_fake_terminal_lifecycle",
    "resume_owned_fake_terminal_lifecycle",
]
