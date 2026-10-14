"""Closed test plans for the private owned-fake terminal channel."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.startup.runtime_receipt.terminal import (
        OwnedFakeTerminalCapability,
        OwnedFakeTerminalFailure,
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


__all__ = [
    "FakeTerminalEvent",
    "FakeTerminalPlan",
    "FakeTerminalSequence",
    "make_owned_fake_terminal_capability",
]
