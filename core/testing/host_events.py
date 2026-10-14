"""Deterministic host-event fixtures for cross-host adapter tests.

These values are test evidence, never session authority. Claude fixtures
model the repository's existing hook contract. Copilot fixtures are fixed as
candidate-unverified and cannot claim live delivery, permissions, lifecycle
semantics, or coverage parity.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from types import MappingProxyType


class FixtureHost(str, Enum):
    """Host profiles represented by the fixture corpus."""

    CLAUDE_LEGACY_V1 = "claude-legacy-v1"
    COPILOT_1_0_84_4_HOOK_CANDIDATE = "copilot-1.0.84-4-hook-candidate"


class FixtureEventKind(str, Enum):
    """Host-neutral event meanings used by fixture scenarios."""

    SESSION_START = "session_start"
    TOOL_START = "tool_start"
    TOOL_SUCCESS = "tool_success"
    TOOL_FAILURE = "tool_failure"
    TURN_END = "turn_end"
    SESSION_END = "session_end"


class FixtureOutcome(str, Enum):
    """Reported tool/event outcome without effect-layer interpretation."""

    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class FixtureEvidenceLevel(str, Enum):
    """Provenance boundary carried with every fixture."""

    EXISTING_CLAUDE_CONTRACT = "existing-claude-hook-contract"
    CANDIDATE_UNVERIFIED = "candidate-unverified"


_EVENT_NAMES = MappingProxyType(
    {
        FixtureHost.CLAUDE_LEGACY_V1: MappingProxyType(
            {
                FixtureEventKind.SESSION_START: "SessionStart",
                FixtureEventKind.TOOL_START: "PreToolUse",
                FixtureEventKind.TOOL_SUCCESS: "PostToolUse",
                FixtureEventKind.TOOL_FAILURE: "PostToolUseFailure",
                FixtureEventKind.TURN_END: "Stop",
                FixtureEventKind.SESSION_END: "SessionEnd",
            }
        ),
        FixtureHost.COPILOT_1_0_84_4_HOOK_CANDIDATE: MappingProxyType(
            {
                FixtureEventKind.SESSION_START: "sessionStart",
                FixtureEventKind.TOOL_START: "preToolUse",
                FixtureEventKind.TOOL_SUCCESS: "postToolUse",
                FixtureEventKind.TOOL_FAILURE: "postToolUseFailure",
                # W1a observed prompt-mode sessionEnd semantics only as a
                # candidate turn boundary. It is never a true session end.
                FixtureEventKind.TURN_END: "sessionEnd",
            }
        ),
    }
)

_CLAUDE_IDENTITY_FIELDS = MappingProxyType(
    {
        "event_kind": "hook_event_name",
        "event_id": "event_id",
        "parent_id": "parent_id",
        "session_id": "session_id",
        "turn_id": "turn_id",
        "agent_id": "agent_id",
        "tool_call_id": "tool_call_id",
    }
)
_CLAUDE_TOOL_FIELDS = MappingProxyType(
    {
        "tool_name": "tool_name",
        "tool_args": "tool_input",
        "success": "success",
        "reason": "reason",
    }
)
_COPILOT_IDENTITY_FIELDS = MappingProxyType(
    {
        "event_kind": "hookEventName",
        "event_id": "eventId",
        "parent_id": "parentId",
        "session_id": "sessionId",
        "turn_id": "turnId",
        "agent_id": "agentId",
        "tool_call_id": "toolCallId",
    }
)
_COPILOT_TOOL_FIELDS = MappingProxyType(
    {
        "tool_name": "toolName",
        "tool_args": "toolArgs",
        "success": "success",
        "reason": "reason",
    }
)
_FIELD_NAMES = MappingProxyType(
    {
        FixtureHost.CLAUDE_LEGACY_V1: MappingProxyType(
            dict(_CLAUDE_IDENTITY_FIELDS) | dict(_CLAUDE_TOOL_FIELDS)
        ),
        FixtureHost.COPILOT_1_0_84_4_HOOK_CANDIDATE: MappingProxyType(
            dict(_COPILOT_IDENTITY_FIELDS) | dict(_COPILOT_TOOL_FIELDS)
        ),
    }
)

_TOOL_EVENTS = frozenset(
    {
        FixtureEventKind.TOOL_START,
        FixtureEventKind.TOOL_SUCCESS,
        FixtureEventKind.TOOL_FAILURE,
    }
)


def _validate_identifier(value: str | None, field_name: str) -> None:
    if value is None:
        return
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or not value.isascii()
        or not value.isprintable()
    ):
        raise ValueError(f"{field_name} must be 1-128 printable ASCII characters")


def _freeze(value: object) -> object:
    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("fixture mapping keys must be strings")
            frozen[key] = _freeze(item)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True)
class HostEventFixture:
    """One immutable event plus out-of-band delivery metadata."""

    fixture_id: str
    host: FixtureHost
    event_kind: FixtureEventKind
    session_id: str | None = None
    event_id: str | None = None
    parent_id: str | None = None
    turn_id: str | None = None
    agent_id: str | None = None
    tool_call_id: str | None = None
    tool_name: str | None = None
    tool_args: Mapping[str, object] | None = None
    outcome: FixtureOutcome = FixtureOutcome.UNKNOWN
    reason: str | None = None
    asynchronous: bool = False
    stale: bool = False
    include_declared_kind: bool = True
    evidence_level: FixtureEvidenceLevel = field(init=False)

    def __post_init__(self) -> None:
        _validate_identifier(self.fixture_id, "fixture_id")
        for field_name in (
            "session_id",
            "event_id",
            "parent_id",
            "turn_id",
            "agent_id",
            "tool_call_id",
            "tool_name",
        ):
            _validate_identifier(getattr(self, field_name), field_name)
        if self.reason is not None and not isinstance(self.reason, str):
            raise TypeError("reason must be a string or None")
        if self.event_kind not in _EVENT_NAMES[self.host]:
            raise ValueError(
                f"{self.host.value} has no fixture mapping for {self.event_kind.value}"
            )
        if self.event_kind in _TOOL_EVENTS:
            if self.tool_name is None:
                raise ValueError("tool events require tool_name")
            if self.tool_args is None:
                raise ValueError("tool events require tool_args")
        elif self.tool_name is not None or self.tool_args is not None:
            raise ValueError("non-tool events cannot carry tool fields")
        if self.tool_args is not None:
            if not isinstance(self.tool_args, Mapping):
                raise TypeError("tool_args must be a mapping")
            object.__setattr__(self, "tool_args", _freeze(self.tool_args))
        evidence = (
            FixtureEvidenceLevel.EXISTING_CLAUDE_CONTRACT
            if self.host is FixtureHost.CLAUDE_LEGACY_V1
            else FixtureEvidenceLevel.CANDIDATE_UNVERIFIED
        )
        object.__setattr__(self, "evidence_level", evidence)

    def payload(
        self,
        *,
        omit_fields: Iterable[str] = (),
        overrides: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        """Return a fresh mutable payload for positive or malformed cases."""
        fields = _FIELD_NAMES[self.host]
        payload: dict[str, object] = {}
        if self.include_declared_kind:
            payload[fields["event_kind"]] = _EVENT_NAMES[self.host][self.event_kind]
        for logical_name in (
            "event_id",
            "parent_id",
            "session_id",
            "turn_id",
            "agent_id",
            "tool_call_id",
            "tool_name",
        ):
            value = getattr(self, logical_name)
            if value is not None:
                payload[fields[logical_name]] = value
        if self.tool_args is not None:
            payload[fields["tool_args"]] = _thaw(self.tool_args)
        if self.outcome is FixtureOutcome.SUCCESS:
            payload[fields["success"]] = True
        elif self.outcome is FixtureOutcome.FAILURE:
            payload[fields["success"]] = False
        if self.reason is not None:
            payload[fields["reason"]] = self.reason
        for field_name in omit_fields:
            payload.pop(field_name, None)
        if overrides is not None:
            if not isinstance(overrides, Mapping):
                raise TypeError("overrides must be a mapping")
            for key, value in overrides.items():
                if not isinstance(key, str):
                    raise TypeError("override keys must be strings")
                payload[key] = _thaw(_freeze(value))
        return payload

    def to_bytes(
        self,
        *,
        omit_fields: Iterable[str] = (),
        overrides: Mapping[str, object] | None = None,
    ) -> bytes:
        """Serialize one deterministic JSON object for a real consumer."""
        return json.dumps(
            self.payload(omit_fields=omit_fields, overrides=overrides),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def record(self) -> dict[str, object]:
        """Return the machine-readable fixture plus its evidence boundary."""
        return {
            "fixture_id": self.fixture_id,
            "host": self.host.value,
            "event_kind": self.event_kind.value,
            "outcome": self.outcome.value,
            "asynchronous": self.asynchronous,
            "stale": self.stale,
            "evidence_level": self.evidence_level.value,
            "payload": self.payload(),
        }


@dataclass(frozen=True)
class HostEventSequence:
    """Immutable delivery ordering for duplicate/race/session scenarios."""

    scenario_id: str
    events: tuple[HostEventFixture, ...]

    def __post_init__(self) -> None:
        _validate_identifier(self.scenario_id, "scenario_id")
        if not self.events:
            raise ValueError("event sequence must not be empty")
        if not isinstance(self.events, tuple):
            object.__setattr__(self, "events", tuple(self.events))
        if not all(isinstance(event, HostEventFixture) for event in self.events):
            raise TypeError("events must contain HostEventFixture values")

    def payloads(self) -> tuple[dict[str, object], ...]:
        """Return independent payload dictionaries in delivery order."""
        return tuple(event.payload() for event in self.events)

    def duplicate(self, index: int) -> HostEventSequence:
        events = list(self.events)
        events.insert(index + 1, events[index])
        return HostEventSequence(f"{self.scenario_id}-duplicate", tuple(events))

    def reordered(self, order: Sequence[int]) -> HostEventSequence:
        if sorted(order) != list(range(len(self.events))):
            raise ValueError("order must be a permutation of event indexes")
        return HostEventSequence(
            f"{self.scenario_id}-reordered",
            tuple(self.events[index] for index in order),
        )

    def foreign_session(
        self,
        index: int,
        session_id: str,
    ) -> HostEventSequence:
        _validate_identifier(session_id, "session_id")
        events = list(self.events)
        events[index] = replace(events[index], session_id=session_id)
        return HostEventSequence(
            f"{self.scenario_id}-foreign-session",
            tuple(events),
        )

    def mark_stale(self, index: int) -> HostEventSequence:
        events = list(self.events)
        events[index] = replace(events[index], stale=True)
        return HostEventSequence(
            f"{self.scenario_id}-stale",
            tuple(events),
        )


def claude_read_event(
    path: str,
    *,
    successful: bool = True,
    argument_name: str = "file_path",
    session_id: str = "claude-session-1",
    event_id: str = "claude-event-1",
    tool_call_id: str = "claude-tool-1",
    tool_name: str = "Read",
    asynchronous: bool = False,
    include_declared_kind: bool = False,
    extra_tool_args: Mapping[str, object] | None = None,
) -> HostEventFixture:
    """Build the existing Claude read-hook shape with explicit metadata."""
    args: dict[str, object] = {argument_name: path}
    if extra_tool_args is not None:
        args.update(extra_tool_args)
    return HostEventFixture(
        fixture_id=("claude-read-success" if successful else "claude-read-failure"),
        host=FixtureHost.CLAUDE_LEGACY_V1,
        event_kind=(
            FixtureEventKind.TOOL_SUCCESS
            if successful
            else FixtureEventKind.TOOL_FAILURE
        ),
        session_id=session_id,
        event_id=event_id,
        tool_call_id=tool_call_id,
        tool_name=tool_name,
        tool_args=args,
        outcome=(FixtureOutcome.SUCCESS if successful else FixtureOutcome.FAILURE),
        asynchronous=asynchronous,
        include_declared_kind=include_declared_kind,
    )


def copilot_candidate_read_event(
    path: str,
    *,
    successful: bool = True,
    argument_name: str = "path",
    session_id: str = "copilot-session-1",
    event_id: str = "copilot-event-1",
    tool_call_id: str = "copilot-tool-1",
    tool_name: str = "view",
    asynchronous: bool = False,
    extra_tool_args: Mapping[str, object] | None = None,
) -> HostEventFixture:
    """Build a candidate-only Copilot read event without argument rewriting."""
    args: dict[str, object] = {argument_name: path}
    if extra_tool_args is not None:
        args.update(extra_tool_args)
    return HostEventFixture(
        fixture_id=(
            "copilot-read-success-candidate"
            if successful
            else "copilot-read-failure-candidate"
        ),
        host=FixtureHost.COPILOT_1_0_84_4_HOOK_CANDIDATE,
        event_kind=(
            FixtureEventKind.TOOL_SUCCESS
            if successful
            else FixtureEventKind.TOOL_FAILURE
        ),
        session_id=session_id,
        event_id=event_id,
        tool_call_id=tool_call_id,
        tool_name=tool_name,
        tool_args=args,
        outcome=(FixtureOutcome.SUCCESS if successful else FixtureOutcome.FAILURE),
        asynchronous=asynchronous,
    )


def startup_event(
    host: FixtureHost,
    *,
    session_id: str,
    event_id: str,
) -> HostEventFixture:
    """Build a host startup event without claiming startup side effects."""
    return HostEventFixture(
        fixture_id=f"{host.value}-startup",
        host=host,
        event_kind=FixtureEventKind.SESSION_START,
        session_id=session_id,
        event_id=event_id,
    )


def turn_end_event(
    host: FixtureHost,
    *,
    session_id: str,
    event_id: str,
    turn_id: str,
    reason: str = "complete",
    asynchronous: bool = False,
) -> HostEventFixture:
    """Build a turn boundary; candidate ``sessionEnd`` stays non-terminal."""
    return HostEventFixture(
        fixture_id=f"{host.value}-turn-end",
        host=host,
        event_kind=FixtureEventKind.TURN_END,
        session_id=session_id,
        event_id=event_id,
        turn_id=turn_id,
        reason=reason,
        asynchronous=asynchronous,
    )


def claude_session_end_event(
    *,
    session_id: str,
    event_id: str,
    reason: str = "complete",
) -> HostEventFixture:
    """Build the existing Claude session-end registration shape."""
    return HostEventFixture(
        fixture_id="claude-session-end",
        host=FixtureHost.CLAUDE_LEGACY_V1,
        event_kind=FixtureEventKind.SESSION_END,
        session_id=session_id,
        event_id=event_id,
        reason=reason,
    )


__all__ = [
    "FixtureEvidenceLevel",
    "FixtureEventKind",
    "FixtureHost",
    "FixtureOutcome",
    "HostEventFixture",
    "HostEventSequence",
    "claude_read_event",
    "claude_session_end_event",
    "copilot_candidate_read_event",
    "startup_event",
    "turn_end_event",
]
