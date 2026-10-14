"""Tests for immutable shared host-event fixtures."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from core.testing.host_events import (
    FixtureEvidenceLevel,
    FixtureEventKind,
    FixtureHost,
    HostEventFixture,
    HostEventSequence,
    claude_read_event,
    claude_session_end_event,
    copilot_candidate_read_event,
    startup_event,
    turn_end_event,
)


def test_claude_and_candidate_argument_spellings_remain_distinct() -> None:
    claude = claude_read_event("/owned/source.py")
    candidate = copilot_candidate_read_event("/owned/source.py")

    assert claude.payload()["tool_input"] == {"file_path": "/owned/source.py"}
    assert candidate.payload()["toolArgs"] == {"path": "/owned/source.py"}
    assert "file_path" not in candidate.payload()["toolArgs"]
    assert claude.evidence_level is (FixtureEvidenceLevel.EXISTING_CLAUDE_CONTRACT)
    assert candidate.evidence_level is (FixtureEvidenceLevel.CANDIDATE_UNVERIFIED)


def test_payload_calls_do_not_share_nested_mutable_values() -> None:
    fixture = copilot_candidate_read_event(
        "/owned/source.py",
        extra_tool_args={"options": {"ranges": [1, 2]}},
    )

    first = fixture.payload()
    first["toolArgs"]["options"]["ranges"].append(3)
    second = fixture.payload()

    assert second["toolArgs"]["options"]["ranges"] == [1, 2]
    with pytest.raises(TypeError):
        fixture.tool_args["new"] = "value"
    with pytest.raises(FrozenInstanceError):
        fixture.stale = True


def test_positive_fixture_can_generate_deliberate_malformed_variants() -> None:
    fixture = copilot_candidate_read_event("/owned/source.py")

    malformed = fixture.payload(
        omit_fields=("toolArgs",),
        overrides={
            "sessionId": 7,
            "toolName": "unknown-tool",
            "unknownField": True,
        },
    )

    assert "toolArgs" not in malformed
    assert malformed["sessionId"] == 7
    assert malformed["toolName"] == "unknown-tool"
    assert fixture.payload()["sessionId"] == "copilot-session-1"


def test_success_failure_startup_and_terminal_shapes_are_explicit() -> None:
    success = copilot_candidate_read_event("/owned/a.py")
    failure = copilot_candidate_read_event("/owned/a.py", successful=False)
    startup = startup_event(
        FixtureHost.COPILOT_1_0_84_4_HOOK_CANDIDATE,
        session_id="session-1",
        event_id="event-start",
    )
    turn_end = turn_end_event(
        FixtureHost.COPILOT_1_0_84_4_HOOK_CANDIDATE,
        session_id="session-1",
        event_id="event-turn-end",
        turn_id="turn-1",
    )
    session_end = claude_session_end_event(
        session_id="session-1",
        event_id="event-session-end",
    )

    assert success.payload()["success"] is True
    assert success.payload()["hookEventName"] == "postToolUse"
    assert failure.payload()["success"] is False
    assert failure.payload()["hookEventName"] == "postToolUseFailure"
    assert startup.payload()["hookEventName"] == "sessionStart"
    assert turn_end.payload()["hookEventName"] == "sessionEnd"
    assert session_end.payload()["hook_event_name"] == "SessionEnd"


def test_candidate_session_end_cannot_be_modelled_as_true_session_end() -> None:
    with pytest.raises(ValueError, match="no fixture mapping"):
        HostEventFixture(
            fixture_id="bad-candidate-session-end",
            host=FixtureHost.COPILOT_1_0_84_4_HOOK_CANDIDATE,
            event_kind=FixtureEventKind.SESSION_END,
            session_id="session-1",
            event_id="event-1",
        )


def test_sequence_preserves_duplicate_reorder_stale_and_foreign_evidence() -> None:
    start = startup_event(
        FixtureHost.CLAUDE_LEGACY_V1,
        session_id="session-1",
        event_id="event-1",
    )
    read = claude_read_event(
        "/owned/a.py",
        session_id="session-1",
        event_id="event-2",
        tool_call_id="tool-1",
        asynchronous=True,
    )
    sequence = HostEventSequence("read-sequence", (start, read))

    duplicate = sequence.duplicate(1)
    reordered = sequence.reordered((1, 0))
    foreign = sequence.foreign_session(1, "session-foreign")
    stale = sequence.mark_stale(1)

    assert duplicate.events[1].event_id == duplicate.events[2].event_id
    assert reordered.events[0].event_id == "event-2"
    assert foreign.events[1].session_id == "session-foreign"
    assert stale.events[1].stale is True
    assert stale.events[1].asynchronous is True
    assert sequence.events[1].session_id == "session-1"
    assert sequence.events[1].stale is False


def test_event_bytes_are_deterministic() -> None:
    fixture = claude_read_event(
        "/owned/source.py",
        include_declared_kind=True,
    )

    assert fixture.to_bytes() == fixture.to_bytes()
    assert fixture.to_bytes().startswith(b'{"event_id":"claude-event-1"')
