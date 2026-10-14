"""Pure host-hook normalization and candidate-profile gates."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path

import pytest

from core.json import JsonBudgetExceededError
from core.llm.copilot_protocol import CANDIDATE_SOURCE_CLI_VERSION
from core.run import host_events
from core.run.host_events import (
    HostEventKind,
    HostEventParseDisposition,
    HostEventProfileId,
    InMemoryEventReceipts,
    MAX_HOST_EVENT_BYTES,
    PROFILE_META,
    event_key,
    event_key_for,
    normalize_host_event,
)
from core.testing.host_events import (
    FixtureEvidenceLevel,
    FixtureHost,
    HostEventFixture,
    copilot_candidate_read_event,
    turn_end_event,
)


def _claude(payload: dict | None = None):
    data = payload or {
        "tool_input": {"file_path": "/owned/source.py"},
    }
    return normalize_host_event(
        json.dumps(data).encode(),
        profile=HostEventProfileId.CLAUDE_LEGACY_V1,
        registration_kind=HostEventKind.TOOL_SUCCESS,
    )


def _candidate(
    fixture: HostEventFixture | None = None,
    *,
    kind: HostEventKind = HostEventKind.TOOL_SUCCESS,
):
    """Normalize immutable candidate-unverified fixture bytes."""
    event = fixture or copilot_candidate_read_event("/owned/source.py")
    assert event.host is FixtureHost.COPILOT_1_0_84_4_HOOK_CANDIDATE
    assert event.evidence_level is FixtureEvidenceLevel.CANDIDATE_UNVERIFIED
    return normalize_host_event(
        event.to_bytes(),
        profile=HostEventProfileId.COPILOT_1_0_84_4_HOOK_CANDIDATE,
        registration_kind=kind,
    )


def test_e05_claude_optional_corroboration_fields_may_be_absent():
    result = _claude()

    assert result.disposition is HostEventParseDisposition.PARSED
    assert result.event is not None
    assert result.event.payload_kind is None
    assert result.event.raw_tool_name is None
    assert result.event.payload_session_id is None


def test_e05_present_claude_registration_mismatch_is_invalid():
    result = _claude(
        {
            "hook_event_name": "Stop",
            "tool_input": {"file_path": "/owned/source.py"},
        }
    )

    assert result.disposition is HostEventParseDisposition.INVALID
    assert result.event is None
    assert result.reason_code == "registration_mismatch"


def test_e05_unknown_kind_and_profile_are_unsupported():
    unknown_kind = normalize_host_event(
        b"{}",
        profile=HostEventProfileId.CLAUDE_LEGACY_V1,
        registration_kind=HostEventKind.UNKNOWN,
    )
    unknown_profile = normalize_host_event(
        b"{}",
        profile=HostEventProfileId.UNKNOWN,
        registration_kind=HostEventKind.TOOL_SUCCESS,
    )

    assert unknown_kind.disposition is HostEventParseDisposition.UNSUPPORTED
    assert unknown_kind.reason_code == "unsupported_kind"
    assert unknown_profile.disposition is HostEventParseDisposition.UNSUPPORTED
    assert unknown_profile.reason_code == "unsupported_profile"


def test_c1_invalid_bytes_precede_unknown_profile_classification():
    result = normalize_host_event(
        b"\xff",
        profile=HostEventProfileId.UNKNOWN,
        registration_kind=HostEventKind.TOOL_SUCCESS,
    )

    assert result.disposition is HostEventParseDisposition.INVALID
    assert result.reason_code == "not_utf8"


@pytest.mark.parametrize(
    ("raw", "reason_code"),
    [
        (b'{"tool_input":{},"tool_input":{}}', "duplicate_key"),
        (b'{"tool_input":{"x":1,"x":2}}', "duplicate_key"),
        (b"\xff", "not_utf8"),
        (json.dumps({"tool_input": {}}).encode("utf-16"), "not_utf8"),
        (b"\xef\xbb\xbf{}", "malformed_json"),
        (b'{"n":NaN}', "non_finite"),
        (b'{"n":Infinity}', "non_finite"),
        (b'{"n":1e999}', "non_finite"),
        (b"[]", "non_object_root"),
        (
            ('{"x":' * 2000 + "null" + "}" * 2000).encode(),
            "depth",
        ),
        (b'{"n":' + b"9" * 5000 + b"}", "integer_out_of_range"),
        (b'{"n":-18446744073709551616}', "integer_out_of_range"),
    ],
)
def test_e06_invalid_payloads_never_raise(raw, reason_code):
    result = normalize_host_event(
        raw,
        profile=HostEventProfileId.CLAUDE_LEGACY_V1,
        registration_kind=HostEventKind.TOOL_SUCCESS,
    )

    assert result.disposition is HostEventParseDisposition.INVALID
    assert result.event is None
    assert result.reason_code == reason_code


def test_e07_budget_is_checked_before_decode_or_parse():
    raw = b"\xff" * (MAX_HOST_EVENT_BYTES + 1)
    result = normalize_host_event(
        raw,
        profile=HostEventProfileId.CLAUDE_LEGACY_V1,
        registration_kind=HostEventKind.TOOL_SUCCESS,
    )

    assert result.disposition is HostEventParseDisposition.INVALID
    assert result.reason_code == "budget"
    assert result.payload_sha256 == hashlib.sha256(raw).hexdigest()


def test_e06_bounded_loader_budget_failure_is_contained(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise JsonBudgetExceededError("SECRET size detail")

    monkeypatch.setattr(host_events, "loads_bounded", refuse)
    result = _claude()

    assert result.disposition is HostEventParseDisposition.INVALID
    assert result.reason_code == "budget"
    assert "SECRET" not in result.detail


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_id", ""),
        ("parent_id", "x" * 129),
        ("session_id", "snowman-\N{SNOWMAN}"),
        ("turn_id", "line\nbreak"),
        ("agent_id", 7),
        ("tool_call_id", False),
    ],
)
def test_e06_identifiers_are_bounded_printable_ascii(field, value):
    result = _claude(
        {
            field: value,
            "tool_input": {"file_path": "/owned/source.py"},
        }
    )

    assert result.disposition is HostEventParseDisposition.INVALID
    assert result.reason_code == "bad_identifier"


@pytest.mark.parametrize(
    ("field", "value", "reason_code"),
    [
        ("tool_name", "", "bad_tool_name"),
        ("tool_name", "x" * 129, "bad_tool_name"),
        ("tool_input", "not-an-object", "bad_tool_args"),
        ("success", "yes", "bad_success"),
        ("reason", 9, "bad_reason"),
    ],
)
def test_e04_typed_fields_fail_closed(field, value, reason_code):
    payload = {"tool_input": {"file_path": "/owned/source.py"}}
    payload[field] = value
    result = _claude(payload)

    assert result.disposition is HostEventParseDisposition.INVALID
    assert result.reason_code == reason_code


def test_e02_e03_candidate_hook_alias_preserves_native_args():
    result = _candidate()

    assert result.disposition is HostEventParseDisposition.PARSED
    assert result.event is not None
    assert result.event.raw_tool_name == "view"
    assert result.event.canonical_tool_name == "Read"
    assert dict(result.event.tool_args or {}) == {
        "path": "/owned/source.py",
    }
    assert "file_path" not in (result.event.tool_args or {})


def test_e13_n8_candidate_session_end_is_only_a_turn_end_parse():
    result = _candidate(
        turn_end_event(
            FixtureHost.COPILOT_1_0_84_4_HOOK_CANDIDATE,
            session_id="session-1",
            event_id="event-1",
            turn_id="turn-1",
        ),
        kind=HostEventKind.TURN_END,
    )

    assert result.disposition is HostEventParseDisposition.PARSED
    assert result.event is not None
    assert result.event.registration_kind is HostEventKind.TURN_END
    assert result.event.payload_kind == "sessionEnd"
    assert (
        PROFILE_META[HostEventProfileId.COPILOT_1_0_84_4_HOOK_CANDIDATE].effects_enabled
        is False
    )


def test_e45_candidate_effects_are_constant_false(monkeypatch):
    """Candidate-unverified fixtures cannot activate candidate effects."""
    monkeypatch.setenv("RAPTOR_COPILOT_EVENTS_ENABLED", "1")
    monkeypatch.setenv("RAPTOR_HOST", "copilot")

    meta = PROFILE_META[HostEventProfileId.COPILOT_1_0_84_4_HOOK_CANDIDATE]
    assert meta.effects_enabled is False
    with pytest.raises(TypeError):
        PROFILE_META[HostEventProfileId.COPILOT_1_0_84_4_HOOK_CANDIDATE] = meta


def test_candidate_hook_profile_matches_protocol_provenance() -> None:
    expected = f"copilot-{CANDIDATE_SOURCE_CLI_VERSION}-hook-candidate"

    assert CANDIDATE_SOURCE_CLI_VERSION == "1.0.84-4"
    assert HostEventProfileId.COPILOT_1_0_84_4_HOOK_CANDIDATE.value == expected
    assert FixtureHost.COPILOT_1_0_84_4_HOOK_CANDIDATE.value == expected


def test_c1_profiles_are_hook_only_and_parser_imports_are_bounded():
    assert set(PROFILE_META) == {
        HostEventProfileId.CLAUDE_LEGACY_V1,
        HostEventProfileId.COPILOT_1_0_84_4_HOOK_CANDIDATE,
    }
    assert HostEventProfileId.UNKNOWN not in PROFILE_META
    assert {meta.channel for meta in PROFILE_META.values()} == {"hook"}

    path = Path(host_events.__file__)
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports.extend(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append((node.module or "").split(".", 1)[0])
    assert set(imports) <= {
        "__future__",
        "copy",
        "core",
        "dataclasses",
        "enum",
        "hashlib",
        "math",
        "types",
        "typing",
    }
    assert "ACCEPTED" not in source


def test_n6_tool_args_are_copied_and_top_level_read_only(monkeypatch):
    source = {
        "tool_input": {
            "file_path": "/owned/source.py",
            "options": {"offset": 1},
        },
    }
    monkeypatch.setattr(host_events, "loads_bounded", lambda *_a, **_k: source)

    result = normalize_host_event(
        b"{}",
        profile=HostEventProfileId.CLAUDE_LEGACY_V1,
        registration_kind=HostEventKind.TOOL_SUCCESS,
    )
    assert result.event is not None
    args = result.event.tool_args
    assert args is not None
    source["tool_input"]["file_path"] = "/changed.py"
    source["tool_input"]["options"]["offset"] = 99
    assert args["file_path"] == "/owned/source.py"
    assert args["options"] == {"offset": 1}
    with pytest.raises(TypeError):
        args["file_path"] = "/mutated.py"

    aliases = host_events._TOOL_NAME_ALIASES[HostEventProfileId.CLAUDE_LEGACY_V1]
    with pytest.raises(TypeError):
        aliases["view"] = "Read"


def test_n6_nested_lists_are_preserved_in_copied_args():
    result = _claude(
        {
            "tool_input": {
                "file_path": "/owned/source.py",
                "ranges": [{"offset": 1}, {"offset": 2}],
            },
        }
    )

    assert result.event is not None
    assert result.event.tool_args is not None
    assert result.event.tool_args["ranges"] == [
        {"offset": 1},
        {"offset": 2},
    ]


def test_e06_parser_and_copy_recursion_are_contained(monkeypatch):
    def recurse(*_args, **_kwargs):
        raise RecursionError

    monkeypatch.setattr(host_events, "loads_bounded", recurse)
    parsed = _claude()
    assert parsed.disposition is HostEventParseDisposition.INVALID
    assert parsed.reason_code == "depth"

    monkeypatch.setattr(
        host_events,
        "loads_bounded",
        lambda *_args, **_kwargs: {
            "tool_input": {"file_path": "/owned/source.py"},
        },
    )
    monkeypatch.setattr(host_events.copy, "deepcopy", recurse)
    copied = _claude()
    assert copied.disposition is HostEventParseDisposition.INVALID
    assert copied.reason_code == "depth"


def test_c5_event_key_and_in_memory_receipt_semantics():
    first = _claude(
        {
            "event_id": "event-1",
            "tool_input": {"file_path": "/owned/source.py"},
        }
    )
    same = _claude(
        {
            "event_id": "event-1",
            "tool_input": {"file_path": "/owned/source.py"},
        }
    )
    changed = _claude(
        {
            "event_id": "event-1",
            "tool_input": {"file_path": "/owned/other.py"},
        }
    )
    no_id = _claude()
    assert first.event is not None
    assert same.event is not None
    assert changed.event is not None
    assert no_id.event is not None

    key = event_key_for(first.event)
    assert key == event_key_for(same.event)
    assert key == event_key(
        HostEventProfileId.CLAUDE_LEGACY_V1,
        HostEventKind.TOOL_SUCCESS,
        "event-1",
    )
    assert event_key_for(no_id.event) == event_key(
        no_id.event.profile,
        no_id.event.registration_kind,
        no_id.event.payload_sha256,
    )

    receipts = InMemoryEventReceipts()
    assert receipts.observe(key, first.payload_sha256) == (
        host_events.EventReceiptResult(duplicate=False, conflict=False)
    )
    assert receipts.observe(key, same.payload_sha256) == (
        host_events.EventReceiptResult(duplicate=True, conflict=False)
    )
    assert receipts.observe(key, changed.payload_sha256) == (
        host_events.EventReceiptResult(duplicate=False, conflict=True)
    )


def test_n5_diagnostics_do_not_echo_payload_values():
    secret = "SECRET-canary-/very/long/path"
    result = _claude(
        {
            "session_id": secret + "\n",
            "tool_input": {"file_path": secret},
        }
    )

    assert result.disposition is HostEventParseDisposition.INVALID
    assert secret not in result.detail
    assert "\n" not in result.detail
    assert re.fullmatch(
        r"raptor-read-hook\[[a-z0-9_]+\]: [ -~]+",
        result.detail,
    )


@pytest.mark.parametrize(
    "payload",
    [
        {
            "event_id": "SECRET\n",
            "tool_input": {"file_path": "/owned/source.py"},
        },
        {
            "tool_name": "SECRET\n",
            "tool_input": {"file_path": "/owned/source.py"},
        },
        {"tool_input": "SECRET-payload"},
        {
            "success": {"SECRET": True},
            "tool_input": {"file_path": "/owned/source.py"},
        },
        {
            "reason": {"SECRET": True},
            "tool_input": {"file_path": "/owned/source.py"},
        },
    ],
)
def test_n5_all_invalid_field_diagnostics_are_template_only(payload):
    result = _claude(payload)

    assert result.disposition is HostEventParseDisposition.INVALID
    assert "SECRET" not in result.detail
    assert re.fullmatch(
        r"raptor-read-hook\[[a-z0-9_]+\]: [ -~]+",
        result.detail,
    )


def test_non_bytes_input_is_invalid_without_exception():
    result = normalize_host_event(
        "{}",  # type: ignore[arg-type]
        profile=HostEventProfileId.CLAUDE_LEGACY_V1,
        registration_kind=HostEventKind.TOOL_SUCCESS,
    )

    assert result.disposition is HostEventParseDisposition.INVALID
    assert result.reason_code == "not_bytes"
