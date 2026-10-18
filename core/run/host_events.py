"""Pure host-hook event normalization.

``PARSED`` means only that bytes matched the fixed profile and registration
contract supplied by a trusted entrypoint. It is never ownership, permission,
or authorization to perform an effect. The module deliberately has no
environment, filesystem, project, session, or lifecycle access.
"""

from __future__ import annotations

import copy
import hashlib
import math
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping

from core.json import JsonBudgetExceededError, loads_bounded

MAX_HOST_EVENT_BYTES = 1 * 1024 * 1024
MAX_HOST_EVENT_IDENTIFIER = 128
_MAX_JSON_INTEGER = (1 << 64) - 1
_MAX_JSON_DEPTH = 128


class HostEventProfileId(str, Enum):
    """A parser profile selected by trusted entrypoint code."""

    CLAUDE_LEGACY_V1 = "claude-legacy-v1"
    COPILOT_1_0_84_4_HOOK_CANDIDATE = "copilot-1.0.84-4-hook-candidate"
    COPILOT_HOOK_V1 = "copilot-hook-v1"
    UNKNOWN = "unknown"


class HostEventKind(str, Enum):
    """Host event semantics independent of a host's spelling."""

    SESSION_START = "session_start"
    TURN_END = "turn_end"
    SESSION_END = "session_end"
    TOOL_START = "tool_start"
    TOOL_SUCCESS = "tool_success"
    TOOL_FAILURE = "tool_failure"
    AGENT_STOP = "agent_stop"
    UNKNOWN = "unknown"


class HostEventParseDisposition(str, Enum):
    """Pure parser outcome; none of these values authorizes an effect."""

    PARSED = "parsed"
    INVALID = "invalid"
    UNSUPPORTED = "unsupported"


class HostEventEffectDisposition(str, Enum):
    """Effect-layer outcomes used by host adapters."""

    APPLIED = "applied"
    NO_OWNER = "no_owner"
    NO_CANDIDATE = "no_candidate"
    AMBIGUOUS = "ambiguous"
    INVALID_TARGET = "invalid_target"
    IO_REFUSED = "io_refused"
    EFFECTS_DISABLED = "effects_disabled"
    DUPLICATE = "duplicate"
    OUT_OF_ORDER = "out_of_order"


@dataclass(frozen=True)
class HostEventProfileMeta:
    """Trusted static metadata for one event profile."""

    effects_enabled: bool
    evidence: str
    channel: str


@dataclass(frozen=True)
class NormalizedHostEvent:
    """Host-neutral data extracted without granting it authority."""

    profile: HostEventProfileId
    registration_kind: HostEventKind
    payload_kind: str | None
    event_id: str | None
    parent_id: str | None
    payload_session_id: str | None
    turn_id: str | None
    agent_id: str | None
    tool_call_id: str | None
    raw_tool_name: str | None
    canonical_tool_name: str | None
    tool_args: Mapping[str, object] | None
    tool_input: Mapping[str, object] | None
    success: bool | None
    reason: str | None
    payload_sha256: str


@dataclass(frozen=True)
class HostEventParseResult:
    """Non-throwing result for attacker-influenced hook bytes."""

    disposition: HostEventParseDisposition
    event: NormalizedHostEvent | None
    reason_code: str
    detail: str
    payload_sha256: str
    profile: HostEventProfileId
    registration_kind: HostEventKind


@dataclass(frozen=True)
class EventReceiptResult:
    """Test-only in-memory duplicate/conflict classification."""

    duplicate: bool
    conflict: bool


PROFILE_META: Mapping[HostEventProfileId, HostEventProfileMeta] = MappingProxyType(
    {
        HostEventProfileId.CLAUDE_LEGACY_V1: HostEventProfileMeta(
            effects_enabled=True,
            evidence="production-active",
            channel="hook",
        ),
        HostEventProfileId.COPILOT_1_0_84_4_HOOK_CANDIDATE: HostEventProfileMeta(
            effects_enabled=False,
            evidence="snapshot-schema-candidate",
            channel="hook",
        ),
        HostEventProfileId.COPILOT_HOOK_V1: HostEventProfileMeta(
            effects_enabled=True,
            evidence="live-observed-copilot-1.0.100-1-alias-normalized",
            channel="hook",
        ),
    }
)

_TOOL_NAME_ALIASES: Mapping[HostEventProfileId, Mapping[str, str]] = MappingProxyType(
    {
        HostEventProfileId.CLAUDE_LEGACY_V1: MappingProxyType(
            {
                "Read": "Read",
            }
        ),
        HostEventProfileId.COPILOT_1_0_84_4_HOOK_CANDIDATE: MappingProxyType(
            {
                "Read": "Read",
                "view": "Read",
            }
        ),
        HostEventProfileId.COPILOT_HOOK_V1: MappingProxyType(
            {
                "view": "Read",
            }
        ),
    }
)

_READ_PATH_KEYS: Mapping[HostEventProfileId, str] = MappingProxyType(
    {
        HostEventProfileId.CLAUDE_LEGACY_V1: "file_path",
        HostEventProfileId.COPILOT_1_0_84_4_HOOK_CANDIDATE: "path",
        HostEventProfileId.COPILOT_HOOK_V1: "path",
    }
)

_COPILOT_LIVE_EXACT_ALIAS_PAIRS = (
    ("eventId", "event_id"),
    ("parentId", "parent_id"),
    ("sessionId", "session_id"),
    ("turnId", "turn_id"),
    ("agentId", "agent_id"),
    ("toolCallId", "tool_call_id"),
)
_COPILOT_LIVE_CRITICAL_ALIAS_PAIRS = (
    ("sessionId", "session_id"),
    ("toolName", "tool_name"),
    ("toolArgs", "tool_input"),
)

_FIELD_NAMES: Mapping[HostEventProfileId, Mapping[str, str]] = MappingProxyType(
    {
        HostEventProfileId.CLAUDE_LEGACY_V1: MappingProxyType(
            dict(
                (
                    ("payload_kind", "hook_event_name"),
                    ("event_id", "event_id"),
                    ("parent_id", "parent_id"),
                    ("session_id", "session_id"),
                    ("turn_id", "turn_id"),
                    ("agent_id", "agent_id"),
                    ("tool_call_id", "tool_call_id"),
                    ("tool_name", "tool_name"),
                    ("tool_args", "tool_input"),
                    ("success", "success"),
                    ("reason", "reason"),
                )
            )
        ),
        HostEventProfileId.COPILOT_1_0_84_4_HOOK_CANDIDATE: MappingProxyType(
            dict(
                (
                    ("payload_kind", "hookEventName"),
                    ("event_id", "eventId"),
                    ("parent_id", "parentId"),
                    ("session_id", "sessionId"),
                    ("turn_id", "turnId"),
                    ("agent_id", "agentId"),
                    ("tool_call_id", "toolCallId"),
                    ("tool_name", "toolName"),
                    ("tool_args", "toolArgs"),
                    ("success", "success"),
                    ("reason", "reason"),
                )
            )
        ),
        HostEventProfileId.COPILOT_HOOK_V1: MappingProxyType(
            dict(
                (
                    ("payload_kind", "hookEventName"),
                    ("event_id", "eventId"),
                    ("parent_id", "parentId"),
                    ("session_id", "sessionId"),
                    ("turn_id", "turnId"),
                    ("agent_id", "agentId"),
                    ("tool_call_id", "toolCallId"),
                    ("tool_name", "toolName"),
                    ("tool_args", "toolArgs"),
                    ("success", "success"),
                    ("reason", "reason"),
                )
            )
        ),
    }
)

_EVENT_NAMES: Mapping[HostEventProfileId, Mapping[HostEventKind, str]] = (
    MappingProxyType(
        {
            HostEventProfileId.CLAUDE_LEGACY_V1: MappingProxyType(
                {
                    HostEventKind.SESSION_START: "SessionStart",
                    HostEventKind.TURN_END: "Stop",
                    HostEventKind.SESSION_END: "SessionEnd",
                    HostEventKind.TOOL_START: "PreToolUse",
                    HostEventKind.TOOL_SUCCESS: "PostToolUse",
                    HostEventKind.TOOL_FAILURE: "PostToolUseFailure",
                    HostEventKind.AGENT_STOP: "SubagentStop",
                }
            ),
            HostEventProfileId.COPILOT_1_0_84_4_HOOK_CANDIDATE: MappingProxyType(
                {
                    HostEventKind.SESSION_START: "sessionStart",
                    HostEventKind.TURN_END: "sessionEnd",
                    HostEventKind.TOOL_START: "preToolUse",
                    HostEventKind.TOOL_SUCCESS: "postToolUse",
                    HostEventKind.TOOL_FAILURE: "postToolUseFailure",
                    HostEventKind.AGENT_STOP: "agentStop",
                }
            ),
            HostEventProfileId.COPILOT_HOOK_V1: MappingProxyType(
                {
                    HostEventKind.SESSION_START: "sessionStart",
                    HostEventKind.SESSION_END: "sessionEnd",
                    HostEventKind.TOOL_START: "preToolUse",
                    HostEventKind.TOOL_SUCCESS: "postToolUse",
                    HostEventKind.TOOL_FAILURE: "postToolUseFailure",
                    HostEventKind.AGENT_STOP: "agentStop",
                }
            ),
        }
    )
)


def _canonical_read_args(
    value: object,
) -> tuple[dict[str, object] | None, str | None]:
    if not isinstance(value, dict):
        return None, "bad_tool_args"
    try:
        normalized = copy.deepcopy(value)
    except RecursionError:
        return None, "depth"
    has_path = "path" in normalized
    has_file_path = "file_path" in normalized
    if (
        has_path
        and has_file_path
        and normalized["path"] != normalized["file_path"]
    ):
        return None, "ambiguous_field_alias"
    if has_path:
        normalized["file_path"] = normalized.pop("path")
    return normalized, None


def _native_read_args(value: Mapping[str, object]) -> dict[str, object]:
    normalized = copy.deepcopy(dict(value))
    if "file_path" in normalized:
        normalized["path"] = normalized.pop("file_path")
    return normalized


def _normalize_copilot_live_aliases(
    payload: Mapping[str, object],
    registration_kind: HostEventKind,
) -> tuple[dict[str, object] | None, str | None]:
    """Coalesce the two fixed Copilot hook spellings without precedence."""
    normalized = dict(payload)
    has_camel = any(primary in payload for primary, _ in (
        _COPILOT_LIVE_CRITICAL_ALIAS_PAIRS
    ))
    has_snake = any(alias in payload for _, alias in (
        _COPILOT_LIVE_CRITICAL_ALIAS_PAIRS
    ))
    if has_camel and has_snake:
        for primary, alias in _COPILOT_LIVE_CRITICAL_ALIAS_PAIRS:
            if (primary in payload) != (alias in payload):
                return None, "ambiguous_field_alias"

    camel_kind = payload.get("hookEventName")
    snake_kind = payload.get("hook_event_name")
    camel_kind_present = "hookEventName" in payload
    snake_kind_present = "hook_event_name" in payload
    expected_camel = _EVENT_NAMES[HostEventProfileId.COPILOT_HOOK_V1][
        registration_kind
    ]
    expected_snake = _EVENT_NAMES[HostEventProfileId.CLAUDE_LEGACY_V1][
        registration_kind
    ]
    if camel_kind_present and not isinstance(camel_kind, str):
        return None, "bad_identifier"
    if snake_kind_present and not isinstance(snake_kind, str):
        return None, "bad_identifier"
    if camel_kind_present and snake_kind_present:
        if camel_kind != expected_camel or snake_kind != expected_snake:
            return None, "ambiguous_field_alias"
        normalized["hookEventName"] = expected_camel
    elif snake_kind_present:
        if snake_kind != expected_snake:
            return None, "registration_mismatch"
        normalized["hookEventName"] = expected_camel
    normalized.pop("hook_event_name", None)

    for primary, alias in _COPILOT_LIVE_EXACT_ALIAS_PAIRS:
        primary_present = primary in payload
        alias_present = alias in payload
        if primary_present and alias_present and payload[primary] != payload[alias]:
            return None, "ambiguous_field_alias"
        if alias_present and not primary_present:
            normalized[primary] = payload[alias]
        normalized.pop(alias, None)

    tool_name_present = "toolName" in payload
    tool_name_alias_present = "tool_name" in payload
    if tool_name_present and not isinstance(payload["toolName"], str):
        return None, "bad_tool_name"
    if tool_name_alias_present and not isinstance(payload["tool_name"], str):
        return None, "bad_tool_name"
    if tool_name_present and tool_name_alias_present:
        if payload["toolName"] != "view" or payload["tool_name"] != "Read":
            return None, "ambiguous_field_alias"
        normalized["toolName"] = "view"
    elif tool_name_alias_present:
        normalized["toolName"] = (
            "view"
            if payload["tool_name"] == "Read"
            else "__unsupported_tool__"
        )
    normalized.pop("tool_name", None)

    tool_args_present = "toolArgs" in payload
    tool_args_alias_present = "tool_input" in payload
    canonical_args: dict[str, object] | None = None
    if tool_args_present:
        canonical_args, problem = _canonical_read_args(payload["toolArgs"])
        if problem is not None:
            return None, problem
    if tool_args_alias_present:
        alias_args, problem = _canonical_read_args(payload["tool_input"])
        if problem is not None:
            return None, problem
        if canonical_args is not None and canonical_args != alias_args:
            return None, "ambiguous_field_alias"
        canonical_args = alias_args
    if canonical_args is not None:
        normalized["toolArgs"] = _native_read_args(canonical_args)
    normalized.pop("tool_input", None)
    return normalized, None


_DETAILS = MappingProxyType(
    dict(
        (
            ("parsed", "hook event parsed; no authority was granted"),
            ("budget", "hook event exceeds the byte budget"),
            ("not_bytes", "hook event input is not bytes"),
            ("not_utf8", "hook event is not strict UTF-8"),
            ("malformed_json", "hook event is not valid JSON"),
            ("duplicate_key", "hook event contains a duplicate object key"),
            ("non_finite", "hook event contains a non-finite number"),
            ("integer_out_of_range", "hook event contains an unsupported integer"),
            ("depth", "hook event nesting exceeds the parser limit"),
            ("non_object_root", "hook event root is not an object"),
            ("unsupported_profile", "hook event profile is unsupported"),
            ("unsupported_kind", "hook event registration kind is unsupported"),
            (
                "registration_mismatch",
                ("hook event does not match the fixed registration"),
            ),
            ("missing_session_id", "hook event session identity is missing"),
            ("missing_tool_name", "hook event tool name is missing"),
            ("bad_identifier", "hook event identifier is invalid"),
            ("bad_tool_name", "hook event tool name is invalid"),
            ("bad_tool_args", "hook event tool arguments are invalid"),
            (
                "ambiguous_field_alias",
                "hook event mixes incompatible field aliases",
            ),
            ("bad_success", "hook event success value is invalid"),
            ("bad_reason", "hook event reason is invalid"),
            ("missing_tool_args", "hook event tool arguments are missing"),
            ("missing_file_path", "hook event read path is missing"),
            ("bad_file_path", "hook event read path is invalid"),
            ("unsupported_tool", "hook event tool is unsupported"),
            ("no_owner", "no verified session owner is available"),
            ("owner_mismatch", "session owner does not match the credential pid"),
            ("bad_env_pid", "session credential pid is invalid"),
            ("profile_mismatch", "session owner frontend does not match the hook"),
            ("no_candidate", "no owned running run is available"),
            ("ambiguous", "multiple owned running runs are available"),
            ("invalid_target", "run target metadata is invalid"),
            ("io_refused", "coverage evidence write was refused"),
            ("stdin_closed", "hook event input could not be read"),
            ("no_stdin", "hook event input could not be read"),
            ("core_import_failed", "coverage hook core import failed"),
            ("import_failure", "coverage hook implementation could not start"),
            ("untrusted_dispatch", "trusted launcher marker is absent"),
            ("internal_error", "coverage hook failed safely"),
        )
    )
)


def _diag(code: str, **values: int | str) -> str:
    """Build one bounded diagnostic without attacker-controlled content."""
    safe_code = code if code in _DETAILS else "internal_error"
    detail = _DETAILS[safe_code]
    if safe_code == "budget":
        size = values.get("size", 0)
        limit = values.get("limit", MAX_HOST_EVENT_BYTES)
        if isinstance(size, int) and isinstance(limit, int):
            detail = f"{detail} ({size}>{limit})"
    return f"raptor-read-hook[{safe_code}]: {detail}"


def _result(
    disposition: HostEventParseDisposition,
    *,
    profile: HostEventProfileId,
    registration_kind: HostEventKind,
    payload_sha256: str,
    reason_code: str,
    event: NormalizedHostEvent | None = None,
    **diag_values: int | str,
) -> HostEventParseResult:
    return HostEventParseResult(
        disposition=disposition,
        event=event,
        reason_code=reason_code,
        detail=_diag(reason_code, **diag_values),
        payload_sha256=payload_sha256,
        profile=profile,
        registration_kind=registration_kind,
    )


def _optional_identifier(
    payload: Mapping[str, object],
    key: str,
) -> tuple[str | None, bool]:
    if key not in payload:
        return None, True
    value = payload[key]
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_HOST_EVENT_IDENTIFIER
        or not value.isascii()
        or not value.isprintable()
    ):
        return None, False
    return value, True


def _json_value_problem(value: object) -> str | None:
    pending = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > _MAX_JSON_DEPTH:
            return "depth"
        if isinstance(current, bool) or current is None:
            continue
        if isinstance(current, int):
            if current < -_MAX_JSON_INTEGER or current > _MAX_JSON_INTEGER:
                return "integer_out_of_range"
            continue
        if isinstance(current, float) and not math.isfinite(current):
            return "non_finite"
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)
    return None


def normalize_host_event(
    raw: bytes,
    *,
    profile: HostEventProfileId,
    registration_kind: HostEventKind,
) -> HostEventParseResult:
    """Normalize bounded hook bytes without granting any effect authority."""
    if not isinstance(raw, bytes):
        digest = hashlib.sha256(b"").hexdigest()
        return _result(
            HostEventParseDisposition.INVALID,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code="not_bytes",
        )
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) > MAX_HOST_EVENT_BYTES:
        return _result(
            HostEventParseDisposition.INVALID,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code="budget",
            size=len(raw),
            limit=MAX_HOST_EVENT_BYTES,
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _result(
            HostEventParseDisposition.INVALID,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code="not_utf8",
        )
    try:
        payload = loads_bounded(
            text,
            max_bytes=MAX_HOST_EVENT_BYTES,
            reject_duplicate_keys=True,
        )
    except JsonBudgetExceededError:
        return _result(
            HostEventParseDisposition.INVALID,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code="budget",
            size=len(raw),
            limit=MAX_HOST_EVENT_BYTES,
        )
    except RecursionError:
        return _result(
            HostEventParseDisposition.INVALID,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code="depth",
        )
    except ValueError as exc:
        message = str(exc)
        if message == "duplicate JSON object key":
            code = "duplicate_key"
        elif message.startswith("non-finite JSON constant rejected:"):
            code = "non_finite"
        elif "integer string conversion" in message:
            code = "integer_out_of_range"
        else:
            code = "malformed_json"
        return _result(
            HostEventParseDisposition.INVALID,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code=code,
        )
    if not isinstance(payload, dict):
        return _result(
            HostEventParseDisposition.INVALID,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code="non_object_root",
        )
    value_problem = _json_value_problem(payload)
    if value_problem is not None:
        return _result(
            HostEventParseDisposition.INVALID,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code=value_problem,
        )

    if profile not in PROFILE_META:
        return _result(
            HostEventParseDisposition.UNSUPPORTED,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code="unsupported_profile",
        )
    expected_names = _EVENT_NAMES[profile]
    if registration_kind not in expected_names:
        return _result(
            HostEventParseDisposition.UNSUPPORTED,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code="unsupported_kind",
        )

    if profile is HostEventProfileId.COPILOT_HOOK_V1:
        payload, alias_problem = _normalize_copilot_live_aliases(
            payload,
            registration_kind,
        )
        if payload is None or alias_problem is not None:
            return _result(
                HostEventParseDisposition.INVALID,
                profile=profile,
                registration_kind=registration_kind,
                payload_sha256=digest,
                reason_code=alias_problem or "ambiguous_field_alias",
            )
    fields = _FIELD_NAMES[profile]
    identifiers: dict[str, str | None] = {}
    for name in (
        "payload_kind",
        "event_id",
        "parent_id",
        "session_id",
        "turn_id",
        "agent_id",
        "tool_call_id",
    ):
        value, valid = _optional_identifier(payload, fields[name])
        if not valid:
            return _result(
                HostEventParseDisposition.INVALID,
                profile=profile,
                registration_kind=registration_kind,
                payload_sha256=digest,
                reason_code="bad_identifier",
            )
        identifiers[name] = value

    payload_kind = identifiers["payload_kind"]
    if payload_kind is not None and payload_kind != expected_names[registration_kind]:
        return _result(
            HostEventParseDisposition.INVALID,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code="registration_mismatch",
        )
    if (
        profile is HostEventProfileId.COPILOT_HOOK_V1
        and identifiers["session_id"] is None
    ):
        return _result(
            HostEventParseDisposition.INVALID,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code="missing_session_id",
        )

    raw_tool_name, tool_name_valid = _optional_identifier(payload, fields["tool_name"])
    if not tool_name_valid:
        return _result(
            HostEventParseDisposition.INVALID,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code="bad_tool_name",
        )
    if (
        profile is HostEventProfileId.COPILOT_HOOK_V1
        and registration_kind
        in {
            HostEventKind.TOOL_START,
            HostEventKind.TOOL_SUCCESS,
            HostEventKind.TOOL_FAILURE,
        }
        and raw_tool_name is None
    ):
        return _result(
            HostEventParseDisposition.INVALID,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code="missing_tool_name",
        )
    canonical_tool_name = _TOOL_NAME_ALIASES[profile].get(raw_tool_name)
    if (
        canonical_tool_name is None
        and raw_tool_name is None
        and profile is HostEventProfileId.CLAUDE_LEGACY_V1
        and registration_kind is HostEventKind.TOOL_SUCCESS
    ):
        # The legacy Claude shim is registered specifically for
        # PostToolUse(Read), and older payloads omit ``tool_name``.
        canonical_tool_name = "Read"

    tool_args_value = payload.get(fields["tool_args"])
    if fields["tool_args"] in payload:
        if not isinstance(tool_args_value, dict):
            return _result(
                HostEventParseDisposition.INVALID,
                profile=profile,
                registration_kind=registration_kind,
                payload_sha256=digest,
                reason_code="bad_tool_args",
            )
        try:
            tool_args = MappingProxyType(copy.deepcopy(tool_args_value))
        except RecursionError:
            return _result(
                HostEventParseDisposition.INVALID,
                profile=profile,
                registration_kind=registration_kind,
                payload_sha256=digest,
                reason_code="depth",
            )
    else:
        tool_args = None
    if (
        profile is HostEventProfileId.COPILOT_HOOK_V1
        and registration_kind
        in {
            HostEventKind.TOOL_START,
            HostEventKind.TOOL_SUCCESS,
            HostEventKind.TOOL_FAILURE,
        }
        and tool_args is None
    ):
        return _result(
            HostEventParseDisposition.INVALID,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code="missing_tool_args",
        )

    tool_input: Mapping[str, object] | None = None
    if canonical_tool_name == "Read" and tool_args_value is not None:
        try:
            canonical_args = copy.deepcopy(tool_args_value)
        except RecursionError:
            return _result(
                HostEventParseDisposition.INVALID,
                profile=profile,
                registration_kind=registration_kind,
                payload_sha256=digest,
                reason_code="depth",
            )
        path_key = _READ_PATH_KEYS[profile]
        if path_key != "file_path":
            if "file_path" in canonical_args:
                return _result(
                    HostEventParseDisposition.INVALID,
                    profile=profile,
                    registration_kind=registration_kind,
                    payload_sha256=digest,
                    reason_code="bad_tool_args",
                )
            if path_key in canonical_args:
                canonical_args["file_path"] = canonical_args.pop(path_key)
        tool_input = MappingProxyType(canonical_args)

    success_value = payload.get(fields["success"])
    if fields["success"] in payload and not isinstance(success_value, bool):
        return _result(
            HostEventParseDisposition.INVALID,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code="bad_success",
        )
    reason_value = payload.get(fields["reason"])
    if fields["reason"] in payload and not isinstance(reason_value, str):
        return _result(
            HostEventParseDisposition.INVALID,
            profile=profile,
            registration_kind=registration_kind,
            payload_sha256=digest,
            reason_code="bad_reason",
        )

    event = NormalizedHostEvent(
        profile=profile,
        registration_kind=registration_kind,
        payload_kind=payload_kind,
        event_id=identifiers["event_id"],
        parent_id=identifiers["parent_id"],
        payload_session_id=identifiers["session_id"],
        turn_id=identifiers["turn_id"],
        agent_id=identifiers["agent_id"],
        tool_call_id=identifiers["tool_call_id"],
        raw_tool_name=raw_tool_name,
        canonical_tool_name=canonical_tool_name,
        tool_args=tool_args,
        tool_input=tool_input,
        success=success_value if isinstance(success_value, bool) else None,
        reason=reason_value if isinstance(reason_value, str) else None,
        payload_sha256=digest,
    )
    return _result(
        HostEventParseDisposition.PARSED,
        profile=profile,
        registration_kind=registration_kind,
        payload_sha256=digest,
        reason_code="parsed",
        event=event,
    )


def event_key(
    profile: HostEventProfileId,
    registration_kind: HostEventKind,
    event_id: str,
) -> str:
    """Return a stable opaque key for a trusted profile registration.

    Callers pass ``event.event_id or event.payload_sha256`` so legacy
    payloads without an event identifier degrade to their payload digest.
    """
    material = (f"{profile.value}\0{registration_kind.value}\0{event_id}").encode(
        "ascii"
    )
    return hashlib.sha256(material).hexdigest()


def event_key_for(event: NormalizedHostEvent) -> str:
    """Return the event ID key, falling back to the payload digest."""
    return event_key(
        event.profile,
        event.registration_kind,
        event.event_id or event.payload_sha256,
    )


class InMemoryEventReceipts:
    """Test-only receipt store; it is never a production authority."""

    def __init__(self) -> None:
        self._payloads: dict[str, str] = {}

    def observe(self, key: str, payload_sha256: str) -> EventReceiptResult:
        previous = self._payloads.get(key)
        if previous is None:
            self._payloads[key] = payload_sha256
            return EventReceiptResult(duplicate=False, conflict=False)
        return EventReceiptResult(
            duplicate=previous == payload_sha256,
            conflict=previous != payload_sha256,
        )


__all__ = [
    "EventReceiptResult",
    "HostEventEffectDisposition",
    "HostEventKind",
    "HostEventParseDisposition",
    "HostEventParseResult",
    "HostEventProfileId",
    "HostEventProfileMeta",
    "InMemoryEventReceipts",
    "MAX_HOST_EVENT_BYTES",
    "MAX_HOST_EVENT_IDENTIFIER",
    "NormalizedHostEvent",
    "PROFILE_META",
    "event_key",
    "event_key_for",
    "normalize_host_event",
]
