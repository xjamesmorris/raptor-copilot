"""Pure parser for an unverified Copilot CLI session-event candidate.

The source facts come from ``session-events.schema.json`` shipped with
GitHub Copilot CLI 1.0.84-4.  No live probe has established that
``--output-format json`` emits this exact stream, so every result is fixed as
``schema-derived-candidate-unverified``.  There is no caller-controlled flag
that can promote it.

This is a deliberately narrow completion-only profile, not a general Copilot
workflow engine.  It accepts one root user/assistant turn, model/usage
evidence, a small terminal sequence, diagnostics, and the safety events that
must fail closed.  It never launches a process.

Canonical UUID v4 IDs, an immediate-predecessor ``parentId`` chain, one turn,
one usage event per model call, and the receipt/idle/shutdown order are
candidate-profile assumptions.  They are conservative admission policy, not
claims that a live ``--output-format json`` stream has been observed.

Evidence levels describe only observed channel coverage.  A request echo is
not runtime identity; shutdown aggregates do not substitute for per-call
usage; and partial model-call coverage remains ``none``.  Billing fields can
raise identity coverage to ``runtime_and_billing``, but that label is neither
billing correctness nor model attestation.  Exact field population and
reconciliation remain future probe gates.  Terminal/content success without
complete per-call runtime evidence is
``candidate_complete_unevidenced`` and is retained only for record inspection;
the admission API refuses it.

Chunked transcripts expose the observed message-ID mode.  The current
candidate profile's global replay rule requires distinct ``messageId`` values
across accepted multi-chunk output, so ``distinct`` is a profile observation,
not proof of live shared-versus-distinct semantics.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID

from core.json import loads_bounded
from core.security.log_sanitisation import sanitise_for_terminal
from core.security.prompt_output_sanitise import sanitise_string
from core.security.redaction import redact_secrets

CANDIDATE_CONTRACT_NAME = "github-copilot-cli-session-events"
CANDIDATE_CONTRACT_VERSION = 1
CANDIDATE_SOURCE_CLI_VERSION = "1.0.84-4"
CANDIDATE_SOURCE_SCHEMA_SHA256 = (
    "ce6ea924e8bd3cb825046d7328a4b0922d787efa9868f9e7816df95e1ab2b545"
)
CANDIDATE_EVIDENCE_LEVEL = "schema-derived-candidate-unverified"

DEFAULT_MAX_TOTAL_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_LINE_BYTES = 1024 * 1024
DEFAULT_MAX_EVENTS = 4096
_MAX_PUBLIC_ERROR_CHARS = 512
_PARSE_FAILED = object()

_ENVELOPE_FIELDS = frozenset(
    {"id", "timestamp", "parentId", "ephemeral", "agentId", "type", "data"}
)
_ENVELOPE_REQUIRED = frozenset({"id", "timestamp", "parentId", "type", "data"})
_EPHEMERAL_EVENTS = frozenset(
    {
        "agent.interrupted",
        "assistant.usage",
        "auto_mode_switch.completed",
        "auto_mode_switch.requested",
        "model.call_failure",
        "model.call_finished",
        "model.call_start",
        "session.idle",
        "session.usage_info",
    }
)

_MODEL_CALL_OUTCOMES = frozenset({"success", "error", "cancelled", "rejected"})
_STOP_REASONS = frozenset({"natural", "terminal_tool", "agent_stop_block_limit"})
_TASK_OUTCOMES = frozenset({"completed", "continue", "blocked"})
_SHUTDOWN_TYPES = frozenset({"routine", "error"})
_ABORT_REASONS = frozenset(
    {"user_initiated", "remote_command", "user_abort", "autopilot_credit_limit"}
)
_MODEL_CHANGE_SOURCES = frozenset(
    {
        "model_command",
        "settings_command",
        "config_command",
        "model_picker",
        "managed_settings",
        "repo_settings",
        "startup",
        "agent",
        "plan_mode",
        "automatic",
        "sdk",
    }
)
_AUTO_SWITCH_RESPONSES = frozenset({"yes", "yes_always", "no"})
_SESSION_MODES = frozenset({"interactive", "plan", "autopilot"})
_REMEDIATIONS = frozenset(
    {
        "sign_in",
        "switch_account",
        "show_account",
        "review_sandbox_policy",
        "allow_sandbox_outbound",
    }
)
_TRANSPORTS = frozenset({"http", "websocket"})
_ENDPOINTS = frozenset(
    {"/chat/completions", "/v1/messages", "/responses", "ws:/responses"}
)
_FAILURE_SOURCES = frozenset({"top_level", "subagent", "mcp_sampling"})
_FAILURE_KINDS = frozenset({"api", "transport"})
_BAD_REQUEST_KINDS = frozenset({"bodyless", "structured_error"})
_INTERRUPTED_ACTIVITIES = frozenset(
    {"model_call", "retry_backoff", "tool_call", "background_agent"}
)
_INTERRUPTED_PHASES = frozenset({"pre_first_token", "mid_stream"})


class CopilotCandidateProtocolError(ValueError):
    """Base class for malformed or unsupported candidate input."""

    def __init__(self, message: object) -> None:
        super().__init__(_public_error_message(message))


class CopilotCandidateStreamLimitError(CopilotCandidateProtocolError):
    """A byte or event budget was exceeded."""


class CopilotCandidateEncodingError(CopilotCandidateProtocolError):
    """A record was not strict UTF-8."""


class CopilotCandidateJSONError(CopilotCandidateProtocolError):
    """A record was not strict JSON."""


class CopilotCandidateTruncatedStreamError(CopilotCandidateJSONError):
    """The stream ended without its line terminator."""


class CopilotCandidateEventError(CopilotCandidateProtocolError):
    """A JSON object violated the candidate event profile."""


class CopilotCandidateVersionError(CopilotCandidateEventError):
    """The stream identified another schema or CLI version."""


class CopilotCandidateReplayError(CopilotCandidateEventError):
    """An event, call, message, tool, or request identity was replayed."""


class CopilotCandidateOrderError(CopilotCandidateEventError):
    """Events were chained or correlated inconsistently."""


class CopilotCandidateUnsupportedEventError(CopilotCandidateEventError):
    """An event outside the bounded candidate subset was encountered."""


class CopilotCandidateAdmissionError(RuntimeError):
    """A parsed transcript cannot be admitted as a pure completion."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(_public_error_message(message))
        self.code = code


class CandidateTranscriptOutcome(str, Enum):
    """Semantic state derived from a structurally valid transcript."""

    CANDIDATE_COMPLETE = "candidate_complete"
    CANDIDATE_COMPLETE_UNEVIDENCED = "candidate_complete_unevidenced"
    ERROR = "error"
    CANCELLED = "cancelled"
    INCOMPLETE = "incomplete"
    REJECTED = "rejected"


class CandidateIdentityEvidence(str, Enum):
    """Observed model-identity coverage, not provider attestation."""

    NONE = "none"
    RUNTIME = "runtime"
    RUNTIME_AND_BILLING = "runtime_and_billing"


class CandidateUsageEvidenceLevel(str, Enum):
    """Observed usage-channel coverage without correctness inference."""

    NONE = "none"
    PER_CALL = "per_call"
    PER_CALL_AND_SHUTDOWN = "per_call_and_shutdown"


class CandidateChunkMessageIdMode(str, Enum):
    """Observed assistant-message ID pattern for the parsed response."""

    SINGLE = "single"
    DISTINCT = "distinct"
    MIXED = "mixed"
    NOT_APPLICABLE = "n/a"


@dataclass(frozen=True)
class CandidateProtocolProvenance:
    """Fixed provenance; init-disabled fields cannot be caller-promoted."""

    contract_name: str = field(default=CANDIDATE_CONTRACT_NAME, init=False)
    contract_version: int = field(default=CANDIDATE_CONTRACT_VERSION, init=False)
    source_cli_version: str = field(default=CANDIDATE_SOURCE_CLI_VERSION, init=False)
    source_schema_sha256: str = field(
        default=CANDIDATE_SOURCE_SCHEMA_SHA256, init=False
    )
    evidence_level: str = field(default=CANDIDATE_EVIDENCE_LEVEL, init=False)


CANDIDATE_PROTOCOL_PROVENANCE = CandidateProtocolProvenance()


@dataclass(frozen=True)
class CandidateStreamLimits:
    """Hard limits checked before and during JSONL parsing."""

    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES
    max_events: int = DEFAULT_MAX_EVENTS

    def __post_init__(self) -> None:
        for name in ("max_total_bytes", "max_line_bytes", "max_events"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_line_bytes > self.max_total_bytes:
            raise ValueError("max_line_bytes cannot exceed max_total_bytes")


@dataclass(frozen=True)
class CandidateRequestedSettings:
    """Exact caller request, kept separate from runtime-reported settings."""

    model: str
    reasoning_effort: str | None = None
    context_tier: str | None = None

    def __post_init__(self) -> None:
        _validate_setting(self.model, "model")
        if self.model == "auto":
            raise ValueError("model must be exact; 'auto' is not permitted")
        if self.reasoning_effort is not None:
            _validate_setting(self.reasoning_effort, "reasoning_effort")
        if self.context_tier is not None:
            _validate_setting(self.context_tier, "context_tier")


@dataclass(frozen=True)
class CandidateReportedSettings:
    """Settings echoed by ``session.start``."""

    selected_model: str | None
    reasoning_effort: str | None
    context_tier: str | None


@dataclass(frozen=True)
class CandidateModelObservation:
    """One runtime, server-billing, or aggregate model identity."""

    event_id: str
    event_type: str
    field: str
    model: str
    source: str


@dataclass(frozen=True)
class CandidateBillingTokenDetail:
    """One server-reported Copilot billing detail."""

    token_type: str
    token_count: int
    batch_size: int
    cost_per_batch: int
    model: str | None


@dataclass(frozen=True)
class CandidateCallUsage:
    """Per-call usage from one ``assistant.usage`` event."""

    event_id: str
    turn_id: str
    model: str
    is_auto: bool | None
    reasoning_effort: str | None
    api_call_id: str | None
    provider_call_id: str | None
    service_request_id: str | None
    transport: str | None
    api_endpoint: str | None
    finish_reason: str | None
    input_tokens: int | None
    output_tokens: int | None
    cache_read_tokens: int | None
    cache_write_tokens: int | None
    reasoning_tokens: int | None
    reported_cost: Decimal | None
    server_billing_model: str | None
    server_total_nano_aiu: Decimal | None
    server_token_details: tuple[CandidateBillingTokenDetail, ...]


@dataclass(frozen=True)
class CandidateUsageTotals:
    """Totals derived only from complete per-call fields."""

    call_count: int
    input_tokens: int | None
    output_tokens: int | None
    cache_read_tokens: int | None
    cache_write_tokens: int | None
    reasoning_tokens: int | None
    reported_cost: Decimal | None
    server_total_nano_aiu: Decimal | None


@dataclass(frozen=True)
class CandidateShutdownModelUsage:
    """One model entry from the shutdown aggregate."""

    model: str
    request_count: int | None
    reported_request_cost: Decimal | None
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    reasoning_tokens: int | None
    total_nano_aiu: Decimal | None


@dataclass(frozen=True)
class CandidateShutdownUsage:
    """Shutdown aggregate, retained separately from per-call totals."""

    current_model: str | None
    total_premium_requests: Decimal | None
    total_nano_aiu: Decimal | None
    model_metrics: tuple[CandidateShutdownModelUsage, ...]


@dataclass(frozen=True)
class CandidateUsageEvidence:
    """Usage channels with no cross-channel addition."""

    calls: tuple[CandidateCallUsage, ...]
    per_call_totals: CandidateUsageTotals | None
    shutdown_aggregate: CandidateShutdownUsage | None


@dataclass(frozen=True)
class CandidateDiagnostic:
    """Redacted informational evidence retained for the caller."""

    event_id: str
    event_type: str
    level: str
    message: str


@dataclass(frozen=True)
class CandidateIssue:
    """A semantic reason a valid transcript is not a completion."""

    code: str
    category: str
    event_id: str | None
    event_type: str | None
    message: str


@dataclass(frozen=True)
class CandidateTerminalEvidence:
    """Candidate terminal markers and correlation IDs."""

    user_message_event_id: str | None
    turn_end_event_id: str | None
    completion_receipt_event_id: str | None
    completion_stop_reason: str | None
    idle_event_id: str | None
    shutdown_event_id: str | None


@dataclass(frozen=True)
class CandidateTranscript:
    """Parsed candidate transcript; never a production approval receipt."""

    provenance: CandidateProtocolProvenance
    outcome: CandidateTranscriptOutcome
    identity_evidence: CandidateIdentityEvidence
    usage_evidence: CandidateUsageEvidenceLevel
    chunk_message_id_mode: CandidateChunkMessageIdMode
    event_count: int
    model_call_count: int
    session_id: str | None
    reported_settings: CandidateReportedSettings | None
    final_content: str | None
    model_observations: tuple[CandidateModelObservation, ...]
    usage: CandidateUsageEvidence
    diagnostics: tuple[CandidateDiagnostic, ...]
    issues: tuple[CandidateIssue, ...]
    terminal: CandidateTerminalEvidence


@dataclass(frozen=True)
class CandidateCompletion:
    """Candidate-only pure completion admitted from a valid transcript."""

    provenance: CandidateProtocolProvenance
    outcome: CandidateTranscriptOutcome
    identity_evidence: CandidateIdentityEvidence
    usage_evidence: CandidateUsageEvidenceLevel
    chunk_message_id_mode: CandidateChunkMessageIdMode
    model_call_count: int
    session_id: str
    requested_settings: CandidateRequestedSettings
    reported_settings: CandidateReportedSettings
    content: str
    model_observations: tuple[CandidateModelObservation, ...]
    usage: CandidateUsageEvidence
    diagnostics: tuple[CandidateDiagnostic, ...]
    terminal: CandidateTerminalEvidence


@dataclass(frozen=True)
class _Shape:
    """Small selected-event profile, not a replacement JSON-schema engine."""

    required: frozenset[str] = frozenset()
    strings: frozenset[str] = frozenset()
    empty_strings: frozenset[str] = frozenset()
    nullable_strings: frozenset[str] = frozenset()
    integers: tuple[tuple[str, int], ...] = ()
    numbers: tuple[tuple[str, Decimal | None], ...] = ()
    booleans: frozenset[str] = frozenset()
    objects: frozenset[str] = frozenset()
    arrays: frozenset[str] = frozenset()
    enums: tuple[tuple[str, frozenset[str]], ...] = ()
    opaque: frozenset[str] = frozenset()

    @property
    def allowed(self) -> frozenset[str]:
        names = (
            set(self.strings)
            | set(self.nullable_strings)
            | {name for name, _ in self.integers}
            | {name for name, _ in self.numbers}
            | set(self.booleans)
            | set(self.objects)
            | set(self.arrays)
            | {name for name, _ in self.enums}
            | set(self.opaque)
        )
        return frozenset(names)


def _shape(
    *,
    required: tuple[str, ...] = (),
    strings: tuple[str, ...] = (),
    empty_strings: tuple[str, ...] = (),
    nullable_strings: tuple[str, ...] = (),
    integers: tuple[tuple[str, int], ...] = (),
    numbers: tuple[tuple[str, Decimal | None], ...] = (),
    booleans: tuple[str, ...] = (),
    objects: tuple[str, ...] = (),
    arrays: tuple[str, ...] = (),
    enums: tuple[tuple[str, frozenset[str]], ...] = (),
    opaque: tuple[str, ...] = (),
) -> _Shape:
    return _Shape(
        required=frozenset(required),
        strings=frozenset(strings),
        empty_strings=frozenset(empty_strings),
        nullable_strings=frozenset(nullable_strings),
        integers=integers,
        numbers=numbers,
        booleans=frozenset(booleans),
        objects=frozenset(objects),
        arrays=frozenset(arrays),
        enums=enums,
        opaque=frozenset(opaque),
    )


_EVENT_SHAPES = {
    "session.start": _shape(
        required=(
            "sessionId",
            "version",
            "producer",
            "copilotVersion",
            "startTime",
        ),
        strings=(
            "sessionId",
            "producer",
            "copilotVersion",
            "startTime",
            "selectedModel",
            "reasoningEffort",
        ),
        nullable_strings=("contextTier",),
        integers=(("version", 0),),
    ),
    "user.message": _shape(
        required=("content",),
        strings=(
            "content",
            "messageId",
            "source",
            "turnId",
            "parentAgentTaskId",
        ),
        empty_strings=("content",),
        booleans=("isAutopilotContinuation",),
    ),
    "assistant.turn_start": _shape(
        required=("turnId",),
        strings=("turnId", "model"),
    ),
    "model.call_start": _shape(
        required=("turnId",),
        strings=("turnId", "model"),
    ),
    "assistant.message": _shape(
        required=("messageId", "content"),
        strings=(
            "messageId",
            "model",
            "content",
            "apiCallId",
            "turnId",
            "parentToolCallId",
        ),
        empty_strings=("content",),
        integers=(("chunkIndex", 0), ("chunkCount", 1), ("outputTokens", 0)),
        arrays=("toolRequests",),
        objects=("serverTools",),
    ),
    "assistant.usage": _shape(
        required=("model",),
        strings=(
            "model",
            "apiCallId",
            "providerCallId",
            "serviceRequestId",
            "reasoningEffort",
            "finishReason",
        ),
        integers=(
            ("inputTokens", 0),
            ("outputTokens", 0),
            ("cacheReadTokens", 0),
            ("cacheWriteTokens", 0),
            ("reasoningTokens", 0),
            ("duration", 0),
        ),
        numbers=(("cost", None),),
        booleans=("isAuto",),
        objects=("copilotUsage",),
        enums=(("transport", _TRANSPORTS), ("apiEndpoint", _ENDPOINTS)),
    ),
    "model.call_finished": _shape(
        required=(
            "turnId",
            "dispatchDurationMs",
            "outcome",
            "editClassifierVersion",
        ),
        strings=("turnId",),
        integers=(("editClassifierVersion", 1),),
        numbers=(("dispatchDurationMs", Decimal(0)),),
        enums=(("outcome", _MODEL_CALL_OUTCOMES),),
    ),
    "model.call_failure": _shape(
        required=("source",),
        strings=(
            "model",
            "initiator",
            "apiCallId",
            "providerCallId",
            "serviceRequestId",
            "reasoningEffort",
            "errorMessage",
            "errorCode",
            "errorType",
        ),
        empty_strings=("errorMessage",),
        integers=(
            ("statusCode", 0),
            ("durationMs", 0),
        ),
        booleans=("isAuto",),
        enums=(
            ("source", _FAILURE_SOURCES),
            ("transport", _TRANSPORTS),
            ("failureKind", _FAILURE_KINDS),
            ("badRequestKind", _BAD_REQUEST_KINDS),
        ),
    ),
    "assistant.turn_end": _shape(
        required=("turnId",),
        strings=("turnId", "model"),
    ),
    "session.completion_receipt": _shape(
        required=(
            "schemaVersion",
            "attempt",
            "sourceEventId",
            "eventRange",
            "stopReason",
            "successfulToolCount",
            "failedToolCount",
        ),
        strings=("sourceEventId",),
        integers=(
            ("schemaVersion", 1),
            ("attempt", 1),
            ("successfulToolCount", 0),
            ("failedToolCount", 0),
        ),
        objects=("eventRange", "finalTool"),
        enums=(("stopReason", _STOP_REASONS),),
    ),
    "session.idle": _shape(
        booleans=("aborted",),
        enums=(("mode", _SESSION_MODES),),
    ),
    "session.shutdown": _shape(
        required=(
            "shutdownType",
            "totalApiDurationMs",
            "sessionStartTime",
            "codeChanges",
            "modelMetrics",
        ),
        strings=("errorReason", "currentModel"),
        empty_strings=("errorReason",),
        integers=(
            ("totalApiDurationMs", 0),
            ("sessionStartTime", 0),
        ),
        numbers=(
            ("totalPremiumRequests", Decimal(0)),
            ("totalNanoAiu", Decimal(0)),
        ),
        objects=("codeChanges", "modelMetrics", "agentMetrics"),
        enums=(("shutdownType", _SHUTDOWN_TYPES),),
    ),
    "session.error": _shape(
        required=("errorType", "message"),
        strings=(
            "errorType",
            "errorCode",
            "message",
            "providerCallId",
            "serviceRequestId",
        ),
        empty_strings=("message",),
        integers=(("statusCode", 0),),
        booleans=("eligibleForAutoSwitch",),
    ),
    "abort": _shape(
        required=("reason",),
        enums=(("reason", _ABORT_REASONS),),
    ),
    "agent.interrupted": _shape(
        required=("activity", "elapsedMs", "turn"),
        strings=("model", "reasoningEffort"),
        integers=(("turn", 0), ("interruptedAgentCount", 1)),
        numbers=(("elapsedMs", Decimal(0)),),
        arrays=("toolNames", "toolCallIds"),
        enums=(
            ("activity", _INTERRUPTED_ACTIVITIES),
            ("transport", _TRANSPORTS),
            ("cancelPhase", _INTERRUPTED_PHASES),
        ),
    ),
    "session.model_change": _shape(
        required=("newModel",),
        strings=(
            "previousModel",
            "newModel",
            "previousReasoningEffort",
            "cause",
        ),
        nullable_strings=("reasoningEffort", "contextTier"),
        enums=(("source", _MODEL_CHANGE_SOURCES),),
    ),
    "session.auto_mode_resolved": _shape(
        required=("chosenModel",),
        strings=(
            "chosenModel",
            "fallbackReason",
        ),
        booleans=("fallback",),
        arrays=("candidateModels", "availableModels"),
    ),
    "auto_mode_switch.requested": _shape(
        required=("requestId",),
        strings=("requestId", "errorCode"),
        integers=(("retryAfterSeconds", 0),),
    ),
    "auto_mode_switch.completed": _shape(
        required=("requestId", "response"),
        strings=("requestId",),
        enums=(("response", _AUTO_SWITCH_RESPONSES),),
    ),
    "tool.execution_start": _shape(
        required=("toolCallId", "toolName"),
        strings=(
            "toolCallId",
            "toolName",
            "model",
            "turnId",
            "parentToolCallId",
        ),
        opaque=("arguments",),
    ),
    "tool.execution_complete": _shape(
        required=("toolCallId", "success"),
        strings=(
            "toolCallId",
            "model",
            "turnId",
            "parentToolCallId",
        ),
        booleans=("success", "sandboxed"),
        objects=("result", "error"),
    ),
    "permission.requested": _shape(
        required=("requestId", "permissionRequest"),
        strings=("requestId",),
        objects=("permissionRequest",),
        enums=(("agentMode", _SESSION_MODES),),
    ),
    "permission.completed": _shape(
        required=("requestId", "result"),
        strings=("requestId", "toolCallId"),
        objects=("result",),
    ),
    "session.task_complete": _shape(
        strings=("summary", "reason"),
        empty_strings=("summary", "reason"),
        integers=(("objectiveId", 0),),
        booleans=("success",),
        enums=(("outcome", _TASK_OUTCOMES),),
    ),
    "session.warning": _shape(
        required=("warningType", "message"),
        strings=("warningType", "message", "url"),
        empty_strings=("message",),
        enums=(("remediation", _REMEDIATIONS),),
    ),
    "session.info": _shape(
        required=("infoType", "message"),
        strings=("infoType", "message", "url", "tip"),
        empty_strings=("message", "tip"),
    ),
    "session.truncation": _shape(
        required=(
            "tokenLimit",
            "preTruncationTokensInMessages",
            "preTruncationMessagesLength",
            "postTruncationTokensInMessages",
            "postTruncationMessagesLength",
            "tokensRemovedDuringTruncation",
            "messagesRemovedDuringTruncation",
            "performedBy",
        ),
        strings=("performedBy",),
        integers=(
            ("tokenLimit", 0),
            ("preTruncationTokensInMessages", 0),
            ("preTruncationMessagesLength", 0),
            ("postTruncationTokensInMessages", 0),
            ("postTruncationMessagesLength", 0),
            ("tokensRemovedDuringTruncation", 0),
            ("messagesRemovedDuringTruncation", 0),
        ),
    ),
    "session.usage_info": _shape(
        required=("tokenLimit", "currentTokens", "messagesLength"),
        integers=(
            ("tokenLimit", 0),
            ("currentTokens", 0),
            ("messagesLength", 0),
            ("systemTokens", 0),
            ("conversationTokens", 0),
            ("toolDefinitionsTokens", 0),
        ),
        booleans=("isInitial",),
    ),
}


@dataclass(frozen=True)
class _Event:
    line_number: int
    event_id: str
    timestamp: datetime
    parent_id: str | None
    ephemeral: bool | None
    agent_id: str | None
    event_type: str
    data: dict[str, Any]


@dataclass
class _ParserState:
    session_id: str | None = None
    reported_settings: CandidateReportedSettings | None = None
    user_message_event_id: str | None = None
    user_turn_id: str | None = None
    active_turn_id: str | None = None
    active_call_turn_id: str | None = None
    model_call_count: int = 0
    active_call_message_count: int = 0
    active_call_message_api_ids: set[str] = field(default_factory=set)
    active_call_messages_without_api_id: int = 0
    active_call_usage_count: int = 0
    active_call_usage_api_ids: set[str] = field(default_factory=set)
    active_call_usage_without_api_id: int = 0
    completed_turn_ids: set[str] = field(default_factory=set)
    message_ids: set[str] = field(default_factory=set)
    message_parts: list[str] = field(default_factory=list)
    message_mode: str | None = None
    chunk_count: int | None = None
    chunk_indexes: set[int] = field(default_factory=set)
    chunk_message_ids: list[str] = field(default_factory=list)
    final_content: str | None = None
    turn_end_event_id: str | None = None
    receipt_event_id: str | None = None
    receipt_stop_reason: str | None = None
    idle_event_id: str | None = None
    shutdown_event_id: str | None = None
    shutdown_usage: CandidateShutdownUsage | None = None
    seen_shutdown: bool = False
    call_usage: list[CandidateCallUsage] = field(default_factory=list)
    model_observations: list[CandidateModelObservation] = field(default_factory=list)
    diagnostics: list[CandidateDiagnostic] = field(default_factory=list)
    issues: list[CandidateIssue] = field(default_factory=list)
    usage_api_call_ids: set[str] = field(default_factory=set)
    settled_api_call_ids: set[str] = field(default_factory=set)
    tool_call_ids: set[str] = field(default_factory=set)
    completed_tool_call_ids: set[str] = field(default_factory=set)
    permission_request_ids: set[str] = field(default_factory=set)
    completed_permission_request_ids: set[str] = field(default_factory=set)
    auto_switch_request_ids: set[str] = field(default_factory=set)


def parse_candidate_transcript(
    payload: bytes,
    *,
    limits: CandidateStreamLimits | None = None,
) -> CandidateTranscript:
    """Parse bounded JSONL under the unverified candidate profile.

    Raw bytes are required so the UTF-8 and byte gates run before text
    materialisation.  A final newline is mandatory: a syntactically complete
    object without it is indistinguishable from a transport truncated
    immediately after its closing brace.
    """

    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    active_limits = limits or CandidateStreamLimits()
    if len(payload) > active_limits.max_total_bytes:
        raise CopilotCandidateStreamLimitError(
            f"candidate stream is {len(payload)} bytes; "
            f"limit is {active_limits.max_total_bytes}"
        )
    if not payload:
        raise CopilotCandidateJSONError("candidate stream is empty")
    if not payload.endswith(b"\n"):
        raise CopilotCandidateTruncatedStreamError(
            "candidate stream is truncated: final newline is missing"
        )

    lines = payload.split(b"\n")[:-1]
    if len(lines) > active_limits.max_events:
        raise CopilotCandidateStreamLimitError(
            f"candidate stream has {len(lines)} events; "
            f"limit is {active_limits.max_events}"
        )

    state = _ParserState()
    seen_event_ids: set[str] = set()
    last_event_id: str | None = None
    last_timestamp: datetime | None = None

    for line_number, raw_line in enumerate(lines, start=1):
        line_bytes = len(raw_line) + 1
        if line_bytes > active_limits.max_line_bytes:
            raise CopilotCandidateStreamLimitError(
                f"candidate line {line_number} is {line_bytes} bytes; "
                f"limit is {active_limits.max_line_bytes}"
            )
        if raw_line.endswith(b"\r"):
            raw_line = raw_line[:-1]
        if not raw_line or raw_line.isspace():
            raise CopilotCandidateJSONError(f"candidate line {line_number} is blank")
        text: str | None
        try:
            text = raw_line.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            text = None
        if text is None:
            raise CopilotCandidateEncodingError(
                f"candidate line {line_number} is not valid UTF-8"
            )
        value: object = _PARSE_FAILED
        try:
            value = loads_bounded(
                text,
                max_bytes=active_limits.max_line_bytes,
                reject_duplicate_keys=True,
            )
        except (ValueError, RecursionError):
            pass
        if value is _PARSE_FAILED:
            raise CopilotCandidateJSONError(
                f"candidate line {line_number} is not valid strict JSON"
            )

        event = _parse_event(value, line_number)
        if event.event_id in seen_event_ids:
            raise CopilotCandidateReplayError(
                f"candidate line {line_number} replays event id {event.event_id}"
            )
        if last_event_id is None:
            if event.parent_id is not None:
                raise CopilotCandidateOrderError(
                    "the first candidate event must have parentId=null"
                )
            if event.event_type != "session.start":
                raise CopilotCandidateOrderError(
                    "the first candidate event must be session.start"
                )
        elif event.parent_id != last_event_id:
            raise CopilotCandidateOrderError(
                f"candidate line {line_number} parentId does not name "
                "the immediately preceding event"
            )
        if last_timestamp is not None and event.timestamp < last_timestamp:
            raise CopilotCandidateOrderError(
                f"candidate line {line_number} timestamp moves backwards"
            )
        if state.seen_shutdown:
            raise CopilotCandidateOrderError(
                f"candidate line {line_number} follows session.shutdown"
            )

        _consume_event(state, event)
        seen_event_ids.add(event.event_id)
        last_event_id = event.event_id
        last_timestamp = event.timestamp

    return _finish_transcript(state, len(lines))


def admit_candidate_completion(
    transcript: CandidateTranscript,
    requested: CandidateRequestedSettings,
) -> CandidateCompletion:
    """Admit an exact-model, completion-only candidate transcript."""

    if not isinstance(transcript, CandidateTranscript):
        raise TypeError("transcript must be CandidateTranscript")
    if not isinstance(requested, CandidateRequestedSettings):
        raise TypeError("requested must be CandidateRequestedSettings")
    if transcript.provenance != CANDIDATE_PROTOCOL_PROVENANCE:
        raise CopilotCandidateAdmissionError(
            "provenance_mismatch",
            "transcript does not carry the fixed candidate provenance",
        )
    if transcript.outcome is not CandidateTranscriptOutcome.CANDIDATE_COMPLETE:
        detail = ", ".join(issue.code for issue in transcript.issues)
        suffix = f": {detail}" if detail else ""
        raise CopilotCandidateAdmissionError(
            transcript.outcome.value,
            f"candidate transcript is {transcript.outcome.value}{suffix}",
        )
    derived_identity, derived_usage = _evidence_levels(
        transcript.model_call_count,
        transcript.usage.calls,
        transcript.usage.shutdown_aggregate,
    )
    if (
        transcript.identity_evidence is not derived_identity
        or transcript.usage_evidence is not derived_usage
    ):
        raise CopilotCandidateAdmissionError(
            "evidence_descriptor_mismatch",
            "candidate transcript evidence descriptors are inconsistent",
        )
    if (
        derived_identity is CandidateIdentityEvidence.NONE
        or derived_usage is CandidateUsageEvidenceLevel.NONE
    ):
        raise CopilotCandidateAdmissionError(
            "insufficient_candidate_evidence",
            "candidate completion lacks complete per-call evidence",
        )
    reported = transcript.reported_settings
    if reported is None or transcript.session_id is None:
        raise CopilotCandidateAdmissionError(
            "missing_session_start",
            "candidate completion lacks session.start evidence",
        )
    _require_reported_setting(
        "selected_model", reported.selected_model, requested.model
    )
    if requested.reasoning_effort is not None:
        _require_reported_setting(
            "reasoning_effort",
            reported.reasoning_effort,
            requested.reasoning_effort,
        )
    if requested.context_tier is not None:
        _require_reported_setting(
            "context_tier", reported.context_tier, requested.context_tier
        )

    for observation in transcript.model_observations:
        if observation.model != requested.model:
            raise CopilotCandidateAdmissionError(
                "reported_model_mismatch",
                f"{observation.event_type}.{observation.field} does not "
                "match the requested model",
            )
    for call in transcript.usage.calls:
        if (
            requested.reasoning_effort is not None
            and call.reasoning_effort is not None
            and call.reasoning_effort != requested.reasoning_effort
        ):
            raise CopilotCandidateAdmissionError(
                "runtime_reasoning_effort_mismatch",
                "assistant.usage reasoningEffort does not match the request",
            )

    if transcript.final_content is None:
        raise AssertionError("complete transcript lost final content")
    return CandidateCompletion(
        provenance=CANDIDATE_PROTOCOL_PROVENANCE,
        outcome=transcript.outcome,
        identity_evidence=transcript.identity_evidence,
        usage_evidence=transcript.usage_evidence,
        chunk_message_id_mode=transcript.chunk_message_id_mode,
        model_call_count=transcript.model_call_count,
        session_id=transcript.session_id,
        requested_settings=requested,
        reported_settings=reported,
        content=transcript.final_content,
        model_observations=transcript.model_observations,
        usage=transcript.usage,
        diagnostics=transcript.diagnostics,
        terminal=transcript.terminal,
    )


def _parse_event(value: object, line_number: int) -> _Event:
    envelope = _object(value, f"candidate line {line_number}")
    _keys(
        envelope,
        _ENVELOPE_REQUIRED,
        _ENVELOPE_FIELDS,
        f"candidate line {line_number}",
    )
    event_type = _string(envelope["type"], f"candidate line {line_number}.type")
    shape = _EVENT_SHAPES.get(event_type)
    if shape is None:
        raise CopilotCandidateUnsupportedEventError(
            f"candidate line {line_number} has unsupported event type "
            f"{event_type!r}; it cannot be classified safely"
        )

    ephemeral = envelope.get("ephemeral")
    if ephemeral is not None and type(ephemeral) is not bool:
        raise CopilotCandidateEventError(
            f"candidate line {line_number}.ephemeral must be a boolean"
        )
    if event_type in _EPHEMERAL_EVENTS and ephemeral is not True:
        raise CopilotCandidateEventError(f"{event_type}.ephemeral must be true")
    agent_id = envelope.get("agentId")
    if agent_id is not None:
        agent_id = _string(agent_id, f"candidate line {line_number}.agentId")

    data = _object(envelope["data"], f"candidate line {line_number}.data")
    _validate_shape(event_type, data, shape)
    _validate_nested(event_type, data)
    return _Event(
        line_number=line_number,
        event_id=_uuid4(envelope["id"], f"candidate line {line_number}.id"),
        timestamp=_timestamp(
            envelope["timestamp"], f"candidate line {line_number}.timestamp"
        ),
        parent_id=(
            None
            if envelope["parentId"] is None
            else _uuid4(
                envelope["parentId"],
                f"candidate line {line_number}.parentId",
            )
        ),
        ephemeral=ephemeral,
        agent_id=agent_id,
        event_type=event_type,
        data=data,
    )


def _consume_event(state: _ParserState, event: _Event) -> None:
    kind = event.event_type
    data = event.data
    if event.agent_id is not None:
        _issue(
            state,
            event,
            "subagent_event",
            "safety",
            "pure completion received a sub-agent event",
        )

    if kind == "session.start":
        if state.session_id is not None:
            raise CopilotCandidateReplayError(
                "candidate transcript contains multiple session.start events"
            )
        state.session_id = data["sessionId"]
        state.reported_settings = CandidateReportedSettings(
            selected_model=data.get("selectedModel"),
            reasoning_effort=data.get("reasoningEffort"),
            context_tier=data.get("contextTier"),
        )
        return
    if state.session_id is None:
        raise CopilotCandidateOrderError(f"{kind} occurred before session.start")

    if kind == "user.message":
        if state.user_message_event_id is not None:
            raise CopilotCandidateOrderError(
                "candidate pure completion contains multiple user messages"
            )
        if state.active_turn_id is not None:
            raise CopilotCandidateOrderError(
                "user.message occurred while an assistant turn was open"
            )
        state.user_message_event_id = event.event_id
        state.user_turn_id = data.get("turnId")
        if data.get("isAutopilotContinuation") is True:
            _issue(
                state,
                event,
                "autopilot_continuation",
                "safety",
                "pure completion received an autopilot continuation",
            )
        if data.get("parentAgentTaskId") is not None:
            _issue(
                state,
                event,
                "subagent_user_message",
                "safety",
                "pure completion user message belongs to a sub-agent task",
            )
        return

    if kind == "assistant.turn_start":
        turn_id = data["turnId"]
        if state.user_message_event_id is None:
            raise CopilotCandidateOrderError(
                "assistant.turn_start occurred before user.message"
            )
        if state.active_turn_id is not None:
            raise CopilotCandidateOrderError(
                "assistant.turn_start occurred while another turn was open"
            )
        if turn_id in state.completed_turn_ids:
            raise CopilotCandidateReplayError(
                f"assistant turn {turn_id!r} was replayed"
            )
        if state.user_turn_id is not None and state.user_turn_id != turn_id:
            raise CopilotCandidateOrderError(
                "assistant.turn_start does not match user.message turnId"
            )
        if state.turn_end_event_id is not None:
            _issue(
                state,
                event,
                "multiple_turns",
                "safety",
                "candidate pure completion contains more than one turn",
            )
        state.active_turn_id = turn_id
        state.message_parts.clear()
        state.message_mode = None
        state.chunk_count = None
        state.chunk_indexes.clear()
        state.chunk_message_ids.clear()
        _observe(state, event, "model", data.get("model"), "runtime")
        return

    if kind == "model.call_start":
        _active_turn(state, event, data["turnId"])
        if state.active_call_turn_id is not None:
            raise CopilotCandidateOrderError(
                "model.call_start occurred while another model call was open"
            )
        state.model_call_count += 1
        state.active_call_turn_id = data["turnId"]
        state.active_call_message_count = 0
        state.active_call_message_api_ids.clear()
        state.active_call_messages_without_api_id = 0
        state.active_call_usage_count = 0
        state.active_call_usage_api_ids.clear()
        state.active_call_usage_without_api_id = 0
        _observe(state, event, "model", data.get("model"), "runtime")
        return

    if kind == "assistant.message":
        _active_call(state, event, data.get("turnId"))
        message_id = data["messageId"]
        if message_id in state.message_ids:
            raise CopilotCandidateReplayError(
                f"assistant message {message_id!r} was replayed"
            )
        state.message_ids.add(message_id)
        api_call_id = data.get("apiCallId")
        state.active_call_message_count += 1
        if api_call_id is None:
            state.active_call_messages_without_api_id += 1
        else:
            if api_call_id in state.settled_api_call_ids:
                raise CopilotCandidateReplayError(
                    f"assistant.message replays apiCallId {api_call_id!r}"
                )
            state.active_call_message_api_ids.add(api_call_id)
        _consume_message(state, data, message_id)
        _observe(state, event, "model", data.get("model"), "runtime")
        if data.get("toolRequests"):
            _issue(
                state,
                event,
                "assistant_tool_request",
                "safety",
                "pure completion contained assistant tool requests",
            )
        if data.get("serverTools"):
            _issue(
                state,
                event,
                "assistant_server_tools",
                "safety",
                "pure completion reported server tools",
            )
        if data.get("parentToolCallId") is not None:
            _issue(
                state,
                event,
                "assistant_tool_parent",
                "safety",
                "assistant message is correlated to a tool call",
            )
        return

    if kind == "assistant.usage":
        _active_call(state, event, state.active_call_turn_id)
        usage = _call_usage(event, state.active_call_turn_id)
        if state.active_call_usage_count:
            if (
                usage.api_call_id is not None
                and usage.api_call_id in state.usage_api_call_ids
            ):
                raise CopilotCandidateReplayError(
                    f"assistant.usage replays apiCallId {usage.api_call_id!r}"
                )
            raise CopilotCandidateOrderError(
                "multiple assistant.usage events make API-call correlation ambiguous"
            )
        state.active_call_usage_count = 1
        if usage.api_call_id is not None:
            if usage.api_call_id in state.usage_api_call_ids:
                raise CopilotCandidateReplayError(
                    f"assistant.usage replays apiCallId {usage.api_call_id!r}"
                )
            if usage.api_call_id in state.settled_api_call_ids:
                raise CopilotCandidateReplayError(
                    f"assistant.usage replays settled apiCallId {usage.api_call_id!r}"
                )
            state.usage_api_call_ids.add(usage.api_call_id)
            state.active_call_usage_api_ids.add(usage.api_call_id)
        else:
            state.active_call_usage_without_api_id = 1
        state.call_usage.append(usage)
        _observe(state, event, "model", usage.model, "runtime")
        if usage.server_billing_model is not None:
            _observe(
                state,
                event,
                "copilotUsage.model",
                usage.server_billing_model,
                "server_billing",
            )
        for index, detail in enumerate(usage.server_token_details):
            if detail.model is not None:
                _observe(
                    state,
                    event,
                    f"copilotUsage.tokenDetails[{index}].model",
                    detail.model,
                    "server_billing",
                )
        if usage.is_auto is True:
            _issue(
                state,
                event,
                "assistant_usage_auto",
                "substitution",
                "assistant.usage reported isAuto=true",
            )
        return

    if kind == "model.call_finished":
        _active_turn(state, event, data["turnId"])
        if state.active_call_turn_id != data["turnId"]:
            raise CopilotCandidateOrderError(
                "model.call_finished has no matching model.call_start"
            )
        _settle_api_call_identity(state)
        state.active_call_turn_id = None
        state.active_call_message_count = 0
        state.active_call_message_api_ids.clear()
        state.active_call_messages_without_api_id = 0
        state.active_call_usage_count = 0
        state.active_call_usage_api_ids.clear()
        state.active_call_usage_without_api_id = 0
        outcome = data["outcome"]
        if outcome == "cancelled":
            _issue(
                state,
                event,
                "model_call_cancelled",
                "cancelled",
                "model call was cancelled",
            )
        elif outcome in {"error", "rejected"}:
            _issue(
                state,
                event,
                f"model_call_{outcome}",
                "error",
                f"model call ended with outcome {outcome}",
            )
        return

    if kind == "model.call_failure":
        _observe(state, event, "model", data.get("model"), "runtime")
        if data.get("isAuto") is True:
            _issue(
                state,
                event,
                "model_call_failure_auto",
                "substitution",
                "model.call_failure reported isAuto=true",
            )
        _issue(
            state,
            event,
            "model_call_failure",
            "error",
            data.get("errorMessage") or "model call failed",
        )
        return

    if kind == "assistant.turn_end":
        turn_id = data["turnId"]
        _active_turn(state, event, turn_id)
        if state.active_call_turn_id is not None:
            raise CopilotCandidateOrderError(
                "assistant.turn_end occurred while a model call was open"
            )
        _finish_message(state)
        state.completed_turn_ids.add(turn_id)
        state.active_turn_id = None
        state.turn_end_event_id = event.event_id
        _observe(state, event, "model", data.get("model"), "runtime")
        return

    if kind == "session.completion_receipt":
        if state.receipt_event_id is not None:
            raise CopilotCandidateReplayError(
                "candidate transcript contains multiple completion receipts"
            )
        if state.user_message_event_id is None or state.turn_end_event_id is None:
            raise CopilotCandidateOrderError(
                "completion receipt occurred before the candidate turn ended"
            )
        event_range = data["eventRange"]
        if (
            data["sourceEventId"] != state.turn_end_event_id
            or event_range["endEventId"] != state.turn_end_event_id
            or event_range["startEventId"] != state.user_message_event_id
        ):
            raise CopilotCandidateOrderError(
                "completion receipt does not correlate to the candidate turn"
            )
        state.receipt_event_id = event.event_id
        state.receipt_stop_reason = data["stopReason"]
        if data["stopReason"] != "natural":
            _issue(
                state,
                event,
                "non_natural_completion",
                "safety",
                "pure completion requires stopReason='natural'",
            )
        if (
            data["successfulToolCount"] != 0
            or data["failedToolCount"] != 0
            or data.get("finalTool") is not None
        ):
            _issue(
                state,
                event,
                "completion_receipt_tools",
                "safety",
                "pure completion receipt reports tool execution",
            )
        return

    if kind == "session.idle":
        if state.idle_event_id is not None:
            raise CopilotCandidateReplayError(
                "candidate transcript contains multiple session.idle events"
            )
        if state.receipt_event_id is None:
            raise CopilotCandidateOrderError(
                "session.idle occurred before completion receipt"
            )
        state.idle_event_id = event.event_id
        if data.get("aborted") is True:
            _issue(
                state,
                event,
                "idle_aborted",
                "cancelled",
                "session became idle after an abort",
            )
        return

    if kind == "session.shutdown":
        if state.shutdown_event_id is not None:
            raise CopilotCandidateReplayError(
                "candidate transcript contains multiple shutdown events"
            )
        if state.idle_event_id is None:
            raise CopilotCandidateOrderError(
                "session.shutdown occurred before session.idle"
            )
        state.shutdown_event_id = event.event_id
        state.seen_shutdown = True
        state.shutdown_usage = _shutdown_usage(data)
        _observe(state, event, "currentModel", data.get("currentModel"), "aggregate")
        for metric in state.shutdown_usage.model_metrics:
            _observe(
                state,
                event,
                f"modelMetrics[{metric.model}]",
                metric.model,
                "aggregate",
            )
        changes = data["codeChanges"]
        if (
            changes["linesAdded"] != 0
            or changes["linesRemoved"] != 0
            or changes["filesModified"]
        ):
            _issue(
                state,
                event,
                "shutdown_code_changes",
                "safety",
                "pure completion reported code changes",
            )
        if data.get("agentMetrics"):
            _issue(
                state,
                event,
                "shutdown_agent_metrics",
                "safety",
                "pure completion reported sub-agent metrics",
            )
        if data["shutdownType"] == "error":
            _issue(
                state,
                event,
                "shutdown_error",
                "error",
                data.get("errorReason") or "session shutdown reported error",
            )
        return

    if kind == "session.error":
        _issue(state, event, "session_error", "error", data["message"])
        return
    if kind == "abort":
        _issue(
            state,
            event,
            "abort",
            "cancelled",
            f"session abort: {data['reason']}",
        )
        return
    if kind == "agent.interrupted":
        _observe(state, event, "model", data.get("model"), "runtime")
        _issue(
            state,
            event,
            "agent_interrupted",
            "cancelled",
            f"agent interrupted during {data['activity']}",
        )
        return

    if kind in {
        "session.model_change",
        "session.auto_mode_resolved",
        "auto_mode_switch.requested",
        "auto_mode_switch.completed",
    }:
        if kind == "auto_mode_switch.requested":
            request_id = data["requestId"]
            if request_id in state.auto_switch_request_ids:
                raise CopilotCandidateReplayError(
                    f"auto-mode request {request_id!r} was replayed"
                )
            state.auto_switch_request_ids.add(request_id)
        elif kind == "auto_mode_switch.completed":
            if data["requestId"] not in state.auto_switch_request_ids:
                raise CopilotCandidateOrderError(
                    "auto_mode_switch.completed has no matching request"
                )
        _issue(
            state,
            event,
            "model_substitution_signal",
            "substitution",
            f"pure completion received {kind}",
        )
        return

    if kind == "tool.execution_start":
        tool_call_id = data["toolCallId"]
        if tool_call_id in state.tool_call_ids:
            raise CopilotCandidateReplayError(
                f"tool call {tool_call_id!r} was replayed"
            )
        state.tool_call_ids.add(tool_call_id)
        _observe(state, event, "model", data.get("model"), "runtime")
        _issue(
            state,
            event,
            "tool_execution_attempt",
            "safety",
            "pure completion attempted tool execution",
        )
        return
    if kind == "tool.execution_complete":
        tool_call_id = data["toolCallId"]
        if tool_call_id not in state.tool_call_ids:
            raise CopilotCandidateOrderError(
                "tool.execution_complete has no matching start"
            )
        if tool_call_id in state.completed_tool_call_ids:
            raise CopilotCandidateReplayError(
                f"tool completion {tool_call_id!r} was replayed"
            )
        state.completed_tool_call_ids.add(tool_call_id)
        _observe(state, event, "model", data.get("model"), "runtime")
        _issue(
            state,
            event,
            "tool_execution",
            "safety",
            "pure completion contains tool execution",
        )
        return

    if kind == "permission.requested":
        request_id = data["requestId"]
        if request_id in state.permission_request_ids:
            raise CopilotCandidateReplayError(
                f"permission request {request_id!r} was replayed"
            )
        state.permission_request_ids.add(request_id)
        _issue(
            state,
            event,
            "permission_attempt",
            "safety",
            "pure completion requested permission",
        )
        return
    if kind == "permission.completed":
        request_id = data["requestId"]
        if request_id not in state.permission_request_ids:
            raise CopilotCandidateOrderError(
                "permission.completed has no matching request"
            )
        if request_id in state.completed_permission_request_ids:
            raise CopilotCandidateReplayError(
                f"permission completion {request_id!r} was replayed"
            )
        state.completed_permission_request_ids.add(request_id)
        _issue(
            state,
            event,
            "permission_result",
            "safety",
            "pure completion contains a permission result",
        )
        return

    if kind == "session.task_complete":
        _issue(
            state,
            event,
            "task_complete_event",
            "safety",
            "session.task_complete is outside the pure completion contract",
        )
        return
    if kind in {"session.warning", "session.info"}:
        state.diagnostics.append(
            CandidateDiagnostic(
                event_id=event.event_id,
                event_type=kind,
                level="warning" if kind == "session.warning" else "info",
                message=_safe(data["message"]),
            )
        )
        return
    if kind == "session.truncation":
        state.diagnostics.append(
            CandidateDiagnostic(
                event_id=event.event_id,
                event_type=kind,
                level="warning",
                message=(
                    "context truncated: "
                    f"{data['tokensRemovedDuringTruncation']} tokens and "
                    f"{data['messagesRemovedDuringTruncation']} messages "
                    "removed"
                ),
            )
        )
        return
    if kind == "session.usage_info":
        state.diagnostics.append(
            CandidateDiagnostic(
                event_id=event.event_id,
                event_type=kind,
                level="info",
                message=(
                    f"context usage: {data['currentTokens']} of "
                    f"{data['tokenLimit']} tokens"
                ),
            )
        )
        return
    raise AssertionError(f"unhandled validated event type: {kind}")


def _finish_transcript(state: _ParserState, event_count: int) -> CandidateTranscript:
    if state.active_call_turn_id is not None:
        _incomplete(state, "open_model_call", "model call did not finish")
    if state.active_turn_id is not None:
        _incomplete(state, "open_turn", "assistant turn did not finish")
    if state.user_message_event_id is None:
        _incomplete(state, "missing_user_message", "user.message is missing")
    if state.turn_end_event_id is None:
        _incomplete(state, "missing_turn_end", "assistant.turn_end is missing")
    if state.final_content is None or not state.final_content.strip():
        _incomplete(
            state, "missing_final_content", "final assistant content is missing"
        )
    if state.receipt_event_id is None:
        _incomplete(
            state,
            "missing_completion_receipt",
            "session.completion_receipt is missing",
        )
    if state.idle_event_id is None:
        _incomplete(state, "missing_idle", "session.idle is missing")
    if state.shutdown_event_id is None:
        _incomplete(state, "missing_shutdown", "session.shutdown is missing")
    if state.session_id is None or state.reported_settings is None:
        _incomplete(state, "missing_session_start", "session.start is missing")

    calls = tuple(state.call_usage)
    usage = CandidateUsageEvidence(
        calls=calls,
        per_call_totals=_usage_totals(calls),
        shutdown_aggregate=state.shutdown_usage,
    )
    identity_evidence, usage_evidence = _evidence_levels(
        state.model_call_count,
        calls,
        state.shutdown_usage,
    )
    categories = {issue.category for issue in state.issues}
    if categories & {"safety", "substitution"}:
        outcome = CandidateTranscriptOutcome.REJECTED
    elif "error" in categories:
        outcome = CandidateTranscriptOutcome.ERROR
    elif "cancelled" in categories:
        outcome = CandidateTranscriptOutcome.CANCELLED
    elif "incomplete" in categories:
        outcome = CandidateTranscriptOutcome.INCOMPLETE
    elif (
        identity_evidence is CandidateIdentityEvidence.NONE
        or usage_evidence is CandidateUsageEvidenceLevel.NONE
    ):
        outcome = CandidateTranscriptOutcome.CANDIDATE_COMPLETE_UNEVIDENCED
    else:
        outcome = CandidateTranscriptOutcome.CANDIDATE_COMPLETE

    return CandidateTranscript(
        provenance=CANDIDATE_PROTOCOL_PROVENANCE,
        outcome=outcome,
        identity_evidence=identity_evidence,
        usage_evidence=usage_evidence,
        chunk_message_id_mode=_chunk_message_id_mode(state),
        event_count=event_count,
        model_call_count=state.model_call_count,
        session_id=state.session_id,
        reported_settings=state.reported_settings,
        final_content=state.final_content,
        model_observations=tuple(state.model_observations),
        usage=usage,
        diagnostics=tuple(state.diagnostics),
        issues=tuple(state.issues),
        terminal=CandidateTerminalEvidence(
            user_message_event_id=state.user_message_event_id,
            turn_end_event_id=state.turn_end_event_id,
            completion_receipt_event_id=state.receipt_event_id,
            completion_stop_reason=state.receipt_stop_reason,
            idle_event_id=state.idle_event_id,
            shutdown_event_id=state.shutdown_event_id,
        ),
    )


def _validate_shape(kind: str, data: dict[str, Any], shape: _Shape) -> None:
    _keys(data, shape.required, shape.allowed, f"{kind}.data")
    for name in shape.strings:
        if name in data:
            _string(
                data[name],
                f"{kind}.data.{name}",
                allow_empty=name in shape.empty_strings,
            )
    for name in shape.nullable_strings:
        if name in data and data[name] is not None:
            _string(data[name], f"{kind}.data.{name}")
    for name, int_minimum in shape.integers:
        if name in data:
            _integer(data[name], f"{kind}.data.{name}", int_minimum)
    for name, number_minimum in shape.numbers:
        if name in data:
            _number(data[name], f"{kind}.data.{name}", number_minimum)
    for name in shape.booleans:
        if name in data and type(data[name]) is not bool:
            raise CopilotCandidateEventError(f"{kind}.data.{name} must be a boolean")
    for name in shape.objects:
        if name in data:
            _object(data[name], f"{kind}.data.{name}")
    for name in shape.arrays:
        if name in data:
            _array(data[name], f"{kind}.data.{name}")
    for name, choices in shape.enums:
        if name in data:
            _enum(data[name], choices, f"{kind}.data.{name}")


def _validate_nested(kind: str, data: dict[str, Any]) -> None:
    if kind == "session.start":
        if data["version"] != CANDIDATE_CONTRACT_VERSION:
            raise CopilotCandidateVersionError(
                f"unsupported session event version {data['version']}; "
                f"expected {CANDIDATE_CONTRACT_VERSION}"
            )
        if data["copilotVersion"] != CANDIDATE_SOURCE_CLI_VERSION:
            raise CopilotCandidateVersionError(
                "session.start copilotVersion does not match the pinned "
                f"candidate version {CANDIDATE_SOURCE_CLI_VERSION}"
            )
        _timestamp(data["startTime"], "session.start.data.startTime")
    elif kind == "assistant.usage":
        if "copilotUsage" in data:
            _validate_copilot_usage(data["copilotUsage"])
    elif kind == "session.completion_receipt":
        event_range = _object(
            data["eventRange"],
            "session.completion_receipt.data.eventRange",
        )
        _keys(
            event_range,
            frozenset({"startEventId", "endEventId"}),
            frozenset({"startEventId", "endEventId"}),
            "session.completion_receipt.data.eventRange",
        )
        _string(
            event_range["startEventId"],
            "session.completion_receipt.data.eventRange.startEventId",
        )
        _string(
            event_range["endEventId"],
            "session.completion_receipt.data.eventRange.endEventId",
        )
    elif kind == "session.shutdown":
        _validate_shutdown(data)
    elif kind == "agent.interrupted":
        for name in ("toolNames", "toolCallIds"):
            for index, value in enumerate(data.get(name, [])):
                _string(value, f"agent.interrupted.data.{name}[{index}]")
    elif kind == "session.auto_mode_resolved":
        for name in ("candidateModels", "availableModels"):
            for index, value in enumerate(data.get(name, [])):
                _string(
                    value,
                    f"session.auto_mode_resolved.data.{name}[{index}]",
                )
    elif kind == "permission.requested":
        request = data["permissionRequest"]
        _string(
            request.get("kind"),
            "permission.requested.data.permissionRequest.kind",
        )
    elif kind == "permission.completed":
        result = data["result"]
        _string(result.get("kind"), "permission.completed.data.result.kind")


def _validate_copilot_usage(data: dict[str, Any]) -> None:
    label = "assistant.usage.data.copilotUsage"
    _keys(
        data,
        frozenset({"totalNanoAiu"}),
        frozenset({"model", "tokenDetails", "totalNanoAiu"}),
        label,
    )
    if "model" in data:
        _string(data["model"], f"{label}.model")
    _number(data["totalNanoAiu"], f"{label}.totalNanoAiu", Decimal(0))
    details = data.get("tokenDetails", [])
    _array(details, f"{label}.tokenDetails")
    required = frozenset({"batchSize", "costPerBatch", "tokenCount", "tokenType"})
    allowed = required | frozenset({"model"})
    for index, value in enumerate(details):
        detail_label = f"{label}.tokenDetails[{index}]"
        detail = _object(value, detail_label)
        _keys(detail, required, allowed, detail_label)
        _string(detail["tokenType"], f"{detail_label}.tokenType")
        if "model" in detail:
            _string(detail["model"], f"{detail_label}.model")
        for name in ("batchSize", "costPerBatch", "tokenCount"):
            _integer(detail[name], f"{detail_label}.{name}", 0)


def _validate_shutdown(data: dict[str, Any]) -> None:
    changes = data["codeChanges"]
    _keys(
        changes,
        frozenset({"linesAdded", "linesRemoved", "filesModified"}),
        frozenset({"linesAdded", "linesRemoved", "filesModified"}),
        "session.shutdown.data.codeChanges",
    )
    _integer(
        changes["linesAdded"],
        "session.shutdown.data.codeChanges.linesAdded",
        0,
    )
    _integer(
        changes["linesRemoved"],
        "session.shutdown.data.codeChanges.linesRemoved",
        0,
    )
    files = _array(
        changes["filesModified"],
        "session.shutdown.data.codeChanges.filesModified",
    )
    for index, value in enumerate(files):
        _string(
            value,
            f"session.shutdown.data.codeChanges.filesModified[{index}]",
        )

    for model, value in data["modelMetrics"].items():
        _string(model, "session.shutdown.data.modelMetrics key")
        _validate_shutdown_metric(model, value)


def _validate_shutdown_metric(model: str, value: object) -> None:
    label = f"session.shutdown.data.modelMetrics[{model!r}]"
    metric = _object(value, label)
    _keys(
        metric,
        frozenset({"requests", "usage"}),
        frozenset({"requests", "usage", "tokenDetails", "totalNanoAiu"}),
        label,
    )
    requests = _object(metric["requests"], f"{label}.requests")
    _keys(
        requests,
        frozenset(),
        frozenset({"count", "cost"}),
        f"{label}.requests",
    )
    if "count" in requests:
        _integer(requests["count"], f"{label}.requests.count", 0)
    if "cost" in requests:
        _number(requests["cost"], f"{label}.requests.cost", None)

    usage = _object(metric["usage"], f"{label}.usage")
    required = frozenset(
        {
            "inputTokens",
            "outputTokens",
            "cacheReadTokens",
            "cacheWriteTokens",
        }
    )
    _keys(usage, required, required | frozenset({"reasoningTokens"}), f"{label}.usage")
    for name in required | frozenset({"reasoningTokens"}):
        if name in usage:
            _integer(usage[name], f"{label}.usage.{name}", 0)
    if "totalNanoAiu" in metric:
        _number(metric["totalNanoAiu"], f"{label}.totalNanoAiu", Decimal(0))
    if "tokenDetails" in metric:
        _validate_token_map(metric["tokenDetails"], f"{label}.tokenDetails")


def _validate_token_map(value: object, label: str) -> None:
    details = _object(value, label)
    for token_type, raw_detail in details.items():
        _string(token_type, f"{label} key")
        detail = _object(raw_detail, f"{label}[{token_type!r}]")
        _keys(
            detail,
            frozenset({"tokenCount"}),
            frozenset({"tokenCount"}),
            f"{label}[{token_type!r}]",
        )
        _integer(
            detail["tokenCount"],
            f"{label}[{token_type!r}].tokenCount",
            0,
        )


def _consume_message(
    state: _ParserState,
    data: dict[str, Any],
    message_id: str,
) -> None:
    index = data.get("chunkIndex")
    count = data.get("chunkCount")
    if (index is None) != (count is None):
        raise CopilotCandidateEventError(
            "assistant.message chunkIndex and chunkCount must appear together"
        )
    if index is None:
        if state.message_mode is not None:
            raise CopilotCandidateReplayError(
                "multiple unchunked assistant.message events are ambiguous"
            )
        state.message_mode = "single"
    else:
        if state.message_mode == "single":
            raise CopilotCandidateOrderError(
                "chunked assistant.message followed an unchunked message"
            )
        if state.chunk_count is None:
            state.chunk_count = count
            state.message_mode = "chunked"
        elif state.chunk_count != count:
            raise CopilotCandidateEventError(
                "assistant.message chunkCount changed within the turn"
            )
        if index in state.chunk_indexes:
            raise CopilotCandidateReplayError(
                f"assistant.message chunkIndex {index} was replayed"
            )
        if index != len(state.chunk_indexes):
            raise CopilotCandidateOrderError(
                "assistant.message chunks are out of order"
            )
        if index >= count:
            raise CopilotCandidateEventError(
                "assistant.message chunkIndex must be less than chunkCount"
            )
        state.chunk_indexes.add(index)
        state.chunk_message_ids.append(message_id)
    state.message_parts.append(data["content"])


def _finish_message(state: _ParserState) -> None:
    if state.message_mode == "chunked":
        if state.chunk_count is None or len(state.chunk_indexes) != state.chunk_count:
            raise CopilotCandidateOrderError(
                "assistant.turn_end occurred before all message chunks arrived"
            )
    state.final_content = "".join(state.message_parts) if state.message_parts else None


def _active_turn(
    state: _ParserState, event: _Event, reported_turn_id: str | None
) -> None:
    if state.active_turn_id is None:
        raise CopilotCandidateOrderError(
            f"{event.event_type} occurred outside an assistant turn"
        )
    if reported_turn_id is not None and reported_turn_id != state.active_turn_id:
        raise CopilotCandidateOrderError(
            f"{event.event_type} turnId does not match the active turn"
        )


def _active_call(
    state: _ParserState, event: _Event, reported_turn_id: str | None
) -> None:
    _active_turn(state, event, reported_turn_id)
    if state.active_call_turn_id is None:
        raise CopilotCandidateOrderError(
            f"{event.event_type} occurred without an open model call"
        )


def _settle_api_call_identity(state: _ParserState) -> None:
    """Resolve optional message/usage API IDs before closing a model call."""
    message_id = _one_optional_api_call_id(
        state.active_call_message_api_ids,
        state.active_call_messages_without_api_id,
        state.active_call_message_count,
        "assistant.message",
    )
    usage_id = _one_optional_api_call_id(
        state.active_call_usage_api_ids,
        state.active_call_usage_without_api_id,
        state.active_call_usage_count,
        "assistant.usage",
    )

    if state.active_call_usage_count == 0:
        if message_id is not None:
            state.settled_api_call_ids.add(message_id)
        return
    if state.active_call_message_count == 0:
        raise CopilotCandidateOrderError(
            "assistant.usage has no assistant.message to correlate"
        )
    if (message_id is None) != (usage_id is None):
        raise CopilotCandidateOrderError(
            "assistant.message and assistant.usage apiCallId metadata is one-sided"
        )
    if message_id is not None and message_id != usage_id:
        raise CopilotCandidateOrderError(
            "assistant.usage apiCallId does not match assistant.message"
        )
    if message_id is not None:
        state.settled_api_call_ids.add(message_id)


def _one_optional_api_call_id(
    values: set[str],
    missing_count: int,
    event_count: int,
    label: str,
) -> str | None:
    if len(values) > 1:
        raise CopilotCandidateOrderError(
            f"{label} events report conflicting apiCallId values"
        )
    if values and missing_count:
        raise CopilotCandidateOrderError(
            f"{label} events mix present and absent apiCallId values"
        )
    if event_count == 0 or not values:
        return None
    return next(iter(values))


def _call_usage(event: _Event, turn_id: str | None) -> CandidateCallUsage:
    if turn_id is None:
        raise AssertionError("assistant.usage has no active call turn")
    data = event.data
    copilot_usage = data.get("copilotUsage")
    billing_model: str | None = None
    billing_total: Decimal | None = None
    details: tuple[CandidateBillingTokenDetail, ...] = ()
    if copilot_usage is not None:
        billing_model = copilot_usage.get("model")
        billing_total = _decimal(copilot_usage["totalNanoAiu"])
        details = tuple(
            CandidateBillingTokenDetail(
                token_type=item["tokenType"],
                token_count=item["tokenCount"],
                batch_size=item["batchSize"],
                cost_per_batch=item["costPerBatch"],
                model=item.get("model"),
            )
            for item in copilot_usage.get("tokenDetails", [])
        )
    return CandidateCallUsage(
        event_id=event.event_id,
        turn_id=turn_id,
        model=data["model"],
        is_auto=data.get("isAuto"),
        reasoning_effort=data.get("reasoningEffort"),
        api_call_id=data.get("apiCallId"),
        provider_call_id=data.get("providerCallId"),
        service_request_id=data.get("serviceRequestId"),
        transport=data.get("transport"),
        api_endpoint=data.get("apiEndpoint"),
        finish_reason=data.get("finishReason"),
        input_tokens=data.get("inputTokens"),
        output_tokens=data.get("outputTokens"),
        cache_read_tokens=data.get("cacheReadTokens"),
        cache_write_tokens=data.get("cacheWriteTokens"),
        reasoning_tokens=data.get("reasoningTokens"),
        reported_cost=_decimal(data["cost"]) if "cost" in data else None,
        server_billing_model=billing_model,
        server_total_nano_aiu=billing_total,
        server_token_details=details,
    )


def _shutdown_usage(data: dict[str, Any]) -> CandidateShutdownUsage:
    metrics: list[CandidateShutdownModelUsage] = []
    for model, value in sorted(data["modelMetrics"].items()):
        requests = value["requests"]
        usage = value["usage"]
        metrics.append(
            CandidateShutdownModelUsage(
                model=model,
                request_count=requests.get("count"),
                reported_request_cost=(
                    _decimal(requests["cost"]) if "cost" in requests else None
                ),
                input_tokens=usage["inputTokens"],
                output_tokens=usage["outputTokens"],
                cache_read_tokens=usage["cacheReadTokens"],
                cache_write_tokens=usage["cacheWriteTokens"],
                reasoning_tokens=usage.get("reasoningTokens"),
                total_nano_aiu=(
                    _decimal(value["totalNanoAiu"]) if "totalNanoAiu" in value else None
                ),
            )
        )
    return CandidateShutdownUsage(
        current_model=data.get("currentModel"),
        total_premium_requests=(
            _decimal(data["totalPremiumRequests"])
            if "totalPremiumRequests" in data
            else None
        ),
        total_nano_aiu=(
            _decimal(data["totalNanoAiu"]) if "totalNanoAiu" in data else None
        ),
        model_metrics=tuple(metrics),
    )


def _evidence_levels(
    model_call_count: int,
    calls: tuple[CandidateCallUsage, ...],
    shutdown: CandidateShutdownUsage | None,
) -> tuple[CandidateIdentityEvidence, CandidateUsageEvidenceLevel]:
    """Classify complete channel coverage without inferring correctness."""
    per_call_complete = model_call_count > 0 and len(calls) == model_call_count
    if not per_call_complete:
        return (
            CandidateIdentityEvidence.NONE,
            CandidateUsageEvidenceLevel.NONE,
        )

    identity = CandidateIdentityEvidence.RUNTIME
    if all(_call_has_billing_identity(call) for call in calls):
        identity = CandidateIdentityEvidence.RUNTIME_AND_BILLING

    usage = CandidateUsageEvidenceLevel.PER_CALL
    if _shutdown_covers_call_models(shutdown, calls):
        usage = CandidateUsageEvidenceLevel.PER_CALL_AND_SHUTDOWN
    return identity, usage


def _call_has_billing_identity(call: CandidateCallUsage) -> bool:
    if call.server_billing_model is not None:
        return True
    return bool(call.server_token_details) and all(
        detail.model is not None for detail in call.server_token_details
    )


def _shutdown_covers_call_models(
    shutdown: CandidateShutdownUsage | None,
    calls: tuple[CandidateCallUsage, ...],
) -> bool:
    if shutdown is None or not calls:
        return False
    aggregate_models = {metric.model for metric in shutdown.model_metrics}
    return {call.model for call in calls} <= aggregate_models


def _chunk_message_id_mode(
    state: _ParserState,
) -> CandidateChunkMessageIdMode:
    if state.message_mode != "chunked":
        return CandidateChunkMessageIdMode.NOT_APPLICABLE
    unique_ids = set(state.chunk_message_ids)
    if len(unique_ids) <= 1:
        return CandidateChunkMessageIdMode.SINGLE
    if len(unique_ids) == len(state.chunk_message_ids):
        return CandidateChunkMessageIdMode.DISTINCT
    return CandidateChunkMessageIdMode.MIXED


def _usage_totals(
    calls: tuple[CandidateCallUsage, ...],
) -> CandidateUsageTotals | None:
    if not calls:
        return None
    return CandidateUsageTotals(
        call_count=len(calls),
        input_tokens=_sum_complete(calls, "input_tokens"),
        output_tokens=_sum_complete(calls, "output_tokens"),
        cache_read_tokens=_sum_complete(calls, "cache_read_tokens"),
        cache_write_tokens=_sum_complete(calls, "cache_write_tokens"),
        reasoning_tokens=_sum_complete(calls, "reasoning_tokens"),
        reported_cost=_sum_decimal(calls, "reported_cost"),
        server_total_nano_aiu=_sum_decimal(calls, "server_total_nano_aiu"),
    )


def _sum_complete(calls: tuple[CandidateCallUsage, ...], name: str) -> int | None:
    values = [getattr(call, name) for call in calls]
    if any(value is None for value in values):
        return None
    return sum(value for value in values if isinstance(value, int))


def _sum_decimal(calls: tuple[CandidateCallUsage, ...], name: str) -> Decimal | None:
    values = [getattr(call, name) for call in calls]
    if any(value is None for value in values):
        return None
    return sum(
        (value for value in values if isinstance(value, Decimal)),
        Decimal(0),
    )


def _observe(
    state: _ParserState,
    event: _Event,
    field_name: str,
    model: object,
    source: str,
) -> None:
    if model is None:
        return
    if not isinstance(model, str):
        raise AssertionError("model field escaped shape validation")
    state.model_observations.append(
        CandidateModelObservation(
            event_id=event.event_id,
            event_type=event.event_type,
            field=field_name,
            model=model,
            source=source,
        )
    )


def _issue(
    state: _ParserState,
    event: _Event,
    code: str,
    category: str,
    message: object,
) -> None:
    state.issues.append(
        CandidateIssue(
            code=code,
            category=category,
            event_id=event.event_id,
            event_type=event.event_type,
            message=_safe(message),
        )
    )


def _incomplete(state: _ParserState, code: str, message: str) -> None:
    if any(issue.code == code for issue in state.issues):
        return
    state.issues.append(
        CandidateIssue(
            code=code,
            category="incomplete",
            event_id=None,
            event_type=None,
            message=message,
        )
    )


def _safe(value: object) -> str:
    return sanitise_string(redact_secrets(value), max_chars=512)


def _public_error_message(value: object) -> str:
    message = sanitise_for_terminal(
        redact_secrets(value),
        max_len=_MAX_PUBLIC_ERROR_CHARS,
    )
    if len(message) > _MAX_PUBLIC_ERROR_CHARS:
        return message[: _MAX_PUBLIC_ERROR_CHARS - 3] + "..."
    return message


def _require_reported_setting(name: str, observed: str | None, expected: str) -> None:
    if observed is None:
        raise CopilotCandidateAdmissionError(
            f"missing_{name}", f"session.start did not report {name}"
        )
    if observed != expected:
        raise CopilotCandidateAdmissionError(
            f"{name}_mismatch",
            f"session.start {name} does not match the request",
        )


def _validate_setting(value: object, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CopilotCandidateEventError(f"{label} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise CopilotCandidateEventError(f"{label} keys must be strings")
    return value


def _array(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise CopilotCandidateEventError(f"{label} must be an array")
    return value


def _keys(
    value: dict[str, Any],
    required: frozenset[str],
    allowed: frozenset[str],
    label: str,
) -> None:
    missing = sorted(required - value.keys())
    if missing:
        raise CopilotCandidateEventError(
            f"{label} is missing required field(s): {', '.join(missing)}"
        )
    unknown = sorted(value.keys() - allowed)
    if unknown:
        raise CopilotCandidateEventError(
            f"{label} has unknown field(s): {', '.join(unknown)}"
        )


def _string(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise CopilotCandidateEventError(f"{label} must be a string")
    if not allow_empty and not value:
        raise CopilotCandidateEventError(f"{label} must not be empty")
    return value


def _integer(value: object, label: str, minimum: int) -> int:
    if type(value) is not int:
        raise CopilotCandidateEventError(f"{label} must be an integer")
    if value < minimum:
        raise CopilotCandidateEventError(f"{label} must be at least {minimum}")
    return value


def _number(
    value: object,
    label: str,
    minimum: Decimal | None,
) -> Decimal:
    if type(value) not in (int, float):
        raise CopilotCandidateEventError(f"{label} must be a number")
    if isinstance(value, float) and not math.isfinite(value):
        raise CopilotCandidateEventError(f"{label} must be finite")
    number = _decimal(value)
    if minimum is not None and number < minimum:
        raise CopilotCandidateEventError(f"{label} must be at least {minimum}")
    return number


def _decimal(value: object) -> Decimal:
    if type(value) not in (int, float):
        raise CopilotCandidateEventError("validated number changed type")
    return Decimal(str(value))


def _enum(value: object, choices: frozenset[str], label: str) -> str:
    text = _string(value, label)
    if text not in choices:
        raise CopilotCandidateEventError(
            f"{label} must be one of: {', '.join(sorted(choices))}"
        )
    return text


def _uuid4(value: object, label: str) -> str:
    text = _string(value, label)
    parsed: UUID | None = None
    try:
        parsed = UUID(text)
    except (ValueError, AttributeError):
        pass
    if parsed is None:
        raise CopilotCandidateEventError(f"{label} must be a UUID")
    if parsed.version != 4 or str(parsed) != text:
        raise CopilotCandidateEventError(f"{label} must be a canonical UUID v4")
    return text


def _timestamp(value: object, label: str) -> datetime:
    text = _string(value, label)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        pass
    if parsed is None:
        raise CopilotCandidateEventError(f"{label} must be an ISO 8601 date-time")
    try:
        offset = parsed.utcoffset()
    except (OverflowError, ValueError):
        offset = None
    if parsed.tzinfo is None or offset is None:
        raise CopilotCandidateEventError(f"{label} must include a valid UTC offset")
    normalized_utc: datetime | None = None
    try:
        normalized_utc = parsed.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        pass
    if normalized_utc is None:
        raise CopilotCandidateEventError(
            f"{label} must be an ISO 8601 date-time representable in UTC"
        )
    return normalized_utc


__all__ = [
    "CANDIDATE_CONTRACT_NAME",
    "CANDIDATE_CONTRACT_VERSION",
    "CANDIDATE_EVIDENCE_LEVEL",
    "CANDIDATE_PROTOCOL_PROVENANCE",
    "CANDIDATE_SOURCE_CLI_VERSION",
    "CANDIDATE_SOURCE_SCHEMA_SHA256",
    "CandidateBillingTokenDetail",
    "CandidateCallUsage",
    "CandidateChunkMessageIdMode",
    "CandidateCompletion",
    "CandidateDiagnostic",
    "CandidateIdentityEvidence",
    "CandidateIssue",
    "CandidateModelObservation",
    "CandidateProtocolProvenance",
    "CandidateReportedSettings",
    "CandidateRequestedSettings",
    "CandidateShutdownModelUsage",
    "CandidateShutdownUsage",
    "CandidateStreamLimits",
    "CandidateTerminalEvidence",
    "CandidateTranscript",
    "CandidateTranscriptOutcome",
    "CandidateUsageEvidence",
    "CandidateUsageEvidenceLevel",
    "CandidateUsageTotals",
    "CopilotCandidateAdmissionError",
    "CopilotCandidateEncodingError",
    "CopilotCandidateEventError",
    "CopilotCandidateJSONError",
    "CopilotCandidateOrderError",
    "CopilotCandidateProtocolError",
    "CopilotCandidateReplayError",
    "CopilotCandidateStreamLimitError",
    "CopilotCandidateTruncatedStreamError",
    "CopilotCandidateUnsupportedEventError",
    "CopilotCandidateVersionError",
    "admit_candidate_completion",
    "parse_candidate_transcript",
]
