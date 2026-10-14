"""Focused tests for the schema-derived Copilot candidate contract.

The fixture corpus is synthetic.  Only the one real-process test executes a
program, and that program is the repository's fixture-owned generic fake CLI.
No test resolves or invokes an operator Copilot installation.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import traceback
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
from pathlib import Path

import pytest

from core.llm.copilot_protocol import (
    CANDIDATE_CONTRACT_NAME,
    CANDIDATE_CONTRACT_VERSION,
    CANDIDATE_EVIDENCE_LEVEL,
    CANDIDATE_PROTOCOL_PROVENANCE,
    CANDIDATE_SOURCE_CLI_VERSION,
    CANDIDATE_SOURCE_SCHEMA_SHA256,
    CandidateChunkMessageIdMode,
    CandidateIdentityEvidence,
    CandidateProtocolProvenance,
    CandidateRequestedSettings,
    CandidateStreamLimits,
    CandidateTranscriptOutcome,
    CandidateUsageEvidenceLevel,
    CopilotCandidateAdmissionError,
    CopilotCandidateEncodingError,
    CopilotCandidateEventError,
    CopilotCandidateJSONError,
    CopilotCandidateOrderError,
    CopilotCandidateReplayError,
    CopilotCandidateStreamLimitError,
    CopilotCandidateTruncatedStreamError,
    CopilotCandidateUnsupportedEventError,
    CopilotCandidateVersionError,
    admit_candidate_completion,
    parse_candidate_transcript,
)
from core.testing import FakeCLIBehavior, make_hermetic_cli

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "copilot_candidate"
COMPLETE_FIXTURE = FIXTURE_DIR / "complete.jsonl"
ERROR_AFTER_RECEIPT_FIXTURE = FIXTURE_DIR / "error-after-receipt.jsonl"
REQUESTED = CandidateRequestedSettings(
    model="synthetic-model-v1",
    reasoning_effort="max",
    context_tier="long_context",
)


def _fixture_bytes(path: Path = COMPLETE_FIXTURE) -> bytes:
    return path.read_bytes()


def _events(path: Path = COMPLETE_FIXTURE) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _event(events: list[dict], event_type: str) -> dict:
    return next(event for event in events if event["type"] == event_type)


def _encode(events: list[dict], *, rechain: bool = True) -> bytes:
    if rechain:
        previous = None
        for index, event in enumerate(events):
            event["parentId"] = previous
            event["timestamp"] = f"2026-09-10T14:00:{index:02d}Z"
            previous = event["id"]
    return (
        "\n".join(
            json.dumps(event, separators=(",", ":"), allow_nan=True) for event in events
        )
        + "\n"
    ).encode("utf-8")


def _insert_event(
    events: list[dict],
    index: int,
    event_type: str,
    data: dict,
    *,
    ephemeral: bool | None = None,
) -> dict:
    event = {
        "id": f"aaaaaaaa-aaaa-4aaa-8aaa-{900 + len(events):012x}",
        "timestamp": "2026-09-10T14:00:00Z",
        "parentId": None,
        "type": event_type,
        "data": data,
    }
    if ephemeral is not None:
        event["ephemeral"] = ephemeral
    events.insert(index, event)
    return event


def _replace_model(events: list[dict], old: str, new: str) -> None:
    for event in events:
        data = event["data"]
        for key in ("selectedModel", "model", "currentModel"):
            if data.get(key) == old:
                data[key] = new
        copilot_usage = data.get("copilotUsage")
        if isinstance(copilot_usage, dict):
            if copilot_usage.get("model") == old:
                copilot_usage["model"] = new
            for detail in copilot_usage.get("tokenDetails", []):
                if detail.get("model") == old:
                    detail["model"] = new
        metrics = data.get("modelMetrics")
        if isinstance(metrics, dict) and old in metrics:
            metrics[new] = metrics.pop(old)


def _swap_events(events: list[dict], first_type: str, second_type: str) -> None:
    first = next(i for i, event in enumerate(events) if event["type"] == first_type)
    second = next(i for i, event in enumerate(events) if event["type"] == second_type)
    events[first], events[second] = events[second], events[first]


class TestCandidateProvenance:
    def test_fixed_candidate_identity_cannot_be_promoted(self):
        assert CANDIDATE_PROTOCOL_PROVENANCE.contract_name == (CANDIDATE_CONTRACT_NAME)
        assert CANDIDATE_PROTOCOL_PROVENANCE.contract_version == (
            CANDIDATE_CONTRACT_VERSION
        )
        assert CANDIDATE_PROTOCOL_PROVENANCE.evidence_level == (
            CANDIDATE_EVIDENCE_LEVEL
        )
        assert "unverified" in CANDIDATE_PROTOCOL_PROVENANCE.evidence_level
        with pytest.raises(TypeError):
            CandidateProtocolProvenance(evidence_level="verified")
        with pytest.raises(FrozenInstanceError):
            CANDIDATE_PROTOCOL_PROVENANCE.evidence_level = "verified"

    def test_fixture_manifest_hashes_and_source_pin(self):
        manifest = json.loads(
            (FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8")
        )
        assert manifest["manifest_version"] == 1
        assert manifest["contract"] == {
            "name": CANDIDATE_CONTRACT_NAME,
            "version": CANDIDATE_CONTRACT_VERSION,
            "evidence_level": CANDIDATE_EVIDENCE_LEVEL,
        }
        assert manifest["source"]["cli_version"] == (CANDIDATE_SOURCE_CLI_VERSION)
        assert manifest["source"]["schema_sha256"] == (CANDIDATE_SOURCE_SCHEMA_SHA256)
        assert manifest["source"]["json_output_equivalence"] == "unverified"
        assert manifest["candidate_profile_assumptions"] == [
            "canonical UUID v4 event identifiers",
            "parentId names the immediately preceding event",
            "one root user/assistant turn",
            "one assistant.usage event per model call",
            "completion receipt, idle, then shutdown terminal order",
        ]
        assert not Path(manifest["source"]["schema_path"]).is_absolute()
        for fixture in manifest["fixtures"]:
            raw = (FIXTURE_DIR / fixture["path"]).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == fixture["sha256"]
            assert fixture["origin"] == "independently-authored-synthetic"
            transcript = parse_candidate_transcript(raw)
            assert transcript.outcome.value == fixture["expected"]["outcome"]
            assert (
                transcript.identity_evidence.value
                == (fixture["expected"]["identity_evidence"])
            )
            assert (
                transcript.usage_evidence.value
                == (fixture["expected"]["usage_evidence"])
            )
            assert (
                transcript.chunk_message_id_mode.value
                == (fixture["expected"]["chunk_message_id_mode"])
            )

    def test_fixture_corpus_contains_no_private_or_live_material(self):
        joined = b"\n".join(
            path.read_bytes()
            for path in (
                COMPLETE_FIXTURE,
                ERROR_AFTER_RECEIPT_FIXTURE,
                FIXTURE_DIR / "README.md",
                FIXTURE_DIR / "manifest.json",
            )
        )
        for forbidden in (
            b"/home/synthetic-user",
            b"github.com/",
            b"api.githubcopilot.com",
            b"ghp_",
            b"github_pat_",
            b"Bearer ",
        ):
            assert forbidden not in joined


class TestCandidateCompletion:
    def test_evidence_enums_use_stable_snake_case_values(self):
        assert [item.value for item in CandidateIdentityEvidence] == [
            "none",
            "runtime",
            "runtime_and_billing",
        ]
        assert [item.value for item in CandidateUsageEvidenceLevel] == [
            "none",
            "per_call",
            "per_call_and_shutdown",
        ]

    def test_complete_fixture_is_candidate_only_and_correlated(self):
        transcript = parse_candidate_transcript(_fixture_bytes())

        assert transcript.outcome is (CandidateTranscriptOutcome.CANDIDATE_COMPLETE)
        assert transcript.identity_evidence is (
            CandidateIdentityEvidence.RUNTIME_AND_BILLING
        )
        assert transcript.usage_evidence is (
            CandidateUsageEvidenceLevel.PER_CALL_AND_SHUTDOWN
        )
        assert transcript.chunk_message_id_mode is (
            CandidateChunkMessageIdMode.NOT_APPLICABLE
        )
        assert transcript.model_call_count == 1
        assert transcript.provenance is CANDIDATE_PROTOCOL_PROVENANCE
        assert transcript.event_count == 11
        assert transcript.session_id == ("11111111-1111-4111-8111-111111111111")
        assert transcript.final_content == "Synthetic candidate response."
        assert transcript.issues == ()
        assert transcript.terminal.completion_stop_reason == "natural"
        assert transcript.terminal.user_message_event_id == (
            "00000000-0000-4000-8000-00000000000b"
        )
        assert transcript.terminal.shutdown_event_id == (
            "00000000-0000-4000-8000-00000000000a"
        )

        completion = admit_candidate_completion(transcript, REQUESTED)
        assert completion.outcome is CandidateTranscriptOutcome.CANDIDATE_COMPLETE
        assert completion.requested_settings is REQUESTED
        assert completion.reported_settings.selected_model == REQUESTED.model
        assert completion.content == "Synthetic candidate response."
        assert completion.identity_evidence is (
            CandidateIdentityEvidence.RUNTIME_AND_BILLING
        )
        assert completion.usage_evidence is (
            CandidateUsageEvidenceLevel.PER_CALL_AND_SHUTDOWN
        )
        assert completion.chunk_message_id_mode is (
            CandidateChunkMessageIdMode.NOT_APPLICABLE
        )
        assert "unverified" in completion.provenance.evidence_level

    def test_arbitrary_exact_model_is_not_restricted_to_development_roles(self):
        events = _events()
        _replace_model(events, "synthetic-model-v1", "operator-selected-model-x")
        transcript = parse_candidate_transcript(_encode(events))
        completion = admit_candidate_completion(
            transcript,
            CandidateRequestedSettings(
                model="operator-selected-model-x",
                reasoning_effort="max",
                context_tier="long_context",
            ),
        )
        assert completion.requested_settings.model == ("operator-selected-model-x")

    def test_requested_settings_remain_separate_from_reported_settings(self):
        transcript = parse_candidate_transcript(_fixture_bytes())
        completion = admit_candidate_completion(transcript, REQUESTED)
        assert completion.requested_settings is not (completion.reported_settings)
        assert completion.requested_settings.model == (
            completion.reported_settings.selected_model
        )

    def test_admission_can_omit_optional_effort_and_context_requirements(self):
        transcript = parse_candidate_transcript(_fixture_bytes())
        completion = admit_candidate_completion(
            transcript,
            CandidateRequestedSettings(model="synthetic-model-v1"),
        )
        assert completion.outcome is CandidateTranscriptOutcome.CANDIDATE_COMPLETE

    def test_per_call_and_shutdown_usage_are_not_double_counted(self):
        transcript = parse_candidate_transcript(_fixture_bytes())
        totals = transcript.usage.per_call_totals
        aggregate = transcript.usage.shutdown_aggregate

        assert totals is not None
        assert totals.call_count == 1
        assert totals.input_tokens == 11
        assert totals.output_tokens == 4
        assert totals.reported_cost == Decimal("0.25")
        assert totals.server_total_nano_aiu == Decimal("125000000")
        (call,) = transcript.usage.calls
        assert call.api_call_id == "chatcmpl-synthetic-1"
        assert call.provider_call_id == "provider-synthetic-1"
        assert call.service_request_id == "service-synthetic-1"
        assert call.transport == "http"
        assert call.api_endpoint == "/responses"
        assert call.finish_reason == "stop"
        assert call.server_billing_model == "synthetic-model-v1"
        assert call.server_token_details[0].model == "synthetic-model-v1"
        assert aggregate is not None
        assert aggregate.model_metrics[0].input_tokens == 11
        assert aggregate.model_metrics[0].reported_request_cost == (Decimal("0.25"))
        assert aggregate.total_nano_aiu == Decimal("125000000")
        assert not hasattr(transcript.usage, "combined_total")

    def test_absent_usage_stays_unknown_not_zero(self):
        events = [event for event in _events() if event["type"] != "assistant.usage"]
        transcript = parse_candidate_transcript(_encode(events))

        assert transcript.outcome is (
            CandidateTranscriptOutcome.CANDIDATE_COMPLETE_UNEVIDENCED
        )
        assert transcript.identity_evidence is CandidateIdentityEvidence.NONE
        assert transcript.usage_evidence is CandidateUsageEvidenceLevel.NONE
        assert transcript.final_content == "Synthetic candidate response."
        assert transcript.usage.calls == ()
        assert transcript.usage.per_call_totals is None
        with pytest.raises(CopilotCandidateAdmissionError) as excinfo:
            admit_candidate_completion(transcript, REQUESTED)
        assert excinfo.value.code == "candidate_complete_unevidenced"

    def test_partially_reported_usage_keeps_missing_fields_unknown(self):
        events = _events()
        usage = _event(events, "assistant.usage")["data"]
        for key in (
            "inputTokens",
            "outputTokens",
            "cacheReadTokens",
            "cacheWriteTokens",
            "reasoningTokens",
            "cost",
            "copilotUsage",
        ):
            usage.pop(key)
        totals = parse_candidate_transcript(_encode(events)).usage.per_call_totals

        assert totals is not None
        assert totals.call_count == 1
        assert totals.input_tokens is None
        assert totals.reported_cost is None
        assert totals.server_total_nano_aiu is None

    def test_explicit_zero_usage_is_preserved_as_reported_zero(self):
        events = _events()
        usage = _event(events, "assistant.usage")["data"]
        for key in (
            "inputTokens",
            "outputTokens",
            "cacheReadTokens",
            "cacheWriteTokens",
            "reasoningTokens",
        ):
            usage[key] = 0
        usage["cost"] = 0
        usage["copilotUsage"]["totalNanoAiu"] = 0
        totals = parse_candidate_transcript(_encode(events)).usage.per_call_totals

        assert totals is not None
        assert totals.input_tokens == 0
        assert totals.reported_cost == Decimal(0)
        assert totals.server_total_nano_aiu == Decimal(0)

    def test_chunked_message_is_joined_only_after_all_chunks_arrive(self):
        events = _events()
        message_index = next(
            i for i, event in enumerate(events) if event["type"] == "assistant.message"
        )
        first = events[message_index]
        first["data"]["content"] = "Synthetic "
        first["data"]["chunkIndex"] = 0
        first["data"]["chunkCount"] = 2
        second = copy.deepcopy(first)
        second["id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        second["data"]["messageId"] = "message-2"
        second["data"]["content"] = "candidate response."
        second["data"]["chunkIndex"] = 1
        events.insert(message_index + 1, second)

        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.final_content == "Synthetic candidate response."
        assert transcript.chunk_message_id_mode is (
            CandidateChunkMessageIdMode.DISTINCT
        )

    def test_single_chunk_metadata_reports_single_message_id_mode(self):
        events = _events()
        message = _event(events, "assistant.message")["data"]
        message["chunkIndex"] = 0
        message["chunkCount"] = 1

        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.chunk_message_id_mode is (CandidateChunkMessageIdMode.SINGLE)

    def test_shared_chunk_message_id_remains_a_replay_error(self):
        events = _events()
        message_index = next(
            i for i, event in enumerate(events) if event["type"] == "assistant.message"
        )
        first = events[message_index]
        first["data"]["content"] = "Synthetic "
        first["data"]["chunkIndex"] = 0
        first["data"]["chunkCount"] = 2
        second = copy.deepcopy(first)
        second["id"] = "12121212-1212-4212-8212-121212121212"
        second["data"]["content"] = "candidate response."
        second["data"]["chunkIndex"] = 1
        events.insert(message_index + 1, second)

        with pytest.raises(CopilotCandidateReplayError, match="message"):
            parse_candidate_transcript(_encode(events))

    def test_turn_end_rejects_incomplete_chunk_sequence(self):
        events = _events()
        message = _event(events, "assistant.message")["data"]
        message["chunkIndex"] = 0
        message["chunkCount"] = 2
        with pytest.raises(CopilotCandidateOrderError, match="before all"):
            parse_candidate_transcript(_encode(events))


class TestEvidenceAdmission:
    def test_request_echo_without_runtime_or_usage_is_unevidenced(self):
        events = [event for event in _events() if event["type"] != "assistant.usage"]
        for event_type in (
            "assistant.turn_start",
            "model.call_start",
            "assistant.message",
            "assistant.turn_end",
        ):
            _event(events, event_type)["data"].pop("model", None)
        shutdown = _event(events, "session.shutdown")["data"]
        shutdown.pop("currentModel", None)
        shutdown["modelMetrics"] = {}

        transcript = parse_candidate_transcript(_encode(events))

        assert transcript.reported_settings is not None
        assert transcript.reported_settings.selected_model == REQUESTED.model
        assert transcript.model_observations == ()
        assert transcript.identity_evidence is CandidateIdentityEvidence.NONE
        assert transcript.usage_evidence is CandidateUsageEvidenceLevel.NONE
        assert transcript.outcome is (
            CandidateTranscriptOutcome.CANDIDATE_COMPLETE_UNEVIDENCED
        )
        assert transcript.final_content == "Synthetic candidate response."
        with pytest.raises(CopilotCandidateAdmissionError):
            admit_candidate_completion(transcript, REQUESTED)

    def test_shutdown_aggregate_without_per_call_usage_is_unevidenced(self):
        events = [event for event in _events() if event["type"] != "assistant.usage"]
        transcript = parse_candidate_transcript(_encode(events))

        assert transcript.usage.shutdown_aggregate is not None
        assert transcript.usage.shutdown_aggregate.model_metrics
        assert transcript.model_observations
        assert transcript.identity_evidence is CandidateIdentityEvidence.NONE
        assert transcript.usage_evidence is CandidateUsageEvidenceLevel.NONE
        assert transcript.outcome is (
            CandidateTranscriptOutcome.CANDIDATE_COMPLETE_UNEVIDENCED
        )

    def test_partial_model_call_coverage_is_unevidenced(self):
        events = _events()
        finish_index = next(
            i
            for i, event in enumerate(events)
            if event["type"] == "model.call_finished"
        )
        _insert_event(
            events,
            finish_index + 1,
            "model.call_start",
            {"turnId": "turn-1", "model": "synthetic-model-v1"},
            ephemeral=True,
        )
        _insert_event(
            events,
            finish_index + 2,
            "model.call_finished",
            {
                "turnId": "turn-1",
                "dispatchDurationMs": 1,
                "outcome": "success",
                "editClassifierVersion": 1,
            },
            ephemeral=True,
        )

        transcript = parse_candidate_transcript(_encode(events))

        assert transcript.model_call_count == 2
        assert len(transcript.usage.calls) == 1
        assert transcript.identity_evidence is CandidateIdentityEvidence.NONE
        assert transcript.usage_evidence is CandidateUsageEvidenceLevel.NONE
        assert transcript.outcome is (
            CandidateTranscriptOutcome.CANDIDATE_COMPLETE_UNEVIDENCED
        )
        with pytest.raises(CopilotCandidateAdmissionError):
            admit_candidate_completion(transcript, REQUESTED)

    def test_admission_recomputes_evidence_instead_of_trusting_labels(self):
        events = [event for event in _events() if event["type"] != "assistant.usage"]
        transcript = parse_candidate_transcript(_encode(events))
        forged_outcome = replace(
            transcript,
            outcome=CandidateTranscriptOutcome.CANDIDATE_COMPLETE,
        )
        with pytest.raises(CopilotCandidateAdmissionError) as excinfo:
            admit_candidate_completion(forged_outcome, REQUESTED)
        assert excinfo.value.code == "insufficient_candidate_evidence"

        forged_labels = replace(
            transcript,
            outcome=CandidateTranscriptOutcome.CANDIDATE_COMPLETE,
            identity_evidence=CandidateIdentityEvidence.RUNTIME_AND_BILLING,
            usage_evidence=CandidateUsageEvidenceLevel.PER_CALL_AND_SHUTDOWN,
        )

        with pytest.raises(CopilotCandidateAdmissionError) as excinfo:
            admit_candidate_completion(forged_labels, REQUESTED)
        assert excinfo.value.code == "evidence_descriptor_mismatch"

    def test_correlated_runtime_usage_is_evidence_sufficient(self):
        events = _events()
        _event(events, "assistant.usage")["data"].pop("copilotUsage")
        shutdown = _event(events, "session.shutdown")["data"]
        shutdown["modelMetrics"] = {}

        transcript = parse_candidate_transcript(_encode(events))
        completion = admit_candidate_completion(transcript, REQUESTED)

        assert transcript.identity_evidence is CandidateIdentityEvidence.RUNTIME
        assert transcript.usage_evidence is CandidateUsageEvidenceLevel.PER_CALL
        assert transcript.outcome is CandidateTranscriptOutcome.CANDIDATE_COMPLETE
        assert completion.identity_evidence is CandidateIdentityEvidence.RUNTIME
        assert completion.usage_evidence is CandidateUsageEvidenceLevel.PER_CALL

    def test_runtime_billing_and_shutdown_channels_are_reported(self):
        transcript = parse_candidate_transcript(_fixture_bytes())
        completion = admit_candidate_completion(transcript, REQUESTED)

        assert transcript.identity_evidence is (
            CandidateIdentityEvidence.RUNTIME_AND_BILLING
        )
        assert transcript.usage_evidence is (
            CandidateUsageEvidenceLevel.PER_CALL_AND_SHUTDOWN
        )
        assert transcript.usage.calls[0].turn_id == "turn-1"
        assert transcript.usage.shutdown_aggregate is not None
        assert (
            transcript.usage.shutdown_aggregate.current_model
            == REQUESTED.model
        )
        assert completion.identity_evidence is (
            CandidateIdentityEvidence.RUNTIME_AND_BILLING
        )
        assert completion.usage_evidence is (
            CandidateUsageEvidenceLevel.PER_CALL_AND_SHUTDOWN
        )

    @pytest.mark.parametrize(
        ("unlabelled_detail", "expected_identity"),
        [
            (True, CandidateIdentityEvidence.RUNTIME),
            (False, CandidateIdentityEvidence.RUNTIME_AND_BILLING),
        ],
        ids=["one-unlabelled-detail", "all-details-labelled"],
    )
    def test_billing_identity_requires_every_token_detail_model(
        self,
        unlabelled_detail: bool,
        expected_identity: CandidateIdentityEvidence,
    ):
        events = _events()
        copilot_usage = _event(events, "assistant.usage")["data"]["copilotUsage"]
        copilot_usage.pop("model")
        second_detail = copy.deepcopy(copilot_usage["tokenDetails"][0])
        second_detail["tokenType"] = "output"
        second_detail["tokenCount"] = 4
        copilot_usage["tokenDetails"].append(second_detail)
        if unlabelled_detail:
            second_detail.pop("model")

        transcript = parse_candidate_transcript(_encode(events))
        completion = admit_candidate_completion(transcript, REQUESTED)

        (call,) = transcript.usage.calls
        assert call.server_billing_model is None
        assert len(call.server_token_details) == 2
        assert transcript.identity_evidence is expected_identity
        assert transcript.usage_evidence is (
            CandidateUsageEvidenceLevel.PER_CALL_AND_SHUTDOWN
        )
        assert transcript.outcome is CandidateTranscriptOutcome.CANDIDATE_COMPLETE
        assert completion.identity_evidence is expected_identity


class TestModelAdmission:
    def test_admission_rejects_wrong_argument_types(self):
        transcript = parse_candidate_transcript(_fixture_bytes())
        with pytest.raises(TypeError, match="transcript"):
            admit_candidate_completion(object(), REQUESTED)
        with pytest.raises(TypeError, match="requested"):
            admit_candidate_completion(transcript, object())

    def test_admission_rejects_modified_candidate_provenance(self):
        transcript = parse_candidate_transcript(_fixture_bytes())
        provenance = CandidateProtocolProvenance()
        object.__setattr__(provenance, "contract_version", 99)
        forged = replace(transcript, provenance=provenance)

        with pytest.raises(CopilotCandidateAdmissionError) as excinfo:
            admit_candidate_completion(forged, REQUESTED)
        assert excinfo.value.code == "provenance_mismatch"

    def test_admission_requires_reported_session_settings(self):
        transcript = parse_candidate_transcript(_fixture_bytes())
        forged = replace(transcript, reported_settings=None)
        with pytest.raises(CopilotCandidateAdmissionError) as excinfo:
            admit_candidate_completion(forged, REQUESTED)
        assert excinfo.value.code == "missing_session_start"

    @pytest.mark.parametrize(
        ("field", "code"),
        [
            ("selected_model", "missing_selected_model"),
            ("reasoning_effort", "missing_reasoning_effort"),
            ("context_tier", "missing_context_tier"),
        ],
    )
    def test_admission_requires_requested_reported_fields(
        self,
        field: str,
        code: str,
    ):
        transcript = parse_candidate_transcript(_fixture_bytes())
        reported = replace(
            transcript.reported_settings,
            **{field: None},
        )
        forged = replace(transcript, reported_settings=reported)

        with pytest.raises(CopilotCandidateAdmissionError) as excinfo:
            admit_candidate_completion(forged, REQUESTED)
        assert excinfo.value.code == code

    def test_runtime_reasoning_effort_mismatch_is_rejected(self):
        events = _events()
        _event(events, "assistant.usage")["data"]["reasoningEffort"] = "high"
        transcript = parse_candidate_transcript(_encode(events))
        with pytest.raises(CopilotCandidateAdmissionError) as excinfo:
            admit_candidate_completion(transcript, REQUESTED)
        assert excinfo.value.code == "runtime_reasoning_effort_mismatch"

    def test_start_selected_model_mismatch_is_rejected(self):
        transcript = parse_candidate_transcript(_fixture_bytes())
        with pytest.raises(CopilotCandidateAdmissionError) as excinfo:
            admit_candidate_completion(
                transcript,
                CandidateRequestedSettings(model="different-model"),
            )
        assert excinfo.value.code == "selected_model_mismatch"

    def test_runtime_usage_model_mismatch_is_rejected(self):
        events = _events()
        _event(events, "assistant.usage")["data"]["model"] = "unexpected-model"
        transcript = parse_candidate_transcript(_encode(events))
        with pytest.raises(CopilotCandidateAdmissionError) as excinfo:
            admit_candidate_completion(transcript, REQUESTED)
        assert excinfo.value.code == "reported_model_mismatch"

    @pytest.mark.parametrize(
        "field_path",
        ["copilotUsage.model", "copilotUsage.tokenDetails.model"],
    )
    def test_server_billing_model_mismatch_is_rejected(self, field_path):
        events = _events()
        usage = _event(events, "assistant.usage")["data"]["copilotUsage"]
        if field_path == "copilotUsage.model":
            usage["model"] = "unexpected-billing-model"
        else:
            usage["tokenDetails"][0]["model"] = "unexpected-billing-model"
        transcript = parse_candidate_transcript(_encode(events))
        with pytest.raises(CopilotCandidateAdmissionError) as excinfo:
            admit_candidate_completion(transcript, REQUESTED)
        assert excinfo.value.code == "reported_model_mismatch"

    def test_shutdown_model_mismatch_is_rejected(self):
        events = _events()
        shutdown = _event(events, "session.shutdown")["data"]
        shutdown["currentModel"] = "unexpected-model"
        transcript = parse_candidate_transcript(_encode(events))
        with pytest.raises(CopilotCandidateAdmissionError) as excinfo:
            admit_candidate_completion(transcript, REQUESTED)
        assert excinfo.value.code == "reported_model_mismatch"

    def test_reasoning_effort_mismatch_is_rejected(self):
        transcript = parse_candidate_transcript(_fixture_bytes())
        with pytest.raises(CopilotCandidateAdmissionError) as excinfo:
            admit_candidate_completion(
                transcript,
                CandidateRequestedSettings(
                    model="synthetic-model-v1",
                    reasoning_effort="high",
                    context_tier="long_context",
                ),
            )
        assert excinfo.value.code == "reasoning_effort_mismatch"

    def test_context_tier_mismatch_is_rejected(self):
        transcript = parse_candidate_transcript(_fixture_bytes())
        with pytest.raises(CopilotCandidateAdmissionError) as excinfo:
            admit_candidate_completion(
                transcript,
                CandidateRequestedSettings(
                    model="synthetic-model-v1",
                    reasoning_effort="max",
                    context_tier="default",
                ),
            )
        assert excinfo.value.code == "context_tier_mismatch"

    @pytest.mark.parametrize(
        ("event_type", "data", "ephemeral"),
        [
            (
                "session.model_change",
                {
                    "previousModel": "synthetic-model-v1",
                    "newModel": "unexpected-model",
                    "source": "automatic",
                },
                None,
            ),
            (
                "session.auto_mode_resolved",
                {"chosenModel": "unexpected-model", "fallback": True},
                None,
            ),
            (
                "auto_mode_switch.requested",
                {"requestId": "switch-1", "errorCode": "rate_limit"},
                True,
            ),
        ],
    )
    def test_substitution_signals_are_rejected(self, event_type, data, ephemeral):
        events = _events()
        _insert_event(events, 1, event_type, data, ephemeral=ephemeral)
        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.outcome is CandidateTranscriptOutcome.REJECTED
        assert any(
            issue.code == "model_substitution_signal" for issue in transcript.issues
        )
        with pytest.raises(CopilotCandidateAdmissionError, match="rejected"):
            admit_candidate_completion(transcript, REQUESTED)

    def test_assistant_usage_auto_signal_is_rejected(self):
        events = _events()
        _event(events, "assistant.usage")["data"]["isAuto"] = True
        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.outcome is CandidateTranscriptOutcome.REJECTED
        assert any(issue.code == "assistant_usage_auto" for issue in transcript.issues)

    @pytest.mark.parametrize("model", ["", " ", "auto"])
    def test_requested_model_must_be_non_auto_exact_string(self, model):
        with pytest.raises(ValueError):
            CandidateRequestedSettings(model=model)


class TestFailureAndTerminalStates:
    def test_error_after_apparent_completion_wins(self):
        transcript = parse_candidate_transcript(
            _fixture_bytes(ERROR_AFTER_RECEIPT_FIXTURE)
        )
        assert transcript.final_content == (
            "This apparent answer must not be admitted."
        )
        assert transcript.terminal.completion_receipt_event_id is not None
        assert transcript.outcome is CandidateTranscriptOutcome.ERROR
        assert {issue.code for issue in transcript.issues} >= {
            "session_error",
            "shutdown_error",
        }
        with pytest.raises(CopilotCandidateAdmissionError) as excinfo:
            admit_candidate_completion(transcript, REQUESTED)
        assert excinfo.value.code == "error"

    def test_aborted_idle_is_cancelled(self):
        events = _events()
        _event(events, "session.idle")["data"]["aborted"] = True
        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.outcome is CandidateTranscriptOutcome.CANCELLED
        with pytest.raises(CopilotCandidateAdmissionError) as excinfo:
            admit_candidate_completion(transcript, REQUESTED)
        assert excinfo.value.code == "cancelled"

    def test_cancelled_model_call_is_cancelled(self):
        events = _events()
        _event(events, "model.call_finished")["data"]["outcome"] = "cancelled"
        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.outcome is CandidateTranscriptOutcome.CANCELLED

    def test_missing_final_content_is_incomplete(self):
        events = _events()
        _event(events, "assistant.message")["data"]["content"] = ""
        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.outcome is CandidateTranscriptOutcome.INCOMPLETE
        assert any(issue.code == "missing_final_content" for issue in transcript.issues)

    def test_missing_shutdown_is_incomplete(self):
        events = _events()[:-1]
        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.outcome is CandidateTranscriptOutcome.INCOMPLETE
        assert any(issue.code == "missing_shutdown" for issue in transcript.issues)

    def test_tool_execution_attempt_is_rejected(self):
        events = _events()
        _insert_event(
            events,
            3,
            "tool.execution_start",
            {
                "toolCallId": "tool-1",
                "toolName": "read",
                "arguments": {"path": "synthetic.txt"},
                "model": "synthetic-model-v1",
                "turnId": "turn-1",
            },
        )
        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.outcome is CandidateTranscriptOutcome.REJECTED
        assert any(
            issue.code == "tool_execution_attempt" for issue in transcript.issues
        )

    def test_permission_attempt_is_rejected(self):
        events = _events()
        _insert_event(
            events,
            3,
            "permission.requested",
            {
                "requestId": "permission-1",
                "permissionRequest": {"kind": "read", "path": "synthetic.txt"},
            },
        )
        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.outcome is CandidateTranscriptOutcome.REJECTED
        assert any(issue.code == "permission_attempt" for issue in transcript.issues)

    def test_task_complete_is_not_treated_as_pure_completion(self):
        events = _events()
        _insert_event(
            events,
            7,
            "session.task_complete",
            {"success": True, "outcome": "completed"},
        )
        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.outcome is CandidateTranscriptOutcome.REJECTED
        assert any(issue.code == "task_complete_event" for issue in transcript.issues)

    def test_root_agent_only(self):
        events = _events()
        _event(events, "assistant.message")["agentId"] = "subagent-1"
        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.outcome is CandidateTranscriptOutcome.REJECTED
        assert any(issue.code == "subagent_event" for issue in transcript.issues)

    def test_known_diagnostic_is_retained_and_redacted(self):
        events = _events()
        _insert_event(
            events,
            1,
            "session.warning",
            {
                "warningType": "synthetic",
                "message": "api_key=synthetic-secret-value-123456",
            },
        )
        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.outcome is (CandidateTranscriptOutcome.CANDIDATE_COMPLETE)
        assert len(transcript.diagnostics) == 1
        assert "synthetic-secret-value-123456" not in (
            transcript.diagnostics[0].message
        )
        assert "[REDACTED]" in transcript.diagnostics[0].message

    @pytest.mark.parametrize(
        ("case", "issue_code"),
        [
            ("autopilot_user", "autopilot_continuation"),
            ("subagent_user", "subagent_user_message"),
            ("tool_requests", "assistant_tool_request"),
            ("server_tools", "assistant_server_tools"),
            ("parent_tool", "assistant_tool_parent"),
            ("failure_auto", "model_call_failure_auto"),
            ("terminal_tool", "non_natural_completion"),
            ("receipt_tools", "completion_receipt_tools"),
            ("code_changes", "shutdown_code_changes"),
            ("agent_metrics", "shutdown_agent_metrics"),
            ("abort", "abort"),
            ("interrupted", "agent_interrupted"),
        ],
    )
    def test_additional_safety_and_terminal_signals_do_not_admit(
        self,
        case: str,
        issue_code: str,
    ):
        events = _events()
        if case == "autopilot_user":
            _event(events, "user.message")["data"]["isAutopilotContinuation"] = True
        elif case == "subagent_user":
            _event(events, "user.message")["data"]["parentAgentTaskId"] = "parent-task"
        elif case == "tool_requests":
            _event(events, "assistant.message")["data"]["toolRequests"] = [
                {"name": "read"}
            ]
        elif case == "server_tools":
            _event(events, "assistant.message")["data"]["serverTools"] = {
                "provider": "synthetic"
            }
        elif case == "parent_tool":
            _event(events, "assistant.message")["data"]["parentToolCallId"] = (
                "tool-parent"
            )
        elif case == "failure_auto":
            finish = next(
                index
                for index, event in enumerate(events)
                if event["type"] == "model.call_finished"
            )
            _insert_event(
                events,
                finish,
                "model.call_failure",
                {
                    "source": "top_level",
                    "model": "synthetic-model-v1",
                    "isAuto": True,
                    "errorMessage": "synthetic failure",
                },
                ephemeral=True,
            )
        elif case == "terminal_tool":
            _event(events, "session.completion_receipt")["data"]["stopReason"] = (
                "terminal_tool"
            )
        elif case == "receipt_tools":
            _event(events, "session.completion_receipt")["data"][
                "successfulToolCount"
            ] = 1
        elif case == "code_changes":
            _event(events, "session.shutdown")["data"]["codeChanges"] = {
                "linesAdded": 1,
                "linesRemoved": 0,
                "filesModified": ["synthetic.txt"],
            }
        elif case == "agent_metrics":
            _event(events, "session.shutdown")["data"]["agentMetrics"] = {"agent-1": {}}
        elif case == "abort":
            receipt = next(
                index
                for index, event in enumerate(events)
                if event["type"] == "session.completion_receipt"
            )
            _insert_event(
                events,
                receipt,
                "abort",
                {"reason": "user_initiated"},
            )
        else:
            receipt = next(
                index
                for index, event in enumerate(events)
                if event["type"] == "session.completion_receipt"
            )
            _insert_event(
                events,
                receipt,
                "agent.interrupted",
                {
                    "activity": "model_call",
                    "elapsedMs": 1,
                    "turn": 1,
                    "model": "synthetic-model-v1",
                },
                ephemeral=True,
            )

        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.outcome is not (CandidateTranscriptOutcome.CANDIDATE_COMPLETE)
        assert any(issue.code == issue_code for issue in transcript.issues)
        with pytest.raises(CopilotCandidateAdmissionError):
            admit_candidate_completion(transcript, REQUESTED)

    def test_informational_diagnostics_remain_nonterminal(self):
        events = _events()
        _insert_event(
            events,
            1,
            "session.info",
            {"infoType": "synthetic", "message": "informational"},
        )
        _insert_event(
            events,
            2,
            "session.truncation",
            {
                "tokenLimit": 100,
                "preTruncationTokensInMessages": 90,
                "preTruncationMessagesLength": 9,
                "postTruncationTokensInMessages": 70,
                "postTruncationMessagesLength": 7,
                "tokensRemovedDuringTruncation": 20,
                "messagesRemovedDuringTruncation": 2,
                "performedBy": "synthetic",
            },
        )
        _insert_event(
            events,
            3,
            "session.usage_info",
            {"tokenLimit": 100, "currentTokens": 70, "messagesLength": 7},
            ephemeral=True,
        )

        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.outcome is CandidateTranscriptOutcome.CANDIDATE_COMPLETE
        assert [diagnostic.event_type for diagnostic in transcript.diagnostics] == [
            "session.info",
            "session.truncation",
            "session.usage_info",
        ]

    @pytest.mark.parametrize(
        "outcome",
        ["error", "rejected"],
    )
    def test_unsuccessful_model_call_outcomes_are_errors(self, outcome: str):
        events = _events()
        _event(events, "model.call_finished")["data"]["outcome"] = outcome
        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.outcome is CandidateTranscriptOutcome.ERROR
        assert any(issue.code == f"model_call_{outcome}" for issue in transcript.issues)

    def test_model_call_failure_without_auto_is_an_error(self):
        events = _events()
        finish = next(
            index
            for index, event in enumerate(events)
            if event["type"] == "model.call_finished"
        )
        _insert_event(
            events,
            finish,
            "model.call_failure",
            {
                "source": "top_level",
                "model": "synthetic-model-v1",
                "isAuto": False,
                "errorMessage": "synthetic failure",
            },
            ephemeral=True,
        )
        transcript = parse_candidate_transcript(_encode(events))
        assert transcript.outcome is CandidateTranscriptOutcome.ERROR
        assert any(issue.code == "model_call_failure" for issue in transcript.issues)


class TestStrictParsingAndCorrelation:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"max_total_bytes": 0},
            {"max_line_bytes": True},
            {"max_events": -1},
            {"max_total_bytes": 10, "max_line_bytes": 11},
        ],
    )
    def test_stream_limits_reject_invalid_bounds(self, kwargs):
        with pytest.raises(ValueError):
            CandidateStreamLimits(**kwargs)

    def test_empty_stream_is_rejected(self):
        with pytest.raises(CopilotCandidateJSONError, match="empty"):
            parse_candidate_transcript(b"")

    def test_crlf_stream_is_accepted(self):
        payload = _fixture_bytes().replace(b"\n", b"\r\n")
        transcript = parse_candidate_transcript(payload)
        assert transcript.outcome is CandidateTranscriptOutcome.CANDIDATE_COMPLETE

    def test_first_event_requires_null_parent_and_session_start(self):
        events = _events()
        events[0]["parentId"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        with pytest.raises(CopilotCandidateOrderError, match="parentId=null"):
            parse_candidate_transcript(_encode(events, rechain=False))

        events = _events()
        events[0]["type"] = "session.info"
        events[0]["data"] = {"infoType": "synthetic", "message": "first"}
        with pytest.raises(CopilotCandidateOrderError, match="session.start"):
            parse_candidate_transcript(_encode(events, rechain=False))

    def test_ephemeral_field_must_be_boolean(self):
        events = _events()
        _event(events, "assistant.message")["ephemeral"] = "false"
        with pytest.raises(CopilotCandidateEventError, match="boolean"):
            parse_candidate_transcript(_encode(events))

    @pytest.mark.parametrize(
        "case",
        [
            "duplicate-start",
            "duplicate-user",
            "turn-before-user",
            "nested-turn",
            "nested-call",
            "duplicate-receipt",
            "idle-before-receipt",
            "shutdown-before-idle",
            "auto-complete-without-request",
            "tool-complete-without-start",
            "permission-complete-without-request",
        ],
    )
    def test_state_machine_rejects_duplicate_or_unmatched_events(
        self,
        case: str,
    ):
        events = _events()
        if case == "duplicate-start":
            duplicate = copy.deepcopy(_event(events, "session.start"))
            duplicate["id"] = "13131313-1313-4313-8313-131313131313"
            events.insert(1, duplicate)
        elif case == "duplicate-user":
            duplicate = copy.deepcopy(_event(events, "user.message"))
            duplicate["id"] = "14141414-1414-4414-8414-141414141414"
            duplicate["data"]["messageId"] = "second-user-message"
            events.insert(2, duplicate)
        elif case == "turn-before-user":
            _swap_events(events, "user.message", "assistant.turn_start")
        elif case == "nested-turn":
            first = next(
                index
                for index, event in enumerate(events)
                if event["type"] == "assistant.turn_start"
            )
            _insert_event(
                events,
                first + 1,
                "assistant.turn_start",
                {"turnId": "turn-2", "model": "synthetic-model-v1"},
            )
        elif case == "nested-call":
            first = next(
                index
                for index, event in enumerate(events)
                if event["type"] == "model.call_start"
            )
            _insert_event(
                events,
                first + 1,
                "model.call_start",
                {"turnId": "turn-1", "model": "synthetic-model-v1"},
                ephemeral=True,
            )
        elif case == "duplicate-receipt":
            first = next(
                index
                for index, event in enumerate(events)
                if event["type"] == "session.completion_receipt"
            )
            duplicate = copy.deepcopy(events[first])
            duplicate["id"] = "15151515-1515-4515-8515-151515151515"
            events.insert(first + 1, duplicate)
        elif case == "idle-before-receipt":
            _swap_events(
                events,
                "session.completion_receipt",
                "session.idle",
            )
        elif case == "shutdown-before-idle":
            _swap_events(events, "session.idle", "session.shutdown")
        elif case == "auto-complete-without-request":
            _insert_event(
                events,
                1,
                "auto_mode_switch.completed",
                {"requestId": "missing-request", "response": "no"},
                ephemeral=True,
            )
        elif case == "tool-complete-without-start":
            _insert_event(
                events,
                4,
                "tool.execution_complete",
                {"toolCallId": "missing-tool", "success": False},
            )
        else:
            _insert_event(
                events,
                1,
                "permission.completed",
                {"requestId": "missing-permission", "result": {"kind": "denied"}},
            )

        with pytest.raises((CopilotCandidateOrderError, CopilotCandidateReplayError)):
            parse_candidate_transcript(_encode(events))

    def test_usage_without_message_is_rejected_at_call_close(self):
        events = [event for event in _events() if event["type"] != "assistant.message"]
        with pytest.raises(CopilotCandidateOrderError, match="no assistant.message"):
            parse_candidate_transcript(_encode(events))

    def test_chunk_api_call_presence_must_be_consistent(self):
        events = _events()
        message_index = next(
            index
            for index, event in enumerate(events)
            if event["type"] == "assistant.message"
        )
        first = events[message_index]
        first["data"]["content"] = "Synthetic "
        first["data"]["chunkIndex"] = 0
        first["data"]["chunkCount"] = 2
        second = copy.deepcopy(first)
        second["id"] = "16161616-1616-4616-8616-161616161616"
        second["data"]["messageId"] = "message-no-call-id"
        second["data"]["content"] = "candidate response."
        second["data"]["chunkIndex"] = 1
        second["data"].pop("apiCallId")
        events.insert(message_index + 1, second)

        with pytest.raises(CopilotCandidateOrderError, match="present and absent"):
            parse_candidate_transcript(_encode(events))

    @pytest.mark.parametrize(
        "case",
        [
            "index-only",
            "count-only",
            "second-unchunked",
            "chunk-after-single",
            "count-change",
            "duplicate-index",
            "out-of-order",
            "index-out-of-range",
        ],
    )
    def test_malformed_chunk_sequences_are_rejected(self, case: str):
        events = _events()
        message_index = next(
            index
            for index, event in enumerate(events)
            if event["type"] == "assistant.message"
        )
        first = events[message_index]
        if case == "index-only":
            first["data"]["chunkIndex"] = 0
        elif case == "count-only":
            first["data"]["chunkCount"] = 1
        elif case == "second-unchunked":
            second = copy.deepcopy(first)
            second["id"] = "22222222-2222-4222-8222-222222222223"
            second["data"]["messageId"] = "message-second"
            events.insert(message_index + 1, second)
        elif case == "chunk-after-single":
            second = copy.deepcopy(first)
            second["id"] = "23232323-2323-4323-8323-232323232323"
            second["data"]["messageId"] = "message-second"
            second["data"]["chunkIndex"] = 1
            second["data"]["chunkCount"] = 2
            events.insert(message_index + 1, second)
        else:
            first["data"]["chunkIndex"] = 0
            first["data"]["chunkCount"] = 2
            second = copy.deepcopy(first)
            second["id"] = "24242424-2424-4424-8424-242424242424"
            second["data"]["messageId"] = "message-second"
            second["data"]["chunkIndex"] = 1
            if case == "count-change":
                second["data"]["chunkCount"] = 3
            elif case == "duplicate-index":
                second["data"]["chunkIndex"] = 0
            elif case == "out-of-order":
                second["data"]["chunkIndex"] = 2
                second["data"]["chunkCount"] = 3
            elif case == "index-out-of-range":
                first["data"]["chunkIndex"] = 2
            events.insert(message_index + 1, second)

        with pytest.raises(
            (
                CopilotCandidateEventError,
                CopilotCandidateOrderError,
                CopilotCandidateReplayError,
            )
        ):
            parse_candidate_transcript(_encode(events))

    def test_minimal_truncated_transcript_reports_all_missing_terminal_parts(self):
        (start,) = _events()[:1]
        transcript = parse_candidate_transcript(_encode([start]))
        assert transcript.outcome is CandidateTranscriptOutcome.INCOMPLETE
        assert {issue.code for issue in transcript.issues} >= {
            "missing_user_message",
            "missing_turn_end",
            "missing_final_content",
            "missing_completion_receipt",
            "missing_idle",
            "missing_shutdown",
        }

    @pytest.mark.parametrize("kind", ["auto", "tool", "permission"])
    def test_correlated_control_events_reject_and_replay_fails(
        self,
        kind: str,
    ):
        events = _events()
        if kind == "auto":
            index = 1
            _insert_event(
                events,
                index,
                "auto_mode_switch.requested",
                {"requestId": "switch-2"},
                ephemeral=True,
            )
            complete = _insert_event(
                events,
                index + 1,
                "auto_mode_switch.completed",
                {"requestId": "switch-2", "response": "no"},
                ephemeral=True,
            )
            duplicate = copy.deepcopy(events[index])
            duplicate["id"] = "17171717-1717-4717-8717-171717171717"
            events.insert(index + 2, duplicate)
            replay_match = "auto-mode request"
        elif kind == "tool":
            index = (
                next(
                    i
                    for i, event in enumerate(events)
                    if event["type"] == "model.call_start"
                )
                + 1
            )
            _insert_event(
                events,
                index,
                "tool.execution_start",
                {"toolCallId": "tool-2", "toolName": "read"},
            )
            complete = _insert_event(
                events,
                index + 1,
                "tool.execution_complete",
                {"toolCallId": "tool-2", "success": False},
            )
            duplicate = copy.deepcopy(complete)
            duplicate["id"] = "18181818-1818-4818-8818-181818181818"
            events.insert(index + 2, duplicate)
            replay_match = "tool completion"
        else:
            index = 1
            _insert_event(
                events,
                index,
                "permission.requested",
                {
                    "requestId": "permission-2",
                    "permissionRequest": {"kind": "read"},
                },
            )
            complete = _insert_event(
                events,
                index + 1,
                "permission.completed",
                {
                    "requestId": "permission-2",
                    "result": {"kind": "denied"},
                },
            )
            duplicate = copy.deepcopy(complete)
            duplicate["id"] = "19191919-1919-4919-8919-191919191919"
            events.insert(index + 2, duplicate)
            replay_match = "permission completion"

        with pytest.raises(CopilotCandidateReplayError, match=replay_match):
            parse_candidate_transcript(_encode(events))

    def test_rejects_non_bytes_input(self):
        with pytest.raises(TypeError, match="payload must be bytes"):
            parse_candidate_transcript("{}\n")  # type: ignore[arg-type]

    def test_rejects_invalid_utf8(self):
        with pytest.raises(CopilotCandidateEncodingError):
            parse_candidate_transcript(b'{"id":"' + bytes([0xFF]) + b'"}\n')

    def test_rejects_malformed_json(self):
        with pytest.raises(CopilotCandidateJSONError):
            parse_candidate_transcript(b"{not-json}\n")

    def test_rejects_non_object_json(self):
        with pytest.raises(CopilotCandidateEventError):
            parse_candidate_transcript(b"[]\n")

    def test_rejects_non_finite_json(self):
        payload = _fixture_bytes().replace(b'"cost":0.25', b'"cost":NaN')
        with pytest.raises(CopilotCandidateJSONError):
            parse_candidate_transcript(payload)

    @pytest.mark.parametrize(
        "payload",
        [
            _fixture_bytes().replace(
                b'"isAuto":false',
                b'"isAuto":true,"isAuto":false',
            ),
            _fixture_bytes().replace(
                b'"copilotUsage":{"model":"synthetic-model-v1"',
                (
                    b'"copilotUsage":{"model":"unexpected-model",'
                    b'"model":"synthetic-model-v1"'
                ),
            ),
        ],
    )
    def test_rejects_duplicate_json_keys_before_interpretation(self, payload):
        with pytest.raises(CopilotCandidateJSONError, match="strict JSON"):
            parse_candidate_transcript(payload)

    def test_rejects_truncated_final_line(self):
        with pytest.raises(CopilotCandidateTruncatedStreamError):
            parse_candidate_transcript(_fixture_bytes().rstrip(b"\n"))

    def test_rejects_blank_jsonl_line(self):
        payload = _fixture_bytes().replace(b"\n", b"\n\n", 1)
        with pytest.raises(CopilotCandidateJSONError, match="blank"):
            parse_candidate_transcript(payload)

    def test_total_input_budget(self):
        payload = _fixture_bytes()
        with pytest.raises(CopilotCandidateStreamLimitError, match="stream"):
            parse_candidate_transcript(
                payload,
                limits=CandidateStreamLimits(
                    max_total_bytes=len(payload) - 1,
                    max_line_bytes=1,
                    max_events=100,
                ),
            )

    def test_line_byte_budget(self):
        payload = _fixture_bytes()
        with pytest.raises(CopilotCandidateStreamLimitError, match="line 1"):
            parse_candidate_transcript(
                payload,
                limits=CandidateStreamLimits(
                    max_total_bytes=len(payload),
                    max_line_bytes=64,
                    max_events=100,
                ),
            )

    def test_event_count_budget(self):
        payload = _fixture_bytes()
        with pytest.raises(CopilotCandidateStreamLimitError, match="events"):
            parse_candidate_transcript(
                payload,
                limits=CandidateStreamLimits(
                    max_total_bytes=len(payload),
                    max_line_bytes=len(payload),
                    max_events=9,
                ),
            )

    def test_rejects_wrong_field_type(self):
        events = _events()
        _event(events, "assistant.usage")["data"]["inputTokens"] = "11"
        with pytest.raises(CopilotCandidateEventError, match="integer"):
            parse_candidate_transcript(_encode(events))

    def test_rejects_unknown_field_in_supported_event(self):
        events = _events()
        _event(events, "session.idle")["data"]["invented"] = True
        with pytest.raises(CopilotCandidateEventError, match="unknown field"):
            parse_candidate_transcript(_encode(events))

    def test_rejects_wrong_candidate_cli_version(self):
        events = _events()
        _event(events, "session.start")["data"]["copilotVersion"] = "1.0.85-0"
        with pytest.raises(CopilotCandidateVersionError):
            parse_candidate_transcript(_encode(events))

    def test_rejects_noncanonical_event_uuid(self):
        events = _events()
        events[0]["id"] = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
        with pytest.raises(CopilotCandidateEventError, match="canonical UUID"):
            parse_candidate_transcript(_encode(events, rechain=False))

    def test_rejects_malformed_event_uuid(self):
        events = _events()
        events[0]["id"] = "not-a-uuid"
        with pytest.raises(CopilotCandidateEventError, match="must be a UUID"):
            parse_candidate_transcript(_encode(events, rechain=False))

    @pytest.mark.parametrize(
        "timestamp",
        ["not-a-timestamp", "2026-09-10T12:00:00"],
    )
    def test_rejects_malformed_or_naive_timestamp(self, timestamp: str):
        events = _events()
        events[0]["timestamp"] = timestamp
        with pytest.raises(CopilotCandidateEventError, match="date-time|UTC offset"):
            parse_candidate_transcript(_encode(events, rechain=False))

    def test_rejects_duplicate_event_id(self):
        events = _events()
        events[1]["id"] = events[0]["id"]
        events[1]["parentId"] = events[0]["id"]
        with pytest.raises(CopilotCandidateReplayError):
            parse_candidate_transcript(_encode(events, rechain=False))

    def test_rejects_non_preceding_parent_id(self):
        events = _events()
        events[2]["parentId"] = events[0]["id"]
        with pytest.raises(CopilotCandidateOrderError, match="parentId"):
            parse_candidate_transcript(_encode(events, rechain=False))

    def test_rejects_backwards_timestamp(self):
        events = _events()
        events[1]["timestamp"] = "2026-09-10T11:59:59Z"
        with pytest.raises(CopilotCandidateOrderError, match="backwards"):
            parse_candidate_transcript(_encode(events, rechain=False))

    def test_rejects_event_after_shutdown(self):
        events = _events()
        _insert_event(
            events,
            len(events),
            "session.info",
            {"infoType": "late", "message": "too late"},
        )
        with pytest.raises(
            CopilotCandidateOrderError, match="follows session.shutdown"
        ):
            parse_candidate_transcript(_encode(events))

    def test_rejects_duplicate_api_call_id(self):
        events = _events()
        usage_index = next(
            i for i, event in enumerate(events) if event["type"] == "assistant.usage"
        )
        duplicate = copy.deepcopy(events[usage_index])
        duplicate["id"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        events.insert(usage_index + 1, duplicate)
        with pytest.raises(CopilotCandidateReplayError, match="apiCallId"):
            parse_candidate_transcript(_encode(events))

    def test_rejects_multiple_usage_records_for_one_model_call(self):
        events = _events()
        usage_index = next(
            i for i, event in enumerate(events) if event["type"] == "assistant.usage"
        )
        second = copy.deepcopy(events[usage_index])
        second["id"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        second["data"]["apiCallId"] = "chatcmpl-synthetic-2"
        second["data"]["providerCallId"] = "provider-synthetic-2"
        second["data"]["serviceRequestId"] = "service-synthetic-2"
        events.insert(usage_index + 1, second)
        with pytest.raises(CopilotCandidateOrderError, match="ambiguous"):
            parse_candidate_transcript(_encode(events))

    def test_rejects_usage_api_call_mismatch(self):
        events = _events()
        _event(events, "assistant.usage")["data"]["apiCallId"] = "chatcmpl-unrelated"
        with pytest.raises(
            CopilotCandidateOrderError, match="apiCallId does not match"
        ):
            parse_candidate_transcript(_encode(events))

    def test_matching_usage_before_message_is_correlated(self):
        events = _events()
        _swap_events(events, "assistant.message", "assistant.usage")
        transcript = parse_candidate_transcript(_encode(events))
        completion = admit_candidate_completion(transcript, REQUESTED)
        assert completion.usage.calls[0].api_call_id == "chatcmpl-synthetic-1"

    def test_rejects_usage_before_message_api_call_mismatch(self):
        events = _events()
        usage = _event(events, "assistant.usage")
        usage["data"]["apiCallId"] = "different-unrelated-call"
        _swap_events(events, "assistant.message", "assistant.usage")
        with pytest.raises(CopilotCandidateOrderError, match="apiCallId"):
            parse_candidate_transcript(_encode(events))

    def test_rejects_conflicting_chunk_api_call_ids(self):
        events = _events()
        message_index = next(
            i for i, event in enumerate(events) if event["type"] == "assistant.message"
        )
        first = events[message_index]
        first["data"]["content"] = "Synthetic "
        first["data"]["chunkIndex"] = 0
        first["data"]["chunkCount"] = 2
        second = copy.deepcopy(first)
        second["id"] = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
        second["data"]["messageId"] = "message-conflict"
        second["data"]["content"] = "candidate response."
        second["data"]["chunkIndex"] = 1
        second["data"]["apiCallId"] = "different-unrelated-call"
        events.insert(message_index + 1, second)
        with pytest.raises(CopilotCandidateOrderError, match="apiCallId"):
            parse_candidate_transcript(_encode(events))

    @pytest.mark.parametrize("missing_from", ["message", "usage"])
    def test_rejects_one_sided_api_call_identity(self, missing_from):
        events = _events()
        _event(events, f"assistant.{missing_from}")["data"].pop("apiCallId")
        with pytest.raises(CopilotCandidateOrderError, match="apiCallId"):
            parse_candidate_transcript(_encode(events))

    def test_rejects_user_and_assistant_turn_mismatch(self):
        events = _events()
        _event(events, "user.message")["data"]["turnId"] = "different-turn"
        with pytest.raises(CopilotCandidateOrderError, match="user.message turnId"):
            parse_candidate_transcript(_encode(events))

    def test_rejects_out_of_order_turn_end(self):
        events = _events()
        call_finish = next(
            i
            for i, event in enumerate(events)
            if event["type"] == "model.call_finished"
        )
        turn_end = next(
            i for i, event in enumerate(events) if event["type"] == "assistant.turn_end"
        )
        events[call_finish], events[turn_end] = (
            events[turn_end],
            events[call_finish],
        )
        with pytest.raises(CopilotCandidateOrderError, match="model call was open"):
            parse_candidate_transcript(_encode(events))

    def test_rejects_unrelated_completion_receipt(self):
        events = _events()
        receipt = _event(events, "session.completion_receipt")["data"]
        receipt["sourceEventId"] = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        with pytest.raises(CopilotCandidateOrderError, match="does not correlate"):
            parse_candidate_transcript(_encode(events))

    def test_unknown_event_cannot_manufacture_success(self):
        events = _events()
        _insert_event(
            events,
            8,
            "session.future_terminal_state",
            {"success": True},
        )
        with pytest.raises(CopilotCandidateUnsupportedEventError):
            parse_candidate_transcript(_encode(events))

    def test_public_error_redacts_escapes_and_bounds_unknown_field(self):
        events = _events()
        canary = "api_key=synthetic-secret-value-123456\n\x1b[31m" + "x" * 4096
        _event(events, "session.idle")["data"][canary] = True

        with pytest.raises(CopilotCandidateEventError) as excinfo:
            parse_candidate_transcript(_encode(events))

        message = str(excinfo.value)
        rendered = "".join(
            traceback.format_exception(
                type(excinfo.value),
                excinfo.value,
                excinfo.value.__traceback__,
            )
        )
        for captured in (message, rendered):
            assert "synthetic-secret-value-123456" not in captured
            assert "\x1b" not in captured
        assert "\n" not in message
        assert "\\x1b" in message
        assert "[REDACTED]" in message
        assert len(message) <= 512

    def test_malformed_json_does_not_leak_through_exception_chain(self):
        canary = "api_key=synthetic-json-secret-123456"
        payload = f'{{"{canary}": "\\u001b",'.encode()
        with pytest.raises(CopilotCandidateJSONError) as excinfo:
            parse_candidate_transcript(payload + b"\n")

        rendered = "".join(
            traceback.format_exception(
                type(excinfo.value),
                excinfo.value,
                excinfo.value.__traceback__,
            )
        )
        assert canary not in str(excinfo.value)
        assert canary not in rendered
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__context__ is None

    @pytest.mark.parametrize(
        "timestamp",
        [
            "0001-01-01T00:00:00+00:01",
            "9999-12-31T23:59:59-00:01",
        ],
    )
    def test_timestamp_utc_conversion_overflow_is_typed_and_unchained(self, timestamp):
        events = _events()
        events[0]["timestamp"] = timestamp
        with pytest.raises(CopilotCandidateEventError) as excinfo:
            parse_candidate_transcript(_encode(events, rechain=False))
        assert "ISO 8601" in str(excinfo.value)
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__context__ is None

    def test_minimum_utc_timestamp_is_accepted(self):
        events = _events()
        events[0]["timestamp"] = "0001-01-01T00:00:00Z"
        transcript = parse_candidate_transcript(_encode(events, rechain=False))
        assert transcript.outcome is (CandidateTranscriptOutcome.CANDIDATE_COMPLETE)

    def test_maximum_utc_timestamp_is_accepted(self):
        events = _events()
        events[-1]["timestamp"] = "9999-12-31T23:59:59Z"
        transcript = parse_candidate_transcript(_encode(events, rechain=False))
        assert transcript.outcome is (CandidateTranscriptOutcome.CANDIDATE_COMPLETE)

    def test_ephemeral_candidate_events_require_true(self):
        events = _events()
        _event(events, "assistant.usage")["ephemeral"] = False
        with pytest.raises(CopilotCandidateEventError, match="ephemeral must be true"):
            parse_candidate_transcript(_encode(events))


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="generic fake CLI executables use POSIX shebang execution",
)
def test_candidate_fixture_round_trips_through_real_fake_process_pipe(
    tmp_path: Path,
) -> None:
    workspace = make_hermetic_cli(tmp_path)
    workspace.configure_cli(
        "copilot",
        FakeCLIBehavior(stdout=_fixture_bytes().decode("utf-8")),
    )

    process = subprocess.run(
        ["copilot", "--output-format", "json"],
        input=b"synthetic prompt over stdin",
        capture_output=True,
        timeout=5,
        check=False,
        cwd=workspace.cwd,
        env=workspace.child_env(),
    )

    assert process.returncode == 0
    completion = admit_candidate_completion(
        parse_candidate_transcript(process.stdout),
        REQUESTED,
    )
    assert completion.content == "Synthetic candidate response."
    (invocation,) = workspace.invocations("copilot")
    assert invocation.stdin == b"synthetic prompt over stdin"
    assert invocation.argv == ("--output-format", "json")
    assert invocation.executable == workspace.executable("copilot")
