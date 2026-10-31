"""Structured counter-direction: schema field + gate consumption.

The review model emits ``counter_direction`` (supports_vuln /
refutes_vuln) at generation time; the clean-counter escalation gate
consumes it instead of re-deriving direction from prose. The keyword
classifier stays as the fallback for responses lacking the field.
"""

from core.audit.llm_review import (
    REVIEW_SCHEMA,
    REVIEW_SCHEMA_BLIND,
    _clean_counter_escalates,
)

# The subjunctive-conditional refutation shape that sailed past the
# keyword classifier: full of vulnerability vocabulary, but its
# conclusion argues clean.
_SUBJUNCTIVE_REFUTATION = (
    "If the crypto driver could invoke the completion callback twice, "
    "the kfree at lines 222-224 would be a double-free of the request "
    "buffer — but the crypto API completion contract guarantees "
    "exactly-once invocation, which prevents it."
)

_SUPPORTS_COUNTER = (
    "An attacker who controls the length header can make the copy "
    "overflow the 64-byte stack buffer because the bounds check "
    "compares against the tainted size instead of the buffer size."
)


class TestSchemaField:
    def test_field_in_both_schemas(self):
        for schema in (REVIEW_SCHEMA, REVIEW_SCHEMA_BLIND):
            prop = schema["properties"]["counter_direction"]
            assert prop["enum"] == ["supports_vuln", "refutes_vuln"]
            assert "counter_direction" in schema["required"]


class TestEscalationConsumesDirection:
    def test_refutes_vuln_blocks_escalation(self):
        # Keyword-compelling counter (names mechanisms), but the model
        # says it cuts in the refutation direction.
        result = {
            "counter_hypothesis": _SUBJUNCTIVE_REFUTATION,
            "counter_direction": "refutes_vuln",
        }
        assert _clean_counter_escalates(result) is False

    def test_supports_vuln_still_needs_compellingness(self):
        result = {
            "counter_hypothesis": _SUPPORTS_COUNTER,
            "counter_direction": "supports_vuln",
        }
        assert _clean_counter_escalates(result) is True
        vague = {
            "counter_hypothesis": "could be dangerous in some situations "
                                  "if inputs are weird somehow sometimes",
            "counter_direction": "supports_vuln",
        }
        assert _clean_counter_escalates(vague) is False

    def test_absent_field_falls_back_to_prose(self):
        # Without the field, the subjunctive refutation still fools
        # the keyword classifier — documented fallback limitation.
        assert _clean_counter_escalates(
            {"counter_hypothesis": _SUPPORTS_COUNTER},
        ) is True

    def test_past_tense_refutation_blocked_by_fallback(self):
        assert _clean_counter_escalates({
            "counter_hypothesis": (
                "The overflow claim was refuted by the bounds check "
                "on line 42 that caps size below the buffer length."
            ),
        }) is False
