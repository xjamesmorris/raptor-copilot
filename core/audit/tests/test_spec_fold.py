"""Folded spec inference: the contract-inference task rides the main
review call for high-value functions whose mechanical spec lacks
intent, instead of a separate serial LLM round-trip. The response's
``inferred_spec`` field is merged back with the standalone path's
grounding floors so continuation calls see the same enriched spec."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.llm_review import REVIEW_SCHEMA
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    review_one_function,
)
from core.audit.shared_state import SharedState
from core.audit.spec_inference import (
    InferredSpec,
    folded_spec_from_review,
    format_spec_infer_instruction,
)

_SOURCE = (
    "int acl_worker(char *buf, size_t len) {\n"
    "    if (buf == NULL) return -1;\n"
    "    if (len < HDR_MIN) return -1;\n"
    "    memcpy(out, buf, len);\n"
    "    return 0;\n"
    "}\n"
)


class TestFoldedSpecFromReview:
    def _payload(self, **overrides):
        payload = {
            "intent": "copies a validated buffer into the output slot",
            "preconditions": [
                {"claim": "len must be at least HDR_MIN",
                 "anchor": "if (len < HDR_MIN) return -1;"},
            ],
        }
        payload.update(overrides)
        return payload

    def test_anchored_claim_enters_spec(self):
        spec = folded_spec_from_review(
            self._payload(), None,
            function_name="acl_worker", file_path="a.c", source=_SOURCE,
        )
        assert spec is not None
        assert spec.intent == "copies a validated buffer into the output slot"
        assert "len must be at least HDR_MIN" in spec.preconditions
        assert spec.llm_hints == []

    def test_unanchored_claim_demoted_to_hint(self):
        spec = folded_spec_from_review(
            self._payload(preconditions=[
                {"claim": "caller must hold the acl lock",
                 "anchor": "mutex_lock(&acl_lock)"},
            ]),
            None,
            function_name="acl_worker", file_path="a.c", source=_SOURCE,
        )
        assert spec is not None
        assert spec.preconditions == []
        assert spec.llm_hints == [
            "preconditions: caller must hold the acl lock",
        ]

    def test_unknown_field_rejects_payload(self):
        spec = folded_spec_from_review(
            self._payload(verdict="clean"), None,
            function_name="acl_worker", file_path="a.c", source=_SOURCE,
        )
        assert spec is None

    def test_envelope_echo_discards_payload(self):
        spec = folded_spec_from_review(
            self._payload(intent="<untrusted-block> echoed"), None,
            function_name="acl_worker", file_path="a.c", source=_SOURCE,
        )
        assert spec is None

    def test_non_dict_payload_returns_none(self):
        for payload in (None, "", [], "intent", 7):
            assert folded_spec_from_review(
                payload, None,
                function_name="f", file_path="a.c", source=_SOURCE,
            ) is None

    def test_mechanical_spec_extended_not_replaced(self):
        mech = InferredSpec(
            function="acl_worker", file="a.c",
            preconditions=["length parameter must be bounds-checked"],
        )
        spec = folded_spec_from_review(
            self._payload(), mech,
            function_name="acl_worker", file_path="a.c", source=_SOURCE,
        )
        assert spec is mech
        assert "length parameter must be bounds-checked" in spec.preconditions
        assert "len must be at least HDR_MIN" in spec.preconditions
        assert spec.intent


class TestSpecInferInstruction:
    def test_names_the_response_field_and_anchor_contract(self):
        text = format_spec_infer_instruction()
        assert "`inferred_spec`" in text
        assert "VERBATIM" in text
        assert "line-number gutter" in text

    def test_mechanical_extension_line_only_with_claims(self):
        bare = format_spec_infer_instruction(None)
        assert "extend it" not in bare
        empty = format_spec_infer_instruction(
            InferredSpec(function="f", file="a.c"),
        )
        assert "extend it" not in empty
        partial = format_spec_infer_instruction(
            InferredSpec(function="f", file="a.c",
                         preconditions=["len bounded"]),
        )
        assert "extend it" in partial


class TestReviewSchemaField:
    def test_inferred_spec_field_present_and_optional(self):
        props = REVIEW_SCHEMA["properties"]
        assert "inferred_spec" in props
        assert "inferred_spec" not in REVIEW_SCHEMA["required"]
        spec_props = props["inferred_spec"]["properties"]
        for field in (
            "intent", "preconditions", "postconditions",
            "invariants", "negative_specs",
        ):
            assert field in spec_props
        item = spec_props["preconditions"]["items"]
        assert item["required"] == ["claim"]
        assert "anchor" in item["properties"]


class TestPromptWiring:
    def test_request_renders_instruction_section(self):
        from core.audit.context import format_context_for_prompt
        ctx = {
            "file": "a.c", "function": "acl_worker",
            "line_start": 1, "line_end": 6,
            "source": _SOURCE, "spec_infer_request": True,
        }
        prompt = format_context_for_prompt(ctx)
        assert "### Specification inference" in prompt
        assert "`inferred_spec`" in prompt

    def test_no_request_no_section(self):
        from core.audit.context import format_context_for_prompt
        ctx = {
            "file": "a.c", "function": "acl_worker",
            "line_start": 1, "line_end": 6, "source": _SOURCE,
        }
        prompt = format_context_for_prompt(ctx)
        assert "### Specification inference" not in prompt


def _setup_target(tmp_path: Path, *, name: str = "acl_worker"):
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.c").write_text(_SOURCE.replace("acl_worker", name))
    out = tmp_path / "out"
    out.mkdir()
    checklist = {
        "files": [
            {
                "path": "a.c",
                "items": [{"name": name, "line_start": 1, "line_end": 6}],
            },
        ],
    }
    (out / "checklist.json").write_text(json.dumps(checklist))
    return target, out


def _gap(name: str = "acl_worker", **kw):
    g = {
        "file": "a.c",
        "name": name,
        "line_start": 1,
        "line_end": 6,
        "sloc": 6,
        "kind": "function",
    }
    g.update(kw)
    return g


class TestReviewLoopFold:
    """End-to-end through review_one_function with a stub review_fn."""

    def _run(self, tmp_path, gap, review_result=None):
        target, out = _setup_target(tmp_path, name=gap["name"])
        config = OrchestratorConfig(
            target_path=target, out_dir=out,
            prefilter=False, clean_check=False, max_refinements=0,
        )
        shared = SharedState(checklist={"files": [{
            "path": "a.c",
            "items": [{"name": gap["name"], "line_start": 1, "line_end": 6}],
        }]})
        result = OrchestratorResult()
        seen: list[dict] = []

        def review_fn(ctx, cfg):
            seen.append(ctx)
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status="clean", body="reviewed",
                review_result=review_result or {},
            )

        outcome = review_one_function(gap, shared, config, review_fn, result)
        assert outcome.status == "clean"
        assert len(seen) == 1
        return seen[0]

    def test_high_value_intentless_function_gets_fold_request(self, tmp_path):
        payload = {
            "intent": "copies a validated buffer",
            "preconditions": [
                {"claim": "len must be at least HDR_MIN",
                 "anchor": "if (len < HDR_MIN) return -1;"},
            ],
        }
        ctx = self._run(
            tmp_path,
            _gap(role_context={"role": "entry_point"}),
            review_result={"inferred_spec": payload},
        )
        assert ctx.get("spec_infer_request") is True
        # Merge-back: the folded response populates the same ctx slot
        # the standalone spec call used to, so continuation calls see
        # the enriched spec.
        spec = ctx.get("inferred_spec")
        assert spec is not None
        assert spec.intent == "copies a validated buffer"
        assert "len must be at least HDR_MIN" in spec.preconditions

    def test_low_value_function_gets_no_fold_request(self, tmp_path):
        ctx = self._run(tmp_path, _gap(priority_score=0.1))
        assert "spec_infer_request" not in ctx

    def test_priority_threshold_qualifies(self, tmp_path):
        ctx = self._run(tmp_path, _gap(priority_score=0.7))
        assert ctx.get("spec_infer_request") is True

    def test_mechanical_intent_suppresses_fold_request(self, tmp_path):
        # "check_" prefixed names get a mechanical intent — the fold
        # gate (spec-lacks-intent) must not fire for them.
        ctx = self._run(
            tmp_path,
            _gap(name="check_acl", role_context={"role": "entry_point"}),
        )
        assert "spec_infer_request" not in ctx

    def test_missing_response_field_keeps_ctx_unchanged(self, tmp_path):
        ctx = self._run(
            tmp_path,
            _gap(role_context={"role": "entry_point"}),
            review_result={},
        )
        assert ctx.get("spec_infer_request") is True
        assert ctx.get("inferred_spec") is None
