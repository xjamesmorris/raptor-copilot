"""JSON Schema for ``orchestrated_report.json`` (QoL #11e).

Codifies the per-finding shape + canonical status enum that
``packages.llm_analysis.orchestrator`` writes at the end of every
``/agentic`` run. Descriptive contract for downstream tooling —
NOT a runtime validation gate (the orchestrator does not validate
against this schema before writing).

## Why a schema, not just docs

Multiple consumers read this file:

* ``raptor_agentic`` summary printer.
* Report renderers (``report.json`` → markdown).
* ``/project findings``, ``/project correlate``, ``/project report``.
* External automation: CI scripts, dashboards, custom tooling.

Before the status enum landed (QoL #19) each consumer re-implemented
its own field-presence detection (``is_true_positive is None``,
``error`` truthy, ``self_contradictory=True``, …). The schema's
``status`` enum is now the single contract these consumers can
write against.

## Strictness

Intentionally PERMISSIVE — ``additionalProperties: true`` everywhere
so the orchestrator can stamp new fields without breaking
consumers. ``required`` lists only fields consumers can reliably
depend on:

* Top-level: ``mode``, ``results``.
* Per-finding: ``finding_id``, ``status``.

Everything else is optional. The schema documents the SHAPE of
fields when present, not the requirement that they be present.

## How to consume

```python
from core.json import load_json
from core.run.orchestrated_report_schema import SCHEMA

# Validate an on-disk report (requires the optional `jsonschema`
# dependency — not pulled in by RAPTOR's runtime).
import jsonschema
report = load_json(
    "orchestrated_report.json", strict=True, max_bytes=64 * 1024 * 1024,
)
jsonschema.validate(report, SCHEMA)
```

Without ``jsonschema`` installed, consumers can still read SCHEMA
as a plain dict for documentation / field-name lookup.
"""

from __future__ import annotations


# All status values stamped by ``_finalize_results_for_emit``. Kept
# in sync with ``core.run.finding_status.ALL_STATUSES`` via
# ``test_orchestrated_report_schema.test_status_enum_matches``.
_STATUS_VALUES = [
    "analysed",
    "analysis_inconsistent",
    "skipped_over_budget",
    "skipped_duplicate",
    "skipped_dead_code",
    "skipped_filtered",
    "skipped_tool_absent",
    "skipped",
    "error",
]


_FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "finding_id": {"type": "string"},
        "status": {"type": "string", "enum": _STATUS_VALUES},

        # Verdict fields — present on analysed findings; absent on
        # skipped / error records.
        "is_true_positive": {"type": ["boolean", "null"]},
        "is_exploitable": {"type": ["boolean", "null"]},
        "exploitable": {"type": ["boolean", "null"]},
        "exploitability_score": {"type": ["number", "null"]},
        "self_contradictory": {"type": "boolean"},
        "contradiction_resolved_by_judge": {"type": "boolean"},

        # Provenance + scoping.
        "file_path": {"type": "string"},
        "function": {"type": "string"},
        "line": {"type": ["integer", "null"]},
        "rule_id": {"type": "string"},
        "severity": {"type": "string"},
        "vuln_type": {"type": "string"},
        "analysed_by": {"type": "string"},
        "analysed_by_provider": {"type": "string"},
        "analysis_route": {
            "type": "object",
            "properties": {
                "provider": {"type": "string"},
                "model": {"type": "string"},
            },
            "description": (
                "Logical transport-owned provider/model route; not an "
                "endpoint identity or served-model attestation."
            ),
            "additionalProperties": True,
        },
        "resolved_model": {
            "type": "string",
            "description": "Provider-reported observation, not authorization.",
        },
        "analysis_provenance": {
            "type": "object",
            "description": (
                "Transport-owned provenance, separate from model-generated "
                "analysis content."
            ),
            "additionalProperties": True,
        },
        "cost_observation": {
            "type": "object",
            "description": (
                "Typed transport cost observation serialized by core/llm; "
                "its basis distinguishes billed, estimated, subscription, "
                "and unknown amounts."
            ),
            "additionalProperties": True,
        },
        "accounting": {
            "type": "object",
            "description": (
                "Accounting summary for this emitted response record, "
                "not the run-wide or internal-retry total."
            ),
            "additionalProperties": True,
        },
        "accounting_complete": {
            "type": "boolean",
            "description": (
                "This response record has a numeric USD figure, billed or "
                "estimated, or explicit no-spend evidence such as a cache "
                "hit. Not invoice authority or run-wide/internal-retry "
                "completeness."
            ),
        },
        "cache_hit": {
            "type": "boolean",
            "description": "Core cache evidence; no new provider spend.",
        },

        # LLM-emitted prose / structured data.
        "reasoning": {"type": "string"},
        "exploit_code": {"type": "string"},
        "patch_code": {"type": "string"},
        "has_exploit": {"type": "boolean"},
        "has_patch": {"type": "boolean"},

        # Error / skip detail.
        "error": {"type": "string"},
        "cc_error": {"type": "string"},
        "cc_debug_file": {"type": "string"},
        "skip_reason": {"type": "string"},
    },
    "required": ["finding_id", "status"],
    "additionalProperties": True,
}


_ORCHESTRATION_SCHEMA = {
    "type": "object",
    "properties": {
        "analysis_model": {"type": ["string", "null"]},
        "consensus_model": {"type": ["string", "null"]},
        "judge_model": {"type": ["string", "null"]},
        "aggregate_model": {"type": ["string", "null"]},
        "findings_analysed": {"type": "integer", "minimum": 0},
        "findings_skipped": {"type": "integer", "minimum": 0},
        "findings_total": {"type": "integer", "minimum": 0},

        "cost": {
            "type": "object",
            "properties": {
                "total_cost": {"type": "number", "minimum": 0},
                "total_tokens": {"type": "integer", "minimum": 0},
                "by_model": {"type": "object"},
                "cost_by_model": {
                    "type": "object",
                    "description": "Legacy numeric subtotals, not invoice proof.",
                    "additionalProperties": {"type": "number", "minimum": 0},
                },
                "accounting_by_route": {
                    "type": "object",
                    "description": (
                        "Logical provider/model-keyed accounting summaries. "
                        "Each entry contains its route and per-basis totals."
                    ),
                    "additionalProperties": {
                        "type": "object",
                        "additionalProperties": True,
                    },
                },
                "cache_hits": {"type": "integer", "minimum": 0},
                "failed_dispatches": {
                    "type": "integer", "minimum": 0,
                    "description": (
                        "Error-shaped package dispatches; not proof of "
                        "provider usage or spend."
                    ),
                },
                "unclassified_legacy_events": {
                    "type": "integer", "minimum": 0,
                    "description": (
                        "Legacy aggregates without per-attempt cost basis. "
                        "They make totals incomplete without fabricating "
                        "an unknown provider-call count."
                    ),
                },
                "provider_billed_usd": {
                    "type": "number", "minimum": 0,
                },
                "catalog_priced_usd": {
                    "type": "number", "minimum": 0,
                },
                "configured_rate_usd": {
                    "type": "number", "minimum": 0,
                },
                "cli_reported_usd": {
                    "type": "number", "minimum": 0,
                },
                "estimated_usd": {"type": "number", "minimum": 0},
                "provider_billed_calls": {
                    "type": "integer", "minimum": 0,
                },
                "catalog_priced_calls": {
                    "type": "integer", "minimum": 0,
                },
                "configured_rate_calls": {
                    "type": "integer", "minimum": 0,
                },
                "cli_reported_calls": {
                    "type": "integer", "minimum": 0,
                },
                "subscription_calls": {
                    "type": "integer", "minimum": 0,
                },
                "unknown_calls": {
                    "type": "integer", "minimum": 0,
                },
                "unknown_failed_attempts": {
                    "type": "integer", "minimum": 0,
                },
                "retained_reservation_estimate_usd": {
                    "type": "number", "minimum": 0,
                },
                "exposure_unresolved": {"type": "boolean"},
                "usd_total_complete": {
                    "type": "boolean",
                    "description": (
                        "Run-wide numeric USD coverage after reconciliation "
                        "with the core snapshot. Figures may be estimates; "
                        "this is not invoice authority."
                    ),
                },
                "authoritative_remaining_usd": {
                    "type": ["number", "null"],
                    "minimum": 0,
                },
            },
            "additionalProperties": True,
        },

        # Provider-served snapshots — feeds run provenance.
        "fired_models": {
            "type": "array",
            "items": {"type": ["string", "object"]},
        },

        # Defense telemetry — only present when has_warnings.
        "defense_telemetry": {"type": "object"},
    },
    "additionalProperties": True,
}


SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "https://github.com/gadievron/raptor/"
           "core/run/orchestrated_report_schema.py",
    "title": "RAPTOR orchestrated_report.json",
    "description": (
        "Per-run output of /agentic and related orchestrated "
        "analysis paths. Each ``results[]`` entry carries the "
        "canonical ``status`` enum so consumers don't need to "
        "re-derive ''analysed vs skipped vs error'' from "
        "absent-field detection."
    ),
    "type": "object",
    "properties": {
        "mode": {
            "type": "string",
            "description": (
                "Always ``orchestrated`` for files written by "
                "the orchestrator. Distinguishes from prep-only "
                "and CC-only intermediate reports."
            ),
        },
        "results": {
            "type": "array",
            "items": _FINDING_SCHEMA,
        },
        "orchestration": _ORCHESTRATION_SCHEMA,

        # Aggregate counters — recomputable from ``results``, kept
        # at the top level for cheap-read summary consumers.
        "analyzed": {"type": "integer", "minimum": 0},
        "exploitable": {"type": "integer", "minimum": 0},
        "exploits_generated": {"type": "integer", "minimum": 0},
        "patches_generated": {"type": "integer", "minimum": 0},

        # Optional grouping / correlation sections — present when
        # the corresponding feature ran.
        "cross_finding_groups": {"type": "array"},
        "dataflow_validation": {"type": "object"},
        "group_analyses": {"type": "object"},
        "correlation": {"type": "object"},
        "aggregation": {"type": "object"},
    },
    "required": ["mode", "results"],
    "additionalProperties": True,
}


__all__ = ["SCHEMA"]
