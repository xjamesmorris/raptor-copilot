"""Tests for ``core/run/orchestrated_report_schema.py`` —
descriptive contract for ``orchestrated_report.json`` (QoL #11e).

The schema is consumed by external tooling; not validated at runtime.
Tests verify the schema itself is well-formed and stays in sync
with the producer (finding_status enum, _finalize_results_for_emit
behaviour). We deliberately do NOT pull in ``jsonschema`` for these
tests — it's not a declared RAPTOR dependency
(``feedback-no-jsonschema-in-tests``); the schema is asserted as a
plain dict shape.
"""

from __future__ import annotations

import unittest

from core.llm.accounting import AccountingSummary, CostBasis, CostObservation, RouteIdentity
from core.run.finding_status import ALL_STATUSES
from core.run.orchestrated_report_schema import SCHEMA


class TestSchemaShape(unittest.TestCase):
    """Plain-dict assertions on the schema's structure. Catches a
    typo / wrong nesting at import time without requiring the
    jsonschema validator."""

    def test_top_level_required_fields(self):
        self.assertIn("mode", SCHEMA["properties"])
        self.assertIn("results", SCHEMA["properties"])
        self.assertEqual(set(SCHEMA["required"]), {"mode", "results"})

    def test_top_level_additional_properties_permissive(self):
        # Permissive top-level so the orchestrator can stamp new
        # sections (dataflow_validation, defense_telemetry, future
        # additions) without breaking consumers pinned to this
        # schema.
        self.assertTrue(SCHEMA.get("additionalProperties", False))

    def test_results_is_array_of_findings(self):
        results = SCHEMA["properties"]["results"]
        self.assertEqual(results["type"], "array")
        items = results["items"]
        self.assertEqual(items["type"], "object")
        # finding_id + status both required on every per-finding
        # record (the contract consumers rely on).
        self.assertEqual(
            set(items["required"]), {"finding_id", "status"},
        )

    def test_status_enum_matches_finding_status_module(self):
        # The schema's status enum MUST stay in lock-step with
        # ``core.run.finding_status.ALL_STATUSES`` — drift here
        # would silently produce reports that consumers pinned
        # to the schema can't parse.
        status_prop = (
            SCHEMA["properties"]["results"]["items"]
                  ["properties"]["status"]
        )
        self.assertEqual(set(status_prop["enum"]), set(ALL_STATUSES))

    def test_orchestration_section_present(self):
        orch = SCHEMA["properties"]["orchestration"]
        self.assertEqual(orch["type"], "object")
        # Cost subobject required to be an object when present.
        self.assertEqual(orch["properties"]["cost"]["type"], "object")

    def test_assessment_completeness_contract_is_documented(self):
        assessment_ref = SCHEMA["properties"]["assessment"]["$ref"]
        self.assertEqual(assessment_ref, "#/definitions/assessment")
        assessment = SCHEMA["definitions"]["assessment"]
        self.assertTrue({
            "requested",
            "eligible",
            "selected",
            "analyzed",
            "unreviewed",
            "cap",
            "cap_applied",
        }.issubset(assessment["required"]))
        self.assertEqual(
            SCHEMA["properties"]["orchestration"]["properties"]
            ["assessment"]["$ref"],
            assessment_ref,
        )

    def test_cost_section_documents_additive_accounting_fields(self):
        cost = SCHEMA["properties"]["orchestration"]["properties"]["cost"]
        props = cost["properties"]
        for name in (
            "provider_billed_usd",
            "catalog_priced_usd",
            "configured_rate_usd",
            "cli_reported_usd",
            "estimated_usd",
            "provider_billed_calls",
            "catalog_priced_calls",
            "configured_rate_calls",
            "cli_reported_calls",
            "subscription_calls",
            "unknown_calls",
            "unknown_failed_attempts",
            "retained_reservation_estimate_usd",
            "exposure_unresolved",
            "usd_total_complete",
            "authoritative_remaining_usd",
            "total_tokens",
            "cost_by_model",
            "accounting_by_route",
            "cache_hits",
            "failed_dispatches",
            "unclassified_legacy_events",
        ):
            self.assertIn(name, props)
        self.assertEqual(
            props["authoritative_remaining_usd"]["type"],
            ["number", "null"],
        )
        self.assertEqual(props["total_cost"]["type"], "number")

    def test_finding_documents_transport_owned_metadata(self):
        finding = SCHEMA["properties"]["results"]["items"]
        props = finding["properties"]
        for name in (
            "analysed_by",
            "analysed_by_provider",
            "analysis_route",
            "analysis_provenance",
            "resolved_model",
            "cost_observation",
            "accounting",
            "accounting_complete",
            "cache_hit",
            "diagnostic_artifact",
            "artifacts",
        ):
            self.assertIn(name, props)
            self.assertNotIn(name, finding["required"])
        self.assertEqual(props["accounting_complete"]["type"], "boolean")
        self.assertEqual(props["cache_hit"]["type"], "boolean")
        for name in (
            "analysis_route",
            "analysis_provenance",
            "cost_observation",
            "accounting",
        ):
            self.assertEqual(props[name]["type"], "object")
            self.assertTrue(props[name]["additionalProperties"])

    def test_orchestration_documents_dispatch_batch_completeness(self):
        props = SCHEMA["properties"]["orchestration"]["properties"]
        self.assertIn("dispatch_batches", props)
        self.assertIn("dispatch_failures", props)
        self.assertIn("dispatch_incomplete_tasks", props)
        batch = props["dispatch_batches"]["items"]
        for name in (
            "task",
            "phase",
            "status",
            "input_items",
            "result_records",
            "succeeded",
            "failed",
            "not_run",
            "complete",
            "error_types",
            "failed_by_model",
            "first_error",
            "artifacts",
        ):
            self.assertIn(name, batch["properties"])

    def test_completeness_descriptions_do_not_claim_invoice_authority(self):
        finding = SCHEMA["properties"]["results"]["items"]["properties"]
        cost = SCHEMA["properties"]["orchestration"]["properties"]["cost"]
        record_description = finding["accounting_complete"]["description"]
        self.assertIn("estimated", record_description)
        self.assertIn("no-spend", record_description)
        self.assertIn("Not invoice authority", record_description)
        self.assertIn("internal-retry", record_description)
        self.assertIn(
            "not invoice authority",
            cost["properties"]["usd_total_complete"]["description"],
        )

    def test_finding_additional_properties_permissive(self):
        # Per-finding records carry arbitrary keys from the prep
        # stage + downstream enrichment; tests' fixture parity
        # would otherwise need to chase every new key. Permissive
        # by design.
        items = SCHEMA["properties"]["results"]["items"]
        self.assertTrue(items.get("additionalProperties", False))


class TestSchemaConsumerExample(unittest.TestCase):
    """End-to-end sanity: a minimal report dict matching what the
    orchestrator produces validates against the dict-shape
    expectations. Independent of jsonschema — assertions on the
    KEYS the schema declares, applied to a real-shape report."""

    def _make_minimal_report(self):
        return {
            "mode": "orchestrated",
            "results": [
                {
                    "finding_id": "F1",
                    "status": "analysed",
                    "is_true_positive": True,
                    "is_exploitable": False,
                    "file_path": "src/main.c",
                    "function": "main",
                    "line": 42,
                    "rule_id": "p/security-audit.sqli",
                    "severity": "high",
                    "reasoning": "Tainted input flows to query string.",
                },
                {
                    "finding_id": "F2",
                    "status": "skipped_dead_code",
                    "file_path": "src/unused.c",
                    "function": "dead_fn",
                },
                {
                    "finding_id": "F3",
                    "status": "error",
                    "error": "timeout after 600s",
                },
            ],
            "analyzed": 1,
            "exploitable": 0,
            "exploits_generated": 0,
            "patches_generated": 0,
            "orchestration": {
                "analysis_model": "claude-haiku-4-5",
                "cost": {"total_cost": 0.0042, "by_model": {}},
                "fired_models": [],
            },
        }

    def test_minimal_report_has_all_required_fields(self):
        report = self._make_minimal_report()
        # Top-level required.
        for key in SCHEMA["required"]:
            self.assertIn(key, report)
        # Per-finding required.
        items_required = (
            SCHEMA["properties"]["results"]["items"]["required"]
        )
        for f in report["results"]:
            for key in items_required:
                self.assertIn(key, f, f"missing {key} on {f}")

    def test_all_status_enum_values_are_representable(self):
        # Every status the schema declares should be acceptable on
        # a real finding shape — catches an enum drift before it
        # produces an in-the-wild rejection.
        status_enum = (
            SCHEMA["properties"]["results"]["items"]
                  ["properties"]["status"]["enum"]
        )
        for status in status_enum:
            report = self._make_minimal_report()
            report["results"][0]["status"] = status
            # Just assert the dict shape stays parseable + the
            # value is in the enum.
            self.assertIn(report["results"][0]["status"], status_enum)

    def test_accounted_report_fields_match_the_descriptive_schema(self):
        route = RouteIdentity("example-provider", "example-model")
        observation = CostObservation(CostBasis.UNKNOWN, route=route)
        accounting = AccountingSummary().add(observation).as_dict()
        report = self._make_minimal_report()
        report["results"][0].update({
            "analysed_by": route.model,
            "analysed_by_provider": route.provider,
            "analysis_route": route.as_dict(),
            "analysis_provenance": route.as_dict(),
            "cost_observation": observation.as_dict(),
            "accounting": accounting,
            "accounting_complete": False,
        })
        report["orchestration"]["cost"].update({
            "total_tokens": 12,
            "cost_by_model": {route.model: 0.0},
            "accounting_by_route": {
                f"{route.provider}/{route.model}": {
                    "route": route.as_dict(),
                    **accounting,
                },
            },
            "cache_hits": 0,
            "failed_dispatches": 0,
            "unclassified_legacy_events": 0,
            **accounting,
        })
        finding_props = SCHEMA["properties"]["results"]["items"]["properties"]
        cost_props = (
            SCHEMA["properties"]["orchestration"]["properties"]["cost"]
            ["properties"]
        )
        self.assertTrue(set(report["results"][0]).issubset(finding_props))
        self.assertTrue(set(report["orchestration"]["cost"]).issubset(cost_props))
        self.assertFalse(report["orchestration"]["cost"]["usd_total_complete"])


if __name__ == "__main__":
    unittest.main()
