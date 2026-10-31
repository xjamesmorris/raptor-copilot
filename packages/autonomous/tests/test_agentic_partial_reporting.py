"""Truthful aggregate reporting for capped and failed-tool runs."""

from __future__ import annotations

from core.json import load_json, save_json
from core.reporting import build_findings_spec, build_findings_summary, render_report
from core.run.safe_io import (
    ARTIFACT_REFERENCE_MAX_BYTES,
    ARTIFACT_REFERENCE_MAX_COUNT,
    ARTIFACT_REFERENCES_MAX_BYTES,
)
from packages.llm_analysis.orchestrator import _build_assessment_summary
from raptor_agentic import (
    _assessment_from_reports,
    _build_run_result,
    _build_tool_execution_report_section,
    _codeql_enrichment_tool_fields,
    _completion_partial_metadata,
    _dispatch_failure_summary,
    _finalize_run_lifecycle,
    _record_tool_failure,
    _result_contract_fields,
    _tool_state,
)


def _complete_assessment(count: int = 10) -> dict:
    return _build_assessment_summary(
        requested=count,
        eligible=count,
        selected=count,
        analyzed=count,
        cap=0,
        cap_source="explicit",
    )

def test_cache_only_sca_is_usable_but_keeps_assessment_partial():
    tools = {
        "semgrep": _tool_state("completed", requested=True, findings=2),
        "codeql": _tool_state("skipped", requested=False),
        "sca": _tool_state(
            "completed", requested=True, findings=1, degraded=True,
            offline=True, reason="offline cache-only advisory coverage",
        ),
    }

    result = _build_run_result(tools, _complete_assessment())
    section = _build_tool_execution_report_section(tools).content

    assert result["status"] == "partial"
    assert result["scanners"]["usable"] == ["semgrep", "sca"]
    assert any(
        reason.startswith("SCA degraded: offline cache-only")
        for reason in result["partial_reasons"]
    )
    assert "SCA | Completed" in section
    assert "offline cache-only" in section


def test_dispatch_failure_summary_keeps_failed_review_beside_success():
    summary = _dispatch_failure_summary({
        "dispatch_batches": [
            {
                "phase": "analysis_primary",
                "succeeded": 0,
                "failed": 3,
                "not_run": 7,
            },
            {
                "phase": "analysis_claude_fallback",
                "succeeded": 10,
                "failed": 0,
                "not_run": 0,
            },
            {
                "phase": "group_analysis",
                "succeeded": 2,
                "failed": 0,
                "not_run": 0,
            },
        ],
    })

    assert summary == {
        "failed": 3,
        "not_run": 7,
        "details": ["analysis_primary: 3 failed, 7 not run"],
    }


def test_codeql_enrichment_warning_does_not_rewrite_standard_success():
    diagnostic = "out/run/codeql/codeql_python_pack_install.json"
    fields = _codeql_enrichment_tool_fields({
        "enrichment_health": {
            "status": "completed",
            "attempted": True,
            "completed": True,
            "failed": False,
            "skipped": False,
            "degraded": True,
            "artifacts": [diagnostic],
            "languages": {
                "python": {
                    "status": "completed",
                    "degraded": True,
                    "install": {"status": "failed", "returncode": 2},
                    "query": {"status": "completed", "returncode": 0},
                },
            },
        },
    })
    enrichment_artifacts = fields.pop("artifacts")
    reason = fields.pop("reason")
    tools = {
        "semgrep": _tool_state(
            "skipped", requested=False, reason="not requested",
        ),
        "codeql": _tool_state(
            "completed",
            requested=True,
            reason=reason,
            artifacts=["out/run/codeql/codeql_report.json",
                       *enrichment_artifacts],
            findings=0,
            **fields,
        ),
        "sca": _tool_state(
            "skipped", requested=False, reason="not requested",
        ),
    }

    result = _build_run_result(tools, _complete_assessment())
    section = _build_tool_execution_report_section(tools).content

    assert tools["codeql"]["status"] == "completed"
    assert tools["codeql"]["failed"] is False
    assert tools["codeql"]["enrichment_status"] == "completed"
    assert tools["codeql"]["enrichment_degraded"] is True
    assert tools["codeql"]["enrichment_artifact"] == diagnostic
    assert diagnostic in tools["codeql"]["artifacts"]
    assert result["status"] == "complete"
    assert result["exit_code"] == 0
    assert "CodeQL | Completed" in section
    assert "install diagnostic warnings" in section


def test_codeql_enrichment_failure_stays_separate_from_scanner_failure():
    fields = _codeql_enrichment_tool_fields({
        "enrichment_health": {
            "status": "failed",
            "attempted": True,
            "completed": False,
            "failed": True,
            "skipped": False,
            "degraded": False,
            "artifacts": ["out/run/codeql/install.diagnostics.json"],
            "languages": {
                "python": {
                    "status": "failed",
                    "install": {"status": "failed", "returncode": 2},
                    "query": {"status": "failed", "returncode": 7},
                },
            },
        },
    })
    enrichment_artifacts = fields.pop("artifacts")
    reason = fields.pop("reason")
    codeql = _tool_state(
        "completed",
        requested=True,
        reason=reason,
        artifacts=["out/run/codeql/codeql_report.json",
                   *enrichment_artifacts],
        findings=0,
        **fields,
    )

    assert codeql["status"] == "completed"
    assert codeql["failed"] is False
    assert codeql["enrichment_status"] == "failed"
    assert "enrichment failed" in codeql["reason"]

    result = _build_run_result(
        {
            "semgrep": _tool_state("skipped", requested=False),
            "codeql": _tool_state(
                "completed", requested=True, reason=codeql["reason"],
                degraded=codeql["enrichment_status"] == "failed",
            ),
            "sca": _tool_state("skipped", requested=False),
        },
        _complete_assessment(),
    )
    assert result["status"] == "partial"
    assert any(
        "CodeQL degraded" in reason
        for reason in result["partial_reasons"]
    )


def test_tool_artifact_references_are_sanitized_and_aggregate_bounded():
    secret = "glpat-MnBvCxZlKjHgFdSaPoIuYtRe"
    hostile = (
        "out/\x1b]0;title\x07/\u202e/"
        + secret
        + "/"
        + "x" * (ARTIFACT_REFERENCE_MAX_BYTES * 2)
    )
    state = _tool_state(
        "completed",
        requested=True,
        artifacts=[
            f"{hostile}-{index}"
            for index in range(ARTIFACT_REFERENCE_MAX_COUNT + 10)
        ],
    )
    refs = state["artifacts"]

    assert len(refs) <= ARTIFACT_REFERENCE_MAX_COUNT
    assert sum(
        len(ref.encode("utf-8")) + (1 if index else 0)
        for index, ref in enumerate(refs)
    ) <= ARTIFACT_REFERENCES_MAX_BYTES
    assert all(
        len(ref.encode("utf-8")) <= ARTIFACT_REFERENCE_MAX_BYTES
        for ref in refs
    )
    assert all("\x1b" not in ref and "\x07" not in ref for ref in refs)
    assert all("\u202e" not in ref for ref in refs)
    assert all(secret not in ref for ref in refs)
    assert state["artifact"] == refs[0]
    assert state["artifact_references_truncated"] is True
    assert state["artifact_references_omitted"] > 0


def test_failure_receipt_is_private_and_refuses_preplanted_symlink(tmp_path):
    out = tmp_path / "codeql"
    receipt = _record_tool_failure(out, "codeql", "hostile\x1b\u202e")

    assert receipt == out / "failure.json"
    assert receipt.stat().st_mode & 0o777 == 0o600
    persisted = load_json(receipt)
    assert persisted["status"] == "failed"
    assert "\x1b" not in persisted["reason"]
    assert "\u202e" not in persisted["reason"]

    target = tmp_path / "target.json"
    target.write_text('{"untouched": true}\n', encoding="utf-8")
    receipt.unlink()
    receipt.symlink_to(target)

    assert _record_tool_failure(out, "codeql", "second failure") is None
    assert target.read_text(encoding="utf-8") == '{"untouched": true}\n'


def test_failure_receipt_write_error_does_not_hide_tool_failure(
    tmp_path, monkeypatch,
):
    def _fail_write(_path, _payload):
        raise PermissionError("receipt directory is read-only")

    monkeypatch.setattr("raptor_agentic.write_private_json", _fail_write)
    receipt = _record_tool_failure(
        tmp_path / "codeql",
        "codeql",
        "database analysis failed",
    )
    state = _tool_state(
        "failed",
        requested=True,
        reason="database analysis failed",
        artifacts=[receipt],
    )

    assert receipt is None
    assert state["status"] == "failed"
    assert state["failure_reason"] == "database analysis failed"
    assert state["artifacts"] == []


def test_semgrep_success_codeql_failure_is_usable_partial():
    tools = {
        "semgrep": _tool_state(
            "completed",
            requested=True,
            artifacts=["out/run/scan/combined.sarif"],
            findings=0,
        ),
        "codeql": _tool_state(
            "failed",
            requested=True,
            reason=(
                "database create failed\x1b]0;unsafe\x07 "
                + ("detail " * 100)
            ),
            artifacts=["out/run/codeql/failure.json"],
            findings=None,
        ),
        "sca": _tool_state(
            "skipped",
            requested=False,
            reason="not requested",
            findings=0,
        ),
    }

    result = _build_run_result(tools, _complete_assessment())
    lifecycle = _completion_partial_metadata(
        result, _complete_assessment(), tools,
    )
    section = _build_tool_execution_report_section(tools).content

    assert result["status"] == "partial"
    assert result["exit_code"] == 0
    assert "usable aggregate output" in result["exit_code_contract"]
    assert result["scanners"]["usable"] == ["semgrep"]
    assert result["scanners"]["failed"] == ["codeql"]
    assert lifecycle["result_status"] == "partial"
    assert lifecycle["tool_failures"]["codeql"]["artifact"].endswith(
        "codeql/failure.json"
    )
    assert "Semgrep | Completed" in section
    assert "CodeQL | Failed" in section
    assert "CodeQL | Failed | yes | unknown" in section
    assert "\x1b" not in section
    assert "\x07" not in section
    assert len(tools["codeql"]["failure_reason"]) <= 300


def test_sca_timeout_is_failed_not_disabled_or_clean():
    tools = {
        "semgrep": _tool_state(
            "completed", requested=True, findings=4,
        ),
        "codeql": _tool_state(
            "skipped", requested=False, reason="not requested", findings=0,
        ),
        "sca": _tool_state(
            "failed",
            requested=True,
            reason=(
                "exit code 124: sca-agent timed out after 600s during "
                "llm-review (running LLM behavioural review)"
            ),
            artifacts=[
                "out/run/sca/failure.json",
                "out/run/sca/stderr.log",
                "out/run/sca/diagnostics.json",
            ],
            findings=None,
            timed_out=True,
            disposition="failed",
            diagnostic_status="timed_out",
            phase="llm-review",
            phase_description="running LLM behavioural review",
            analysis_mode="mechanical",
        ),
    }

    result = _build_run_result(tools, _complete_assessment())
    sca = tools["sca"]
    section = _build_tool_execution_report_section(tools).content

    assert sca["requested"] is True
    assert sca["enabled"] is True
    assert sca["attempted"] is True
    assert sca["completed"] is False
    assert sca["failed"] is True
    assert sca["skipped"] is False
    assert "timed out after 600s" in sca["failure_reason"]
    assert sca["disposition"] == "failed"
    assert sca["diagnostic_status"] == "timed_out"
    assert sca["phase"] == "llm-review"
    assert sca["analysis_mode"] == "mechanical"
    assert result["status"] == "partial"
    assert "SCA | Failed" in section
    assert "SCA | Failed | yes | unknown" in section
    assert "llm-review" in section
    assert "SCA | Skipped" not in section


def test_all_requested_scanners_failed_is_failed_exit_one():
    tools = {
        "semgrep": _tool_state(
            "failed", requested=True, reason="timeout", findings=None,
        ),
        "codeql": _tool_state(
            "failed", requested=True, reason="database failed", findings=None,
        ),
        "sca": _tool_state(
            "skipped", requested=False, reason="not requested", findings=0,
        ),
    }

    result = _build_run_result(tools, _complete_assessment())

    assert result["status"] == "failed"
    assert result["partial"] is False
    assert result["failed"] is True
    assert result["usable_output"] is False
    assert result["exit_code"] == 1
    assert result["pipeline_execution"] == "failed"
    assert result["failure_reason"] == "all requested scanners failed"
    assert result["scanners"]["all_requested_failed"] is True
    assert result["scanners"]["usable"] == []


def test_semgrep_timeout_without_artifact_is_hard_failure():
    tools = {
        "semgrep": _tool_state(
            "failed",
            requested=True,
            reason="timed out after 600s",
            artifacts=[],
            findings=None,
            timed_out=True,
        ),
        "codeql": _tool_state(
            "skipped", requested=False, reason="not requested", findings=0,
        ),
        "sca": _tool_state(
            "skipped", requested=False, reason="not requested", findings=0,
        ),
    }

    result = _build_run_result(tools, _complete_assessment())

    assert "artifact" not in tools["semgrep"]
    assert result["status"] == "failed"
    assert result["exit_code"] == 1


def test_requested_skipped_scanner_keeps_usable_partial_truthful():
    tools = {
        "semgrep": _tool_state(
            "completed", requested=True, findings=0,
        ),
        "codeql": _tool_state(
            "skipped",
            requested=True,
            reason="tool unavailable",
            findings=None,
        ),
        "sca": _tool_state(
            "skipped", requested=False, reason="not requested", findings=0,
        ),
    }

    result = _build_run_result(tools, _complete_assessment())

    assert result["status"] == "partial"
    assert result["exit_code"] == 0
    assert result["scanners"]["usable"] == ["semgrep"]
    assert result["scanners"]["skipped"] == ["codeql"]
    assert result["scanners"]["not_requested"] == ["sca"]


def test_import_only_skipped_tools_do_not_trigger_all_failed():
    tools = {
        name: _tool_state(
            "skipped",
            requested=False,
            reason="replaced by imported SARIF",
            findings=0,
        )
        for name in ("semgrep", "codeql", "sca")
    }

    result = _build_run_result(tools, _complete_assessment())

    assert result["status"] == "complete"
    assert result["exit_code"] == 0
    assert result["scanners"]["requested"] == []
    assert result["scanners"]["all_requested_failed"] is False
    assert result["scanners"]["not_requested"] == [
        "semgrep", "codeql", "sca",
    ]


def test_import_and_openant_only_ignore_additive_sca_as_exit_requirement():
    for mode in ("imported-SARIF-only", "openant-only"):
        tools = {
            "semgrep": _tool_state(
                "skipped",
                requested=False,
                reason=f"{mode}: primary scanner not requested",
            ),
            "codeql": _tool_state(
                "skipped",
                requested=False,
                reason=f"{mode}: primary scanner not requested",
            ),
            "sca": {
                **_tool_state(
                    "failed",
                    requested=True,
                    reason="registry unavailable",
                    findings=None,
                ),
                "required_for_success": False,
            },
        }

        result = _build_run_result(tools, _complete_assessment())

        assert result["status"] == "partial", mode
        assert result["exit_code"] == 0, mode
        assert result["failed"] is False, mode
        assert result["failure_reason"] is None, mode
        assert result["scanners"]["required_for_success"] == [], mode
        assert "SCA failed" in " ".join(result["partial_reasons"]), mode


def test_capped_10_of_370_records_360_unreviewed():
    assessment = _build_assessment_summary(
        requested=370,
        eligible=370,
        selected=10,
        analyzed=10,
        cap=10,
        cap_source="provider_default",
    )

    assert assessment == {
        "status": "partial",
        "requested": 370,
        "eligible": 370,
        "selected": 10,
        "analyzed": 10,
        "unreviewed": 360,
        "unselected": 360,
        "analysis_failures": 0,
        "not_eligible": 0,
        "cap": 10,
        "cap_applied": True,
        "cap_source": "provider_default",
        "cap_reason": "provider default cap",
        "reason": "provider default cap",
    }


def test_explicit_cap_records_explicit_selection_reason():
    assessment = _build_assessment_summary(
        requested=370,
        eligible=370,
        selected=10,
        analyzed=10,
        cap=10,
        cap_source="explicit",
    )

    assert assessment["status"] == "partial"
    assert assessment["cap_applied"] is True
    assert assessment["cap_source"] == "explicit"
    assert assessment["cap_reason"] == "explicit --max-findings cap"


def test_explicit_uncapped_full_assessment_remains_complete():
    assessment = _build_assessment_summary(
        requested=370,
        eligible=370,
        selected=370,
        analyzed=370,
        cap=0,
        cap_source="explicit",
    )

    assert assessment["status"] == "complete"
    assert assessment["unreviewed"] == 0
    assert assessment["cap_applied"] is False
    assert assessment["cap_reason"] is None


def test_provider_default_uncapped_full_assessment_remains_complete():
    assessment = _build_assessment_summary(
        requested=370,
        eligible=370,
        selected=370,
        analyzed=370,
        cap=0,
        cap_source="provider_default",
    )

    assert assessment["status"] == "complete"
    assert assessment["cap"] == 0
    assert assessment["cap_applied"] is False
    assert assessment["cap_source"] == "provider_default"
    assert assessment["cap_reason"] is None


def test_report_fallback_preserves_provider_explicit_and_uncapped_caps():
    provider_default = _assessment_from_reports(
        validated_findings=370,
        analysis={"mode": "full", "processed": 10, "analyzed": 10},
        orchestration_result=None,
        max_findings=None,
        llm_available=True,
    )
    explicit = _assessment_from_reports(
        validated_findings=370,
        analysis={"mode": "full", "processed": 10, "analyzed": 10},
        orchestration_result=None,
        max_findings=10,
        llm_available=True,
    )
    uncapped = _assessment_from_reports(
        validated_findings=370,
        analysis={"mode": "full", "processed": 370, "analyzed": 370},
        orchestration_result=None,
        max_findings=0,
        llm_available=True,
    )

    assert provider_default["cap_source"] == "provider_default"
    assert provider_default["cap"] == 10
    assert provider_default["cap_reason"] == "provider default cap"
    assert explicit["cap_source"] == "explicit"
    assert explicit["cap"] == 10
    assert explicit["cap_reason"] == "explicit --max-findings cap"
    assert uncapped["status"] == "complete"
    assert uncapped["cap_source"] == "explicit"
    assert uncapped["cap"] == 0
    assert uncapped["cap_applied"] is False


def test_all_mechanically_skipped_prep_has_no_analysis_backlog():
    assessment = _assessment_from_reports(
        validated_findings=3,
        analysis={
            "mode": "prep_only",
            "processed": 3,
            # Prep counters include mechanically resolved records, but
            # their explicit statuses make them ineligible for LLM work.
            "analyzed": 3,
            "results": [
                {
                    "finding_id": "dead",
                    "status": "skipped_dead_code",
                    "skip_reason": "binary_oracle_absent",
                },
                {
                    "finding_id": "fixture",
                    "status": "skipped",
                    "skip_reason": "fixture_demotion",
                },
                {
                    "finding_id": "filtered",
                    "status": "skipped_filtered",
                    "skip_reason": "operator filter",
                },
            ],
        },
        orchestration_result=None,
        max_findings=None,
        llm_available=True,
    )

    assert assessment == {
        "status": "complete",
        "requested": 3,
        "eligible": 0,
        "selected": 0,
        "analyzed": 0,
        "unreviewed": 0,
        "unselected": 0,
        "analysis_failures": 0,
        "not_eligible": 3,
        "cap": 0,
        "cap_applied": False,
        "cap_source": "provider_default",
        "cap_reason": None,
        "reason": None,
    }


def test_persisted_report_and_partial_lifecycle_are_additive(
    tmp_path, monkeypatch,
):
    tools = {
        "semgrep": _tool_state(
            "completed", requested=True, findings=0,
        ),
        "codeql": _tool_state(
            "failed", requested=True, reason="database failed", findings=None,
        ),
        "sca": _tool_state(
            "skipped", requested=False, reason="not requested", findings=0,
        ),
    }
    assessment = _complete_assessment()
    result = _build_run_result(tools, assessment)
    report = {
        "timestamp": "legacy",
        "tools_used": {"semgrep": True, "codeql": True, "sca": False},
        "phases": {
            "scanning": {
                "semgrep": {"enabled": True, "findings": 0},
                "codeql": {"enabled": True, "findings": None},
            },
        },
        "legacy_extension": {"preserve": True},
        "verdicts": build_findings_summary([
            {
                "finding_id": "typed-negative",
                "is_true_positive": False,
                "ruling": "test_code",
            },
        ]),
    }
    report.update(_result_contract_fields(result, assessment))
    report_path = tmp_path / "raptor_agentic_report.json"
    save_json(report_path, report)

    persisted = load_json(report_path, strict=True)
    assert persisted["timestamp"] == "legacy"
    assert persisted["tools_used"]["semgrep"] is True
    assert persisted["phases"]["scanning"]["semgrep"] == {
        "enabled": True,
        "findings": 0,
    }
    assert persisted["legacy_extension"] == {"preserve": True}
    assert persisted["result"]["status"] == "partial"
    assert persisted["assessment"]["status"] == "complete"
    assert persisted["verdicts"]["false_positive"] == 0
    assert persisted["verdicts"]["false_positive_exact"] == 0
    assert persisted["verdicts"]["negative_total"] == 1
    assert persisted["verdicts"]["test_code"] == 1

    def fake_complete(out_dir, extra=None, manifest=None):
        save_json(out_dir / ".raptor-run.json", {
            "status": "completed",
            "extra": extra,
            "manifest": manifest,
        })

    def unexpected_fail(*_args, **_kwargs):
        raise AssertionError("usable partial output must not fail lifecycle")

    monkeypatch.setattr("core.run.complete_run", fake_complete)
    monkeypatch.setattr("core.run.fail_run", unexpected_fail)
    lifecycle_extra = {
        "legacy_marker": "kept",
        **_completion_partial_metadata(result, assessment, tools),
    }
    lifecycle_status = _finalize_run_lifecycle(
        tmp_path,
        result,
        extra=lifecycle_extra,
        manifest={"models": []},
    )
    lifecycle = load_json(tmp_path / ".raptor-run.json", strict=True)

    assert lifecycle_status == "completed"
    assert lifecycle["status"] == "completed"
    assert lifecycle["extra"]["legacy_marker"] == "kept"
    assert lifecycle["extra"]["result_status"] == "partial"
    assert lifecycle["extra"]["exit_code"] == 0


def test_persisted_all_failed_lifecycle_is_failed(tmp_path, monkeypatch):
    tools = {
        "semgrep": _tool_state(
            "failed", requested=True, reason="timeout", findings=None,
        ),
        "codeql": _tool_state(
            "failed", requested=True, reason="database failed", findings=None,
        ),
        "sca": _tool_state(
            "skipped", requested=False, reason="not requested", findings=0,
        ),
    }
    assessment = _complete_assessment()
    result = _build_run_result(tools, assessment)

    def unexpected_complete(*_args, **_kwargs):
        raise AssertionError("all-failed output must not complete lifecycle")

    def fake_fail(out_dir, error=None, extra=None):
        save_json(out_dir / ".raptor-run.json", {
            "status": "failed",
            "error": error,
            "extra": extra,
        })

    monkeypatch.setattr("core.run.complete_run", unexpected_complete)
    monkeypatch.setattr("core.run.fail_run", fake_fail)
    lifecycle_extra = _completion_partial_metadata(
        result, assessment, tools,
    )
    lifecycle_status = _finalize_run_lifecycle(
        tmp_path,
        result,
        extra=lifecycle_extra,
        manifest={"models": []},
    )
    lifecycle = load_json(tmp_path / ".raptor-run.json", strict=True)

    assert lifecycle_status == "failed"
    assert lifecycle["status"] == "failed"
    assert lifecycle["error"] == "all requested scanners failed"
    assert lifecycle["extra"]["result_status"] == "failed"
    assert lifecycle["extra"]["partial"] is False
    assert lifecycle["extra"]["exit_code"] == 1


def test_agentic_verdict_distribution_preserves_typed_negative_rulings():
    findings = [
        {
            "finding_id": f"fp-{index}",
            "is_true_positive": False,
            "ruling": "false_positive",
        }
        for index in range(6)
    ]
    findings.append({
        "finding_id": "mitigated-1",
        "is_true_positive": False,
        "ruling": "mitigated",
    })
    findings.extend({
        "finding_id": f"test-{index}",
        "is_true_positive": False,
        "ruling": "test_code",
    } for index in range(3))

    counts = build_findings_summary(findings)
    markdown = render_report(build_findings_spec(findings))

    assert counts["false_positive"] == 6
    assert counts["false_positive_exact"] == 6
    assert counts["negative_total"] == 10
    assert counts["mitigated"] == 1
    assert counts["test_code"] == 3
    assert "| False Positive | 6 |" in markdown
    assert "| Mitigated | 1 |" in markdown
    assert "| Test Code | 3 |" in markdown
    assert markdown.count("| False Positive | — | — |") == 6
    assert markdown.count("| Mitigated | — | — |") == 1
    assert markdown.count("| Test Code | — | — |") == 3
