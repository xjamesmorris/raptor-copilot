"""Copilot-native /agentic handoff artifact contract."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.json import load_json, save_json
from core.run.metadata import (
    RUN_METADATA_FILE,
    interrupt_run,
    load_run_metadata,
    start_run,
)
from packages.llm_analysis.copilot_native import (
    AUDIT_RECEIPT_SCHEMA,
    CONTEXT_RECEIPT_SCHEMA,
    CopilotNativeError,
    MANIFEST_SCHEMA,
    MODEL_CONTRIBUTION_SCHEMA,
    MODEL_RECEIPT_SCHEMA,
    PART_SCHEMA,
    attach_audit_handoff,
    attach_context_handoff,
    finalize_handoff,
    lint_part,
    lint_model_contribution,
    main,
    prepare_handoff,
    seal_model_part,
)
from packages.llm_analysis.validation import check_self_contradiction


def _finding(finding_id: str = "FIND-001") -> dict:
    return {
        "finding_id": finding_id,
        "rule_id": "fixture.rule",
        "file_path": "src/main.py",
        "start_line": 7,
        "message": "fixture finding",
        "code": "dangerous(value)",
        "surrounding_context": "def handler(value): dangerous(value)",
        "has_dataflow": False,
    }


def _analysis(finding_id: str = "FIND-001") -> dict:
    return {
        "finding_id": finding_id,
        "reasoning": "The sink receives a constant in the fixture path.",
        "attack_scenario": None,
        "exploit_code": None,
        "patch_code": None,
        "cvss_vector": None,
        "cvss_score_estimate": None,
        "vuln_type": "command_injection",
        "cwe_id": "CWE-78",
        "dataflow_summary": "constant -> sink",
        "remediation": "Keep the value constant or validate it.",
        "false_positive_reason": "No attacker-controlled source reaches the sink.",
        "tool": "copilot-native",
        "rule_id": "fixture.rule",
        "severity_assessment": "low",
        "exploitability_score": 0.0,
        "confidence": "high",
        "ruling": "false_positive",
        "is_true_positive": False,
        "is_exploitable": False,
    }


def _base_report(run_dir: Path, target: Path, prep: Path) -> dict:
    tool = {
        "status": "completed",
        "requested": True,
        "attempted": True,
        "completed": True,
        "failed": False,
        "skipped": False,
        "findings": 1,
        "artifacts": [],
    }
    return {
        "timestamp": "2026-10-20T00:00:00Z",
        "repository": str(target),
        "duration_seconds": 1.0,
        "phases": {
            "scanning": {
                "status": "completed",
                "total_findings": 1,
                "semgrep": dict(tool),
                "codeql": {
                    "status": "skipped",
                    "requested": False,
                    "attempted": False,
                    "completed": False,
                    "failed": False,
                    "skipped": True,
                    "findings": 0,
                    "artifacts": [],
                },
            },
            "sca": {
                "status": "skipped",
                "requested": False,
                "attempted": False,
                "completed": False,
                "failed": False,
                "skipped": True,
                "findings": 0,
                "artifacts": [],
            },
            "exploitability_validation": {
                "completed": True,
                "validated_findings": 1,
            },
            "autonomous_analysis": {
                "completed": False,
                "prepared": True,
                "mode": "prep_only",
            },
            "orchestration": {
                "completed": False,
                "mode": "copilot_native_pending",
            },
        },
        "outputs": {
            "autonomous_report": str(prep),
            "orchestrated_report": None,
        },
    }


def _prepared_run(
    tmp_path: Path,
    *,
    count: int = 1,
    validate_postpass: bool = False,
    allow_unreachable: bool = False,
    context_handoff_factory=None,
    audit_policy: dict | None = None,
    model_plan: dict | None = None,
    sequential: bool = False,
):
    target = tmp_path / "target"
    target.mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    autonomous = run_dir / "autonomous"
    autonomous.mkdir()
    prep = autonomous / "autonomous_analysis_report.json"
    save_json(prep, {
        "mode": "prep_only",
        "processed": count,
        "results": [_finding(f"FIND-{index:03d}") for index in range(1, count + 1)],
    })
    start_run(run_dir, "agentic", target=str(target))
    save_json(run_dir / "raptor_agentic_report.json", _base_report(
        run_dir, target, prep,
    ))
    context_handoff = (
        context_handoff_factory(target, run_dir)
        if context_handoff_factory is not None
        else None
    )
    manifest = prepare_handoff(
        run_dir=run_dir,
        repo_path=target,
        prep_report_path=prep,
        max_findings=0,
        batch_size=2,
        no_journal=True,
        validate_postpass=validate_postpass,
        allow_unreachable=allow_unreachable,
        context_handoff=context_handoff,
        audit_policy=audit_policy,
        model_plan=model_plan,
        sequential=sequential,
    )
    interrupt_run(
        run_dir,
        reason="awaiting host-managed Copilot analysis",
        expected_command="agentic",
    )
    return target, run_dir, prep, manifest


def _write_parts(manifest_path: Path) -> None:
    manifest = load_json(manifest_path, strict=True)
    assert isinstance(manifest, dict)
    manifest_sha = __import__("hashlib").sha256(
        manifest_path.read_bytes(),
    ).hexdigest()
    for part in manifest["parts"]:
        save_json(Path(part["result_path"]), {
            "schema": PART_SCHEMA,
            "manifest_sha256": manifest_sha,
            "part_id": part["part_id"],
            "results": [
                _analysis(finding_id)
                for finding_id in part["finding_ids"]
            ],
        })


def _write_model_contributions(manifest_path: Path) -> None:
    manifest = load_json(manifest_path, strict=True)
    manifest_sha = __import__("hashlib").sha256(
        manifest_path.read_bytes(),
    ).hexdigest()
    for part in manifest["parts"]:
        for task in part.get("model_tasks", []):
            save_json(Path(task["result_path"]), {
                "schema": MODEL_CONTRIBUTION_SCHEMA,
                "manifest_sha256": manifest_sha,
                "part_id": part["part_id"],
                "task_id": task["task_id"],
                "role": task["role"],
                "model": task["model"],
                "results": [
                    _analysis(finding_id)
                    for finding_id in part["finding_ids"]
                ],
            })


def test_prepare_writes_non_overlapping_bound_parts(tmp_path):
    _, _, _, manifest_path = _prepared_run(tmp_path, count=3)
    manifest = load_json(manifest_path, strict=True)

    assert manifest["schema"] == MANIFEST_SCHEMA
    assert manifest["selected_findings"] == 3
    assert [part["finding_ids"] for part in manifest["parts"]] == [
        ["FIND-001", "FIND-002"],
        ["FIND-003"],
    ]
    for part in manifest["parts"]:
        request = load_json(Path(part["request_path"]), strict=True)
        assert request["finding_ids"] == part["finding_ids"]
        assert request["result_path"] == part["result_path"]


def test_prepare_sequential_forces_one_host_task(tmp_path):
    _, _, _, manifest_path = _prepared_run(
        tmp_path,
        count=3,
        sequential=True,
    )
    manifest = load_json(manifest_path, strict=True)

    assert manifest["sequential"] is True
    assert manifest["max_parallel"] == 1


def test_multi_model_contributions_require_seal_and_retain_provenance(
    tmp_path,
):
    plan = {
        "enabled": True,
        "analysis_models": ["model-a", "model-b"],
        "consensus_model": "model-c",
        "judge_model": "model-d",
        "aggregate_model": "model-e",
        "canonical_model": "model-e",
    }
    _, run_dir, _, manifest_path = _prepared_run(
        tmp_path,
        model_plan=plan,
    )
    manifest = load_json(manifest_path, strict=True)
    part = manifest["parts"][0]
    roles = [task["role"] for task in part["model_tasks"]]
    assert roles == [
        "analysis",
        "analysis",
        "consensus",
        "judge",
        "aggregate",
    ]
    judge = next(
        task for task in part["model_tasks"]
        if task["role"] == "judge"
    )
    assert judge["depends_on"] == [
        "analysis-01",
        "analysis-02",
        "consensus-01",
    ]
    aggregate = next(
        task for task in part["model_tasks"]
        if task["role"] == "aggregate"
    )
    assert aggregate["depends_on"][-1] == "judge-01"

    _write_parts(manifest_path)
    with pytest.raises(CopilotNativeError, match="model receipt"):
        lint_part(manifest_path, Path(part["result_path"]))

    _write_model_contributions(manifest_path)
    for task in part["model_tasks"]:
        lint_model_contribution(
            manifest_path,
            Path(task["result_path"]),
        )
    receipt = seal_model_part(manifest_path, part["part_id"])

    assert receipt["schema"] == MODEL_RECEIPT_SCHEMA
    assert receipt["canonical_model"] == "model-e"
    assert len(receipt["contributions"]) == 5
    lint_part(manifest_path, Path(part["result_path"]))
    first_request = Path(part["model_tasks"][0]["request_path"])
    original_request = first_request.read_bytes()
    first_request.write_text("{}")
    with pytest.raises(
        CopilotNativeError,
        match="model receipt contribution mismatch",
    ):
        lint_part(manifest_path, Path(part["result_path"]))
    first_request.write_bytes(original_request)
    finalized = finalize_handoff(manifest_path)

    orchestrated = load_json(
        run_dir / "orchestrated_report.json",
        strict=True,
    )
    result = orchestrated["results"][0]
    assert result["analysed_by"] == "model-e"
    assert len(result["multi_model_analyses"]) == 5
    assert result["model_execution"]["canonical_model"] == "model-e"
    assert orchestrated["orchestration"]["multi_model"] is True
    assert orchestrated["orchestration"]["analysis_models"] == [
        "model-a",
        "model-b",
    ]
    assert orchestrated["orchestration"]["aggregate_models"] == [
        "model-e",
    ]
    metadata = load_run_metadata(run_dir)
    assert [row["role"] for row in metadata["manifest"]["models"]] == [
        "analysis",
        "analysis",
        "consensus",
        "judge",
        "aggregate",
    ]
    assert finalized["assessment"]["analyzed"] == 1


def test_context_attachment_gates_lint_and_finalization(tmp_path):
    from core.inventory import save_checklist
    from core.orchestration import prepare_native_context_prepass
    from core.run.metadata import complete_run, start_run

    understand_dir = tmp_path / "understand"

    def fake_start(_command, target, parent_run_dir=None):
        assert Path(parent_run_dir) == tmp_path / "run"
        start_run(understand_dir, "understand", target=str(target))
        return MagicMock(run_dir=understand_dir.resolve(), error=None)

    def context_factory(target, run_dir):
        target_file = target / "src" / "main.py"
        target_file.parent.mkdir(parents=True)
        target_file.write_text("def handler(value):\n    return value\n")
        save_checklist(run_dir, {
            "target_path": str(target),
            "files": [{
                "path": "src/main.py",
                "items": [{
                    "name": "handler",
                    "kind": "function",
                    "line_start": 1,
                    "line_end": 2,
                }],
            }],
        })
        return prepare_native_context_prepass(
            target=target,
            agentic_out_dir=run_dir,
            threat_model_requested=True,
        ).to_dict()

    with patch(
        "core.orchestration.agentic_passes.start_lifecycle",
        side_effect=fake_start,
    ):
        _, run_dir, _, manifest_path = _prepared_run(
            tmp_path,
            context_handoff_factory=context_factory,
        )

    manifest = load_json(manifest_path, strict=True)
    request = load_json(
        Path(manifest["parts"][0]["request_path"]),
        strict=True,
    )
    assert request["context_receipt"] == str(
        run_dir / "copilot-native" / "context-receipt.json",
    )
    _write_parts(manifest_path)
    with pytest.raises(CopilotNativeError, match="context receipt"):
        lint_part(
            manifest_path,
            Path(manifest["parts"][0]["result_path"]),
        )

    save_json(understand_dir / "context-map.json", {
        "meta": {"target": str(manifest["target"])},
        "sources": [],
        "sinks": [],
        "trust_boundaries": [],
        "entry_points": [{
            "id": "EP-001",
            "name": "handler",
            "file": "src/main.py",
            "line": 1,
        }],
        "sink_details": [],
        "unchecked_flows": [],
    })
    start_run(
        understand_dir,
        "understand",
        target=str(manifest["target"]),
    )
    complete_run(understand_dir)

    threat_model_path = run_dir / "threat-model.json"
    threat_model_path.write_text("{}")
    threat_summary = {
        "completed": True,
        "threat_model_json": str(threat_model_path),
        "generated_candidates": 0,
    }
    with patch(
        "raptor_agentic._materialise_threat_model_phase",
        return_value=threat_summary,
    ) as materialise:
        receipt = attach_context_handoff(manifest_path)
        reused = attach_context_handoff(manifest_path)

    assert receipt["schema"] == CONTEXT_RECEIPT_SCHEMA
    assert reused == receipt
    assert receipt["threat_model_requested"] is True
    assert receipt["threat_model_summary"] == threat_summary
    assert receipt["checklist_enriched"] is True
    materialise.assert_called_once()
    context_map_path = understand_dir / "context-map.json"
    original_context_map = context_map_path.read_bytes()
    context_map_path.write_text('{"entry_points": []}')
    with pytest.raises(CopilotNativeError, match="context map changed"):
        lint_part(
            manifest_path,
            Path(manifest["parts"][0]["result_path"]),
        )
    context_map_path.write_bytes(original_context_map)
    lint_part(
        manifest_path,
        Path(manifest["parts"][0]["result_path"]),
    )
    finalized = finalize_handoff(manifest_path)
    final_receipt = load_json(
        run_dir / "copilot-native" / "finalization-receipt.json",
        strict=True,
    )
    assert final_receipt["context_receipt"]["context_map_sha256"] == (
        receipt["context_map_sha256"]
    )
    assert finalized["run_dir"] == str(run_dir)


def test_gap_audit_defers_then_feeds_native_validation(tmp_path):
    from core.inventory import save_checklist
    from core.orchestration import prepare_native_context_prepass
    from core.run.metadata import complete_run, start_run

    understand_dir = tmp_path / "understand"
    audit_dir = tmp_path / "audit"
    validate_dir = tmp_path / "validate"

    def fake_start(command, target, parent_run_dir=None):
        run_dir = {
            "understand": understand_dir,
            "audit": audit_dir,
            "validate": validate_dir,
        }[command]
        start_run(run_dir, command, target=str(target))
        return MagicMock(run_dir=run_dir.resolve(), error=None)

    def context_factory(target, run_dir):
        target_file = target / "src" / "main.py"
        target_file.parent.mkdir(parents=True)
        target_file.write_text("def handler(value):\n    return value\n")
        save_checklist(run_dir, {
            "target_path": str(target),
            "files": [{
                "path": "src/main.py",
                "items": [{
                    "name": "handler",
                    "kind": "function",
                    "line_start": 1,
                    "line_end": 2,
                }],
            }],
        })
        return prepare_native_context_prepass(
            target=target,
            agentic_out_dir=run_dir,
        ).to_dict()

    policy = {
        "enabled": True,
        "validate_after": True,
        "budget": 10,
        "strategy": "general",
        "scopes": [],
        "schedule": "priority",
        "no_adversarial": True,
        "reserved_cost_usd": None,
        "parent_max_cost_usd": None,
        "binary": [],
        "binary_auto": False,
        "no_binary_oracle": False,
        "codeql_dbs": [],
        "prior_journals": [],
        "coverage_policy": "map_grade_is_not_review",
    }
    with patch(
        "core.orchestration.agentic_passes.start_lifecycle",
        side_effect=fake_start,
    ):
        _, run_dir, _, manifest_path = _prepared_run(
            tmp_path,
            validate_postpass=True,
            context_handoff_factory=context_factory,
            audit_policy=policy,
        )
        manifest = load_json(manifest_path, strict=True)
        save_json(understand_dir / "context-map.json", {
            "meta": {"target": str(manifest["target"])},
            "sources": [],
            "sinks": [],
            "trust_boundaries": [],
            "entry_points": [{
                "id": "EP-001",
                "name": "handler",
                "file": "src/main.py",
                "line": 1,
            }],
            "sink_details": [],
            "unchecked_flows": [],
        })
        start_run(
            understand_dir,
            "understand",
            target=str(manifest["target"]),
        )
        complete_run(understand_dir)
        attach_context_handoff(manifest_path)
        _write_parts(manifest_path)

        first = finalize_handoff(manifest_path)

        assert first["audit_postpass"]["prepared"] is True
        assert first["validation_postpass"]["deferred"] is True
        assert not validate_dir.exists()

        save_json(audit_dir / "audit-report.json", {
            "stats": {"reviewed": 1, "finding": 1},
            "findings_count": 1,
            "gaps_remaining": 0,
        })
        save_json(audit_dir / "findings.json", {
            "findings": [{
                "id": "AUDIT-001",
                "file": "src/main.py",
                "line": 1,
                "description": "Tool-confirmed audit finding",
                "status": "finding",
                "confidence": "high",
            }],
        })
        start_run(audit_dir, "audit", target=str(manifest["target"]))
        complete_run(audit_dir)
        audit_receipt = attach_audit_handoff(manifest_path)

        second = finalize_handoff(manifest_path)

    assert audit_receipt["schema"] == AUDIT_RECEIPT_SCHEMA
    assert audit_receipt["findings_count"] == 1
    assert audit_receipt["stats"]["reviewed"] == 1
    assert audit_receipt["gaps_remaining"] == 0
    attached_report = load_json(
        audit_dir / "audit-report.json",
        strict=True,
    )
    assert attached_report["completeness"]["run_status"] == "completed"
    assert attached_report["completeness"]["resumable"] is False
    assert second["audit_postpass"]["completed"] is True
    assert second["audit_postpass"]["reviewed"] == 1
    assert second["audit_postpass"]["gaps_remaining"] == 0
    parent_report = (run_dir / "agentic-report.md").read_text(
        encoding="utf-8",
    )
    assert "Functions reviewed: **1**" in parent_report
    assert "Gaps remaining: **0**" in parent_report
    assert second["validation_postpass"]["prepared"] is True
    selection = load_json(
        Path(second["validation_postpass"]["selection_file"]),
        strict=True,
    )
    assert [row["id"] for row in selection["findings"]][0] == "AUDIT-001"
    final_receipt = load_json(
        run_dir / "copilot-native" / "finalization-receipt.json",
        strict=True,
    )
    assert final_receipt["audit_postpass"]["completed"] is True


def test_lint_rejects_unassigned_result(tmp_path):
    _, _, _, manifest_path = _prepared_run(tmp_path)
    manifest = load_json(manifest_path, strict=True)
    part = manifest["parts"][0]
    manifest_sha = __import__("hashlib").sha256(
        manifest_path.read_bytes(),
    ).hexdigest()
    save_json(Path(part["result_path"]), {
        "schema": PART_SCHEMA,
        "manifest_sha256": manifest_sha,
        "part_id": part["part_id"],
        "results": [_analysis("OTHER")],
    })

    with pytest.raises(CopilotNativeError, match="assignment mismatch"):
        lint_part(manifest_path, Path(part["result_path"]))


def test_lint_requires_exploit_and_patch_for_exploitable_result(tmp_path):
    _, _, _, manifest_path = _prepared_run(tmp_path)
    manifest = load_json(manifest_path, strict=True)
    part = manifest["parts"][0]
    manifest_sha = __import__("hashlib").sha256(
        manifest_path.read_bytes(),
    ).hexdigest()
    result = _analysis()
    result.update({
        "false_positive_reason": None,
        "ruling": "validated",
        "is_true_positive": True,
        "is_exploitable": True,
        "exploitability_score": 0.9,
    })
    save_json(Path(part["result_path"]), {
        "schema": PART_SCHEMA,
        "manifest_sha256": manifest_sha,
        "part_id": part["part_id"],
        "results": [result],
    })

    with pytest.raises(CopilotNativeError, match="needs exploit_code"):
        lint_part(manifest_path, Path(part["result_path"]))


def test_lint_requires_unified_diff_patch_for_exploitable_result(tmp_path):
    _, _, _, manifest_path = _prepared_run(tmp_path)
    manifest = load_json(manifest_path, strict=True)
    part = manifest["parts"][0]
    manifest_sha = __import__("hashlib").sha256(
        manifest_path.read_bytes(),
    ).hexdigest()
    result = _analysis()
    result.update({
        "false_positive_reason": None,
        "ruling": "validated",
        "is_true_positive": True,
        "is_exploitable": True,
        "exploitability_score": 0.9,
        "exploit_code": "print('bounded proof')",
        "patch_code": "replace the unwrap with an error return",
    })
    save_json(Path(part["result_path"]), {
        "schema": PART_SCHEMA,
        "manifest_sha256": manifest_sha,
        "part_id": part["part_id"],
        "results": [result],
    })

    with pytest.raises(CopilotNativeError, match="must be a unified diff"):
        lint_part(manifest_path, Path(part["result_path"]))


def test_lint_rejects_unified_diff_that_does_not_apply(tmp_path):
    _, _, _, manifest_path = _prepared_run(tmp_path)
    manifest = load_json(manifest_path, strict=True)
    part = manifest["parts"][0]
    manifest_sha = __import__("hashlib").sha256(
        manifest_path.read_bytes(),
    ).hexdigest()
    result = _analysis()
    result.update({
        "false_positive_reason": None,
        "ruling": "validated",
        "is_true_positive": True,
        "is_exploitable": True,
        "exploitability_score": 0.9,
        "exploit_code": "print('bounded proof')",
        "patch_code": (
            "diff --git a/missing.py b/missing.py\n"
            "--- a/missing.py\n"
            "+++ b/missing.py\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        ),
    })
    save_json(Path(part["result_path"]), {
        "schema": PART_SCHEMA,
        "manifest_sha256": manifest_sha,
        "part_id": part["part_id"],
        "results": [result],
    })

    with pytest.raises(CopilotNativeError, match="does not apply"):
        lint_part(manifest_path, Path(part["result_path"]))


def test_finalize_merges_parts_and_completes_run(tmp_path):
    _, run_dir, _, manifest_path = _prepared_run(tmp_path, count=3)
    _write_parts(manifest_path)

    result = finalize_handoff(manifest_path)

    assert result["assessment"]["status"] == "complete"
    orchestrated = load_json(run_dir / "orchestrated_report.json", strict=True)
    assert orchestrated["mode"] == "orchestrated"
    assert orchestrated["orchestration"]["mode"] == "copilot_native"
    assert orchestrated["assessment"]["analyzed"] == 3
    aggregate = load_json(run_dir / "raptor_agentic_report.json", strict=True)
    assert aggregate["assessment"]["status"] == "complete"
    assert aggregate["outputs"]["orchestrated_report"].endswith(
        "orchestrated_report.json",
    )
    metadata = load_run_metadata(run_dir)
    assert metadata["status"] == "completed"
    assert metadata["extra"]["analysis_model"] == "copilot-native"
    report = (run_dir / "agentic-report.md").read_text(encoding="utf-8")
    assert "Copilot-native subagents analysed 3 of 3" in report
    assert (run_dir / "copilot-native" / "finalization-receipt.json").is_file()
    assert (run_dir / RUN_METADATA_FILE).is_file()

    rerun = finalize_handoff(manifest_path)
    assert rerun["assessment"]["status"] == "complete"
    metadata = load_run_metadata(run_dir)
    assert metadata["status"] == "completed"
    assert metadata["extra"]["reopens"][-1]["prior_status"] == "completed"


def test_finalize_prepares_native_validate_handoff(tmp_path):
    from core.run.metadata import complete_run, start_run

    target, run_dir, _, manifest_path = _prepared_run(
        tmp_path,
        validate_postpass=True,
        allow_unreachable=True,
    )
    _write_parts(manifest_path)
    validate_dir = tmp_path / "validate"

    def fake_start(command, started_target, parent_run_dir=None):
        assert command == "validate"
        assert Path(started_target) == target.resolve()
        assert Path(parent_run_dir) == run_dir.resolve()
        start_run(validate_dir, "validate", target=str(target))
        return MagicMock(run_dir=validate_dir.resolve(), error=None)

    with patch(
        "core.orchestration.agentic_passes.start_lifecycle",
        side_effect=fake_start,
    ) as start:
        result = finalize_handoff(manifest_path)
        rerun = finalize_handoff(manifest_path)
        assert load_run_metadata(validate_dir)["status"] == "interrupted"
        start_run(validate_dir, "validate", target=str(target))
        (validate_dir / "validation-report.md").write_text(
            "# Exploitability Validation Report\n",
        )
        complete_run(validate_dir)
        completed = finalize_handoff(manifest_path)

    handoff = result["validation_postpass"]
    assert handoff["requested"] is True
    assert handoff["prepared"] is True
    assert handoff["selected_count"] == 1
    assert rerun["validation_postpass"]["request_path"] == (
        handoff["request_path"]
    )
    assert completed["validation_postpass"]["completed"] is True
    assert completed["validation_postpass"]["prepared"] is False
    assert start.call_count == 1
    request_path = Path(handoff["request_path"])
    request = load_json(request_path, strict=True)
    assert request["allow_unreachable"] is True
    assert request["apply_target_patches"] is False

    aggregate = load_json(
        run_dir / "raptor_agentic_report.json",
        strict=True,
    )
    assert aggregate["phases"]["validation_postpass"]["status"] == "completed"
    assert aggregate["outputs"]["validation_postpass_run"] == str(
        validate_dir.resolve(),
    )
    receipt = load_json(
        run_dir / "copilot-native" / "finalization-receipt.json",
        strict=True,
    )
    assert receipt["validation_postpass"]["request_path"] == str(
        request_path,
    )
    assert receipt["validation_postpass"]["request_sha256"] == (
        handoff["request_sha256"]
    )
    assert receipt["validation_postpass"]["selection_sha256"] == (
        handoff["selection_sha256"]
    )
    metadata = load_run_metadata(run_dir)
    assert metadata["status"] == "completed"
    assert metadata["extra"]["validation_postpass_status"] == "completed"
    assert metadata["extra"]["copilot_native_validation_request"] == str(
        request_path,
    )
    validate_metadata = load_run_metadata(validate_dir)
    assert validate_metadata["status"] == "completed"


def test_validate_handoff_failure_leaves_agentic_interrupted(tmp_path):
    _, run_dir, _, manifest_path = _prepared_run(
        tmp_path,
        validate_postpass=True,
    )
    _write_parts(manifest_path)

    with patch(
        "core.orchestration.prepare_native_validate_postpass",
        side_effect=RuntimeError("lifecycle refused"),
    ), pytest.raises(
        CopilotNativeError,
        match="native validation handoff preparation failed",
    ):
        finalize_handoff(manifest_path)

    metadata = load_run_metadata(run_dir)
    assert metadata["status"] == "interrupted"
    assert not (
        run_dir / "copilot-native" / "finalization-receipt.json"
    ).exists()


def test_finalize_records_native_validate_skip(tmp_path):
    _, run_dir, _, manifest_path = _prepared_run(
        tmp_path,
        validate_postpass=True,
    )
    manifest = load_json(manifest_path, strict=True)
    part = manifest["parts"][0]
    manifest_sha = __import__("hashlib").sha256(
        manifest_path.read_bytes(),
    ).hexdigest()
    result = _analysis()
    result["confidence"] = "low"
    save_json(Path(part["result_path"]), {
        "schema": PART_SCHEMA,
        "manifest_sha256": manifest_sha,
        "part_id": part["part_id"],
        "results": [result],
    })

    finalized = finalize_handoff(manifest_path)

    handoff = finalized["validation_postpass"]
    assert handoff["requested"] is True
    assert handoff["prepared"] is False
    assert handoff["completed"] is False
    assert "no findings matched" in handoff["skipped_reason"]
    metadata = load_run_metadata(run_dir)
    assert metadata["status"] == "completed"
    assert metadata["extra"]["validation_postpass_status"] == "skipped"


def test_finalize_materializes_exploit_and_patch_artifacts(tmp_path):
    _, run_dir, _, manifest_path = _prepared_run(tmp_path)
    manifest = load_json(manifest_path, strict=True)
    part = manifest["parts"][0]
    manifest_sha = __import__("hashlib").sha256(
        manifest_path.read_bytes(),
    ).hexdigest()
    target = Path(manifest["target"])
    target_file = target / "src" / "main.py"
    target_file.parent.mkdir(parents=True)
    target_file.write_text("old\n", encoding="utf-8")
    exploit = "print('bounded proof')\n"
    patch = (
        "diff --git a/src/main.py b/src/main.py\n"
        "--- a/src/main.py\n"
        "+++ b/src/main.py\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
    )
    result = _analysis()
    result.update({
        "false_positive_reason": None,
        "ruling": "validated",
        "is_true_positive": True,
        "is_exploitable": True,
        "exploitability_score": 0.9,
        "exploit_code": exploit,
        "patch_code": patch,
    })
    save_json(Path(part["result_path"]), {
        "schema": PART_SCHEMA,
        "manifest_sha256": manifest_sha,
        "part_id": part["part_id"],
        "results": [result],
    })

    finalize_handoff(manifest_path)

    exploit_path = run_dir / "autonomous" / "exploits" / "FIND-001_poc.txt"
    patch_path = run_dir / "autonomous" / "patches" / "FIND-001.patch"
    assert exploit_path.read_text(encoding="utf-8") == exploit
    assert patch_path.read_text(encoding="utf-8") == patch
    index = load_json(
        run_dir / "copilot-native" / "code-artifacts.json",
        strict=True,
    )
    assert index["artifacts"][0]["finding_id"] == "FIND-001"


def test_unreachable_reasoning_can_contrast_with_false_positive():
    row = {
        "finding_id": "FIND-001",
        "reasoning": "The real bug is unreachable rather than a false positive.",
        "ruling": "unreachable",
        "is_true_positive": True,
        "is_exploitable": False,
    }

    assert check_self_contradiction({"FIND-001": row}) == 0
    assert "self_contradictory" not in row


def test_finalize_cli_prints_validation_request(monkeypatch, capsys, tmp_path):
    request = tmp_path / "validate" / "request.json"
    monkeypatch.setattr(
        "packages.llm_analysis.copilot_native.finalize_handoff",
        lambda _path: {
            "run_dir": str(tmp_path / "agentic"),
            "validation_postpass": {
                "requested": True,
                "prepared": True,
                "request_path": str(request),
            },
        },
    )

    assert main(["finalize", str(tmp_path / "manifest.json")]) == 0

    output = capsys.readouterr().out
    assert f"COPILOT_NATIVE_VALIDATE_REQUEST={request}" in output
    assert f"COPILOT_NATIVE_FINALIZED={tmp_path / 'agentic'}" in output


def test_finalize_cli_prints_audit_request_and_validation_deferred(
    monkeypatch,
    capsys,
    tmp_path,
):
    audit_request = tmp_path / "audit" / "request.json"
    monkeypatch.setattr(
        "packages.llm_analysis.copilot_native.finalize_handoff",
        lambda _path: {
            "run_dir": str(tmp_path / "agentic"),
            "audit_postpass": {
                "requested": True,
                "prepared": True,
                "completed": False,
                "request_path": str(audit_request),
            },
            "validation_postpass": {
                "requested": True,
                "prepared": False,
                "completed": False,
                "deferred": True,
                "skipped_reason": "deferred until native gap audit is attached",
            },
        },
    )

    assert main(["finalize", str(tmp_path / "manifest.json")]) == 0

    output = capsys.readouterr().out
    assert f"COPILOT_NATIVE_AUDIT_REQUEST={audit_request}" in output
    assert "COPILOT_NATIVE_VALIDATE_DEFERRED=" in output


def test_attach_context_cli_prints_receipt(monkeypatch, capsys, tmp_path):
    receipt_path = tmp_path / "agentic" / "copilot-native" / "context-receipt.json"
    context_map = tmp_path / "understand" / "context-map.json"
    monkeypatch.setattr(
        "packages.llm_analysis.copilot_native.attach_context_handoff",
        lambda _path: {
            "receipt": str(receipt_path),
            "context_map": str(context_map),
            "threat_model_requested": True,
        },
    )

    assert main(["attach-context", str(tmp_path / "manifest.json")]) == 0

    output = capsys.readouterr().out
    assert f"COPILOT_NATIVE_CONTEXT_ATTACHED={receipt_path}" in output


def test_attach_audit_cli_prints_receipt(monkeypatch, capsys, tmp_path):
    receipt_path = tmp_path / "agentic" / "copilot-native" / "audit-receipt.json"
    audit_dir = tmp_path / "audit"
    monkeypatch.setattr(
        "packages.llm_analysis.copilot_native.attach_audit_handoff",
        lambda _path: {
            "receipt": str(receipt_path),
            "audit_dir": str(audit_dir),
            "findings_count": 2,
        },
    )

    assert main(["attach-audit", str(tmp_path / "manifest.json")]) == 0

    output = capsys.readouterr().out
    assert f"COPILOT_NATIVE_AUDIT_ATTACHED={receipt_path}" in output


def test_finalize_cli_prints_completed_validation(monkeypatch, capsys, tmp_path):
    validate_dir = tmp_path / "validate"
    monkeypatch.setattr(
        "packages.llm_analysis.copilot_native.finalize_handoff",
        lambda _path: {
            "run_dir": str(tmp_path / "agentic"),
            "validation_postpass": {
                "requested": True,
                "prepared": False,
                "completed": True,
                "validate_dir": str(validate_dir),
            },
        },
    )

    assert main(["finalize", str(tmp_path / "manifest.json")]) == 0

    output = capsys.readouterr().out
    assert f"COPILOT_NATIVE_VALIDATE_COMPLETED={validate_dir}" in output
