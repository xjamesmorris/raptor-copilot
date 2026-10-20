"""Copilot-native /agentic handoff artifact contract."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.json import load_json, save_json
from core.run.metadata import (
    RUN_METADATA_FILE,
    interrupt_run,
    load_run_metadata,
    start_run,
)
from packages.llm_analysis.copilot_native import (
    CopilotNativeError,
    MANIFEST_SCHEMA,
    PART_SCHEMA,
    finalize_handoff,
    lint_part,
    prepare_handoff,
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


def _prepared_run(tmp_path: Path, *, count: int = 1):
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
    manifest = prepare_handoff(
        run_dir=run_dir,
        repo_path=target,
        prep_report_path=prep,
        max_findings=0,
        batch_size=2,
        no_journal=True,
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
