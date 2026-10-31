"""Hermetic tests for the POST-02 live-acceptance driver."""

from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
import time
from pathlib import Path

import pytest

from core.json import load_json, save_json
from core.run.metadata import (
    RUN_METADATA_FILE,
    interrupt_run,
    start_run,
)
from packages.llm_analysis.copilot_native import (
    PART_SCHEMA,
    finalize_handoff,
    prepare_handoff,
)

_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "copilot_post02_acceptance.py"
)


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location(
        "copilot_post02_acceptance",
        _SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run(*argv: str, cwd: Path) -> str:
    result = subprocess.run(
        list(argv),
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "bin").mkdir()
    launcher = repo / "bin" / "raptor"
    launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    launcher.chmod(0o755)
    (repo / "out").mkdir()
    (repo / ".gitignore").write_text("out/\n", encoding="utf-8")
    _run("git", "init", "-b", "main", cwd=repo)
    _run("git", "config", "user.name", "POST-02 Test", cwd=repo)
    _run("git", "config", "user.email", "post02-test@invalid", cwd=repo)
    _run("git", "add", ".gitignore", "bin/raptor", cwd=repo)
    _run("git", "commit", "-m", "Initial test repository", cwd=repo)
    return repo


def _prepare(mod, tmp_path: Path, monkeypatch) -> tuple[Path, Path, dict]:
    repo = _repo(tmp_path)
    monkeypatch.setattr(
        mod,
        "_copilot_version",
        lambda _repo_root: "copilot version 1.0-test",
    )
    workspace = repo / "out" / "post02-workspace"
    mod._prepare_workspace(
        workspace,
        frontend_model="approved-test-model",
        repo_root=repo,
    )
    state = mod._load_state(workspace)
    return repo, workspace, state


def _finding(finding_id: str) -> dict:
    return {
        "finding_id": finding_id,
        "rule_id": "fixture.command-injection",
        "file_path": "vulnerable.py",
        "start_line": 6,
        "message": "shell command uses untrusted input",
        "code": "subprocess.run(value, shell=True)",
        "surrounding_context": "def run(value): ...",
        "has_dataflow": True,
    }


def _analysis(finding_id: str) -> dict:
    return {
        "finding_id": finding_id,
        "reasoning": "User input reaches a shell interpreter.",
        "attack_scenario": "An attacker supplies shell metacharacters.",
        "exploit_code": "python vulnerable.py",
        "patch_code": (
            "--- a/vulnerable.py\n"
            "+++ b/vulnerable.py\n"
            "@@ -3,7 +3,8 @@ import subprocess\n"
            " \n"
            " \n"
            " def run_command() -> None:\n"
            "-    subprocess.run(input(\"command: \"), shell=True, check=False)\n"
            "+    command = input(\"command: \")\n"
            "+    subprocess.run([command], shell=False, check=False)\n"
            " \n"
            " \n"
            " def run_system() -> None:\n"
        ),
        "cvss_vector": None,
        "cvss_score_estimate": 7.5,
        "vuln_type": "command_injection",
        "cwe_id": "CWE-78",
        "dataflow_summary": "input -> subprocess shell",
        "remediation": "Use an argument vector without shell=True.",
        "false_positive_reason": None,
        "tool": "copilot-native",
        "rule_id": "fixture.command-injection",
        "severity_assessment": "high",
        "exploitability_score": 0.9,
        "confidence": "high",
        "ruling": "validated",
        "is_true_positive": True,
        "is_exploitable": True,
    }


def _base_report(target: Path, prep: Path) -> dict:
    completed_tool = {
        "status": "completed",
        "requested": True,
        "attempted": True,
        "completed": True,
        "failed": False,
        "skipped": False,
        "findings": 2,
        "artifacts": [],
    }
    return {
        "timestamp": "2026-10-28T00:00:00Z",
        "repository": str(target),
        "duration_seconds": 1.0,
        "phases": {
            "scanning": {
                "status": "completed",
                "total_findings": 2,
                "semgrep": dict(completed_tool),
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
                "validated_findings": 2,
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


def _prepared_run(repo: Path, target: Path, name: str) -> Path:
    run_dir = repo / "out" / name
    run_dir.mkdir()
    autonomous = run_dir / "autonomous"
    autonomous.mkdir()
    prep = autonomous / "autonomous_analysis_report.json"
    save_json(prep, {
        "mode": "prep_only",
        "processed": 4,
        "results": [
            _finding(f"FIND-{index:03d}")
            for index in range(1, 5)
        ],
    })
    start_run(run_dir, "agentic", target=str(target))
    save_json(
        run_dir / "raptor_agentic_report.json",
        _base_report(target, prep),
    )
    manifest = prepare_handoff(
        run_dir=run_dir,
        repo_path=target,
        prep_report_path=prep,
        max_findings=2,
        batch_size=1,
        no_journal=True,
    )
    interrupt_run(
        run_dir,
        reason="awaiting host-managed Copilot analysis",
        expected_command="agentic",
    )
    _mark_copilot_route(run_dir, manifest)
    return manifest


def _mark_copilot_route(
    run_dir: Path,
    manifest: Path,
    *,
    session_host: str | None = None,
    include_models: bool = True,
) -> None:
    metadata_path = run_dir / RUN_METADATA_FILE
    metadata = load_json(metadata_path, strict=True)
    if session_host is None:
        metadata.pop("session_host", None)
    else:
        metadata["session_host"] = session_host
    if include_models:
        metadata["manifest"]["models"] = [{
            "provider": "copilot",
            "model": "host-managed-subagent",
            "role": "analysis",
        }]
    else:
        metadata["manifest"].pop("models", None)
    metadata.setdefault("extra", {})["copilot_native_manifest"] = str(manifest)
    save_json(metadata_path, metadata)


def _write_parts(manifest_path: Path) -> None:
    manifest = load_json(manifest_path, strict=True)
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
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


def _record_launch(mod, workspace: Path, phase: str) -> None:
    state = mod._load_state(workspace)
    run_state = state["runs"][phase]
    run_state.update({
        "launch_started_at": mod._now(),
        "launch_started_epoch": time.time() - 10,
        "usage_path": str(mod._usage_path(workspace, phase)),
    })
    run_state["launcher_argv"] = mod._launcher_argv(
        state,
        phase,
        repo_root=Path(state["repo_root"]),
    )
    mod._save_state(workspace, state)


def _write_session_evidence(
    mod,
    repo: Path,
    workspace: Path,
    phase: str,
) -> None:
    state = mod._load_state(workspace)
    usage_path = Path(state["runs"][phase]["usage_path"])
    save_json(usage_path, {
        "totalNanoAiu": 0,
        "totalUserRequests": 0,
        "totalApiDurationMs": 0,
        "sessionStartTime": mod._now(),
        "modelMetrics": {},
        "agentMetrics": {},
    })
    (repo / ".startup-output").write_text(
        "frontend: GitHub Copilot CLI (model: test-model)\n"
        "   llm: Copilot session only (standalone providers blocked)\n",
        encoding="utf-8",
    )


def test_prepare_creates_committed_fixture_and_bounded_launcher(
    mod,
    tmp_path,
    monkeypatch,
):
    repo, workspace, state = _prepare(mod, tmp_path, monkeypatch)

    fixture = Path(state["fixture"])
    assert (fixture / "vulnerable.py").is_file()
    assert _run("git", "status", "--short", cwd=fixture) == ""
    assert state["fixture_commit"] == _run(
        "git",
        "rev-parse",
        "HEAD",
        cwd=fixture,
    )

    argv = mod._launcher_argv(state, "success", repo_root=repo)
    assert "--model=approved-test-model" in argv
    assert "--project=-" in argv
    assert "--max-findings=2" in argv
    assert "--max-ai-credits=30" in argv
    assert any(arg.startswith("--usage-output-file=") for arg in argv)
    assert argv[-1] == str(fixture)
    assert (workspace / mod.EVIDENCE_FILE).is_file()


def test_frontend_model_validation(mod):
    assert mod._frontend_model("approved-model") == "approved-model"
    with pytest.raises(mod.AcceptanceError, match="non-empty"):
        mod._frontend_model("")
    with pytest.raises(mod.AcceptanceError, match="control bytes"):
        mod._frontend_model("bad\nmodel")


def test_nested_frontend_launch_is_refused(mod, monkeypatch):
    monkeypatch.setenv("COPILOT_CLI", "1")
    with pytest.raises(mod.AcceptanceError, match="second Copilot frontend"):
        mod._refuse_nested_frontend()


def test_success_cancel_and_resume_checks(
    mod,
    tmp_path,
    monkeypatch,
):
    repo, workspace, state = _prepare(mod, tmp_path, monkeypatch)
    target = Path(state["fixture"])

    _record_launch(mod, workspace, "success")
    _write_session_evidence(mod, repo, workspace, "success")
    success_manifest = _prepared_run(
        repo,
        target,
        "agentic_success",
    )
    _write_parts(success_manifest)
    finalize_handoff(success_manifest)
    _mark_copilot_route(success_manifest.parents[1], success_manifest)

    success = mod._check_complete(
        workspace,
        "success",
        repo_root=repo,
    )
    assert success["lifecycle_status"] == "completed"
    assert success["selected_findings"] == 2
    assert len(success["linted_parts"]) == 2
    assert success["assessment"]["status"] == "partial"
    assert success["host_evidence"]["mode"] == "launcher_corroborated"
    assert success["usage"]["accounting_complete"] is False

    _record_launch(mod, workspace, "cancellation")
    _write_session_evidence(mod, repo, workspace, "cancellation")
    cancelled_manifest = _prepared_run(
        repo,
        target,
        "agentic_cancelled",
    )
    _mark_copilot_route(
        cancelled_manifest.parents[1],
        cancelled_manifest,
        include_models=False,
    )
    cancelled = mod._check_cancelled(
        workspace,
        repo_root=repo,
    )
    assert cancelled["lifecycle_status"] == "interrupted"
    assert cancelled["premature_finalization_refused"] is True
    assert cancelled["incomplete_parts"] == ["part-001", "part-002"]
    assert (workspace / mod.RESUME_PROMPT_FILE).is_file()

    _write_parts(cancelled_manifest)
    finalize_handoff(cancelled_manifest)
    _mark_copilot_route(cancelled_manifest.parents[1], cancelled_manifest)
    resumed = mod._check_complete(
        workspace,
        "cancellation",
        repo_root=repo,
    )
    assert resumed["lifecycle_status"] == "completed"

    final_state = mod._load_state(workspace)
    assert final_state["runs"]["cancellation"]["resumed"] is True
    evidence = (workspace / mod.EVIDENCE_FILE).read_text(encoding="utf-8")
    assert "Premature finalization refused: `True`" in evidence
    assert "Resumed same run: `True`" in evidence
    assert "launcher_corroborated" in evidence
    assert "unknown host usage, not proof of zero spend" in evidence
    assert "- [ ] Both `OUTPUT_DIR=`" in evidence

    mod._record_attestations(
        workspace,
        sentinels_source="session log",
        operator_source="operator confirmation",
    )

    attested_state = mod._load_state(workspace)
    assert mod._attestations_complete(attested_state) is True
    attested_evidence = (
        workspace / mod.EVIDENCE_FILE
    ).read_text(encoding="utf-8")
    assert "- [x] Both `OUTPUT_DIR=`" in attested_evidence
    assert "Source: session log." in attested_evidence
    assert "Source: operator confirmation." in attested_evidence


def test_non_copilot_metadata_host_is_rejected(
    mod,
    tmp_path,
    monkeypatch,
):
    repo, workspace, state = _prepare(mod, tmp_path, monkeypatch)
    manifest = _prepared_run(
        repo,
        Path(state["fixture"]),
        "agentic_wrong_host",
    )
    _mark_copilot_route(
        manifest.parents[1],
        manifest,
        session_host="claude",
    )
    context = mod._inspect_manifest(manifest, state, repo_root=repo)

    with pytest.raises(mod.AcceptanceError, match="non-Copilot host"):
        mod._run_metadata(context)


def test_interrupted_native_run_may_precede_model_metadata(
    mod,
    tmp_path,
    monkeypatch,
):
    repo, _, state = _prepare(mod, tmp_path, monkeypatch)
    manifest = _prepared_run(
        repo,
        Path(state["fixture"]),
        "agentic_pending_model",
    )
    _mark_copilot_route(
        manifest.parents[1],
        manifest,
        include_models=False,
    )
    context = mod._inspect_manifest(manifest, state, repo_root=repo)

    metadata = mod._run_metadata(context)

    assert metadata["status"] == "interrupted"
