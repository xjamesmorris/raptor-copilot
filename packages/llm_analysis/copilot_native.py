"""Copilot-native /agentic handoff and deterministic finalization.

RAPTOR's repository process cannot invoke the authenticated Copilot model
service. Under the Copilot frontend, Phase 3 therefore prepares findings and
hands bounded, non-overlapping parts to host-managed subagents. This module
owns the artifact contract between those agents and the mechanical pipeline:

* ``prepare_handoff`` writes an immutable manifest plus per-part requests.
* ``lint_part`` validates exact finding ownership and structured result shape.
* ``finalize_handoff`` merges validated parts, regenerates reports, and
  resumes/completes the original run.

The host session owns model dispatch. No provider credentials or network
transport enter this module.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.json import load_json, save_json
from core.llm.response_validation import validate_structured_response
from core.run.finding_status import ALL_STATUSES, is_skipped
from core.security.log_sanitisation import sanitise_for_terminal
from packages.llm_analysis.prompts.schemas import FINDING_RESULT_SCHEMA

MANIFEST_SCHEMA = "raptor.copilot-native-agentic-manifest/v1"
REQUEST_SCHEMA = "raptor.copilot-native-agentic-request/v1"
PART_SCHEMA = "raptor.copilot-native-agentic-part/v1"
RECEIPT_SCHEMA = "raptor.copilot-native-agentic-finalization/v1"

_MAX_PREP_BYTES = 256 * 1024 * 1024
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_MAX_PART_BYTES = 32 * 1024 * 1024
_DEFAULT_BATCH_SIZE = 8
_CORE_RESULT_FIELDS = frozenset({
    "finding_id",
    "reasoning",
    "attack_scenario",
    "remediation",
    "severity_assessment",
    "exploitability_score",
    "confidence",
    "ruling",
    "is_true_positive",
    "is_exploitable",
})


class CopilotNativeError(ValueError):
    """A handoff artifact violates the Copilot-native contract."""


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_file(path: Path, *, role: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as exc:
        raise CopilotNativeError(f"{role} does not exist: {path}") from exc
    if not stat.S_ISREG(mode):
        raise CopilotNativeError(f"{role} must be a regular file: {path}")


def _load_object(path: Path, *, role: str, max_bytes: int) -> dict[str, Any]:
    _regular_file(path, role=role)
    value = load_json(path, strict=True, max_bytes=max_bytes)
    if not isinstance(value, dict):
        raise CopilotNativeError(f"{role} must contain a JSON object")
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_in_run(run_dir: Path, value: object, *, role: str) -> Path:
    if not isinstance(value, str) or not value:
        raise CopilotNativeError(f"{role} path is missing")
    path = Path(value).resolve()
    root = run_dir.resolve()
    if path != root and root not in path.parents:
        raise CopilotNativeError(f"{role} escapes the run directory")
    return path


def _prepared_findings(
    prep_report: dict[str, Any],
    *,
    max_findings: int | None,
) -> tuple[list[dict[str, Any]], int, int]:
    if prep_report.get("mode") != "prep_only":
        raise CopilotNativeError(
            "Copilot-native handoff requires a prep_only analysis report",
        )
    raw = prep_report.get("results")
    if not isinstance(raw, list):
        raise CopilotNativeError("prep report results must be a list")

    requested = len(raw)
    eligible: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, finding in enumerate(raw):
        if not isinstance(finding, dict):
            raise CopilotNativeError(
                f"prep report result {index} is not a JSON object",
            )
        finding_id = finding.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            raise CopilotNativeError(
                f"prep report result {index} has no finding_id",
            )
        if finding_id in seen:
            raise CopilotNativeError(
                f"prep report contains duplicate finding_id {finding_id!r}",
            )
        seen.add(finding_id)
        if (
            finding.get("status") in ALL_STATUSES
            and is_skipped(finding)
        ):
            continue
        eligible.append(finding)

    cap = 0 if max_findings is None else max(int(max_findings), 0)
    selected = eligible if cap <= 0 else eligible[:cap]
    return selected, requested, len(eligible)


def _finding_ref(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": finding.get("finding_id"),
        "file_path": finding.get("file_path") or finding.get("file"),
        "start_line": (
            finding.get("start_line")
            or finding.get("line")
            or finding.get("line_number")
        ),
        "rule_id": finding.get("rule_id") or finding.get("rule"),
        "message": finding.get("message") or finding.get("title"),
    }


def prepare_handoff(
    *,
    run_dir: Path,
    repo_path: Path,
    prep_report_path: Path,
    max_findings: int | None,
    batch_size: int = _DEFAULT_BATCH_SIZE,
    no_exploits: bool = False,
    no_patches: bool = False,
    no_journal: bool = False,
    max_parallel: int | None = None,
    max_cost_usd: float | None = None,
) -> Path:
    """Write the native-agent manifest and return its path."""
    run_dir = run_dir.resolve()
    repo_path = repo_path.resolve()
    prep_report_path = prep_report_path.resolve()
    if run_dir not in prep_report_path.parents:
        raise CopilotNativeError("prep report must live inside the run directory")
    if batch_size <= 0 or batch_size > 50:
        raise CopilotNativeError("Copilot-native batch size must be 1..50")

    prep_report = _load_object(
        prep_report_path,
        role="prep report",
        max_bytes=_MAX_PREP_BYTES,
    )
    selected, requested, eligible = _prepared_findings(
        prep_report,
        max_findings=max_findings,
    )

    native_dir = run_dir / "copilot-native"
    parts_dir = native_dir / "parts"
    requests_dir = native_dir / "requests"
    parts_dir.mkdir(parents=True, exist_ok=True)
    requests_dir.mkdir(parents=True, exist_ok=True)

    parts: list[dict[str, Any]] = []
    for offset in range(0, len(selected), batch_size):
        number = len(parts) + 1
        part_id = f"part-{number:03d}"
        batch = selected[offset:offset + batch_size]
        parts.append({
            "part_id": part_id,
            "finding_ids": [str(row["finding_id"]) for row in batch],
            "request_path": str(requests_dir / f"{part_id}.json"),
            "result_path": str(parts_dir / f"{part_id}.json"),
        })

    manifest_path = native_dir / "manifest.json"
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "created_at": _utc_now(),
        "run_dir": str(run_dir),
        "target": str(repo_path),
        "prep_report": str(prep_report_path),
        "prep_report_sha256": _sha256_path(prep_report_path),
        "requested_findings": requested,
        "eligible_findings": eligible,
        "selected_findings": len(selected),
        "max_findings": max_findings,
        "batch_size": batch_size,
        "max_parallel": max_parallel,
        "max_cost_usd": max_cost_usd,
        "no_exploits": bool(no_exploits),
        "no_patches": bool(no_patches),
        "no_journal": bool(no_journal),
        "parts": parts,
    }
    save_json(manifest_path, manifest)
    manifest_sha = _sha256_path(manifest_path)

    findings_by_id = {
        str(row["finding_id"]): row
        for row in selected
    }
    for part in parts:
        finding_ids = list(part["finding_ids"])
        request = {
            "schema": REQUEST_SCHEMA,
            "manifest_path": str(manifest_path),
            "manifest_sha256": manifest_sha,
            "part_id": part["part_id"],
            "target": str(repo_path),
            "prep_report": str(prep_report_path),
            "prep_report_sha256": manifest["prep_report_sha256"],
            "finding_ids": finding_ids,
            "finding_refs": [
                _finding_ref(findings_by_id[finding_id])
                for finding_id in finding_ids
            ],
            "result_path": part["result_path"],
            "no_exploits": bool(no_exploits),
            "no_patches": bool(no_patches),
            "result_schema": FINDING_RESULT_SCHEMA,
        }
        save_json(Path(part["request_path"]), request)

    return manifest_path


def _normalise_result(
    raw: object,
    *,
    expected_id: str,
    target: Path,
    no_exploits: bool,
    no_patches: bool,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise CopilotNativeError(
            f"result for {expected_id!r} must be a JSON object",
        )
    extra = set(raw) - set(FINDING_RESULT_SCHEMA["properties"])
    if extra:
        names = ", ".join(sorted(extra))
        raise CopilotNativeError(
            f"result for {expected_id!r} has unsupported fields: {names}",
        )

    validated = validate_structured_response(raw, FINDING_RESULT_SCHEMA)
    if validated.incomplete:
        missing = ", ".join(validated.incomplete)
        raise CopilotNativeError(
            f"result for {expected_id!r} is incomplete: {missing}",
        )
    result = dict(validated.data)
    if result.get("finding_id") != expected_id:
        raise CopilotNativeError(
            f"result finding_id does not match assignment {expected_id!r}",
        )
    for field in _CORE_RESULT_FIELDS:
        if field not in raw:
            raise CopilotNativeError(
                f"result for {expected_id!r} omitted core field {field!r}",
            )
    reasoning = result.get("reasoning")
    if not isinstance(reasoning, str) or not reasoning.strip():
        raise CopilotNativeError(
            f"result for {expected_id!r} has empty reasoning",
        )
    if result.get("is_true_positive") is False and result.get(
        "is_exploitable",
    ) is True:
        raise CopilotNativeError(
            f"result for {expected_id!r} is logically contradictory",
        )
    if result.get("is_true_positive") is False and not result.get(
        "false_positive_reason",
    ):
        raise CopilotNativeError(
            f"false-positive result for {expected_id!r} needs a reason",
        )
    if result.get("is_exploitable") is True:
        if not no_exploits and not result.get("exploit_code"):
            raise CopilotNativeError(
                f"exploitable result for {expected_id!r} needs exploit_code",
            )
        if not no_patches and not result.get("patch_code"):
            raise CopilotNativeError(
                f"exploitable result for {expected_id!r} needs patch_code",
            )
        if not no_patches and not _looks_like_unified_diff(
            result.get("patch_code"),
        ):
            raise CopilotNativeError(
                f"patch_code for {expected_id!r} must be a unified diff",
            )
        if not no_patches:
            _require_applicable_patch(
                target,
                str(result["patch_code"]),
                finding_id=expected_id,
            )

    result["analysed_by"] = "copilot-native"
    result["analysed_by_provider"] = "copilot"
    result["analysis_provenance"] = "host-managed-subagent"
    result["analysis_route"] = "copilot-native"
    return result


def _looks_like_unified_diff(value: object) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    return (
        ("diff --git " in text or ("\n--- " in f"\n{text}" and "\n+++ " in text))
        and "\n@@ " in text
    )


def _require_applicable_patch(
    target: Path,
    patch: str,
    *,
    finding_id: str,
) -> None:
    from core.config import RaptorConfig
    from core.git.clone import safe_git_command

    command = safe_git_command(
        "-C", str(target), "apply", "--check", "-",
    )
    try:
        result = subprocess.run(
            command,
            input=patch,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
            env=RaptorConfig.get_safe_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CopilotNativeError(
            f"patch_code for {finding_id!r} could not be checked: "
            f"{type(exc).__name__}",
        ) from exc
    if result.returncode != 0:
        detail = sanitise_for_terminal(
            (result.stderr or result.stdout or "git apply --check failed"),
            max_len=240,
        )
        raise CopilotNativeError(
            f"patch_code for {finding_id!r} does not apply: {detail}",
        )


def _manifest_parts(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    parts = manifest.get("parts")
    if not isinstance(parts, list):
        raise CopilotNativeError("manifest parts must be a list")
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for index, part in enumerate(parts):
        if not isinstance(part, dict):
            raise CopilotNativeError(f"manifest part {index} is not an object")
        part_id = part.get("part_id")
        finding_ids = part.get("finding_ids")
        if not isinstance(part_id, str) or not part_id:
            raise CopilotNativeError(f"manifest part {index} has no part_id")
        if part_id in seen:
            raise CopilotNativeError(f"manifest duplicate part_id {part_id!r}")
        seen.add(part_id)
        if (
            not isinstance(finding_ids, list)
            or not all(isinstance(item, str) and item for item in finding_ids)
        ):
            raise CopilotNativeError(
                f"manifest part {part_id!r} has invalid finding_ids",
            )
        out.append(part)
    return out


def lint_part(
    manifest_path: Path,
    part_path: Path,
) -> list[dict[str, Any]]:
    """Validate one result part and return normalized result rows."""
    manifest_path = manifest_path.resolve()
    manifest = _load_object(
        manifest_path,
        role="manifest",
        max_bytes=_MAX_MANIFEST_BYTES,
    )
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise CopilotNativeError("unsupported manifest schema")
    run_dir = Path(str(manifest.get("run_dir"))).resolve()
    expected_parts = {
        str(part["part_id"]): part
        for part in _manifest_parts(manifest)
    }

    part_path = part_path.resolve()
    if run_dir not in part_path.parents:
        raise CopilotNativeError("part file escapes the run directory")
    part = _load_object(part_path, role="part", max_bytes=_MAX_PART_BYTES)
    if part.get("schema") != PART_SCHEMA:
        raise CopilotNativeError("unsupported part schema")
    part_id = part.get("part_id")
    if not isinstance(part_id, str) or part_id not in expected_parts:
        raise CopilotNativeError(f"unknown part_id {part_id!r}")
    expected_path = _resolve_in_run(
        run_dir,
        expected_parts[part_id].get("result_path"),
        role="part result",
    )
    if expected_path != part_path:
        raise CopilotNativeError(
            f"part {part_id!r} was written to the wrong result path",
        )
    if part.get("manifest_sha256") != _sha256_path(manifest_path):
        raise CopilotNativeError(
            f"part {part_id!r} does not match the current manifest",
        )

    expected_ids = list(expected_parts[part_id]["finding_ids"])
    target = Path(str(manifest.get("target"))).resolve()
    raw_results = part.get("results")
    if not isinstance(raw_results, list):
        raise CopilotNativeError(f"part {part_id!r} results must be a list")
    by_id: dict[str, object] = {}
    for raw in raw_results:
        if not isinstance(raw, dict):
            raise CopilotNativeError(
                f"part {part_id!r} contains a non-object result",
            )
        finding_id = raw.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            raise CopilotNativeError(
                f"part {part_id!r} contains a result without finding_id",
            )
        if finding_id in by_id:
            raise CopilotNativeError(
                f"part {part_id!r} duplicates finding_id {finding_id!r}",
            )
        by_id[finding_id] = raw

    if set(by_id) != set(expected_ids):
        missing = sorted(set(expected_ids) - set(by_id))
        extra = sorted(set(by_id) - set(expected_ids))
        raise CopilotNativeError(
            f"part {part_id!r} assignment mismatch "
            f"(missing={missing}, extra={extra})",
        )
    return [
        _normalise_result(
            by_id[finding_id],
            expected_id=finding_id,
            target=target,
            no_exploits=bool(manifest.get("no_exploits")),
            no_patches=bool(manifest.get("no_patches")),
        )
        for finding_id in expected_ids
    ]


def _tool_states_from_report(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    phases = report.get("phases") or {}
    scanning = phases.get("scanning") or {}
    return {
        "semgrep": dict(scanning.get("semgrep") or {}),
        "codeql": dict(scanning.get("codeql") or {}),
        "sca": dict(phases.get("sca") or {}),
    }


def _summary_sentence(
    *,
    analyzed: int,
    exploitable: int,
    total: int,
) -> str:
    return (
        f"Copilot-native subagents analysed {analyzed} of {total} selected "
        f"findings; {exploitable} were ruled exploitable. Scanner and "
        "dependency-feed coverage limitations remain listed below."
    )


def _materialize_code_artifacts(
    run_dir: Path,
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    from core.atomic_fs import write_text_atomically
    from packages.llm_analysis.cc_dispatch import _safe_id

    autonomous = run_dir / "autonomous"
    exploits_dir = autonomous / "exploits"
    patches_dir = autonomous / "patches"
    index_path = run_dir / "copilot-native" / "code-artifacts.json"

    previous = load_json(index_path, max_bytes=8 * 1024 * 1024)
    if isinstance(previous, dict):
        for row in previous.get("artifacts", []):
            if not isinstance(row, dict):
                continue
            for key in ("exploit_path", "patch_path"):
                raw = row.get(key)
                if not isinstance(raw, str) or not raw:
                    continue
                path = Path(raw).resolve()
                if run_dir.resolve() in path.parents:
                    path.unlink(missing_ok=True)

    artifacts: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict) or not result.get("finding_id"):
            continue
        finding_id = str(result["finding_id"])
        safe_id = _safe_id(finding_id)
        exploit_path = None
        patch_path = None
        exploit_code = result.get("exploit_code")
        if isinstance(exploit_code, str) and exploit_code.strip():
            exploits_dir.mkdir(parents=True, exist_ok=True)
            exploit_path = exploits_dir / f"{safe_id}_poc.txt"
            write_text_atomically(exploit_path, exploit_code)
            result["exploit_artifact"] = str(exploit_path)
        patch_code = result.get("patch_code")
        if isinstance(patch_code, str) and patch_code.strip():
            patches_dir.mkdir(parents=True, exist_ok=True)
            patch_path = patches_dir / f"{safe_id}.patch"
            write_text_atomically(patch_path, patch_code)
            result["patch_artifact"] = str(patch_path)
        if exploit_path or patch_path:
            artifacts.append({
                "finding_id": finding_id,
                "exploit_path": str(exploit_path) if exploit_path else None,
                "exploit_sha256": (
                    _sha256_path(exploit_path) if exploit_path else None
                ),
                "patch_path": str(patch_path) if patch_path else None,
                "patch_sha256": (
                    _sha256_path(patch_path) if patch_path else None
                ),
            })

    index = {
        "schema": "raptor.copilot-native-code-artifacts/v1",
        "generated_at": _utc_now(),
        "artifacts": artifacts,
    }
    save_json(index_path, index)
    return {
        "index": str(index_path),
        "exploits_directory": (
            str(exploits_dir) if exploits_dir.is_dir() else None
        ),
        "patches_directory": (
            str(patches_dir) if patches_dir.is_dir() else None
        ),
        "count": len(artifacts),
    }


def _render_agentic_report(
    *,
    run_dir: Path,
    aggregate: dict[str, Any],
    orchestrated: dict[str, Any],
    tool_states: dict[str, dict[str, Any]],
    run_result: dict[str, Any],
    assessment: dict[str, Any],
) -> None:
    from core.reporting import (
        build_findings_spec,
        render_report,
    )
    from core.reporting.formatting import format_elapsed
    from raptor_agentic import _build_tool_execution_report_section

    results = [
        row for row in orchestrated.get("results", [])
        if isinstance(row, dict)
        and ("is_true_positive" in row or "error" in row)
    ]
    phases = aggregate.get("phases") or {}
    scanning = phases.get("scanning") or {}
    validation = phases.get("exploitability_validation") or {}
    duration = float(aggregate.get("duration_seconds") or 0.0)
    pipeline = []
    scan_status = str(scanning.get("status") or "completed")
    pipeline.append(
        "Scan" if scan_status == "completed" else f"Scan ({scan_status})",
    )
    if tool_states["sca"].get("completed"):
        pipeline.append("SCA")
    if validation.get("completed"):
        pipeline.append("Dedup")
    pipeline.append("Copilot-native Analyse")

    metadata = {
        "Target": f"`{aggregate.get('repository', 'unknown')}`",
        "Date": str(aggregate.get("timestamp") or "")[:10],
        "Pipeline": f"{' → '.join(pipeline)} ({format_elapsed(duration)})",
        "Execution": str(
            run_result.get("pipeline_execution", "failed")
        ).title(),
        "Assessment": (
            f"{str(assessment.get('status', 'partial')).title()} — "
            f"{assessment.get('analyzed', 0)}/"
            f"{assessment.get('eligible', 0)} eligible findings analyzed; "
            f"{assessment.get('unreviewed', 0)} unreviewed"
        ),
        "Model": "Copilot native subagents",
    }

    extra_summary: dict[str, Any] = {
        "Total findings": scanning.get("total_findings", 0),
    }
    for name, label in (
        ("semgrep", "Semgrep"),
        ("codeql", "CodeQL"),
        ("sca", "SCA"),
    ):
        state = tool_states[name]
        extra_summary[label] = (
            state.get("findings", 0)
            if state.get("completed")
            else f"{str(state.get('status', 'skipped')).title()} — "
                 f"{state.get('reason', '')}"
        )
    if validation.get("completed"):
        extra_summary["After deduplication"] = validation.get(
            "validated_findings", 0,
        )
    extra_summary.update({
        "Selected for analysis": assessment.get("selected", 0),
        "Analysed": assessment.get("analyzed", 0),
        "Unreviewed": assessment.get("unreviewed", 0),
        "Exploitable": orchestrated.get("exploitable", 0),
        "Exploits generated": orchestrated.get("exploits_generated", 0),
        "Patches generated": orchestrated.get("patches_generated", 0),
    })

    warnings: list[str] = []
    prefix = "Failed result" if run_result.get("failed") else "Partial result"
    if run_result.get("failed") or run_result.get("partial"):
        warnings.extend(
            f"{prefix}: {reason}"
            for reason in run_result.get("reasons", [])
        )

    outputs = aggregate.get("outputs") or {}
    output_files = [
        str(run_dir / "orchestrated_report.json"),
        str(outputs.get("autonomous_report") or ""),
        "agentic-report.md",
    ]
    output_files = [item for item in output_files if item]
    spec = build_findings_spec(
        results,
        title="RAPTOR Agentic Security Report",
        metadata=metadata,
        extra_summary=extra_summary,
        warnings=warnings,
        extra_sections=[_build_tool_execution_report_section(tool_states)],
        output_files=output_files,
        include_details=False,
    )
    rendered = render_report(spec)
    header = "# RAPTOR Agentic Security Report\n"
    if rendered.startswith(header):
        rendered = (
            header
            + "\n"
            + _summary_sentence(
                analyzed=int(assessment.get("analyzed", 0) or 0),
                exploitable=int(orchestrated.get("exploitable", 0) or 0),
                total=int(assessment.get("selected", 0) or 0),
            )
            + "\n"
            + rendered[len(header):]
        )
    (run_dir / "agentic-report.md").write_text(rendered, encoding="utf-8")


def finalize_handoff(manifest_path: Path) -> dict[str, Any]:
    """Validate every part, merge results, and complete the original run."""
    started = time.monotonic()
    manifest_path = manifest_path.resolve()
    manifest = _load_object(
        manifest_path,
        role="manifest",
        max_bytes=_MAX_MANIFEST_BYTES,
    )
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise CopilotNativeError("unsupported manifest schema")
    run_dir = Path(str(manifest.get("run_dir"))).resolve()
    prep_report_path = _resolve_in_run(
        run_dir, manifest.get("prep_report"), role="prep report",
    )
    if manifest.get("prep_report_sha256") != _sha256_path(prep_report_path):
        raise CopilotNativeError("prep report changed after handoff creation")

    prep_report = _load_object(
        prep_report_path,
        role="prep report",
        max_bytes=_MAX_PREP_BYTES,
    )
    part_rows = _manifest_parts(manifest)
    native_results: list[dict[str, Any]] = []
    dispatch_batches: list[dict[str, Any]] = []
    for part in part_rows:
        result_path = _resolve_in_run(
            run_dir, part.get("result_path"), role="part result",
        )
        normalized = lint_part(manifest_path, result_path)
        native_results.extend(normalized)
        dispatch_batches.append({
            "phase": "copilot_native_analysis",
            "task": str(part["part_id"]),
            "succeeded": len(normalized),
            "failed": 0,
            "not_run": 0,
            "complete": True,
        })

    selected = int(manifest.get("selected_findings") or 0)
    if len(native_results) != selected:
        raise CopilotNativeError(
            f"native result count {len(native_results)} != selected {selected}",
        )

    from packages.llm_analysis.orchestrator import (
        _build_assessment_summary,
        _finalize_results_for_emit,
        _merge_results,
        _structural_grouping,
    )
    merged = _merge_results(
        prep_report,
        native_results,
        no_exploits=bool(manifest.get("no_exploits")),
        no_patches=bool(manifest.get("no_patches")),
        checkers_dir=run_dir / "checkers",
    )
    from raptor_agentic import _postprocess_findings
    _postprocess_findings(merged.get("results", []))
    code_artifacts = _materialize_code_artifacts(
        run_dir,
        merged.get("results", []),
    )
    groups = _structural_grouping(merged.get("results", []))
    merged["cross_finding_groups"] = groups

    analyzed = int(merged.get("analyzed") or 0)
    assessment = _build_assessment_summary(
        requested=int(manifest.get("requested_findings") or 0),
        eligible=int(manifest.get("eligible_findings") or 0),
        selected=selected,
        analyzed=analyzed,
        cap=(
            int(manifest["max_findings"])
            if isinstance(manifest.get("max_findings"), int)
            else 0
        ),
        cap_source="explicit",
    )
    elapsed = round(time.monotonic() - started, 3)
    merged["assessment"] = assessment
    merged["orchestration"] = {
        "completed": assessment.get("status") == "complete",
        "mode": "copilot_native",
        "multi_model": False,
        "analysis_model": "copilot-native",
        "analysis_models": ["copilot-native"],
        "aggregate_models": [],
        "aggregated": False,
        "findings_dispatched": selected,
        "findings_analysed": analyzed,
        "findings_failed": selected - analyzed,
        "assessment": assessment,
        "dispatch_batches": dispatch_batches,
        "dispatch_failures": selected - analyzed,
        "dispatch_incomplete_tasks": [],
        "structural_groups": len(groups),
        "group_analyses": 0,
        "elapsed_seconds": elapsed,
        "max_parallel": manifest.get("max_parallel"),
        "cost": {
            "accounting_complete": False,
            "note": (
                "Copilot-native AI-credit usage is owned by the host "
                "session and is not represented as repository USD spend"
            ),
        },
        "fired_models": [],
    }
    _finalize_results_for_emit(merged.get("results", []))
    save_json(run_dir / "orchestrated_report.json", merged)

    if not manifest.get("no_journal"):
        from packages.llm_analysis.journal_emit import (
            journal_orchestrated_results,
        )
        journal_orchestrated_results(
            run_dir,
            Path(str(manifest.get("target"))).resolve(),
            merged.get("results") or [],
        )

    aggregate_path = run_dir / "raptor_agentic_report.json"
    aggregate = _load_object(
        aggregate_path,
        role="aggregate report",
        max_bytes=_MAX_PREP_BYTES,
    )
    tool_states = _tool_states_from_report(aggregate)
    from raptor_agentic import (
        _build_run_result,
        _completion_partial_metadata,
        _result_contract_fields,
    )
    run_result = _build_run_result(tool_states, assessment)
    aggregate["duration_seconds"] = max(
        float(aggregate.get("duration_seconds") or 0.0),
        elapsed,
    )
    phases = aggregate.setdefault("phases", {})
    phases["autonomous_analysis"] = {
        "completed": True,
        "prepared": True,
        "mode": "copilot_native",
        "skipped": False,
        "exploitable": merged.get("exploitable", 0),
        "exploits_generated": merged.get("exploits_generated", 0),
        "patches_generated": merged.get("patches_generated", 0),
        "dataflow_validated": 0,
        "assessment": assessment,
    }
    phases["orchestration"] = merged["orchestration"]
    outputs = aggregate.setdefault("outputs", {})
    outputs["orchestrated_report"] = str(
        run_dir / "orchestrated_report.json",
    )
    outputs["exploits_directory"] = code_artifacts[
        "exploits_directory"
    ]
    outputs["patches_directory"] = code_artifacts[
        "patches_directory"
    ]
    outputs["copilot_native_code_artifacts"] = code_artifacts["index"]
    aggregate["assessment"] = assessment
    from core.reporting import build_findings_summary
    aggregate["verdicts"] = build_findings_summary(
        merged.get("results", []),
    )
    aggregate.update(_result_contract_fields(run_result, assessment))
    save_json(aggregate_path, aggregate)
    _render_agentic_report(
        run_dir=run_dir,
        aggregate=aggregate,
        orchestrated=merged,
        tool_states=tool_states,
        run_result=run_result,
        assessment=assessment,
    )

    receipt = {
        "schema": RECEIPT_SCHEMA,
        "completed_at": _utc_now(),
        "manifest": str(manifest_path),
        "manifest_sha256": _sha256_path(manifest_path),
        "prep_report_sha256": manifest.get("prep_report_sha256"),
        "parts": [
            {
                "part_id": part["part_id"],
                "result_path": part["result_path"],
                "sha256": _sha256_path(Path(str(part["result_path"]))),
            }
            for part in part_rows
        ],
        "assessment": assessment,
        "result_status": run_result.get("status"),
        "code_artifacts": code_artifacts,
    }
    save_json(run_dir / "copilot-native" / "finalization-receipt.json", receipt)

    from core.run.metadata import (
        complete_run,
        load_run_metadata,
        reopen_run,
        resume_run,
    )
    current = load_run_metadata(run_dir)
    if isinstance(current, dict) and current.get("status") == "completed":
        reopen_run(
            run_dir,
            note="Copilot-native result correction and re-finalization",
        )
    resume_run(run_dir, note="Copilot-native /agentic analysis")
    lifecycle_extra = {
        "findings_count": analyzed,
        "exploitable_count": int(merged.get("exploitable") or 0),
        "duration_seconds": aggregate["duration_seconds"],
        "analysis_model": "copilot-native",
        "analysis_models": ["copilot-native"],
        "aggregate_models": [],
        "aggregated": False,
        **_completion_partial_metadata(
            run_result,
            assessment,
            tool_states,
        ),
    }
    complete_run(
        run_dir,
        extra=lifecycle_extra,
        manifest={
            "models": [{
                "provider": "copilot",
                "model": "host-managed-subagent",
                "role": "analysis",
            }],
            "deterministically_reproducible": False,
        },
        expected_command="agentic",
    )
    return {
        "run_dir": str(run_dir),
        "orchestrated_report": str(run_dir / "orchestrated_report.json"),
        "agentic_report": str(run_dir / "agentic-report.md"),
        "assessment": assessment,
        "run_result": run_result,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Copilot-native RAPTOR agentic handoff helper",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    lint = sub.add_parser("lint-part", help="validate one native-agent part")
    lint.add_argument("manifest")
    lint.add_argument("part")

    finalize = sub.add_parser(
        "finalize",
        help="merge all native-agent parts and complete the run",
    )
    finalize.add_argument("manifest")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "lint-part":
            results = lint_part(Path(args.manifest), Path(args.part))
            print(json.dumps({
                "status": "ok",
                "part": str(Path(args.part).resolve()),
                "results": len(results),
            }, sort_keys=True))
            return 0
        if args.command == "finalize":
            result = finalize_handoff(Path(args.manifest))
            print(json.dumps({
                "status": "ok",
                **result,
            }, sort_keys=True))
            print(f"COPILOT_NATIVE_FINALIZED={result['run_dir']}")
            return 0
    except (CopilotNativeError, OSError, ValueError) as exc:
        safe = sanitise_for_terminal(str(exc), max_len=500)
        print(f"copilot-native-agentic: {safe}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
