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
CONTEXT_RECEIPT_SCHEMA = "raptor.copilot-native-context-receipt/v1"
AUDIT_RECEIPT_SCHEMA = "raptor.copilot-native-audit-receipt/v1"
MODEL_TASK_REQUEST_SCHEMA = "raptor.copilot-native-model-task/v1"
MODEL_CONTRIBUTION_SCHEMA = "raptor.copilot-native-model-contribution/v1"
MODEL_CANONICAL_REQUEST_SCHEMA = (
    "raptor.copilot-native-model-canonical-request/v1"
)
MODEL_RECEIPT_SCHEMA = "raptor.copilot-native-model-receipt/v1"

_MAX_PREP_BYTES = 256 * 1024 * 1024
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_MAX_PART_BYTES = 32 * 1024 * 1024
_MAX_CONTEXT_BYTES = 64 * 1024 * 1024
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


def _normalise_model_plan(
    plan: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if plan is None:
        return None
    if not isinstance(plan, dict) or not plan.get("enabled"):
        raise CopilotNativeError("native model plan is invalid")
    raw_analysis = plan.get("analysis_models")
    if (
        not isinstance(raw_analysis, list)
        or not raw_analysis
        or not all(
            isinstance(model, str) and model
            for model in raw_analysis
        )
    ):
        raise CopilotNativeError(
            "native model plan requires analysis_models",
        )
    if len(raw_analysis) != len(set(raw_analysis)):
        raise CopilotNativeError(
            "native model plan contains duplicate analysis models",
        )
    normalized = {
        "enabled": True,
        "analysis_models": list(raw_analysis),
        "consensus_model": plan.get("consensus_model"),
        "judge_model": plan.get("judge_model"),
        "aggregate_model": plan.get("aggregate_model"),
        "canonical_model": plan.get("canonical_model"),
    }
    for key in (
        "consensus_model",
        "judge_model",
        "aggregate_model",
        "canonical_model",
    ):
        value = normalized[key]
        if value is not None and (
            not isinstance(value, str) or not value
        ):
            raise CopilotNativeError(
                f"native model plan {key} must be a model ID",
            )
    if not normalized["canonical_model"]:
        raise CopilotNativeError(
            "native model plan requires canonical_model",
        )
    return normalized


def _model_tasks_for_part(
    *,
    part_id: str,
    model_plan: dict[str, Any],
    model_requests_dir: Path,
    contributions_dir: Path,
) -> tuple[list[dict[str, Any]], str, str]:
    tasks: list[dict[str, Any]] = []
    analysis_ids: list[str] = []
    for index, model in enumerate(model_plan["analysis_models"], start=1):
        task_id = f"analysis-{index:02d}"
        analysis_ids.append(task_id)
        tasks.append({
            "task_id": task_id,
            "role": "analysis",
            "model": model,
            "request_path": str(
                model_requests_dir / part_id / f"{task_id}.json"
            ),
            "result_path": str(
                contributions_dir / part_id / f"{task_id}.json"
            ),
            "depends_on": [],
        })

    prior_ids = list(analysis_ids)
    consensus_model = model_plan.get("consensus_model")
    if consensus_model:
        task_id = "consensus-01"
        tasks.append({
            "task_id": task_id,
            "role": "consensus",
            "model": consensus_model,
            "request_path": str(
                model_requests_dir / part_id / f"{task_id}.json"
            ),
            "result_path": str(
                contributions_dir / part_id / f"{task_id}.json"
            ),
            "depends_on": [],
        })
        prior_ids.append(task_id)

    judge_model = model_plan.get("judge_model")
    if judge_model:
        task_id = "judge-01"
        tasks.append({
            "task_id": task_id,
            "role": "judge",
            "model": judge_model,
            "request_path": str(
                model_requests_dir / part_id / f"{task_id}.json"
            ),
            "result_path": str(
                contributions_dir / part_id / f"{task_id}.json"
            ),
            "depends_on": list(prior_ids),
        })
        prior_ids.append(task_id)

    aggregate_model = model_plan.get("aggregate_model")
    if aggregate_model:
        task_id = "aggregate-01"
        tasks.append({
            "task_id": task_id,
            "role": "aggregate",
            "model": aggregate_model,
            "request_path": str(
                model_requests_dir / part_id / f"{task_id}.json"
            ),
            "result_path": str(
                contributions_dir / part_id / f"{task_id}.json"
            ),
            "depends_on": list(prior_ids),
        })
        prior_ids.append(task_id)

    canonical_request = str(
        model_requests_dir / part_id / "canonical.json"
    )
    receipt_path = str(
        contributions_dir / part_id / "receipt.json"
    )
    return tasks, canonical_request, receipt_path


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
    sequential: bool = False,
    validate_postpass: bool = False,
    allow_unreachable: bool = False,
    context_handoff: dict[str, Any] | None = None,
    audit_policy: dict[str, Any] | None = None,
    model_plan: dict[str, Any] | None = None,
) -> Path:
    """Write the native-agent manifest and return its path."""
    run_dir = run_dir.resolve()
    repo_path = repo_path.resolve()
    prep_report_path = prep_report_path.resolve()
    if run_dir not in prep_report_path.parents:
        raise CopilotNativeError("prep report must live inside the run directory")
    if batch_size <= 0 or batch_size > 50:
        raise CopilotNativeError("Copilot-native batch size must be 1..50")
    if sequential:
        max_parallel = 1

    prep_report = _load_object(
        prep_report_path,
        role="prep report",
        max_bytes=_MAX_PREP_BYTES,
    )
    selected, requested, eligible = _prepared_findings(
        prep_report,
        max_findings=max_findings,
    )
    model_plan = _normalise_model_plan(model_plan)

    native_dir = run_dir / "copilot-native"
    parts_dir = native_dir / "parts"
    requests_dir = native_dir / "requests"
    model_requests_dir = native_dir / "model-requests"
    contributions_dir = native_dir / "contributions"
    parts_dir.mkdir(parents=True, exist_ok=True)
    requests_dir.mkdir(parents=True, exist_ok=True)
    if model_plan is not None:
        model_requests_dir.mkdir(parents=True, exist_ok=True)
        contributions_dir.mkdir(parents=True, exist_ok=True)

    parts: list[dict[str, Any]] = []
    for offset in range(0, len(selected), batch_size):
        number = len(parts) + 1
        part_id = f"part-{number:03d}"
        batch = selected[offset:offset + batch_size]
        part: dict[str, Any] = {
            "part_id": part_id,
            "finding_ids": [str(row["finding_id"]) for row in batch],
            "request_path": str(requests_dir / f"{part_id}.json"),
            "result_path": str(parts_dir / f"{part_id}.json"),
        }
        if model_plan is not None:
            tasks, canonical_request, model_receipt = (
                _model_tasks_for_part(
                    part_id=part_id,
                    model_plan=model_plan,
                    model_requests_dir=model_requests_dir,
                    contributions_dir=contributions_dir,
                )
            )
            part["model_tasks"] = tasks
            part["canonical_request_path"] = canonical_request
            part["model_receipt_path"] = model_receipt
        parts.append(part)

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
        "sequential": bool(sequential),
        "validate_postpass": bool(validate_postpass),
        "allow_unreachable": bool(allow_unreachable),
        "context_handoff": context_handoff,
        "audit_policy": audit_policy,
        "model_plan": model_plan,
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
            "context_receipt": (
                context_handoff.get("receipt_path")
                if isinstance(context_handoff, dict)
                else None
            ),
            "no_exploits": bool(no_exploits),
            "no_patches": bool(no_patches),
            "result_schema": FINDING_RESULT_SCHEMA,
        }
        save_json(Path(part["request_path"]), request)
        if model_plan is None:
            continue
        task_by_id = {
            str(task["task_id"]): task
            for task in part["model_tasks"]
        }
        for task in part["model_tasks"]:
            request_path = Path(str(task["request_path"]))
            request_path.parent.mkdir(parents=True, exist_ok=True)
            dependency_paths = [
                task_by_id[dependency]["result_path"]
                for dependency in task["depends_on"]
            ]
            save_json(request_path, {
                "schema": MODEL_TASK_REQUEST_SCHEMA,
                "manifest_path": str(manifest_path),
                "manifest_sha256": manifest_sha,
                "part_id": part["part_id"],
                "task_id": task["task_id"],
                "role": task["role"],
                "model": task["model"],
                "target": str(repo_path),
                "base_request": part["request_path"],
                "finding_ids": finding_ids,
                "result_path": task["result_path"],
                "depends_on": task["depends_on"],
                "dependency_result_paths": dependency_paths,
                "blind": task["role"] in {"analysis", "consensus"},
                "result_schema": FINDING_RESULT_SCHEMA,
                "no_exploits": True,
                "no_patches": True,
            })
        save_json(Path(str(part["canonical_request_path"])), {
            "schema": MODEL_CANONICAL_REQUEST_SCHEMA,
            "manifest_path": str(manifest_path),
            "manifest_sha256": manifest_sha,
            "part_id": part["part_id"],
            "model": model_plan["canonical_model"],
            "target": str(repo_path),
            "base_request": part["request_path"],
            "finding_ids": finding_ids,
            "contribution_paths": [
                task["result_path"] for task in part["model_tasks"]
            ],
            "result_path": part["result_path"],
            "model_receipt_path": part["model_receipt_path"],
            "result_schema": FINDING_RESULT_SCHEMA,
            "no_exploits": bool(no_exploits),
            "no_patches": bool(no_patches),
        })

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
    properties = FINDING_RESULT_SCHEMA.get("properties")
    if not isinstance(properties, dict):
        raise CopilotNativeError("finding result schema has no properties")
    extra = set(raw) - set(properties)
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


def _model_tasks(part: dict[str, Any]) -> list[dict[str, Any]]:
    tasks = part.get("model_tasks")
    if not isinstance(tasks, list):
        raise CopilotNativeError("model-enabled part has no model_tasks")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for task in tasks:
        if not isinstance(task, dict):
            raise CopilotNativeError("model task must be an object")
        task_id = task.get("task_id")
        if not isinstance(task_id, str) or not task_id or task_id in seen:
            raise CopilotNativeError("model task_id is missing or duplicate")
        seen.add(task_id)
        if task.get("role") not in {
            "analysis",
            "consensus",
            "judge",
            "aggregate",
        }:
            raise CopilotNativeError(
                f"model task {task_id!r} has an invalid role",
            )
        if not isinstance(task.get("model"), str) or not task["model"]:
            raise CopilotNativeError(
                f"model task {task_id!r} has no model",
            )
        dependencies = task.get("depends_on")
        if (
            not isinstance(dependencies, list)
            or not all(
                isinstance(item, str) and item
                for item in dependencies
            )
        ):
            raise CopilotNativeError(
                f"model task {task_id!r} has invalid dependencies",
            )
        out.append(task)
    if any(
        dependency not in seen
        for task in out
        for dependency in task["depends_on"]
    ):
        raise CopilotNativeError("model task dependency is unknown")
    return out


def _load_model_contribution(
    manifest_path: Path,
    manifest: dict[str, Any],
    part: dict[str, Any],
    task: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    run_dir = Path(str(manifest.get("run_dir"))).resolve()
    result_path = _resolve_in_run(
        run_dir,
        task.get("result_path"),
        role="model contribution",
    )
    contribution = _load_object(
        result_path,
        role="model contribution",
        max_bytes=_MAX_PART_BYTES,
    )
    if (
        contribution.get("schema") != MODEL_CONTRIBUTION_SCHEMA
        or contribution.get("manifest_sha256")
        != _sha256_path(manifest_path)
        or contribution.get("part_id") != part.get("part_id")
        or contribution.get("task_id") != task.get("task_id")
        or contribution.get("role") != task.get("role")
        or contribution.get("model") != task.get("model")
    ):
        raise CopilotNativeError(
            f"model contribution {task.get('task_id')!r} binding mismatch",
        )
    results = contribution.get("results")
    if not isinstance(results, list):
        raise CopilotNativeError(
            f"model contribution {task.get('task_id')!r} results "
            "must be a list",
        )
    expected_ids = list(part["finding_ids"])
    by_id: dict[str, object] = {}
    for raw in results:
        if not isinstance(raw, dict):
            raise CopilotNativeError(
                f"model contribution {task.get('task_id')!r} "
                "contains a non-object result",
            )
        finding_id = raw.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            raise CopilotNativeError(
                f"model contribution {task.get('task_id')!r} "
                "contains a result without finding_id",
            )
        if finding_id in by_id:
            raise CopilotNativeError(
                f"model contribution {task.get('task_id')!r} "
                f"duplicates finding_id {finding_id!r}",
            )
        by_id[finding_id] = raw
    if set(by_id) != set(expected_ids):
        raise CopilotNativeError(
            f"model contribution {task.get('task_id')!r} "
            "assignment mismatch",
        )
    target = Path(str(manifest.get("target"))).resolve()
    normalized = [
        _normalise_result(
            by_id[finding_id],
            expected_id=finding_id,
            target=target,
            no_exploits=True,
            no_patches=True,
        )
        for finding_id in expected_ids
    ]
    return contribution, normalized


def lint_model_contribution(
    manifest_path: Path,
    contribution_path: Path,
) -> list[dict[str, Any]]:
    """Validate one model-role contribution."""
    manifest_path = manifest_path.resolve()
    manifest = _load_object(
        manifest_path,
        role="manifest",
        max_bytes=_MAX_MANIFEST_BYTES,
    )
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise CopilotNativeError("unsupported manifest schema")
    contribution_path = contribution_path.resolve()
    for part in _manifest_parts(manifest):
        if not isinstance(part.get("model_tasks"), list):
            continue
        tasks = _model_tasks(part)
        by_id = {str(task["task_id"]): task for task in tasks}
        for task in tasks:
            expected_path = Path(str(task["result_path"])).resolve()
            if expected_path != contribution_path:
                continue
            for dependency in task["depends_on"]:
                dependency_task = by_id[dependency]
                _load_model_contribution(
                    manifest_path,
                    manifest,
                    part,
                    dependency_task,
                )
            _, normalized = _load_model_contribution(
                manifest_path,
                manifest,
                part,
                task,
            )
            return normalized
    raise CopilotNativeError(
        "contribution path is not assigned by the manifest",
    )


def _required_model_receipt(
    manifest_path: Path,
    manifest: dict[str, Any],
    part: dict[str, Any],
) -> dict[str, Any] | None:
    if not isinstance(manifest.get("model_plan"), dict):
        return None
    run_dir = Path(str(manifest.get("run_dir"))).resolve()
    receipt_path = _resolve_in_run(
        run_dir,
        part.get("model_receipt_path"),
        role="model receipt",
    )
    receipt = _load_object(
        receipt_path,
        role="model receipt",
        max_bytes=_MAX_PART_BYTES,
    )
    if (
        receipt.get("schema") != MODEL_RECEIPT_SCHEMA
        or receipt.get("manifest_sha256") != _sha256_path(manifest_path)
        or receipt.get("part_id") != part.get("part_id")
        or receipt.get("receipt") != str(receipt_path)
        or receipt.get("canonical_model")
        != manifest["model_plan"].get("canonical_model")
    ):
        raise CopilotNativeError("model receipt binding mismatch")
    canonical_path = _resolve_in_run(
        run_dir,
        part.get("result_path"),
        role="canonical part",
    )
    canonical_request_path = _resolve_in_run(
        run_dir,
        part.get("canonical_request_path"),
        role="canonical model request",
    )
    if (
        receipt.get("canonical_request_path")
        != str(canonical_request_path)
        or not canonical_request_path.is_file()
        or receipt.get("canonical_request_sha256")
        != _sha256_path(canonical_request_path)
        or
        receipt.get("canonical_result_path") != str(canonical_path)
        or not canonical_path.is_file()
        or receipt.get("canonical_sha256") != _sha256_path(canonical_path)
    ):
        raise CopilotNativeError("canonical model result changed after sealing")
    expected_tasks = _model_tasks(part)
    records = receipt.get("contributions")
    if not isinstance(records, list) or len(records) != len(expected_tasks):
        raise CopilotNativeError("model receipt contribution count mismatch")
    by_task = {
        record.get("task_id"): record
        for record in records
        if isinstance(record, dict)
    }
    for task in expected_tasks:
        record = by_task.get(task["task_id"])
        result_path = _resolve_in_run(
            run_dir,
            task.get("result_path"),
            role="model contribution",
        )
        request_path = _resolve_in_run(
            run_dir,
            task.get("request_path"),
            role="model task request",
        )
        if (
            not isinstance(record, dict)
            or record.get("role") != task.get("role")
            or record.get("model") != task.get("model")
            or record.get("request_path") != str(request_path)
            or not request_path.is_file()
            or record.get("request_sha256") != _sha256_path(request_path)
            or record.get("result_path") != str(result_path)
            or not result_path.is_file()
            or record.get("sha256") != _sha256_path(result_path)
        ):
            raise CopilotNativeError(
                f"model receipt contribution mismatch: {task['task_id']}",
            )
    return receipt


def seal_model_part(
    manifest_path: Path,
    part_id: str,
) -> dict[str, Any]:
    """Validate every model contribution and seal the canonical part."""
    manifest_path = manifest_path.resolve()
    manifest = _load_object(
        manifest_path,
        role="manifest",
        max_bytes=_MAX_MANIFEST_BYTES,
    )
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise CopilotNativeError("unsupported manifest schema")
    parts = {
        str(part["part_id"]): part
        for part in _manifest_parts(manifest)
    }
    part = parts.get(part_id)
    if part is None or not isinstance(part.get("model_tasks"), list):
        raise CopilotNativeError(f"unknown model-enabled part {part_id!r}")
    contribution_records: list[dict[str, Any]] = []
    for task in _model_tasks(part):
        contribution, _ = _load_model_contribution(
            manifest_path,
            manifest,
            part,
            task,
        )
        result_path = Path(str(task["result_path"])).resolve()
        contribution_records.append({
            "task_id": task["task_id"],
            "role": task["role"],
            "model": task["model"],
            "request_path": str(Path(task["request_path"]).resolve()),
            "request_sha256": _sha256_path(
                Path(task["request_path"]).resolve(),
            ),
            "result_path": str(result_path),
            "sha256": _sha256_path(result_path),
            "result_count": len(contribution["results"]),
        })
    canonical_path = Path(str(part["result_path"])).resolve()
    canonical_request_path = Path(
        str(part["canonical_request_path"]),
    ).resolve()
    _lint_part(
        manifest_path,
        canonical_path,
        require_model_receipt=False,
    )
    receipt_path = Path(str(part["model_receipt_path"])).resolve()
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt = {
        "schema": MODEL_RECEIPT_SCHEMA,
        "sealed_at": _utc_now(),
        "manifest": str(manifest_path),
        "manifest_sha256": _sha256_path(manifest_path),
        "part_id": part_id,
        "receipt": str(receipt_path),
        "canonical_model": manifest["model_plan"]["canonical_model"],
        "canonical_request_path": str(canonical_request_path),
        "canonical_request_sha256": _sha256_path(
            canonical_request_path,
        ),
        "canonical_result_path": str(canonical_path),
        "canonical_sha256": _sha256_path(canonical_path),
        "contributions": contribution_records,
    }
    save_json(receipt_path, receipt)
    return receipt


def _model_evidence_for_part(
    manifest_path: Path,
    manifest: dict[str, Any],
    part: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(manifest.get("model_plan"), dict):
        return {}
    _required_model_receipt(manifest_path, manifest, part)
    evidence: dict[str, list[dict[str, Any]]] = {
        str(finding_id): []
        for finding_id in part["finding_ids"]
    }
    for task in _model_tasks(part):
        _, normalized = _load_model_contribution(
            manifest_path,
            manifest,
            part,
            task,
        )
        for result in normalized:
            evidence[str(result["finding_id"])].append({
                "task_id": task["task_id"],
                "role": task["role"],
                "model": task["model"],
                "ruling": result.get("ruling"),
                "is_true_positive": result.get("is_true_positive"),
                "is_exploitable": result.get("is_exploitable"),
                "confidence": result.get("confidence"),
                "severity_assessment": result.get(
                    "severity_assessment",
                ),
                "reasoning": result.get("reasoning"),
            })
    return evidence


def attach_context_handoff(manifest_path: Path) -> dict[str, Any]:
    """Bind a completed understand run to its native agentic manifest."""
    manifest_path = manifest_path.resolve()
    manifest = _load_object(
        manifest_path,
        role="manifest",
        max_bytes=_MAX_MANIFEST_BYTES,
    )
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise CopilotNativeError("unsupported manifest schema")
    context = manifest.get("context_handoff")
    if not isinstance(context, dict) or not context.get("prepared"):
        raise CopilotNativeError("manifest has no native context handoff")

    run_dir = Path(str(manifest.get("run_dir"))).resolve()
    target = Path(str(manifest.get("target"))).resolve()
    try:
        understand_dir = Path(str(context["understand_dir"])).resolve()
        request_path = Path(str(context["request_path"])).resolve()
        receipt_path = Path(str(context["receipt_path"])).resolve()
    except (KeyError, OSError, ValueError) as exc:
        raise CopilotNativeError(
            "native context handoff paths are invalid",
        ) from exc
    if understand_dir.parent != run_dir.parent:
        raise CopilotNativeError(
            "understand run is not a sibling of the agentic run",
        )
    if (
        request_path
        != understand_dir / "copilot-native-context-request.json"
    ):
        raise CopilotNativeError("native context request path is invalid")
    if receipt_path != run_dir / "copilot-native" / "context-receipt.json":
        raise CopilotNativeError("native context receipt path is invalid")

    request = _load_object(
        request_path,
        role="native context request",
        max_bytes=_MAX_MANIFEST_BYTES,
    )
    from core.orchestration.agentic_passes import (
        NATIVE_CONTEXT_REQUEST_SCHEMA,
        PrepassResult,
        _enrich_agentic_checklist,
        _validate_context_map_shape,
    )
    if request.get("schema") != NATIVE_CONTEXT_REQUEST_SCHEMA:
        raise CopilotNativeError("unsupported native context request schema")
    if context.get("request_sha256") != _sha256_path(request_path):
        raise CopilotNativeError("native context request changed after handoff")
    if (
        request.get("target") != str(target)
        or request.get("agentic_run_dir") != str(run_dir)
        or request.get("understand_dir") != str(understand_dir)
        or request.get("context_receipt_path") != str(receipt_path)
        or request.get("apply_target_patches") is not False
        or request.get("resume_argv") != [
            "libexec/raptor-run-lifecycle",
            "start",
            "understand",
            "--target",
            str(target),
            "--out",
            str(understand_dir),
        ]
    ):
        raise CopilotNativeError("native context request binding mismatch")

    context_map_path = Path(str(request.get("context_map_path"))).resolve()
    if context_map_path != understand_dir / "context-map.json":
        raise CopilotNativeError("native context map path is invalid")
    context_map = _load_object(
        context_map_path,
        role="context map",
        max_bytes=_MAX_CONTEXT_BYTES,
    )
    shape_error = _validate_context_map_shape(context_map)
    if shape_error is not None:
        raise CopilotNativeError(f"context map is invalid: {shape_error}")
    context_map_sha256 = _sha256_path(context_map_path)

    from core.inventory import read_checklist
    checklist = read_checklist(understand_dir)
    if not isinstance(checklist, dict) or not checklist:
        raise CopilotNativeError("understand checklist is missing or invalid")
    from core.orchestration.agentic_passes import _json_sha256
    if request.get("checklist_sha256") != _json_sha256(checklist):
        raise CopilotNativeError("understand checklist changed after handoff")

    from core.run.metadata import load_run_metadata
    understand_meta = load_run_metadata(understand_dir)
    if (
        not isinstance(understand_meta, dict)
        or understand_meta.get("command") != "understand"
        or understand_meta.get("status") != "completed"
        or Path(str(understand_meta.get("target_path"))).resolve() != target
    ):
        raise CopilotNativeError(
            "understand lifecycle is not completed for this target",
        )

    if receipt_path.is_file() and not receipt_path.is_symlink():
        verified = _required_context_receipt(manifest_path, manifest)
        if verified is None:
            raise CopilotNativeError("native context receipt is missing")
        return verified

    checklist_enriched = _enrich_agentic_checklist(
        run_dir,
        context_map_path,
    )
    threat_model_summary = None
    if request.get("threat_model_requested"):
        from raptor_agentic import _materialise_threat_model_phase
        threat_model_summary = _materialise_threat_model_phase(
            target=target,
            out_dir=run_dir,
            prepass_result=PrepassResult(
                ran=True,
                understand_dir=understand_dir,
                context_map_path=context_map_path,
                checklist_enriched=checklist_enriched,
            ),
            refresh=bool(request.get("threat_model_refresh")),
            allow_stale=bool(request.get("threat_model_use_stale")),
        )
        if not threat_model_summary.get("completed"):
            raise CopilotNativeError(
                "native threat-model materialization did not complete: "
                + str(
                    threat_model_summary.get("skipped_reason")
                    or "unknown failure"
                ),
            )

    threat_model_artifacts: dict[str, dict[str, str]] = {}
    if isinstance(threat_model_summary, dict):
        for key in (
            "threat_model_json",
            "threat_model_markdown",
            "threat_model_report",
            "threat_model_lint",
            "threat_model_drift",
            "threats",
            "candidate_sarif",
        ):
            value = threat_model_summary.get(key)
            if value is None:
                continue
            artifact = Path(str(value)).resolve()
            if not artifact.is_file() or artifact.is_symlink():
                raise CopilotNativeError(
                    f"native threat-model artifact is missing: {key}",
                )
            threat_model_artifacts[key] = {
                "path": str(artifact),
                "sha256": _sha256_path(artifact),
            }

    aggregate_path = run_dir / "raptor_agentic_report.json"
    aggregate = _load_object(
        aggregate_path,
        role="aggregate report",
        max_bytes=_MAX_PREP_BYTES,
    )
    phases = aggregate.setdefault("phases", {})
    phases["understand_prepass"] = {
        "requested": True,
        "completed": True,
        "run_dir": str(understand_dir),
        "context_map": str(context_map_path),
        "checklist_enriched": checklist_enriched,
    }
    outputs = aggregate.setdefault("outputs", {})
    outputs["context_map"] = str(context_map_path)
    outputs["copilot_native_context_receipt"] = str(receipt_path)
    if isinstance(threat_model_summary, dict):
        phases["threat_model"] = threat_model_summary
        for key in (
            "threat_model_json",
            "threat_model_markdown",
            "threat_model_report",
            "threat_model_lint",
            "threat_model_drift",
            "threats",
            "candidate_sarif",
        ):
            if threat_model_summary.get(key) is not None:
                outputs[key] = threat_model_summary[key]
    save_json(aggregate_path, aggregate)

    receipt = {
        "schema": CONTEXT_RECEIPT_SCHEMA,
        "attached_at": _utc_now(),
        "manifest": str(manifest_path),
        "manifest_sha256": _sha256_path(manifest_path),
        "receipt": str(receipt_path),
        "request": str(request_path),
        "request_sha256": _sha256_path(request_path),
        "understand_dir": str(understand_dir),
        "context_map": str(context_map_path),
        "context_map_sha256": context_map_sha256,
        "checklist_enriched": checklist_enriched,
        "threat_model_requested": bool(
            request.get("threat_model_requested"),
        ),
        "threat_model_summary": threat_model_summary,
        "threat_model_artifacts": threat_model_artifacts,
        "apply_target_patches": False,
    }
    save_json(receipt_path, receipt)

    parent_meta = load_run_metadata(run_dir)
    parent_extra = (
        dict(parent_meta.get("extra") or {})
        if isinstance(parent_meta, dict)
        else {}
    )
    parent_extra.update({
        "copilot_native_context_receipt": str(receipt_path),
        "context_map": str(context_map_path),
        "threat_model_status": (
            "completed"
            if threat_model_summary is not None
            else "not_requested"
        ),
    })
    from core.run.metadata import interrupt_run
    interrupt_run(
        run_dir,
        reason="awaiting host-managed Copilot analysis",
        extra=parent_extra,
        expected_command="agentic",
    )
    return receipt


def _required_context_receipt(
    manifest_path: Path,
    manifest: dict[str, Any],
) -> dict[str, Any] | None:
    context = manifest.get("context_handoff")
    if not isinstance(context, dict) or not context.get("prepared"):
        return None
    receipt_value = context.get("receipt_path")
    if not isinstance(receipt_value, str) or not receipt_value:
        raise CopilotNativeError("native context receipt path is missing")
    run_dir = Path(str(manifest.get("run_dir"))).resolve()
    receipt_path = Path(receipt_value).resolve()
    if receipt_path != run_dir / "copilot-native" / "context-receipt.json":
        raise CopilotNativeError("native context receipt path is invalid")
    receipt = _load_object(
        receipt_path,
        role="native context receipt",
        max_bytes=_MAX_CONTEXT_BYTES,
    )
    if (
        receipt.get("schema") != CONTEXT_RECEIPT_SCHEMA
        or receipt.get("manifest_sha256") != _sha256_path(manifest_path)
        or receipt.get("receipt") != str(receipt_path)
        or receipt.get("apply_target_patches") is not False
        or bool(receipt.get("threat_model_requested"))
        != bool(context.get("threat_model_requested"))
    ):
        raise CopilotNativeError(
            "native context receipt does not match the manifest",
        )
    if context.get("threat_model_requested"):
        summary = receipt.get("threat_model_summary")
        if not isinstance(summary, dict) or not summary.get("completed"):
            raise CopilotNativeError(
                "native threat-model receipt is incomplete",
            )
        artifacts = receipt.get("threat_model_artifacts")
        if not isinstance(artifacts, dict) or not artifacts:
            raise CopilotNativeError(
                "native threat-model artifact hashes are missing",
            )
        for key, record in artifacts.items():
            if (
                not isinstance(key, str)
                or not isinstance(record, dict)
                or not isinstance(record.get("path"), str)
                or not isinstance(record.get("sha256"), str)
            ):
                raise CopilotNativeError(
                    "native threat-model artifact record is invalid",
                )
            artifact = Path(record["path"]).resolve()
            if (
                not artifact.is_file()
                or artifact.is_symlink()
                or record["sha256"] != _sha256_path(artifact)
            ):
                raise CopilotNativeError(
                    f"native threat-model artifact changed: {key}",
                )
    request_path = Path(str(context.get("request_path"))).resolve()
    if (
        receipt.get("request") != str(request_path)
        or receipt.get("request_sha256") != context.get("request_sha256")
        or not request_path.is_file()
        or request_path.is_symlink()
        or context.get("request_sha256") != _sha256_path(request_path)
    ):
        raise CopilotNativeError(
            "native context request changed after attachment",
        )
    context_map_path = Path(str(receipt.get("context_map"))).resolve()
    if (
        not context_map_path.is_file()
        or context_map_path.is_symlink()
        or receipt.get("context_map_sha256")
        != _sha256_path(context_map_path)
    ):
        raise CopilotNativeError(
            "native context map changed after attachment",
        )
    return receipt


def attach_audit_handoff(manifest_path: Path) -> dict[str, Any]:
    """Bind a completed in-session gap audit to its parent agentic run."""
    manifest_path = manifest_path.resolve()
    manifest = _load_object(
        manifest_path,
        role="manifest",
        max_bytes=_MAX_MANIFEST_BYTES,
    )
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise CopilotNativeError("unsupported manifest schema")
    audit_policy = manifest.get("audit_policy")
    if not isinstance(audit_policy, dict) or not audit_policy.get("enabled"):
        raise CopilotNativeError("manifest has no native gap-audit policy")
    context_receipt = _required_context_receipt(manifest_path, manifest)
    if context_receipt is None:
        raise CopilotNativeError("native gap audit requires attached context")

    run_dir = Path(str(manifest.get("run_dir"))).resolve()
    target = Path(str(manifest.get("target"))).resolve()
    pointer_path = run_dir / "copilot-native" / "audit-handoff.json"
    pointer = _load_object(
        pointer_path,
        role="native audit handoff",
        max_bytes=_MAX_MANIFEST_BYTES,
    )
    from core.orchestration.agentic_passes import (
        NATIVE_AUDIT_REQUEST_SCHEMA,
        _NATIVE_AUDIT_POINTER_SCHEMA,
        _json_sha256,
    )
    if (
        pointer.get("schema") != _NATIVE_AUDIT_POINTER_SCHEMA
        or pointer.get("target") != str(target)
        or pointer.get("agentic_run_dir") != str(run_dir)
        or pointer.get("context_map_sha256")
        != context_receipt.get("context_map_sha256")
        or pointer.get("audit_policy_sha256")
        != _json_sha256(audit_policy)
    ):
        raise CopilotNativeError("native audit handoff binding mismatch")
    try:
        audit_dir = Path(str(pointer["audit_dir"])).resolve()
        request_path = Path(str(pointer["request_path"])).resolve()
        receipt_path = Path(str(pointer["receipt_path"])).resolve()
    except (KeyError, OSError, ValueError) as exc:
        raise CopilotNativeError("native audit handoff paths are invalid") from exc
    if audit_dir.parent != run_dir.parent:
        raise CopilotNativeError("audit run is not a sibling of agentic run")
    if request_path != audit_dir / "copilot-native-audit-request.json":
        raise CopilotNativeError("native audit request path is invalid")
    if receipt_path != run_dir / "copilot-native" / "audit-receipt.json":
        raise CopilotNativeError("native audit receipt path is invalid")
    request = _load_object(
        request_path,
        role="native audit request",
        max_bytes=_MAX_MANIFEST_BYTES,
    )
    if (
        request.get("schema") != NATIVE_AUDIT_REQUEST_SCHEMA
        or pointer.get("request_sha256") != _sha256_path(request_path)
        or request.get("target") != str(target)
        or request.get("agentic_run_dir") != str(run_dir)
        or request.get("audit_dir") != str(audit_dir)
        or request.get("audit_receipt") != str(receipt_path)
        or request.get("policy") != audit_policy
        or request.get("coverage_policy") != "map_grade_is_not_review"
        or request.get("apply_target_patches") is not False
    ):
        raise CopilotNativeError("native audit request binding mismatch")

    from core.run.metadata import load_run_metadata
    audit_meta = load_run_metadata(audit_dir)
    if (
        not isinstance(audit_meta, dict)
        or audit_meta.get("command") != "audit"
        or audit_meta.get("status") != "completed"
        or Path(str(audit_meta.get("target_path"))).resolve() != target
    ):
        raise CopilotNativeError(
            "audit lifecycle is not completed for this target",
        )

    if receipt_path.is_file() and not receipt_path.is_symlink():
        receipt = _required_audit_receipt(
            manifest_path,
            manifest,
            context_receipt,
        )
        if receipt is None:
            raise CopilotNativeError("native audit receipt is missing")
        return receipt

    report_path = audit_dir / "audit-report.json"
    findings_path = audit_dir / "findings.json"
    report = _load_object(
        report_path,
        role="audit report",
        max_bytes=_MAX_CONTEXT_BYTES,
    )
    completeness = report.get("completeness")
    if not isinstance(completeness, dict):
        completeness = {}
        report["completeness"] = completeness
    completeness["run_status"] = "completed"
    completeness["resumable"] = False
    completeness["partial"] = bool(completeness.get("missing"))
    save_json(report_path, report)
    if not findings_path.is_file() or findings_path.is_symlink():
        raise CopilotNativeError("audit findings are missing")
    findings_hash = _sha256_path(findings_path)
    findings = load_json(
        findings_path,
        strict=True,
        max_bytes=_MAX_CONTEXT_BYTES,
    )
    rows = (
        findings.get("findings")
        if isinstance(findings, dict)
        else findings
    )
    if not isinstance(rows, list):
        raise CopilotNativeError("audit findings must be a list")

    receipt = {
        "schema": AUDIT_RECEIPT_SCHEMA,
        "attached_at": _utc_now(),
        "receipt": str(receipt_path),
        "manifest": str(manifest_path),
        "manifest_sha256": _sha256_path(manifest_path),
        "request": str(request_path),
        "request_sha256": _sha256_path(request_path),
        "audit_dir": str(audit_dir),
        "audit_report": str(report_path),
        "audit_report_sha256": _sha256_path(report_path),
        "findings": str(findings_path),
        "findings_sha256": findings_hash,
        "findings_count": len(
            [row for row in rows if isinstance(row, dict)]
        ),
        "stats": (
            dict(report["stats"])
            if isinstance(report.get("stats"), dict)
            else {}
        ),
        "gaps_remaining": int(report.get("gaps_remaining") or 0),
        "coverage_policy": "map_grade_is_not_review",
        "validation_deferred_to_parent": bool(
            audit_policy.get("validate_after"),
        ),
        "apply_target_patches": False,
    }
    save_json(receipt_path, receipt)

    aggregate_path = run_dir / "raptor_agentic_report.json"
    aggregate = _load_object(
        aggregate_path,
        role="aggregate report",
        max_bytes=_MAX_PREP_BYTES,
    )
    phases = aggregate.setdefault("phases", {})
    phases["audit"] = {
        "enabled": True,
        "completed": True,
        "audit_dir": str(audit_dir),
        "findings_count": receipt["findings_count"],
        "reviewed": int(receipt["stats"].get("reviewed") or 0),
        "clean": int(receipt["stats"].get("clean") or 0),
        "suspicious": int(receipt["stats"].get("suspicious") or 0),
        "dormant": int(receipt["stats"].get("dormant") or 0),
        "gaps_remaining": receipt["gaps_remaining"],
        "coverage_policy": "map_grade_is_not_review",
        "validation_deferred_to_parent": receipt[
            "validation_deferred_to_parent"
        ],
        "stats": report.get("stats"),
    }
    outputs = aggregate.setdefault("outputs", {})
    outputs["audit_report"] = str(report_path)
    outputs["audit_findings"] = str(findings_path)
    outputs["copilot_native_audit_receipt"] = str(receipt_path)
    save_json(aggregate_path, aggregate)

    parent_meta = load_run_metadata(run_dir)
    parent_extra = (
        dict(parent_meta.get("extra") or {})
        if isinstance(parent_meta, dict)
        else {}
    )
    parent_extra.update({
        "copilot_native_audit_receipt": str(receipt_path),
        "audit_run": str(audit_dir),
        "audit_findings_count": receipt["findings_count"],
    })
    from core.run.metadata import interrupt_run
    interrupt_run(
        run_dir,
        reason="awaiting host-managed Copilot analysis finalization",
        extra=parent_extra,
        expected_command="agentic",
    )
    return receipt


def _required_audit_receipt(
    manifest_path: Path,
    manifest: dict[str, Any],
    context_receipt: dict[str, Any],
) -> dict[str, Any] | None:
    audit_policy = manifest.get("audit_policy")
    if not isinstance(audit_policy, dict) or not audit_policy.get("enabled"):
        return None
    run_dir = Path(str(manifest.get("run_dir"))).resolve()
    receipt_path = run_dir / "copilot-native" / "audit-receipt.json"
    if not receipt_path.exists():
        return None
    receipt = _load_object(
        receipt_path,
        role="native audit receipt",
        max_bytes=_MAX_CONTEXT_BYTES,
    )
    if (
        receipt.get("schema") != AUDIT_RECEIPT_SCHEMA
        or receipt.get("receipt") != str(receipt_path)
        or receipt.get("manifest_sha256") != _sha256_path(manifest_path)
        or receipt.get("coverage_policy") != "map_grade_is_not_review"
        or receipt.get("apply_target_patches") is not False
        or bool(receipt.get("validation_deferred_to_parent"))
        != bool(audit_policy.get("validate_after"))
    ):
        raise CopilotNativeError(
            "native audit receipt does not match the manifest",
        )
    for path_key, hash_key in (
        ("request", "request_sha256"),
        ("audit_report", "audit_report_sha256"),
        ("findings", "findings_sha256"),
    ):
        path = Path(str(receipt.get(path_key))).resolve()
        if (
            not path.is_file()
            or path.is_symlink()
            or receipt.get(hash_key) != _sha256_path(path)
        ):
            raise CopilotNativeError(
                f"native audit artifact changed: {path_key}",
            )
    request = _load_object(
        Path(str(receipt["request"])),
        role="native audit request",
        max_bytes=_MAX_MANIFEST_BYTES,
    )
    if (
        request.get("policy") != audit_policy
        or request.get("context_map_sha256")
        != context_receipt.get("context_map_sha256")
    ):
        raise CopilotNativeError(
            "native audit request no longer matches context/policy",
        )
    return receipt


def lint_part(
    manifest_path: Path,
    part_path: Path,
) -> list[dict[str, Any]]:
    """Validate one result part and return normalized result rows."""
    return _lint_part(
        manifest_path,
        part_path,
        require_model_receipt=True,
    )


def _lint_part(
    manifest_path: Path,
    part_path: Path,
    *,
    require_model_receipt: bool,
) -> list[dict[str, Any]]:
    """Internal part validator with a sealing bypass for seal-model-part."""
    manifest_path = manifest_path.resolve()
    manifest = _load_object(
        manifest_path,
        role="manifest",
        max_bytes=_MAX_MANIFEST_BYTES,
    )
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise CopilotNativeError("unsupported manifest schema")
    _required_context_receipt(manifest_path, manifest)
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
    if require_model_receipt:
        _required_model_receipt(
            manifest_path,
            manifest,
            expected_parts[part_id],
        )
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
    from raptor_agentic import (
        _build_audit_report_section,
        _build_tool_execution_report_section,
    )

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
    extra_sections = [_build_tool_execution_report_section(tool_states)]
    audit_phase = phases.get("audit")
    if isinstance(audit_phase, dict) and audit_phase.get("enabled"):
        extra_sections.append(_build_audit_report_section(
            audit_phase,
            validate_dir=outputs.get("validation_postpass_run"),
        ))
    spec = build_findings_spec(
        results,
        title="RAPTOR Agentic Security Report",
        metadata=metadata,
        extra_summary=extra_summary,
        warnings=warnings,
        extra_sections=extra_sections,
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
    context_receipt = _required_context_receipt(
        manifest_path,
        manifest,
    )
    audit_policy = manifest.get("audit_policy")
    audit_requested = (
        isinstance(audit_policy, dict)
        and bool(audit_policy.get("enabled"))
    )
    audit_receipt = None
    if audit_requested:
        if context_receipt is None:
            raise CopilotNativeError(
                "native gap audit requires attached context",
            )
        audit_receipt = _required_audit_receipt(
            manifest_path,
            manifest,
            context_receipt,
        )
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
        model_evidence = _model_evidence_for_part(
            manifest_path,
            manifest,
            part,
        )
        if model_evidence:
            canonical_model = manifest["model_plan"]["canonical_model"]
            for result in normalized:
                finding_id = str(result["finding_id"])
                result["multi_model_analyses"] = model_evidence[
                    finding_id
                ]
                result["model_execution"] = {
                    "canonical_model": canonical_model,
                    "contribution_count": len(
                        model_evidence[finding_id],
                    ),
                    "receipt": part["model_receipt_path"],
                }
                result["analysed_by"] = canonical_model
            for task in _model_tasks(part):
                dispatch_batches.append({
                    "phase": f"copilot_native_{task['role']}",
                    "task": (
                        f"{part['part_id']}:{task['task_id']}"
                    ),
                    "model": task["model"],
                    "succeeded": len(normalized),
                    "failed": 0,
                    "not_run": 0,
                    "complete": True,
                })
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
    model_plan = manifest.get("model_plan")
    if isinstance(model_plan, dict):
        analysis_models = list(model_plan["analysis_models"])
        aggregate_models = (
            [model_plan["aggregate_model"]]
            if model_plan.get("aggregate_model")
            else []
        )
        fired_models = list(dict.fromkeys([
            *analysis_models,
            *(
                [model_plan["consensus_model"]]
                if model_plan.get("consensus_model")
                else []
            ),
            *(
                [model_plan["judge_model"]]
                if model_plan.get("judge_model")
                else []
            ),
            *aggregate_models,
            model_plan["canonical_model"],
        ]))
        multi_model = (
            len(analysis_models) > 1
            or bool(model_plan.get("consensus_model"))
            or bool(model_plan.get("judge_model"))
            or bool(model_plan.get("aggregate_model"))
        )
    else:
        analysis_models = ["copilot-native"]
        aggregate_models = []
        fired_models = []
        multi_model = False
    merged["assessment"] = assessment
    merged["orchestration"] = {
        "completed": assessment.get("status") == "complete",
        "mode": "copilot_native",
        "multi_model": multi_model,
        "analysis_model": analysis_models[0],
        "analysis_models": analysis_models,
        "aggregate_models": aggregate_models,
        "aggregated": bool(aggregate_models),
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
        "fired_models": fired_models,
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

    audit_handoff: dict[str, Any] = {
        "requested": audit_requested,
        "prepared": False,
        "completed": bool(audit_receipt),
        "attach_required": False,
        "audit_dir": (
            audit_receipt.get("audit_dir")
            if isinstance(audit_receipt, dict)
            else None
        ),
        "request_path": None,
        "request_sha256": None,
        "receipt_path": (
            audit_receipt.get("receipt")
            if isinstance(audit_receipt, dict)
            else None
        ),
    }
    audit_pending = False
    if audit_requested and audit_receipt is None:
        assert isinstance(context_receipt, dict)
        assert isinstance(audit_policy, dict)
        try:
            from core.orchestration import prepare_native_audit_postpass
            prepared_audit = prepare_native_audit_postpass(
                target=Path(str(manifest.get("target"))).resolve(),
                agentic_out_dir=run_dir,
                context_receipt=context_receipt,
                audit_policy=audit_policy,
            )
        except Exception as exc:
            raise CopilotNativeError(
                "native audit handoff preparation failed: "
                f"{type(exc).__name__}: {exc}",
            ) from exc
        audit_handoff = {
            "requested": True,
            **prepared_audit.to_dict(),
            "attach_required": prepared_audit.completed,
        }
        audit_pending = True
        phases["audit"] = {
            "enabled": True,
            "completed": False,
            "status": (
                "attach_required"
                if prepared_audit.completed
                else "interrupted"
            ),
            "audit_dir": str(prepared_audit.audit_dir),
            "request": str(prepared_audit.request_path),
            "coverage_policy": "map_grade_is_not_review",
        }
        outputs["copilot_native_audit_request"] = str(
            prepared_audit.request_path,
        )
        outputs["audit_run"] = str(prepared_audit.audit_dir)
    elif isinstance(audit_receipt, dict):
        audit_report = _load_object(
            Path(str(audit_receipt["audit_report"])),
            role="audit report",
            max_bytes=_MAX_CONTEXT_BYTES,
        )
        audit_stats = (
            audit_report["stats"]
            if isinstance(audit_report.get("stats"), dict)
            else {}
        )
        audit_handoff.update({
            "findings_count": audit_receipt.get("findings_count", 0),
            "reviewed": int(audit_stats.get("reviewed") or 0),
            "clean": int(audit_stats.get("clean") or 0),
            "suspicious": int(audit_stats.get("suspicious") or 0),
            "dormant": int(audit_stats.get("dormant") or 0),
            "gaps_remaining": int(
                audit_report.get("gaps_remaining") or 0
            ),
        })
        phases["audit"] = {
            "enabled": True,
            "completed": True,
            "status": "completed",
            "audit_dir": audit_receipt.get("audit_dir"),
            "findings_count": audit_handoff["findings_count"],
            "reviewed": audit_handoff["reviewed"],
            "clean": audit_handoff["clean"],
            "suspicious": audit_handoff["suspicious"],
            "dormant": audit_handoff["dormant"],
            "gaps_remaining": audit_handoff["gaps_remaining"],
            "coverage_policy": "map_grade_is_not_review",
        }
        outputs["audit_report"] = audit_receipt.get("audit_report")
        outputs["audit_findings"] = audit_receipt.get("findings")
        outputs["copilot_native_audit_receipt"] = audit_receipt.get(
            "receipt",
        )
    aggregate["audit_postpass"] = audit_handoff

    validation_handoff: dict[str, Any] = {
        "requested": bool(manifest.get("validate_postpass")),
        "prepared": False,
        "completed": False,
        "deferred": False,
        "skipped_reason": None,
        "selected_count": 0,
        "validate_dir": None,
        "selection_file": None,
        "selection_sha256": None,
        "request_path": None,
        "request_sha256": None,
    }
    if validation_handoff["requested"] and audit_pending:
        validation_handoff["deferred"] = True
        validation_handoff["skipped_reason"] = (
            "deferred until native gap audit is attached"
        )
        phases["validation_postpass"] = {
            "requested": True,
            "prepared": False,
            "completed": False,
            "status": "deferred",
            "reason": validation_handoff["skipped_reason"],
        }
    elif validation_handoff["requested"]:
        try:
            from core.orchestration import prepare_native_validate_postpass
            prepared = prepare_native_validate_postpass(
                target=Path(str(manifest.get("target"))).resolve(),
                agentic_out_dir=run_dir,
                analysis_report=run_dir / "orchestrated_report.json",
                allow_unreachable=bool(
                    manifest.get("allow_unreachable"),
                ),
                audit_dir=(
                    Path(str(audit_receipt["audit_dir"]))
                    if isinstance(audit_receipt, dict)
                    else None
                ),
            )
        except Exception as exc:
            raise CopilotNativeError(
                "native validation handoff preparation failed: "
                f"{type(exc).__name__}: {exc}",
            ) from exc
        validation_handoff = prepared.to_dict()
        if prepared.prepared:
            phases["validation_postpass"] = {
                "requested": True,
                "prepared": True,
                "completed": False,
                "status": "interrupted",
                "selected_findings": prepared.selected_count,
                "run_dir": str(prepared.validate_dir),
                "request": str(prepared.request_path),
            }
            outputs["copilot_native_validation_request"] = str(
                prepared.request_path,
            )
            outputs["validation_postpass_run"] = str(
                prepared.validate_dir,
            )
        elif prepared.completed:
            phases["validation_postpass"] = {
                "requested": True,
                "prepared": False,
                "completed": True,
                "status": "completed",
                "selected_findings": prepared.selected_count,
                "run_dir": str(prepared.validate_dir),
                "report": str(
                    Path(str(prepared.validate_dir))
                    / "validation-report.md"
                ),
            }
            outputs["validation_postpass_run"] = str(
                prepared.validate_dir,
            )
            outputs["validation_postpass_report"] = str(
                Path(str(prepared.validate_dir))
                / "validation-report.md"
            )
        else:
            phases["validation_postpass"] = {
                "requested": True,
                "prepared": False,
                "completed": False,
                "status": "skipped",
                "selected_findings": 0,
                "reason": prepared.skipped_reason,
            }
    if audit_requested or validation_handoff["requested"]:
        aggregate["validation_postpass"] = validation_handoff
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
        "context_receipt": context_receipt,
        "audit_postpass": audit_handoff,
        "validation_postpass": validation_handoff,
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
        "analysis_model": analysis_models[0],
        "analysis_models": analysis_models,
        "aggregate_models": aggregate_models,
        "aggregated": bool(aggregate_models),
        "copilot_native_context_receipt": (
            manifest.get("context_handoff", {}).get("receipt_path")
            if isinstance(manifest.get("context_handoff"), dict)
            else None
        ),
        "copilot_native_validation_request": (
            validation_handoff.get("request_path")
        ),
        "copilot_native_audit_request": audit_handoff.get(
            "request_path",
        ),
        "audit_run": audit_handoff.get("audit_dir"),
        "audit_postpass_status": (
            "completed"
            if audit_handoff.get("completed")
            else (
                "attach_required"
                if audit_handoff.get("attach_required")
                else (
                    "prepared"
                    if audit_handoff.get("prepared")
                    else "not_requested"
                )
            )
        ),
        "validation_postpass_run": validation_handoff.get("validate_dir"),
        "validation_postpass_status": (
            "completed"
            if validation_handoff.get("completed")
            else (
                "deferred"
                if validation_handoff.get("deferred")
                else (
                    "prepared"
                    if validation_handoff.get("prepared")
                    else (
                        "skipped"
                        if validation_handoff.get("requested")
                        else "not_requested"
                    )
                )
            )
        ),
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
            "models": (
                (
                    [
                        {
                            "provider": "copilot",
                            "model": model,
                            "role": "analysis",
                        }
                        for model in analysis_models
                    ]
                    + (
                        [{
                            "provider": "copilot",
                            "model": manifest["model_plan"][
                                "consensus_model"
                            ],
                            "role": "consensus",
                        }]
                        if manifest["model_plan"].get("consensus_model")
                        else []
                    )
                    + (
                        [{
                            "provider": "copilot",
                            "model": manifest["model_plan"]["judge_model"],
                            "role": "judge",
                        }]
                        if manifest["model_plan"].get("judge_model")
                        else []
                    )
                    + (
                        [{
                            "provider": "copilot",
                            "model": manifest["model_plan"][
                                "aggregate_model"
                            ],
                            "role": "aggregate",
                        }]
                        if manifest["model_plan"].get("aggregate_model")
                        else []
                    )
                )
                if isinstance(manifest.get("model_plan"), dict)
                else [{
                    "provider": "copilot",
                    "model": "host-managed-subagent",
                    "role": "analysis",
                }]
            ),
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
        "audit_postpass": audit_handoff,
        "validation_postpass": validation_handoff,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Copilot-native RAPTOR agentic handoff helper",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    lint = sub.add_parser("lint-part", help="validate one native-agent part")
    lint.add_argument("manifest")
    lint.add_argument("part")

    lint_contribution = sub.add_parser(
        "lint-contribution",
        help="validate one native model-role contribution",
    )
    lint_contribution.add_argument("manifest")
    lint_contribution.add_argument("contribution")

    seal = sub.add_parser(
        "seal-model-part",
        help="seal model contributions and canonical part",
    )
    seal.add_argument("manifest")
    seal.add_argument("part_id")

    attach = sub.add_parser(
        "attach-context",
        help="bind a completed native understand run to the agentic run",
    )
    attach.add_argument("manifest")

    attach_audit = sub.add_parser(
        "attach-audit",
        help="bind a completed native gap audit to the agentic run",
    )
    attach_audit.add_argument("manifest")

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
        if args.command == "lint-contribution":
            results = lint_model_contribution(
                Path(args.manifest),
                Path(args.contribution),
            )
            print(json.dumps({
                "status": "ok",
                "contribution": str(
                    Path(args.contribution).resolve(),
                ),
                "results": len(results),
            }, sort_keys=True))
            return 0
        if args.command == "seal-model-part":
            receipt = seal_model_part(
                Path(args.manifest),
                str(args.part_id),
            )
            print(json.dumps({
                "status": "ok",
                "part_id": receipt["part_id"],
                "receipt": receipt["receipt"],
                "contributions": len(receipt["contributions"]),
            }, sort_keys=True))
            return 0
        if args.command == "attach-context":
            receipt = attach_context_handoff(Path(args.manifest))
            receipt_path = Path(str(receipt["receipt"])).resolve()
            print(json.dumps({
                "status": "ok",
                "receipt": str(receipt_path),
                "context_map": receipt["context_map"],
                "threat_model_requested": receipt[
                    "threat_model_requested"
                ],
            }, sort_keys=True))
            print(f"COPILOT_NATIVE_CONTEXT_ATTACHED={receipt_path}")
            return 0
        if args.command == "attach-audit":
            receipt = attach_audit_handoff(Path(args.manifest))
            receipt_path = Path(str(receipt["receipt"])).resolve()
            print(json.dumps({
                "status": "ok",
                "receipt": str(receipt_path),
                "audit_dir": receipt["audit_dir"],
                "findings_count": receipt["findings_count"],
            }, sort_keys=True))
            print(f"COPILOT_NATIVE_AUDIT_ATTACHED={receipt_path}")
            return 0
        if args.command == "finalize":
            result = finalize_handoff(Path(args.manifest))
            print(json.dumps({
                "status": "ok",
                **result,
            }, sort_keys=True))
            audit = result.get("audit_postpass")
            if isinstance(audit, dict):
                if audit.get("completed"):
                    print(
                        "COPILOT_NATIVE_AUDIT_COMPLETED="
                        + str(audit["audit_dir"]),
                    )
                elif audit.get("request_path"):
                    print(
                        "COPILOT_NATIVE_AUDIT_REQUEST="
                        + str(audit["request_path"]),
                    )
            validation = result.get("validation_postpass")
            if isinstance(validation, dict):
                if validation.get("completed"):
                    print(
                        "COPILOT_NATIVE_VALIDATE_COMPLETED="
                        + str(validation["validate_dir"]),
                    )
                elif validation.get("prepared"):
                    print(
                        "COPILOT_NATIVE_VALIDATE_REQUEST="
                        + str(validation["request_path"]),
                    )
                elif validation.get("deferred"):
                    reason = sanitise_for_terminal(
                        str(validation.get("skipped_reason") or "deferred"),
                        max_len=300,
                    )
                    print(f"COPILOT_NATIVE_VALIDATE_DEFERRED={reason}")
                elif validation.get("requested"):
                    reason = sanitise_for_terminal(
                        str(validation.get("skipped_reason") or "no work"),
                        max_len=300,
                    )
                    print(f"COPILOT_NATIVE_VALIDATE_SKIPPED={reason}")
            print(f"COPILOT_NATIVE_FINALIZED={result['run_dir']}")
            return 0
    except (CopilotNativeError, OSError, ValueError) as exc:
        safe = sanitise_for_terminal(str(exc), max_len=500)
        print(f"copilot-native-agentic: {safe}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
