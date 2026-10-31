#!/usr/bin/env python3
"""Drive and verify the POST-02 live Copilot acceptance procedure.

The live model work must run in the operator's launcher-bound Copilot
session. This helper automates everything deterministic around those sessions:

* create and commit an intentionally vulnerable fixture repository;
* launch projectless, bounded success and cancellation sessions;
* discover the exact run by target and launch time, never by "latest";
* verify manifest ownership, independently lint every result, and check the
  lifecycle/finalization artifacts;
* prove premature finalization refuses an incomplete cancelled run;
* write a version-controlled-review-friendly evidence draft.

The only manual actions left are allowing the first session to finish,
pressing Ctrl+C once during the second session's managed analysis, and pasting
the generated resume prompt into that same session.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from core.config import RaptorConfig  # noqa: E402
from core.json import load_json  # noqa: E402
from core.security.log_sanitisation import sanitise_for_terminal  # noqa: E402
from packages.llm_analysis.copilot_native import (  # noqa: E402
    CopilotNativeError,
    MANIFEST_SCHEMA,
    RECEIPT_SCHEMA,
    finalize_handoff,
    lint_part,
)

STATE_SCHEMA = "raptor.copilot-post02-acceptance/v1"
STATE_FILE = "post02-state.json"
EVIDENCE_FILE = "acceptance-evidence.md"
RESUME_PROMPT_FILE = "resume-prompt.txt"
_MAX_STATE_BYTES = 2 * 1024 * 1024
_MAX_METADATA_BYTES = 2 * 1024 * 1024
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_MAX_USAGE_BYTES = 8 * 1024 * 1024
_MAX_STARTUP_BYTES = 256 * 1024
_PART_ID_RE = re.compile(r"^part-\d{3}$")
_NESTED_COPILOT_MARKERS = (
    "COPILOT_AGENT_SESSION_ID",
    "COPILOT_CLI",
    "COPILOT_CLI_BINARY_VERSION",
    "COPILOT_CLI_RESOLVED_DIST_DIR",
    "COPILOT_LOADER_PID",
)

_FIXTURE_SOURCE = """\
import os
import subprocess


def run_command() -> None:
    subprocess.run(input("command: "), shell=True, check=False)


def run_system() -> None:
    os.system(input("system command: "))
"""

_FIXTURE_README = """\
# RAPTOR POST-02 fixture

Intentionally vulnerable, operator-owned code for local acceptance testing.
"""


class AcceptanceError(RuntimeError):
    """The acceptance driver found a failed precondition or invariant."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _display(value: object, *, max_len: int = 800) -> str:
    return sanitise_for_terminal(str(value), max_len=max_len)


def _atomic_write_text(path: Path, text: str, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    _atomic_write_text(
        path,
        json.dumps(value, indent=2, sort_keys=True) + "\n",
    )


def _load_object(path: Path, *, role: str, max_bytes: int) -> dict[str, Any]:
    try:
        file_stat = path.lstat()
    except FileNotFoundError as exc:
        raise AcceptanceError(f"{role} does not exist: {path}") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise AcceptanceError(f"{role} must be a regular file: {path}")
    if file_stat.st_size > max_bytes:
        raise AcceptanceError(
            f"{role} exceeds {max_bytes} bytes: {path}",
        )
    try:
        value = load_json(path, strict=True, max_bytes=max_bytes)
    except (OSError, ValueError) as exc:
        raise AcceptanceError(f"cannot read {role} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AcceptanceError(f"{role} must contain a JSON object: {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_run(
    argv: list[str],
    *,
    cwd: Path,
    timeout: int = 30,
) -> str:
    env = RaptorConfig.get_safe_env()
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise AcceptanceError(
            f"{shlex.join(argv)} failed with exit {result.returncode}: "
            f"{_display(detail)}",
        )
    return result.stdout.strip()


def _tool(name: str) -> str:
    value = shutil.which(name)
    if not value:
        raise AcceptanceError(f"required executable not found on PATH: {name}")
    return str(Path(value).resolve())


def _git(repo: Path, *args: str) -> str:
    return _safe_run([_tool("git"), *args], cwd=repo)


def _copilot_version(repo_root: Path) -> str:
    return _safe_run([_tool("copilot"), "--version"], cwd=repo_root)


def _default_workspace(repo_root: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return repo_root / "out" / f"copilot-post02-acceptance-{stamp}"


def _frontend_model(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AcceptanceError("frontend model must be a non-empty string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise AcceptanceError("frontend model must not contain control bytes")
    return value


def _state_path(workspace: Path) -> Path:
    return workspace / STATE_FILE


def _load_state(workspace: Path) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    state = _load_object(
        _state_path(workspace),
        role="POST-02 state",
        max_bytes=_MAX_STATE_BYTES,
    )
    if state.get("schema") != STATE_SCHEMA:
        raise AcceptanceError("unsupported POST-02 state schema")
    recorded_workspace = Path(str(state.get("workspace"))).resolve()
    if recorded_workspace != workspace:
        raise AcceptanceError(
            "state workspace does not match the requested workspace",
        )
    return state


def _save_state(workspace: Path, state: dict[str, Any]) -> None:
    state["updated_at"] = _now()
    _atomic_write_json(_state_path(workspace), state)
    _write_evidence(workspace, state)


def _prepare_workspace(
    workspace: Path | None = None,
    *,
    frontend_model: str,
    repo_root: Path | None = None,
) -> Path:
    repo_root = (repo_root or REPO_ROOT).resolve()
    frontend_model = _frontend_model(frontend_model)
    workspace = (workspace or _default_workspace(repo_root)).expanduser().resolve()
    if workspace.exists():
        raise AcceptanceError(
            f"workspace already exists; choose a fresh path: {workspace}",
        )
    workspace.parent.mkdir(parents=True, exist_ok=True)
    workspace.mkdir(mode=0o700)

    fixture = workspace / "fixture"
    fixture.mkdir(mode=0o700)
    _atomic_write_text(fixture / "vulnerable.py", _FIXTURE_SOURCE, mode=0o600)
    _atomic_write_text(fixture / "README.md", _FIXTURE_README, mode=0o600)

    _git(fixture, "init", "-b", "main")
    _git(fixture, "config", "user.name", "RAPTOR POST-02 Acceptance")
    _git(fixture, "config", "user.email", "raptor-post02@invalid")
    _git(fixture, "add", "README.md", "vulnerable.py")
    _git(fixture, "commit", "-m", "Add POST-02 acceptance fixture")

    launcher = repo_root / "bin" / "raptor"
    if not launcher.is_file():
        raise AcceptanceError(f"RAPTOR launcher is missing: {launcher}")

    state: dict[str, Any] = {
        "schema": STATE_SCHEMA,
        "created_at": _now(),
        "updated_at": _now(),
        "repo_root": str(repo_root),
        "workspace": str(workspace),
        "fixture": str(fixture),
        "python_executable": str(Path(sys.executable).resolve()),
        "frontend_model": frontend_model,
        "fixture_commit": _git(fixture, "rev-parse", "HEAD"),
        "raptor_commit": _git(repo_root, "rev-parse", "HEAD"),
        "raptor_status": _git(repo_root, "status", "--short", "--branch"),
        "copilot_version": _copilot_version(repo_root),
        "runs": {
            "success": {},
            "cancellation": {},
        },
    }
    _save_state(workspace, state)
    return workspace


def _usage_path(workspace: Path, phase: str) -> Path:
    name = "success" if phase == "success" else "cancellation"
    return workspace / f"copilot-{name}-usage.json"


def _launcher_argv(
    state: dict[str, Any],
    phase: str,
    *,
    repo_root: Path | None = None,
) -> list[str]:
    repo_root = (repo_root or Path(str(state["repo_root"]))).resolve()
    workspace = Path(str(state["workspace"])).resolve()
    fixture = Path(str(state["fixture"])).resolve()
    frontend_model = _frontend_model(state.get("frontend_model"))
    return [
        str(repo_root / "bin" / "raptor"),
        "--frontend",
        "copilot",
        f"--model={frontend_model}",
        "--project=-",
        "--max-findings=2",
        "--max-ai-credits=30",
        f"--usage-output-file={_usage_path(workspace, phase)}",
        str(fixture),
    ]


def _refuse_nested_frontend() -> None:
    present = [name for name in _NESTED_COPILOT_MARKERS if os.environ.get(name)]
    if present:
        raise AcceptanceError(
            "refusing to launch a second Copilot frontend from inside the "
            "current Copilot session; exit it first "
            f"(markers: {', '.join(present)})",
        )


def _launch(
    workspace: Path,
    phase: str,
    *,
    retry: bool = False,
    repo_root: Path | None = None,
) -> None:
    _refuse_nested_frontend()
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
    repo_root = (repo_root or Path(str(state["repo_root"]))).resolve()
    run_state = state["runs"][phase]
    if (
        phase == "cancellation"
        and state["runs"]["success"].get("lifecycle_status") != "completed"
    ):
        raise AcceptanceError(
            "verify the successful run before launching the cancellation run",
        )
    if run_state.get("launch_started_epoch") is not None and not retry:
        raise AcceptanceError(
            f"{phase} launch already recorded; pass --retry only after "
            "confirming that launch created no usable run",
        )
    run_state.clear()
    run_state.update({
        "launch_started_at": _now(),
        "launch_started_epoch": time.time(),
        "usage_path": str(_usage_path(workspace, phase)),
        "frontend_model": _frontend_model(state.get("frontend_model")),
    })
    argv = _launcher_argv(state, phase, repo_root=repo_root)
    run_state["launcher_argv"] = argv
    _save_state(workspace, state)

    print(f"Launching POST-02 {phase} session:", flush=True)
    print("  " + shlex.join(argv), flush=True)
    if phase == "cancellation":
        print(
            "Press Ctrl+C once only after scan/prep has emitted both "
            "sentinels and managed analysis is running.",
            flush=True,
        )

    env = os.environ.copy()
    venv = repo_root / ".venv"
    venv_bin = venv / "bin"
    if venv_bin.is_dir():
        env["VIRTUAL_ENV"] = str(venv)
        env["PATH"] = str(venv_bin) + os.pathsep + env.get("PATH", "")
    os.chdir(repo_root)
    os.execve(argv[0], argv, env)


def _parse_timestamp(value: object) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _candidate_manifests(
    state: dict[str, Any],
    phase: str,
    *,
    repo_root: Path,
) -> list[Path]:
    run_state = state["runs"][phase]
    launch_epoch = run_state.get("launch_started_epoch")
    if not isinstance(launch_epoch, (int, float)):
        raise AcceptanceError(f"{phase} launch has not been recorded")
    fixture = Path(str(state["fixture"])).resolve()
    excluded = {
        Path(str(value.get("run_dir"))).resolve()
        for name, value in state["runs"].items()
        if name != phase and isinstance(value, dict) and value.get("run_dir")
    }
    candidates: list[Path] = []
    out_dir = repo_root / "out"
    if not out_dir.is_dir():
        return candidates
    for run_dir in sorted(out_dir.glob("agentic_*")):
        if not run_dir.is_dir() or run_dir.is_symlink() or run_dir.resolve() in excluded:
            continue
        metadata_path = run_dir / ".raptor-run.json"
        if not metadata_path.is_file() or metadata_path.is_symlink():
            continue
        try:
            metadata = _load_object(
                metadata_path,
                role="run metadata",
                max_bytes=_MAX_METADATA_BYTES,
            )
        except AcceptanceError:
            continue
        if metadata.get("command") != "agentic":
            continue
        target_path = metadata.get("target_path")
        if not isinstance(target_path, str):
            continue
        try:
            if Path(target_path).resolve() != fixture:
                continue
        except OSError:
            continue
        run_epoch = _parse_timestamp(metadata.get("timestamp"))
        if run_epoch is None or run_epoch < float(launch_epoch) - 5:
            continue
        extra = metadata.get("extra")
        manifest_value = (
            extra.get("copilot_native_manifest")
            if isinstance(extra, dict)
            else None
        )
        manifest_path = (
            Path(manifest_value).resolve()
            if isinstance(manifest_value, str) and manifest_value
            else run_dir.resolve() / "copilot-native" / "manifest.json"
        )
        if manifest_path.is_file() and not manifest_path.is_symlink():
            candidates.append(manifest_path)
    return candidates


def _resolve_manifest(
    state: dict[str, Any],
    phase: str,
    manifest: Path | None,
    *,
    repo_root: Path,
) -> Path:
    if manifest is not None:
        return manifest.expanduser().resolve()
    recorded = state["runs"][phase].get("manifest")
    if isinstance(recorded, str) and recorded:
        return Path(recorded).resolve()
    candidates = _candidate_manifests(state, phase, repo_root=repo_root)
    if len(candidates) != 1:
        rendered = ", ".join(_display(path) for path in candidates) or "none"
        raise AcceptanceError(
            f"expected exactly one {phase} run matching the fixture and "
            f"launch time; found {len(candidates)} ({rendered}). Pass "
            "--manifest with the exact emitted COPILOT_NATIVE_MANIFEST path.",
        )
    return candidates[0]


def _inside(root: Path, path: Path) -> bool:
    root = root.resolve()
    path = path.resolve()
    return path == root or root in path.parents


def _inspect_manifest(
    manifest_path: Path,
    state: dict[str, Any],
    *,
    repo_root: Path,
) -> dict[str, Any]:
    manifest_path = manifest_path.resolve()
    manifest = _load_object(
        manifest_path,
        role="Copilot-native manifest",
        max_bytes=_MAX_MANIFEST_BYTES,
    )
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise AcceptanceError("unsupported Copilot-native manifest schema")
    run_dir = Path(str(manifest.get("run_dir"))).resolve()
    expected_manifest = run_dir / "copilot-native" / "manifest.json"
    if manifest_path != expected_manifest:
        raise AcceptanceError(
            "manifest is not the canonical manifest inside its run directory",
        )
    if not _inside(repo_root / "out", run_dir):
        raise AcceptanceError(
            "projectless POST-02 run escaped the repository out directory",
        )
    target = Path(str(manifest.get("target"))).resolve()
    fixture = Path(str(state["fixture"])).resolve()
    if target != fixture:
        raise AcceptanceError(
            f"manifest target {_display(target)} does not match fixture "
            f"{_display(fixture)}",
        )
    if manifest.get("max_findings") != 2:
        raise AcceptanceError("POST-02 manifest must record max_findings=2")
    selected = manifest.get("selected_findings")
    if not isinstance(selected, int) or not 1 <= selected <= 2:
        raise AcceptanceError(
            "fixture scan must select one or two findings for acceptance",
        )
    parts = manifest.get("parts")
    if not isinstance(parts, list) or not parts:
        raise AcceptanceError("Copilot-native manifest contains no parts")

    part_ids: list[str] = []
    finding_ids: list[str] = []
    rows: list[dict[str, Any]] = []
    for index, part in enumerate(parts):
        if not isinstance(part, dict):
            raise AcceptanceError(f"manifest part {index} is not an object")
        part_id = part.get("part_id")
        if not isinstance(part_id, str) or not _PART_ID_RE.fullmatch(part_id):
            raise AcceptanceError(f"manifest part {index} has invalid part_id")
        raw_findings = part.get("finding_ids")
        if (
            not isinstance(raw_findings, list)
            or not raw_findings
            or not all(isinstance(item, str) and item for item in raw_findings)
        ):
            raise AcceptanceError(f"{part_id} has invalid finding_ids")
        request_path = Path(str(part.get("request_path"))).resolve()
        result_path = Path(str(part.get("result_path"))).resolve()
        if not _inside(run_dir, request_path) or not _inside(run_dir, result_path):
            raise AcceptanceError(f"{part_id} path escapes the run directory")
        if not request_path.is_file() or request_path.is_symlink():
            raise AcceptanceError(f"{part_id} request is missing or not regular")
        part_ids.append(part_id)
        finding_ids.extend(raw_findings)
        rows.append({
            "part_id": part_id,
            "finding_ids": list(raw_findings),
            "request_path": request_path,
            "result_path": result_path,
        })
    if len(part_ids) != len(set(part_ids)):
        raise AcceptanceError("manifest contains duplicate part IDs")
    if len(finding_ids) != len(set(finding_ids)):
        raise AcceptanceError("manifest assigns a finding more than once")
    if len(finding_ids) != selected:
        raise AcceptanceError(
            "manifest assignment count does not match selected_findings",
        )
    return {
        "manifest": manifest,
        "manifest_path": manifest_path,
        "run_dir": run_dir,
        "parts": rows,
        "selected": selected,
    }


def _lint_results(context: dict[str, Any]) -> dict[str, Any]:
    manifest_path = context["manifest_path"]
    valid: list[dict[str, Any]] = []
    missing: list[str] = []
    invalid: dict[str, str] = {}
    for part in context["parts"]:
        result_path = part["result_path"]
        if not result_path.exists():
            missing.append(part["part_id"])
            continue
        try:
            results = lint_part(manifest_path, result_path)
        except CopilotNativeError as exc:
            invalid[part["part_id"]] = str(exc)
            continue
        valid.append({
            "part_id": part["part_id"],
            "finding_ids": list(part["finding_ids"]),
            "result_path": str(result_path),
            "results": len(results),
            "sha256": _sha256(result_path),
        })
    return {
        "valid": valid,
        "missing": missing,
        "invalid": invalid,
    }


def _run_metadata(context: dict[str, Any]) -> dict[str, Any]:
    metadata = _load_object(
        context["run_dir"] / ".raptor-run.json",
        role="run metadata",
        max_bytes=_MAX_METADATA_BYTES,
    )
    if metadata.get("command") != "agentic":
        raise AcceptanceError("run metadata command is not agentic")
    session_host = metadata.get("session_host")
    if session_host not in (None, "copilot"):
        raise AcceptanceError(
            f"run metadata records a non-Copilot host: {session_host!r}",
        )
    target = metadata.get("target_path")
    if not isinstance(target, str) or Path(target).resolve() != Path(
        str(context["manifest"]["target"]),
    ).resolve():
        raise AcceptanceError("run metadata target does not match manifest")
    models = (
        metadata.get("manifest", {}).get("models")
        if isinstance(metadata.get("manifest"), dict)
        else None
    )
    if isinstance(models, list) and models:
        if any(
            not isinstance(model, dict)
            or model.get("provider") != "copilot"
            for model in models
        ):
            raise AcceptanceError(
                "run metadata records non-Copilot model routing",
            )
    elif metadata.get("status") == "interrupted":
        extra = metadata.get("extra")
        expected_manifest = (
            extra.get("copilot_native_manifest")
            if isinstance(extra, dict)
            else None
        )
        if (
            not isinstance(expected_manifest, str)
            or Path(expected_manifest).resolve() != context["manifest_path"]
        ):
            raise AcceptanceError(
                "interrupted run metadata lacks its Copilot-native manifest",
            )
    else:
        raise AcceptanceError(
            "completed run metadata does not record Copilot model routing",
        )
    return metadata


def _argv_value(argv: list[str], name: str) -> str | None:
    prefix = f"{name}="
    for index, value in enumerate(argv):
        if value.startswith(prefix):
            return value[len(prefix):]
        if value == name and index + 1 < len(argv):
            return argv[index + 1]
    return None


def _launcher_claim(
    state: dict[str, Any],
    phase: str,
    *,
    repo_root: Path,
) -> dict[str, Any]:
    run_state = state["runs"][phase]
    raw_argv = run_state.get("launcher_argv")
    if (
        not isinstance(raw_argv, list)
        or not raw_argv
        or not all(isinstance(value, str) and value for value in raw_argv)
    ):
        raise AcceptanceError(f"{phase} launcher argv is missing")
    argv = list(raw_argv)
    expected_launcher = (repo_root / "bin" / "raptor").resolve()
    if Path(argv[0]).resolve() != expected_launcher:
        raise AcceptanceError(
            f"{phase} launcher argv names another executable",
        )
    expected = {
        "--frontend": "copilot",
        "--project": "-",
        "--max-findings": "2",
        "--max-ai-credits": "30",
        "--usage-output-file": str(
            Path(str(run_state.get("usage_path"))).resolve(),
        ),
    }
    for name, value in expected.items():
        if _argv_value(argv, name) != value:
            raise AcceptanceError(
                f"{phase} launcher argv does not preserve {name}={value}",
            )
    frontend_model = run_state.get("frontend_model")
    if frontend_model is not None and (
        not isinstance(frontend_model, str)
        or not frontend_model
        or _argv_value(argv, "--model") != frontend_model
    ):
        raise AcceptanceError(
            f"{phase} launcher argv does not preserve its frontend model",
        )
    fixture = Path(str(state["fixture"])).resolve()
    if Path(argv[-1]).resolve() != fixture:
        raise AcceptanceError(f"{phase} launcher target does not match fixture")
    return {
        "argv": argv,
        "launcher": str(expected_launcher),
        "target": str(fixture),
    }


def _host_evidence(
    state: dict[str, Any],
    phase: str,
    metadata: dict[str, Any],
    *,
    repo_root: Path,
    startup: dict[str, Any],
    usage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    session_host = metadata.get("session_host")
    if session_host == "copilot":
        return {
            "mode": "run_metadata",
            "run_metadata_session_host": "copilot",
            "exception": None,
        }

    claim = _launcher_claim(state, phase, repo_root=repo_root)
    if not startup.get("present"):
        raise AcceptanceError(
            "run metadata has no session_host and current launcher startup "
            "evidence is unavailable",
        )
    frontend = startup.get("frontend")
    llm = startup.get("llm")
    if (
        not isinstance(frontend, str)
        or not frontend.startswith("frontend: GitHub Copilot CLI")
        or llm != "llm: Copilot session only (standalone providers blocked)"
    ):
        raise AcceptanceError(
            "run metadata has no session_host and startup does not record the "
            "Copilot session-only frontend",
        )
    if usage is not None:
        usage_epoch = _parse_timestamp(usage.get("session_start_time"))
        launch_epoch = state["runs"][phase].get("launch_started_epoch")
        if (
            not isinstance(launch_epoch, (int, float))
            or usage_epoch is None
            or usage_epoch < float(launch_epoch) - 5
        ):
            raise AcceptanceError(
                "Copilot usage output does not belong to the recorded launch",
            )
    return {
        "mode": "launcher_corroborated",
        "run_metadata_session_host": None,
        "launcher": claim,
        "exception": (
            "run metadata omitted session_host after launcher-bound local "
            "scan/prep recovery; the checker did not rewrite it and instead "
            "corroborated the exact launcher argv, fresh Copilot startup "
            "banner, target, timestamps, Copilot-only model manifest, usage "
            "output and native finalization artifacts"
        ),
    }


def _assert_launch_binding(
    state: dict[str, Any],
    phase: str,
    context: dict[str, Any],
    metadata: dict[str, Any],
) -> None:
    launch_epoch = state["runs"][phase].get("launch_started_epoch")
    if not isinstance(launch_epoch, (int, float)):
        raise AcceptanceError(f"{phase} launch time is missing")
    run_epoch = _parse_timestamp(metadata.get("timestamp"))
    if run_epoch is None or run_epoch < float(launch_epoch) - 5:
        raise AcceptanceError(
            "run metadata predates the recorded launcher invocation",
        )
    if phase == "cancellation":
        successful_run = state["runs"]["success"].get("run_dir")
        if (
            isinstance(successful_run, str)
            and Path(successful_run).resolve() == context["run_dir"]
        ):
            raise AcceptanceError(
                "cancellation phase resolved to the successful run",
            )


def _usage_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"present": False, "path": str(path)}
    usage = _load_object(
        path,
        role="Copilot usage output",
        max_bytes=_MAX_USAGE_BYTES,
    )
    model_metrics = usage.get("modelMetrics")
    models = (
        sorted(str(name) for name in model_metrics)
        if isinstance(model_metrics, dict)
        else []
    )
    total_nano_aiu = usage.get("totalNanoAiu")
    credits_status = usage.get("aiCreditsStatus")
    if (
        isinstance(total_nano_aiu, bool)
        or not isinstance(total_nano_aiu, (int, float))
    ):
        raise AcceptanceError(
            "Copilot usage output lacks numeric totalNanoAiu",
        )
    if credits_status is not None and (
        not isinstance(credits_status, str) or not credits_status
    ):
        raise AcceptanceError("Copilot usage aiCreditsStatus is invalid")
    session_start_time = usage.get("sessionStartTime")
    if _parse_timestamp(session_start_time) is None:
        raise AcceptanceError(
            "Copilot usage output lacks a valid sessionStartTime",
        )
    agent_metrics = usage.get("agentMetrics")
    attributed_activity = bool(
        total_nano_aiu
        or usage.get("totalUserRequests")
        or models
        or (isinstance(agent_metrics, dict) and agent_metrics)
    )
    accounting_complete = (
        credits_status == "complete" and attributed_activity
    )
    accounting_note = None
    if not accounting_complete:
        accounting_note = (
            "Copilot usage output did not attest complete managed-agent "
            "credit accounting; zero or absent attribution is unknown host "
            "usage, not proof of zero spend"
        )
    return {
        "present": True,
        "path": str(path),
        "sha256": _sha256(path),
        "bytes": path.stat().st_size,
        "current_model": usage.get("currentModel"),
        "models": models,
        "total_nano_aiu": total_nano_aiu,
        "ai_credits_status": credits_status or "not_reported",
        "accounting_complete": accounting_complete,
        "accounting_note": accounting_note,
        "session_start_time": session_start_time,
        "total_user_requests": usage.get("totalUserRequests"),
        "total_api_duration_ms": usage.get("totalApiDurationMs"),
    }


def _startup_snapshot(repo_root: Path, launch_epoch: object) -> dict[str, Any]:
    path = repo_root / ".startup-output"
    if not isinstance(launch_epoch, (int, float)):
        return {"present": False, "reason": "launch time unavailable"}
    try:
        file_stat = path.lstat()
    except FileNotFoundError:
        return {"present": False, "reason": "startup output missing"}
    if not stat.S_ISREG(file_stat.st_mode):
        return {"present": False, "reason": "startup output not regular"}
    if file_stat.st_size > _MAX_STARTUP_BYTES:
        return {"present": False, "reason": "startup output too large"}
    if file_stat.st_mtime < float(launch_epoch) - 5:
        return {"present": False, "reason": "startup output predates launch"}
    text = path.read_text(encoding="utf-8", errors="replace")
    frontend = next(
        (line.strip() for line in text.splitlines() if line.startswith("frontend:")),
        None,
    )
    llm = next(
        (line.strip() for line in text.splitlines() if line.startswith("   llm:")),
        None,
    )
    return {
        "present": bool(frontend and llm),
        "path": str(path),
        "frontend": frontend,
        "llm": llm,
    }


def _complete_record(
    state: dict[str, Any],
    phase: str,
    context: dict[str, Any],
    lint: dict[str, Any],
    metadata: dict[str, Any],
    *,
    repo_root: Path,
    usage_path: Path,
    startup: dict[str, Any],
) -> dict[str, Any]:
    if lint["missing"] or lint["invalid"]:
        raise AcceptanceError(
            "complete run has missing or invalid native result parts",
        )
    if metadata.get("status") != "completed":
        raise AcceptanceError(
            f"expected completed lifecycle, got {metadata.get('status')!r}",
        )
    run_dir = context["run_dir"]
    required = (
        run_dir / "agentic-report.md",
        run_dir / "orchestrated_report.json",
        run_dir / "copilot-native" / "finalization-receipt.json",
    )
    for path in required:
        if not path.is_file() or path.is_symlink():
            raise AcceptanceError(f"required final artifact missing: {path}")
    receipt = _load_object(
        required[2],
        role="finalization receipt",
        max_bytes=_MAX_MANIFEST_BYTES,
    )
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise AcceptanceError("unsupported finalization receipt schema")
    if Path(str(receipt.get("manifest"))).resolve() != context["manifest_path"]:
        raise AcceptanceError("finalization receipt names another manifest")
    if receipt.get("manifest_sha256") != _sha256(context["manifest_path"]):
        raise AcceptanceError("finalization receipt manifest hash mismatch")
    extra = metadata.get("extra")
    if not isinstance(extra, dict):
        raise AcceptanceError("run metadata extra field is missing")
    assessment = extra.get("assessment")
    if not isinstance(assessment, dict):
        raise AcceptanceError("run metadata assessment is missing")
    selected = context["selected"]
    if (
        assessment.get("selected") != selected
        or assessment.get("analyzed") != selected
        or assessment.get("analysis_failures") != 0
    ):
        raise AcceptanceError(
            "run metadata does not completely assess the selected findings",
        )
    assessment_status = assessment.get("status")
    if assessment_status == "complete":
        if assessment.get("unreviewed") != 0:
            raise AcceptanceError(
                "complete assessment still records unreviewed findings",
            )
    elif assessment_status == "partial":
        eligible = assessment.get("eligible")
        unreviewed = assessment.get("unreviewed")
        unselected = assessment.get("unselected")
        if (
            not assessment.get("cap_applied")
            or assessment.get("cap_source") != "explicit"
            or assessment.get("cap") != selected
            or not isinstance(eligible, int)
            or eligible < selected
            or unreviewed != eligible - selected
            or unselected != eligible - selected
        ):
            raise AcceptanceError(
                "partial assessment is not explained solely by the explicit "
                "finding cap",
            )
    else:
        raise AcceptanceError(
            f"unsupported assessment status: {assessment_status!r}",
        )
    if extra.get("analysis_model") != "copilot-native":
        raise AcceptanceError("run metadata analysis_model is not copilot-native")
    usage = _usage_summary(usage_path)
    if not usage.get("present"):
        raise AcceptanceError(
            "Copilot usage output is missing; exit the live session before "
            "running the completion check",
        )
    if not startup.get("present"):
        raise AcceptanceError(
            f"current launcher startup lines are unavailable: "
            f"{startup.get('reason', 'frontend/llm lines missing')}",
        )
    host_evidence = _host_evidence(
        state,
        phase,
        metadata,
        repo_root=repo_root,
        startup=startup,
        usage=usage,
    )
    return {
        "checked_at": _now(),
        "manifest": str(context["manifest_path"]),
        "manifest_sha256": _sha256(context["manifest_path"]),
        "run_dir": str(run_dir),
        "selected_findings": context["selected"],
        "part_ids": [part["part_id"] for part in context["parts"]],
        "finding_ids": [
            finding_id
            for part in context["parts"]
            for finding_id in part["finding_ids"]
        ],
        "linted_parts": lint["valid"],
        "lifecycle_status": metadata.get("status"),
        "assessment": assessment,
        "artifacts": [str(path) for path in required],
        "partial_reasons": extra.get("partial_reasons", []),
        "usage": usage,
        "startup": startup,
        "host_evidence": host_evidence,
    }


def _check_complete(
    workspace: Path,
    phase: str,
    *,
    manifest: Path | None = None,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
    repo_root = (repo_root or Path(str(state["repo_root"]))).resolve()
    manifest_path = _resolve_manifest(
        state,
        phase,
        manifest,
        repo_root=repo_root,
    )
    context = _inspect_manifest(manifest_path, state, repo_root=repo_root)
    lint = _lint_results(context)
    metadata = _run_metadata(context)
    _assert_launch_binding(state, phase, context, metadata)
    run_state = state["runs"][phase]
    startup = _startup_snapshot(
        repo_root,
        run_state.get("launch_started_epoch"),
    )
    record = _complete_record(
        state,
        phase,
        context,
        lint,
        metadata,
        repo_root=repo_root,
        usage_path=Path(str(run_state["usage_path"])).resolve(),
        startup=startup,
    )
    run_state.update(record)
    if phase == "cancellation":
        run_state["resumed"] = True
    _save_state(workspace, state)
    return record


def _resume_prompt(manifest_path: Path, incomplete: list[str]) -> str:
    part_text = ", ".join(incomplete)
    return (
        "Resume the existing Copilot-native RAPTOR run using the manifest at "
        f"{manifest_path}. Dispatch only these missing or invalid parts: "
        f"{part_text}. Independently run "
        "`libexec/raptor-copilot-agentic lint-part` for every result, then "
        "finalize this same manifest. Do not start a new scan, run, frontend, "
        "provider, or account.\n"
    )


def _check_cancelled(
    workspace: Path,
    *,
    manifest: Path | None = None,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
    repo_root = (repo_root or Path(str(state["repo_root"]))).resolve()
    manifest_path = _resolve_manifest(
        state,
        "cancellation",
        manifest,
        repo_root=repo_root,
    )
    context = _inspect_manifest(manifest_path, state, repo_root=repo_root)
    metadata = _run_metadata(context)
    _assert_launch_binding(state, "cancellation", context, metadata)
    startup = _startup_snapshot(
        repo_root,
        state["runs"]["cancellation"].get("launch_started_epoch"),
    )
    usage_path = Path(
        str(state["runs"]["cancellation"].get("usage_path")),
    ).resolve()
    usage = _usage_summary(usage_path) if usage_path.exists() else None
    host_evidence = _host_evidence(
        state,
        "cancellation",
        metadata,
        repo_root=repo_root,
        startup=startup,
        usage=usage,
    )
    if metadata.get("status") != "interrupted":
        raise AcceptanceError(
            "cancelled run must remain interrupted before resume",
        )
    lint = _lint_results(context)
    incomplete = lint["missing"] + sorted(lint["invalid"])
    if not incomplete:
        raise AcceptanceError(
            "every part is already valid; cancellation happened too late to "
            "prove premature-finalization refusal",
        )
    try:
        finalize_handoff(manifest_path)
    except CopilotNativeError as exc:
        refusal = str(exc)
    else:
        raise AcceptanceError(
            "premature finalization unexpectedly succeeded",
        )
    metadata_after = _run_metadata(context)
    if metadata_after.get("status") != "interrupted":
        raise AcceptanceError(
            "premature finalization changed the interrupted lifecycle",
        )
    prompt = _resume_prompt(manifest_path, incomplete)
    prompt_path = workspace / RESUME_PROMPT_FILE
    _atomic_write_text(prompt_path, prompt)
    record = {
        "checked_at": _now(),
        "manifest": str(manifest_path),
        "manifest_sha256": _sha256(manifest_path),
        "run_dir": str(context["run_dir"]),
        "selected_findings": context["selected"],
        "part_ids": [part["part_id"] for part in context["parts"]],
        "valid_parts_before_resume": [
            part["part_id"] for part in lint["valid"]
        ],
        "incomplete_parts": incomplete,
        "premature_finalization_refused": True,
        "premature_finalization_error": refusal,
        "lifecycle_status": metadata_after.get("status"),
        "resume_prompt": str(prompt_path),
        "startup": startup,
        "host_evidence": host_evidence,
        "usage_before_resume": usage,
    }
    state["runs"]["cancellation"].update(record)
    _save_state(workspace, state)
    return record


def _md(value: object) -> str:
    return _display(value, max_len=1200).replace("|", "\\|").replace("\n", "<br>")


def _phase_rows(name: str, value: dict[str, Any]) -> list[str]:
    if not value.get("manifest"):
        return [f"| {name} | Not checked |  |"]
    status = value.get("lifecycle_status", "")
    run_dir = value.get("run_dir", "")
    return [f"| {name} | {_md(status)} | `{_md(run_dir)}` |"]


def _usage_rows(state: dict[str, Any]) -> list[str]:
    rows: list[str] = []
    for name, run in state["runs"].items():
        usage = run.get("usage")
        if not isinstance(usage, dict):
            rows.append(f"| {name} | Not recorded |  |  |  |")
            continue
        rows.append(
            f"| {name} | {_md(usage.get('ai_credits_status'))} | "
            f"{_md(usage.get('total_nano_aiu'))} | "
            f"{_md(usage.get('accounting_complete'))} | "
            f"{_md(', '.join(usage.get('models', [])))} |",
        )
    return rows


def _write_evidence(workspace: Path, state: dict[str, Any]) -> None:
    success = state["runs"]["success"]
    cancellation = state["runs"]["cancellation"]
    attestations = state.get("operator_attestations")
    if not isinstance(attestations, dict):
        attestations = {}

    def attestation_line(key: str, text: str) -> str:
        record = attestations.get(key)
        checked = isinstance(record, dict) and record.get("value") is True
        marker = "x" if checked else " "
        source = (
            f" Source: {_md(record.get('source'))}."
            if checked and isinstance(record, dict) and record.get("source")
            else ""
        )
        return f"- [{marker}] {text}{source}"

    lines = [
        "# POST-02 live Copilot acceptance evidence",
        "",
        "> Generated by `.github/scripts/copilot_post02_acceptance.py`.",
        "> Review the manual attestations before copying this into tracked docs.",
        "",
        "## Baseline",
        "",
        "| Item | Value |",
        "|---|---|",
        f"| RAPTOR commit | `{_md(state.get('raptor_commit'))}` |",
        f"| RAPTOR status | `{_md(state.get('raptor_status'))}` |",
        f"| Fixture commit | `{_md(state.get('fixture_commit'))}` |",
        f"| Fixture | `{_md(state.get('fixture'))}` |",
        f"| Copilot version | `{_md(state.get('copilot_version'))}` |",
        f"| Requested frontend model | "
        f"`{_md(state.get('frontend_model', 'not recorded'))}` |",
        "",
        "## Run status",
        "",
        "| Phase | Lifecycle | Run directory |",
        "|---|---|---|",
        *_phase_rows("Successful run", success),
        *_phase_rows("Cancellation/resume run", cancellation),
        "",
        "## Cancellation proof",
        "",
        f"- Premature finalization refused: "
        f"`{_md(cancellation.get('premature_finalization_refused', False))}`",
        f"- Refusal: `{_md(cancellation.get('premature_finalization_error', ''))}`",
        f"- Incomplete parts: "
        f"`{_md(', '.join(cancellation.get('incomplete_parts', [])))}`",
        f"- Resumed same run: `{_md(cancellation.get('resumed', False))}`",
        "",
        "## Host usage",
        "",
        "| Phase | Credits status | totalNanoAiu | Accounting complete | Models |",
        "|---|---|---:|---|---|",
        *_usage_rows(state),
        "",
        "Repository USD limits are not Copilot-managed-agent credit limits.",
        "",
        "## Acceptance exceptions",
        "",
        f"- Successful-run host evidence: "
        f"`{_md(success.get('host_evidence', {}).get('mode', 'not checked'))}`",
        f"- Successful-run host exception: "
        f"`{_md(success.get('host_evidence', {}).get('exception', 'none'))}`",
        f"- Successful-run accounting note: "
        f"`{_md(success.get('usage', {}).get('accounting_note', 'none'))}`",
        f"- Cancellation-run host evidence: "
        f"`{_md(cancellation.get('host_evidence', {}).get('mode', 'not checked'))}`",
        f"- Cancellation-run host exception: "
        f"`{_md(cancellation.get('host_evidence', {}).get('exception', 'none'))}`",
        "",
        "## Manual attestations",
        "",
        attestation_line(
            "sentinels_visible",
            "Both `OUTPUT_DIR=` and `COPILOT_NATIVE_MANIFEST=` were visibly "
            "emitted by each accepted scan/prep run.",
        ),
        attestation_line(
            "assignment_integrity",
            "The transcript shows one active owner per manifest part per "
            "attempt, no duplicate concurrent assignment, and only the "
            "cancelled part was re-dispatched during resume.",
        ),
        attestation_line(
            "service_boundary",
            "No second frontend, provider, account, saved credential, or "
            "external fallback was used.",
        ),
        attestation_line(
            "reductions_visible",
            "Offline/cache-only SCA and every unsupported native stage were "
            "reported as visible reductions.",
        ),
        "",
    ]
    _atomic_write_text(workspace / EVIDENCE_FILE, "\n".join(lines))


def _record_attestations(
    workspace: Path,
    *,
    sentinels_source: str,
    operator_source: str,
) -> None:
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
    if (
        state["runs"]["success"].get("lifecycle_status") != "completed"
        or state["runs"]["cancellation"].get("lifecycle_status") != "completed"
        or not state["runs"]["cancellation"].get("premature_finalization_refused")
        or not state["runs"]["cancellation"].get("resumed")
    ):
        raise AcceptanceError(
            "mechanical success and cancellation/resume checks must complete "
            "before attestations are recorded",
        )
    checked_at = _now()
    state["operator_attestations"] = {
        "sentinels_visible": {
            "value": True,
            "source": sentinels_source,
            "checked_at": checked_at,
        },
        "assignment_integrity": {
            "value": True,
            "source": operator_source,
            "checked_at": checked_at,
        },
        "service_boundary": {
            "value": True,
            "source": operator_source,
            "checked_at": checked_at,
        },
        "reductions_visible": {
            "value": True,
            "source": operator_source,
            "checked_at": checked_at,
        },
    }
    _save_state(workspace, state)


def _attestations_complete(state: dict[str, Any]) -> bool:
    attestations = state.get("operator_attestations")
    if not isinstance(attestations, dict):
        return False
    return all(
        isinstance(attestations.get(key), dict)
        and attestations[key].get("value") is True
        for key in (
            "sentinels_visible",
            "assignment_integrity",
            "service_boundary",
            "reductions_visible",
        )
    )


def _next_steps(workspace: Path, state: dict[str, Any]) -> list[str]:
    script = Path(__file__).resolve()
    python = Path(str(state.get("python_executable") or sys.executable)).resolve()
    quoted_python = shlex.quote(str(python))
    quoted_script = shlex.quote(str(script))
    quoted_workspace = shlex.quote(str(workspace))
    success = state["runs"]["success"]
    cancellation = state["runs"]["cancellation"]
    if not success.get("launch_started_epoch"):
        return [
            "Exit the current Copilot session, then run:",
            f"{quoted_python} {quoted_script} launch-success "
            f"--workspace {quoted_workspace}",
        ]
    if not success.get("manifest"):
        return [
            "After the successful session exits, run:",
            f"{quoted_python} {quoted_script} check-success "
            f"--workspace {quoted_workspace}",
        ]
    if not cancellation.get("launch_started_epoch"):
        return [
            "Start the cancellation run:",
            f"{quoted_python} {quoted_script} launch-cancel "
            f"--workspace {quoted_workspace}",
            "Press Ctrl+C once after managed analysis starts.",
        ]
    if not cancellation.get("premature_finalization_refused"):
        return [
            "Inside the still-running cancelled Copilot session, run or ask "
            "Copilot to run:",
            f"{quoted_python} {quoted_script} check-cancelled "
            f"--workspace {quoted_workspace}",
        ]
    if not cancellation.get("resumed"):
        return [
            f"Paste `{workspace / RESUME_PROMPT_FILE}` into the same session.",
            "After the resumed run completes and the session exits, run:",
            f"{quoted_python} {quoted_script} check-resumed "
            f"--workspace {quoted_workspace}",
        ]
    if not _attestations_complete(state):
        return [
            "POST-02 mechanical checks are complete.",
            f"Review `{workspace / EVIDENCE_FILE}` and complete its manual "
            "attestations.",
        ]
    return [
        "POST-02 acceptance evidence is complete.",
        f"Evidence: `{workspace / EVIDENCE_FILE}`",
    ]


def _show(workspace: Path) -> None:
    workspace = workspace.expanduser().resolve()
    state = _load_state(workspace)
    print(f"WORKSPACE={workspace}")
    print(f"FIXTURE={state['fixture']}")
    print(f"STATE={workspace / STATE_FILE}")
    print(f"EVIDENCE={workspace / EVIDENCE_FILE}")
    print()
    for line in _next_steps(workspace, state):
        print(line)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Automate deterministic POST-02 Copilot acceptance work",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare", help="create fixture and acceptance state")
    prepare.add_argument("--workspace", type=Path)
    prepare.add_argument(
        "--frontend-model",
        required=True,
        help="explicit same-service Copilot model ID for both live sessions",
    )

    for name in ("launch-success", "launch-cancel"):
        launch = sub.add_parser(name, help=f"start the {name[7:]} live session")
        launch.add_argument("--workspace", type=Path, required=True)
        launch.add_argument("--retry", action="store_true")

    for name in ("check-success", "check-cancelled"):
        check = sub.add_parser(name, help=f"verify the {name[6:]} phase")
        check.add_argument("--workspace", type=Path, required=True)
        check.add_argument("--manifest", type=Path)

    resumed = sub.add_parser(
        "check-resumed",
        help="verify completion of the interrupted run",
    )
    resumed.add_argument("--workspace", type=Path, required=True)

    show = sub.add_parser("show", help="show current state and exact next command")
    show.add_argument("--workspace", type=Path, required=True)

    attest = sub.add_parser(
        "attest",
        help="record completed transcript/operator attestations",
    )
    attest.add_argument("--workspace", type=Path, required=True)
    attest.add_argument("--sentinels-source", required=True)
    attest.add_argument("--operator-source", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare":
            _refuse_nested_frontend()
            workspace = _prepare_workspace(
                args.workspace,
                frontend_model=args.frontend_model,
            )
            _show(workspace)
            return 0
        if args.command == "launch-success":
            _launch(args.workspace, "success", retry=args.retry)
            return 0
        if args.command == "launch-cancel":
            _launch(args.workspace, "cancellation", retry=args.retry)
            return 0
        if args.command == "check-success":
            record = _check_complete(
                args.workspace,
                "success",
                manifest=args.manifest,
            )
            print(
                "Successful run verified: "
                f"{_display(record['run_dir'])}",
            )
            _show(args.workspace)
            return 0
        if args.command == "check-cancelled":
            record = _check_cancelled(
                args.workspace,
                manifest=args.manifest,
            )
            print(
                "Interrupted run and premature-finalization refusal verified.",
            )
            print()
            print(
                Path(str(record["resume_prompt"])).read_text(encoding="utf-8"),
                end="",
            )
            print()
            _show(args.workspace)
            return 0
        if args.command == "check-resumed":
            state = _load_state(args.workspace.expanduser().resolve())
            cancellation = state["runs"]["cancellation"]
            if not cancellation.get("premature_finalization_refused"):
                raise AcceptanceError(
                    "run check-cancelled before check-resumed",
                )
            record = _check_complete(args.workspace, "cancellation")
            print(
                "Resumed cancellation run verified: "
                f"{_display(record['run_dir'])}",
            )
            _show(args.workspace)
            return 0
        if args.command == "show":
            _show(args.workspace)
            return 0
        if args.command == "attest":
            _record_attestations(
                args.workspace,
                sentinels_source=args.sentinels_source,
                operator_source=args.operator_source,
            )
            print("POST-02 attestations recorded.")
            _show(args.workspace)
            return 0
    except AcceptanceError as exc:
        print(f"POST-02 acceptance: {_display(exc)}", file=sys.stderr)
        return 2
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
