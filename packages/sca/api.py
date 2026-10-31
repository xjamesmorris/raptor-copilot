"""Programmatic API for the SCA pipeline.

Thin wrapper over :func:`pipeline.run_sca` that returns a structured
result dict suitable for JSON serialisation or direct consumption by
the ``/agentic`` orchestrator. Callers that need full control should
call :func:`pipeline.run_sca` directly.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .diagnostics import (
    DIAGNOSTIC_FILENAME,
    ScaDeadlineExceeded,
    finalize_sca_diagnostic,
)
from .pipeline import RunOptions, RunResult, run_sca

logger = logging.getLogger(__name__)


def analyse(
    target: Path,
    output_dir: Path,
    *,
    offline: bool = False,
    no_cache: bool = False,
    sarif_dirs: list[Path] | None = None,
    enable_llm_review: bool = True,
    enable_triage: bool = True,
    deadline_seconds: float | None = None,
    analysis_mode: str = "deep",
) -> dict[str, Any]:
    """Run the full SCA pipeline and return a summary dict.

    Parameters
    ----------
    target:
        Root of the project to scan.
    output_dir:
        Where to write findings.json, report.md, sbom, sarif.
    offline:
        Skip all network calls.
    no_cache:
        Ignore cached data.
    sarif_dirs:
        Sibling SARIF directories from other tools (Semgrep, CodeQL).
        When provided, cross-tool ``related_findings`` linking is
        performed after the SCA run completes.
    enable_llm_review / enable_triage:
        Deep-SCA gates. The agentic mechanical subprocess disables both;
        direct/deep SCA keeps the existing enabled defaults. Passing
        ``analysis_mode="mechanical"`` centrally normalizes both gates off;
        lower-level ``RunOptions`` rejects contradictory mechanical+LLM
        combinations.
    deadline_seconds:
        Optional child-side budget. The agentic parent passes a deadline
        shorter than its own timeout so the child can persist diagnostics
        and exit cleanly before the outer kill.

    Returns a dict with keys: ``status``, ``findings_path``,
    ``sarif_path``, ``report_path``, ``sbom_path``, ``vuln_findings``,
    ``hygiene_findings``, ``supply_chain_findings``,
    ``suppressed_findings``, ``in_kev``, ``deps_analysed``,
    ``llm_cost``.
    """
    output_dir = Path(output_dir)
    diagnostics_path = output_dir / DIAGNOSTIC_FILENAME
    if analysis_mode == "mechanical":
        if enable_llm_review or enable_triage:
            logger.info(
                "sca.api: mechanical mode normalizes LLM review and "
                "triage off; use analysis_mode='deep' to enable them",
            )
        enable_llm_review = False
        enable_triage = False
    options = RunOptions(
        offline=offline,
        no_cache=no_cache,
        enable_llm_review=enable_llm_review,
        enable_triage=enable_triage,
        deadline_seconds=deadline_seconds,
        diagnostics_path=diagnostics_path,
        analysis_mode=analysis_mode,
    )

    try:
        result = run_sca(
            target=Path(target).resolve(),
            output_dir=output_dir,
            options=options,
        )
    except ScaDeadlineExceeded as exc:
        logger.warning("sca.api.analyse deadline exhausted: %s", exc)
        finalize_sca_diagnostic(
            output_dir,
            disposition="failed",
            reason=str(exc),
            returncode=124,
            timed_out=True,
            mode=analysis_mode,
        )
        return {
            "status": "error",
            "error": str(exc),
            "timed_out": True,
        }
    except Exception as exc:
        logger.exception("sca.api.analyse failed: %s", exc)
        finalize_sca_diagnostic(
            output_dir,
            disposition="failed",
            reason=f"{type(exc).__name__}: {exc}",
            mode=analysis_mode,
        )
        return {"status": "error", "error": str(exc)}

    if sarif_dirs:
        try:
            from .cross_tool import link_related_findings

            link_related_findings(
                sca_findings_path=result.findings_path,
                sarif_dirs=sarif_dirs,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("sca.api: cross-tool linking failed: %s", exc)

    summary = _summarise(result)
    finalize_sca_diagnostic(
        output_dir,
        disposition="success",
        returncode=0,
        mode=analysis_mode,
        summary=summary,
    )
    return summary


def _summarise(result: RunResult) -> dict[str, Any]:
    return {
        "status": "ok",
        "findings_path": str(result.findings_path),
        "sarif_path": str(result.sarif_path),
        "report_path": str(result.report_path),
        "sbom_path": str(result.sbom_path),
        "vuln_findings": result.vuln_findings,
        "hygiene_findings": result.hygiene_findings,
        "supply_chain_findings": result.supply_chain_findings,
        "deps_analysed": result.deps_analysed,
        "suppressed_findings": result.suppressed_findings,
        "in_kev": result.in_kev,
        "llm_cost": result.llm_cost,
    }
