#!/usr/bin/env python3
"""Subprocess-compatible SCA entry point + cross-tool launch helpers.

When invoked as a script::

    python3 packages/sca/agent.py --repo /path/to/target --out /path/to/out

Runs the full SCA analyse pipeline and writes findings.json + SARIF +
report.md into ``--out``, then prints a one-line JSON summary to stdout
so the caller can parse it.

When imported as a module, exposes two helpers used by
``raptor_agentic.py`` and other RAPTOR-side callers that want to launch
SCA as a sandboxed subprocess rather than in-process:

  - :func:`_find_sca_agent` — discover the SCA agent entry point.
    Returns the resolved path to this file (or to an external override
    set via ``RAPTOR_SCA_AGENT`` env). Pre-merge, this used to bridge
    to a separate ``raptor-sca`` repo; post-merge SCA lives in-tree.
  - :func:`run_sca_subprocess` — launch the agent under
    ``core.sandbox.run`` with egress restricted to
    :data:`packages.sca.SCA_ALLOWED_HOSTS`. This helper is the agentic
    mechanical lane: it disables LLM review/triage and propagates a child
    deadline shorter than the parent timeout. The separate deep ``--sca``
    phase retains LLM review and triage.

When ``--sandbox`` is passed to the script form, the analysis runs
inside a sandbox context with egress proxy enabled — the
``EgressClient`` default in ``packages.sca.__init__`` already routes
HTTP through the proxy, and the resolver subprocesses already sandbox
themselves, so the outer context adds Landlock FS confinement for the
manifest-parsing phase.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

# Path setup for direct CLI invocation. `os.environ["RAPTOR_DIR"]`
# (no fallback) is the canonical project root marker — see CLAUDE.md
# "Python path safety"; a KeyError surfaces the configuration problem
# at startup instead of a positional walk silently rooting imports at
# the wrong tree. (The old comment's "raptor-sca repo root" predated
# the merge into RAPTOR.)
sys.path.insert(0, os.environ["RAPTOR_DIR"])

from packages.sca.diagnostics import (
    finalize_sca_diagnostic,
    read_sca_diagnostic,
)

logger = logging.getLogger(__name__)

DEFAULT_SCA_SUBPROCESS_TIMEOUT = 600


# ---------------------------------------------------------------------------
# Cross-tool launch helpers
# ---------------------------------------------------------------------------

def _find_sca_agent() -> Path | None:
    """Discover the SCA agent entry point.

    Post-merge, SCA lives in-tree — this file IS the agent. So the
    default answer is ``Path(__file__).resolve()``. The
    ``RAPTOR_SCA_AGENT`` env var still allows pointing at an external
    agent (e.g. a vendored or pinned version) for CI / custom layouts.
    Returns ``None`` only when the override path is set but invalid.
    """
    env_path = os.environ.get("RAPTOR_SCA_AGENT")
    if env_path:
        p = Path(env_path).resolve()
        if not p.is_file():
            logger.warning("RAPTOR_SCA_AGENT=%s does not exist — ignoring",
                           env_path)
            return None
        # Content discriminator: a file CAN exist at the override path
        # without being a real SCA agent — operator typos, stale
        # symlinks, sibling-project ``agent.py`` files, placeholder
        # scripts. Pre-content-check, those silently launched the
        # wrong subprocess and surfaced as opaque "no SCA findings"
        # or downstream crashes blamed on raptor-sca itself. The
        # `from packages.sca import SCA_ALLOWED_HOSTS` import is the
        # discriminator — every real agent imports it; nothing else
        # has reason to.
        # Cap the marker-check read at 256 KB. Pre-fix
        # ``read_text()`` loaded the WHOLE candidate file before
        # the marker check — if RAPTOR_SCA_AGENT picked up a giant
        # file by mistake (a vendored binary mislabeled as
        # ``agent.py``, an inadvertent log paste), we'd buffer the
        # whole thing into memory just to confirm "no, this isn't
        # the right file." The marker we're looking for
        # (``from packages.sca import SCA_ALLOWED_HOSTS``) is at
        # the top of any legitimate agent — 256 KB is two orders
        # of magnitude beyond any realistic Python module's
        # first-block imports.
        _MAX_MARKER_BYTES = 256 * 1024
        try:
            with Path(p).open(encoding="utf-8", errors="replace") as fh:
                text = fh.read(_MAX_MARKER_BYTES)
        except OSError:
            logger.warning(
                "RAPTOR_SCA_AGENT=%s could not be read — ignoring",
                env_path,
            )
            return None
        if "from packages.sca import SCA_ALLOWED_HOSTS" not in text:
            logger.warning(
                "RAPTOR_SCA_AGENT=%s does not look like a raptor-sca "
                "agent (missing SCA_ALLOWED_HOSTS import) — ignoring",
                env_path,
            )
            return None
        return p
    return Path(__file__).resolve()


def run_sca_subprocess(
    agent_path: Path,
    target: Path,
    output_dir: Path,
    *,
    sandbox_args: Sequence[str] = (),
    env: dict | None = None,
    offline: bool = False,
    timeout: int | None = DEFAULT_SCA_SUBPROCESS_TIMEOUT,
    cancel_fd: int | None = None,
) -> tuple:
    """Run the SCA agent as a sandboxed subprocess.

    Online requests use the hostname-allowlisted egress proxy. Offline
    requests keep sandbox network isolation without starting a proxy.
    Landlock confines writes to ``output_dir``.

    Returns ``(returncode, stdout, stderr)``. Timeout/deadline exits use
    ``124``; caller cancellation uses ``130``. The sandbox owns process-tree
    teardown for all three terminal paths.
    """
    from core.config import RaptorConfig, pin_raptor_dir
    from core.sandbox import SandboxCancelled, SandboxSetupError
    from core.sandbox.disable_consent import (
        NONCE_ENV_VAR,
        export_disable_consent,
    )
    from core.sandbox import python_runtime_tool_paths, run as sandbox_run

    agent_path = agent_path.resolve()
    if not agent_path.is_file():
        raise FileNotFoundError(f"SCA agent file is missing or invalid: {agent_path}")
    # Ensure output_dir exists before Landlock setup — the sandbox
    # registers a writable rule by opening the path as a directory fd.
    # If it doesn't exist, the rule silently fails and every write
    # inside the child gets EACCES.
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd: list[str] = [
        sys.executable, str(agent_path),
        "--repo", str(target),
        "--out", str(output_dir),
        "--agentic-worker",
        # This is the always-on mechanical phase; deep review belongs to
        # /agentic --sca, not this time-bounded subprocess.
        "--skip-review",
        "--skip-triage",
    ]
    offline = offline or "--offline" in sandbox_args
    if offline and "--offline" not in sandbox_args:
        cmd.append("--offline")
    child_deadline = _child_deadline_seconds(timeout)
    if child_deadline is not None:
        cmd.extend(["--deadline-seconds", str(child_deadline)])
    cmd.extend(sandbox_args)

    # The child's import chain initializes RaptorLogger, which writes
    # to LOG_DIR. Grant it explicitly so the first log emit can succeed.
    log_dir = RaptorConfig.LOG_DIR
    log_dir.mkdir(parents=True, exist_ok=True)

    from packages.sca import sca_cache_root as _sca_cache_root
    cache_dir = _sca_cache_root()
    cache_dir.mkdir(parents=True, exist_ok=True)
    child_env = dict(
        env if env is not None else RaptorConfig.get_safe_env()
    )
    pin_raptor_dir(child_env)
    # --sandbox none / --no-sandbox is consent-gated again in the child.
    # Export only an already-accepted parent grant; this helper cannot mint
    # authority and is a no-op for ordinary sandboxed runs.
    child_env.pop(NONCE_ENV_VAR, None)
    export_disable_consent(child_env)

    # Mount namespaces see the target and output, not the RAPTOR checkout.
    # Bind only the Python source the trusted worker imports, rather than
    # exposing the entire checkout (including other runs and local secrets).
    source_roots = (
        RaptorConfig.REPO_ROOT / "core",
        RaptorConfig.REPO_ROOT / "packages",
    )
    tool_paths = [str(root) for root in source_roots]
    tool_paths.extend(python_runtime_tool_paths())
    if not any(agent_path.is_relative_to(root) for root in source_roots):
        tool_paths.append(str(agent_path))

    network_options = (
        {"block_network": True}
        if offline else {
            "use_egress_proxy": True,
            "require_proxy_netns": True,
            "proxy_hosts": _compose_proxy_hosts(target),
        }
    )
    try:
        result = sandbox_run(
            cmd,
            **network_options,
            caller_label="sca-agent",
            target=str(target),
            output=str(output_dir),
            tool_paths=tool_paths,
            writable_paths=[str(log_dir), str(cache_dir)],
            env=child_env,
            env_caller_filtered=True,
            # ``cmd`` runs RAPTOR's OWN SCA agent — a trusted in-tree
            # dispatch, NOT untrusted target code.  Without this the
            # sandbox's TARGET_ENV_STRIP_SET strips RAPTOR_DIR and the
            # child KeyErrors at import.
            keep_trust_markers_for_dispatch=True,
            # Separate explicit authority: the SCA child re-parses
            # --sandbox none / --no-sandbox, so an already-accepted parent
            # consent must survive this RAPTOR-owned dispatch only.
            keep_disable_consent_for_dispatch=True,
            capture_output=True,
            text=True,
            timeout=(timeout or None),
            cancel_fd=cancel_fd,
        )
    except subprocess.TimeoutExpired as exc:
        partial_stdout = _decode_partial_stream(exc.stdout)
        partial_stderr = _decode_partial_stream(exc.stderr)
        message = f"sca-agent timed out after {timeout}s"
        stderr = _append_diagnostic_line(partial_stderr, message)
        finalize_sca_diagnostic(
            output_dir,
            disposition="failed",
            reason=message,
            returncode=124,
            timed_out=True,
            stderr=stderr,
            mode="mechanical",
        )
        return (
            124,
            partial_stdout,
            stderr,
        )
    except SandboxCancelled as exc:
        partial_stdout = _decode_partial_stream(exc.output)
        partial_stderr = _decode_partial_stream(exc.stderr)
        message = "sca-agent cancelled"
        stderr = _append_diagnostic_line(partial_stderr, message)
        finalize_sca_diagnostic(
            output_dir,
            disposition="failed",
            reason=message,
            returncode=130,
            cancelled=True,
            stderr=stderr,
            mode="mechanical",
        )
        return 130, partial_stdout, stderr
    except SandboxSetupError as exc:
        finalize_sca_diagnostic(
            output_dir,
            disposition="failed",
            reason=f"SandboxSetupError: {exc}",
            mode="mechanical",
        )
        raise
    except KeyboardInterrupt:
        finalize_sca_diagnostic(
            output_dir,
            disposition="failed",
            reason="sca-agent interrupted by operator",
            returncode=130,
            interrupted=True,
            mode="mechanical",
        )
        raise
    except Exception as exc:
        finalize_sca_diagnostic(
            output_dir,
            disposition="failed",
            reason=f"{type(exc).__name__}: {exc}",
            mode="mechanical",
        )
        raise
    if result.returncode == 0:
        finalize_sca_diagnostic(
            output_dir,
            disposition="success",
            returncode=0,
            mode="mechanical",
        )
    else:
        child_diagnostic = read_sca_diagnostic(output_dir)
        reason = child_diagnostic.get("reason")
        if not isinstance(reason, str) or not reason:
            reason = _decode_partial_stream(result.stderr)
        finalize_sca_diagnostic(
            output_dir,
            disposition="failed",
            reason=reason,
            returncode=result.returncode,
            stderr=result.stderr,
            mode="mechanical",
        )
    return result.returncode, result.stdout, result.stderr


def _child_deadline_seconds(
    timeout: int | float | None,
) -> float | None:
    """Leave parent-side time to persist diagnostics and reap the tree."""
    if timeout is None or float(timeout) <= 0:
        return None
    timeout = float(timeout)
    grace = min(15.0, max(0.1, timeout * 0.05))
    return round(max(0.1, timeout - grace), 3)


def _decode_partial_stream(value: object) -> str:
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


def _append_diagnostic_line(stderr: str, message: str) -> str:
    stderr = stderr.rstrip()
    return f"{stderr}\n{message}" if stderr else message


def _compose_proxy_hosts(target: Path) -> list:
    """Re-export of :func:`packages.sca.compose_proxy_hosts` for the
    sandbox-subprocess code path.

    Kept as a thin module-level alias so existing test stubs that
    monkeypatch ``packages.sca.agent._compose_proxy_hosts`` continue
    to work. New callers should use the package-level
    ``packages.sca.compose_proxy_hosts`` directly — same impl, also
    used by the in-process ``default_client(target)`` seam so both
    code paths share one allowlist composition.
    """
    from packages.sca import compose_proxy_hosts as _impl
    return _impl(target)


# ---------------------------------------------------------------------------
# Subprocess entry point — when invoked as `python3 packages/sca/agent.py …`
# ---------------------------------------------------------------------------

def _normalise_direct_sandbox_argv(argv) -> list[str]:
    """Apply the direct-SCA ``--no-sandbox`` compatibility override.

    The shared sandbox parser correctly makes the two disable/profile
    spellings mutually exclusive. The historical direct SCA surface predates
    that parser and documents ``--no-sandbox`` as the winning escape hatch,
    so remove any profile spelling before strict parsing. Unknown options are
    untouched and still fail at argparse.
    """
    values = list(sys.argv[1:] if argv is None else argv)
    if "--no-sandbox" not in values:
        return values
    normalized: list[str] = []
    index = 0
    while index < len(values):
        value = values[index]
        if value == "--sandbox":
            index += 2
            continue
        if value.startswith("--sandbox="):
            index += 1
            continue
        normalized.append(value)
        index += 1
    return normalized


def main(argv=None) -> int:
    # Escaping-console chokepoint: this is the sandboxed subprocess
    # entry (its own process). Wired via core.logging directly — the
    # cli._configure_logging helper the dispatch-table subcommands use
    # would pull the whole CLI module into the sandboxed child for no
    # gain. Without it, logging.lastResort would relay WARNING+
    # foreign text (resolver stderr, registry doc content) to the
    # parent-visible stderr with a plain formatter.
    from core.logging import configure_cli_logging
    configure_cli_logging(logging.WARNING)
    from core.sandbox import add_cli_args, apply_cli_args
    from packages.sca.api import analyse
    ap = argparse.ArgumentParser(description="RAPTOR SCA agent")
    ap.add_argument("--repo", required=True, help="Target project root")
    ap.add_argument("--out", required=True, help="Output directory")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument(
        "--skip-review",
        action="store_true",
        help="Disable deep LLM behavioural review",
    )
    ap.add_argument(
        "--skip-triage",
        action="store_true",
        help="Disable deep LLM triage",
    )
    ap.add_argument(
        "--deadline-seconds",
        type=float,
        default=None,
        help="Internal deadline shorter than the parent process timeout",
    )
    ap.add_argument(
        "--agentic-worker",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    ap.add_argument("--sarif-dirs", nargs="*",
                    help="Sibling SARIF directories for cross-tool linking")
    # This is the complete, explicitly-supported wrapper passthrough
    # surface. In particular it includes --sandbox-floor, which
    # /agentic forwards to every scanner worker. Anything else is a
    # direct-agent typo or wrapper contract drift and must fail at
    # argparse instead of disappearing silently.
    add_cli_args(ap)
    args = ap.parse_args(_normalise_direct_sandbox_argv(argv))
    direct_disable = bool(
        args.no_sandbox or args.sandbox == "none"
    )
    direct_compat_disable = direct_disable and not args.agentic_worker
    if direct_compat_disable:
        # Scoped trusted-library compatibility: SCA runs RAPTOR's parser
        # over data; it does not execute target build/install code. Keep
        # every other entry point's disable-consent gate intact, and keep
        # agentic workers on the shared gate below.
        if (
            args.audit
            or args.audit_verbose
            or args.audit_budget is not None
            or args.sandbox_floor is not None
            or args.sandbox_readable_paths
            or args.sandbox_tool_paths
        ):
            ap.error(
                "direct SCA sandbox disable is incompatible with audit, "
                "floor, readable-path, tool-path, and audit-budget options"
            )
    else:
        apply_cli_args(args, ap)

    sarif_dirs = [Path(p) for p in args.sarif_dirs] if args.sarif_dirs else None
    target = Path(args.repo).resolve()
    output_dir = Path(args.out).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if not direct_compat_disable:
        from core.project.trust import apply_project_sandbox_floor
        apply_project_sandbox_floor(
            args,
            banner=False,
            target_path=target,
            run_dir=output_dir,
        )

    use_sandbox = args.sandbox is not None and not args.no_sandbox

    if use_sandbox:
        result = _run_sandboxed(
            target=target,
            output_dir=output_dir,
            offline=args.offline,
            no_cache=args.no_cache,
            sarif_dirs=sarif_dirs,
            profile=args.sandbox,
            audit=args.audit,
            audit_verbose=args.audit_verbose,
            enable_llm_review=not args.skip_review,
            enable_triage=not args.skip_triage,
            deadline_seconds=args.deadline_seconds,
            analysis_mode=(
                "mechanical"
                if args.skip_review and args.skip_triage
                else "deep"
            ),
        )
    else:
        result = analyse(
            target=target,
            output_dir=output_dir,
            offline=args.offline,
            no_cache=args.no_cache,
            sarif_dirs=sarif_dirs,
            enable_llm_review=not args.skip_review,
            enable_triage=not args.skip_triage,
            deadline_seconds=args.deadline_seconds,
            analysis_mode=(
                "mechanical"
                if args.skip_review and args.skip_triage
                else "deep"
            ),
        )

    print(json.dumps(result))
    if result.get("status") == "ok":
        return 0
    return 124 if result.get("timed_out") is True else 1


def _run_sandboxed(
    *, target, output_dir, offline, no_cache, sarif_dirs, profile,
    audit: bool = False, audit_verbose: bool = False,
    enable_llm_review: bool = True,
    enable_triage: bool = True,
    deadline_seconds: float | None = None,
    analysis_mode: str = "deep",
):
    """Run analyse() inside a sandbox context.

    ``audit`` / ``audit_verbose`` pair with
    :func:`core.sandbox.context.sandbox`'s audit knob: when set,
    Landlock filesystem denials and proxy host-allowlist
    refusals get appended to ``<output_dir>/sandbox-audit.jsonl``
    so operators can verify the sandbox engaged (and spot any
    accidentally-blocked read that's degrading the run). Without
    these wired through, the agent.py CLI exposes ``--audit`` but
    the flag is silently inert — surfaced by the Tier-7 dev E2E
    sweep.
    """
    try:
        from core.sandbox.context import sandbox
    except ImportError:
        msg = (
            "sca.agent: --sandbox requested but core.sandbox.context "
            "is not importable; refusing to run unsandboxed"
        )
        raise RuntimeError(msg) from None

    from packages.sca import sca_cache_root as _sca_cache_root
    cache_dir = _sca_cache_root()
    cache_dir.mkdir(parents=True, exist_ok=True)

    network_options = (
        {"block_network": True}
        if offline else {
            "use_egress_proxy": True,
            "require_proxy_netns": True,
            "proxy_hosts": _compose_proxy_hosts(target),
        }
    )
    with sandbox(
        target=str(target),
        output=str(output_dir),
        profile=profile,
        **network_options,
        caller_label="sca-agent",
        writable_paths=[str(cache_dir)],
        audit=audit,
        audit_verbose=audit_verbose,
        audit_run_dir=str(output_dir) if audit else None,
    ):
        from packages.sca.api import analyse as _analyse
        return _analyse(
            target=target, output_dir=output_dir,
            offline=offline, no_cache=no_cache, sarif_dirs=sarif_dirs,
            enable_llm_review=enable_llm_review,
            enable_triage=enable_triage,
            deadline_seconds=deadline_seconds,
            analysis_mode=analysis_mode,
        )


if __name__ == "__main__":
    sys.exit(main())
