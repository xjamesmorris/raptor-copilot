"""Map a sandbox execution's ``sandbox_info`` dict to a ``WitnessOutcome``.

The sandbox layer (``core/sandbox/observe.py::_interpret_result``) already
classifies post-execution state:

  * crash signals (SIGSEGV / SIGABRT / SIGBUS / SIGFPE / SIGILL)
  * resource-limit kills (SIGXCPU / SIGXFSZ)
  * seccomp kills (SIGSYS)
  * sanitizer reports (ASAN / UBSAN / MSAN / TSAN)
  * sandbox-enforcement events (network / write / seccomp blocks)

This module is the thin adapter that turns that dict into the
``WitnessOutcome`` enum plus a structured ``outcome_detail`` payload, so
consumers (LLM-exploit executors, future PoC runners) can write
post-execution Witnesses with consistent provenance.

``core.witness`` does not import ``core.sandbox`` — the function takes a
plain dict so the dependency arrow stays clean. Producers grab the dict
off the ``CompletedProcess`` (``result.sandbox_info``) and pass it in.
"""

from __future__ import annotations

from typing import Any

from core.witness.types import WitnessOutcome

# Canonical status string for "the environment refused to execute the
# payload at the required containment tier" — the sandbox floor
# contract's verdict at the verification seam. Deliberately NOT a new
# ``WitnessOutcome`` / verdict enum member: producers keep their
# existing error-shaped vocabulary (``verdict="error"``,
# ``WitnessOutcome.UNKNOWN``, a refused ``ProfileVerdict``) and carry
# this status inside their structured detail payload instead, so no
# schema consumer needs to learn a new terminal value. Explicitly
# neither confirmed nor refuted — an unverifiable environment is not
# a negative result.
UNVERIFIABLE_ENVIRONMENT = "unverifiable_environment"


def _tier_str(value: Any) -> str:
    """Posture label for a ContainmentTier (``"mount-ns"``), falling
    back to ``str(value)`` for anything the lattice doesn't know."""
    try:
        from core.sandbox.tiers import tier_label

        return tier_label(value)
    except (ImportError, KeyError, ValueError):
        return str(value)


def refusal_detail(exc: BaseException) -> dict[str, str] | None:
    """Canonical unverifiable-environment payload for a containment-
    floor refusal, or ``None`` when ``exc`` is not one.

    The shared chokepoint of the sandbox floor contract's
    verification-seam mapping: the attacker-payload executors
    (dark_verify, exploit_verify, under_mitigations) each catch
    :class:`~core.sandbox.errors.SandboxFloorError` at their own seam
    — they do not share an exception-handling site — and every arm
    derives its structured "unverifiable environment" outcome from
    this one function, so the payload shape cannot drift per caller.

    Semantics are record-then-raise: the catching arm records this
    payload on the finding it was verifying, then RE-RAISES the
    error. A floor refusal is host-deterministic — every subsequent
    payload run on the host refuses identically — so the stage fails
    loudly at the first refusal with exactly one surfaced record,
    and a misconfigured CI host cannot masquerade as N benign
    "error" verdicts. ``None`` means the arm must not map: re-raise
    (or fall through to) the caller's existing handling unchanged.

    ``core.witness`` still does not import ``core.sandbox`` at module
    level — the isinstance check imports lazily, and a
    ``SandboxFloorError`` instance can only exist in a process where
    that import succeeds.

    Payload keys (all strings, flat, JSON-safe):

    * ``status`` — :data:`UNVERIFIABLE_ENVIRONMENT`.
    * ``floor`` / ``achievable`` — posture labels of the required
      and deliverable containment tiers (``"mount-ns"``,
      ``"landlock"``, ...).
    * ``remedies`` — the refusal's operator-facing remedy text
      (``exc.instructions``; may be empty).
    * ``failure_mode`` — ``"constrained_by_env"``, matching
      ``core.labeled_attempts.types.FailureMode.CONSTRAINED_BY_ENV``
      so attempt-record writers classify the non-success as
      environmental without re-deriving it.
    """
    try:
        from core.sandbox.errors import SandboxFloorError
    except ImportError:
        return None
    if not isinstance(exc, SandboxFloorError):
        return None
    return {
        "status": UNVERIFIABLE_ENVIRONMENT,
        "floor": _tier_str(exc.floor),
        "achievable": _tier_str(exc.achievable),
        "remedies": exc.instructions or "",
        "failure_mode": "constrained_by_env",
    }


def refusal_summary_line(detail: dict[str, str], count: int = 1) -> str:
    """The one-line run-summary rendering of a floor refusal.

    One canonical shape shared by every recording arm so operator
    output cannot drift: sourced from the structured payload, never
    from log scraping. Under record-then-raise ``count`` is 1 by
    construction (the first refusal fails the stage); the parameter
    exists so a future cross-run aggregator can reuse the wording.
    """
    remedies = detail.get("remedies") or "(none recorded)"
    return (
        f"{count} execution(s) refused: environment cannot meet the "
        f"containment floor ({detail.get('floor', '?')} required, "
        f"{detail.get('achievable', '?')} achievable) — remedies: "
        f"{remedies}"
    )


def outcome_from_sandbox_info(
    sandbox_info: dict[str, Any] | None,
    returncode: int | None = None,
) -> tuple[WitnessOutcome, dict[str, Any]]:
    """Classify a sandboxed execution as a ``(WitnessOutcome, detail)`` pair.

    Precedence (most-informative wins):

    1. **Sanitizer report** → ``SANITIZER_REPORT``. ASAN with
       ``halt_on_error=0`` can fire without abnormal exit; we still
       call that a sanitizer outcome because the bug was observed.
    2. **Crash signal** (``crashed=True``, or signal in
       SIGSEGV/SIGABRT/SIGBUS/SIGFPE/SIGILL) → ``EXIT_SIGNAL``.
    3. **Resource-exceeded** (SIGXCPU / SIGXFSZ) → ``EXIT_SIGNAL``
       with ``resource_exceeded=True`` in detail. Caller can disambiguate
       a fuzz-hang from a sanitizer-triggered crash by reading detail.
    4. **Seccomp kill** (SIGSYS) → ``EXIT_SIGNAL`` with
       ``seccomp_killed=True``. Operationally a different class than
       a target crash, but still "the process died by signal."
    5. **Sandbox enforcement** (``blocked`` non-empty, no other class
       fired) → ``NO_OBVIOUS_EFFECT`` with ``blocked`` in detail. The
       process didn't trigger the target bug; the sandbox stopped it
       doing something else.
    6. **Nothing classifiable** → ``NO_OBVIOUS_EFFECT`` (clean exit, no
       sanitizer trip, no enforcement). The exploit ran but produced
       no observable security-relevant event.

    ``UNKNOWN`` is reserved for "we couldn't even run the sandbox" /
    "the result object wasn't shaped like CompletedProcess" cases
    handled by the caller before this function is reached. ``NOT_RUN``
    is what callers use when they choose not to execute at all and
    never reaches here.

    ``FLAG_CAPTURED`` (the ExploitGym terminal-success outcome) is
    not derivable from sandbox_info alone — it requires an oracle
    that checks for a specific marker (file, stdout pattern, etc.).
    Producers that have such an oracle should call this function for
    the substrate classification, then upgrade to ``FLAG_CAPTURED``
    on a positive oracle match.

    Args:
        sandbox_info: Dict produced by
            ``core/sandbox/observe.py::_interpret_result``. May be
            ``None`` if the sandbox attached no info — treated as
            "nothing classifiable" (returns ``NO_OBVIOUS_EFFECT``,
            empty detail).
        returncode: Optional ``CompletedProcess.returncode`` for
            inclusion in ``outcome_detail``. Not used for
            classification (the sandbox layer already did that
            mapping into ``signal`` / ``signal_num``).

    Returns:
        ``(outcome, detail)`` where ``outcome`` is one of
        ``EXIT_SIGNAL`` / ``SANITIZER_REPORT`` / ``NO_OBVIOUS_EFFECT``
        and ``detail`` is a flat dict carrying only present fields
        (absent → omitted, matching the rest of the Witness
        outcome_detail convention).
    """
    detail: dict[str, Any] = {}
    if returncode is not None:
        detail["returncode"] = returncode

    info = sandbox_info or {}

    # Evidence tiering (stamped by observe.py; see its comments):
    # ``signal_provenance == "waitstatus"`` means the parent's own
    # waitpid saw WIFSIGNALED — kernel truth the target cannot mint via
    # exit(2). ``"exitcode"`` means the 128+sig decoding of an exit
    # CODE, which a hostile target forges with a one-line exit(139).
    # Sanitizer detection is always a stderr substring match at this
    # layer (``sanitizer_provenance == "stderr_match"``) and therefore
    # never mechanical on its own. ``evidence_grade`` summarises the
    # tier for verdict makers: "mechanical" (unforgeable-by-target) vs
    # "heuristic" (target-forgeable). Legacy sandbox_info without the
    # provenance stamps grades heuristic — fail-safe, and honest for
    # the spawn tiers that re-encode signals as exit codes. Consumers
    # holding a stronger oracle (dark_verify's sentinel channel, the
    # exploit_verify waitstatus wrapper) may upgrade the grade with
    # their own out-of-band evidence. New detail fields only: outcomes
    # keep their historical meaning and tolerant readers are unaffected.
    sig_prov = info.get("signal_provenance")
    _grade = "mechanical" if sig_prov == "waitstatus" else "heuristic"

    # Sanitizer wins because it directly identifies a bug class, even
    # when the process exited cleanly via halt_on_error=0.
    sanitizer = info.get("sanitizer")
    if sanitizer:
        detail["sanitizer"] = sanitizer
        if info.get("crashed"):
            detail["crashed"] = True
        if info.get("signal"):
            detail["signal"] = info["signal"]
        if info.get("evidence"):
            detail["evidence"] = info["evidence"]
        if sig_prov:
            detail["signal_provenance"] = sig_prov
        if info.get("sanitizer_provenance"):
            detail["sanitizer_provenance"] = info["sanitizer_provenance"]
        detail["evidence_grade"] = _grade
        return WitnessOutcome.SANITIZER_REPORT, detail

    # Signal-killed (crash, resource-exceeded, seccomp). All collapse
    # to EXIT_SIGNAL at the enum level; detail flags disambiguate.
    if info.get("signal"):
        detail["signal"] = info["signal"]
        if "signal_num" in info:
            detail["signal_num"] = info["signal_num"]
        if info.get("crashed"):
            detail["crashed"] = True
        if info.get("resource_exceeded"):
            detail["resource_exceeded"] = True
        if info.get("seccomp_killed"):
            detail["seccomp_killed"] = True
        if info.get("evidence"):
            detail["evidence"] = info["evidence"]
        if info.get("blocked"):
            detail["blocked"] = list(info["blocked"])
        if sig_prov:
            detail["signal_provenance"] = sig_prov
        detail["evidence_grade"] = _grade
        return WitnessOutcome.EXIT_SIGNAL, detail

    # `crashed` without a signal: shouldn't happen with current
    # observe.py, but defensive — observe might add cases.
    if info.get("crashed"):
        detail["crashed"] = True
        if info.get("evidence"):
            detail["evidence"] = info["evidence"]
        detail["evidence_grade"] = "heuristic"
        return WitnessOutcome.EXIT_SIGNAL, detail

    # Sandbox enforcement only (no crash, no sanitizer).
    if info.get("blocked"):
        detail["blocked"] = list(info["blocked"])
        if info.get("evidence"):
            detail["evidence"] = info["evidence"]
        return WitnessOutcome.NO_OBVIOUS_EFFECT, detail

    # Nothing observed.
    if info.get("evidence"):
        detail["evidence"] = info["evidence"]
    return WitnessOutcome.NO_OBVIOUS_EFFECT, detail
