"""Generic parallel dispatch for LLM tasks.

Provides DispatchTask base class and dispatch_task() function.
The dispatcher handles threading, progress, cost tracking, and error handling.
Task subclasses define semantics: what prompt, what schema, which model.
"""

import logging
import math
import sys
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any

from core.llm.accounting import (
    AccountingSummary,
    CostBasis,
    CostObservation,
    LLMPolicyError,
    RouteIdentity,
    cost_observation_from_exception,
)

# Error classification moved to the shared consumer-side envelope
# (core.llm.structured_call) — the word-boundary regexes this module
# introduced are now the ONE classifier, extended with audit's
# provider phrasings ("model refused", content_filter, "blocked by").
# The aliased names below stay as thin aliases: they are this
# package's documented seam (tests and callers import them from here).
from core.llm.structured_call import (
    classify_error_text as _classify_error,
)
from core.llm.structured_call import (
    is_auth_error_text as _is_auth_error,
)
from core.run.finding_status import read_verdict
from core.security.log_sanitisation import escape_nonprintable

logger = logging.getLogger(__name__)

# Corpora checked by dispatch preflight.  Excludes "structural_injection"
# because the assembled prompt contains RAPTOR's own JSON fields
# ("ruling": "false_positive", "is_exploitable": false) which those
# patterns legitimately match.
_DISPATCH_CORPORA = (
    "english",
    "role_injection",
    "unicode_smuggling",
    "encoding_evasion",
)


class _ModelCircuitOpen(Exception):
    """Signal from a worker that its model was already circuit-broken.

    Every (model, item) future is pre-submitted before the drain loop
    starts, so "stopping dispatch to this model" needs an execution-time
    check: a queued future whose model has since been declared dead
    raises this instead of spending another API call on it. Carries the
    model key as its message.
    """


class _ErrorDictResult(Exception):
    """A dispatch_fn returned a DispatchResult whose payload is an
    error envelope (``{"error": ...}``) instead of raising.

    Non-raising dispatch paths (the CC subprocess adapter, external
    clients that wrap failures) report every failure this way. The
    drain loop raises this internally so those failures flow through
    the SAME except-branch as raised exceptions — per-model
    circuit breaker, auth abort, error classification, and failure
    telemetry all fire. Without the re-route, a persistently dead
    transport masquerades as an endless stream of successes: the
    consecutive-failure counter is RESET on each error envelope and
    the run burns one full timeout per finding with no early stop.

    Carries the model name the dispatch path attributed the failure
    to (``""`` when the path didn't know).
    """

    def __init__(
        self,
        message: str,
        model_name: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.model_name = model_name
        self.metadata = metadata or {}


_PROVENANCE_METADATA_FIELDS = frozenset({
    "analysed_by",
    "analysed_by_provider",
    "analysis_provenance",
    "analysis_route",
    "resolved_model",
})
_ACCOUNTING_METADATA_FIELDS = frozenset({
    "accounting",
    "accounting_complete",
    "cache_hit",
    "cost_observation",
    "cost_usd",
    "duration_seconds",
})
DISPATCH_METADATA_FIELDS = (
    _PROVENANCE_METADATA_FIELDS | _ACCOUNTING_METADATA_FIELDS
)


def strip_dispatch_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    """Remove transport-owned fields from model-generated content."""
    out = dict(payload)
    for key in DISPATCH_METADATA_FIELDS:
        out.pop(key, None)
    return out


class DispatchResult:
    """Normalised result from any dispatch path (external LLM or CC)."""

    def __init__(self, result: dict[str, Any], cost: float = 0.0,
                 tokens: int = 0, model: str = "", duration: float = 0.0,
                 quality: float = 1.0, resolved_model: str | None = None,
                 thinking_tokens: int = 0, provider: str = "",
                 cost_observation: CostObservation | None = None,
                 cache_hit: bool = False, no_spend: bool = False,
                 core_accounted: bool = False,
                 retained_reservation_estimate_usd: float = 0.0) -> None:
        if (
            cost_observation is not None
            and not isinstance(cost_observation, CostObservation)
        ):
            raise TypeError(
                "cost_observation must be CostObservation or None",
            )
        self.result = result
        self.cost = cost
        self.tokens = tokens
        self.model = model if isinstance(model, str) else ""
        self.provider = (
            provider.strip().lower()
            if isinstance(provider, str) and provider.strip()
            else ""
        )
        self.duration = duration
        self.quality = quality
        # Provider-reported thinking-token usage (0 when the provider
        # doesn't surface it). Funnelled into CostTracker.add_cost so
        # the run summary's thinking-token telemetry can fire.
        self.thinking_tokens = thinking_tokens
        # Provider-served snapshot behind the (possibly floating) `model`
        # alias, when the SDK exposed one. Carried into the per-finding result
        # dict so consensus/judge can record scorecard reliability against the
        # concrete model version, not the drifting alias.
        self.resolved_model = (
            resolved_model
            if isinstance(resolved_model, str) and resolved_model
            else None
        )
        self.cost_observation = cost_observation
        self.route = (
            cost_observation.route
            if cost_observation is not None
            and cost_observation.route is not None
            else RouteIdentity(self.provider, self.model)
            if self.provider and self.model
            else None
        )
        self.cache_hit = bool(cache_hit)
        self.no_spend = bool(no_spend or cache_hit)
        self.core_accounted = bool(core_accounted)
        self.accounting_complete = (
            self.no_spend
            or (
                cost_observation is not None
                and cost_observation.basis
                not in (CostBasis.UNKNOWN, CostBasis.SUBSCRIPTION)
            )
        )
        self.retained_reservation_estimate_usd = float(
            retained_reservation_estimate_usd,
        )

    @classmethod
    def from_core_response(
        cls,
        response: Any,
        *,
        result: dict[str, Any],
        quality: float = 1.0,
    ) -> "DispatchResult":
        """Preserve metadata supplied by an LLMClient response.

        A disagreement between the legacy numeric cost and its typed
        observation is a contract error. Generic dispatch records that as a
        per-item failure; the sequential agent treats it as an analysis
        failure. Neither path silently chooses one value and reports success.
        """
        def _string(name: str) -> str:
            value = getattr(response, name, "")
            return value if isinstance(value, str) else ""

        def _float(name: str) -> float:
            value = getattr(response, name, 0)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return 0.0
            return float(value)

        def _int(name: str) -> int:
            value = getattr(response, name, 0)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return 0
            return int(value)

        observation = getattr(response, "cost_observation", None)
        if not isinstance(observation, CostObservation):
            observation = None
        cost = _float("cost")
        if (
            observation is not None
            and not math.isclose(
                cost,
                observation.legacy_cost_usd,
                rel_tol=1e-9,
                abs_tol=1e-12,
            )
        ):
            raise ValueError(
                "core response cost does not match its cost observation",
            )
        return cls(
            result=result,
            cost=cost,
            tokens=_int("tokens_used"),
            model=_string("model"),
            provider=_string("provider"),
            duration=_float("duration"),
            quality=quality,
            resolved_model=_string("resolved_model") or None,
            thinking_tokens=_int("thinking_tokens"),
            cost_observation=observation,
            cache_hit=(
                getattr(response, "cached", False) is True
                or getattr(response, "finish_reason", "") == "cached"
            ),
            core_accounted=True,
        )


def _dispatch_route(result: Any) -> RouteIdentity | None:
    route = getattr(result, "route", None)
    if isinstance(route, RouteIdentity):
        return route
    observation = getattr(result, "cost_observation", None)
    if isinstance(observation, CostObservation) and observation.route is not None:
        return observation.route
    provider = getattr(result, "provider", "")
    model = getattr(result, "model", "")
    provider = provider if isinstance(provider, str) else ""
    model = model if isinstance(model, str) else ""
    if provider and model:
        return RouteIdentity(provider, model)
    return None


def _effective_observation(
    result: Any,
    *,
    failed: bool,
) -> CostObservation | None:
    observation = getattr(result, "cost_observation", None)
    if isinstance(observation, CostObservation):
        return observation
    if getattr(result, "no_spend", False) is True:
        return None
    if failed:
        usage_values = (
            getattr(result, "cost", 0),
            getattr(result, "tokens", 0),
            getattr(result, "thinking_tokens", 0),
        )
        if not any(
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value > 0
            for value in usage_values
        ):
            return None
    return CostObservation.unknown(route=_dispatch_route(result))


def _attempt_accounting(
    result: Any,
    *,
    failed: bool,
) -> tuple[CostObservation | None, AccountingSummary]:
    observation = _effective_observation(result, failed=failed)
    summary = AccountingSummary()
    if getattr(result, "no_spend", False) is True:
        return None, summary
    if observation is None:
        return observation, summary
    if failed and observation.basis is CostBasis.UNKNOWN:
        return observation, summary.add_unknown_failure(
            retained_reservation_estimate_usd=getattr(
                result, "retained_reservation_estimate_usd", 0.0,
            ),
        )
    return observation, summary.add(observation)


def dispatch_result_metadata(
    result: Any,
    *,
    failed: bool = False,
) -> dict[str, Any]:
    """Trusted report metadata derived from the transport object, not content."""
    observation, accounting = _attempt_accounting(result, failed=failed)
    route = _dispatch_route(result)
    raw_model = getattr(result, "model", "")
    raw_provider = getattr(result, "provider", "")
    model = (
        route.model if route is not None
        else raw_model if isinstance(raw_model, str) else ""
    )
    provider = (
        route.provider if route is not None
        else raw_provider if isinstance(raw_provider, str) else ""
    )
    metadata: dict[str, Any] = {}
    if model:
        metadata["analysed_by"] = model
    if provider:
        metadata["analysed_by_provider"] = provider
    if route is not None:
        metadata["analysis_route"] = route.as_dict()
    resolved_model = getattr(result, "resolved_model", None)
    if resolved_model:
        metadata["resolved_model"] = resolved_model
    provenance = {
        key: value for key, value in {
            "provider": provider or None,
            "model": model or None,
            "resolved_model": resolved_model,
        }.items() if value is not None
    }
    if provenance:
        metadata["analysis_provenance"] = provenance
    if observation is not None:
        metadata["cost_observation"] = observation.as_dict()
    if observation is not None or getattr(result, "no_spend", False) is True:
        metadata["accounting"] = accounting.as_dict()
        metadata["accounting_complete"] = accounting.usd_total_complete
    if getattr(result, "cache_hit", False) is True:
        metadata["cache_hit"] = True
    return metadata


def record_dispatch_accounting(
    cost_tracker: Any,
    result: Any,
    *,
    failed: bool = False,
    model_name: str | None = None,
) -> None:
    """Record one dispatch result through the tracker's typed seam."""
    if cost_tracker is None:
        return
    observation = _effective_observation(result, failed=failed)
    result_model = getattr(result, "model", "")
    model = (
        observation.route.model
        if observation is not None and observation.route is not None
        else result_model
        if isinstance(result_model, str) and result_model
        else model_name or "unknown"
    )
    def _number(name: str, *, integer: bool = False) -> float | int:
        value = getattr(result, name, 0)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return 0
        return int(value) if integer else float(value)

    record_attempt = getattr(cost_tracker, "record_attempt", None)
    if callable(record_attempt):
        record_attempt(
            model,
            cost=_number("cost"),
            tokens=_number("tokens", integer=True),
            thinking_tokens=_number("thinking_tokens", integer=True),
            observation=observation,
            route=_dispatch_route(result),
            failed=failed,
            no_spend=getattr(result, "no_spend", False) is True,
            cache_hit=getattr(result, "cache_hit", False) is True,
            core_accounted=(
                getattr(result, "core_accounted", False) is True
            ),
            retained_reservation_estimate_usd=_number(
                "retained_reservation_estimate_usd",
            ),
        )
        return
    cost = _number("cost")
    tokens = _number("tokens", integer=True)
    thinking = _number("thinking_tokens", integer=True)
    if cost > 0 or tokens > 0 or thinking > 0:
        cost_tracker.add_cost(model, cost)


def record_exception_accounting(
    cost_tracker: Any,
    error: BaseException,
    *,
    model_name: str = "unknown",
) -> dict[str, Any]:
    """Record a failed dispatch and any accounting evidence attached by core."""
    observation = cost_observation_from_exception(error)
    if observation is None:
        record_attempt = getattr(cost_tracker, "record_attempt", None)
        if callable(record_attempt):
            record_attempt(
                model_name,
                cost=0.0,
                failed=True,
            )
        return {}
    route = observation.route
    result = DispatchResult(
        result={},
        cost=observation.legacy_cost_usd,
        model=route.model if route else "",
        provider=route.provider if route else "",
        cost_observation=observation,
        core_accounted=True,
    )
    record_dispatch_accounting(cost_tracker, result, failed=True)
    return dispatch_result_metadata(result, failed=True)


class DispatchTask:
    """Base class for parallel LLM dispatch tasks.

    Subclasses define what to dispatch (prompts, schemas, model selection).
    The generic dispatcher handles how (threading, progress, cost, errors).
    """

    name: str = "task"
    model_role: str = "analysis"
    temperature: float = 0.7
    budget_cutoff: float = 1.0  # 1.0 = never skip. 0.85 = skip at 85% budget

    def get_last_nonce(self) -> str:
        """Return the nonce from the most recent build_prompt call, if any.

        Subclasses that use PromptBundle should store bundle.nonce and
        return it here so the dispatcher can feed it to defense telemetry.
        """
        return ""

    def get_profile_name(self) -> str:
        """Return the defense profile name for telemetry."""
        return ""

    def select_items(self, items: list, prior_results: dict) -> list:
        """Select which items to process. Default: all items."""
        return items

    def get_models(self, role_resolution: dict) -> list:
        """Return list of models to dispatch to. Default: single model for this role."""
        model = role_resolution.get(f"{self.model_role}_model")
        return [model] if model else []

    def build_prompt(self, item: dict[str, Any]) -> str:
        """Build the prompt for one item. Must be implemented by subclass."""
        raise NotImplementedError

    def get_schema(self, _item: dict[str, Any]) -> dict | None:
        """Schema for structured output, or None for free-form generate()."""
        return None

    def get_system_prompt(self) -> str | None:
        """System prompt for this task."""
        return None

    def budget_tokens_for_model(self, model) -> int:
        """Context budget for user content (prompt) given a model.

        Returns 0 (no shedding) by default.  Subclasses that use
        prompt-budget shedding override this.
        """
        return 0

    def process_result(
        self, _item: dict[str, Any], result: DispatchResult,
    ) -> dict[str, Any]:
        """Post-process a single result. Default: return result dict with metadata."""
        out = strip_dispatch_metadata(result.result)
        if result.cost > 0:
            out["cost_usd"] = result.cost
        if result.duration > 0:
            out["duration_seconds"] = round(result.duration, 1)
        out.update(dispatch_result_metadata(result))
        # Surface the validator quality score when the response was
        # incomplete. Lets downstream report consumers see *why* a
        # finding is unverdicted (gh #549) — `quality` defaults to 1.0
        # and only drops when `validate_structured_response` flags
        # missing required fields, so quietly omit it on the happy path.
        # Gate on the rounded value so a 0.999 score (which would
        # display as "1.00" anyway) doesn't pollute the output.
        quality_rounded = round(result.quality, 2)
        if quality_rounded < 1.0:
            out["quality"] = quality_rounded
        return out

    def finalize(self, results: list[dict], prior_results: dict) -> list[dict]:
        """Post-dispatch processing. Default: no-op.

        Override for consensus verdicts, etc.
        """
        return results

    def get_item_id(self, item: dict[str, Any]) -> str:
        """ID for result matching and progress display."""
        return item.get("finding_id", item.get("group_id", "unknown"))

    def get_item_display(self, item: dict[str, Any]) -> str:
        """Human-readable location for progress line."""
        fp = item.get("file_path", "")
        if fp:
            fp = fp.split("/")[-1]
            line = item.get("start_line", "")
            return f"{fp}:{line}" if line else fp
        return ""


def _format_elapsed(seconds: float) -> str:
    """Format elapsed seconds. Delegates to core.reporting.formatting."""
    from core.reporting.formatting import format_elapsed
    return format_elapsed(seconds)


# Consecutive-failure count at which even a PROVEN model (one with
# prior successes this run) is circuit-broken. Both-directions
# trade-off: lower and a transient burst (timeout storm, proxy blip —
# observed bursts run <= 5) kills a healthy model mid-run; higher and
# a model that succeeded once then died permanently (mid-run
# credential expiry, provider outage) burns one full timeout per
# remaining work item before anything stops it. The never-succeeded
# fast path stays at 3 — a model that has produced nothing but
# failures earns no patience.
_BREAKER_PROVEN_THRESHOLD = 10


def _breaker_should_open(consec: int, completed: int) -> bool:
    """Decide whether a model's circuit opens after its latest failure.

    ``consec`` is the model's current consecutive-failure streak;
    ``completed`` counts ALL of its drained completions this run
    (successes included). Two independent triggers:

    - Never-succeeded fast path: 3 consecutive failures from a model
      whose every completion so far was one of those failures
      (``completed == consec``) — a model that has produced nothing
      but failures earns no patience.
    - History-independent threshold: even a proven model (prior
      successes this run) opens after ``_BREAKER_PROVEN_THRESHOLD``
      consecutive failures — see the constant's both-directions
      rationale.
    """
    return ((consec >= 3 and completed == consec)
            or consec >= _BREAKER_PROVEN_THRESHOLD)


def dispatch_task(
    task: DispatchTask,
    items: list,
    dispatch_fn: Callable,
    role_resolution: dict,
    prior_results: dict,
    cost_tracker: Any,
    max_parallel: int = 3,
    prefilter_fn: Callable | None = None,
) -> list[dict[str, Any]]:
    """Generic parallel dispatcher.

    Handles threading, progress output, cost tracking, error handling,
    and auth abort. The task defines semantics (prompts, schemas, model
    selection). The dispatch_fn abstracts the LLM interaction.

    Args:
        task: DispatchTask subclass defining what to dispatch.
        items: Raw items (findings, groups, etc) — task.select_items filters them.
        dispatch_fn: Callable(prompt, schema, system_prompt,
            temperature, model) -> DispatchResult.
        role_resolution: Model role resolution dict from resolve_model_roles().
        prior_results: Results from earlier tasks, keyed by item ID.
        cost_tracker: CostTracker for budget enforcement.
        max_parallel: Maximum concurrent dispatches.
        prefilter_fn: Optional ``(item) -> Optional[result-dict]`` hook
            invoked before building the prompt and calling dispatch_fn.
            When it returns a dict the work item is short-circuited
            (no full ANALYSE call, no token/cost accounting beyond
            whatever the hook itself spent). Used by /agentic to wire
            in the scorecard prefilter; ``None`` for tasks that don't
            participate.

    Returns:
        List of result dicts, one per item dispatched. Failed items have "error" key.
    """
    selected = task.select_items(items, prior_results)
    if not selected:
        return []

    models = task.get_models(role_resolution)
    if not models:
        # CC path: no model resolution, dispatch_fn ignores model parameter
        models = [None]

    # Budget pre-check.
    #
    # Pre-fix this used `models[0].model_name` for the per-call
    # rate estimate. With multi-model dispatch (`--model
    # claude-opus --model gpt-4o`), the cost tracker estimated
    # the WHOLE phase as if every call used models[0]'s rate —
    # so a phase routing 50% of calls to a 10x-cheaper secondary
    # model still got estimated at the full primary rate.
    # Operators saw "skipped — budget" warnings on phases that
    # would actually have fit within budget.
    #
    # Use the MAXIMUM per-call rate across the model list. The
    # estimate is then conservative (over-, never under-), so
    # the budget gate fires at most where it should and never
    # silently skips a phase that would have fit.
    if task.budget_cutoff < 1.0:
        # Pick the most expensive model name as the pessimistic
        # estimator. cost_tracker.should_skip_phase indexes by
        # name to look up the rate; passing the priciest gives
        # the conservative ceiling. Fallback to "" if all None
        # (CC path) — should_skip_phase handles unknown.
        named_models = [m for m in models if m is not None]
        if named_models:
            try:
                model_name = max(
                    named_models,
                    key=lambda m: cost_tracker.estimate_cost(
                        1, model_name=m.model_name,
                    ),
                ).model_name
            except (AttributeError, TypeError):
                model_name = named_models[0].model_name
        else:
            model_name = ""
        total_calls = len(selected) * len(models)
        skip = cost_tracker.should_skip_phase(
            total_calls, model_name, task.budget_cutoff, task.name,
            # No named models ⇒ the CC subprocess path. Estimating CC
            # calls at the external-LLM default (~$0.03) under-gates
            # ~7x against the documented ~$0.20/finding observed rate.
            is_cc=not named_models,
        )
        if skip:
            print(f"\n  {task.name}: skipped ({len(selected)} items) — "
                  f"budget > {int(task.budget_cutoff * 100)}%"
                  f"; raise --max-cost to include")
            return []

    # Build work items: (model, item) pairs
    work: list[tuple[Any, Any]] = []
    for model in models:
        work.extend((model, item) for item in selected)

    print(f"\n  {task.name}: {len(selected)} items"
          + (f" x {len(models)} models" if len(models) > 1 else "")
          + f" (max {max_parallel} parallel)")

    start = time.monotonic()
    system_prompt = task.get_system_prompt()
    profile_name = task.get_profile_name()

    from core.llm.concurrency import read_throttle_cooldown_s
    from core.llm.throttle import AdaptiveThrottle
    _throttle = AdaptiveThrottle(
        max_parallel, cooldown_s=read_throttle_cooldown_s(),
    )

    try:  # guarantees _throttle.close() on any exit path
        return _dispatch_inner(
            task, work, selected, dispatch_fn, cost_tracker,
            max_parallel, prefilter_fn, prior_results, _throttle,
            start, system_prompt, profile_name,
        )
    finally:
        if _throttle.signal_count:
            logger.info(
                "dispatch throttle: %d 429 signals, effective=%d/%d",
                _throttle.signal_count, _throttle.effective_workers,
                _throttle.max_workers,
            )
        _throttle.close()


def _dispatch_inner(
    task, work, selected, dispatch_fn, cost_tracker,
    max_parallel, prefilter_fn, prior_results, _throttle,
    start, system_prompt, profile_name,
):
    from core.security.prompt_input_preflight import preflight
    from core.security.prompt_telemetry import defense_telemetry

    total = len(work)
    completed = 0
    running_cost = 0.0
    results = []
    abort = False
    abort_reason = "auth failure"
    _per_model_auth_fail: set = set()
    _per_model_dead: set = set()
    _per_model_state: dict[str, dict[str, int]] = {}

    import threading as _th
    # Guards _per_model_dead: the drain loop (main thread) adds dead
    # models while worker threads check membership in _do_one.
    _dead_lock = _th.Lock()
    # Key by (item_id, model_key) tuple — NOT just item_id. With N
    # models analysing the same item (multi-model orchestration),
    # all N writes land on the same `iid` key and last-writer-
    # wins, then the first completed future pops the entry and
    # the remaining N-1 model responses see an empty nonce →
    # `defense_telemetry.record_response` silently never fires
    # for them, defeating the entire prompt-injection / nonce-
    # leak detection layer (it can't detect leakage if it never
    # gets to compare the response against the nonce). Each
    # (item, model) pair must hold its own nonce to its own
    # completion.
    _nonces: dict[tuple, str] = {}
    _nonces_lock = _th.Lock()
    task._tls_budget = _th.local()

    def _model_key(m) -> str:
        """Stable hashable identity for a model object — same
        formula used for telemetry's `model_id` so the nonce
        lookup matches the recorded response."""
        return getattr(m, "model_name", None) or str(m)

    with ThreadPoolExecutor(max_workers=max_parallel) as executor:
        futures = {}
        for model, item in work:
            def _do_one(m=model, it=item):
                # Circuit-breaker enforcement. All (model, item)
                # futures are pre-submitted before the drain loop
                # starts, so a model declared dead mid-run still has
                # queued work — short-circuit those futures here
                # instead of spending another API call on a model
                # that keeps failing.
                with _dead_lock:
                    if _model_key(m) in _per_model_dead:
                        raise _ModelCircuitOpen(_model_key(m))
                # Prefilter hook (fast-tier scorecard) — fires before
                # prompt build and full dispatch so we don't pay for
                # token-heavy work when the cheap-tier verdict is
                # trusted. Returning a dict here ends this work item
                # with that result; ``None`` proceeds to full dispatch.
                if prefilter_fn is not None:
                    sc_result = prefilter_fn(it)
                    if sc_result is not None:
                        model_name = m.model_name if m is not None else "prefilter"
                        return DispatchResult(
                            result=sc_result,
                            cost=0.0,
                            tokens=0,
                            model=model_name,
                            duration=0.0,
                            quality=1.0,
                            no_spend=True,
                        )
                task._tls_budget.tokens = task.budget_tokens_for_model(m)
                prompt = task.build_prompt(it)
                nonce = task.get_last_nonce()
                if nonce:
                    iid = task.get_item_id(it)
                    with _nonces_lock:
                        _nonces[(iid, _model_key(m))] = nonce
                pf = preflight(prompt, corpora=_DISPATCH_CORPORA, strict=True)
                defense_telemetry.record_preflight(hit=pf.has_injection_indicators)
                schema = task.get_schema(it)
                with _throttle.acquire_sync():
                    return dispatch_fn(prompt, schema, system_prompt, task.temperature, m)

            future = executor.submit(_do_one)
            futures[future] = (model, item)

        # Which futures the drain loop below actually consumed — the
        # post-abort straggler sweep needs the complement.
        drained_futures: set[Future] = set()

        for future in as_completed(futures):
            drained_futures.add(future)
            model, item = futures[future]
            item_id = task.get_item_id(item)
            model_key = _model_key(model)
            completed += 1
            elapsed = time.monotonic() - start

            accounting_recorded = False
            try:
                dispatch_result = future.result()
                payload = getattr(dispatch_result, "result", None)
                # Key-presence check, per _ErrorDictResult's contract
                # (dicts with an ``error`` key): a truthiness check
                # let an ``{"error": ""}`` envelope ride the success
                # path and reset the circuit breaker.
                is_error_envelope = (
                    isinstance(payload, dict) and "error" in payload
                )
                record_dispatch_accounting(
                    cost_tracker,
                    dispatch_result,
                    failed=is_error_envelope,
                )
                accounting_recorded = True
                if is_error_envelope:
                    # Error envelope from a non-raising dispatch path —
                    # book any cost the failed call still burned (a CC
                    # timeout can bill before dying), then route the
                    # failure through the except-branch below so the
                    # circuit breaker / auth abort / telemetry see it.
                    _err_cost = getattr(dispatch_result, "cost", 0) or 0
                    _err_tokens = getattr(dispatch_result, "tokens", 0) or 0
                    _err_model = getattr(dispatch_result, "model", "") or ""
                    running_cost += _err_cost
                    raise _ErrorDictResult(
                        str(payload.get("error")),
                        model_name=_err_model,
                        metadata=dispatch_result_metadata(
                            dispatch_result, failed=True,
                        ),
                    )
                processed = task.process_result(item, dispatch_result)
                processed["finding_id"] = item_id
                processed["_quality"] = getattr(dispatch_result, "quality", 1.0)
                item_cost = processed.get("cost_usd", 0)
                running_cost += item_cost
                results.append(processed)
                # Reset this model's consecutive-failure counter
                # — successful response means we're not in a
                # death spiral for this model.
                pm = _per_model_state.setdefault(
                    model_key, {"consec": 0, "completed": 0},
                )
                pm["completed"] += 1
                pm["consec"] = 0

                # Record defense telemetry (nonce leakage, schema rejection)
                with _nonces_lock:
                    nonce = _nonces.pop((item_id, model_key), "")
                if nonce and profile_name:
                    raw = ""
                    has_dict = (
                        hasattr(dispatch_result, "result")
                        and isinstance(dispatch_result.result, dict)
                    )
                    if has_dict:
                        raw = dispatch_result.result.get("content", "")
                    raw_text = raw or str(dispatch_result.result)
                    defense_telemetry.record_response(
                        model_id=processed.get("analysed_by", "unknown"),
                        profile_name=profile_name,
                        nonce=nonce,
                        raw_response=raw_text,
                        schema_accepted=True,
                        schema_retried=False,
                    )
                    from core.security.prompt_envelope import nonce_leaked_in
                    if nonce_leaked_in(nonce, raw_text):
                        processed["_nonce_leaked"] = True

                # Cost, token, route, and basis accounting was recorded
                # above through the typed seam. Keep the hostile-repo
                # display value terminal-safe.
                display = escape_nonprintable(task.get_item_display(item))
                if "is_exploitable" in processed:
                    exploitable = read_verdict(processed, "is_exploitable")
                    score = processed.get("exploitability_score")
                    ruling = processed.get("ruling")
                    if exploitable is None:
                        # Response validation nulled the verdict —
                        # the model abstained. "not exploitable" on
                        # the progress line would show the operator
                        # a definitive ruling nobody made.
                        status = "no verdict"
                    else:
                        try:
                            if exploitable:
                                status = f"exploitable ({float(score):.2f})"
                            else:
                                status = "not exploitable"
                        except (ValueError, TypeError):
                            status = ("exploitable" if exploitable
                                      else "not exploitable")
                        # Show short ruling labels (enum values), not
                        # long-form text
                        valid_rulings = {
                            "false_positive", "unreachable",
                            "test_code", "dead_code", "mitigated",
                        }
                        if (ruling and ruling in valid_rulings
                                and not exploitable):
                            status = ruling.replace("_", " ")
                else:
                    status = "done"
                cost = processed.get("cost_usd")
                try:
                    cost_str = f"  ${float(cost):.2f}" if cost else ""
                except (ValueError, TypeError):
                    cost_str = ""
                prefix = (
                    f"  [{completed}/{total} "
                    f"{_format_elapsed(elapsed)} "
                    f"${running_cost:.2f}]"
                )
                print(f"{prefix} {display} {status}{cost_str}")

            except _ModelCircuitOpen:
                # The worker short-circuited a pre-submitted future
                # for an already-dead model: no API call was made, no
                # nonce was stored, and this is not a fresh failure —
                # record the skip without touching the per-model
                # consecutive-failure counters or telemetry.
                model_name = model.model_name if model is not None else "?"
                results.append({
                    "finding_id": item_id,
                    "error": "skipped (model circuit-broken)",
                    "error_type": "circuit_breaker",
                    "analysed_by": model_name,
                })
                display = escape_nonprintable(task.get_item_display(item))
                prefix = (
                    f"  [{completed}/{total} "
                    f"{_format_elapsed(elapsed)} "
                    f"${running_cost:.2f}]"
                )
                print(f"{prefix} {display} skipped — model circuit-broken")

            except LLMPolicyError as e:
                if not accounting_recorded:
                    record_exception_accounting(
                        cost_tracker, e, model_name=model_key,
                    )
                raise

            except Exception as e:  # noqa: BLE001 — per-item isolation: one failed dispatch must not sink the batch
                err_str = str(e)
                error_type = _classify_error(err_str)
                model_name = model.model_name if model is not None else "?"
                error_metadata: dict[str, Any] = {}
                if isinstance(e, _ErrorDictResult) and e.model_name:
                    # The error envelope carried its own attribution
                    # (e.g. "claude-code") — better than the "?" bucket
                    # the CC path (model=None) would otherwise land in.
                    model_name = e.model_name
                    error_metadata = e.metadata
                elif not isinstance(e, _ErrorDictResult):
                    if not accounting_recorded:
                        error_metadata = record_exception_accounting(
                            cost_tracker, e, model_name=model_key,
                        )
                error_record = {
                    "finding_id": item_id,
                    "error": err_str,
                    "error_type": error_type,
                    "analysed_by": model_name,
                }
                error_record.update(error_metadata)
                results.append(error_record)
                display = escape_nonprintable(task.get_item_display(item))
                prefix = (
                    f"  [{completed}/{total} "
                    f"{_format_elapsed(elapsed)} "
                    f"${running_cost:.2f}]"
                )
                # err_str can embed response excerpts on the external
                # LLM path (the CC path pre-escapes; this one is the
                # chokepoint for everything else).
                print(f"{prefix} {display} FAILED — {escape_nonprintable(err_str)}")

                # Record schema failure telemetry (skip auth/network errors)
                if error_type not in ("auth", "timeout") and profile_name:
                    with _nonces_lock:
                        nonce = _nonces.pop((item_id, model_key), "")
                    if nonce:
                        # When dispatching via CC (model=None,
                        # cc_dispatch.invoke_cc_simple), `model` is
                        # None and pre-fix `getattr(None,
                        # "model_name", str(None))` produced the
                        # literal string "None" as the telemetry
                        # model_id. Per-model telemetry counters
                        # then attributed every CC schema failure
                        # to a phantom model called "None" instead
                        # of "claude-code". Coerce the CC case to
                        # the canonical "claude-code" string so
                        # failure telemetry matches the success
                        # path's `analysed_by` attribution
                        # (cc_dispatch.py sets it to "claude-code").
                        if model is None:
                            model_id = "claude-code"
                        else:
                            model_id = getattr(model, "model_name", str(model))
                        defense_telemetry.record_response(
                            model_id=model_id,
                            profile_name=profile_name,
                            nonce=nonce,
                            raw_response=err_str,
                            schema_accepted=False,
                            schema_retried=False,
                        )

                # Per-model auth-failure tracking. Pre-fix any
                # single auth error from ANY model aborted the
                # WHOLE dispatch — so with multi-model dispatch
                # (M models × N findings) a single bad credential
                # on one model killed work in progress on every
                # other valid model. Track per (model_key, "auth")
                # and only abort when ALL models active for this
                # task have hit auth errors.
                if _is_auth_error(err_str):
                    _per_model_auth_fail.add(model_key)
                    distinct_models = {_model_key(m) for m, _ in work}
                    if _per_model_auth_fail >= distinct_models:
                        print(
                            "\n  All models hit auth/billing"
                            " errors — aborting remaining",
                            file=sys.stderr,
                        )
                        abort = True
                        abort_reason = "auth failure"
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    # Single-model auth failure — keep dispatching
                    # to other models. Surface the per-model
                    # failure but don't kill peers.
                    print(
                        f"  (model {model_key} auth-failed;"
                        " continuing with other models)",
                        file=sys.stderr,
                    )

                # Per-model consecutive_errors. Pre-fix the global
                # counter triggered "3 consecutive failures" abort
                # when one bad model's failures interleaved with
                # other models' successes — with M models the
                # round-robin scheduler frequently hit
                # fail/fail/fail-from-same-model bursts that the
                # GLOBAL counter saw as universal failure even
                # when other models had succeeded between them.
                # Open/stay-closed logic lives in
                # _breaker_should_open; a model whose circuit opens
                # gets its remaining futures short-circuited by the
                # dead-check in _do_one.
                pm = _per_model_state.setdefault(
                    model_key, {"consec": 0, "completed": 0},
                )
                pm["completed"] += 1
                pm["consec"] += 1
                if _breaker_should_open(pm["consec"], pm["completed"]):
                    print(
                        f"\n  Model {model_key}:"
                        f" {pm['consec']} consecutive"
                        " failures — stopping dispatch"
                        " to this model (others continue)",
                        file=sys.stderr,
                    )
                    with _dead_lock:
                        _per_model_dead.add(model_key)
                    distinct_models = {_model_key(m) for m, _ in work}
                    if _per_model_dead >= distinct_models:
                        print(
                            "\n  All models circuit-broken —"
                            " aborting remaining",
                            file=sys.stderr,
                        )
                        abort = True
                        abort_reason = "all models circuit-broken"
                        executor.shutdown(wait=False, cancel_futures=True)
                        break

    if abort:
        # Straggler sweep. The executor context-exit above ran
        # shutdown(wait=True), so every future is now drained,
        # cancelled, or done-but-undrained. The undrained ones are
        # stragglers: futures whose dead-check beat the dead-add, so a
        # REAL API call ran to completion after the drain loop's abort
        # break. Without this sweep a straggler's telemetry event was
        # LOST and the backfill below rewrote its real outcome as
        # "aborted (...)" — a paid-for result (or a real failure that
        # telemetry must count) mislabelled as an abort casualty.
        for future, (model, item) in futures.items():
            if (future in drained_futures or future.cancelled()
                    or not future.done()):
                continue
            item_id = task.get_item_id(item)
            model_key = _model_key(model)
            model_name = model.model_name if model is not None else "?"
            err_str = None
            dispatch_result = None
            exc = future.exception()
            if isinstance(exc, _ModelCircuitOpen):
                # Short-circuited before dispatch: no API call, no
                # fresh failure — same skip row as the drain loop.
                results.append({
                    "finding_id": item_id,
                    "error": "skipped (model circuit-broken)",
                    "error_type": "circuit_breaker",
                    "analysed_by": model_name,
                })
                continue
            if exc is not None:
                err_str = str(exc)
            else:
                dispatch_result = future.result()
                payload = getattr(dispatch_result, "result", None)
                # Key-presence check, per _ErrorDictResult's contract
                # (mirrors the drain loop's envelope handling).
                if isinstance(payload, dict) and "error" in payload:
                    err_str = str(payload.get("error"))
                    _err_cost = getattr(dispatch_result, "cost", 0) or 0
                    _err_tokens = getattr(
                        dispatch_result, "tokens", 0) or 0
                    _err_model = getattr(
                        dispatch_result, "model", "") or ""
                    if _err_cost > 0 or _err_tokens > 0:
                        cost_tracker.add_cost(
                            _err_model or "unknown", _err_cost,
                            tokens=_err_tokens,
                        )
                    if _err_model:
                        model_name = _err_model
            if err_str is None:
                try:
                    processed = task.process_result(item, dispatch_result)
                except Exception as e:  # noqa: BLE001 — per-item isolation, as in the drain loop
                    err_str = str(e)
                else:
                    processed["finding_id"] = item_id
                    processed["_quality"] = getattr(
                        dispatch_result, "quality", 1.0)
                    item_cost = processed.get("cost_usd", 0)
                    item_tokens = getattr(
                        dispatch_result, "tokens", 0) or 0
                    item_thinking = getattr(
                        dispatch_result, "thinking_tokens", 0) or 0
                    if (item_cost > 0 or item_tokens > 0
                            or item_thinking > 0):
                        cost_tracker.add_cost(
                            processed.get("analysed_by", "unknown"),
                            item_cost, tokens=item_tokens,
                            thinking_tokens=item_thinking,
                        )
                    # Nonce-leak check, mirroring the drain's success
                    # path: the leak flag still has consumers after an
                    # abort — the defense summary merged into run
                    # output, and the cross-family recheck's item
                    # selection (whose checker model can be healthy
                    # even when every model here died). The recheck
                    # skips rows carrying an "error" key, so the old
                    # "aborted" mislabel accidentally quarantined a
                    # leaking straggler; sweeping it in unflagged
                    # would PROMOTE it instead.
                    with _nonces_lock:
                        nonce = _nonces.pop((item_id, model_key), "")
                    if nonce and profile_name:
                        raw = ""
                        has_dict = (
                            hasattr(dispatch_result, "result")
                            and isinstance(dispatch_result.result, dict)
                        )
                        if has_dict:
                            raw = dispatch_result.result.get("content", "")
                        raw_text = raw or str(dispatch_result.result)
                        defense_telemetry.record_response(
                            model_id=processed.get(
                                "analysed_by", "unknown"),
                            profile_name=profile_name,
                            nonce=nonce,
                            raw_response=raw_text,
                            schema_accepted=True,
                            schema_retried=False,
                        )
                        from core.security.prompt_envelope import (
                            nonce_leaked_in,
                        )
                        if nonce_leaked_in(nonce, raw_text):
                            processed["_nonce_leaked"] = True
                    results.append(processed)
                    continue
            error_type = _classify_error(err_str)
            results.append({"finding_id": item_id, "error": err_str,
                            "error_type": error_type,
                            "analysed_by": model_name})
            # Record the straggler's failure telemetry exactly like
            # the drain loop would have (skip auth/network errors).
            if error_type not in ("auth", "timeout") and profile_name:
                with _nonces_lock:
                    nonce = _nonces.pop((item_id, model_key), "")
                if nonce:
                    if model is None:
                        model_id = "claude-code"
                    else:
                        model_id = getattr(model, "model_name", str(model))
                    defense_telemetry.record_response(
                        model_id=model_id,
                        profile_name=profile_name,
                        nonce=nonce,
                        raw_response=err_str,
                        schema_accepted=False,
                        schema_retried=False,
                    )

        completed_ids = {r.get("finding_id") for r in results}
        for item in selected:
            item_id = task.get_item_id(item)
            if item_id not in completed_ids:
                # Pre-fix this hardcoded "aborted (auth failure)" even
                # when the abort came from the all-models-circuit-broken
                # branch — mislabelling non-auth death spirals in the
                # per-item error records. Carry the actual reason.
                results.append({
                    "finding_id": item_id,
                    "error": f"aborted ({abort_reason})",
                })

    # Finalize (e.g. consensus verdict rules)
    return task.finalize(results, prior_results)
