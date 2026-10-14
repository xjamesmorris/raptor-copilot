"""Adapter: orchestrator dispatch_fn → hypothesis_validation LLMClientProtocol.

The /agentic orchestrator builds a `dispatch_fn(prompt, schema,
system_prompt, temperature, model) -> DispatchResult` that handles
external-LLM and CC-fallback modes uniformly. hypothesis_validation
expects a different shape: `client.generate_structured(prompt, schema,
system_prompt=..., task_type=..., **kwargs) -> dict-or-None`.

This adapter bridges the two so the dataflow-validation pass can reuse
the orchestrator's already-configured client without forcing
hypothesis_validation to know about DispatchResult, role resolution, or
CostTracker.
"""

import logging
from collections.abc import Callable
from typing import Any

from core.llm.accounting import LLMPolicyError
from core.llm.coerce import structured_result
from packages.llm_analysis.dispatch import (
    record_dispatch_accounting,
    record_exception_accounting,
)

logger = logging.getLogger(__name__)


def _cost_model_key(model: Any) -> str:
    """Cost-attribution key for a model spec — never its repr.

    The key becomes the ``cost_by_model`` label emitted verbatim into
    the run report, which operators share when reporting issues.
    ModelConfig-style dataclasses carry ``api_key`` as a repr-visible
    field, so falling back to ``str(model)`` would write credential
    material into that artifact. Read the known name attributes
    (``model_name`` on ModelConfig, ``model`` on plain client shapes)
    and otherwise fall back to the class name, which is structurally
    incapable of carrying secrets. Non-string attribute values are
    ignored for the same reason — only a plain string name is trusted
    as a label.
    """
    if model is None:
        return "unknown"
    if isinstance(model, str):
        return model or "unknown"
    for attr in ("model_name", "model"):
        value = getattr(model, attr, None)
        if isinstance(value, str) and value:
            return value
    return type(model).__name__


class DispatchClient:
    """Wrap a dispatch_fn so it satisfies LLMClientProtocol.

    Args:
        dispatch_fn: The orchestrator's dispatch callable. Signature:
            (prompt, schema, system_prompt, temperature, model) -> DispatchResult
            where DispatchResult has .result (dict) and .cost (float).
        model: Model spec (typically a ModelConfig) to use for every
            call this adapter makes. The orchestrator selects this once
            per /agentic run; we don't need per-call model selection.
        cost_tracker: Optional CostTracker. When provided, each call's
            cost is added so the budget guard sees dataflow validation
            work.
        temperature: Sampling temperature, default 0.0 (deterministic).
            hypothesis_validation generates rules and evaluates evidence;
            both want low entropy.
    """

    def __init__(
        self,
        dispatch_fn: Callable,
        model: Any,
        *,
        cost_tracker: Any | None = None,
        temperature: float = 0.0,
    ) -> None:
        self._dispatch_fn = dispatch_fn
        self._model = model
        self._cost_tracker = cost_tracker
        self._temperature = temperature

    def generate_structured(
        self,
        prompt: str,
        schema: dict[str, Any],
        system_prompt: str | None = None,
        task_type: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        """Invoke the orchestrator's dispatch_fn and return the parsed dict.

        `task_type` is accepted for protocol compatibility but ignored —
        the model is fixed at construction time per the orchestrator's
        role resolution. `kwargs` are also ignored.

        Returns the result dict on success, or None for an ordinary unusable
        response. Explicit policy refusals remain typed errors and are never
        converted into a success-shaped value.
        """
        try:
            response = self._dispatch_fn(
                prompt, schema, system_prompt, self._temperature, self._model,
            )
        except Exception as e:  # noqa: BLE001 — classify before fail-open
            record_exception_accounting(
                self._cost_tracker,
                e,
                model_name=_cost_model_key(self._model),
            )
            logger.warning("dispatch_fn raised during dataflow validation: %s", e)
            if isinstance(e, LLMPolicyError):
                raise
            return None

        result = structured_result(response)
        if not isinstance(result, dict):
            record_dispatch_accounting(
                self._cost_tracker,
                response,
                failed=True,
                model_name=_cost_model_key(self._model),
            )
            return None
        if "error" in result:
            record_dispatch_accounting(
                self._cost_tracker,
                response,
                failed=True,
                model_name=_cost_model_key(self._model),
            )
            logger.warning(
                "dispatch_fn returned error during dataflow validation: %s",
                result.get("error"),
            )
            return None
        record_dispatch_accounting(
            self._cost_tracker,
            response,
            failed=False,
            model_name=_cost_model_key(self._model),
        )
        return result


__all__ = ["DispatchClient"]
