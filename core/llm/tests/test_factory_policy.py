"""Explicit LLM policy failures must not be softened into no-client."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from core.llm.accounting import PinnedRouteViolation
from core.llm.config import LLMConfig, ModelConfig
from core.llm.factory import get_client
from core.security.session_services import ServiceAuthorizationError


@pytest.mark.parametrize("error", (PinnedRouteViolation, ServiceAuthorizationError))
def test_factory_reraises_explicit_policy_refusal(error) -> None:
    config = LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic",
            model_name="model",
            api_key="unused",
        ),
        fallback_models=[],
    )
    with patch(
        "core.llm.factory.LLMClient",
        side_effect=error("policy refused"),
    ), pytest.raises(error, match="policy refused"):
        get_client(config)
