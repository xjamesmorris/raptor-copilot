"""Explicit catalogue-unlisted Claude model routing.

These cases are hermetic: no Claude binary or provider endpoint is called.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.llm.config as llm_config_module
from core.llm.accounting import (
    AccountingMode,
    CostBasis,
    cost_basis_for_model_config,
    direct_api_accounting_capability,
)
from core.llm.cc_adapter import CCTransportError, StreamJsonResult
from core.llm.client import _pinned_llm_config
from core.llm.config import LLMConfig, ModelConfig, set_operator_primary_override
from core.llm.model_data import (
    context_window_for,
    max_output_for,
    resolve_model_costs,
    resolve_model_limits,
)
from core.llm.providers import (
    AnthropicProvider,
    ClaudeCodeLLMProvider,
    LLMProvider,
)
from core.security.llm_family import explicit_provider_of, provider_of
from packages.llm_analysis.orchestrator import build_llm_config_from_flags


UNLISTED = "vendor/rhyolite.preview:2026_10@beta"
FAMILY_SHAPED_EXACT = "claude-rhyolite.preview:2026_10@beta"
REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def _reset_explicit_primary(monkeypatch):
    set_operator_primary_override(None)
    for name in (
        "ANTHROPIC_API_KEY",
        "RAPTOR_CC_MODEL",
        "RAPTOR_CC_PIN_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)
    yield
    set_operator_primary_override(None)


def _configured(monkeypatch, entries: list[dict]) -> None:
    monkeypatch.setattr(
        "core.llm.config._get_configured_models",
        lambda: entries,
    )


def test_claude_frontend_forwards_model_verbatim():
    source = (REPO_ROOT / "bin" / "raptor").read_text(encoding="utf-8")
    start = source.index("        -m|--model)")
    model_case = source[start:source.index("            ;;", start)]
    assert 'FRONTEND_ARGS+=("--model" "$2")' in model_case

    exec_start = source.index("# RAPTOR_FRONTEND_EXEC_BEGIN")
    exec_end = source.index("# RAPTOR_FRONTEND_EXEC_END")
    exec_block = source[exec_start:exec_end]
    assert '"${FRONTEND_ARGS[@]}"' in exec_block


def test_exact_configured_unusual_name_keeps_declared_route(monkeypatch):
    _configured(monkeypatch, [{
        "provider": "anthropic",
        "model": UNLISTED,
        "api_key": "configured-key",
        "api_base": "https://claude-gateway.example.invalid/v1",
        "max_context": 123_456,
        "max_output": 7_890,
    }])

    config = build_llm_config_from_flags(
        models=[UNLISTED],
        auto_detect=False,
    )

    assert config is not None
    model = config.primary_model
    assert model is not None
    assert model.provider == "anthropic"
    assert model.model_name == UNLISTED
    assert model.api_key == "configured-key"
    assert model.api_base == "https://claude-gateway.example.invalid/v1"
    assert model.max_context == 123_456
    assert model.max_tokens == 7_890
    assert config.fallback_models == []
    assert config.specialized_models == {}


def test_pinned_headless_path_honours_exact_configured_unusual_name(
    monkeypatch,
):
    _configured(monkeypatch, [{
        "provider": "anthropic",
        "model": UNLISTED,
        "api_key": "configured-key",
        "api_base": "https://claude-gateway.example.invalid/v1",
        "max_context": 123_456,
        "max_output": 7_890,
    }])

    config = _pinned_llm_config(UNLISTED)

    model = config.primary_model
    assert model is not None
    assert model.provider == "anthropic"
    assert model.model_name == UNLISTED
    assert model.api_key == "configured-key"
    assert model.api_base == "https://claude-gateway.example.invalid/v1"
    assert model.max_context == 123_456
    assert model.max_tokens == 7_890
    assert config.exact_pinned is True


def test_exact_family_shaped_name_keeps_configured_claudecode_route(
    monkeypatch,
):
    entries = [{
        "provider": "claudecode",
        "model": FAMILY_SHAPED_EXACT,
        "max_context": 222_222,
        "max_output": 9_999,
        "timeout": 777,
    }]
    _configured(monkeypatch, entries)
    monkeypatch.setattr(
        "shutil.which",
        lambda name: "/opt/fake/claude" if name == "claude" else None,
    )

    assert provider_of(FAMILY_SHAPED_EXACT) == "anthropic"
    assert explicit_provider_of(FAMILY_SHAPED_EXACT) == ""

    configured_model = ModelConfig(
        provider="claudecode",
        model_name=FAMILY_SHAPED_EXACT,
        max_context=222_222,
        max_tokens=9_999,
        timeout=777,
    )
    resolver = LLMConfig(
        primary_model=None,
        fallback_models=[configured_model],
        specialized_models={},
    )
    assert resolver.config_for_model(FAMILY_SHAPED_EXACT) is configured_model

    config = build_llm_config_from_flags(
        models=[FAMILY_SHAPED_EXACT],
        auto_detect=False,
    )
    assert config is not None
    model = config.primary_model
    assert model is not None
    assert model.provider == "claudecode"
    assert model.model_name == FAMILY_SHAPED_EXACT
    assert model.max_context == 222_222
    assert model.max_tokens == 9_999
    assert model.timeout == 777

    pinned = _pinned_llm_config(FAMILY_SHAPED_EXACT)
    assert pinned.primary_model is not None
    assert pinned.primary_model.provider == "claudecode"
    assert pinned.primary_model.model_name == FAMILY_SHAPED_EXACT


def test_provider_qualified_unlisted_claude_borrows_same_provider_route(
    monkeypatch,
):
    _configured(monkeypatch, [
        {
            "provider": "anthropic",
            "model": "claude-opus-4-6",
            "api_key": "anthropic-key",
            "api_base": "https://claude-gateway.example.invalid/v1",
            "max_context": 999_999,
            "max_output": 88_888,
        },
        {
            "provider": "gemini",
            "model": "gemini-2.5-pro",
            "api_key": "gemini-key",
            "api_base": "https://gemini-gateway.example.invalid/v1",
        },
    ])

    config = build_llm_config_from_flags(
        models=[f"anthropic/{UNLISTED}"],
        auto_detect=False,
    )

    assert config is not None
    model = config.primary_model
    assert model is not None
    assert model.provider == "anthropic"
    assert model.model_name == UNLISTED
    assert model.api_key == "anthropic-key"
    assert model.api_base == "https://claude-gateway.example.invalid/v1"
    assert model.api_key != "gemini-key"
    # A sibling lends only auth/route, never its advertised capability.
    assert model.max_context != 999_999
    assert model.max_tokens != 88_888
    assert config.specialized_models == {}


def test_provider_qualified_exact_name_respects_explicit_route(monkeypatch):
    wrong_route = ModelConfig(
        provider="gemini",
        model_name=UNLISTED,
        api_key="wrong-key",
        api_base="https://wrong.example.invalid/v1",
    )
    right_route = ModelConfig(
        provider="anthropic",
        model_name=UNLISTED,
        api_key="right-key",
        api_base="https://right.example.invalid/v1",
    )
    config = LLMConfig(
        primary_model=None,
        fallback_models=[wrong_route, right_route],
        specialized_models={},
    )

    model = config.config_for_model(f"anthropic/{UNLISTED}")

    assert model is right_route
    assert model.api_key == "right-key"
    assert model.api_base == "https://right.example.invalid/v1"

    _configured(monkeypatch, [
        {
            "provider": "gemini",
            "model": UNLISTED,
            "api_key": "wrong-key",
            "api_base": "https://wrong.example.invalid/v1",
        },
        {
            "provider": "anthropic",
            "model": UNLISTED,
            "api_key": "right-key",
            "api_base": "https://right.example.invalid/v1",
        },
    ])
    built = build_llm_config_from_flags(
        models=[f"anthropic/{UNLISTED}"],
        auto_detect=False,
    )
    pinned = _pinned_llm_config(f"anthropic/{UNLISTED}")
    assert built is not None
    for resolved in (built.primary_model, pinned.primary_model):
        assert resolved is not None
        assert resolved.provider == "anthropic"
        assert resolved.api_key == "right-key"
        assert resolved.api_base == "https://right.example.invalid/v1"


def test_pinned_provider_qualified_model_prefers_configured_route_over_env(
    monkeypatch,
):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ambient-key")
    _configured(monkeypatch, [{
        "provider": "anthropic",
        "model": "claude-opus-4-6",
        "api_key": "configured-key",
        "api_base": "https://configured.example.invalid/v1",
        "max_context": 999_999,
        "max_output": 88_888,
    }])

    config = _pinned_llm_config(f"anthropic/{UNLISTED}")

    model = config.primary_model
    assert model is not None
    assert model.provider == "anthropic"
    assert model.model_name == UNLISTED
    assert model.api_key == "configured-key"
    assert model.api_base == "https://configured.example.invalid/v1"
    assert model.max_context == 32_000
    assert model.max_tokens == 4_096
    assert model.cost_per_1k_tokens == 0.0
    assert config.exact_pinned is True
    assert config.fallback_models == []
    assert config.specialized_models == {}


@pytest.mark.parametrize(
    ("route", "expected_provider"),
    [
        ("claudecode", "claudecode"),
        ("claude-code", "claudecode"),
        ("claude_code", "claudecode"),
        ("claudecode-resumable", "claudecode-resumable"),
        ("claude-code-resumable", "claudecode-resumable"),
        ("claude_code_resumable", "claudecode-resumable"),
    ],
)
def test_provider_qualified_claudecode_unlisted_model_is_retained(
    monkeypatch,
    route,
    expected_provider,
):
    _configured(monkeypatch, [])
    monkeypatch.setattr(
        "shutil.which",
        lambda name: "/opt/fake/claude" if name == "claude" else None,
    )

    config = build_llm_config_from_flags(
        models=[f"{route}/{UNLISTED}"],
        auto_detect=False,
    )

    assert config is not None
    model = config.primary_model
    assert model is not None
    assert model.provider == expected_provider
    assert model.model_name == UNLISTED
    assert model.api_key is None
    assert config.fallback_models == []


@pytest.mark.parametrize(
    ("route", "expected_provider"),
    [
        ("anthropic", "anthropic"),
        ("claudecode", "claudecode"),
        ("claude-code", "claudecode"),
    ],
)
@pytest.mark.parametrize(
    "model_id",
    [
        "rhyolite.preview:2026_10@beta",
        "Vendor/Rhyolite-Preview.v2:Beta+Tools@20261016",
    ],
)
def test_provider_qualified_unusual_separators_are_retained_verbatim(
    monkeypatch,
    route,
    expected_provider,
    model_id,
):
    _configured(monkeypatch, [{
        "provider": "anthropic",
        "model": "claude-opus-4-6",
        "api_key": "configured-key",
        "api_base": "https://configured.example.invalid/v1",
    }])
    monkeypatch.setattr(
        "shutil.which",
        lambda name: "/opt/fake/claude" if name == "claude" else None,
    )

    config = build_llm_config_from_flags(
        models=[f"{route}/{model_id}"],
        auto_detect=False,
    )

    assert config is not None
    model = config.primary_model
    assert model is not None
    assert model.provider == expected_provider
    assert model.model_name == model_id
    if expected_provider == "anthropic":
        assert model.api_key == "configured-key"
        assert model.api_base == "https://configured.example.invalid/v1"
    else:
        assert model.api_key is None


def test_unqualified_unknown_typo_fails_loudly(monkeypatch, capsys):
    _configured(monkeypatch, [{
        "provider": "anthropic",
        "model": "claude-opus-4-6",
        "api_key": "configured-key",
    }])

    config = build_llm_config_from_flags(
        models=["rhyolte-preview-20261016"],
        auto_detect=False,
    )

    assert config is None
    stderr = capsys.readouterr().err
    assert "unrecognized model" in stderr
    assert "provider/model" in stderr
    assert llm_config_module._operator_primary_override is None
    with pytest.raises(ValueError, match="unrecognized model"):
        _pinned_llm_config("rhyolte.preview:2026_10@beta")


def test_unlisted_model_capability_and_cost_remain_unknown(monkeypatch):
    _configured(monkeypatch, [{
        "provider": "anthropic",
        "model": "claude-opus-4-6",
        "api_key": "configured-key",
    }])
    config = build_llm_config_from_flags(
        models=[f"anthropic/{UNLISTED}"],
        auto_detect=False,
    )
    assert config is not None
    model = config.primary_model
    assert model is not None

    assert resolve_model_limits(model.model_name) is None
    assert resolve_model_costs(model.model_name) is None
    with pytest.raises(KeyError, match="unknown model"):
        context_window_for(model.model_name)
    with pytest.raises(KeyError, match="unknown model"):
        max_output_for(model.model_name)
    # Runtime-safe request bounds are conservative sentinels, not
    # published capability claims.
    assert model.max_context == 32_000
    assert model.max_tokens == 4_096
    assert model.cost_per_1k_tokens == 0.0
    assert cost_basis_for_model_config(model) is CostBasis.UNKNOWN
    assert (
        direct_api_accounting_capability(model).mode
        is AccountingMode.UNKNOWN
    )


def test_unlisted_claudecode_capability_and_cost_remain_unknown(
    monkeypatch,
):
    _configured(monkeypatch, [])
    monkeypatch.setattr(
        "shutil.which",
        lambda name: "/opt/fake/claude" if name == "claude" else None,
    )
    config = build_llm_config_from_flags(
        models=[f"claudecode/{UNLISTED}"],
        auto_detect=False,
    )
    assert config is not None
    model = config.primary_model
    assert model is not None

    assert resolve_model_limits(model.model_name) is None
    assert resolve_model_costs(model.model_name) is None
    with pytest.raises(KeyError, match="unknown model"):
        context_window_for(model.model_name)
    with pytest.raises(KeyError, match="unknown model"):
        max_output_for(model.model_name)
    assert model.max_context == 32_000
    assert model.max_tokens == 4_096
    assert model.cost_per_1k_tokens == 0.0
    provider = ClaudeCodeLLMProvider(
        model,
        claude_bin="/opt/fake/claude",
    )
    assert provider.expected_cost_basis() is CostBasis.UNKNOWN
    assert provider.accounting_capability().mode is AccountingMode.UNKNOWN


def test_claudecode_upstream_rejection_propagates_without_substitution(
    monkeypatch,
):
    import core.llm.cc_adapter as cc_adapter

    captured: dict[str, object] = {}

    def reject(cmd, prompt, *, env, timeout_s):
        captured["cmd"] = list(cmd)
        captured["prompt"] = prompt
        return StreamJsonResult(
            cost_usd=0.0,
            cost_reported=False,
            error=f"upstream rejected model {UNLISTED}",
        )

    @contextmanager
    def no_system_prompt_file(_config):
        yield None

    monkeypatch.setattr(cc_adapter, "run_cc_streaming", reject)
    monkeypatch.setattr(
        cc_adapter,
        "system_prompt_file_for",
        no_system_prompt_file,
    )
    monkeypatch.setattr(cc_adapter, "cc_subprocess_env", lambda: {})

    provider = ClaudeCodeLLMProvider(
        ModelConfig(
            provider="claudecode",
            model_name=UNLISTED,
            timeout=30,
        ),
        claude_bin="/opt/fake/claude",
    )

    with pytest.raises(
        CCTransportError,
        match=re.escape(f"upstream rejected model {UNLISTED}"),
    ):
        provider.generate("test prompt")

    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert cmd[cmd.index("--model") + 1] == UNLISTED
    assert captured["prompt"] == "test prompt"


def test_anthropic_upstream_rejection_propagates_exact_model():
    captured: dict[str, object] = {}
    rejection = RuntimeError(f"upstream rejected model {UNLISTED}")

    class RejectingMessages:
        def create(self, **kwargs):
            captured.update(kwargs)
            raise rejection

    provider = AnthropicProvider.__new__(AnthropicProvider)
    LLMProvider.__init__(
        provider,
        ModelConfig(
            provider="anthropic",
            model_name=UNLISTED,
            api_key="configured-key",
        ),
    )
    provider.client = SimpleNamespace(messages=RejectingMessages())
    provider._stream_sse_ok = False

    with pytest.raises(RuntimeError) as exc_info:
        provider.generate("test prompt")

    assert exc_info.value is rejection
    assert captured["model"] == UNLISTED
