"""Versioned provider-qualified LLM response-cache identity."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.hash import sha256_string
from core.json import dumps_canonical
from core.llm import cache_integrity
from core.llm.client import LLMClient
from core.llm.config import ModelConfig
from core.llm.providers import LLMResponse, StructuredResponse
from core.testing import (
    FakeStructuredProvider,
    install_provider,
    make_test_client,
)

_SCHEMA = {
    "type": "object",
    "properties": {"route": {"type": "string"}},
}


def _text_provider(*, content: str, model: str, provider: str) -> MagicMock:
    fake = MagicMock()
    fake.generate.return_value = LLMResponse(
        content=content,
        model=model,
        provider=provider,
        tokens_used=4,
        cost=0.0,
        finish_reason="stop",
    )
    return fake


def _full_provider(
    *,
    content: str,
    model: str,
    provider: str,
    resolved_model: str | None = None,
) -> MagicMock:
    fake = MagicMock()
    fake.total_cost = 0.0
    fake.total_tokens = 0
    fake.total_input_tokens = 0
    fake.total_output_tokens = 0
    fake.total_cache_read_tokens = 0
    fake.total_cache_write_tokens = 0
    fake.generate.return_value = LLMResponse(
        content=content,
        model=model,
        provider=provider,
        tokens_used=4,
        cost=0.0,
        finish_reason="stop",
        resolved_model=resolved_model,
    )
    fake.generate_structured.return_value = StructuredResponse(
        result={"route": content},
        raw=json.dumps({"route": content}),
        model=model,
        provider=provider,
        resolved_model=resolved_model,
    )
    return fake


def _fallback_client(
    tmp_path: Path,
    *,
    resolved_model: str | None = None,
) -> tuple[LLMClient, ModelConfig, MagicMock, MagicMock]:
    client = make_test_client(tmp_path, provider="anthropic")
    fallback = ModelConfig(
        provider="openai",
        model_name="fallback-model",
        api_key="not-used",
    )
    client.config.enable_fallback = True
    client.config.fallback_models = [fallback]

    primary_provider = _full_provider(
        content="primary",
        model="test-primary",
        provider="anthropic",
    )
    primary_provider.generate.side_effect = ValueError("primary failed")
    primary_provider.generate_structured.side_effect = ValueError(
        "primary failed",
    )
    fallback_provider = _full_provider(
        content="fallback",
        model="fallback-model",
        provider="openai",
        resolved_model=resolved_model,
    )
    client.providers["anthropic:test-primary"] = primary_provider
    client.providers["openai:fallback-model"] = fallback_provider
    return client, fallback, primary_provider, fallback_provider


def _write_stamped(path: Path, name: str, entry: dict) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / f"{name}.json").write_text(
        json.dumps(cache_integrity.stamp(name, entry)),
        encoding="utf-8",
    )


def _legacy_freeform_key(
    prompt: str, system_prompt: str | None, model: str,
) -> str:
    return sha256_string(dumps_canonical([
        model,
        system_prompt or "",
        prompt,
        "",
    ]))


def _legacy_structured_key(
    prompt: str, system_prompt: str | None, model: str, schema: dict,
) -> str:
    assert schema == _SCHEMA
    schema_json = (
        '{"properties": {"route": {"type": "string"}}, '
        '"type": "object"}'
    )
    return sha256_string(dumps_canonical([
        "v3",
        model,
        system_prompt or "",
        prompt,
        schema_json,
        "",
    ]))


def test_freeform_same_route_hits_but_different_provider_misses(
    tmp_path: Path,
) -> None:
    direct = make_test_client(tmp_path, provider="anthropic")
    cli = make_test_client(tmp_path, provider="claudecode")
    direct_provider = _text_provider(
        content="direct", model="test-primary", provider="anthropic",
    )
    cli_provider = _text_provider(
        content="cli", model="test-primary", provider="claudecode",
    )
    install_provider(direct, direct_provider)
    install_provider(cli, cli_provider)

    assert direct._get_cache_key(
        "same prompt", None, "test-primary", provider="anthropic",
    ) != cli._get_cache_key(
        "same prompt", None, "test-primary", provider="claudecode",
    )
    assert direct.generate("same prompt").content == "direct"
    direct_hit = direct.generate("same prompt")
    assert cli.generate("same prompt").content == "cli"
    cli_hit = cli.generate("same prompt")

    assert direct_provider.generate.call_count == 1
    assert cli_provider.generate.call_count == 1
    assert direct_hit.finish_reason == "cached"
    assert direct_hit.provider == "anthropic"
    assert cli_hit.finish_reason == "cached"
    assert cli_hit.provider == "claudecode"


def test_structured_same_route_hits_but_different_provider_misses(
    tmp_path: Path,
) -> None:
    direct = make_test_client(tmp_path, provider="anthropic")
    cli = make_test_client(tmp_path, provider="claudecode")
    direct_provider = FakeStructuredProvider(
        {"route": "direct"}, raw='{"route":"direct"}',
    )
    cli_provider = FakeStructuredProvider(
        {"route": "cli"}, raw='{"route":"cli"}',
    )
    install_provider(direct, direct_provider)
    install_provider(cli, cli_provider)

    assert direct._get_structured_cache_key(
        "same prompt", None, "test-primary", _SCHEMA,
        provider="anthropic",
    ) != cli._get_structured_cache_key(
        "same prompt", None, "test-primary", _SCHEMA,
        provider="claudecode",
    )
    assert direct.generate_structured("same prompt", _SCHEMA).result == {
        "route": "direct",
    }
    direct_hit = direct.generate_structured("same prompt", _SCHEMA)
    assert cli.generate_structured("same prompt", _SCHEMA).result == {
        "route": "cli",
    }
    cli_hit = cli.generate_structured("same prompt", _SCHEMA)

    assert direct_provider.calls == 1
    assert cli_provider.calls == 1
    assert direct_hit.cached is True
    assert direct_hit.provider == "anthropic"
    assert cli_hit.cached is True
    assert cli_hit.provider == "claudecode"


def test_legacy_keys_are_not_read_by_v2_routes(tmp_path: Path) -> None:
    text_client = make_test_client(tmp_path, provider="anthropic")
    text_provider = _text_provider(
        content="fresh", model="test-primary", provider="anthropic",
    )
    install_provider(text_client, text_provider)
    legacy_key = _legacy_freeform_key(
        "legacy prompt", None, "test-primary",
    )
    _write_stamped(text_client.config.cache_dir, legacy_key, {
        "content": "legacy",
        "model": "test-primary",
        "provider": "anthropic",
        "timestamp": time.time(),
    })

    structured_client = make_test_client(tmp_path, provider="anthropic")
    structured_provider = FakeStructuredProvider(
        {"route": "fresh"}, raw='{"route":"fresh"}',
    )
    install_provider(structured_client, structured_provider)
    legacy_structured_key = _legacy_structured_key(
        "legacy structured", None, "test-primary", _SCHEMA,
    )
    _write_stamped(
        structured_client.config.cache_dir,
        f"structured-{legacy_structured_key}",
        {
            "result": {"route": "legacy"},
            "raw": '{"route":"legacy"}',
            "model": "test-primary",
            "provider": "anthropic",
            "timestamp": time.time(),
        },
    )

    assert text_client.generate("legacy prompt").content == "fresh"
    assert structured_client.generate_structured(
        "legacy structured", _SCHEMA,
    ).result == {"route": "fresh"}
    assert text_provider.generate.call_count == 1
    assert structured_provider.calls == 1


def test_providerless_entries_in_v2_slots_are_misses(tmp_path: Path) -> None:
    text_client = make_test_client(tmp_path, provider="anthropic")
    text_provider = _text_provider(
        content="fresh", model="test-primary", provider="anthropic",
    )
    install_provider(text_client, text_provider)
    text_key = text_client._get_cache_key(
        "p", None, "test-primary", provider="anthropic",
    )
    _write_stamped(text_client.config.cache_dir, text_key, {
        "content": "legacy",
        "model": "test-primary",
        "provider": "anthropic",
        "timestamp": time.time(),
    })

    structured_client = make_test_client(tmp_path, provider="anthropic")
    structured_provider = FakeStructuredProvider({"route": "fresh"})
    install_provider(structured_client, structured_provider)
    structured_key = structured_client._get_structured_cache_key(
        "sp", None, "test-primary", _SCHEMA, provider="anthropic",
    )
    _write_stamped(
        structured_client.config.cache_dir,
        f"structured-{structured_key}",
        {
            "result": {"route": "legacy"},
            "raw": '{"route":"legacy"}',
            "model": "test-primary",
            "provider": "anthropic",
            "timestamp": time.time(),
        },
    )

    assert text_client.generate("p").content == "fresh"
    assert structured_client.generate_structured(
        "sp", _SCHEMA,
    ).result == {"route": "fresh"}
    assert text_provider.generate.call_count == 1
    assert structured_provider.calls == 1


def test_freeform_fallback_cache_replays_serving_route(
    tmp_path: Path,
) -> None:
    client = make_test_client(tmp_path, provider="anthropic")
    fallback = ModelConfig(
        provider="openai",
        model_name="fallback-model",
        api_key="not-used",
    )
    client.config.enable_fallback = True
    client.config.fallback_models = [fallback]

    primary_provider = MagicMock()
    primary_provider.generate.side_effect = ValueError("primary failed")
    fallback_provider = _text_provider(
        content="fallback answer",
        model="fallback-model",
        provider="openai",
    )
    client.providers["anthropic:test-primary"] = primary_provider
    client.providers["openai:fallback-model"] = fallback_provider

    with patch("core.llm.telemetry.emit") as emit:
        fresh = client.generate("fallback prompt")
        replay = client.generate("fallback prompt")

    assert fresh.model == replay.model == "fallback-model"
    assert fresh.provider == replay.provider == "openai"
    assert replay.finish_reason == "cached"
    assert primary_provider.generate.call_count == 1
    assert fallback_provider.generate.call_count == 1

    entry_path = next(
        p for p in client.config.cache_dir.glob("*.json")
        if not p.name.startswith("structured-")
    )
    entry = json.loads(entry_path.read_text(encoding="utf-8"))
    assert entry["cache_identity"] == {
        "version": 2,
        "provider": "anthropic",
        "model": "test-primary",
    }
    assert entry["provider"] == "openai"
    assert entry["model"] == "fallback-model"
    cache_event = emit.call_args_list[-1].kwargs
    assert cache_event["disposition"] == "cache_hit"
    assert cache_event["provider"] == "openai"
    assert cache_event["model"] == "fallback-model"
    assert cache_event["requested_provider"] == "anthropic"
    assert cache_event["requested_model"] == "test-primary"


def test_structured_fallback_cache_replays_serving_route(
    tmp_path: Path,
) -> None:
    client = make_test_client(tmp_path, provider="anthropic")
    fallback = ModelConfig(
        provider="openai",
        model_name="fallback-model",
        api_key="not-used",
    )
    client.config.enable_fallback = True
    client.config.fallback_models = [fallback]

    primary_provider = MagicMock()
    primary_provider.total_cost = 0.0
    primary_provider.total_tokens = 0
    primary_provider.total_input_tokens = 0
    primary_provider.total_output_tokens = 0
    primary_provider.total_cache_read_tokens = 0
    primary_provider.total_cache_write_tokens = 0
    primary_provider.generate_structured.side_effect = ValueError(
        "primary failed",
    )
    fallback_provider = FakeStructuredProvider(
        {"route": "fallback"}, raw='{"route":"fallback"}',
    )
    client.providers["anthropic:test-primary"] = primary_provider
    client.providers["openai:fallback-model"] = fallback_provider

    with patch("core.llm.telemetry.emit") as emit:
        fresh = client.generate_structured("fallback prompt", _SCHEMA)
        replay = client.generate_structured("fallback prompt", _SCHEMA)

    assert fresh.model == replay.model == "fallback-model"
    assert fresh.provider == replay.provider == "openai"
    assert replay.cached is True
    assert primary_provider.generate_structured.call_count == 1
    assert fallback_provider.calls == 1

    entry_path = next(client.config.cache_dir.glob("structured-*.json"))
    entry = json.loads(entry_path.read_text(encoding="utf-8"))
    assert entry["cache_identity"] == {
        "version": 2,
        "provider": "anthropic",
        "model": "test-primary",
    }
    assert entry["provider"] == "openai"
    assert entry["model"] == "fallback-model"
    cache_event = emit.call_args_list[-1].kwargs
    assert cache_event["disposition"] == "cache_hit"
    assert cache_event["provider"] == "openai"
    assert cache_event["model"] == "fallback-model"
    assert cache_event["requested_provider"] == "anthropic"
    assert cache_event["requested_model"] == "test-primary"


@pytest.mark.parametrize(
    "policy",
    ["fallback-disabled", "fallback-removed", "model-disabled", "excluded"],
)
def test_warm_fallback_rechecks_current_policy_for_both_apis(
    tmp_path: Path,
    policy: str,
) -> None:
    client, fallback, primary_provider, fallback_provider = _fallback_client(
        tmp_path,
        # A provider-reported snapshot is evidence only. Even when it
        # happens to equal the authorized primary alias, it must not
        # authorize the fallback's distinct logical route.
        resolved_model="test-primary",
    )
    client.generate("policy-freeform")
    client.generate_structured("policy-structured", _SCHEMA)
    assert primary_provider.generate.call_count == 1
    assert primary_provider.generate_structured.call_count == 1
    assert fallback_provider.generate.call_count == 1
    assert fallback_provider.generate_structured.call_count == 1

    if policy == "fallback-disabled":
        client.config.enable_fallback = False
    elif policy == "fallback-removed":
        client.config.fallback_models = []
    elif policy == "model-disabled":
        fallback.enabled = False

    with pytest.raises(RuntimeError):
        if policy == "excluded":
            client.generate(
                "policy-freeform",
                exclude_fallback_to={"fallback-model"},
            )
        else:
            client.generate("policy-freeform")
    with pytest.raises(RuntimeError):
        if policy == "excluded":
            client.generate_structured(
                "policy-structured",
                _SCHEMA,
                exclude_fallback_to={"fallback-model"},
            )
        else:
            client.generate_structured("policy-structured", _SCHEMA)

    assert primary_provider.generate.call_count == 2
    assert primary_provider.generate_structured.call_count == 2
    assert fallback_provider.generate.call_count == 1
    assert fallback_provider.generate_structured.call_count == 1

    if policy == "fallback-disabled":
        client.config.enable_fallback = True
    elif policy == "fallback-removed":
        client.config.fallback_models = [fallback]
    elif policy == "model-disabled":
        fallback.enabled = True

    freeform = client.generate("policy-freeform")
    structured = client.generate_structured("policy-structured", _SCHEMA)
    assert freeform.finish_reason == "cached"
    assert structured.cached is True
    assert freeform.model == structured.model == "fallback-model"
    assert freeform.resolved_model == "test-primary"
    assert structured.resolved_model == "test-primary"
    assert primary_provider.generate.call_count == 2
    assert primary_provider.generate_structured.call_count == 2
    assert fallback_provider.generate.call_count == 1
    assert fallback_provider.generate_structured.call_count == 1


@pytest.mark.parametrize(
    ("fallback_provider_name", "fallback_model"),
    [
        ("openai", "test-primary"),
        ("ollama", "fallback-model"),
    ],
    ids=["same-name", "cross-tier"],
)
def test_same_name_and_cross_tier_routes_remain_ineligible(
    tmp_path: Path,
    fallback_provider_name: str,
    fallback_model: str,
) -> None:
    client = make_test_client(tmp_path, provider="anthropic")
    fallback = ModelConfig(
        provider=fallback_provider_name,
        model_name=fallback_model,
        api_key="not-used",
    )
    client.config.enable_fallback = True
    client.config.fallback_models = [fallback]

    primary_provider = _full_provider(
        content="primary",
        model="test-primary",
        provider="anthropic",
    )
    primary_provider.generate.side_effect = ValueError("primary failed")
    primary_provider.generate_structured.side_effect = ValueError(
        "primary failed",
    )
    fallback_provider = _full_provider(
        content="fallback",
        model=fallback_model,
        provider=fallback_provider_name,
    )
    client.providers["anthropic:test-primary"] = primary_provider
    client.providers[
        f"{fallback_provider_name}:{fallback_model}"
    ] = fallback_provider

    freeform_key = client._get_cache_key(
        "ineligible-freeform",
        None,
        "test-primary",
        provider="anthropic",
    )
    client._save_to_cache(
        freeform_key,
        fallback_provider.generate.return_value,
        requested_provider="anthropic",
        requested_model="test-primary",
        serving_provider=fallback_provider_name,
        serving_model=fallback_model,
    )
    structured_key = client._get_structured_cache_key(
        "ineligible-structured",
        None,
        "test-primary",
        _SCHEMA,
        provider="anthropic",
    )
    client._save_structured_to_cache(
        structured_key,
        fallback_provider.generate_structured.return_value,
        requested_provider="anthropic",
        requested_model="test-primary",
        serving_provider=fallback_provider_name,
        serving_model=fallback_model,
    )

    with pytest.raises(RuntimeError):
        client.generate("ineligible-freeform")
    with pytest.raises(RuntimeError):
        client.generate_structured("ineligible-structured", _SCHEMA)

    assert primary_provider.generate.call_count == 1
    assert primary_provider.generate_structured.call_count == 1
    assert fallback_provider.generate.call_count == 0
    assert fallback_provider.generate_structured.call_count == 0


def test_warm_fallback_remains_admissible_when_quota_throttled(
    tmp_path: Path,
) -> None:
    client, _, primary_provider, fallback_provider = _fallback_client(
        tmp_path,
    )
    client.generate("quota-freeform")
    client.generate_structured("quota-structured", _SCHEMA)
    client._daily_quota_exhausted.add(("openai", "fallback-model"))

    freeform = client.generate("quota-freeform")
    structured = client.generate_structured("quota-structured", _SCHEMA)

    assert freeform.finish_reason == "cached"
    assert structured.cached is True
    assert primary_provider.generate.call_count == 1
    assert primary_provider.generate_structured.call_count == 1
    assert fallback_provider.generate.call_count == 1
    assert fallback_provider.generate_structured.call_count == 1


def test_primary_same_route_hits_despite_fallback_exclusion(
    tmp_path: Path,
) -> None:
    client = make_test_client(tmp_path, provider="anthropic")
    provider = _full_provider(
        content="primary",
        model="test-primary",
        provider="anthropic",
    )
    install_provider(client, provider)

    client.generate("primary-freeform")
    client.generate_structured("primary-structured", _SCHEMA)
    freeform = client.generate(
        "primary-freeform",
        exclude_fallback_to={"fallback-model"},
    )
    structured = client.generate_structured(
        "primary-structured",
        _SCHEMA,
        exclude_fallback_to={"fallback-model"},
    )

    assert freeform.finish_reason == "cached"
    assert structured.cached is True
    assert provider.generate.call_count == 1
    assert provider.generate_structured.call_count == 1


def test_disabled_primary_model_does_not_replay_same_route(
    tmp_path: Path,
) -> None:
    client = make_test_client(tmp_path, provider="anthropic")
    provider = _full_provider(
        content="primary",
        model="test-primary",
        provider="anthropic",
    )
    install_provider(client, provider)
    client.generate("disabled-primary-freeform")
    client.generate_structured("disabled-primary-structured", _SCHEMA)

    assert client.config.primary_model is not None
    client.config.primary_model.enabled = False

    with pytest.raises(RuntimeError):
        client.generate("disabled-primary-freeform")
    with pytest.raises(RuntimeError):
        client.generate_structured(
            "disabled-primary-structured", _SCHEMA,
        )

    assert provider.generate.call_count == 1
    assert provider.generate_structured.call_count == 1


def test_resolved_model_roundtrips_for_both_cache_shapes(
    tmp_path: Path,
) -> None:
    client = make_test_client(tmp_path, provider="anthropic")
    provider = _full_provider(
        content="primary",
        model="test-primary",
        provider="anthropic",
        resolved_model="runtime-reported-snapshot",
    )
    install_provider(client, provider)

    fresh_freeform = client.generate("resolved-freeform")
    fresh_structured = client.generate_structured(
        "resolved-structured", _SCHEMA,
    )
    cached_freeform = client.generate("resolved-freeform")
    cached_structured = client.generate_structured(
        "resolved-structured", _SCHEMA,
    )

    assert (
        fresh_freeform.resolved_model
        == cached_freeform.resolved_model
        == "runtime-reported-snapshot"
    )
    assert (
        fresh_structured.resolved_model
        == cached_structured.resolved_model
        == "runtime-reported-snapshot"
    )
    assert provider.generate.call_count == 1
    assert provider.generate_structured.call_count == 1


@pytest.mark.parametrize("metadata", ["missing", "malformed"])
def test_unusable_cached_resolved_model_remains_unknown(
    tmp_path: Path,
    metadata: str,
) -> None:
    client = make_test_client(tmp_path, provider="anthropic")
    provider = _full_provider(
        content="fresh",
        model="test-primary",
        provider="anthropic",
    )
    install_provider(client, provider)

    freeform_key = client._get_cache_key(
        "malformed-freeform",
        None,
        "test-primary",
        provider="anthropic",
    )
    freeform_entry = {
        "cache_identity": client._cache_identity(
            "anthropic", "test-primary",
        ),
        "content": "cached",
        "model": "test-primary",
        "provider": "anthropic",
        "timestamp": time.time(),
    }
    if metadata == "malformed":
        freeform_entry["resolved_model"] = {"not": "a string"}
    _write_stamped(
        client.config.cache_dir, freeform_key, freeform_entry,
    )
    structured_key = client._get_structured_cache_key(
        "malformed-structured",
        None,
        "test-primary",
        _SCHEMA,
        provider="anthropic",
    )
    structured_entry = {
        "cache_identity": client._cache_identity(
            "anthropic", "test-primary",
        ),
        "result": {"route": "cached"},
        "raw": '{"route":"cached"}',
        "model": "test-primary",
        "provider": "anthropic",
        "timestamp": time.time(),
    }
    if metadata == "malformed":
        structured_entry["resolved_model"] = 17
    _write_stamped(
        client.config.cache_dir,
        f"structured-{structured_key}",
        structured_entry,
    )

    freeform = client.generate("malformed-freeform")
    structured = client.generate_structured(
        "malformed-structured", _SCHEMA,
    )

    assert freeform.finish_reason == "cached"
    assert freeform.resolved_model is None
    assert structured.cached is True
    assert structured.resolved_model is None
    assert provider.generate.call_count == 0
    assert provider.generate_structured.call_count == 0


def test_malformed_fresh_resolved_model_remains_unknown_on_replay(
    tmp_path: Path,
) -> None:
    client = make_test_client(tmp_path, provider="anthropic")
    provider = _full_provider(
        content="primary",
        model="test-primary",
        provider="anthropic",
    )
    provider.generate.return_value.resolved_model = {
        "not": "a string",
    }
    provider.generate_structured.return_value.resolved_model = 17
    install_provider(client, provider)

    fresh_freeform = client.generate("malformed-fresh-freeform")
    fresh_structured = client.generate_structured(
        "malformed-fresh-structured", _SCHEMA,
    )
    cached_freeform = client.generate("malformed-fresh-freeform")
    cached_structured = client.generate_structured(
        "malformed-fresh-structured", _SCHEMA,
    )

    assert fresh_freeform.resolved_model is None
    assert cached_freeform.resolved_model is None
    assert fresh_structured.resolved_model is None
    assert cached_structured.resolved_model is None
    assert provider.generate.call_count == 1
    assert provider.generate_structured.call_count == 1


def test_resolved_model_is_integrity_protected_for_both_cache_shapes(
    tmp_path: Path,
) -> None:
    client = make_test_client(tmp_path, provider="anthropic")
    provider = _full_provider(
        content="primary",
        model="test-primary",
        provider="anthropic",
        resolved_model="runtime-reported-snapshot",
    )
    install_provider(client, provider)
    client.generate("tampered-freeform")
    client.generate_structured("tampered-structured", _SCHEMA)

    cache_files = list(client.config.cache_dir.glob("*.json"))
    assert len(cache_files) == 2
    for cache_file in cache_files:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        data["resolved_model"] = "forged-snapshot"
        cache_file.write_text(json.dumps(data), encoding="utf-8")

    freeform = client.generate("tampered-freeform")
    structured = client.generate_structured(
        "tampered-structured", _SCHEMA,
    )

    assert freeform.finish_reason == "stop"
    assert structured.cached is False
    assert freeform.resolved_model == "runtime-reported-snapshot"
    assert structured.resolved_model == "runtime-reported-snapshot"
    assert provider.generate.call_count == 2
    assert provider.generate_structured.call_count == 2
    assert client.cache_tamper_events == 2
