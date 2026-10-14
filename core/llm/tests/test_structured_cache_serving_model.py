"""Incomplete serving-route metadata is never replayed from cache."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from core.llm import cache_integrity
from core.testing import (
    FakeStructuredProvider,
    install_provider,
    make_test_client,
)

_SCHEMA = {"type": "object", "properties": {"verdict": {"type": "string"}}}


@pytest.fixture(autouse=True)
def _isolated_mac_key(tmp_path_factory, monkeypatch):
    """Fresh per-test key dir: never touch the developer's real key."""
    monkeypatch.setenv(
        "XDG_DATA_HOME", str(tmp_path_factory.mktemp("xdg-data")),
    )


def test_entry_without_serving_model_is_a_miss(tmp_path: Path) -> None:
    """Even a route-qualified entry cannot replay without serving model."""
    client = make_test_client(tmp_path)
    fake = FakeStructuredProvider({"verdict": "safe"})
    install_provider(client, fake)

    cache_key = client._get_structured_cache_key(
        "p", None, "test-primary", _SCHEMA, None,
        provider="anthropic",
    )
    name = f"structured-{cache_key}"
    entry = cache_integrity.stamp(name, {
        "cache_identity": client._cache_identity(
            "anthropic", "test-primary",
        ),
        "result": {"verdict": "stale"},
        "raw": '{"verdict": "stale"}',
        "provider": "anthropic",
        "tokens_used": 5,
        "timestamp": time.time(),
    })
    client.config.cache_dir.mkdir(parents=True, exist_ok=True)
    (client.config.cache_dir / f"{name}.json").write_text(
        json.dumps(entry),
    )

    replay = client.generate_structured("p", _SCHEMA)
    assert fake.calls == 1
    assert replay.cached is False
    assert replay.result == {"verdict": "safe"}
