from __future__ import annotations

from core.json import save_json
from packages.sca.host_refresh import REQUIRED_SOURCES, SCHEMA, fresh_receipt


def _write(cache, target, *, refreshed_at=1000.0, sources=None):
    cache.mkdir()
    save_json(cache / "host-refresh-receipt.json", {
        "schema": SCHEMA,
        "refreshed_at": refreshed_at,
        "target": str(target),
        "sources": list(sources or REQUIRED_SOURCES),
        "anonymous": True,
    })


def test_accepts_fresh_target_bound_anonymous_receipt(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    cache = tmp_path / "cache"
    _write(cache, target)

    assert fresh_receipt(target, cache_root=cache, now=1100.0) is not None


def test_rejects_stale_wrong_target_or_incomplete_sources(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    other = tmp_path / "other"
    other.mkdir()

    stale = tmp_path / "stale"
    _write(stale, target, refreshed_at=1.0)
    assert fresh_receipt(target, cache_root=stale, now=100000.0) is None

    wrong = tmp_path / "wrong"
    _write(wrong, other)
    assert fresh_receipt(target, cache_root=wrong, now=1100.0) is None

    incomplete = tmp_path / "incomplete"
    _write(incomplete, target, sources=["api.osv.dev"])
    assert fresh_receipt(target, cache_root=incomplete, now=1100.0) is None
