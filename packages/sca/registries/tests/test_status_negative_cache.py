"""Registry client cache-honesty regressions.

- Maven POM / NuGet nuspec 404s arrive as *responses* (both clients
  fetch with ``raise_on_status=False``), so the exception-path
  ``should_negative_cache`` gate never saw them: every detector
  re-fetched the same dead POM/nuspec — the exact duplicate-404
  traffic the negative cache was built to stop.
- A locally-missing defusedxml is an ENVIRONMENT condition; caching it
  as "no nuspec" kept serving the miss for a full TTL after the
  dependency was installed.
- The Debian suite cache key is built by the shared injective builder
  (a raw suite containing ``..`` raised ValueError out of the cache
  layer; ``\\`` aliased distinct suites).
- RubyGems adapts its payload to a ``releases`` map; a missing version
  must not mint a ``None`` key (JSON round-trip turns it into "null",
  so first call and cached call returned different shapes).
"""

from __future__ import annotations

from typing import Any

import pytest

from core.json import JsonCache

from packages.sca.registries.debian import DebianClient
from packages.sca.registries.maven import MavenClient
from packages.sca.registries.nuget import NugetClient
from packages.sca.registries.rubygems import RubyGemsClient


class _StatusHttp:
    """Stub returning a fixed status via the request() surface."""

    def __init__(self, status: int = 404, content: bytes = b"") -> None:
        self.status = status
        self.content = content
        self.request_calls: list[str] = []

    def request(self, method: str, url: str, **kw: Any):
        self.request_calls.append(url)

        outer = self

        class _Resp:
            status_code = outer.status
            content = outer.content

        return _Resp()

    def get_json(self, url: str, **kw: Any) -> Any:  # pragma: no cover
        raise NotImplementedError


class _JsonHttp:
    def __init__(self, payload: Any) -> None:
        self.payload = payload
        self.calls: list[str] = []

    def get_json(self, url: str, **kw: Any) -> Any:
        self.calls.append(url)
        return self.payload


class TestMavenPom404NegativeCache:
    def test_404_is_negative_cached(self, tmp_path):
        http = _StatusHttp(status=404)
        cache = JsonCache(root=tmp_path)
        client = MavenClient(http, cache=cache)
        assert client.get_pom("com.example:artifact", "1.2.3") is None
        assert client.get_pom("com.example:artifact", "1.2.3") is None
        assert len(http.request_calls) == 1, "dead POM re-fetched despite 404"

    def test_5xx_stays_uncached(self, tmp_path):
        http = _StatusHttp(status=503)
        cache = JsonCache(root=tmp_path)
        client = MavenClient(http, cache=cache)
        assert client.get_pom("com.example:artifact", "1.2.3") is None
        assert client.get_pom("com.example:artifact", "1.2.3") is None
        assert len(http.request_calls) == 2, "transient 5xx was cached"


class TestNugetNuspec404NegativeCache:
    def test_404_is_negative_cached(self, tmp_path):
        http = _StatusHttp(status=404)
        cache = JsonCache(root=tmp_path)
        client = NugetClient(http, cache=cache)
        assert client.get_nuspec("Newtonsoft.Json", "1.0.0") is None
        assert client.get_nuspec("Newtonsoft.Json", "1.0.0") is None
        assert len(http.request_calls) == 1

    def test_defusedxml_missing_is_never_cached(self, tmp_path, monkeypatch):
        import packages.sca.registries.nuget as nuget_mod

        nuspec = (b"<?xml version='1.0'?><package><metadata>"
                  b"<id>P</id><version>1.0.0</version>"
                  b"</metadata></package>")
        http = _StatusHttp(status=200, content=nuspec)
        cache = JsonCache(root=tmp_path)
        client = NugetClient(http, cache=cache)

        monkeypatch.setattr(nuget_mod, "_DEFUSEDXML_AVAILABLE", False)
        assert client.get_nuspec("P", "1.0.0") is None

        # "Install defusedxml" — the next call must parse, not serve a
        # cached environment miss.
        monkeypatch.setattr(nuget_mod, "_DEFUSEDXML_AVAILABLE", True)
        assert client.get_nuspec("P", "1.0.0") is not None


class TestDebianSuiteCacheKey:
    def test_hostile_suite_does_not_raise_from_cache_layer(self, tmp_path):
        http = _JsonHttp({"result": []})
        cache = JsonCache(root=tmp_path)
        client = DebianClient(http, cache=cache)
        # Raw '..' in a hand-built key raised ValueError out of _query;
        # the injective builder percent-encodes it instead.
        assert client.versions_in_suite("zlib1g", "../escape") == []

    def test_distinct_suites_get_distinct_entries(self, tmp_path):
        cache = JsonCache(root=tmp_path)
        c1 = DebianClient(_JsonHttp({"result": [{"binaries": []}]}), cache=cache)
        c1.versions_in_suite("zlib1g", "suite\\a")
        http2 = _JsonHttp({"result": [{"binaries": []}]})
        c2 = DebianClient(http2, cache=cache)
        c2.versions_in_suite("zlib1g", "suite_a")
        # Pre-fix JsonCache's lossy '\\'->'_' mapping aliased the two
        # keys and the second call served the first suite's entry.
        assert len(http2.calls) == 1, "second suite served the first's cache entry"


class TestRubyGemsVersionKeyShape:
    def test_missing_version_yields_empty_releases_not_none_key(self, tmp_path):
        http = _JsonHttp({"name": "rack"})  # no "version" key
        cache = JsonCache(root=tmp_path)
        client = RubyGemsClient(http, cache=cache)
        first = client.get_metadata("rack")
        assert first is not None and first["releases"] == {}
        cached = client.get_metadata("rack")
        assert cached is not None
        assert cached["releases"] == first["releases"], (
            "shape changed between first call and cached call"
        )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
