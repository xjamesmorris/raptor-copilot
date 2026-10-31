"""Semantics of the shared origin primitive and its six consumers.

Origin comparison is the package's core scope-containment check; the
point of consolidating the hand-rolled copies is that these properties
hold identically everywhere.
"""

from __future__ import annotations

import pytest

from packages.web.origin import origin_of


class TestOriginOf:
    def test_default_ports_normalize(self):
        assert origin_of("https://host/x") == ("https", "host", 443)
        assert origin_of("http://host/x") == ("http", "host", 80)
        assert origin_of("https://host:443/") == origin_of("https://host/")
        assert origin_of("http://host:80/") == origin_of("http://host/")

    def test_scheme_and_host_are_case_insensitive(self):
        assert origin_of("HTTPS://HOST.Example/") == ("https", "host.example", 443)

    def test_explicit_port_zero_is_not_the_default_port(self):
        # Port 0 is falsy but is NOT the default port: https://host:0/
        # must not compare equal to the default-port origin.
        assert origin_of("https://host:0/") == ("https", "host", 0)
        assert origin_of("https://host:0/") != origin_of("https://host/")
        assert origin_of("http://host:0/") != origin_of("http://host/")

    def test_invalid_port_never_matches_and_never_raises(self):
        # Hostile crawled anchor: urlparse defers the ValueError to
        # .port access — the primitive must classify, not raise.
        assert origin_of("http://h:99999/x")[2] == -1
        assert origin_of("http://h:99999/x") != origin_of("http://h/x")

    def test_missing_host_yields_empty_hostname(self):
        assert origin_of("not a url")[1] == ""

    def test_scheme_map_folds_before_default_port(self):
        ws_map = {"ws": "http", "wss": "https"}
        assert origin_of("wss://host/socket", scheme_map=ws_map) == (
            "https", "host", 443,
        )
        assert origin_of("ws://host/socket", scheme_map=ws_map) == (
            "http", "host", 80,
        )


class TestConsumersAgree:
    """Every consumer shares one semantics — no more port-0 drift."""

    def test_client_scope_rejects_port_zero_alias(self):
        pytest.importorskip("requests")
        from packages.web.client import WebClient

        client = WebClient("https://t.example")
        assert not client._is_in_scope("https://t.example:0/path")
        assert client._is_in_scope("https://t.example:443/path")

    def test_ffuf_origin_matches_shared_semantics(self):
        from pathlib import Path

        from packages.web.ffuf import FfufRunner

        runner = FfufRunner("https://t.example", Path("/tmp"))
        assert runner._origin("https://t.example:0/") == ("https", "t.example", 0)
        assert runner._origin("http://h:99999/x")[2] == -1

    def test_discovery_helpers_match_shared_semantics(self):
        from packages.web.discovery.js_routes import _origin as js_origin
        from packages.web.discovery.sitemap import _origin as sm_origin

        for helper in (js_origin, sm_origin):
            assert helper("https://t.example:0/") != helper("https://t.example/")
            assert helper("http://h:99999/x")[2] == -1

    def test_execution_policy_keeps_loud_denials(self):
        from packages.web.execution_policy import WebPolicyError, _origin

        assert _origin("https://t.example:0/") == ("https", "t.example", 0)
        with pytest.raises(WebPolicyError):
            _origin("/relative/only")
        with pytest.raises(WebPolicyError):
            _origin("http://h:99999/x")

    def test_browser_gate_matches_shared_semantics(self):
        from packages.web.browser import BrowserEngine

        norm = BrowserEngine._normalized_origin
        assert norm("https://t.example:0/") != norm("https://t.example/")
        assert norm(
            "wss://t.example/s", scheme_map={"ws": "http", "wss": "https"},
        ) == ("https", "t.example", 443)
