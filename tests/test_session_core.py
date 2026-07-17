from __future__ import annotations

import hwatlib.session as session_mod
from hwatlib.http import HttpClient, HttpOptions
from hwatlib.session import HwatSession, new_session


def test_ensure_ip_caches_and_resolves(monkeypatch):
    calls = []

    def fake_resolve(target):
        calls.append(target)
        return "10.0.0.5"

    monkeypatch.setattr(session_mod, "resolve_host", fake_resolve)
    s = HwatSession(target="example.test")
    assert s.ensure_ip() == "10.0.0.5"
    # Second call is cached and does not resolve again.
    assert s.ensure_ip() == "10.0.0.5"
    assert calls == ["example.test"]


def test_ensure_ip_preexisting():
    s = HwatSession(target="example.test", ip="1.2.3.4")
    assert s.ensure_ip() == "1.2.3.4"


def test_ensure_http_creates_and_caches():
    s = HwatSession(target="example.test", http_options=HttpOptions(timeout=3.0))
    c1 = s.ensure_http()
    c2 = s.ensure_http()
    assert isinstance(c1, HttpClient)
    assert c1 is c2
    assert c1.options.timeout == 3.0


def test_ensure_base_url_defaults_to_http():
    s = HwatSession(target="example.test")
    assert s.ensure_base_url() == "http://example.test"


def test_ensure_base_url_preserves_scheme():
    s = HwatSession(target="https://example.test")
    assert s.ensure_base_url() == "https://example.test"


def test_ensure_base_url_cached():
    s = HwatSession(target="example.test", base_url="http://cached.test")
    assert s.ensure_base_url() == "http://cached.test"


def test_logger_property_returns_named_logger():
    s = HwatSession(target="x", logger_name="hwatlib.test")
    assert s.logger.name == "hwatlib.test"


def test_new_session_wires_http_and_base_url():
    s = new_session("example.test", base_url="http://x.test", http_options=HttpOptions(timeout=7.0))
    assert s.base_url == "http://x.test"
    assert s.http is not None
    assert s.http_options.timeout == 7.0
