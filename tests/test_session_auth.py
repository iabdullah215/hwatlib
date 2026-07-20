from __future__ import annotations

import requests

from hwatlib.http import HttpClient
from hwatlib.session import new_session


class _FakeSession:
    def __init__(self):
        self.headers = {}
        self.cookies = requests.cookies.RequestsCookieJar()
        self.proxies = {}
        self.requests = []

    def mount(self, *a):
        pass

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))

        class _R:
            status_code = 200

        # Simulate the server issuing a session cookie on login.
        if url.endswith("/login"):
            self.cookies.set("sessionid", "SECRET")
        return _R()


def _session_with_fake():
    s = new_session("example.test")
    s.http = HttpClient(options=s.http_options, session=_FakeSession())
    return s


def test_set_headers_updates_options_and_live_client():
    s = _session_with_fake()
    s.set_headers({"X-API-Key": "k1"})
    assert s.http_options.headers["X-API-Key"] == "k1"
    assert s.http.session.headers["X-API-Key"] == "k1"


def test_set_headers_before_client_created():
    s = new_session("example.test")
    # Force no client yet.
    s.http = None
    s.set_headers({"X-Test": "v"})
    assert s.http_options.headers["X-Test"] == "v"
    # New client picks it up from options at creation.
    assert s.ensure_http().session.headers["X-Test"] == "v"


def test_set_bearer_token():
    s = _session_with_fake()
    s.set_bearer_token("tok")
    assert s.http.session.headers["Authorization"] == "Bearer tok"


def test_set_cookies():
    s = _session_with_fake()
    s.set_cookies({"visited": "1"})
    assert s.http_options.cookies["visited"] == "1"
    assert "visited" in s.current_cookies()


def test_set_basic_auth_propagates_to_client():
    s = _session_with_fake()
    s.set_basic_auth("user", "pass")
    assert s.http_options.auth == ("user", "pass")
    assert s.http.options.auth == ("user", "pass")


def test_login_form_persists_cookies():
    s = _session_with_fake()
    ok = s.login_form("http://example.test/login", {"user": "a", "pass": "b"})
    assert ok is True
    assert s.current_cookies().get("sessionid") == "SECRET"
    method, url, kwargs = s.http.session.requests[0]
    assert method == "POST"
    assert kwargs["data"] == {"user": "a", "pass": "b"}


def test_login_form_custom_success_check():
    s = _session_with_fake()
    ok = s.login_form(
        "http://example.test/login",
        {"u": "a"},
        success_check=lambda r: r.status_code == 201,
    )
    assert ok is False  # fake returns 200, check wants 201


def test_fluent_chaining():
    s = _session_with_fake()
    result = s.set_headers({"A": "1"}).set_bearer_token("t").set_cookies({"c": "2"})
    assert result is s
    assert s.http.session.headers["A"] == "1"
    assert s.http.session.headers["Authorization"] == "Bearer t"


def test_current_cookies_without_client():
    s = new_session("example.test")
    s.http = None
    s.set_cookies({"seed": "x"})
    assert s.current_cookies() == {"seed": "x"}
