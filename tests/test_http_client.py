from __future__ import annotations

import hwatlib.http as http_mod
from hwatlib.http import HttpClient, HttpOptions


class _FakeSession:
    def __init__(self):
        self.headers = {}
        self.cookies = {}
        self.proxies = {}
        self.mounted = {}
        self.calls = []

    def update_dictlike(self):  # pragma: no cover - unused helper
        pass

    def mount(self, prefix, adapter):
        self.mounted[prefix] = adapter

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return {"method": method, "url": url, "kwargs": kwargs}


def _client(**opts):
    session = _FakeSession()
    # requests.Session().headers is a dict-like; our fake uses plain dicts,
    # and .update() works on them the same way.
    return HttpClient(options=HttpOptions(**opts), session=session), session


def test_applies_headers_cookies_proxies():
    client, session = _client(
        headers={"User-Agent": "hwatlib"},
        cookies={"sid": "abc"},
        proxies={"http": "http://127.0.0.1:8080"},
    )
    assert session.headers["User-Agent"] == "hwatlib"
    assert session.cookies["sid"] == "abc"
    assert session.proxies["http"] == "http://127.0.0.1:8080"


def test_mounts_retry_adapters():
    _c, session = _client(retries=3)
    assert "http://" in session.mounted
    assert "https://" in session.mounted


def test_request_passes_timeout_and_verify_defaults():
    client, session = _client(timeout=9.0, verify=False)
    client.get("http://example.test")
    method, url, kwargs = session.calls[0]
    assert method == "GET"
    assert url == "http://example.test"
    assert kwargs["timeout"] == 9.0
    assert kwargs["verify"] is False


def test_request_kwargs_override_options():
    client, session = _client(timeout=9.0)
    client.request("POST", "http://example.test", timeout=1.0, verify=True, json={"a": 1})
    _method, _url, kwargs = session.calls[0]
    assert kwargs["timeout"] == 1.0
    assert kwargs["json"] == {"a": 1}


def test_head_uses_head_method():
    client, session = _client()
    client.head("http://example.test")
    assert session.calls[0][0] == "HEAD"


def test_rate_limit_sleeps_between_requests(monkeypatch):
    sleeps = []
    clock = {"t": 1000.0}
    monkeypatch.setattr(http_mod.time, "time", lambda: clock["t"])
    monkeypatch.setattr(http_mod.time, "sleep", lambda s: sleeps.append(s))

    client, _session = _client(rate_limit_per_sec=2.0)  # min interval 0.5s
    client.get("http://example.test")  # first call: no sleep
    client.get("http://example.test")  # second call: immediate -> should sleep ~0.5
    assert sleeps and abs(sleeps[0] - 0.5) < 1e-6


def test_rate_limit_disabled_when_unset(monkeypatch):
    sleeps = []
    monkeypatch.setattr(http_mod.time, "sleep", lambda s: sleeps.append(s))
    client, _session = _client()  # rate_limit_per_sec is None
    client.get("http://example.test")
    client.get("http://example.test")
    assert sleeps == []


def test_suppress_insecure_warning_path_is_safe():
    # verify=False + suppress flag should not raise even though it touches urllib3.
    client, session = _client(verify=False, suppress_insecure_warning=True)
    client.get("http://example.test")
    assert session.calls[0][2]["verify"] is False
