from __future__ import annotations

import hwatlib.dns as dns_mod

CRTSH_SAMPLE = [
    {"name_value": "www.example.com\n*.example.com"},
    {"name_value": "api.example.com"},
    {"common_name": "mail.example.com"},
    {"name_value": "example.com"},
    {"name_value": "evil.com"},              # out of scope
    {"name_value": "admin@example.com"},     # email address, skip
    "not-a-dict",                             # ignored
]


class _Resp:
    def __init__(self, data, *, boom=False):
        self._data = data
        self._boom = boom

    def json(self):
        if self._boom:
            raise ValueError("bad json")
        return self._data


class _Session:
    def __init__(self, resp):
        self._resp = resp
        self.call = None

    def get(self, url, params=None, timeout=None):
        self.call = (url, params, timeout)
        return self._resp


def test_parse_crtsh_names_filters_and_dedupes():
    names = dns_mod._parse_crtsh_names(CRTSH_SAMPLE, "example.com")
    assert names == ["api.example.com", "example.com", "mail.example.com", "www.example.com"]


def test_parse_crtsh_names_non_list():
    assert dns_mod._parse_crtsh_names({"x": 1}, "example.com") == []


def test_discover_subdomains_passive_success():
    session = _Session(_Resp(CRTSH_SAMPLE))
    out = dns_mod.discover_subdomains_passive("example.com", session=session)
    assert "api.example.com" in out
    assert "evil.com" not in out
    assert session.call[0] == "https://crt.sh/"
    assert session.call[1] == {"q": "%.example.com", "output": "json"}


def test_discover_subdomains_passive_network_error():
    class _Boom:
        def get(self, url, params=None, timeout=None):
            raise dns_mod.requests.RequestException("dead")

    assert dns_mod.discover_subdomains_passive("example.com", session=_Boom()) == []


def test_discover_subdomains_passive_bad_json():
    session = _Session(_Resp(None, boom=True))
    assert dns_mod.discover_subdomains_passive("example.com", session=session) == []


def test_enumerate_subdomains_merges_active_and_passive(monkeypatch):
    session = _Session(_Resp(CRTSH_SAMPLE))
    # Active brute resolves 'www' via the wordlist path.
    monkeypatch.setattr(dns_mod, "resolve_host", lambda name: "1.2.3.4" if name.startswith("www") else None)

    out = dns_mod.enumerate_subdomains(
        "example.com", words=["www"], passive=True, resolve=True, session=session
    )
    # Active discovery resolved www.example.com to an IP.
    assert out["www.example.com"] == "1.2.3.4"
    # Passive discovery added names (resolved to None here since resolve_host returns None).
    assert "api.example.com" in out
    assert out["api.example.com"] is None


def test_enumerate_subdomains_passive_disabled(monkeypatch):
    monkeypatch.setattr(dns_mod, "resolve_host", lambda name: "9.9.9.9")
    out = dns_mod.enumerate_subdomains("example.com", words=["www"], passive=False)
    assert out == {"www.example.com": "9.9.9.9"}


def test_enumerate_subdomains_no_resolve(monkeypatch):
    session = _Session(_Resp([{"name_value": "api.example.com"}]))
    out = dns_mod.enumerate_subdomains("example.com", passive=True, resolve=False, session=session)
    assert out == {"api.example.com": None}
