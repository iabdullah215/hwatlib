from __future__ import annotations

import hwatlib.web as web
from hwatlib.web import (
    WebScanner,
    _cookie_names,
    _tech_from_headers,
    _tech_hints,
    export_sitemap_csv,
    export_sitemap_json,
    fetch_all,
    fetch_forms_http,
    fetch_headers_http,
    fetch_js_http,
    fingerprint_tech,
    scan,
)


class _Resp:
    def __init__(self, text="", headers=None, status_code=200):
        self.text = text
        self.headers = headers or {}
        self.status_code = status_code


class _FakeClient:
    """Minimal HttpClient stand-in returning a fixed response."""

    def __init__(self, resp):
        self._resp = resp
        self.urls = []

    def get(self, url, timeout=5):
        self.urls.append(url)
        return self._resp


PAGE = """
<html><head>
  <script src="/static/app.js"></script>
</head><body>
  <form action="/login" method="POST"><input name="user"/><input name="pw" type="password"/></form>
  <a href="/about">about</a>
</body></html>
"""


def test_fetch_headers_http():
    client = _FakeClient(_Resp(headers={"Server": "nginx"}))
    assert fetch_headers_http("example.test", client=client) == {"Server": "nginx"}
    assert client.urls == ["http://example.test"]


def test_fetch_forms_http_parses_form():
    client = _FakeClient(_Resp(text=PAGE))
    forms = fetch_forms_http("http://example.test", client=client)
    assert len(forms) == 1
    assert forms[0].action == "/login"
    assert forms[0].method == "POST"
    names = {f.name for f in forms[0].inputs}
    assert {"user", "pw"} <= names


def test_fetch_js_http_absolutizes():
    client = _FakeClient(_Resp(text=PAGE))
    js = fetch_js_http("http://example.test", client=client)
    assert js == ["http://example.test/static/app.js"]


def test_fetch_all_with_client_builds_result():
    client = _FakeClient(_Resp(text=PAGE, headers={"Server": "x"}))
    out = fetch_all("http://example.test", client=client)
    assert out.headers == {"Server": "x"}
    assert len(out.forms) == 1
    assert out.js == ["http://example.test/static/app.js"]


def test_fingerprint_tech_detects_from_headers_and_body():
    body = "<html>wp-content/themes ... csrfmiddlewaretoken ...</html>"
    client = _FakeClient(
        _Resp(text=body, headers={"Server": "nginx", "X-Powered-By": "PHP/8", "Set-Cookie": "sid=1; Path=/"})
    )
    tech = fingerprint_tech("http://example.test", client=client)
    assert tech.ok is True
    assert tech.server == "nginx"
    assert "wordpress" in tech.hints
    assert "django" in tech.hints
    assert "nginx" in tech.hints
    assert "php" in tech.hints
    assert tech.cookies == ["sid"]


def test_fingerprint_tech_handles_request_error():
    class _Boom:
        def get(self, url, timeout=5):
            raise web.requests.RequestException("dead")

    tech = fingerprint_tech("http://example.test", client=_Boom())
    assert tech.ok is False
    assert "dead" in (tech.error or "")


def test_scan_aggregates(monkeypatch):
    # crawl issues its own requests; stub _fetch_text so scan stays hermetic.
    monkeypatch.setattr(web, "_fetch_text", lambda *a, **k: None)
    client = _FakeClient(_Resp(text=PAGE, headers={"Server": "nginx"}))
    result = scan("http://example.test", client=client, depth=1)
    assert result.ok is True
    assert result.fetch is not None
    assert result.tech is not None
    assert result.sitemap is not None


def test_cookie_names_parsing():
    assert _cookie_names("a=1; Path=/, b=2; Secure") == ["a", "b"]
    assert _cookie_names("") == []


def test_tech_from_headers_variants():
    out = _tech_from_headers({"server": "Apache/2.4", "x-powered-by": "Express"})
    assert "apache" in out
    assert "express" in out


def test_tech_hints_dedupes_and_sorts():
    hints = _tech_hints(headers={"server": "nginx"}, body="wp-content laravel")
    assert hints == sorted(set(hints))
    assert "wordpress" in hints and "laravel" in hints and "nginx" in hints


def test_export_sitemap_json_and_csv(tmp_path):
    links = ["http://a.test/1", "http://a.test/2"]
    jp = tmp_path / "s.json"
    cp = tmp_path / "sub" / "s.csv"
    export_sitemap_json("http://a.test", links, str(jp))
    export_sitemap_csv("http://a.test", links, str(cp))

    import json

    data = json.loads(jp.read_text())
    assert data["count"] == 2
    assert data["links"] == links
    csv_text = cp.read_text()
    assert "http://a.test/1" in csv_text
    assert "http://a.test/2" in csv_text


def test_webscanner_crawl_follows_in_scope_links(monkeypatch):
    pages = {
        "http://site.test": '<a href="/a">a</a><a href="http://other.test/x">off</a>',
        "http://site.test/a": '<a href="/b">b</a>',
        "http://site.test/b": "<html></html>",
    }

    class _Sess:
        def get(self, url, timeout=5):
            return _Resp(text=pages.get(url, ""))

    sc = WebScanner("site.test")
    sc.session = _Sess()
    sc.crawl(depth=3)
    # In-scope links are collected; the off-domain link is not recursed into.
    assert "http://site.test/a" in sc.found_links
    assert "http://site.test/b" in sc.found_links


def test_webscanner_dir_bruteforce_no_wordlist_is_noop():
    sc = WebScanner("site.test")
    # No wordlist -> returns without error.
    assert sc.dir_bruteforce() is None
