from __future__ import annotations

import asyncio

import hwatlib.web as web
from hwatlib.web import (
    WebScanner,
    crawl,
    crawl_dict,
    discover_sitemaps,
    fetch_forms,
    fetch_headers,
    fetch_js,
    fingerprint_tech,
)


class _Resp:
    def __init__(self, text="", headers=None, status_code=200):
        self.text = text
        self.headers = headers or {}
        self.status_code = status_code


class _Sess:
    def __init__(self, resp):
        self._resp = resp
        self.urls = []

    def get(self, url, timeout=5):
        self.urls.append(url)
        return self._resp


PAGE = '<form action="/a" method="get"><input name="x"/></form><script src="/s.js"></script>'


def test_fetch_headers_session():
    out = fetch_headers("example.test", session=_Sess(_Resp(headers={"Server": "s"})))
    assert out == {"Server": "s"}


def test_fetch_forms_session():
    forms = fetch_forms("http://example.test", session=_Sess(_Resp(text=PAGE)))
    assert forms[0].action == "/a"
    assert forms[0].method == "GET"


def test_fetch_js_session():
    js = fetch_js("http://example.test", session=_Sess(_Resp(text=PAGE)))
    assert js == ["http://example.test/s.js"]


def test_fingerprint_tech_no_client(monkeypatch):
    monkeypatch.setattr(
        web.requests, "get",
        lambda url, timeout=5: _Resp(headers={"Server": "nginx"}, text="wp-content"),
    )
    tech = fingerprint_tech("http://example.test")
    assert tech.ok is True
    assert "nginx" in tech.hints
    assert "wordpress" in tech.hints


def test_scanner_dir_bruteforce(monkeypatch, tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\nlogin\n")
    sc = WebScanner("site.test", wordlist=str(wl))
    hits = {"http://site.test/admin": 200, "http://site.test/login": 404}
    sc.session = _Sess(None)
    sc.session.get = lambda url, timeout=3: _Resp(status_code=hits.get(url, 404))
    # Should iterate without raising.
    assert sc.dir_bruteforce() is None


def test_scanner_param_discovery():
    sc = WebScanner("site.test")
    sc.session = _Sess(_Resp(text="body", status_code=200))
    assert sc.param_discovery(["id", "q"]) is None


def test_scanner_analyze_headers():
    sc = WebScanner("site.test")
    sc.session = _Sess(_Resp(headers={"X-Frame-Options": "DENY"}))
    assert sc.analyze_headers() is None


def test_scanner_vuln_checks_reflect():
    sc = WebScanner("site.test")
    # XSS reflects payload; SQLi surfaces an error string; LFI leaks /etc/passwd.
    sc.session = _Sess(_Resp(text="<script>alert(1)</script> SQL syntax error root:x:0:0"))
    assert sc.check_xss("q") is None
    assert sc.check_sqli("id") is None
    assert sc.check_lfi("file") is None


def test_crawl_functional(monkeypatch):
    pages = {
        "http://site.test": '<a href="/a">a</a>',
        "http://site.test/a": "<html></html>",
    }
    monkeypatch.setattr(web, "_fetch_text", lambda url, **k: pages.get(url, ""))
    monkeypatch.setattr(web, "discover_sitemaps", lambda *a, **k: web.SitemapDiscovery(
        robots_url="", sitemap_xml_url="", robots_sitemaps=[], sitemap_xml_locs=[]
    ))
    result = crawl("http://site.test", depth=2)
    assert result.base == "http://site.test"
    d = crawl_dict("http://site.test", depth=1)
    assert "links" in d


def test_discover_sitemaps(monkeypatch):
    def fake_fetch(url, **k):
        if url.endswith("robots.txt"):
            return "Sitemap: https://site.test/sitemap.xml"
        if url.endswith("sitemap.xml"):
            return '<urlset><url><loc>https://site.test/a</loc></url></urlset>'
        return None

    monkeypatch.setattr(web, "_fetch_text", fake_fetch)
    out = discover_sitemaps("https://site.test")
    assert "https://site.test/sitemap.xml" in out.robots_sitemaps
    assert any("site.test/a" in u for u in out.sitemap_xml_locs)


def test_async_fetch_and_fingerprint():
    class _AsyncClient:
        async def get(self, url):
            return _Resp(text="wp-content laravel", headers={"Server": "nginx"})

    fetched = asyncio.run(web.fetch_all_async("http://x.test", client=_AsyncClient()))
    assert fetched.headers["Server"] == "nginx"

    tech = asyncio.run(web.fingerprint_tech_async("http://x.test", client=_AsyncClient()))
    assert "wordpress" in tech.hints and "laravel" in tech.hints


def test_async_fingerprint_error():
    class _Boom:
        async def get(self, url):
            raise RuntimeError("dead")

    tech = asyncio.run(web.fingerprint_tech_async("http://x.test", client=_Boom()))
    assert tech.ok is False


def test_scan_async(monkeypatch):
    class _AsyncClient:
        async def get(self, url):
            return _Resp(text=PAGE, headers={"Server": "nginx"})

    async def fake_crawl_async(base, *, depth, client):
        return web.CrawlResult(base=base, count=0, links=[], sitemaps=None)

    monkeypatch.setattr(web, "crawl_async", fake_crawl_async)
    result = asyncio.run(web.scan_async("http://x.test", client=_AsyncClient(), depth=1))
    assert result.ok is True
