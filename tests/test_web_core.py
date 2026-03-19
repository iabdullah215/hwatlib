from __future__ import annotations

import asyncio

import requests

import hwatlib.web as web


class _Resp:
    def __init__(self, text: str, headers: dict[str, str] | None = None, status_code: int = 200):
        self.text = text
        self.headers = headers or {}
        self.status_code = status_code


class _SyncSession:
    def __init__(self, html: str):
        self._html = html

    def get(self, _url: str, timeout: int = 5):
        return _Resp(self._html, headers={"Server": "unit-test"}, status_code=200)


class _AsyncClient:
    def __init__(self, html: str):
        self._html = html

    async def get(self, _url: str):
        return _Resp(self._html, headers={"Server": "unit-test"}, status_code=200)


def test_fetch_all_parses_forms_and_js(monkeypatch):
    html = """
    <html>
      <body>
        <form action="/login" method="post"><input name="u" type="text" /></form>
        <script src="/app.js"></script>
      </body>
    </html>
    """

    monkeypatch.setattr(web.requests, "Session", lambda: _SyncSession(html))

    out = web.fetch_all("https://example.test")

    assert out.headers.get("Server") == "unit-test"
    assert len(out.forms) == 1
    assert out.forms[0].action == "/login"
    assert out.js == ["https://example.test/app.js"]


def test_crawl_collect_tolerates_fetch_errors():
    pages = {
        "http://example.test/": '<a href="/ok">ok</a><a href="/err">err</a>',
        "http://example.test/ok": '<a href="/ok">self</a>',
    }

    def fetcher(url: str) -> str:
        if url.endswith("/err"):
            raise requests.RequestException("boom")
        return pages[url]

    out = web._crawl_collect("http://example.test", 2, fetcher)

    assert "http://example.test/ok" in out
    assert "http://example.test/err" in out


def test_fetch_all_async_matches_sync_shape(monkeypatch):
    html = '<form action="/x"></form><script src="/a.js"></script>'
    monkeypatch.setattr(web.requests, "Session", lambda: _SyncSession(html))

    sync_out = web.fetch_all("https://example.test").to_dict()
    async_out = asyncio.run(web.fetch_all_async("https://example.test", client=_AsyncClient(html))).to_dict()

    assert sync_out["headers"] == async_out["headers"]
    assert sync_out["js"] == async_out["js"]
    assert len(sync_out["forms"]) == len(async_out["forms"])


def test_crawl_collect_async_tolerates_fetch_errors():
    pages = {
        "http://example.test/": '<a href="/ok">ok</a><a href="/bad">bad</a>',
        "http://example.test/ok": "<html></html>",
    }

    async def fetcher(url: str) -> str:
        if url.endswith("/bad"):
            raise RuntimeError("fail")
        return pages[url]

    out = asyncio.run(web._crawl_collect_async("http://example.test", 2, fetcher, max_concurrency=5))

    assert "http://example.test/ok" in out
    assert "http://example.test/bad" in out
