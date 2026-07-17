from __future__ import annotations

import asyncio

import pytest

from hwatlib.async_http import AsyncHttpClient, AsyncResponse, _backoff_sleep
from hwatlib.http import HttpOptions


def _run(coro):
    return asyncio.run(coro)


def test_resolve_proxy_explicit_and_from_options():
    client = AsyncHttpClient(options=HttpOptions(proxies={"http": "http://p:8080"}))
    assert client._resolve_proxy("http://x", {"proxy": "http://explicit"}) == "http://explicit"
    assert client._resolve_proxy("http://x", {}) == "http://p:8080"
    assert client._resolve_proxy("https://x", {}) is None


def test_resolve_proxy_none_when_unset():
    client = AsyncHttpClient()
    assert client._resolve_proxy("http://x", {}) is None


def test_resolve_auth_variants():
    client = AsyncHttpClient(options=HttpOptions(auth=("u", "p")))
    assert client._resolve_auth({"auth": "explicit"}) == "explicit"
    ba = client._resolve_auth({})
    assert ba is not None  # aiohttp.BasicAuth instance
    client2 = AsyncHttpClient()
    assert client2._resolve_auth({}) is None


def test_backoff_sleep_zero(monkeypatch):
    slept = []

    async def fake_sleep(s):
        slept.append(s)

    monkeypatch.setattr("hwatlib.async_http.asyncio.sleep", fake_sleep)
    _run(_backoff_sleep(3, 0.0))
    assert slept == [0]


def test_backoff_sleep_bounded(monkeypatch):
    slept = []

    async def fake_sleep(s):
        slept.append(s)

    monkeypatch.setattr("hwatlib.async_http.asyncio.sleep", fake_sleep)
    _run(_backoff_sleep(10, 1.0))  # 1*2^10 = 1024 -> clamped to 10
    assert slept == [10.0]


def test_rate_limit_sleeps(monkeypatch):
    slept = []

    async def fake_sleep(s):
        slept.append(s)

    clock = {"t": 100.0}
    monkeypatch.setattr("hwatlib.async_http.time.time", lambda: clock["t"])
    monkeypatch.setattr("hwatlib.async_http.asyncio.sleep", fake_sleep)

    client = AsyncHttpClient(options=HttpOptions(rate_limit_per_sec=4.0))  # min interval 0.25

    async def go():
        await client._rate_limit()  # first, no sleep
        await client._rate_limit()  # immediate -> sleep ~0.25

    _run(go())
    assert slept and abs(slept[0] - 0.25) < 1e-6


def test_request_retries_on_forcelist(monkeypatch):
    client = AsyncHttpClient(options=HttpOptions(retries=2, backoff_factor=0.0, status_forcelist=(503,)))
    calls = {"n": 0}

    async def fake_once(method, url, kwargs, *, proxy, auth):
        calls["n"] += 1
        status = 503 if calls["n"] < 2 else 200
        return AsyncResponse(status=status, headers={}, text="", url=url)

    monkeypatch.setattr(client, "_request_once", fake_once)
    monkeypatch.setattr(client, "_ensure_session", lambda: None)
    out = _run(client.get("http://x"))
    assert out.status == 200
    assert calls["n"] == 2


def test_request_retries_on_exception_then_succeeds(monkeypatch):
    client = AsyncHttpClient(options=HttpOptions(retries=2, backoff_factor=0.0))
    calls = {"n": 0}

    async def fake_once(method, url, kwargs, *, proxy, auth):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("boom")
        return AsyncResponse(status=200, headers={}, text="ok", url=url)

    monkeypatch.setattr(client, "_request_once", fake_once)
    monkeypatch.setattr(client, "_ensure_session", lambda: None)
    out = _run(client.request("GET", "http://x"))
    assert out.text == "ok"


def test_request_exhausts_retries_raises(monkeypatch):
    client = AsyncHttpClient(options=HttpOptions(retries=1, backoff_factor=0.0))

    async def fake_once(method, url, kwargs, *, proxy, auth):
        raise ConnectionError("always")

    monkeypatch.setattr(client, "_request_once", fake_once)
    monkeypatch.setattr(client, "_ensure_session", lambda: None)
    with pytest.raises(RuntimeError):
        _run(client.head("http://x"))
