from __future__ import annotations

import asyncio

import pytest

import hwatlib.plugins as plugins
import hwatlib.recon as recon
from hwatlib import config
from hwatlib.async_http import AsyncHttpClient
from hwatlib.exceptions import (
    ConfigError,
    DependencyError,
    HwatlibError,
    NetworkError,
    PluginError,
    RequestError,
    ScanError,
    TargetUnreachable,
)
from hwatlib.exploit import connect_remote
from hwatlib.http import HttpOptions


def test_hierarchy_relationships():
    assert issubclass(ConfigError, HwatlibError)
    assert issubclass(PluginError, HwatlibError)
    assert issubclass(NetworkError, HwatlibError)
    assert issubclass(TargetUnreachable, NetworkError)
    assert issubclass(RequestError, NetworkError)


def test_backwards_compatible_builtin_bases():
    # Old code catching the built-ins keeps working.
    assert issubclass(ConfigError, ValueError)
    assert issubclass(PluginError, ValueError)
    assert issubclass(DependencyError, RuntimeError)
    assert issubclass(ScanError, RuntimeError)
    assert issubclass(RequestError, RuntimeError)


def test_config_strict_raises_config_error(monkeypatch):
    monkeypatch.setenv("HWAT_TIMEOUT", "not-a-number")
    with pytest.raises(ConfigError):
        config.load_config(strict=True)
    # And still catchable as the historical ValueError.
    monkeypatch.setenv("HWAT_TIMEOUT", "not-a-number")
    with pytest.raises(ValueError):
        config.load_config(strict=True)


def test_plugin_error_types():
    with pytest.raises(PluginError):
        plugins.register_check("", lambda s: None)
    with pytest.raises(PluginError):
        plugins.load_check("no_colon")
    # HwatlibError catches it too.
    with pytest.raises(HwatlibError):
        plugins.load_check("os:sep")


def test_scan_error_on_bad_invocation():
    with pytest.raises(ScanError):
        recon._resolve_scan_target(target=None, session=None, caller="x")
    with pytest.raises(HwatlibError):
        recon.banner_grab()


def test_target_unreachable_on_connect_failure(monkeypatch):
    import hwatlib.exploit as exploit

    def boom(addr, timeout=None):
        raise OSError("connection refused")

    monkeypatch.setattr(exploit.socket, "create_connection", boom)
    with pytest.raises(TargetUnreachable):
        connect_remote("10.255.255.1", 9)
    # Also a NetworkError / HwatlibError.
    monkeypatch.setattr(exploit.socket, "create_connection", boom)
    with pytest.raises(NetworkError):
        connect_remote("10.255.255.1", 9)


def test_request_error_after_retries(monkeypatch):
    client = AsyncHttpClient(options=HttpOptions(retries=0, backoff_factor=0.0))

    async def fake_once(method, url, kwargs, *, proxy, auth):
        raise ConnectionError("boom")

    monkeypatch.setattr(client, "_request_once", fake_once)
    monkeypatch.setattr(client, "_ensure_session", lambda: None)
    with pytest.raises(RequestError):
        asyncio.run(client.get("http://x"))
    # Backwards-compatible with the old RuntimeError contract.
    monkeypatch.setattr(client, "_request_once", fake_once)
    monkeypatch.setattr(client, "_ensure_session", lambda: None)
    with pytest.raises(RuntimeError):
        asyncio.run(client.get("http://x"))
