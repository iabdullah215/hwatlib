from __future__ import annotations

import asyncio

import pytest

import hwatlib.plugins as plugins
from hwatlib.session import HwatSession


@pytest.fixture(autouse=True)
def _clean_registry():
    saved = dict(plugins._registry)
    plugins._registry.clear()
    try:
        yield
    finally:
        plugins._registry.clear()
        plugins._registry.update(saved)


def _session():
    return HwatSession(target="example.test")


# --- async plugin hooks ---

def test_run_checks_async_runs_sync_and_async():
    async def acheck(session):
        await asyncio.sleep(0)
        return {"category": "c", "title": "a", "severity": "high"}

    def scheck(session):
        return {"category": "c", "title": "s", "severity": "low"}

    plugins.register_check("a", acheck)
    plugins.register_check("s", scheck)

    results = asyncio.run(plugins.run_checks_async(_session(), names=["a", "s"]))
    assert results["a"].ok and results["a"].findings[0].title == "a"
    assert results["s"].ok and results["s"].findings[0].title == "s"


def test_run_checks_sync_path_handles_async_check():
    async def acheck(session):
        return {"category": "c", "title": "a", "severity": "high"}

    plugins.register_check("a", acheck)
    results = plugins.run_checks(_session(), names=["a"])
    assert results["a"].ok
    assert results["a"].findings[0].title == "a"


def test_run_checks_async_captures_errors():
    async def boom(session):
        raise RuntimeError("async failed")

    plugins.register_check("boom", boom)
    results = asyncio.run(plugins.run_checks_async(_session(), names=["boom"]))
    assert results["boom"].ok is False
    assert "async failed" in results["boom"].error


def test_run_checks_async_missing_plugin():
    results = asyncio.run(plugins.run_checks_async(_session(), names=["missing:thing"]))
    assert results["missing:thing"].ok is False


def test_run_checks_async_concurrency_bound():
    async def slow(session):
        await asyncio.sleep(0.01)
        return None

    for i in range(5):
        plugins.register_check(f"p{i}", slow, default_enabled=True)
    results = asyncio.run(plugins.run_checks_async(_session(), max_concurrency=2))
    assert len(results) == 5
    assert all(r.ok for r in results.values())


# --- plugin_check decorator ---

def test_plugin_check_decorator_attaches_meta():
    @plugins.plugin_check("named", description="d", severity="high", default_enabled=True, tags=["t"])
    def check(session):
        return None

    assert check._hwat_meta["name"] == "named"
    assert check._hwat_meta["severity"] == "high"
    assert check._hwat_meta["default_enabled"] is True
    assert check._hwat_meta["tags"] == ("t",)


# --- entry-point discovery ---

class _FakeEP:
    def __init__(self, name, obj, *, boom=False):
        self.name = name
        self._obj = obj
        self._boom = boom

    def load(self):
        if self._boom:
            raise ImportError("cannot import")
        return self._obj


def test_discover_plugins_registers_by_entry_point_name(monkeypatch):
    def plain_check(session):
        return {"category": "c", "title": "t", "severity": "low"}

    monkeypatch.setattr(plugins, "_iter_entry_points", lambda group: [_FakeEP("ep_check", plain_check)])
    discovered = plugins.discover_plugins()
    assert "ep_check" in discovered
    # Now runnable by short name without --plugin module:func.
    results = plugins.run_checks(_session(), names=["ep_check"])
    assert results["ep_check"].ok


def test_discover_plugins_uses_decorator_metadata(monkeypatch):
    @plugins.plugin_check("fancy", severity="critical", default_enabled=True)
    def check(session):
        return None

    monkeypatch.setattr(plugins, "_iter_entry_points", lambda group: [_FakeEP("ep_name", check)])
    discovered = plugins.discover_plugins()
    # Registered under the decorator name, not the entry-point name.
    assert "fancy" in discovered
    assert discovered["fancy"].severity == "critical"
    assert discovered["fancy"].default_enabled is True
    # default_enabled plugin runs when names is None.
    results = plugins.run_checks(_session())
    assert "fancy" in results


def test_discover_plugins_skips_broken_and_non_callable(monkeypatch):
    monkeypatch.setattr(
        plugins, "_iter_entry_points",
        lambda group: [_FakeEP("broken", None, boom=True), _FakeEP("not_callable", 42)],
    )
    discovered = plugins.discover_plugins()
    assert discovered == {}
