from __future__ import annotations

import sys
import types

import pytest

from hwatlib.findings import Finding
from hwatlib.plugins import load_check, register_check, run_checks
from hwatlib.session import new_session


def test_load_check_requires_module_function_spec():
    with pytest.raises(ValueError):
        load_check("not_a_spec")


def test_run_checks_allows_module_function_spec_via_sys_modules():
    mod = types.ModuleType("fake_plugin_mod")

    def check(session):
        return {"target": session.target, "ok": True}

    mod.check = check
    sys.modules["fake_plugin_mod"] = mod

    s = new_session("example.com")
    results = run_checks(s, names=["fake_plugin_mod:check"])

    assert "fake_plugin_mod:check" in results
    assert results["fake_plugin_mod:check"].ok is True
    assert results["fake_plugin_mod:check"].result["target"] == "example.com"


def test_run_checks_default_enabled_only_when_names_is_none(monkeypatch):
    import hwatlib.plugins as plugins

    # Isolate registry for test
    monkeypatch.setattr(plugins, "_registry", {})

    def a(session):
        return {"ok": True}

    def b(session):
        return {"ok": True}

    register_check("a", a, default_enabled=True)
    register_check("b", b, default_enabled=False)

    s = new_session("example.com")
    results = run_checks(s, names=None)

    assert "a" in results
    assert "b" not in results


def test_plugin_result_extracts_findings_from_return_value(monkeypatch):
    import hwatlib.plugins as plugins

    monkeypatch.setattr(plugins, "_registry", {})

    def check(session):
        return Finding(category="web", title="Test", severity="low")

    register_check("f", check, default_enabled=True)
    s = new_session("example.com")
    res = run_checks(s, names=None)["f"]

    assert res.ok is True
    assert len(res.findings) == 1
    assert res.findings[0].category == "web"
