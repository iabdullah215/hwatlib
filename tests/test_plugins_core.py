from __future__ import annotations

import pytest

import hwatlib.plugins as plugins
from hwatlib.findings import Finding
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


def test_register_and_list_checks():
    plugins.register_check("c1", lambda s: {"x": 1}, description="d", default_enabled=True)
    metas = plugins.list_checks()
    assert "c1" in metas
    assert metas["c1"].description == "d"


def test_register_check_validates():
    with pytest.raises(ValueError):
        plugins.register_check("", lambda s: None)
    with pytest.raises(ValueError):
        plugins.register_check("x", "not callable")  # type: ignore[arg-type]


def test_load_check_requires_colon():
    with pytest.raises(ValueError):
        plugins.load_check("no_colon")


def test_load_check_imports_callable():
    fn = plugins.load_check("hwatlib.postex:pretty_report")
    assert callable(fn)


def test_load_check_non_callable():
    # os.sep is a stable, always-importable non-callable attribute.
    with pytest.raises(ValueError):
        plugins.load_check("os:sep")


def test_run_checks_default_enabled_only():
    plugins.register_check("on", lambda s: {"ok": 1}, default_enabled=True)
    plugins.register_check("off", lambda s: {"ok": 0}, default_enabled=False)
    results = plugins.run_checks(_session())
    assert set(results) == {"on"}
    assert results["on"].ok is True


def test_run_checks_named_and_missing():
    plugins.register_check("known", lambda s: [], default_enabled=False)
    results = plugins.run_checks(_session(), names=["known", "missing:plugin"])
    assert results["known"].ok is True
    assert results["missing:plugin"].ok is False


def test_run_one_captures_exception():
    def boom(s):
        raise RuntimeError("plugin failed")

    plugins.register_check("bad", boom, default_enabled=True)
    results = plugins.run_checks(_session())
    assert results["bad"].ok is False
    assert "plugin failed" in results["bad"].error


def test_normalize_findings_variants():
    f = Finding(category="c", title="t", severity="high")
    assert plugins._normalize_findings(f) == [f]
    d = {"category": "c", "title": "t", "severity": "low"}
    assert plugins._normalize_findings(d)[0].category == "c"
    mixed = [f, d, "junk", {"nope": 1}]
    out = plugins._normalize_findings(mixed)
    assert len(out) == 2
    assert plugins._normalize_findings(42) == []


def test_plugin_result_to_dict():
    plugins.register_check(
        "fnd",
        lambda s: {"category": "c", "title": "t", "severity": "medium", "evidence": {"k": "v"}},
        default_enabled=True,
        output_schema="findings",
    )
    result = plugins.run_checks(_session())["fnd"]
    d = result.to_dict()
    assert d["ok"] is True
    assert d["findings"][0]["category"] == "c"
    assert d["findings"][0]["evidence"] == {"k": "v"}
