from __future__ import annotations

from hwatlib import workflows
from hwatlib.workflows import (
    _dedupe_findings,
    _extract_plugin_findings,
    _looks_like_ip,
    _merge_findings,
)


def test_looks_like_ip():
    assert _looks_like_ip("10.0.0.1") is True
    assert _looks_like_ip("255.255.255.255") is True
    assert _looks_like_ip("256.0.0.1") is False
    assert _looks_like_ip("example.com") is False
    assert _looks_like_ip("1.2.3") is False


def test_extract_plugin_findings_filters_malformed():
    section = {
        "good": {"findings": [{"category": "c", "title": "t", "severity": "high"}]},
        "bad_payload": "not a dict",
        "no_findings": {"other": 1},
        "findings_not_list": {"findings": "nope"},
        "nested_non_dict": {"findings": ["str", {"category": "d", "title": "e", "severity": "low"}]},
    }
    out = _extract_plugin_findings(section)
    titles = {f["title"] for f in out}
    assert titles == {"t", "e"}


def test_extract_plugin_findings_non_dict_returns_empty():
    assert _extract_plugin_findings("nope") == []


def test_dedupe_findings_by_category_title_severity():
    findings = [
        {"category": "a", "title": "t", "severity": "high"},
        {"category": "a", "title": "t", "severity": "high"},  # dup
        {"category": "a", "title": "t", "severity": "low"},  # different severity
    ]
    out = _dedupe_findings(findings)
    assert len(out) == 2


def test_merge_findings_combines_and_dedupes():
    risk = [{"category": "r", "title": "x", "severity": "medium"}]
    plugins = {"p": {"findings": [{"category": "r", "title": "x", "severity": "medium"}, {"category": "p", "title": "y", "severity": "low"}]}}
    out = _merge_findings(risk, plugins)
    assert len(out) == 2


def test_add_risk_populates_metadata():
    report = workflows.new_report(target="example.test")
    workflows._add_risk(report)
    assert "risk" in report.metadata
    assert "score" in report.metadata["risk"]
    assert "level" in report.metadata["risk"]
    assert isinstance(report.metadata["findings"], list)


def test_build_report_ip_target_no_nmap(monkeypatch):
    # For an IP target with nmap off, DNS is skipped and no network scans run.
    # Stub the phases that would touch the system/network.
    real_risk_score = workflows.privesc_mod.risk_score
    monkeypatch.setattr(workflows.privesc_mod, "run_checks", lambda: {})
    monkeypatch.setattr(workflows.privesc_mod, "risk_score", lambda raw: real_risk_score({}))
    monkeypatch.setattr(workflows.web_mod, "scan", lambda *a, **k: workflows.WebResult(ok=True))
    monkeypatch.setattr(workflows.fp, "fingerprint_service", lambda ip, port: {"service": "unknown"})

    report = workflows.build_report(target="10.0.0.1", url=None, nmap=False)
    assert report.recon.target == "10.0.0.1"
    assert report.recon.ok is True
    assert "risk" in report.metadata
    assert report.metadata["target"] == "10.0.0.1"
