from __future__ import annotations

from hwatlib.report import HwatReport, _group_by_severity


def _report():
    return HwatReport(metadata={
        "target": "example.com",
        "generated_at": "2026-07-20T00:00:00Z",
        "run_id": "report-abc",
        "risk": {"score": 65, "level": "high"},
        "findings": [
            {"category": "secrets", "title": "Secret found", "severity": "high",
             "evidence": {"max_risk": 9}, "recommendation": "Rotate creds"},
            {"category": "web", "title": "Tech hints", "severity": "info",
             "evidence": {"hints": ["nginx"]}},
            {"category": "recon", "title": "TLS verify failed", "severity": "low"},
            {"category": "x", "title": "Another high", "severity": "high"},
        ],
    })


def test_group_by_severity_orders_and_buckets():
    findings = _report().metadata["findings"]
    groups = _group_by_severity(findings)
    assert len(groups["high"]) == 2
    assert len(groups["low"]) == 1
    assert len(groups["info"]) == 1
    assert groups["critical"] == []


def test_to_html_basic_structure():
    html = _report().to_html()
    assert html.startswith("<!DOCTYPE html>")
    assert "hwatlib report" in html
    assert "Risk: HIGH" in html
    assert "score 65" in html
    assert "example.com" in html
    assert "report-abc" in html


def test_to_html_severity_grouping_with_counts():
    html = _report().to_html()
    # High group heading shows count 2.
    assert "High <span class=\"count\">(2)</span>" in html
    assert "Low <span class=\"count\">(1)</span>" in html
    # Findings content present.
    assert "Secret found" in html
    assert "Rotate creds" in html


def test_to_html_escapes_untrusted_content():
    r = HwatReport(metadata={
        "target": "<script>alert(1)</script>",
        "findings": [{"category": "c", "title": "<img src=x onerror=y>", "severity": "high"}],
    })
    html = r.to_html()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x onerror=y>" not in html


def test_to_html_no_findings():
    r = HwatReport(metadata={"target": "t", "risk": {"score": 0, "level": "info"}})
    html = r.to_html()
    assert "No findings." in html


def test_to_html_renders_diff_section():
    r = _report()
    r.metadata["diff"] = {
        "risk": {"old_score": 40, "new_score": 65, "delta": 25, "old_level": "medium", "new_level": "high"},
        "findings": {"added": [{"x": 1}], "removed": []},
        "web": {"tech_hints_added": ["php"], "tech_hints_removed": []},
        "recon": {"ports_added": ["443"], "ports_removed": []},
    }
    html = r.to_html()
    assert "Changes since previous scan" in html
    assert "delta 25" in html
    assert "Ports added:" in html and "443" in html
    assert "Findings added:</strong> 1" in html


def test_to_html_omits_diff_when_absent():
    assert "Changes since previous scan" not in _report().to_html()
