from __future__ import annotations

import json

from hwatlib import diff
from hwatlib.diff import diff_reports, load_report_json, to_markdown


def test_load_report_json(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"metadata": {"risk": {"score": 5}}}))
    assert load_report_json(str(p))["metadata"]["risk"]["score"] == 5


def test_diff_reports_full():
    old = {
        "metadata": {
            "risk": {"score": 10, "level": "low"},
            "findings": [{"category": "a", "title": "t1", "severity": "low"}],
        },
        "web": {"tech": {"hints": ["nginx"]}},
        "recon": {"fingerprint": {"80": {}}},
    }
    new = {
        "metadata": {
            "risk": {"score": 40, "level": "medium"},
            "findings": [{"category": "b", "title": "t2", "severity": "high"}],
        },
        "web": {"tech": {"hints": ["nginx", "php"]}},
        "recon": {"fingerprint": {"80": {}, "443": {}}},
    }
    d = diff_reports(old, new).to_dict()
    assert d["risk"]["delta"] == 30
    assert len(d["findings"]["added"]) == 1
    assert len(d["findings"]["removed"]) == 1
    assert d["web"]["tech_hints_added"] == ["php"]
    assert d["recon"]["ports_added"] == ["443"]


def test_to_markdown_renders_sections():
    old = {"metadata": {"risk": {"score": 0, "level": "info"}}}
    new = {"metadata": {"risk": {"score": 20, "level": "low"}}}
    md = to_markdown(diff_reports(old, new))
    assert "# hwat report diff" in md
    assert "## Risk" in md
    assert "delta: 20" in md
    assert "## Findings" in md
    assert "## Web" in md
    assert "## Recon" in md


def test_diff_reports_tolerates_missing_sections():
    d = diff_reports({}, {}).to_dict()
    assert d["risk"]["delta"] == 0
    assert d["findings"]["added"] == []
    assert d["web"]["tech_hints_added"] == []


def test_normalize_findings_filters_non_dicts():
    assert diff._normalize_findings(["str", {"a": 1}, 5]) == [{"a": 1}]
    assert diff._normalize_findings("nope") == []
