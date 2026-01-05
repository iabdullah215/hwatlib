from __future__ import annotations

from hwatlib.findings import score_report
from hwatlib.report import new_report


def test_score_report_adds_points_for_plugin_findings():
    r = new_report(target="example.com")
    r.plugins = {
        "p": {
            "ok": True,
            "findings": [
                {"category": "plugin", "title": "X", "severity": "medium"},
                {"category": "plugin", "title": "Y", "severity": "low"},
            ],
        }
    }

    out = score_report(r)
    assert out.score >= 15  # 10 + 5 from medium+low
    assert any(f.title == "X" for f in out.findings)
    assert any(f.title == "Y" for f in out.findings)
