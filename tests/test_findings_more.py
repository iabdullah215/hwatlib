from __future__ import annotations

from hwatlib.findings import (
    _score_privesc,
    _score_recon_tls,
    _score_secrets,
    _score_web_tech,
    score_report,
)
from hwatlib.report import HwatReport


def _report(**sections) -> HwatReport:
    return HwatReport(**sections)


def test_score_secrets_high():
    pts, findings = _score_secrets({"max_risk": 9, "count": 3})
    assert pts == 35
    assert findings[0].severity == "high"


def test_score_secrets_medium():
    pts, findings = _score_secrets({"max_risk": 7, "count": 1})
    assert pts == 20
    assert findings[0].severity == "medium"


def test_score_secrets_none():
    assert _score_secrets({"max_risk": 2}) == (0, [])
    assert _score_secrets("not a dict") == (0, [])


def test_score_privesc_levels():
    assert _score_privesc({"score": {"score": 65, "level": "high", "reasons": []}})[0] == 25
    assert _score_privesc({"score": {"score": 40, "level": "medium", "reasons": []}})[0] == 15
    assert _score_privesc({"score": {"score": 10}})[0] == 0
    assert _score_privesc({}) == (0, [])


def test_score_recon_tls_flags_failures():
    fp = {"fingerprint": {"443": {"notes": ["tls_cert_verification_failed"]}, "80": {"notes": []}}}
    pts, findings = _score_recon_tls(fp)
    assert pts == 10
    assert findings[0].evidence["ports"] == ["443"]


def test_score_recon_tls_no_failures():
    assert _score_recon_tls({"fingerprint": {"80": {"notes": []}}}) == (0, [])
    assert _score_recon_tls({}) == (0, [])


def test_score_web_tech_lists_hints():
    findings = _score_web_tech({"tech": {"ok": True, "hints": ["nginx", "php"]}})
    assert findings[0].category == "web"
    assert findings[0].evidence["hints"] == ["nginx", "php"]


def test_score_web_tech_requires_ok_and_hints():
    assert _score_web_tech({"tech": {"ok": False, "hints": ["x"]}}) == []
    assert _score_web_tech({"tech": {"ok": True, "hints": []}}) == []


def test_score_report_end_to_end_and_clamped():
    report = _report(
        secrets={"max_risk": 9, "count": 2},
        privesc={"score": {"score": 65, "level": "high", "reasons": ["sudo"]}},
        recon={"fingerprint": {"443": {"notes": ["tls_cert_verification_failed"]}}},
        web={"tech": {"ok": True, "hints": ["nginx"]}},
        plugins={
            "p": {
                "findings": [
                    {"category": "c", "title": "t", "severity": "critical"},
                    {"category": "c", "title": "t", "severity": "critical"},  # dup
                ]
            }
        },
    )
    summary = score_report(report)
    assert 0 <= summary.score <= 100
    # secrets(35)+privesc(25)+tls(10)+plugins(30 capped) clamps at 100.
    assert summary.score == 100
    assert summary.level == "high"
    categories = {f.category for f in summary.findings}
    assert {"secrets", "privesc", "recon", "web", "c"} <= categories


def test_plugin_severity_points_exact():
    from hwatlib.findings import _plugin_severity_points

    assert _plugin_severity_points("critical") == 30
    assert _plugin_severity_points("high") == 20
    assert _plugin_severity_points("medium") == 10
    assert _plugin_severity_points("low") == 5
    assert _plugin_severity_points("info") == 0
    assert _plugin_severity_points("bogus") == 0


def test_score_plugins_caps_at_30():
    from hwatlib.findings import _score_plugins

    payload = {
        "p": {
            "findings": [
                {"category": "c", "title": f"t{i}", "severity": "critical"}
                for i in range(5)
            ]
        }
    }
    points, findings = _score_plugins(payload)
    assert points == 30  # capped even though 5*30 = 150
    assert len(findings) == 5


def test_score_level_exact_boundaries():
    from hwatlib.findings import _score_level

    assert _score_level(70) == "high"
    assert _score_level(69) == "medium"
    assert _score_level(40) == "medium"
    assert _score_level(39) == "low"
    assert _score_level(15) == "low"
    assert _score_level(14) == "info"


def test_score_report_empty_is_info():
    summary = score_report(_report())
    assert summary.score == 0
    assert summary.level == "info"
