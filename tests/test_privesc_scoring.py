from __future__ import annotations

from hwatlib.privesc import risk_score


def test_risk_score_low_when_empty():
    out = risk_score({})
    assert out.level in {"low", "medium", "high"}
    assert out.score == 0


def test_risk_score_increases_with_sudo_and_suid():
    report = {
        "sudo_rights": "(ALL : ALL) NOPASSWD: ALL",
        "suid_bins": "/usr/bin/sudo\n/usr/bin/passwd\n",
        "bash_history": "export TOKEN=abc123",
    }
    out = risk_score(report)
    assert out.score >= 45
    assert "sudo_rights_present" in out.reasons
    assert "suid_binaries_found" in out.reasons
