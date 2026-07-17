from __future__ import annotations

import asyncio

import hwatlib.workflows_async as wfa
from hwatlib.models import WebResult
from hwatlib.report import new_report


def test_delegators_match_sync():
    assert wfa._looks_like_ip("10.0.0.1") is True
    section = {"p": {"findings": [{"category": "c", "title": "t", "severity": "high"}]}}
    assert wfa._extract_plugin_findings(section)[0]["title"] == "t"
    dupes = [
        {"category": "a", "title": "t", "severity": "high"},
        {"category": "a", "title": "t", "severity": "high"},
    ]
    assert len(wfa._dedupe_findings(dupes)) == 1
    merged = wfa._merge_findings([{"category": "r", "title": "x", "severity": "low"}], section)
    assert len(merged) == 2


def test_add_dns_sync_skips_ip():
    report = new_report(target="10.0.0.1")
    wfa._add_dns(report, "10.0.0.1", dns_wordlist=None, reverse_ips=None)
    # IP target -> DNS section untouched (still default empty dict).
    assert report.dns == {}


def test_add_risk_populates_metadata():
    report = new_report(target="example.test")
    wfa._add_risk(report)
    assert "risk" in report.metadata
    assert isinstance(report.metadata["findings"], list)


class _FakeAsyncClient:
    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def test_build_report_async_ip_target(monkeypatch):
    # Patch the network/system phases so the async pipeline stays hermetic.
    monkeypatch.setattr(wfa, "AsyncHttpClient", _FakeAsyncClient)

    async def fake_scan_async(base_url, *, client, depth):
        return WebResult(ok=True)

    monkeypatch.setattr(wfa.web_mod, "scan_async", fake_scan_async)

    real_risk_score = wfa.sync_workflows.privesc_mod.risk_score
    monkeypatch.setattr(wfa.sync_workflows.privesc_mod, "run_checks", lambda: {})
    monkeypatch.setattr(wfa.sync_workflows.privesc_mod, "risk_score", lambda raw: real_risk_score({}))
    monkeypatch.setattr(wfa.sync_workflows.fp, "fingerprint_service", lambda ip, port: {"service": "unknown"})

    report = asyncio.run(wfa.build_report_async(target="10.0.0.1", nmap=False))
    assert report.recon.target == "10.0.0.1"
    assert report.web.ok is True
    assert "risk" in report.metadata
