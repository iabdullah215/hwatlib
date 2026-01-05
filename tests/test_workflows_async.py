from __future__ import annotations

import asyncio

from hwatlib.findings import Finding, RiskSummary
from hwatlib.http import HttpOptions
from hwatlib.models import CrawlResult, SitemapDiscovery, TechFingerprint, WebFetchResult, WebResult


def test_build_report_async_web_and_risk(monkeypatch):
    import hwatlib.workflows_async as wf

    class DummySession:
        def __init__(self, target: str, base_url: str | None):
            self.target = target
            self._base_url = base_url

        def ensure_ip(self):
            return "127.0.0.1"

        def ensure_base_url(self):
            return self._base_url

    monkeypatch.setattr(wf, "new_session", lambda target, base_url=None, http_options=None: DummySession(target, base_url))

    async def fake_scan_async(base_url: str, *, client, depth: int = 2):
        assert depth == 2
        return WebResult(
            ok=True,
            fetch=WebFetchResult(headers={"server": "nginx"}, forms=[], js=[]),
            tech=TechFingerprint(ok=True, hints=["nginx"]),
            sitemap=CrawlResult(
                base=base_url,
                count=2,
                links=[base_url + "/a", base_url + "/b"],
                sitemaps=SitemapDiscovery(
                    robots_url=base_url + "/robots.txt",
                    sitemap_xml_url=base_url + "/sitemap.xml",
                    robots_sitemaps=[],
                    sitemap_xml_locs=[],
                ),
            ),
        )

    monkeypatch.setattr(wf.web_mod, "scan_async", fake_scan_async)

    class DummyAsyncClient:
        def __init__(self, *, options=None):
            self.options = options

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

    monkeypatch.setattr(wf, "AsyncHttpClient", DummyAsyncClient)

    # Avoid system/network touching parts.
    monkeypatch.setattr(wf, "_add_privesc", lambda report: None)
    monkeypatch.setattr(wf, "_add_fingerprint", lambda report, ip: None)

    def fake_score_report(report):
        return RiskSummary(
            score=42,
            level="medium",
            findings=[Finding(category="test", title="stub", severity="info")],
        )

    monkeypatch.setattr(wf, "score_report", fake_score_report)

    report = asyncio.run(
        wf.build_report_async(
            target="127.0.0.1",
            url="https://example.test",
            http_options=HttpOptions(),
            nmap=False,
        )
    )

    assert report.web.ok is True
    assert report.web.tech and report.web.tech.ok is True
    assert report.web.sitemap and report.web.sitemap.base == "https://example.test"

    assert report.metadata["risk"]["score"] == 42
    assert report.metadata["risk"]["level"] == "medium"
    assert isinstance(report.metadata["findings"], list)
    assert report.metadata["findings"][0]["category"] == "test"
