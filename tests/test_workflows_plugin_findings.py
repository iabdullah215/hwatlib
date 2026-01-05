from __future__ import annotations

import asyncio
from dataclasses import dataclass


def test_build_report_merges_plugin_findings_into_metadata(monkeypatch):
    import hwatlib.workflows as workflows

    @dataclass
    class FakePluginResult:
        def to_dict(self):
            return {
                "ok": True,
                "findings": [
                    {"category": "plugin", "title": "Plugin finding", "severity": "low"},
                ],
            }

    monkeypatch.setattr(
        workflows.plugins_mod,
        "run_checks",
        lambda session, names=None: {"p": FakePluginResult()},
    )

    # Keep the rest of the pipeline minimal and deterministic.
    monkeypatch.setattr(workflows, "_add_recon", lambda report, session, nmap=False: None)
    monkeypatch.setattr(workflows, "_add_dns", lambda report, target, dns_wordlist=None, reverse_ips=None: None)
    monkeypatch.setattr(workflows, "_add_web", lambda report, session, url=None: None)
    monkeypatch.setattr(workflows, "_add_privesc", lambda report: None)
    monkeypatch.setattr(workflows, "_add_secrets", lambda report, secrets_paths=None: None)
    monkeypatch.setattr(workflows, "_add_fingerprint", lambda report, ip: None)

    report = workflows.build_report(target="example.com", plugins=["p"])
    findings = report.metadata.get("findings")

    assert isinstance(findings, list)
    assert any(f.get("title") == "Plugin finding" for f in findings)


def test_build_report_async_merges_plugin_findings_into_metadata(monkeypatch):
    import hwatlib.workflows_async as workflows

    @dataclass
    class FakePluginResult:
        def to_dict(self):
            return {
                "ok": True,
                "findings": [
                    {"category": "plugin", "title": "Plugin finding", "severity": "low"},
                ],
            }

    monkeypatch.setattr(
        workflows.plugins_mod,
        "run_checks",
        lambda session, names=None: {"p": FakePluginResult()},
    )

    async def fake_add_recon_async(report, session, nmap=False):
        return None

    async def fake_add_dns_async(report, target, dns_wordlist=None, reverse_ips=None):
        return None

    async def fake_add_web_async(report, session, url=None, http_options=None):
        return None

    monkeypatch.setattr(workflows, "_add_recon_async", fake_add_recon_async)
    monkeypatch.setattr(workflows, "_add_dns_async", fake_add_dns_async)
    monkeypatch.setattr(workflows, "_add_web_async", fake_add_web_async)
    monkeypatch.setattr(workflows, "_add_privesc", lambda report: None)
    monkeypatch.setattr(workflows, "_add_secrets", lambda report, secrets_paths=None: None)
    monkeypatch.setattr(workflows, "_add_fingerprint", lambda report, ip: None)

    report = asyncio.run(workflows.build_report_async(target="example.com", plugins=["p"]))
    findings = report.metadata.get("findings")

    assert isinstance(findings, list)
    assert any(f.get("title") == "Plugin finding" for f in findings)
