from __future__ import annotations

import hwatlib.workflows as wf
from hwatlib import logging_ext
from hwatlib.models import NmapResult, ReconResult, WebResult
from hwatlib.report import new_report
from hwatlib.session import new_session


def test_new_report_stamps_run_id():
    logging_ext.set_run_id("run-stamp")
    try:
        report = new_report(target="example.test")
        assert report.metadata["run_id"] == "run-stamp"
    finally:
        logging_ext.set_run_id("")


def test_build_report_generates_run_id(monkeypatch):
    logging_ext.set_run_id("")
    monkeypatch.setattr(wf.privesc_mod, "run_checks", lambda: {})
    real = wf.privesc_mod.risk_score
    monkeypatch.setattr(wf.privesc_mod, "risk_score", lambda raw: real({}))
    monkeypatch.setattr(wf.web_mod, "scan", lambda *a, **k: WebResult(ok=True))
    monkeypatch.setattr(wf.fp, "fingerprint_service", lambda ip, port: {})
    report = wf.build_report(target="10.0.0.1", nmap=False)
    assert report.metadata["run_id"].startswith("report-")
    logging_ext.set_run_id("")


def test_add_recon_with_nmap(monkeypatch):
    report = new_report(target="example.test")
    session = new_session("example.test")
    session.ip = "1.2.3.4"

    monkeypatch.setattr(wf.recon_mod, "init", lambda t, ip=None: object())
    monkeypatch.setattr(
        wf.recon_mod, "nmap_scan_typed",
        lambda *, target, session: NmapResult(ok=True, output="o", open_tcp=[22], open_udp=[]),
    )
    monkeypatch.setattr(wf.recon_mod, "banner_grab", lambda host, ports: {22: "ssh"})

    ip = wf._add_recon(report, session, nmap=True)
    assert ip == "1.2.3.4"
    assert report.recon.nmap.open_tcp == [22]
    assert report.recon.banners == {22: "ssh"}


def test_add_recon_init_none(monkeypatch):
    report = new_report(target="example.test")
    session = new_session("example.test")
    session.ip = "1.2.3.4"
    monkeypatch.setattr(wf.recon_mod, "init", lambda t, ip=None: None)
    wf._add_recon(report, session, nmap=True)
    assert report.recon.ok is False
    assert "initialize" in (report.recon.error or "")


def test_add_recon_no_nmap():
    report = new_report(target="example.test")
    session = new_session("example.test")
    session.ip = "1.2.3.4"
    ip = wf._add_recon(report, session, nmap=False)
    assert ip == "1.2.3.4"
    assert report.recon.ok is True


def test_add_dns_skips_ip():
    report = new_report(target="10.0.0.1")
    wf._add_dns(report, "10.0.0.1", dns_wordlist=None, reverse_ips=None)
    assert report.dns == {}


def test_add_dns_runs_for_domain(monkeypatch):
    report = new_report(target="example.test")
    monkeypatch.setattr(wf.dns_mod, "enumerate_dns_typed", lambda *a, **k: {"ok": True})
    wf._add_dns(report, "example.test", dns_wordlist=None, reverse_ips=None)
    assert report.dns == {"ok": True}


def test_add_dns_handles_error(monkeypatch):
    report = new_report(target="example.test")

    def boom(*a, **k):
        raise RuntimeError("dns down")

    monkeypatch.setattr(wf.dns_mod, "enumerate_dns_typed", boom)
    wf._add_dns(report, "example.test", dns_wordlist=None, reverse_ips=None)
    assert report.dns.ok is False


def test_add_web(monkeypatch):
    report = new_report(target="example.test")
    session = new_session("example.test")
    monkeypatch.setattr(wf.web_mod, "scan", lambda *a, **k: WebResult(ok=True))
    wf._add_web(report, session, url=None)
    assert report.web.ok is True


def test_add_web_handles_error(monkeypatch):
    report = new_report(target="example.test")
    session = new_session("example.test")

    def boom(*a, **k):
        raise RuntimeError("web down")

    monkeypatch.setattr(wf.web_mod, "scan", boom)
    wf._add_web(report, session, url="http://x")
    assert report.web.ok is False


def test_add_privesc(monkeypatch):
    report = new_report(target="example.test")
    monkeypatch.setattr(wf.privesc_mod, "run_checks", lambda: {"sudo_rights": ""})
    wf._add_privesc(report)
    assert report.privesc.ok is True


def test_add_privesc_error(monkeypatch):
    report = new_report(target="example.test")

    def boom():
        raise RuntimeError("nope")

    monkeypatch.setattr(wf.privesc_mod, "run_checks", boom)
    wf._add_privesc(report)
    assert report.privesc.ok is False


def test_add_secrets(monkeypatch, tmp_path):
    report = new_report(target="example.test")
    monkeypatch.setattr(wf.secrets_mod, "scan_paths", lambda paths: ["f"])
    monkeypatch.setattr(wf.secrets_mod, "summarize", lambda findings: {"count": 1})
    wf._add_secrets(report, secrets_paths=["/tmp/x"])
    assert report.secrets == {"count": 1}


def test_add_secrets_none():
    report = new_report(target="example.test")
    wf._add_secrets(report, secrets_paths=None)
    assert report.secrets == {}


def test_add_plugins(monkeypatch):
    report = new_report(target="example.test")
    session = new_session("example.test")

    class _Res:
        def to_dict(self):
            return {"ok": True}

    monkeypatch.setattr(wf.plugins_mod, "run_checks", lambda s, names=None: {"p": _Res()})
    wf._add_plugins(report, session, plugins=["p"])
    assert report.plugins == {"p": {"ok": True}}


def test_add_plugins_none():
    report = new_report(target="example.test")
    session = new_session("example.test")
    wf._add_plugins(report, session, plugins=None)
    assert report.plugins == {}


def test_add_fingerprint(monkeypatch):
    report = new_report(target="example.test")
    report.recon = ReconResult(target="example.test", ip="1.2.3.4", ok=True)
    monkeypatch.setattr(wf.fp, "fingerprint_service", lambda ip, port: {"service": "http", "port": port})
    wf._add_fingerprint(report, "1.2.3.4")
    assert set(report.recon.fingerprint.keys()) == {"22", "80", "443"}


def test_add_fingerprint_no_ip():
    report = new_report(target="example.test")
    report.recon = ReconResult(target="example.test", ip=None, ok=True)
    wf._add_fingerprint(report, None)
    # No ip -> no fingerprint added.
    assert getattr(report.recon, "fingerprint", None) in (None, {})
