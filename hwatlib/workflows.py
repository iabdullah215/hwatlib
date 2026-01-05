from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from . import dns as dns_mod
from . import fingerprint as fp
from . import plugins as plugins_mod
from . import privesc as privesc_mod
from . import recon as recon_mod
from . import secrets as secrets_mod
from . import web as web_mod
from .http import HttpOptions
from .findings import score_report
from .models import DnsResultTyped, NmapResult, PrivescResult, ReconResult
from .report import HwatReport, new_report
from .session import HwatSession, new_session


def build_report(
    *,
    target: str,
    url: Optional[str] = None,
    dns_wordlist: Optional[str] = None,
    reverse_ips: Optional[List[str]] = None,
    secrets_paths: Optional[List[str]] = None,
    plugins: Optional[Iterable[str]] = None,
    http_options: Optional[HttpOptions] = None,
    nmap: bool = False,
) -> HwatReport:
    """Run a best-effort, safe-by-default report.

    Notes:
    - Does not perform state-changing actions.
    - Nmap is off by default; enable with nmap=True.
    """

    session = new_session(target, base_url=url, http_options=http_options)
    report = new_report(target=target)

    ip = _add_recon(report, session, nmap=nmap)
    _add_dns(report, target, dns_wordlist=dns_wordlist, reverse_ips=reverse_ips)
    _add_web(report, session, url=url)
    _add_privesc(report)
    _add_secrets(report, secrets_paths=secrets_paths)
    _add_plugins(report, session, plugins=plugins)
    _add_fingerprint(report, ip)

    risk = score_report(report)
    report.metadata["risk"] = {"score": risk.score, "level": risk.level}
    report.metadata["findings"] = _merge_findings([f.to_dict() for f in risk.findings], report.plugins)

    return report


def _merge_findings(risk_findings: List[Dict[str, Any]], plugins_section: Any) -> List[Dict[str, Any]]:
    merged = list(risk_findings)
    merged.extend(_extract_plugin_findings(plugins_section))
    return _dedupe_findings(merged)


def _extract_plugin_findings(plugins_section: Any) -> List[Dict[str, Any]]:
    if not isinstance(plugins_section, dict):
        return []
    out: List[Dict[str, Any]] = []
    for _name, payload in plugins_section.items():
        if not isinstance(payload, dict):
            continue
        findings = payload.get("findings")
        if not isinstance(findings, list):
            continue
        for f in findings:
            if isinstance(f, dict):
                out.append(f)
    return out


def _dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: List[Dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        key = (str(f.get("category") or ""), str(f.get("title") or ""), str(f.get("severity") or ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _add_recon(report: HwatReport, session: HwatSession, *, nmap: bool) -> Optional[str]:
    ip = session.ensure_ip()
    report.recon = ReconResult(target=session.target, ip=ip)
    if not (nmap and ip):
        return ip

    try:
        recon_mod.init(session.target)
        nmap_out = recon_mod.nmap_scan(target=ip)
        report.recon.nmap = NmapResult(ok=True, output=nmap_out)
        try:
            banners = recon_mod.banner_grab()
            report.recon.banners = {int(k): v for k, v in (banners or {}).items()}
        except Exception:
            pass
    except Exception as e:
        report.recon.nmap = NmapResult(ok=False, error=str(e))

    return ip


def _add_dns(
    report: HwatReport,
    target: str,
    *,
    dns_wordlist: Optional[str],
    reverse_ips: Optional[List[str]],
) -> None:
    if not target or _looks_like_ip(target):
        return
    try:
        report.dns = dns_mod.enumerate_dns_typed(target, wordlist_path=dns_wordlist, ips_for_reverse=reverse_ips)
    except Exception as e:
        report.dns = {"ok": False, "error": str(e)}


def _add_web(report: HwatReport, session: HwatSession, *, url: Optional[str]) -> None:
    base_url = url or session.ensure_base_url()
    if not base_url:
        return

    try:
        client = session.ensure_http()
        report.web = web_mod.scan(base_url, client=client, timeout=session.http_options.timeout, depth=2)
    except Exception as e:
        report.web = {"ok": False, "error": str(e)}


def _add_privesc(report: HwatReport) -> None:
    try:
        raw = privesc_mod.run_checks()
        report.privesc = PrivescResult(raw=raw, score=privesc_mod.risk_score(raw))
    except Exception as e:
        report.privesc = {"ok": False, "error": str(e)}


def _add_secrets(report: HwatReport, *, secrets_paths: Optional[List[str]]) -> None:
    if not secrets_paths:
        return
    try:
        findings = secrets_mod.scan_paths(secrets_paths)
        report.secrets = secrets_mod.summarize(findings)
    except Exception as e:
        report.secrets = {"ok": False, "error": str(e)}


def _add_plugins(report: HwatReport, session: HwatSession, *, plugins: Optional[Iterable[str]]) -> None:
    if not plugins:
        return
    try:
        results = plugins_mod.run_checks(session, names=plugins)
        report.plugins = {k: (v.to_dict() if hasattr(v, "to_dict") else v.__dict__) for k, v in results.items()}
    except Exception as e:
        report.plugins = {"ok": False, "error": str(e)}


def _add_fingerprint(report: HwatReport, ip: Optional[str]) -> None:
    if not ip:
        return
    ports = [22, 80, 443]
    fp_out: Dict[str, Any] = {}
    for port in ports:
        try:
            fp_out[str(port)] = fp.fingerprint_service(ip, port)
        except Exception as e:
            fp_out[str(port)] = {"ok": False, "error": str(e)}
    try:
        report.recon.fingerprint = fp_out  # type: ignore[attr-defined]
    except Exception:
        # fallback if recon wasn't a typed object
        if isinstance(report.recon, dict):
            report.recon["fingerprint"] = fp_out


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False
