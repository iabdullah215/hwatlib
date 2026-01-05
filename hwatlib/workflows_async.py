from __future__ import annotations

import asyncio
from typing import Any, Dict, Iterable, List, Optional

from .async_http import AsyncHttpClient
from .findings import score_report
from .http import HttpOptions
from .report import HwatReport, new_report
from .session import HwatSession, new_session
from . import dns as dns_mod
from . import fingerprint as fp
from . import plugins as plugins_mod
from . import privesc as privesc_mod
from . import recon as recon_mod
from . import secrets as secrets_mod
from . import web as web_mod
from .models import NmapResult, PrivescResult, ReconResult


async def build_report_async(
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
    """Async mode for web crawling + header fetching.

    Non-web parts remain best-effort and synchronous.
    """

    session = new_session(target, base_url=url, http_options=http_options)
    report = new_report(target=target)

    ip = await _add_recon_async(report, session, nmap=nmap)
    await _add_dns_async(report, target, dns_wordlist=dns_wordlist, reverse_ips=reverse_ips)
    await _add_web_async(report, session, url=url, http_options=http_options)
    _add_privesc(report)
    _add_secrets(report, secrets_paths=secrets_paths)
    _add_plugins(report, session, plugins=plugins)
    _add_fingerprint(report, ip)
    _add_risk(report)

    return report


async def _add_recon_async(report: HwatReport, session: HwatSession, *, nmap: bool) -> Optional[str]:
    ip = session.ensure_ip()
    report.recon = ReconResult(target=session.target, ip=ip)
    if not (nmap and ip):
        return ip

    try:
        await asyncio.to_thread(recon_mod.init, session.target)
        nmap_res = await asyncio.to_thread(recon_mod.nmap_scan_typed, target=ip)
        report.recon.nmap = nmap_res

        ports = list(getattr(nmap_res, "open_tcp", []) or [])
        if ports:
            banners = await recon_mod.banner_grab_async(
                ip,
                ports,
                max_concurrency=int(session.http_options.max_concurrency or 20),
            )
            report.recon.banners = banners
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
        dns_result = dns_mod.enumerate_dns(target, wordlist_path=dns_wordlist, ips_for_reverse=reverse_ips)
        report.dns = {
            "subdomains": dns_result.subdomains,
            "reverse": dns_result.reverse,
            "zone_transfer": dns_result.zone_transfer,
        }
    except Exception as e:
        report.dns = {"ok": False, "error": str(e)}


async def _add_dns_async(
    report: HwatReport,
    target: str,
    *,
    dns_wordlist: Optional[str],
    reverse_ips: Optional[List[str]],
) -> None:
    if not target or _looks_like_ip(target):
        return
    try:
        report.dns = await dns_mod.enumerate_dns_async_typed(
            target,
            wordlist_path=dns_wordlist,
            ips_for_reverse=reverse_ips,
            max_concurrency=int(50),
        )
    except Exception as e:
        report.dns = {"ok": False, "error": str(e)}


async def _add_web_async(
    report: HwatReport,
    session: HwatSession,
    *,
    url: Optional[str],
    http_options: Optional[HttpOptions],
) -> None:
    base_url = url or session.ensure_base_url()
    if not base_url:
        return
    try:
        async with AsyncHttpClient(options=http_options) as client:
            report.web = await web_mod.scan_async(base_url, client=client, depth=2)
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
    report.recon["fingerprint"] = fp_out


def _add_risk(report: HwatReport) -> None:
    risk = score_report(report)
    report.metadata["risk"] = {"score": risk.score, "level": risk.level}
    report.metadata["findings"] = _merge_findings([f.to_dict() for f in risk.findings], report.plugins)


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


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False
