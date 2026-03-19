from __future__ import annotations

import asyncio
from typing import Any, Dict, Iterable, List, Optional

from .async_http import AsyncHttpClient
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
from .models import DnsResultTyped, NmapResult, PrivescResult, ReconResult, WebResult
from . import workflows as sync_workflows
from .utils import setup_logger


logger = setup_logger()


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
        recon_sess = await asyncio.to_thread(recon_mod.init, session.target, ip=ip)
        nmap_res = await asyncio.to_thread(recon_mod.nmap_scan_typed, target=ip, session=recon_sess)
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
        logger.exception("Async recon phase failed target=%s ip=%s: %s", session.target, ip, e)
        report.recon.ok = False
        report.recon.error = str(e)
        report.recon.nmap = NmapResult(ok=False, error=str(e))

    return ip


def _add_dns(
    report: HwatReport,
    target: str,
    *,
    dns_wordlist: Optional[str],
    reverse_ips: Optional[List[str]],
) -> None:
    if not target or sync_workflows._looks_like_ip(target):
        return
    try:
        report.dns = dns_mod.enumerate_dns_typed(target, wordlist_path=dns_wordlist, ips_for_reverse=reverse_ips)
    except Exception as e:
        logger.exception("Async wrapper DNS phase failed target=%s: %s", target, e)
        report.dns = DnsResultTyped(ok=False, error=str(e))


async def _add_dns_async(
    report: HwatReport,
    target: str,
    *,
    dns_wordlist: Optional[str],
    reverse_ips: Optional[List[str]],
) -> None:
    if not target or sync_workflows._looks_like_ip(target):
        return
    try:
        report.dns = await dns_mod.enumerate_dns_async_typed(
            target,
            wordlist_path=dns_wordlist,
            ips_for_reverse=reverse_ips,
            max_concurrency=int(50),
        )
    except Exception as e:
        logger.exception("Async DNS phase failed target=%s: %s", target, e)
        report.dns = DnsResultTyped(ok=False, error=str(e))


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
        logger.exception("Async web phase failed target=%s url=%s: %s", session.target, base_url, e)
        report.web = WebResult(ok=False, error=str(e))


def _add_privesc(report: HwatReport) -> None:
    sync_workflows._add_privesc(report)


def _add_secrets(report: HwatReport, *, secrets_paths: Optional[List[str]]) -> None:
    sync_workflows._add_secrets(report, secrets_paths=secrets_paths)


def _add_plugins(report: HwatReport, session: HwatSession, *, plugins: Optional[Iterable[str]]) -> None:
    sync_workflows._add_plugins(report, session, plugins=plugins)


def _add_fingerprint(report: HwatReport, ip: Optional[str]) -> None:
    sync_workflows._add_fingerprint(report, ip)


def _add_risk(report: HwatReport) -> None:
    sync_workflows._add_risk(report)


def _merge_findings(risk_findings: List[Dict[str, Any]], plugins_section: Any) -> List[Dict[str, Any]]:
    return sync_workflows._merge_findings(risk_findings, plugins_section)


def _extract_plugin_findings(plugins_section: Any) -> List[Dict[str, Any]]:
    return sync_workflows._extract_plugin_findings(plugins_section)


def _dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sync_workflows._dedupe_findings(findings)


def _looks_like_ip(value: str) -> bool:
    return sync_workflows._looks_like_ip(value)
