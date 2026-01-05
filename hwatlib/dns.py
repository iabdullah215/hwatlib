from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from typing import TYPE_CHECKING

from .utils import resolve_host

from .models import DnsResultTyped, ZoneTransferResult

if TYPE_CHECKING:  # pragma: no cover
    import dns.query  # type: ignore
    import dns.resolver  # type: ignore
    import dns.zone  # type: ignore


@dataclass
class DnsResult:
    subdomains: Dict[str, str]
    reverse: Dict[str, str]
    zone_transfer: Dict[str, Any]


def reverse_lookup(ip: str) -> Optional[str]:
    try:
        name, _aliases, _ips = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None


async def reverse_lookup_async(ip: str) -> Optional[str]:
    return await asyncio.to_thread(reverse_lookup, ip)


def discover_subdomains(domain: str, words: Iterable[str], *, limit: int = 500) -> Dict[str, str]:
    found: Dict[str, str] = {}
    count = 0
    for w in words:
        if count >= limit:
            break
        w = w.strip()
        if not w or w.startswith("#"):
            continue
        fqdn = f"{w}.{domain}".lower()
        ip = resolve_host(fqdn)
        if ip:
            found[fqdn] = ip
            count += 1
    return found


async def discover_subdomains_async(
    domain: str,
    words: Iterable[str],
    *,
    limit: int = 500,
    max_concurrency: int = 50,
) -> Dict[str, str]:
    sem = asyncio.Semaphore(max(1, int(max_concurrency or 1)))
    found: Dict[str, str] = {}

    async def resolve_one(fqdn: str) -> Optional[str]:
        async with sem:
            try:
                import dns.asyncresolver  # type: ignore

                ans = await dns.asyncresolver.resolve(fqdn, "A")
                for r in ans:
                    return str(r)
                return None
            except Exception:
                return await asyncio.to_thread(resolve_host, fqdn)

    tasks: List[asyncio.Task[tuple[str, Optional[str]]]] = []
    count = 0
    for w in words:
        if count >= limit:
            break
        w = (w or "").strip()
        if not w or w.startswith("#"):
            continue
        fqdn = f"{w}.{domain}".lower()

        async def run(f: str = fqdn):
            return f, await resolve_one(f)

        tasks.append(asyncio.create_task(run()))
        count += 1

    for fqdn, ip in await asyncio.gather(*tasks, return_exceptions=False):
        if ip:
            found[fqdn] = ip

    return found


def try_zone_transfer(domain: str) -> Dict[str, Any]:
    """Report-only zone transfer attempt.

    Uses dnspython if installed; otherwise returns a message.
    """

    try:
        import dns.resolver  # type: ignore
        import dns.query  # type: ignore
        import dns.zone  # type: ignore

        ns = []
        try:
            ans = dns.resolver.resolve(domain, "NS")
            ns = [str(r).rstrip(".") for r in ans]
        except Exception:
            return {"ok": False, "reason": "Could not resolve NS records"}

        results = {}
        for server in ns[:5]:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(server, domain, timeout=3.0))
                results[server] = {"ok": True, "records": len(list(z.nodes.keys()))}
            except Exception as e:
                results[server] = {"ok": False, "error": str(e)}

        return {"ok": any(v.get("ok") for v in results.values()), "nameservers": ns, "results": results}
    except Exception:
        return {"ok": False, "reason": "dnspython not installed (install extras: pip install hwatlib[dns])"}


async def try_zone_transfer_async(domain: str) -> Dict[str, Any]:
    return await asyncio.to_thread(try_zone_transfer, domain)


def try_zone_transfer_typed(domain: str) -> ZoneTransferResult:
    zt = try_zone_transfer(domain)
    return ZoneTransferResult(
        ok=bool(zt.get("ok")),
        nameservers=list(zt.get("nameservers") or []),
        results=dict(zt.get("results") or {}),
        reason=str(zt.get("reason")) if zt.get("reason") else None,
    )


def enumerate_dns(domain: str, *, wordlist_path: Optional[str] = None, ips_for_reverse: Optional[List[str]] = None) -> DnsResult:
    words: List[str] = []
    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]
        except Exception:
            words = []

    subdomains = discover_subdomains(domain, words) if words else {}

    reverse: Dict[str, str] = {}
    for ip in ips_for_reverse or []:
        name = reverse_lookup(ip)
        if name:
            reverse[ip] = name

    zt = try_zone_transfer(domain)

    return DnsResult(subdomains=subdomains, reverse=reverse, zone_transfer=zt)


def enumerate_dns_typed(
    domain: str,
    *,
    wordlist_path: Optional[str] = None,
    ips_for_reverse: Optional[List[str]] = None,
) -> DnsResultTyped:
    r = enumerate_dns(domain, wordlist_path=wordlist_path, ips_for_reverse=ips_for_reverse)
    zt = r.zone_transfer if isinstance(r.zone_transfer, dict) else {}
    return DnsResultTyped(
        subdomains=dict(r.subdomains),
        reverse=dict(r.reverse),
        zone_transfer=ZoneTransferResult(
            ok=bool(zt.get("ok")),
            nameservers=list(zt.get("nameservers") or []),
            results=dict(zt.get("results") or {}),
            reason=str(zt.get("reason")) if zt.get("reason") else None,
        ),
    )


async def enumerate_dns_async_typed(
    domain: str,
    *,
    wordlist_path: Optional[str] = None,
    ips_for_reverse: Optional[List[str]] = None,
    max_concurrency: int = 50,
) -> DnsResultTyped:
    words: List[str] = []
    if wordlist_path:
        words = await _read_wordlist_async(wordlist_path)

    subdomains = await discover_subdomains_async(domain, words, max_concurrency=max_concurrency) if words else {}

    reverse: Dict[str, str] = {}
    if ips_for_reverse:
        names = await asyncio.gather(*(reverse_lookup_async(ip) for ip in ips_for_reverse))
        for ip, name in zip(ips_for_reverse, names):
            if name:
                reverse[ip] = name

    zt = await try_zone_transfer_async(domain)
    zone_typed = ZoneTransferResult(
        ok=bool(zt.get("ok")),
        nameservers=list(zt.get("nameservers") or []),
        results=dict(zt.get("results") or {}),
        reason=str(zt.get("reason")) if zt.get("reason") else None,
    )

    return DnsResultTyped(subdomains=subdomains, reverse=reverse, zone_transfer=zone_typed)


async def _read_wordlist_async(path: str) -> List[str]:
    def read_sync() -> List[str]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception:
            return []

    return await asyncio.to_thread(read_sync)
