from __future__ import annotations

import asyncio
import socket
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional

import requests

from .models import DnsResultTyped, ZoneTransferResult
from .utils import get_logger, resolve_host

logger = get_logger()

# Certificate Transparency log aggregator used for passive subdomain discovery.
_CRTSH_URL = "https://crt.sh/"

if TYPE_CHECKING:  # pragma: no cover
    pass  # type: ignore


def reverse_lookup(ip: str) -> Optional[str]:
    try:
        name, _aliases, _ips = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, OSError):
        logger.debug("Reverse lookup failed ip=%s", ip)
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


def _parse_crtsh_names(entries: Any, domain: str) -> List[str]:
    """Extract in-scope subdomain names from a crt.sh JSON response."""
    domain = domain.lower().lstrip(".")
    names: set[str] = set()
    if not isinstance(entries, list):
        return []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        value = entry.get("name_value") or entry.get("common_name") or ""
        for line in str(value).splitlines():
            name = line.strip().lstrip("*.").lower().rstrip(".")
            if not name or "@" in name:
                continue
            if name == domain or name.endswith("." + domain):
                names.add(name)
    return sorted(names)


def discover_subdomains_passive(
    domain: str,
    *,
    timeout: float = 15.0,
    session: Optional[requests.Session] = None,
) -> List[str]:
    """Passive subdomain discovery via Certificate Transparency logs (crt.sh).

    Read-only and target-agnostic: it queries the public crt.sh aggregator, not
    the target itself, and returns the discovered names **without** resolving
    them. Returns an empty list on any network/parse error.
    """
    getter = session.get if session is not None else requests.get
    try:
        resp = getter(_CRTSH_URL, params={"q": f"%.{domain}", "output": "json"}, timeout=timeout)
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        logger.debug("crt.sh passive discovery failed domain=%s error=%s", domain, e)
        return []
    return _parse_crtsh_names(data, domain)


def enumerate_subdomains(
    domain: str,
    *,
    words: Optional[Iterable[str]] = None,
    passive: bool = True,
    resolve: bool = True,
    limit: int = 500,
    timeout: float = 15.0,
    session: Optional[requests.Session] = None,
) -> Dict[str, Optional[str]]:
    """Combine passive (CT logs) and active (wordlist brute) subdomain discovery.

    Returns a mapping of ``fqdn -> ip`` (or ``None`` when ``resolve`` is False or
    a passively-discovered name does not resolve).
    """
    results: Dict[str, Optional[str]] = {}

    if words:
        for fqdn, ip in discover_subdomains(domain, words, limit=limit).items():
            results[fqdn] = ip

    if passive:
        for name in discover_subdomains_passive(domain, timeout=timeout, session=session):
            if name in results:
                continue
            results[name] = resolve_host(name) if resolve else None

    return results


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
            except Exception as e:
                logger.debug("Async DNS resolver failed fqdn=%s error=%s; falling back", fqdn, e)
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


def try_zone_transfer(domain: str) -> ZoneTransferResult:
    """Report-only zone transfer attempt.

    Uses dnspython if installed; otherwise returns a message.
    """

    try:
        import dns.query  # type: ignore
        import dns.resolver  # type: ignore
        import dns.zone  # type: ignore

        ns = []
        try:
            ans = dns.resolver.resolve(domain, "NS")
            ns = [str(r).rstrip(".") for r in ans]
        except Exception as e:
            logger.debug("Could not resolve NS records domain=%s error=%s", domain, e)
            return ZoneTransferResult(ok=False, reason="Could not resolve NS records")

        results: Dict[str, Dict[str, Any]] = {}
        for server in ns[:5]:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(server, domain, timeout=3.0))
                results[server] = {"ok": True, "records": len(list(z.nodes.keys()))}
            except Exception as e:
                logger.debug("Zone transfer failed domain=%s ns=%s error=%s", domain, server, e)
                results[server] = {"ok": False, "error": str(e)}

        return ZoneTransferResult(
            ok=any(v.get("ok") for v in results.values()),
            nameservers=ns,
            results=results,
        )
    except Exception as e:
        logger.debug("dnspython unavailable or zone transfer init failed domain=%s error=%s", domain, e)
        return ZoneTransferResult(
            ok=False,
            reason="dnspython not installed (install extras: pip install hwatlib[dns])",
        )


async def try_zone_transfer_async(domain: str) -> ZoneTransferResult:
    return await asyncio.to_thread(try_zone_transfer, domain)


def try_zone_transfer_typed(domain: str) -> ZoneTransferResult:
    return try_zone_transfer(domain)


def enumerate_dns(
    domain: str,
    *,
    wordlist_path: Optional[str] = None,
    ips_for_reverse: Optional[List[str]] = None,
) -> DnsResultTyped:
    words: List[str] = []
    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]
        except OSError as e:
            logger.warning("Could not read DNS wordlist path=%s error=%s", wordlist_path, e)
            words = []

    subdomains = discover_subdomains(domain, words) if words else {}

    reverse: Dict[str, str] = {}
    for ip in ips_for_reverse or []:
        name = reverse_lookup(ip)
        if name:
            reverse[ip] = name

    zt = try_zone_transfer(domain)

    return DnsResultTyped(
        ok=True,
        subdomains=subdomains,
        reverse=reverse,
        zone_transfer=zt,
    )


def enumerate_dns_typed(
    domain: str,
    *,
    wordlist_path: Optional[str] = None,
    ips_for_reverse: Optional[List[str]] = None,
) -> DnsResultTyped:
    return enumerate_dns(domain, wordlist_path=wordlist_path, ips_for_reverse=ips_for_reverse)


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

    zone_typed = await try_zone_transfer_async(domain)

    return DnsResultTyped(ok=True, subdomains=subdomains, reverse=reverse, zone_transfer=zone_typed)


async def _read_wordlist_async(path: str) -> List[str]:
    def read_sync() -> List[str]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except OSError as e:
            logger.warning("Could not read DNS wordlist path=%s error=%s", path, e)
            return []

    return await asyncio.to_thread(read_sync)
