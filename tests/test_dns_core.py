from __future__ import annotations

import asyncio
import socket

import hwatlib.dns as dns_mod


def test_reverse_lookup_success(monkeypatch):
    monkeypatch.setattr(dns_mod.socket, "gethostbyaddr", lambda ip: ("host.test", [], [ip]))
    assert dns_mod.reverse_lookup("1.2.3.4") == "host.test"


def test_reverse_lookup_failure(monkeypatch):
    def boom(ip):
        raise socket.herror("nope")

    monkeypatch.setattr(dns_mod.socket, "gethostbyaddr", boom)
    assert dns_mod.reverse_lookup("1.2.3.4") is None


def test_reverse_lookup_async(monkeypatch):
    monkeypatch.setattr(dns_mod.socket, "gethostbyaddr", lambda ip: ("h", [], [ip]))
    assert asyncio.run(dns_mod.reverse_lookup_async("1.2.3.4")) == "h"


def test_discover_subdomains_resolves_and_filters(monkeypatch):
    resolved = {"www.example.com": "1.1.1.1", "mail.example.com": "2.2.2.2"}
    monkeypatch.setattr(dns_mod, "resolve_host", lambda fqdn: resolved.get(fqdn))
    words = ["www", "", "# comment", "mail", "nope"]
    out = dns_mod.discover_subdomains("example.com", words)
    assert out == resolved


def test_discover_subdomains_respects_limit(monkeypatch):
    monkeypatch.setattr(dns_mod, "resolve_host", lambda fqdn: "9.9.9.9")
    out = dns_mod.discover_subdomains("example.com", ["a", "b", "c"], limit=2)
    assert len(out) == 2


def test_try_zone_transfer_no_ns(monkeypatch):
    import dns.resolver

    def boom(domain, rtype):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver, "resolve", boom)
    result = dns_mod.try_zone_transfer("example.com")
    assert result.ok is False
    assert "NS records" in (result.reason or "")


def test_enumerate_dns_integration(monkeypatch, tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("www\nmail\n")
    monkeypatch.setattr(dns_mod, "resolve_host", lambda fqdn: "1.1.1.1")
    monkeypatch.setattr(dns_mod, "reverse_lookup", lambda ip: "ptr.test")
    monkeypatch.setattr(
        dns_mod, "try_zone_transfer",
        lambda domain: dns_mod.ZoneTransferResult(ok=False, reason="stub"),
    )
    result = dns_mod.enumerate_dns("example.com", wordlist_path=str(wl), ips_for_reverse=["8.8.8.8"])
    assert result.ok is True
    assert result.subdomains == {"www.example.com": "1.1.1.1", "mail.example.com": "1.1.1.1"}
    assert result.reverse == {"8.8.8.8": "ptr.test"}


def test_enumerate_dns_missing_wordlist(monkeypatch):
    monkeypatch.setattr(
        dns_mod, "try_zone_transfer",
        lambda domain: dns_mod.ZoneTransferResult(ok=False, reason="stub"),
    )
    result = dns_mod.enumerate_dns("example.com", wordlist_path="/nonexistent/path.txt")
    assert result.ok is True
    assert result.subdomains == {}


def test_discover_subdomains_async_fallback(monkeypatch):
    import dns.asyncresolver

    async def boom(fqdn, rtype):
        raise RuntimeError("no async resolver")

    monkeypatch.setattr(dns.asyncresolver, "resolve", boom)
    monkeypatch.setattr(dns_mod, "resolve_host", lambda fqdn: "5.5.5.5")
    out = asyncio.run(dns_mod.discover_subdomains_async("example.com", ["www", "mail"]))
    assert out == {"www.example.com": "5.5.5.5", "mail.example.com": "5.5.5.5"}
