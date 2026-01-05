from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


# -----------------
# Common helpers
# -----------------


def to_dict(obj: Any) -> Any:
    if hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
        return obj.to_dict()
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    return obj


# -----------------
# Recon
# -----------------


@dataclass
class NmapResult:
    ok: bool
    output: str = ""
    open_tcp: List[int] = field(default_factory=list)
    open_udp: List[int] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReconResult:
    target: str
    ip: Optional[str] = None
    nmap: Optional[NmapResult] = None
    banners: Dict[int, Optional[str]] = field(default_factory=dict)
    fingerprint: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # normalize int keys for JSON
        d["banners"] = {str(k): v for k, v in (self.banners or {}).items()}
        return d


# -----------------
# DNS
# -----------------


@dataclass
class ZoneTransferResult:
    ok: bool
    nameservers: List[str] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DnsResultTyped:
    subdomains: Dict[str, str] = field(default_factory=dict)
    reverse: Dict[str, str] = field(default_factory=dict)
    zone_transfer: Optional[ZoneTransferResult] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.zone_transfer is not None:
            d["zone_transfer"] = self.zone_transfer.to_dict()
        return d


# -----------------
# Web
# -----------------


@dataclass
class WebFormField:
    name: Optional[str]
    type: Optional[str]
    value: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WebForm:
    action: Optional[str]
    method: str
    inputs: List[WebFormField] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method,
            "inputs": [i.to_dict() for i in self.inputs],
        }


@dataclass
class WebFetchResult:
    headers: Dict[str, str] = field(default_factory=dict)
    forms: List[WebForm] = field(default_factory=list)
    js: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "headers": dict(self.headers),
            "forms": [f.to_dict() for f in self.forms],
            "js": list(self.js),
        }


@dataclass
class TechFingerprint:
    ok: bool
    server: Optional[str] = None
    x_powered_by: Optional[str] = None
    cookies: List[str] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SitemapDiscovery:
    robots_url: str
    sitemap_xml_url: str
    robots_sitemaps: List[str] = field(default_factory=list)
    sitemap_xml_locs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CrawlResult:
    base: str
    count: int
    links: List[str] = field(default_factory=list)
    sitemaps: Optional[SitemapDiscovery] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.sitemaps is not None:
            d["sitemaps"] = self.sitemaps.to_dict()
        return d


@dataclass
class WebResult:
    ok: bool = True
    fetch: Optional[WebFetchResult] = None
    tech: Optional[TechFingerprint] = None
    sitemap: Optional[CrawlResult] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "error": self.error,
            "headers": {} if self.fetch is None else self.fetch.headers,
            "forms": [] if self.fetch is None else [f.to_dict() for f in self.fetch.forms],
            "js": [] if self.fetch is None else list(self.fetch.js),
            "tech": None if self.tech is None else self.tech.to_dict(),
            "sitemap": None if self.sitemap is None else self.sitemap.to_dict(),
        }


# -----------------
# Secrets
# -----------------


@dataclass
class SecretsSummary:
    count: int
    by_kind: Dict[str, int] = field(default_factory=dict)
    max_risk: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# -----------------
# Privesc
# -----------------


@dataclass
class PrivescScore:
    score: int
    level: str
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PrivescResult:
    raw: Dict[str, Any] = field(default_factory=dict)
    score: Optional[PrivescScore] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw": dict(self.raw),
            "score": None if self.score is None else self.score.to_dict(),
        }
