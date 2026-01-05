import argparse
import asyncio
import csv
import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional

from pathlib import Path

import requests
from bs4 import BeautifulSoup

from .http import HttpClient
from .async_http import AsyncHttpClient
from .models import (
    CrawlResult,
    SitemapDiscovery,
    TechFingerprint,
    WebFetchResult,
    WebForm,
    WebFormField,
    WebResult,
)
from .utils import setup_logger


HTML_PARSER = "html.parser"


logger = setup_logger()


def _normalize_target(target: str) -> str:
    return target if target.startswith("http://") or target.startswith("https://") else "http://" + target


def canonicalize_url(url: str) -> str:
    """Canonicalize a URL for dedupe purposes (best-effort)."""

    try:
        u = urllib.parse.urlsplit(url)
        scheme = (u.scheme or "http").lower()
        netloc = u.netloc.lower()
        path = u.path or "/"
        query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(u.query, keep_blank_values=True)))
        # drop fragments
        return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))
    except Exception:
        return url


class WebScanner:
    def __init__(self, target, wordlist=None):
        self.target = _normalize_target(target)
        self.wordlist = wordlist
        self.visited = set()
        self.found_links = []
        self.session = requests.Session()

    # ---------------- CRAWLER ----------------
    def crawl(self, depth=2):
        logger.info("Crawling %s (depth=%s)", self.target, depth)
        self._crawl(self.target, depth)

    def _crawl(self, url, depth):
        if depth == 0 or url in self.visited:
            return
        try:
            resp = self.session.get(url, timeout=5)
            self.visited.add(url)
            soup = BeautifulSoup(resp.text, HTML_PARSER)
            for link in soup.find_all("a", href=True):
                abs_url = urllib.parse.urljoin(url, link["href"])
                if self.target in abs_url and abs_url not in self.visited:
                    self.found_links.append(abs_url)
                    logger.info("[link] %s", abs_url)
                    self._crawl(abs_url, depth - 1)
        except Exception as e:
            logger.warning("Crawl error: %s", e)

    # ---------------- DIRECTORY BRUTEFORCE ----------------
    def dir_bruteforce(self):
        if not self.wordlist:
            logger.warning("No wordlist provided for directory brute force")
            return
        logger.info("Directory brute force on %s", self.target)
        with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                path = line.strip()
                url = urllib.parse.urljoin(self.target, path)
                try:
                    r = self.session.get(url, timeout=3)
                    if r.status_code == 200:
                        logger.info("[dir] %s (%s)", url, r.status_code)
                except Exception:
                    pass

    # ---------------- PARAMETER DISCOVERY ----------------
    def param_discovery(self, params=["id", "page", "q", "file"]):
        logger.info("Parameter discovery on %s", self.target)
        for p in params:
            url = f"{self.target}?{p}=test"
            try:
                r = self.session.get(url, timeout=3)
                if r.status_code == 200:
                    logger.info("[param] %s -> %s bytes", url, len(r.text))
            except Exception:
                pass

    # ---------------- HEADER ANALYSIS ----------------
    def analyze_headers(self):
        logger.info("Analyzing headers for %s", self.target)
        try:
            r = self.session.get(self.target, timeout=5)
            for h, v in r.headers.items():
                logger.info("%s: %s", h, v)
            missing = []
            for sec in [
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Strict-Transport-Security",
            ]:
                if sec not in r.headers:
                    missing.append(sec)
            if missing:
                logger.warning("Missing security headers: %s", ", ".join(missing))
        except Exception as e:
            logger.warning("Header analysis failed: %s", e)

    # ---------------- BASIC VULN CHECKS ----------------
    def check_xss(self, param="q"):
        logger.info("Testing for XSS on param %s", param)
        payload = "<script>alert(1)</script>"
        url = f"{self.target}?{param}={payload}"
        try:
            r = self.session.get(url, timeout=5)
            if payload in r.text:
                logger.warning("[VULN] Reflected XSS at %s", url)
        except Exception:
            pass

    def check_sqli(self, param="id"):
        logger.info("Testing for SQLi on param %s", param)
        payloads = ["'", "' OR '1'='1", '" OR "1"="1']
        for p in payloads:
            url = f"{self.target}?{param}={p}"
            try:
                r = self.session.get(url, timeout=5)
                if re.search(r"(SQL|syntax|database|mysql|odbc)", r.text, re.I):
                    logger.warning("[VULN] Possible SQLi at %s", url)
            except Exception:
                pass

    def check_lfi(self, param="file"):
        logger.info("Testing for LFI on param %s", param)
        payloads = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
        for p in payloads:
            url = f"{self.target}?{param}={p}"
            try:
                r = self.session.get(url, timeout=5)
                if "root:" in r.text or "[extensions]" in r.text:
                    logger.warning("[VULN] LFI at %s", url)
            except Exception:
                pass


# ----------------
# README-compatible functional API
# ----------------

def fetch_headers(url: str, *, timeout: int = 5, session: Optional[requests.Session] = None) -> Dict[str, str]:
    """Fetch and return response headers (README: web.fetch_headers())."""

    s = session or requests.Session()
    r = s.get(_normalize_target(url), timeout=timeout)
    return dict(r.headers)


def fetch_headers_http(url: str, *, client: HttpClient, timeout: int = 5) -> Dict[str, str]:
    r = client.get(_normalize_target(url), timeout=timeout)
    return dict(r.headers)


def fetch_forms(url: str, *, timeout: int = 5, session: Optional[requests.Session] = None) -> List[WebForm]:
    """Fetch a page and extract HTML forms (README: web.fetch_forms())."""

    s = session or requests.Session()
    r = s.get(_normalize_target(url), timeout=timeout)
    soup = BeautifulSoup(r.text, HTML_PARSER)
    forms: List[WebForm] = []

    for form in soup.find_all("form"):
        action = form.get("action")
        method = (form.get("method") or "GET").upper()
        inputs: List[WebFormField] = []
        for i in form.find_all(["input", "textarea", "select"]):
            inputs.append(WebFormField(name=i.get("name"), type=i.get("type"), value=i.get("value")))
        forms.append(WebForm(action=action, method=method, inputs=inputs))

    return forms


def fetch_forms_http(url: str, *, client: HttpClient, timeout: int = 5) -> List[WebForm]:
    r = client.get(_normalize_target(url), timeout=timeout)
    soup = BeautifulSoup(r.text, HTML_PARSER)
    forms: List[WebForm] = []

    for form in soup.find_all("form"):
        action = form.get("action")
        method = (form.get("method") or "GET").upper()
        inputs: List[WebFormField] = []
        for i in form.find_all(["input", "textarea", "select"]):
            inputs.append(WebFormField(name=i.get("name"), type=i.get("type"), value=i.get("value")))
        forms.append(WebForm(action=action, method=method, inputs=inputs))

    return forms


def fetch_js(url: str, *, timeout: int = 5, session: Optional[requests.Session] = None) -> List[str]:
    """Fetch a page and return referenced JS URLs (README: web.fetch_js())."""

    s = session or requests.Session()
    base = _normalize_target(url)
    r = s.get(base, timeout=timeout)
    soup = BeautifulSoup(r.text, HTML_PARSER)

    scripts: List[str] = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            scripts.append(urllib.parse.urljoin(base, src))

    return scripts


def fetch_js_http(url: str, *, client: HttpClient, timeout: int = 5) -> List[str]:
    base = _normalize_target(url)
    r = client.get(base, timeout=timeout)
    soup = BeautifulSoup(r.text, HTML_PARSER)

    scripts: List[str] = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            scripts.append(urllib.parse.urljoin(base, src))

    return scripts


def fetch_all(url: str, *, timeout: int = 5, client: Optional[HttpClient] = None) -> WebFetchResult:
    """Convenience wrapper used in README (web.fetch_all()).

    If client is provided, uses the shared HttpClient options (timeout, verify, proxies, retries).
    """

    if client is not None:
        return WebFetchResult(
            headers=fetch_headers_http(url, timeout=timeout, client=client),
            forms=fetch_forms_http(url, timeout=timeout, client=client),
            js=fetch_js_http(url, timeout=timeout, client=client),
        )

    s = requests.Session()
    return WebFetchResult(
        headers=fetch_headers(url, timeout=timeout, session=s),
        forms=fetch_forms(url, timeout=timeout, session=s),
        js=fetch_js(url, timeout=timeout, session=s),
    )


def fetch_all_dict(url: str, *, timeout: int = 5, client: Optional[HttpClient] = None) -> Dict[str, Any]:
    return fetch_all(url, timeout=timeout, client=client).to_dict()


async def fetch_all_async(url: str, *, client: Optional[AsyncHttpClient] = None) -> WebFetchResult:
    """Async version of fetch_all() using AsyncHttpClient (aiohttp)."""

    base = _normalize_target(url)
    if client is None:
        async with AsyncHttpClient() as c:
            return await fetch_all_async(base, client=c)

    r = await client.get(base)
    headers = dict(r.headers)
    soup = BeautifulSoup(r.text, HTML_PARSER)

    forms: List[Dict[str, Any]] = []
    for form in soup.find_all("form"):
        action = form.get("action")
        method = (form.get("method") or "GET").upper()
        inputs: List[WebFormField] = []
        for i in form.find_all(["input", "textarea", "select"]):
            inputs.append(WebFormField(name=i.get("name"), type=i.get("type"), value=i.get("value")))
        forms.append(WebForm(action=action, method=method, inputs=inputs))

    scripts: List[str] = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            scripts.append(urllib.parse.urljoin(base, src))

    return WebFetchResult(headers=headers, forms=forms, js=scripts)


async def fetch_all_async_dict(url: str, *, client: Optional[AsyncHttpClient] = None) -> Dict[str, Any]:
    return (await fetch_all_async(url, client=client)).to_dict()


def crawl(url: str, *, depth: int = 2, client: Optional[HttpClient] = None, timeout: int = 5) -> CrawlResult:
    """Best-effort crawler returning a simple sitemap-like output."""

    base = _normalize_target(url)

    def fetch_text(u: str) -> str:
        if client is not None:
            return client.get(u, timeout=timeout).text
        return requests.get(u, timeout=timeout).text

    found = _crawl_collect(base, depth, fetch_text)
    sitemaps = discover_sitemaps(base, client=client, timeout=timeout)
    return CrawlResult(base=base, count=len(found), links=found, sitemaps=sitemaps)


def crawl_dict(url: str, *, depth: int = 2, client: Optional[HttpClient] = None, timeout: int = 5) -> Dict[str, Any]:
    return crawl(url, depth=depth, client=client, timeout=timeout).to_dict()


async def crawl_async(
    url: str,
    *,
    depth: int = 2,
    client: Optional[AsyncHttpClient] = None,
) -> CrawlResult:
    """Async crawler returning sitemap-like output."""

    base = _normalize_target(url)
    if client is None:
        async with AsyncHttpClient() as c:
            return await crawl_async(base, depth=depth, client=c)

    async def fetch_text(u: str) -> str:
        r = await client.get(u)
        return r.text

    max_conc = int(getattr(client.options, "max_concurrency", 20)) if client is not None else 20
    found = await _crawl_collect_async(base, depth, fetch_text, max_concurrency=max_conc)
    sitemaps = await discover_sitemaps_async(base, client=client)
    return CrawlResult(base=base, count=len(found), links=found, sitemaps=sitemaps)


async def crawl_async_dict(
    url: str,
    *,
    depth: int = 2,
    client: Optional[AsyncHttpClient] = None,
) -> Dict[str, Any]:
    return (await crawl_async(url, depth=depth, client=client)).to_dict()


def _take_crawl_batch(
    queue: List[tuple[str, int]],
    visited: set[str],
    *,
    batch_size: int,
) -> List[tuple[str, int]]:
    batch: List[tuple[str, int]] = []
    while queue and len(batch) < batch_size:
        current, d = queue.pop(0)
        if d < 0 or current in visited:
            continue
        visited.add(current)
        batch.append((current, d))
    return batch


async def _fetch_batch(fetcher, urls: List[str]) -> List[tuple[str, Optional[str]]]:
    async def fetch_one(u: str):
        try:
            return u, await fetcher(u)
        except Exception:
            return u, None

    return await asyncio.gather(*(fetch_one(u) for u in urls))


async def _crawl_collect_async(base: str, depth: int, fetcher, *, max_concurrency: int) -> List[str]:
    visited: set[str] = set()
    found: List[str] = []
    queue: List[tuple[str, int]] = [(canonicalize_url(base), depth)]

    batch_size = max(1, int(max_concurrency or 1))

    while queue:
        batch = _take_crawl_batch(queue, visited, batch_size=batch_size)
        if not batch:
            continue

        pages = await _fetch_batch(fetcher, [u for u, _d in batch])
        depth_by_url = dict(batch)

        _process_crawled_pages(base, pages, depth_by_url, visited, found, queue)

    return sorted(set(found))


def _process_crawled_pages(
    base: str,
    pages: List[tuple[str, Optional[str]]],
    depth_by_url: Dict[str, int],
    visited: set[str],
    found: List[str],
    queue: List[tuple[str, int]],
) -> None:
    for page_url, html in pages:
        if not html:
            continue
        d = depth_by_url.get(page_url, 0)
        for link in _extract_links(base, page_url, html):
            if link in visited:
                continue
            found.append(link)
            queue.append((link, d - 1))


def _crawl_collect(base: str, depth: int, fetcher) -> List[str]:
    visited: set[str] = set()
    found: List[str] = []
    queue: List[tuple[str, int]] = [(canonicalize_url(base), depth)]

    while queue:
        current, d = queue.pop(0)
        if d < 0 or current in visited:
            continue
        visited.add(current)

        try:
            html = fetcher(current)
        except Exception:
            continue

        for link in _extract_links(base, current, html):
            if link in visited:
                continue
            found.append(link)
            queue.append((link, d - 1))

    return sorted(set(found))


def _extract_links(base: str, page_url: str, html: str) -> List[str]:
    soup = BeautifulSoup(html, HTML_PARSER)
    out: List[str] = []
    for a in soup.find_all("a", href=True):
        abs_url = urllib.parse.urljoin(page_url, a["href"])
        abs_url = canonicalize_url(abs_url)
        if abs_url.startswith(canonicalize_url(base)):
            out.append(abs_url)
    return out


def discover_sitemaps(url: str, *, client: Optional[HttpClient] = None, timeout: int = 5) -> SitemapDiscovery:
    """Discover sitemap URLs via robots.txt and /sitemap.xml (read-only)."""

    base = _normalize_target(url)
    robots_url = urllib.parse.urljoin(base, "/robots.txt")
    sitemap_url = urllib.parse.urljoin(base, "/sitemap.xml")

    robots_text = _fetch_text(robots_url, client=client, timeout=timeout)
    robots_sitemaps = _parse_robots_sitemaps(robots_text, base) if robots_text else []

    sitemap_text = _fetch_text(sitemap_url, client=client, timeout=timeout)
    sitemap_locs = _parse_sitemap_xml_locs(sitemap_text) if sitemap_text else []

    return SitemapDiscovery(
        robots_url=robots_url,
        sitemap_xml_url=sitemap_url,
        robots_sitemaps=sorted(set(robots_sitemaps)),
        sitemap_xml_locs=sorted(set(sitemap_locs)),
    )


def discover_sitemaps_dict(url: str, *, client: Optional[HttpClient] = None, timeout: int = 5) -> Dict[str, Any]:
    return discover_sitemaps(url, client=client, timeout=timeout).to_dict()


async def discover_sitemaps_async(url: str, *, client: Optional[AsyncHttpClient] = None) -> SitemapDiscovery:
    base = _normalize_target(url)
    if client is None:
        async with AsyncHttpClient() as c:
            return await discover_sitemaps_async(base, client=c)

    robots_url = urllib.parse.urljoin(base, "/robots.txt")
    sitemap_url = urllib.parse.urljoin(base, "/sitemap.xml")

    robots_text = await _fetch_text_async(robots_url, client=client)
    robots_sitemaps = _parse_robots_sitemaps(robots_text, base) if robots_text else []

    sitemap_text = await _fetch_text_async(sitemap_url, client=client)
    sitemap_locs = _parse_sitemap_xml_locs(sitemap_text) if sitemap_text else []

    return SitemapDiscovery(
        robots_url=robots_url,
        sitemap_xml_url=sitemap_url,
        robots_sitemaps=sorted(set(robots_sitemaps)),
        sitemap_xml_locs=sorted(set(sitemap_locs)),
    )


async def discover_sitemaps_async_dict(url: str, *, client: Optional[AsyncHttpClient] = None) -> Dict[str, Any]:
    return (await discover_sitemaps_async(url, client=client)).to_dict()


def export_sitemap_json(base: str, links: List[str], path: str) -> None:
    Path(path).write_text(json.dumps({"base": base, "count": len(links), "links": links}, indent=2), encoding="utf-8")


def export_sitemap_csv(base: str, links: List[str], path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["base", base])
        w.writerow(["url"])
        for u in links:
            w.writerow([u])


def _fetch_text(url: str, *, client: Optional[HttpClient], timeout: int) -> Optional[str]:
    try:
        if client is not None:
            return client.get(url, timeout=timeout).text
        return requests.get(url, timeout=timeout).text
    except Exception:
        return None


async def _fetch_text_async(url: str, *, client: AsyncHttpClient) -> Optional[str]:
    try:
        r = await client.get(url)
        return r.text
    except Exception:
        return None


def _parse_robots_sitemaps(text: str, base: str) -> List[str]:
    out: List[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("sitemap:"):
            val = line.split(":", 1)[1].strip()
            out.append(canonicalize_url(urllib.parse.urljoin(base, val)))
    return out


def _parse_sitemap_xml_locs(text: str) -> List[str]:
    try:
        import xml.etree.ElementTree as ET

        root = ET.fromstring(text)
        out: List[str] = []
        for el in root.iter():
            if el.tag.lower().endswith("loc") and el.text:
                out.append(canonicalize_url(el.text.strip()))
        return out
    except Exception:
        return []


def fingerprint_tech(url: str, *, client: Optional[HttpClient] = None, timeout: int = 5) -> TechFingerprint:
    """Very lightweight tech hints from headers/body markers."""

    base = _normalize_target(url)

    try:
        r = client.get(base, timeout=timeout) if client is not None else requests.get(base, timeout=timeout)
    except Exception as e:
        return TechFingerprint(ok=False, error=str(e))

    headers = {k.lower(): v for k, v in r.headers.items()}
    body = (r.text or "").lower()

    server = headers.get("server")
    powered_by = headers.get("x-powered-by")
    set_cookie = headers.get("set-cookie", "")

    hints = _tech_hints(headers=headers, body=body)
    cookies = _cookie_names(set_cookie)

    return TechFingerprint(ok=True, server=server, x_powered_by=powered_by, cookies=cookies, hints=hints)


def fingerprint_tech_dict(url: str, *, client: Optional[HttpClient] = None, timeout: int = 5) -> Dict[str, Any]:
    return fingerprint_tech(url, client=client, timeout=timeout).to_dict()


async def fingerprint_tech_async(url: str, *, client: Optional[AsyncHttpClient] = None) -> TechFingerprint:
    """Async version of fingerprint_tech() using AsyncHttpClient."""

    base = _normalize_target(url)
    if client is None:
        async with AsyncHttpClient() as c:
            return await fingerprint_tech_async(base, client=c)

    try:
        r = await client.get(base)
    except Exception as e:
        return TechFingerprint(ok=False, error=str(e))

    headers = {k.lower(): v for k, v in (r.headers or {}).items()}
    body = (r.text or "").lower()

    server = headers.get("server")
    powered_by = headers.get("x-powered-by")
    set_cookie = headers.get("set-cookie", "")

    hints = _tech_hints(headers=headers, body=body)
    cookies = _cookie_names(set_cookie)

    return TechFingerprint(ok=True, server=server, x_powered_by=powered_by, cookies=cookies, hints=hints)


async def fingerprint_tech_async_dict(url: str, *, client: Optional[AsyncHttpClient] = None) -> Dict[str, Any]:
    return (await fingerprint_tech_async(url, client=client)).to_dict()


def scan(url: str, *, client: Optional[HttpClient] = None, timeout: int = 5, depth: int = 2) -> WebResult:
    try:
        fetch = fetch_all(url, timeout=timeout, client=client)
        tech = fingerprint_tech(url, timeout=timeout, client=client)
        sitemap = crawl(url, depth=depth, client=client, timeout=timeout)
        return WebResult(ok=True, fetch=fetch, tech=tech, sitemap=sitemap)
    except Exception as e:
        return WebResult(ok=False, error=str(e))


async def scan_async(url: str, *, client: Optional[AsyncHttpClient] = None, depth: int = 2) -> WebResult:
    base = _normalize_target(url)
    if client is None:
        async with AsyncHttpClient() as c:
            return await scan_async(base, client=c, depth=depth)
    try:
        fetch, tech, sitemap = await asyncio.gather(
            fetch_all_async(base, client=client),
            fingerprint_tech_async(base, client=client),
            crawl_async(base, depth=depth, client=client),
        )
        return WebResult(ok=True, fetch=fetch, tech=tech, sitemap=sitemap)
    except Exception as e:
        return WebResult(ok=False, error=str(e))


def _cookie_names(set_cookie: str) -> List[str]:
    if not set_cookie:
        return []
    out: List[str] = []
    for part in set_cookie.split(","):
        c = part.strip().split(";", 1)[0]
        if "=" in c:
            out.append(c.split("=", 1)[0].strip())
    return sorted(set(out))


def _tech_hints(*, headers: Dict[str, str], body: str) -> List[str]:
    hints: List[str] = []
    if "wordpress" in body or "wp-content" in body:
        hints.append("wordpress")
    if "drupal" in body and ("drupal.settings" in body or "sites/all" in body):
        hints.append("drupal")
    if "csrfmiddlewaretoken" in body:
        hints.append("django")
    if "laravel" in body or "x-laravel" in body:
        hints.append("laravel")

    hints.extend(_tech_from_headers(headers))
    return sorted(set(hints))


def _tech_from_headers(headers: Dict[str, str]) -> List[str]:
    server = (headers.get("server") or "").lower()
    powered_by = (headers.get("x-powered-by") or "").lower()
    out: List[str] = []

    # Common servers
    if "nginx" in server:
        out.append("nginx")
    if "apache" in server or "httpd" in server:
        out.append("apache")
    if "caddy" in server:
        out.append("caddy")
    if "cloudflare" in server:
        out.append("cloudflare")
    if "gunicorn" in server:
        out.append("gunicorn")
    if "uvicorn" in server:
        out.append("uvicorn")

    # Framework hints
    if "express" in powered_by:
        out.append("express")
    if "php" in powered_by:
        out.append("php")
    if "asp.net" in powered_by:
        out.append("asp.net")
    if "django" in powered_by:
        out.append("django")

    return out


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="hwat-web", description="hwatlib web enumeration helpers")
    parser.add_argument("url", help="Target URL")
    args = parser.parse_args(argv)

    result = fetch_all(args.url)
    print("[headers]")
    for k, v in result.headers.items():
        print(f"{k}: {v}")

    print("\n[forms]")
    for form in result.forms:
        print(form.to_dict())

    print("\n[js]")
    for js in result.js:
        print(js)

    return 0
