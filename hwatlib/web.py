import argparse
import asyncio
import csv
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

import defusedxml.ElementTree as ET
import requests
from bs4 import BeautifulSoup

from . import techrules
from .async_http import AsyncHttpClient
from .http import HttpClient
from .models import (
    CrawlResult,
    DirBruteResult,
    DirEntry,
    SitemapDiscovery,
    TechFingerprint,
    WebFetchResult,
    WebForm,
    WebFormField,
    WebResult,
)
from .utils import authorized_use_banner, get_logger, setup_logger

HTML_PARSER = "html.parser"


logger = get_logger()


def _normalize_target(target: str) -> str:
    return target if target.startswith("http://") or target.startswith("https://") else "http://" + target


def _attr_str(value: Any) -> Optional[str]:
    """Coerce a BeautifulSoup attribute value to Optional[str].

    Multi-valued attributes (e.g. ``class``) are returned by bs4 as a list;
    join them so callers always get a plain string or None.
    """
    if value is None or isinstance(value, str):
        return value
    return " ".join(str(v) for v in value)


def _parse_forms_from_html(html: str) -> List[WebForm]:
    soup = BeautifulSoup(html or "", HTML_PARSER)
    forms: List[WebForm] = []
    for form in soup.find_all("form"):
        action = _attr_str(form.get("action"))
        method = (_attr_str(form.get("method")) or "GET").upper()
        inputs: List[WebFormField] = []
        for i in form.find_all(["input", "textarea", "select"]):
            inputs.append(
                WebFormField(
                    name=_attr_str(i.get("name")),
                    type=_attr_str(i.get("type")),
                    value=_attr_str(i.get("value")),
                )
            )
        forms.append(WebForm(action=action, method=method, inputs=inputs))
    return forms


def _extract_script_urls(base: str, html: str) -> List[str]:
    soup = BeautifulSoup(html or "", HTML_PARSER)
    scripts: List[str] = []
    for tag in soup.find_all("script"):
        src = _attr_str(tag.get("src"))
        if src:
            scripts.append(urllib.parse.urljoin(base, src))
    return scripts


def _build_web_fetch_result(base: str, headers: Mapping[str, Any], html: str) -> WebFetchResult:
    return WebFetchResult(
        headers={str(k): str(v) for k, v in (headers or {}).items()},
        forms=_parse_forms_from_html(html),
        js=_extract_script_urls(base, html),
    )


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
    except ValueError as e:
        logger.debug("URL canonicalization failed url=%s error=%s", url, e)
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
        except requests.RequestException as e:
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
                except requests.RequestException as e:
                    logger.debug("Dir bruteforce request failed url=%s error=%s", url, e)

    # ---------------- PARAMETER DISCOVERY ----------------
    def param_discovery(self, params: Optional[List[str]] = None):
        logger.info("Parameter discovery on %s", self.target)
        scan_params = params if params is not None else ["id", "page", "q", "file"]
        for p in scan_params:
            url = f"{self.target}?{p}=test"
            try:
                r = self.session.get(url, timeout=3)
                if r.status_code == 200:
                    logger.info("[param] %s -> %s bytes", url, len(r.text))
            except requests.RequestException as e:
                logger.debug("Param discovery request failed url=%s error=%s", url, e)

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
        except requests.RequestException as e:
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
        except requests.RequestException as e:
            logger.debug("XSS check request failed url=%s error=%s", url, e)

    def check_sqli(self, param="id"):
        logger.info("Testing for SQLi on param %s", param)
        payloads = ["'", "' OR '1'='1", '" OR "1"="1']
        for p in payloads:
            url = f"{self.target}?{param}={p}"
            try:
                r = self.session.get(url, timeout=5)
                if re.search(r"(SQL|syntax|database|mysql|odbc)", r.text, re.I):
                    logger.warning("[VULN] Possible SQLi at %s", url)
            except requests.RequestException as e:
                logger.debug("SQLi check request failed url=%s error=%s", url, e)

    def check_lfi(self, param="file"):
        logger.info("Testing for LFI on param %s", param)
        payloads = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
        for p in payloads:
            url = f"{self.target}?{param}={p}"
            try:
                r = self.session.get(url, timeout=5)
                if "root:" in r.text or "[extensions]" in r.text:
                    logger.warning("[VULN] LFI at %s", url)
            except requests.RequestException as e:
                logger.debug("LFI check request failed url=%s error=%s", url, e)


# ----------------
# README-compatible functional API
# ----------------

def fetch_headers(url: str, *, timeout: float = 5, session: Optional[requests.Session] = None) -> Dict[str, str]:
    """Fetch and return response headers (README: web.fetch_headers())."""

    s = session or requests.Session()
    r = s.get(_normalize_target(url), timeout=timeout)
    return dict(r.headers)


def fetch_headers_http(url: str, *, client: HttpClient, timeout: float = 5) -> Dict[str, str]:
    r = client.get(_normalize_target(url), timeout=timeout)
    return dict(r.headers)


def fetch_forms(url: str, *, timeout: float = 5, session: Optional[requests.Session] = None) -> List[WebForm]:
    """Fetch a page and extract HTML forms (README: web.fetch_forms())."""

    s = session or requests.Session()
    r = s.get(_normalize_target(url), timeout=timeout)
    return _parse_forms_from_html(r.text)


def fetch_forms_http(url: str, *, client: HttpClient, timeout: float = 5) -> List[WebForm]:
    r = client.get(_normalize_target(url), timeout=timeout)
    return _parse_forms_from_html(r.text)


def fetch_js(url: str, *, timeout: float = 5, session: Optional[requests.Session] = None) -> List[str]:
    """Fetch a page and return referenced JS URLs (README: web.fetch_js())."""

    s = session or requests.Session()
    base = _normalize_target(url)
    r = s.get(base, timeout=timeout)
    return _extract_script_urls(base, r.text)


def fetch_js_http(url: str, *, client: HttpClient, timeout: float = 5) -> List[str]:
    base = _normalize_target(url)
    r = client.get(base, timeout=timeout)
    return _extract_script_urls(base, r.text)


def fetch_all(url: str, *, timeout: float = 5, client: Optional[HttpClient] = None) -> WebFetchResult:
    """Convenience wrapper used in README (web.fetch_all()).

    If client is provided, uses the shared HttpClient options (timeout, verify, proxies, retries).
    """

    base = _normalize_target(url)
    if client is not None:
        r = client.get(base, timeout=timeout)
        return _build_web_fetch_result(base, r.headers, r.text)

    s = requests.Session()
    r = s.get(base, timeout=timeout)
    return _build_web_fetch_result(base, r.headers, r.text)


def fetch_all_dict(url: str, *, timeout: float = 5, client: Optional[HttpClient] = None) -> Dict[str, Any]:
    return fetch_all(url, timeout=timeout, client=client).to_dict()


async def fetch_all_async(url: str, *, client: Optional[AsyncHttpClient] = None) -> WebFetchResult:
    """Async version of fetch_all() using AsyncHttpClient (aiohttp)."""

    base = _normalize_target(url)
    if client is None:
        async with AsyncHttpClient() as c:
            return await fetch_all_async(base, client=c)

    r = await client.get(base)
    return _build_web_fetch_result(base, r.headers, r.text)


async def fetch_all_async_dict(url: str, *, client: Optional[AsyncHttpClient] = None) -> Dict[str, Any]:
    return (await fetch_all_async(url, client=client)).to_dict()


def crawl(url: str, *, depth: int = 2, client: Optional[HttpClient] = None, timeout: float = 5) -> CrawlResult:
    """Best-effort crawler returning a simple sitemap-like output."""

    base = _normalize_target(url)

    def fetch_text(u: str) -> str:
        if client is not None:
            return client.get(u, timeout=timeout).text
        return requests.get(u, timeout=timeout).text

    found = _crawl_collect(base, depth, fetch_text)
    sitemaps = discover_sitemaps(base, client=client, timeout=timeout)
    return CrawlResult(base=base, count=len(found), links=found, sitemaps=sitemaps)


def crawl_dict(url: str, *, depth: int = 2, client: Optional[HttpClient] = None, timeout: float = 5) -> Dict[str, Any]:
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
        except Exception as e:
            logger.debug("Async crawl fetch failed url=%s error=%s", u, e)
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
        except requests.RequestException as e:
            logger.debug("Crawl fetch failed url=%s error=%s", current, e)
            continue
        except Exception as e:
            logger.debug("Crawl fetcher failed url=%s error=%s", current, e)
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
        href = _attr_str(a.get("href"))
        if href is None:
            continue
        abs_url = urllib.parse.urljoin(page_url, href)
        abs_url = canonicalize_url(abs_url)
        if abs_url.startswith(canonicalize_url(base)):
            out.append(abs_url)
    return out


def discover_sitemaps(url: str, *, client: Optional[HttpClient] = None, timeout: float = 5) -> SitemapDiscovery:
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


def discover_sitemaps_dict(url: str, *, client: Optional[HttpClient] = None, timeout: float = 5) -> Dict[str, Any]:
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


def _fetch_text(url: str, *, client: Optional[HttpClient], timeout: float) -> Optional[str]:
    try:
        if client is not None:
            return client.get(url, timeout=timeout).text
        return requests.get(url, timeout=timeout).text
    except requests.RequestException as e:
        logger.debug("Failed fetching text url=%s error=%s", url, e)
        return None
    except Exception as e:
        logger.debug("Unexpected fetch_text error url=%s error=%s", url, e)
        return None


async def _fetch_text_async(url: str, *, client: AsyncHttpClient) -> Optional[str]:
    try:
        r = await client.get(url)
        return r.text
    except Exception as e:
        logger.debug("Failed fetching async text url=%s error=%s", url, e)
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
        root = ET.fromstring(text)
        out: List[str] = []
        for el in root.iter():
            if el.tag.lower().endswith("loc") and el.text:
                out.append(canonicalize_url(el.text.strip()))
        return out
    except ET.ParseError as e:
        logger.debug("Sitemap XML parse failed error=%s", e)
        return []
    except Exception as e:
        logger.debug("Unexpected sitemap parsing error=%s", e)
        return []


def fingerprint_tech(url: str, *, client: Optional[HttpClient] = None, timeout: float = 5) -> TechFingerprint:
    """Very lightweight tech hints from headers/body markers."""

    base = _normalize_target(url)

    try:
        r = client.get(base, timeout=timeout) if client is not None else requests.get(base, timeout=timeout)
    except requests.RequestException as e:
        logger.exception("Technology fingerprint request failed url=%s: %s", base, e)
        return TechFingerprint(ok=False, error=str(e))

    headers = {k.lower(): v for k, v in r.headers.items()}
    body = (r.text or "").lower()

    server = headers.get("server")
    powered_by = headers.get("x-powered-by")
    set_cookie = headers.get("set-cookie", "")

    cookies = _cookie_names(set_cookie)
    matches = _detect_tech(headers, cookies, body)

    return TechFingerprint(
        ok=True,
        server=server,
        x_powered_by=powered_by,
        cookies=cookies,
        hints=[m.name for m in matches],
        technologies=[m.to_dict() for m in matches],
    )


def fingerprint_tech_dict(url: str, *, client: Optional[HttpClient] = None, timeout: float = 5) -> Dict[str, Any]:
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
        logger.exception("Async technology fingerprint request failed url=%s: %s", base, e)
        return TechFingerprint(ok=False, error=str(e))

    headers = {k.lower(): v for k, v in (r.headers or {}).items()}
    body = (r.text or "").lower()

    server = headers.get("server")
    powered_by = headers.get("x-powered-by")
    set_cookie = headers.get("set-cookie", "")

    cookies = _cookie_names(set_cookie)
    matches = _detect_tech(headers, cookies, body)

    return TechFingerprint(
        ok=True,
        server=server,
        x_powered_by=powered_by,
        cookies=cookies,
        hints=[m.name for m in matches],
        technologies=[m.to_dict() for m in matches],
    )


async def fingerprint_tech_async_dict(url: str, *, client: Optional[AsyncHttpClient] = None) -> Dict[str, Any]:
    return (await fingerprint_tech_async(url, client=client)).to_dict()


def scan(url: str, *, client: Optional[HttpClient] = None, timeout: float = 5, depth: int = 2) -> WebResult:
    try:
        fetch = fetch_all(url, timeout=timeout, client=client)
        tech = fingerprint_tech(url, timeout=timeout, client=client)
        sitemap = crawl(url, depth=depth, client=client, timeout=timeout)
        return WebResult(ok=True, fetch=fetch, tech=tech, sitemap=sitemap)
    except Exception as e:
        logger.exception("Web scan failed url=%s depth=%s: %s", url, depth, e)
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
        logger.exception("Async web scan failed url=%s depth=%s: %s", base, depth, e)
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


def _detect_tech(headers: Dict[str, str], cookies: List[str], body: str) -> List[techrules.TechMatch]:
    """Run the Wappalyzer-style rule engine over a response."""
    return techrules.detect(headers, cookies, body)


def _tech_hints(*, headers: Dict[str, str], body: str) -> List[str]:
    """Return detected technology names (backwards-compatible hint list)."""
    return [m.name for m in _detect_tech(headers, [], body)]


def _tech_from_headers(headers: Dict[str, str]) -> List[str]:
    """Technology names inferred from response headers alone."""
    return [m.name for m in _detect_tech(headers, [], "")]


# ----------------
# Directory / content brute-forcing
# ----------------

# Status codes that usually indicate a resource worth reporting.
_DIR_INTERESTING = frozenset({200, 201, 202, 203, 204, 301, 302, 307, 308, 401, 403, 405, 500})


def _iter_wordlist(wordlist: Any):
    """Yield stripped words from a file path (str/Path) or an iterable of words."""
    if isinstance(wordlist, (str, Path)):
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                yield line.strip()
    else:
        for word in wordlist:
            yield str(word).strip()


def _candidate_paths(word: str, extensions: Optional[List[str]]) -> List[str]:
    word = word.strip().lstrip("/")
    if not word or word.startswith("#"):
        return []
    paths = [word]
    for ext in extensions or []:
        dotted = ext if ext.startswith(".") else "." + ext
        paths.append(word + dotted)
    return paths


def dir_bruteforce(
    base_url: str,
    wordlist: Any,
    *,
    client: Optional[HttpClient] = None,
    timeout: float = 5,
    extensions: Optional[List[str]] = None,
    status_include: Optional[List[int]] = None,
) -> DirBruteResult:
    """Directory/content brute-force over a wordlist.

    ``wordlist`` may be a file path (str/Path) or an iterable of words. Pass a
    configured ``HttpClient`` (e.g. ``HttpClient(options=HttpOptions(
    rate_limit_per_sec=5))``) to apply rate limiting and retries. Redirects are
    not followed so 30x locations are reported. Returns a typed result.
    """
    base = _normalize_target(base_url).rstrip("/") + "/"
    interesting = frozenset(status_include) if status_include else _DIR_INTERESTING
    http = client if client is not None else HttpClient()

    found: List[DirEntry] = []
    tested = 0
    try:
        for word in _iter_wordlist(wordlist):
            for path in _candidate_paths(word, extensions):
                url = urllib.parse.urljoin(base, path)
                tested += 1
                try:
                    r = http.get(url, timeout=timeout, allow_redirects=False)
                except requests.RequestException as e:
                    logger.debug("Dir brute request failed url=%s error=%s", url, e)
                    continue
                if r.status_code in interesting:
                    found.append(
                        DirEntry(
                            url=url,
                            status=r.status_code,
                            length=len(r.text or ""),
                            redirect=r.headers.get("Location"),
                        )
                    )
        return DirBruteResult(base=base, tested=tested, found=found)
    except OSError as e:
        logger.warning("Dir brute wordlist read failed error=%s", e)
        return DirBruteResult(base=base, tested=tested, found=found, error=str(e))


async def dir_bruteforce_async(
    base_url: str,
    wordlist: Any,
    *,
    client: Optional[AsyncHttpClient] = None,
    extensions: Optional[List[str]] = None,
    status_include: Optional[List[int]] = None,
    max_concurrency: int = 20,
) -> DirBruteResult:
    """Async directory/content brute-force (concurrency via AsyncHttpClient)."""
    base = _normalize_target(base_url).rstrip("/") + "/"
    if client is None:
        async with AsyncHttpClient() as c:
            return await dir_bruteforce_async(
                base, wordlist, client=c, extensions=extensions,
                status_include=status_include, max_concurrency=max_concurrency,
            )

    interesting = frozenset(status_include) if status_include else _DIR_INTERESTING
    try:
        candidates = [
            urllib.parse.urljoin(base, path)
            for word in _iter_wordlist(wordlist)
            for path in _candidate_paths(word, extensions)
        ]
    except OSError as e:
        return DirBruteResult(base=base, tested=0, found=[], error=str(e))

    sem = asyncio.Semaphore(max(1, int(max_concurrency or 1)))

    async def probe(url: str) -> Optional[DirEntry]:
        async with sem:
            try:
                r = await client.get(url)
            except Exception as e:
                logger.debug("Async dir brute request failed url=%s error=%s", url, e)
                return None
            if r.status in interesting:
                return DirEntry(
                    url=url,
                    status=r.status,
                    length=len(r.text or ""),
                    redirect=r.headers.get("location"),
                )
            return None

    results = await asyncio.gather(*(probe(u) for u in candidates))
    found = [e for e in results if e is not None]
    return DirBruteResult(base=base, tested=len(candidates), found=found)


def main(argv: Optional[List[str]] = None) -> int:
    setup_logger()
    authorized_use_banner()
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
