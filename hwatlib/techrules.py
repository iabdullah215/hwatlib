"""Wappalyzer-style passive technology fingerprinting rules.

A small, dependency-free rule engine that infers technologies from HTTP response
headers, cookies, and body markers. Each :class:`TechRule` is data-driven; a
rule is considered a match if **any** of its matcher groups fire:

- ``headers``   — header name -> substring that must appear in that header value
  (an empty string matches on mere presence of the header).
- ``cookies``   — cookie names that must be present.
- ``body_groups`` — an AND of ORs: every inner list must have at least one of its
  substrings present in the (lowercased) body. Lets a rule require several
  independent markers (e.g. Drupal).
- ``meta``      — substring expected in a ``<meta name="generator" ...>`` tag.

Matching is intentionally conservative and read-only; it never sends requests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Mapping

_META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


@dataclass(frozen=True)
class TechRule:
    name: str
    category: str
    headers: Mapping[str, str] = field(default_factory=dict)
    cookies: tuple = ()
    body_groups: tuple = ()  # tuple of tuples of substrings (AND of ORs)
    meta: tuple = ()  # substrings to look for in the generator meta tag
    implies: tuple = ()


@dataclass(frozen=True)
class TechMatch:
    name: str
    category: str

    def to_dict(self) -> Dict[str, str]:
        return {"name": self.name, "category": self.category}


# Category constants (kept short; Wappalyzer-like grouping).
_WEB_SERVER = "web-server"
_CMS = "cms"
_FRAMEWORK = "web-framework"
_LANGUAGE = "programming-language"
_JS = "javascript-framework"
_CDN = "cdn"
_ANALYTICS = "analytics"
_ECOMMERCE = "ecommerce"
_WAF = "security"


# The rule set. Names are lowercase so downstream "hint" strings stay stable.
RULES: List[TechRule] = [
    # --- Web servers (Server header) ---
    TechRule("nginx", _WEB_SERVER, headers={"server": "nginx"}),
    TechRule("apache", _WEB_SERVER, headers={"server": "apache"}),
    TechRule("apache", _WEB_SERVER, headers={"server": "httpd"}),
    TechRule("caddy", _WEB_SERVER, headers={"server": "caddy"}),
    TechRule("iis", _WEB_SERVER, headers={"server": "microsoft-iis"}),
    TechRule("tomcat", _WEB_SERVER, headers={"server": "tomcat"}),
    TechRule("jetty", _WEB_SERVER, headers={"server": "jetty"}),
    TechRule("gunicorn", _WEB_SERVER, headers={"server": "gunicorn"}),
    TechRule("uvicorn", _WEB_SERVER, headers={"server": "uvicorn"}),
    TechRule("werkzeug", _WEB_SERVER, headers={"server": "werkzeug"}, implies=("python",)),
    TechRule("openresty", _WEB_SERVER, headers={"server": "openresty"}, implies=("nginx",)),
    # --- CDN / edge / WAF ---
    TechRule("cloudflare", _CDN, headers={"server": "cloudflare"}),
    TechRule("cloudflare", _CDN, headers={"cf-ray": ""}),
    TechRule("fastly", _CDN, headers={"x-served-by": "fastly"}),
    TechRule("fastly", _CDN, headers={"x-fastly-request-id": ""}),
    TechRule("varnish", _CDN, headers={"via": "varnish"}),
    TechRule("varnish", _CDN, headers={"x-varnish": ""}),
    TechRule("akamai", _CDN, headers={"x-akamai-transformed": ""}),
    TechRule("amazon-s3", _CDN, headers={"server": "amazons3"}),
    TechRule("sucuri", _WAF, headers={"x-sucuri-id": ""}),
    # --- Languages / frameworks via X-Powered-By and cookies ---
    TechRule("php", _LANGUAGE, headers={"x-powered-by": "php"}),
    TechRule("php", _LANGUAGE, cookies=("PHPSESSID",)),
    TechRule("asp.net", _FRAMEWORK, headers={"x-powered-by": "asp.net"}),
    TechRule("asp.net", _FRAMEWORK, headers={"x-aspnet-version": ""}),
    TechRule("asp.net", _FRAMEWORK, cookies=("ASP.NET_SessionId",)),
    TechRule("express", _FRAMEWORK, headers={"x-powered-by": "express"}, implies=("node.js",)),
    TechRule("next.js", _FRAMEWORK, headers={"x-powered-by": "next.js"}, implies=("react", "node.js")),
    TechRule("django", _FRAMEWORK, headers={"x-powered-by": "django"}, implies=("python",)),
    TechRule("django", _FRAMEWORK, cookies=("csrftoken", "django_language"), implies=("python",)),
    TechRule("django", _FRAMEWORK, body_groups=(("csrfmiddlewaretoken",),), implies=("python",)),
    TechRule("laravel", _FRAMEWORK, cookies=("laravel_session", "XSRF-TOKEN"), implies=("php",)),
    TechRule("laravel", _FRAMEWORK, headers={"x-powered-by": "laravel"}, implies=("php",)),
    TechRule("laravel", _FRAMEWORK, body_groups=(("laravel", "x-laravel"),), implies=("php",)),
    TechRule("ruby-on-rails", _FRAMEWORK, headers={"x-powered-by": "phusion passenger"}, implies=("ruby",)),
    TechRule("ruby-on-rails", _FRAMEWORK, cookies=("_rails_session",)),
    TechRule("flask", _FRAMEWORK, cookies=("session",), implies=("python",)),
    # --- CMS / ecommerce ---
    TechRule("wordpress", _CMS, body_groups=(("wordpress", "wp-content", "wp-includes"),), implies=("php",)),
    TechRule("wordpress", _CMS, meta=("wordpress",), implies=("php",)),
    TechRule("drupal", _CMS, body_groups=(("drupal",), ("drupal.settings", "sites/all", "sites/default")), implies=("php",)),
    TechRule("drupal", _CMS, headers={"x-generator": "drupal"}, implies=("php",)),
    TechRule("joomla", _CMS, body_groups=(("joomla",), ("/media/jui", "com_content")), implies=("php",)),
    TechRule("joomla", _CMS, meta=("joomla",), implies=("php",)),
    TechRule("magento", _ECOMMERCE, cookies=("X-Magento-Vary",), implies=("php",)),
    TechRule("magento", _ECOMMERCE, body_groups=(("mage/cookies", "/static/version"),), implies=("php",)),
    TechRule("shopify", _ECOMMERCE, headers={"x-shopify-stage": ""}),
    TechRule("shopify", _ECOMMERCE, body_groups=(("cdn.shopify.com",),)),
    TechRule("wix", _CMS, headers={"x-wix-request-id": ""}),
    TechRule("ghost", _CMS, meta=("ghost",)),
    # --- JS libraries / frameworks (body markers) ---
    TechRule("jquery", _JS, body_groups=(("jquery.js", "jquery.min.js", "/jquery-"),)),
    TechRule("react", _JS, body_groups=(("react.production.min.js", "data-reactroot", "__reactcontainer"),)),
    TechRule("vue.js", _JS, body_groups=(("vue.js", "vue.min.js", "data-v-"),)),
    TechRule("angular", _JS, body_groups=(("ng-version", "ng-app", "angular.js"),)),
    TechRule("bootstrap", _JS, body_groups=(("bootstrap.min.css", "bootstrap.css", "bootstrap.min.js"),)),
    TechRule("gatsby", _JS, body_groups=(("___gatsby", "/page-data/"),), implies=("react",)),
    # --- Analytics ---
    TechRule("google-analytics", _ANALYTICS, body_groups=(("google-analytics.com/analytics.js", "gtag/js", "googletagmanager.com"),)),
    TechRule("hotjar", _ANALYTICS, body_groups=(("static.hotjar.com",),)),
]


def _headers_lower(headers: Mapping[str, object]) -> Dict[str, str]:
    return {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}


def _rule_matches(
    rule: TechRule,
    headers: Dict[str, str],
    cookie_names: List[str],
    body: str,
    meta_generator: str,
) -> bool:
    # Header matchers (any specified header hitting is enough).
    for hname, needle in rule.headers.items():
        value = headers.get(hname.lower())
        if value is not None and (needle == "" or needle.lower() in value):
            return True

    # Cookie matchers (case-insensitive by name).
    lower_cookies = {c.lower() for c in cookie_names}
    for cookie in rule.cookies:
        if cookie.lower() in lower_cookies:
            return True

    # Body groups: AND of ORs.
    if rule.body_groups:
        if all(any(marker in body for marker in group) for group in rule.body_groups):
            return True

    # Meta generator.
    for token in rule.meta:
        if token.lower() in meta_generator:
            return True

    return False


def detect(
    headers: Mapping[str, object],
    cookie_names: List[str],
    body: str,
) -> List[TechMatch]:
    """Return the technologies detected from headers, cookies, and body."""
    hdrs = _headers_lower(headers)
    body_l = (body or "").lower()
    meta_match = _META_GENERATOR_RE.search(body or "")
    meta_generator = meta_match.group(1).lower() if meta_match else ""

    names: Dict[str, str] = {}  # name -> category (deduped)
    for rule in RULES:
        if rule.name in names:
            continue
        if _rule_matches(rule, hdrs, cookie_names, body_l, meta_generator):
            names[rule.name] = rule.category
            for implied in rule.implies:
                names.setdefault(implied, _implied_category(implied))

    return [TechMatch(name=n, category=c) for n, c in sorted(names.items())]


_IMPLIED_CATEGORIES = {
    "python": _LANGUAGE,
    "php": _LANGUAGE,
    "ruby": _LANGUAGE,
    "node.js": _LANGUAGE,
    "react": _JS,
    "nginx": _WEB_SERVER,
}


def _implied_category(name: str) -> str:
    return _IMPLIED_CATEGORIES.get(name, "other")


__all__ = ["TechRule", "TechMatch", "RULES", "detect"]
