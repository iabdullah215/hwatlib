from __future__ import annotations

from hwatlib import techrules


def _names(headers=None, cookies=None, body=""):
    return [m.name for m in techrules.detect(headers or {}, cookies or [], body)]


def test_server_header_detection():
    assert "nginx" in _names(headers={"Server": "nginx/1.25"})
    assert "apache" in _names(headers={"server": "Apache/2.4 (Ubuntu)"})
    assert "apache" in _names(headers={"server": "httpd"})
    assert "iis" in _names(headers={"Server": "Microsoft-IIS/10.0"})


def test_x_powered_by_and_implies():
    names = _names(headers={"X-Powered-By": "Express"})
    assert "express" in names
    assert "node.js" in names  # implied


def test_cookie_detection():
    assert "php" in _names(cookies=["PHPSESSID"])
    assert "asp.net" in _names(cookies=["ASP.NET_SessionId"])
    assert "laravel" in _names(cookies=["laravel_session"])


def test_body_markers():
    assert "wordpress" in _names(body="<link href='/wp-content/themes/x'>")
    assert "jquery" in _names(body="<script src='/js/jquery.min.js'>")
    assert "react" in _names(body="<div data-reactroot></div>")


def test_drupal_requires_two_markers():
    # Only the word "drupal" -> not enough.
    assert "drupal" not in _names(body="this mentions drupal once")
    # "drupal" + a structural marker -> detected.
    assert "drupal" in _names(body="Drupal.settings loaded; drupal core")


def test_meta_generator():
    assert "wordpress" in _names(body='<meta name="generator" content="WordPress 6.4.2">')
    assert "joomla" in _names(body='<meta name="generator" content="Joomla! - Open Source CMS">')


def test_cloudflare_via_header_presence():
    assert "cloudflare" in _names(headers={"CF-RAY": "abc-DFW"})
    assert "fastly" in _names(headers={"X-Served-By": "cache-fastly-XYZ"})


def test_detect_dedupes_and_sorts():
    names = _names(headers={"server": "nginx"}, body="wp-content nginx")
    assert names == sorted(names)
    assert names.count("nginx") == 1


def test_matches_carry_category():
    matches = techrules.detect({"server": "nginx"}, [], "")
    by_name = {m.name: m.category for m in matches}
    assert by_name["nginx"] == "web-server"


def test_no_false_positive_on_empty():
    assert techrules.detect({}, [], "") == []


def test_header_presence_empty_needle():
    # A rule with an empty needle matches on header presence alone.
    assert "asp.net" in _names(headers={"X-AspNet-Version": "4.0.30319"})
