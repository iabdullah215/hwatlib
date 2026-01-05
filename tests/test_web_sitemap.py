from __future__ import annotations

from hwatlib.web import canonicalize_url, _parse_robots_sitemaps, _parse_sitemap_xml_locs


def test_canonicalize_url_drops_fragment_and_sorts_query():
    u = canonicalize_url("https://Example.com/a?b=2&a=1#frag")
    assert u == "https://example.com/a?a=1&b=2"


def test_parse_robots_sitemaps():
    text = """
User-agent: *
Disallow: /admin
Sitemap: /sitemap.xml
Sitemap: https://example.com/alt.xml
""".strip()

    out = _parse_robots_sitemaps(text, "https://example.com")
    assert "https://example.com/sitemap.xml" in out
    assert "https://example.com/alt.xml" in out


def test_parse_sitemap_xml_locs():
    xml = """<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">
  <url><loc>https://example.com/a</loc></url>
  <url><loc>https://example.com/b</loc></url>
</urlset>
"""
    out = _parse_sitemap_xml_locs(xml)
    assert "https://example.com/a" in out
    assert "https://example.com/b" in out
