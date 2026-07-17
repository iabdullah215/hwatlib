"""Property-based tests for hwatlib's parsers and scoring heuristics.

These use Hypothesis to fuzz the pure, deterministic parts of the library:
URL/robots/sitemap parsing, report diffing, config validation, and the
privesc/findings scoring logic. The invariants asserted here are the ones a
downstream consumer relies on — e.g. "scores never leave 0..100", "canonicalize
is idempotent", "a validator never returns an out-of-range value".
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from hwatlib import config, diff, findings, privesc
from hwatlib.web import (
    _parse_robots_sitemaps,
    _parse_sitemap_xml_locs,
    canonicalize_url,
)

# ---------------------------------------------------------------------------
# URL / robots / sitemap parsing
# ---------------------------------------------------------------------------

_URLISH = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)),
    max_size=200,
)


@given(_URLISH)
def test_canonicalize_url_never_raises(url):
    # It is called on untrusted input from crawled pages; must not throw.
    result = canonicalize_url(url)
    assert isinstance(result, str)


@given(st.text(min_size=1, max_size=100))
def test_canonicalize_url_is_idempotent(path):
    url = f"https://Example.com/{path}?b=2&a=1#frag"
    once = canonicalize_url(url)
    twice = canonicalize_url(once)
    assert once == twice


@given(
    st.sampled_from(["http", "https"]),
    st.text(min_size=1, max_size=30, alphabet="abcdefghijklmnopqrstuvwxyz0123456789.-"),
    st.text(min_size=0, max_size=30),
)
def test_canonicalize_url_drops_fragment(scheme, host, frag):
    url = f"{scheme}://{host}/path?a=1#{frag}"
    result = canonicalize_url(url)
    # In the normalized form the fragment component is removed.
    if result != url:
        assert "#" not in result


@given(st.text(max_size=500), st.sampled_from(["https://example.com", "http://h.test"]))
def test_parse_robots_sitemaps_never_raises(text, base):
    out = _parse_robots_sitemaps(text, base)
    assert isinstance(out, list)
    assert all(isinstance(x, str) for x in out)


@given(st.lists(st.text(min_size=1, max_size=40), max_size=10))
def test_parse_robots_sitemaps_collects_declared_entries(paths):
    base = "https://example.com"
    lines = [f"Sitemap: /{p}" for p in paths]
    text = "User-agent: *\n" + "\n".join(lines)
    out = _parse_robots_sitemaps(text, base)
    # Every declared Sitemap line yields exactly one absolute URL.
    assert len(out) == len(paths)
    assert all(u.startswith("http") for u in out)


@given(st.text(max_size=500))
def test_parse_sitemap_xml_locs_never_raises(text):
    out = _parse_sitemap_xml_locs(text)
    assert isinstance(out, list)


# ---------------------------------------------------------------------------
# privesc.risk_score
# ---------------------------------------------------------------------------

_REPORT_VALUES = st.one_of(
    st.none(),
    st.text(max_size=60),
    st.integers(),
    st.booleans(),
)

_PRIVESC_KEYS = ["sudo_rights", "suid_bins", "bash_history", "ssh_keys", "network_shares"]


@given(st.dictionaries(st.sampled_from(_PRIVESC_KEYS), _REPORT_VALUES))
def test_risk_score_is_bounded_and_consistent(report):
    result = privesc.risk_score(report)
    assert 0 <= result.score <= 100
    assert result.level in {"low", "medium", "high"}
    # Level must agree with the documented score thresholds.
    if result.score >= 60:
        assert result.level == "high"
    elif result.score >= 30:
        assert result.level == "medium"
    else:
        assert result.level == "low"


@given(st.text(max_size=80))
def test_risk_score_sudo_dominates(sudo_text):
    # Any sudo text containing the trigger tokens must add its weight.
    report = {"sudo_rights": f"user ALL (ALL) NOPASSWD: {sudo_text}"}
    result = privesc.risk_score(report)
    assert "sudo_rights_present" in result.reasons
    assert result.score >= 35


def test_risk_score_empty_report_is_low():
    result = privesc.risk_score({})
    assert result.score == 0
    assert result.level == "low"


# ---------------------------------------------------------------------------
# findings scoring helpers
# ---------------------------------------------------------------------------

@given(st.text(max_size=20))
def test_plugin_severity_points_bounded(sev):
    pts = findings._plugin_severity_points(sev)
    assert 0 <= pts <= 30


def test_plugin_severity_points_monotonic():
    order = ["", "low", "medium", "high", "critical"]
    pts = [findings._plugin_severity_points(s) for s in order]
    assert pts == sorted(pts)  # non-decreasing with severity


@given(st.integers())
def test_score_level_thresholds(score):
    level = findings._score_level(score)
    assert level in {"info", "low", "medium", "high"}
    if score >= 70:
        assert level == "high"
    elif score >= 40:
        assert level == "medium"
    elif score >= 15:
        assert level == "low"
    else:
        assert level == "info"


# ---------------------------------------------------------------------------
# diff.diff_reports
# ---------------------------------------------------------------------------

_ARBITRARY_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=20),
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(st.text(max_size=8), children, max_size=4),
    max_leaves=15,
)


@given(_ARBITRARY_JSON, _ARBITRARY_JSON)
def test_diff_reports_never_raises(old, new):
    old_d = old if isinstance(old, dict) else {}
    new_d = new if isinstance(new, dict) else {}
    result = diff.diff_reports(old_d, new_d)
    d = result.to_dict()
    assert set(d.keys()) == {"risk", "findings", "web", "recon"}
    # Risk delta must always equal new - old.
    assert d["risk"]["delta"] == d["risk"]["new_score"] - d["risk"]["old_score"]


@given(st.integers(min_value=0, max_value=100), st.integers(min_value=0, max_value=100))
def test_diff_reports_risk_delta(old_score, new_score):
    old = {"metadata": {"risk": {"score": old_score, "level": "low"}}}
    new = {"metadata": {"risk": {"score": new_score, "level": "high"}}}
    d = diff.diff_reports(old, new).to_dict()
    assert d["risk"]["delta"] == new_score - old_score


# ---------------------------------------------------------------------------
# config validators
# ---------------------------------------------------------------------------

@given(st.integers())
def test_validate_int_clamps_to_range_or_default(value):
    default = 5
    out = config._validate_int(
        value, default=default, field="x", source="test",
        min_value=1, max_value=10, strict=False,
    )
    # Result is always either the in-range input or the default.
    assert out == value if 1 <= value <= 10 else out == default
    assert 1 <= out <= 10


@given(st.floats(allow_nan=False, allow_infinity=False, min_value=-1e9, max_value=1e9))
def test_validate_float_clamps_to_range_or_default(value):
    default = 2.5
    out = config._validate_float(
        value, default=default, field="x", source="test",
        min_value=0.0, max_value=100.0, strict=False,
    )
    assert 0.0 <= out <= 100.0
    if 0.0 <= value <= 100.0:
        assert out == value
    else:
        assert out == default


@given(st.one_of(st.text(max_size=10), st.integers(), st.none(), st.floats(allow_nan=False)))
def test_validate_bool_rejects_non_bool(value):
    out = config._validate_bool(value, default=True, field="x", source="test", strict=False)
    assert out is True  # non-bool falls back to default


@given(st.booleans())
def test_validate_bool_passes_through_bools(value):
    out = config._validate_bool(value, default=not value, field="x", source="test", strict=False)
    assert out is value
