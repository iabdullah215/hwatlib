from __future__ import annotations

import asyncio
import json

import hwatlib.web as web
from hwatlib.web import (
    _build_openapi_discovery,
    _extract_openapi_endpoints,
    _parse_openapi_document,
    discover_openapi,
    discover_openapi_dict,
)

SPEC = {
    "openapi": "3.0.1",
    "info": {"title": "Petstore"},
    "paths": {
        "/pets": {"get": {}, "post": {}},
        "/pets/{id}": {"get": {}, "delete": {}},
        "/health": {"get": {}},
        "x-vendor": "not-a-dict",
    },
}

SWAGGER = {"swagger": "2.0", "info": {"title": "Legacy"}, "paths": {"/v1/thing": {"get": {}}}}


class _Resp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status
        self.headers = {}


class _Client:
    """Serve a body for a URL suffix; 404 otherwise."""

    def __init__(self, by_suffix):
        self.by_suffix = by_suffix
        self.requested = []

    def get(self, url, timeout=5):
        self.requested.append(url)
        for suffix, body in self.by_suffix.items():
            if url.endswith(suffix):
                return _Resp(body)
        return _Resp("", status=404)


class _AsyncClient:
    def __init__(self, by_suffix):
        self.by_suffix = by_suffix

    async def get(self, url):
        for suffix, body in self.by_suffix.items():
            if url.endswith(suffix):
                return _Resp(body)
        return _Resp("", status=404)


def test_parse_openapi_json():
    assert _parse_openapi_document(json.dumps(SPEC))["openapi"] == "3.0.1"


def test_parse_openapi_rejects_non_object():
    assert _parse_openapi_document("[1,2,3]") is None
    assert _parse_openapi_document("not json") is None


def test_extract_endpoints_filters_non_methods_and_non_dicts():
    endpoints = _extract_openapi_endpoints(SPEC["paths"])
    by_path = {e.path: e.methods for e in endpoints}
    assert by_path["/pets"] == ["GET", "POST"]
    assert by_path["/pets/{id}"] == ["DELETE", "GET"]
    assert "x-vendor" not in by_path  # non-dict path item skipped
    assert _extract_openapi_endpoints("nope") == []


def test_build_discovery_openapi():
    d = _build_openapi_discovery("http://api/spec", SPEC, ["http://api/spec"])
    assert d.ok is True
    assert d.spec_type == "openapi"
    assert d.version == "3.0.1"
    assert d.title == "Petstore"
    assert d.endpoint_count == 3


def test_build_discovery_swagger():
    d = _build_openapi_discovery("http://api/spec", SWAGGER, [])
    assert d.spec_type == "swagger"
    assert d.version == "2.0"
    assert d.endpoint_count == 1


def test_build_discovery_rejects_non_spec():
    assert _build_openapi_discovery("u", {"foo": "bar"}, []) is None


def test_discover_openapi_finds_spec():
    client = _Client({"/v3/api-docs": json.dumps(SPEC)})
    d = discover_openapi("http://api.test", client=client)
    assert d.ok is True
    assert d.spec_url.endswith("/v3/api-docs")
    assert d.endpoint_count == 3


def test_discover_openapi_first_match_wins():
    # Both present; probe order puts /openapi.json before /v3/api-docs.
    client = _Client({"/openapi.json": json.dumps(SPEC), "/v3/api-docs": json.dumps(SWAGGER)})
    d = discover_openapi("http://api.test", client=client)
    assert d.spec_url.endswith("/openapi.json")
    assert d.spec_type == "openapi"


def test_discover_openapi_not_found():
    d = discover_openapi("http://api.test", client=_Client({}))
    assert d.ok is False
    assert d.error == "No OpenAPI/Swagger spec found"
    assert len(d.checked) == len(web._OPENAPI_CANDIDATE_PATHS)


def test_discover_openapi_ignores_non_spec_json():
    # A 200 JSON body that isn't an OpenAPI doc must not be treated as one.
    client = _Client({"/openapi.json": json.dumps({"hello": "world"})})
    d = discover_openapi("http://api.test", client=client)
    assert d.ok is False


def test_discover_openapi_dict():
    client = _Client({"/swagger.json": json.dumps(SWAGGER)})
    out = discover_openapi_dict("http://api.test", client=client)
    assert out["ok"] is True
    assert out["endpoints"][0]["path"] == "/v1/thing"


def test_discover_openapi_async():
    client = _AsyncClient({"/openapi.json": json.dumps(SPEC)})
    d = asyncio.run(web.discover_openapi_async("http://api.test", client=client))
    assert d.ok is True
    assert d.endpoint_count == 3


def test_parse_openapi_yaml_when_available():
    import pytest

    yaml = pytest.importorskip("yaml")
    text = yaml.safe_dump(SPEC)
    parsed = _parse_openapi_document(text)
    assert parsed is not None
    assert parsed["openapi"] == "3.0.1"


def test_scan_includes_openapi(monkeypatch):
    # Serve an HTML page for normal fetches and a spec at /openapi.json.
    monkeypatch.setattr(web, "_fetch_text", lambda url, **k: json.dumps(SPEC) if url.endswith("/openapi.json") else None)
    client = _Client({"/openapi.json": json.dumps(SPEC)})
    # fetch_all/fingerprint use client.get; crawl uses _fetch_text (stubbed).
    result = web.scan("http://api.test", client=client, depth=1)
    assert result.ok is True
    assert result.openapi is not None
    assert result.openapi.ok is True
    assert result.to_dict()["openapi"]["endpoint_count"] == 3
