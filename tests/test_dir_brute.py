from __future__ import annotations

import asyncio

import hwatlib.web as web
from hwatlib.web import _candidate_paths, dir_bruteforce, dir_bruteforce_async


class _Resp:
    def __init__(self, status, text="body", location=None):
        self.status_code = status
        self.text = text
        self.headers = {"Location": location} if location else {}


class _Client:
    def __init__(self, table):
        self.table = table
        self.calls = []

    def get(self, url, timeout=5, allow_redirects=True):
        self.calls.append((url, allow_redirects))
        for suffix, (status, loc) in self.table.items():
            if url.endswith(suffix):
                return _Resp(status, "x" * 12, loc)
        return _Resp(404)


class _AsyncResp:
    def __init__(self, status, text="body", location=None):
        self.status = status
        self.text = text
        self.headers = {"location": location} if location else {}


class _AsyncClient:
    def __init__(self, table):
        self.table = table

    async def get(self, url):
        for suffix, (status, loc) in self.table.items():
            if url.endswith(suffix):
                return _AsyncResp(status, "y" * 5, loc)
        return _AsyncResp(404)


def test_candidate_paths_with_extensions():
    assert _candidate_paths("admin", [".php", "bak"]) == ["admin", "admin.php", "admin.bak"]
    assert _candidate_paths("/leading/", None) == ["leading/"]
    assert _candidate_paths("# comment", None) == []
    assert _candidate_paths("", None) == []


def test_dir_bruteforce_reports_interesting_statuses():
    client = _Client({"/admin": (200, None), "/login": (301, "/home"), "/secret": (403, None)})
    res = dir_bruteforce("http://t.test", ["admin", "login", "secret", "nope"], client=client)
    statuses = {e.status for e in res.found}
    assert statuses == {200, 301, 403}
    login = next(e for e in res.found if e.status == 301)
    assert login.redirect == "/home"
    assert res.tested == 4


def test_dir_bruteforce_does_not_follow_redirects():
    client = _Client({"/x": (200, None)})
    dir_bruteforce("http://t.test", ["x"], client=client)
    assert client.calls[0][1] is False


def test_dir_bruteforce_extensions_expand_words():
    client = _Client({"/config.php": (200, None)})
    res = dir_bruteforce("http://t.test", ["config"], client=client, extensions=["php", ".bak"])
    assert res.tested == 3  # config, config.php, config.bak
    assert any(e.url.endswith("/config.php") for e in res.found)


def test_dir_bruteforce_custom_status_filter():
    client = _Client({"/a": (200, None), "/b": (403, None)})
    res = dir_bruteforce("http://t.test", ["a", "b"], client=client, status_include=[403])
    assert [e.status for e in res.found] == [403]


def test_dir_bruteforce_from_wordlist_file(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("admin\n\n# comment\nlogin\n")
    client = _Client({"/admin": (200, None), "/login": (200, None)})
    res = dir_bruteforce("http://t.test", str(wl), client=client)
    assert {e.url.rsplit("/", 1)[1] for e in res.found} == {"admin", "login"}


def test_dir_bruteforce_missing_wordlist_file_returns_error():
    res = dir_bruteforce("http://t.test", "/no/such/file.txt", client=_Client({}))
    assert res.error is not None
    assert res.found == []


def test_dir_bruteforce_tolerates_request_errors():
    class _Boom:
        def get(self, url, timeout=5, allow_redirects=True):
            raise web.requests.RequestException("dead")

    res = dir_bruteforce("http://t.test", ["a", "b"], client=_Boom())
    assert res.found == []
    assert res.tested == 2


def test_dir_bruteforce_to_dict():
    client = _Client({"/a": (200, None)})
    d = dir_bruteforce("http://t.test", ["a"], client=client).to_dict()
    assert d["found"][0]["status"] == 200
    assert set(d.keys()) == {"base", "tested", "found", "error"}


def test_dir_bruteforce_async():
    client = _AsyncClient({"/admin": (200, None), "/api": (401, None)})
    res = asyncio.run(dir_bruteforce_async("http://t.test", ["admin", "api", "nope"], client=client))
    assert {e.status for e in res.found} == {200, 401}
    assert res.tested == 3


def test_dir_bruteforce_async_missing_file():
    res = asyncio.run(
        dir_bruteforce_async("http://t.test", "/no/such/file.txt", client=_AsyncClient({}))
    )
    assert res.error is not None
