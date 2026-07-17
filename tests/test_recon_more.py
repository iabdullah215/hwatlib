from __future__ import annotations

import asyncio

import pytest

import hwatlib.recon as recon


def test_is_ipv4():
    assert recon._is_ipv4("10.0.0.1") is True
    assert recon._is_ipv4("example.com") is False
    assert recon._is_ipv4("") is False


def test_resolve_target_ip_passthrough(monkeypatch):
    monkeypatch.setattr(recon, "resolve_host", lambda t: None)
    assert recon.resolve_target("10.0.0.1") == "10.0.0.1"


def test_resolve_target_resolves(monkeypatch):
    monkeypatch.setattr(recon, "resolve_host", lambda t: "1.2.3.4")
    assert recon.resolve_target("example.com") == "1.2.3.4"


def test_resolve_target_writes_hosts(monkeypatch, tmp_path):
    monkeypatch.setattr(recon, "resolve_host", lambda t: "1.2.3.4")
    hosts = tmp_path / "hosts"
    hosts.write_text("# hosts\n")
    recon.resolve_target("example.com", add_to_hosts=True, hosts_path=str(hosts))
    assert "1.2.3.4 example.com" in hosts.read_text()


def test_resolve_target_hosts_permission_error(monkeypatch):
    monkeypatch.setattr(recon, "resolve_host", lambda t: "1.2.3.4")

    def boom(*a, **k):
        raise PermissionError()

    monkeypatch.setattr("builtins.open", boom)
    # Still returns the resolved IP despite the write failure.
    assert recon.resolve_target("example.com", add_to_hosts=True) == "1.2.3.4"


def test_resolve_target_unresolvable(monkeypatch):
    monkeypatch.setattr(recon, "resolve_host", lambda t: None)
    assert recon.resolve_target("no.such.host") is None


def test_run_nmap_parses_open_tcp(monkeypatch):
    output = b"Starting Nmap\n22/tcp open ssh\n80/tcp open http\n443/tcp closed https\n"
    monkeypatch.setattr(recon.subprocess, "check_output", lambda *a, **k: output)
    result = recon.run_nmap("1.2.3.4")
    assert result.ok is True
    assert result.open_tcp == [22, 80]


def test_run_nmap_udp(monkeypatch):
    outputs = [b"53/tcp open dns\n", b"161/udp open snmp\n"]
    monkeypatch.setattr(recon.subprocess, "check_output", lambda *a, **k: outputs.pop(0))
    result = recon.run_nmap("1.2.3.4", udp=True)
    assert result.open_udp == [161]


def test_run_nmap_timeout_returns_typed_error(monkeypatch):
    def boom(*a, **k):
        raise recon.subprocess.TimeoutExpired(cmd="nmap", timeout=300.0)

    monkeypatch.setattr(recon.subprocess, "check_output", boom)
    result = recon.run_nmap("1.2.3.4", timeout=300.0)
    assert result.ok is False
    assert "timed out" in (result.error or "")


def test_run_nmap_passes_timeout(monkeypatch):
    seen = {}

    def fake(cmd, stderr=None, timeout=None):
        seen["timeout"] = timeout
        return b"22/tcp open ssh\n"

    monkeypatch.setattr(recon.subprocess, "check_output", fake)
    recon.run_nmap("1.2.3.4", timeout=42.0)
    assert seen["timeout"] == 42.0


def test_run_nmap_failure(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError("nmap missing")

    monkeypatch.setattr(recon.subprocess, "check_output", boom)
    result = recon.run_nmap("1.2.3.4")
    assert result.ok is False
    assert "nmap missing" in (result.error or "")


def test_init_returns_session(monkeypatch):
    monkeypatch.setattr(recon, "resolve_host", lambda t: "1.2.3.4")
    sess = recon.init("example.com")
    assert sess is not None
    assert sess.ip == "1.2.3.4"


def test_init_none_when_unresolvable(monkeypatch):
    monkeypatch.setattr(recon, "resolve_host", lambda t: None)
    assert recon.init("no.host") is None


def test_resolve_scan_target_variants():
    assert recon._resolve_scan_target(target="1.1.1.1", session=None, caller="x") == "1.1.1.1"
    sess = recon.ReconSession(target="t", ip="2.2.2.2")
    assert recon._resolve_scan_target(target=None, session=sess, caller="x") == "2.2.2.2"
    with pytest.raises(RuntimeError):
        recon._resolve_scan_target(target=None, session=None, caller="x")


def test_nmap_scan_updates_session(monkeypatch):
    sess = recon.ReconSession(target="t", ip="2.2.2.2", open_tcp=[], open_udp=[])
    monkeypatch.setattr(
        recon, "run_nmap",
        lambda target, options=recon.DEFAULT_NMAP_OPTIONS, udp=False, timeout=None: recon.NmapResult(
            ok=True, output="out", open_tcp=[22], open_udp=[]
        ),
    )
    result = recon.nmap_scan(session=sess)
    assert result.open_tcp == [22]
    assert sess.open_tcp == [22]
    assert sess.nmap_output == "out"


def test_nmap_scan_typed_updates_session(monkeypatch):
    sess = recon.ReconSession(target="t", ip="2.2.2.2")
    monkeypatch.setattr(
        recon, "run_nmap",
        lambda target, options=recon.DEFAULT_NMAP_OPTIONS, udp=False, timeout=None: recon.NmapResult(
            ok=True, output="o", open_tcp=[80], open_udp=[]
        ),
    )
    result = recon.nmap_scan_typed(session=sess)
    assert result.open_tcp == [80]
    assert sess.open_tcp == [80]


def test_banner_grab_explicit(monkeypatch):
    monkeypatch.setattr(recon, "_banner_grab_ports", lambda host, ports: {p: "banner" for p in ports})
    assert recon.banner_grab("h", [22]) == {22: "banner"}


def test_banner_grab_session(monkeypatch):
    sess = recon.ReconSession(target="t", ip="2.2.2.2", open_tcp=[80])
    monkeypatch.setattr(recon, "_banner_grab_ports", lambda host, ports: {80: f"{host}:{ports}"})
    out = recon.banner_grab(session=sess)
    assert out[80].startswith("2.2.2.2")


def test_banner_grab_requires_args():
    with pytest.raises(RuntimeError):
        recon.banner_grab()


def test_banner_grab_ports_with_fake_socket(monkeypatch):
    class _Sock:
        def settimeout(self, t):
            pass

        def connect(self, addr):
            pass

        def send(self, data):
            pass

        def recv(self, n):
            return b"HTTP/1.1 200 OK\r\nServer: x\r\n"

        def close(self):
            pass

    monkeypatch.setattr(recon.socket, "socket", lambda *a, **k: _Sock())
    out = recon._banner_grab_ports("h", [80])
    assert out[80].startswith("HTTP/1.1 200 OK")


def test_banner_grab_ports_connect_fails(monkeypatch):
    class _Sock:
        def settimeout(self, t):
            pass

        def connect(self, addr):
            raise OSError("refused")

        def close(self):
            pass

    monkeypatch.setattr(recon.socket, "socket", lambda *a, **k: _Sock())
    out = recon._banner_grab_ports("h", [81])
    assert out[81] is None


def test_banner_grab_async(monkeypatch):
    class _Reader:
        async def read(self, n):
            return b"HTTP/1.0 200 OK\r\n"

    class _Writer:
        def write(self, data):
            pass

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def fake_open(host, port):
        return _Reader(), _Writer()

    monkeypatch.setattr(recon.asyncio, "open_connection", fake_open)
    out = asyncio.run(recon.banner_grab_async("h", [80]))
    assert out[80] == "HTTP/1.0 200 OK"
