from __future__ import annotations

import subprocess

import hwatlib.recon as recon
from hwatlib.models import NmapResult


class _FakeBannerSocket:
    def __init__(self, *_args, **_kwargs):
        self.port = None

    def settimeout(self, _timeout):
        return None

    def connect(self, addr):
        _host, port = addr
        self.port = int(port)
        if self.port == 9999:
            raise OSError("closed")

    def send(self, _payload):
        return None

    def recv(self, _size):
        if self.port == 80:
            return b"HTTP/1.1 200 OK\r\nServer: test\r\n"
        raise OSError("no banner")

    def close(self):
        return None


def test_run_nmap_parses_tcp_and_udp_ports(monkeypatch):
    def fake_check_output(cmd, stderr=None):
        if "-sU" in cmd:
            return b"53/udp open domain\n"
        return b"22/tcp open ssh\n80/tcp open http\n"

    monkeypatch.setattr(recon.subprocess, "check_output", fake_check_output)

    out = recon.run_nmap("127.0.0.1", udp=True)

    assert out.ok is True
    assert out.open_tcp == [22, 80]
    assert out.open_udp == [53]


def test_run_nmap_returns_typed_error_on_failure(monkeypatch):
    def fake_check_output(_cmd, stderr=None):
        raise subprocess.CalledProcessError(returncode=1, cmd="nmap")

    monkeypatch.setattr(recon.subprocess, "check_output", fake_check_output)

    out = recon.run_nmap("127.0.0.1")

    assert out.ok is False
    assert isinstance(out.error, str)
    assert out.output == ""


def test_nmap_scan_updates_session(monkeypatch):
    def fake_run_nmap(*_args, **_kwargs):
        return NmapResult(ok=True, output="scan-output", open_tcp=[22, 443], open_udp=[53])

    monkeypatch.setattr(recon, "run_nmap", fake_run_nmap)

    s = recon.ReconSession(target="example.com", ip="127.0.0.1", open_tcp=[], open_udp=[])
    out = recon.nmap_scan(session=s)

    assert out.ok is True
    assert s.nmap_output == "scan-output"
    assert s.open_tcp == [22, 443]
    assert s.open_udp == [53]


def test_banner_grab_explicit_host_ports(monkeypatch):
    monkeypatch.setattr(recon.socket, "socket", _FakeBannerSocket)

    out = recon.banner_grab(host="127.0.0.1", ports=[80, 22, 9999])

    assert out[80].startswith("HTTP/1.1 200 OK")
    assert out[22] == "Open (no banner)"
    assert out[9999] is None
