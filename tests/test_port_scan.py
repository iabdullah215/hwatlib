from __future__ import annotations

import asyncio
import socket

import hwatlib.recon as recon


def test_parse_ports_single_range_and_invalid():
    assert recon.parse_ports("22,80,443") == [22, 80, 443]
    assert recon.parse_ports("8000-8003") == [8000, 8001, 8002, 8003]
    assert recon.parse_ports("443,443,80") == [80, 443]  # dedup + sort
    assert recon.parse_ports("bad,-,70000,0,22") == [22]  # drops invalid/out-of-range
    assert recon.parse_ports("90-88") == [88, 89, 90]  # reversed range normalized
    assert recon.parse_ports("") == []


def test_scan_ports_detects_open_and_closed():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    open_port = srv.getsockname()[1]
    # Find a very likely-closed port.
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()

    try:
        result = recon.scan_ports("127.0.0.1", [open_port, closed_port], timeout=0.5)
        assert result.host == "127.0.0.1"
        assert result.scanned == 2
        assert open_port in result.open_ports
        assert closed_port not in result.open_ports
        assert result.error is None
    finally:
        srv.close()


def test_scan_ports_default_uses_common_ports(monkeypatch):
    async def fake_async(host, ports, *, timeout, max_concurrency):
        assert ports == recon.COMMON_PORTS
        return [80, 443]

    monkeypatch.setattr(recon, "async_scan_ports", fake_async)
    result = recon.scan_ports("10.0.0.1")
    assert result.open_ports == [80, 443]
    assert result.scanned == len(recon.COMMON_PORTS)


def test_scan_ports_handles_error(monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("loop down")

    monkeypatch.setattr(recon, "async_scan_ports", boom)
    result = recon.scan_ports("10.0.0.1", [80])
    assert result.open_ports == []
    assert result.error is not None


def test_async_scan_ports_empty_list():
    out = asyncio.run(recon.async_scan_ports("127.0.0.1", []))
    assert out == []


def test_async_scan_ports_all_closed(monkeypatch):
    async def refuse(host, port):
        raise ConnectionRefusedError()

    monkeypatch.setattr(recon.asyncio, "open_connection", refuse)
    out = asyncio.run(recon.async_scan_ports("127.0.0.1", [1, 2, 3], timeout=0.2))
    assert out == []


def test_async_scan_ports_open(monkeypatch):
    class _Writer:
        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def connect(host, port):
        if port == 80:
            return object(), _Writer()
        raise ConnectionRefusedError()

    monkeypatch.setattr(recon.asyncio, "open_connection", connect)
    out = asyncio.run(recon.async_scan_ports("127.0.0.1", [80, 81], timeout=0.2))
    assert out == [80]
