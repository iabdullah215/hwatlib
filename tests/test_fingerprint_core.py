from __future__ import annotations

import ssl

import hwatlib.fingerprint as fp


def test_fingerprint_ssh_short_circuits(monkeypatch):
    monkeypatch.setattr(fp, "_try_ssh_banner", lambda h, p, t: "SSH-2.0-OpenSSH_9.0")
    out = fp.fingerprint_service("host", 22)
    assert out["service"] == "ssh"
    assert out["version"] == "SSH-2.0-OpenSSH_9.0"
    assert out["tls"] is False


def test_fingerprint_https_with_server_header(monkeypatch):
    monkeypatch.setattr(fp, "_try_ssh_banner", lambda h, p, t: None)
    monkeypatch.setattr(fp, "_try_tls", lambda h, p, timeout=2.0: True)
    monkeypatch.setattr(fp, "_get_tls_cert_info", lambda h, p, timeout=2.0: {"subject": "x"})
    monkeypatch.setattr(fp, "_try_http_server_header", lambda h, p, t, *, tls: "nginx/1.25")
    out = fp.fingerprint_service("host", 443)
    assert out["service"] == "https"
    assert out["version"] == "nginx/1.25"
    assert out["tls"] is True
    assert out["tls_cert"] == {"subject": "x"}


def test_fingerprint_http_plain(monkeypatch):
    monkeypatch.setattr(fp, "_try_ssh_banner", lambda h, p, t: None)
    monkeypatch.setattr(fp, "_try_tls", lambda h, p, timeout=2.0: False)
    monkeypatch.setattr(fp, "_try_http_server_header", lambda h, p, t, *, tls: "Apache")
    out = fp.fingerprint_service("host", 80)
    assert out["service"] == "http"
    assert out["version"] == "Apache"
    assert out["tls"] is False


def test_fingerprint_cert_verification_failure(monkeypatch):
    monkeypatch.setattr(fp, "_try_ssh_banner", lambda h, p, t: None)
    monkeypatch.setattr(fp, "_try_tls", lambda h, p, timeout=2.0: True)
    monkeypatch.setattr(fp, "_get_tls_cert_info", lambda h, p, timeout=2.0: None)

    def boom(h, p, t, *, tls):
        raise ssl.SSLCertVerificationError("bad cert")

    monkeypatch.setattr(fp, "_try_http_server_header", boom)
    out = fp.fingerprint_service("host", 443)
    assert out["service"] == "https"
    assert out["tls"] is True
    assert "tls_cert_verification_failed" in out["notes"]


def test_fingerprint_unknown_on_generic_error(monkeypatch):
    monkeypatch.setattr(fp, "_try_ssh_banner", lambda h, p, t: None)
    monkeypatch.setattr(fp, "_try_tls", lambda h, p, timeout=2.0: False)

    def boom(h, p, t, *, tls):
        raise OSError("refused")

    monkeypatch.setattr(fp, "_try_http_server_header", boom)
    out = fp.fingerprint_service("host", 8080)
    assert out["service"] == "unknown"
    assert out["version"] is None


def test_try_ssh_banner_rejects_non_ssh(monkeypatch):
    class _Sock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, t):
            pass

        def recv(self, n):
            return b"HTTP/1.1 200 OK"

    monkeypatch.setattr(fp.socket, "create_connection", lambda *a, **k: _Sock())
    assert fp._try_ssh_banner("h", 22, 1.0) is None


def test_try_ssh_banner_accepts_ssh(monkeypatch):
    class _Sock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, t):
            pass

        def recv(self, n):
            return b"SSH-2.0-OpenSSH_9.6\r\n"

    monkeypatch.setattr(fp.socket, "create_connection", lambda *a, **k: _Sock())
    assert fp._try_ssh_banner("h", 22, 1.0) == "SSH-2.0-OpenSSH_9.6"
