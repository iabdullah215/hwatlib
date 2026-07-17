from __future__ import annotations

import ssl

import hwatlib.fingerprint as fp


class _RawSock:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def sendall(self, data):
        pass

    def recv(self, n):
        return b"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n\r\n"


class _TLSSock(_RawSock):
    def __init__(self, cert=None):
        self._cert = cert

    def getpeercert(self):
        return self._cert


def test_try_tls_success(monkeypatch):
    monkeypatch.setattr(fp.socket, "create_connection", lambda *a, **k: _RawSock())

    class _Ctx:
        minimum_version = None

        def wrap_socket(self, raw, server_hostname=None):
            return _TLSSock()

    monkeypatch.setattr(fp.ssl, "create_default_context", lambda purpose=None: _Ctx())
    assert fp._try_tls("h", 443) is True


def test_try_tls_cert_error_still_true(monkeypatch):
    monkeypatch.setattr(fp.socket, "create_connection", lambda *a, **k: _RawSock())

    class _Ctx:
        minimum_version = None

        def wrap_socket(self, raw, server_hostname=None):
            raise ssl.SSLCertVerificationError("bad")

    monkeypatch.setattr(fp.ssl, "create_default_context", lambda purpose=None: _Ctx())
    # Cert invalid but TLS is present -> True.
    assert fp._try_tls("h", 443) is True


def test_try_tls_generic_failure(monkeypatch):
    def boom(*a, **k):
        raise OSError("refused")

    monkeypatch.setattr(fp.socket, "create_connection", boom)
    assert fp._try_tls("h", 443) is False


def test_get_tls_cert_info_success(monkeypatch):
    monkeypatch.setattr(fp.socket, "create_connection", lambda *a, **k: _RawSock())

    class _Ctx:
        minimum_version = None

        def wrap_socket(self, raw, server_hostname=None):
            return _TLSSock(cert={"subject": "x"})

    monkeypatch.setattr(fp.ssl, "create_default_context", lambda purpose=None: _Ctx())
    assert fp._get_tls_cert_info("h", 443) == {"subject": "x"}


def test_get_tls_cert_info_verification_error(monkeypatch):
    monkeypatch.setattr(fp.socket, "create_connection", lambda *a, **k: _RawSock())

    class _Ctx:
        minimum_version = None

        def wrap_socket(self, raw, server_hostname=None):
            raise ssl.SSLCertVerificationError("bad")

    monkeypatch.setattr(fp.ssl, "create_default_context", lambda purpose=None: _Ctx())
    assert fp._get_tls_cert_info("h", 443) is None


def test_try_http_server_header_plain(monkeypatch):
    monkeypatch.setattr(fp.socket, "create_connection", lambda *a, **k: _RawSock())
    server = fp._try_http_server_header("h", 80, 2.0, tls=False)
    assert server == "nginx/1.25"


def test_try_http_server_header_tls(monkeypatch):
    monkeypatch.setattr(fp.socket, "create_connection", lambda *a, **k: _RawSock())

    class _Ctx:
        minimum_version = None

        def wrap_socket(self, raw, server_hostname=None):
            return _RawSock()

    monkeypatch.setattr(fp.ssl, "create_default_context", lambda purpose=None: _Ctx())
    server = fp._try_http_server_header("h", 443, 2.0, tls=True)
    assert server == "nginx/1.25"
