from __future__ import annotations

import ssl
import time

import hwatlib.tls as tls

# --- pure helpers ---

def test_name_to_str():
    rdns = ((("commonName", "example.com"),), (("organizationName", "Acme"),))
    assert tls._name_to_str(rdns) == "commonName=example.com, organizationName=Acme"
    assert tls._name_to_str(None) is None
    assert tls._name_to_str(()) is None


def test_extract_sans():
    cert = {"subjectAltName": (("DNS", "a.com"), ("DNS", "b.com"), ("IP Address", "1.2.3.4"))}
    assert tls._extract_sans(cert) == ["a.com", "b.com", "IP Address:1.2.3.4"]
    assert tls._extract_sans({}) == []


def test_is_weak_cipher():
    assert tls._is_weak_cipher("AES128-SHA", 64) is True  # low bits
    assert tls._is_weak_cipher("ECDHE-RSA-RC4-SHA", 128) is True  # marker
    assert tls._is_weak_cipher("ECDHE-RSA-AES256-GCM-SHA384", 256) is False
    assert tls._is_weak_cipher(None, None) is False


def test_expiry_future_and_past():
    future = time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(time.time() + 30 * 86400))
    days, expired = tls._expiry(future)
    assert 28 <= days <= 31
    assert expired is False

    past = time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(time.time() - 10 * 86400))
    days, expired = tls._expiry(past)
    assert days < 0 and expired is True

    assert tls._expiry(None) == (None, False)
    assert tls._expiry("garbage") == (None, False)


# --- inspect_tls with mocked connection ---

_CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": ((("commonName", "Real CA"),),),
    "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com")),
    "notBefore": "Jan  1 00:00:00 2024 GMT",
    "notAfter": time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(time.time() + 60 * 86400)),
}


def test_inspect_tls_happy_path(monkeypatch):
    monkeypatch.setattr(tls, "_connect", lambda h, p, t, ciphers=None: (b"DER", "TLSv1.3", ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)))
    monkeypatch.setattr(tls, "_decode_der", lambda der: _CERT)
    monkeypatch.setattr(tls, "_supports_weak_ciphers", lambda h, p, t: False)

    info = tls.inspect_tls("example.com", 443)
    assert info.ok is True
    assert info.subject == "commonName=example.com"
    assert info.issuer == "commonName=Real CA"
    assert info.sans == ["example.com", "*.example.com"]
    assert info.protocol == "TLSv1.3"
    assert info.cipher == "TLS_AES_256_GCM_SHA384"
    assert info.cipher_bits == 256
    assert info.weak_protocol is False
    assert info.weak_cipher is False
    assert info.self_signed is False
    assert info.expired is False
    assert info.days_until_expiry is not None and info.days_until_expiry > 0


def test_inspect_tls_flags_weaknesses(monkeypatch):
    self_signed_cert = dict(_CERT)
    self_signed_cert["issuer"] = self_signed_cert["subject"]
    self_signed_cert["notAfter"] = "Jan  1 00:00:00 2000 GMT"  # expired

    monkeypatch.setattr(tls, "_connect", lambda h, p, t, ciphers=None: (b"DER", "TLSv1", ("ECDHE-RSA-RC4-SHA", "TLSv1", 128)))
    monkeypatch.setattr(tls, "_decode_der", lambda der: self_signed_cert)
    monkeypatch.setattr(tls, "_supports_weak_ciphers", lambda h, p, t: True)

    info = tls.inspect_tls("bad.example", 443)
    assert info.weak_protocol is True       # TLSv1
    assert info.weak_cipher is True         # RC4
    assert info.supports_weak_ciphers is True
    assert info.self_signed is True
    assert info.expired is True
    assert info.days_until_expiry < 0


def test_inspect_tls_connect_failure(monkeypatch):
    def boom(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(tls, "_connect", boom)
    info = tls.inspect_tls("unreachable.example", 443)
    assert info.ok is False
    assert "refused" in (info.error or "")


def test_inspect_tls_skip_weak_probe(monkeypatch):
    called = {"probed": False}

    def probe(*a, **k):
        called["probed"] = True
        return True

    monkeypatch.setattr(tls, "_connect", lambda h, p, t, ciphers=None: (b"DER", "TLSv1.3", ("X", "TLSv1.3", 256)))
    monkeypatch.setattr(tls, "_decode_der", lambda der: _CERT)
    monkeypatch.setattr(tls, "_supports_weak_ciphers", probe)

    tls.inspect_tls("example.com", 443, probe_weak_ciphers=False)
    assert called["probed"] is False


def test_inspect_tls_dict(monkeypatch):
    monkeypatch.setattr(tls, "_connect", lambda h, p, t, ciphers=None: (b"DER", "TLSv1.3", ("X", "TLSv1.3", 256)))
    monkeypatch.setattr(tls, "_decode_der", lambda der: _CERT)
    monkeypatch.setattr(tls, "_supports_weak_ciphers", lambda h, p, t: False)
    d = tls.inspect_tls_dict("example.com")
    assert d["ok"] is True
    assert d["protocol"] == "TLSv1.3"


def test_supports_weak_ciphers_false_on_error(monkeypatch):
    def boom(*a, **k):
        raise ssl.SSLError("no cipher")

    monkeypatch.setattr(tls, "_connect", boom)
    assert tls._supports_weak_ciphers("h", 443, 2.0) is False
