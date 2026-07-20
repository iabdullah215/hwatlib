"""TLS / certificate inspection.

Connects to a TLS service and reports certificate details (subject, issuer,
Subject Alternative Names, validity window and days-until-expiry) plus the
negotiated protocol and cipher, flagging weak protocols/ciphers. Read-only.

The certificate is fetched with verification disabled so that self-signed,
expired, or hostname-mismatched certificates can still be *inspected* (the point
is to surface those problems, not to reject them). Verification state is
reported via ``expired`` / ``self_signed`` rather than by raising.
"""

from __future__ import annotations

import os
import socket
import ssl
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from .models import TlsCertInfo
from .utils import get_logger

logger = get_logger()

# Protocols considered weak/deprecated.
_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
# Substrings that mark a cipher suite as weak.
_WEAK_CIPHER_MARKERS = ("RC4", "DES", "NULL", "EXPORT", "MD5", "ANON", "ADH", "AECDH")
# Cipher string offered when probing whether a server still accepts weak ciphers.
_WEAK_CIPHER_PROBE = "RC4:3DES:DES-CBC3-SHA:NULL:EXPORT:aNULL:eNULL:LOW:MD5"


def _name_to_str(rdns: Any) -> Optional[str]:
    """Render an X.509 name (tuple of RDNs) as a comma-separated string."""
    if not rdns:
        return None
    parts: List[str] = []
    for rdn in rdns:
        try:
            for key, value in rdn:
                parts.append(f"{key}={value}")
        except (TypeError, ValueError):
            continue
    return ", ".join(parts) or None


def _extract_sans(cert: Dict[str, Any]) -> List[str]:
    sans: List[str] = []
    for entry in cert.get("subjectAltName", ()) or ():
        try:
            typ, val = entry
        except (TypeError, ValueError):
            continue
        sans.append(str(val) if typ == "DNS" else f"{typ}:{val}")
    return sans


def _decode_der(der: bytes) -> Optional[Dict[str, Any]]:
    """Parse a DER certificate into the dict shape returned by getpeercert().

    Uses the stdlib decoder via a temporary PEM file so that any certificate can
    be parsed regardless of validity (getpeercert() returns {} under CERT_NONE).
    """
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
    except Exception as e:  # pragma: no cover - defensive
        logger.debug("DER->PEM conversion failed error=%s", e)
        return None

    path = None
    try:
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except Exception as e:
        logger.debug("Certificate decode failed error=%s", e)
        return None
    finally:
        if path is not None:
            try:
                os.unlink(path)
            except OSError:
                pass


def _connect(
    host: str, port: int, timeout: float, *, ciphers: Optional[str] = None
) -> Tuple[Optional[bytes], Optional[str], Optional[Tuple[str, str, int]]]:
    """Open a TLS connection (verification disabled) and return cert + cipher."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if ciphers:
        ctx.set_ciphers(ciphers)
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as sock:
            der = sock.getpeercert(binary_form=True)
            return der, sock.version(), sock.cipher()


def _is_weak_cipher(name: Optional[str], bits: Optional[int]) -> bool:
    if bits is not None and bits < 128:
        return True
    if name:
        upper = name.upper()
        return any(marker in upper for marker in _WEAK_CIPHER_MARKERS)
    return False


def _supports_weak_ciphers(host: str, port: int, timeout: float) -> bool:
    """Best-effort: does the server complete a handshake using only weak ciphers?"""
    try:
        _connect(host, port, timeout, ciphers=_WEAK_CIPHER_PROBE)
        return True
    except Exception:
        # No such ciphers locally, or the server refused them -> not supported.
        return False


def _expiry(not_after: Optional[str]) -> Tuple[Optional[int], bool]:
    if not not_after:
        return None, False
    try:
        expires_at = ssl.cert_time_to_seconds(not_after)
    except (ValueError, TypeError):
        return None, False
    days = int((expires_at - time.time()) // 86400)
    return days, days < 0


def inspect_tls(
    host: str,
    port: int = 443,
    *,
    timeout: float = 5.0,
    probe_weak_ciphers: bool = True,
) -> TlsCertInfo:
    """Inspect a TLS service's certificate and negotiated parameters."""
    try:
        der, protocol, cipher = _connect(host, port, timeout)
    except Exception as e:
        logger.debug("TLS inspect connect failed host=%s port=%s error=%s", host, port, e)
        return TlsCertInfo(ok=False, host=host, port=port, error=str(e))

    cert = _decode_der(der) if der else None
    subject = issuer = None
    sans: List[str] = []
    not_before = not_after = None
    days_until_expiry: Optional[int] = None
    expired = False
    self_signed = False

    if cert:
        subject = _name_to_str(cert.get("subject"))
        issuer = _name_to_str(cert.get("issuer"))
        sans = _extract_sans(cert)
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        days_until_expiry, expired = _expiry(not_after)
        self_signed = bool(subject and subject == issuer)

    cipher_name = cipher[0] if cipher else None
    cipher_bits = cipher[2] if cipher else None

    return TlsCertInfo(
        ok=True,
        host=host,
        port=port,
        subject=subject,
        issuer=issuer,
        sans=sans,
        not_before=not_before,
        not_after=not_after,
        days_until_expiry=days_until_expiry,
        expired=expired,
        self_signed=self_signed,
        protocol=protocol,
        cipher=cipher_name,
        cipher_bits=cipher_bits,
        weak_protocol=bool(protocol) and protocol in _WEAK_PROTOCOLS,
        weak_cipher=_is_weak_cipher(cipher_name, cipher_bits),
        supports_weak_ciphers=_supports_weak_ciphers(host, port, timeout) if probe_weak_ciphers else False,
    )


def inspect_tls_dict(host: str, port: int = 443, *, timeout: float = 5.0) -> Dict[str, Any]:
    return inspect_tls(host, port, timeout=timeout).to_dict()


__all__ = ["inspect_tls", "inspect_tls_dict"]
