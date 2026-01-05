from __future__ import annotations

import re
import socket
import ssl
from typing import Any, Dict, Optional


HTTP_PORTS = {80, 8080, 8000, 8008, 8888}
HTTPS_PORTS = {443, 8443}


def _try_tls(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except ssl.SSLCertVerificationError:
        # TLS is present but the cert is invalid/untrusted for this hostname.
        return True
    except Exception:
        return False


def _get_tls_cert_info(host: str, port: int, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
    """Return peer certificate info using a verifying context.

    If verification fails, returns None (we do not disable verification).
    """

    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                return s.getpeercert() or None
    except ssl.SSLCertVerificationError:
        return None
    except Exception:
        return None


def _try_ssh_banner(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(256).decode(errors="ignore").strip()
            return banner if banner.startswith("SSH-") else None
    except Exception:
        return None


def _try_http_server_header(host: str, port: int, timeout: float, *, tls: bool) -> Optional[str]:
    req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        sock = raw
        if tls:
            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            sock = ctx.wrap_socket(raw, server_hostname=host)
        sock.sendall(req)
        data = sock.recv(2048).decode(errors="ignore")
    m = re.search(r"^Server:\s*(.+)$", data, re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip() if m else None


def fingerprint_service(host: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """Best-effort service fingerprinting.

    Returns: {service, version, tls, notes}
    """

    info: Dict[str, Any] = {
        "service": "unknown",
        "version": None,
        "tls": False,
        "tls_cert": None,
        "notes": [],
    }

    banner = _try_ssh_banner(host, port, timeout)
    if banner:
        info["service"] = "ssh"
        info["version"] = banner
        return info

    tls = _try_tls(host, port, timeout=timeout)
    info["tls"] = tls
    if tls:
        info["tls_cert"] = _get_tls_cert_info(host, port, timeout=timeout)

    # Basic HTTP header probe (socket-based) to avoid extra deps
    if port in HTTP_PORTS or port in HTTPS_PORTS or tls:
        try:
            server = _try_http_server_header(host, port, timeout, tls=tls)
            info["service"] = "https" if tls else "http"
            info["version"] = server
            return info
        except ssl.SSLCertVerificationError:
            info["service"] = "https"
            info["tls"] = True
            info["notes"].append("tls_cert_verification_failed")
            return info
        except Exception:
            pass

    return info
