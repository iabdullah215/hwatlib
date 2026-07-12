from __future__ import annotations

import logging
import os
import re
import shlex
import socket
import subprocess
import sys
import warnings
from datetime import datetime
from typing import Optional, Sequence

import requests
import urllib3


def get_logger(name: str = "hwatlib") -> logging.Logger:
    """Return a library logger without configuring handlers or output.

    Library code should use this so that merely importing hwatlib does not
    attach handlers or hijack logging for the host application. Applications
    (e.g. the CLIs) opt into visible output by calling setup_logger().
    """
    return logging.getLogger(name)


AUTHORIZED_USE_NOTICE = (
    "hwatlib: authorized use only. Run this only against systems you own or have "
    "explicit written permission to test. Unauthorized access is illegal and is "
    "solely your responsibility. See SECURITY.md. Set HWAT_NO_BANNER=1 to silence."
)

_banner_shown = False


def authorized_use_banner(*, force: bool = False) -> None:
    """Print a one-time authorized-use notice to stderr.

    Written to stderr so machine-readable stdout (JSON reports, sitemaps) is
    never polluted. Suppressed when HWAT_NO_BANNER is set in the environment,
    which is convenient for scripted/CI runs.
    """
    global _banner_shown
    if _banner_shown and not force:
        return
    _banner_shown = True
    if os.environ.get("HWAT_NO_BANNER"):
        return
    print(f"[!] {AUTHORIZED_USE_NOTICE}", file=sys.stderr)


def setup_logger(name: str = "hwatlib", level: int = logging.INFO) -> logging.Logger:
    """Configure a StreamHandler for visible output. For application/CLI use.

    Libraries should not call this at import time; use get_logger() instead.
    """
    logger = logging.getLogger(name)
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        handler = logging.StreamHandler()
        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger


logger = get_logger()


_IPV4_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def _resolve_with_dnspython(target: str) -> Optional[str]:
    """Resolve an A record using dnspython, if the optional ``dns`` extra is installed.

    Returns the first A-record address, or None if dnspython is unavailable or
    resolution fails. ``import dns`` refers to top-level dnspython, not the
    ``hwatlib.dns`` submodule.
    """
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return None
    try:
        for rdata in dns.resolver.resolve(target, "A"):
            return str(rdata)
    except Exception as e:  # dns.exception.DNSException and friends
        logger.debug("dnspython resolution failed target=%s error=%s", target, e)
    return None


def resolve_host(target: str) -> Optional[str]:
    """Resolve a hostname to an IPv4 address.

    Resolution order: the input itself if already an IPv4 literal, then the
    stdlib resolver, then dnspython (the optional ``dns`` extra), and finally a
    ``nslookup`` subprocess as a last resort.

    Returns:
    - IPv4 string when resolved
    - the input if it is already an IPv4 string
    - None if resolution fails
    """

    if not target:
        return None
    if _IPV4_RE.fullmatch(target):
        return target

    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        # Prefer the dnspython library path (no subprocess) when available.
        resolved = _resolve_with_dnspython(target)
        if resolved:
            return resolved

        # Last resort: nslookup, if present (common on pentest boxes).
        try:
            result = subprocess.check_output(["nslookup", target], stderr=subprocess.STDOUT).decode(errors="ignore")
            match = re.search(r"Address: (\d+\.\d+\.\d+\.\d+)", result)
            if match:
                return match.group(1)
        except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
            logger.debug("nslookup fallback failed target=%s error=%s", target, e)

        logger.error(f"Could not resolve host: {target}")
        return None


def resolve_domain(domain: str) -> Optional[str]:
    """Backwards-compatible alias for resolve_host()."""
    return resolve_host(domain)


def grab_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    """Grab service banner from a port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore")
            return banner.strip()
    except (OSError, socket.timeout) as e:
        logger.debug("Banner grab failed ip=%s port=%s error=%s", ip, port, e)
        return f"Banner grab failed: {e}"


def run_command(command: Sequence[str] | str) -> Optional[str]:
    """Run a system command safely (no shell) and return its output.

    This is intentionally *not* a shell helper. If you pass a string, it will
    be tokenized via shlex and executed without a shell.

    Use run_command_unsafe_shell() only when you truly need shell features.
    """
    try:
        argv: Sequence[str]
        if isinstance(command, str):
            argv = shlex.split(command)
        else:
            argv = command

        result = subprocess.run(argv, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.strip() if result.stdout else result.stderr.strip()
    except ValueError as e:
        logger.error("Command parsing failed command=%r error=%s", command, e)
        return None
    except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
        logger.error("Command execution failed command=%r error=%s", command, e)
        return None


def run_command_unsafe_shell(command: str) -> Optional[str]:
    """Deprecated compatibility wrapper.

    For security, shell execution is disabled. This helper now delegates to
    run_command(), which executes without a shell.
    """

    logger.warning("run_command_unsafe_shell() is deprecated; executing without shell")
    return run_command(command)


def check_sudo() -> bool:
    """Check if the current user has sudo privileges."""
    try:
        result = subprocess.run(["sudo", "-n", "true"], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
        logger.debug("Sudo check failed error=%s", e)
        return False


def fetch_url(url: str, timeout: float = 5.0, *, verify: bool = True, suppress_insecure_warning: bool = False) -> Optional[str]:
    """Fetch contents of a URL.

    Safer default: TLS verification is enabled by default.
    To disable verification, pass verify=False explicitly.
    """
    try:
        # Scope any warning suppression to this call only, so one insecure
        # request does not silence InsecureRequestWarning process-wide.
        with warnings.catch_warnings():
            if verify is False and suppress_insecure_warning:
                warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
            resp = requests.get(url, timeout=timeout, verify=verify)
            return resp.text
    except requests.RequestException as e:
        logger.error("Failed to fetch url=%s: %s", url, e)
        return None


def extract_links(html: str) -> list:
    """Extract all href links from HTML."""
    return re.findall(r"href=['\"]?([^'\" >]+)", html)


def timestamp() -> str:
    """Return current timestamp."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def save_to_file(filename: str, data: str) -> None:
    """Save data to a file."""
    try:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(data + "\n")
        logger.info(f"Data saved to {filename}")
    except OSError as e:
        logger.error("Could not save file filename=%s error=%s", filename, e)
