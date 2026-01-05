import logging
import re
import shlex
import socket
import subprocess
import warnings
from datetime import datetime
from typing import Optional, Sequence, Union

import requests
import urllib3


def setup_logger(name: str = "hwatlib", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger


logger = setup_logger()


_IPV4_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def resolve_host(target: str) -> Optional[str]:
    """Resolve a hostname to an IPv4 address.

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
        # Fallback to nslookup when available (common on pentest boxes)
        try:
            result = subprocess.check_output(["nslookup", target], stderr=subprocess.STDOUT).decode(errors="ignore")
            match = re.search(r"Address: (\d+\.\d+\.\d+\.\d+)", result)
            if match:
                return match.group(1)
        except Exception:
            pass

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
    except Exception as e:
        return f"Banner grab failed: {e}"


def run_command(command: str) -> Optional[str]:
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
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        return None


def run_command_unsafe_shell(command: str) -> Optional[str]:
    """Run a system command through the shell (unsafe).

    Prefer run_command() whenever possible.
    """

    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.strip() if result.stdout else result.stderr.strip()
    except Exception as e:
        logger.error(f"Shell command execution failed: {e}")
        return None


def check_sudo() -> bool:
    """Check if the current user has sudo privileges."""
    try:
        result = subprocess.run("sudo -n true", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except Exception:
        return False


def fetch_url(url: str, timeout: int = 5, *, verify: bool = True, suppress_insecure_warning: bool = False) -> Optional[str]:
    """Fetch contents of a URL.

    Safer default: TLS verification is enabled by default.
    To disable verification, pass verify=False explicitly.
    """
    try:
        if verify is False and suppress_insecure_warning:
            warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        resp = requests.get(url, timeout=timeout, verify=verify)
        return resp.text
    except Exception as e:
        logger.error(f"Failed to fetch {url}: {e}")
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
    except Exception as e:
        logger.error(f"Could not save file {filename}: {e}")
