import socket
import subprocess
import re
import requests
import logging
from datetime import datetime

def setup_logger(name="hwatlib", level=logging.INFO):
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger

logger = setup_logger()

def resolve_domain(domain: str) -> str:
    """Resolve domain to IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.error:
        logger.error(f"Could not resolve domain: {domain}")
        return None

def grab_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    """Grab service banner from a port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore")
            return banner.strip()
    except Exception as e:
        return f"Banner grab failed: {e}"

def run_command(command: str) -> str:
    """Run a system command and return its output."""
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.strip() if result.stdout else result.stderr.strip()
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        return None

def check_sudo() -> bool:
    """Check if the current user has sudo privileges."""
    try:
        result = subprocess.run("sudo -n true", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except Exception:
        return False

def fetch_url(url: str, timeout: int = 5) -> str:
    """Fetch contents of a URL."""
    try:
        resp = requests.get(url, timeout=timeout, verify=False)
        return resp.text
    except Exception as e:
        logger.error(f"Failed to fetch {url}: {e}")
        return None

def extract_links(html: str) -> list:
    """Extract all href links from HTML."""
    return re.findall(r'href=[\'"]?([^\'" >]+)', html)

def timestamp() -> str:
    """Return current timestamp."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def save_to_file(filename: str, data: str):
    """Save data to a file."""
    try:
        with open(filename, "a") as f:
            f.write(data + "\n")
        logger.info(f"Data saved to {filename}")
    except Exception as e:
        logger.error(f"Could not save file {filename}: {e}")
