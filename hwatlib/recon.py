import argparse
import asyncio
import re
import socket
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .utils import resolve_host, setup_logger
from .models import NmapResult


logger = setup_logger()

DEFAULT_NMAP_OPTIONS = "-sV -sC -A"


@dataclass
class ReconSession:
    target: str
    ip: str
    nmap_output: Optional[str] = None
    open_tcp: Optional[List[int]] = None
    open_udp: Optional[List[int]] = None


_session: Optional[ReconSession] = None


def _is_ipv4(value: str) -> bool:
    return bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", value or ""))


def resolve_target(target: str, ip: Optional[str] = None, *, add_to_hosts: bool = False, hosts_path: str = "/etc/hosts") -> Optional[str]:
    """Resolve a domain/IP; optionally add domain->IP to /etc/hosts.

    Notes:
    - For safety, modifying /etc/hosts is opt-in via add_to_hosts=True.
    """

    resolved_ip = ip or resolve_host(target)

    if add_to_hosts and resolved_ip and target and not _is_ipv4(target):
        try:
            with open(hosts_path, "a", encoding="utf-8") as f:
                f.write(f"\n{resolved_ip} {target}\n")
        except PermissionError:
            # Keep the resolved IP even if hosts write fails.
            logger.warning("Permission denied writing %s; run as root to modify hosts", hosts_path)

    if resolved_ip:
        return resolved_ip
    if _is_ipv4(target):
        return target
    return None


def run_nmap(target: str, options: str = DEFAULT_NMAP_OPTIONS, udp: bool = False) -> Tuple[str, List[int], List[int]]:
    """Run Nmap and return output plus open ports lists."""

    try:
        output = subprocess.check_output(["nmap"] + options.split() + [target], stderr=subprocess.STDOUT).decode(
            errors="ignore"
        )

        open_tcp: List[int] = []
        for line in output.splitlines():
            if re.match(r"^\d+/tcp\s+open", line):
                open_tcp.append(int(line.split("/")[0]))

        open_udp: List[int] = []
        if udp:
            udp_output = subprocess.check_output(["nmap", "-sU", target], stderr=subprocess.STDOUT).decode(errors="ignore")
            output += "\n\n" + udp_output
            for line in udp_output.splitlines():
                if re.match(r"^\d+/udp\s+open", line):
                    open_udp.append(int(line.split("/")[0]))

        return output, open_tcp, open_udp
    except Exception as e:
        return f"[-] Nmap failed: {e}", [], []


def _banner_grab_ports(host: str, ports: List[int]) -> Dict[int, Optional[str]]:
    """Grab simple banners for a list of ports."""

    results: Dict[int, Optional[str]] = {}
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect((host, port))
            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode(errors="ignore")
                results[port] = banner.strip().split("\n")[0]
            except Exception:
                results[port] = "Open (no banner)"
        except Exception:
            results[port] = None
        finally:
            s.close()
    return results


# ----------------
# README-compatible convenience API
# ----------------

def init(target: str, *, add_to_hosts: bool = False, ip: Optional[str] = None) -> Optional[str]:
    """Initialize a global recon session (README: recon.init(...))."""

    global _session
    resolved = resolve_target(target, ip=ip, add_to_hosts=add_to_hosts)
    if not resolved:
        logger.error("Could not resolve target: %s", target)
        _session = None
        return None

    _session = ReconSession(target=target, ip=resolved, open_tcp=[], open_udp=[])
    return resolved


def nmap_scan(options: str = DEFAULT_NMAP_OPTIONS, udp: bool = False, *, target: Optional[str] = None):
    """Run an Nmap scan using the initialized session (README: recon.nmap_scan())."""

    global _session

    if target is None:
        if not _session:
            raise RuntimeError("recon.init(target) must be called before recon.nmap_scan()")
        target = _session.ip

    logger.info("Running nmap against %s", target)

    output, open_tcp, open_udp = run_nmap(target, options=options, udp=udp)

    if _session and target == _session.ip:
        _session.nmap_output = output
        _session.open_tcp = open_tcp
        _session.open_udp = open_udp

    return output


def nmap_scan_typed(options: str = DEFAULT_NMAP_OPTIONS, udp: bool = False, *, target: Optional[str] = None) -> NmapResult:
    global _session

    if target is None:
        if not _session:
            raise RuntimeError("recon.init(target) must be called before recon.nmap_scan_typed()")
        target = _session.ip

    try:
        output, open_tcp, open_udp = run_nmap(target, options=options, udp=udp)
        if _session and target == _session.ip:
            _session.nmap_output = output
            _session.open_tcp = open_tcp
            _session.open_udp = open_udp
        return NmapResult(ok=True, output=output, open_tcp=open_tcp, open_udp=open_udp)
    except Exception as e:
        return NmapResult(ok=False, output="", error=str(e))


def banner_grab(host: Optional[str] = None, ports: Optional[List[int]] = None):
    """Grab banners.

    Supports both:
    - README style: recon.banner_grab() (uses last scan session)
    - Explicit style: recon.banner_grab(host, ports)
    """

    if host is not None and ports is not None:
        return _banner_grab_ports(host, ports)

    if not _session:
        raise RuntimeError("recon.init(target) must be called before recon.banner_grab()")

    session_ports = _session.open_tcp or []
    return _banner_grab_ports(_session.ip, session_ports)


async def banner_grab_async(
    host: str,
    ports: List[int],
    *,
    max_concurrency: int = 50,
) -> Dict[int, Optional[str]]:
    sem = asyncio.Semaphore(max(1, int(max_concurrency or 1)))

    async def grab_one(port: int) -> tuple[int, Optional[str]]:
        async with sem:
            try:
                async with asyncio.timeout(2.0):
                    reader, writer = await asyncio.open_connection(host, port)
                try:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                    async with asyncio.timeout(2.0):
                        data = await reader.read(1024)
                    text = data.decode(errors="ignore").strip().split("\n")[0] if data else "Open (no banner)"
                    return port, text
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
            except Exception:
                return port, None

    pairs = await asyncio.gather(*(grab_one(p) for p in ports))
    return dict(pairs)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="hwat-recon", description="hwatlib recon helpers")
    parser.add_argument("target", help="Domain or IP")
    parser.add_argument("--add-to-hosts", action="store_true", help="Append domain->IP to /etc/hosts")
    parser.add_argument("--options", default=DEFAULT_NMAP_OPTIONS, help="Nmap options")
    parser.add_argument("--udp", action="store_true", help="Also run a UDP scan")
    args = parser.parse_args(argv)

    ip = init(args.target, add_to_hosts=args.add_to_hosts)
    if not ip:
        print("[-] Could not resolve target")
        return 2

    output = nmap_scan(options=args.options, udp=args.udp)
    print(output)

    if _session and _session.open_tcp:
        banners = _banner_grab_ports(_session.ip, _session.open_tcp)
        for port, banner in banners.items():
            if banner:
                print(f"{port}/tcp: {banner}")

    return 0
