import argparse
import asyncio
import re
import shlex
import socket
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional

from .models import NmapResult
from .utils import resolve_host, setup_logger

logger = setup_logger()

DEFAULT_NMAP_OPTIONS = "-sV -sC -A"


@dataclass
class ReconSession:
    target: str
    ip: str
    nmap_output: Optional[str] = None
    open_tcp: Optional[List[int]] = None
    open_udp: Optional[List[int]] = None


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


def run_nmap(target: str, options: str = DEFAULT_NMAP_OPTIONS, udp: bool = False) -> NmapResult:
    """Run Nmap and return a typed result contract."""

    try:
        output = subprocess.check_output(["nmap"] + shlex.split(options) + [target], stderr=subprocess.STDOUT).decode(
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

        return NmapResult(ok=True, output=output, open_tcp=open_tcp, open_udp=open_udp)
    except Exception as e:
        return NmapResult(ok=False, output="", open_tcp=[], open_udp=[], error=str(e))


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

def init(target: str, *, add_to_hosts: bool = False, ip: Optional[str] = None) -> Optional[ReconSession]:
    """Initialize and return a recon session context."""

    resolved = resolve_target(target, ip=ip, add_to_hosts=add_to_hosts)
    if not resolved:
        logger.error("Could not resolve target: %s", target)
        return None

    return ReconSession(target=target, ip=resolved, open_tcp=[], open_udp=[])


def _resolve_scan_target(
    *,
    target: Optional[str],
    session: Optional[ReconSession],
    caller: str,
) -> str:
    if target is not None:
        return target
    if session is not None:
        return session.ip
    raise RuntimeError(f"{caller} requires either target=... or session=...")


def nmap_scan(
    options: str = DEFAULT_NMAP_OPTIONS,
    udp: bool = False,
    *,
    target: Optional[str] = None,
    session: Optional[ReconSession] = None,
)-> NmapResult:
    """Run an Nmap scan using explicit target/session context."""

    target = _resolve_scan_target(target=target, session=session, caller="recon.nmap_scan")

    logger.info("Running nmap against %s", target)

    nmap_result = run_nmap(target, options=options, udp=udp)

    if session is not None and target == session.ip:
        session.nmap_output = nmap_result.output
        session.open_tcp = list(nmap_result.open_tcp)
        session.open_udp = list(nmap_result.open_udp)

    return nmap_result


def nmap_scan_typed(
    options: str = DEFAULT_NMAP_OPTIONS,
    udp: bool = False,
    *,
    target: Optional[str] = None,
    session: Optional[ReconSession] = None,
) -> NmapResult:
    target = _resolve_scan_target(target=target, session=session, caller="recon.nmap_scan_typed")
    result = run_nmap(target, options=options, udp=udp)
    if session is not None and target == session.ip:
        session.nmap_output = result.output
        session.open_tcp = list(result.open_tcp)
        session.open_udp = list(result.open_udp)
    return result


def banner_grab(
    host: Optional[str] = None,
    ports: Optional[List[int]] = None,
    *,
    session: Optional[ReconSession] = None,
):
    """Grab banners.

    Supports both:
    - Context style: recon.banner_grab(session=s)
    - Explicit style: recon.banner_grab(host, ports)
    """

    if host is not None and ports is not None:
        return _banner_grab_ports(host, ports)

    if session is None:
        raise RuntimeError("recon.banner_grab() requires host+ports or session=...")

    session_ports = session.open_tcp or []
    return _banner_grab_ports(session.ip, session_ports)


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

    session = init(args.target, add_to_hosts=args.add_to_hosts)
    if not session:
        print("[-] Could not resolve target")
        return 2

    nmap_result = nmap_scan(options=args.options, udp=args.udp, session=session)
    print(nmap_result.output if nmap_result.ok else f"[-] Nmap failed: {nmap_result.error}")

    if session.open_tcp:
        banners = _banner_grab_ports(session.ip, session.open_tcp)
        for port, banner in banners.items():
            if banner:
                print(f"{port}/tcp: {banner}")

    return 0
