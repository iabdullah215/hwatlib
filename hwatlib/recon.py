import socket
import subprocess
import re
import os

def resolve_target(target, ip=None):
    """
    Resolve domain/IP and optionally add domain to /etc/hosts.
    Args:
        target (str): Domain or IP.
        ip (str): Optional IP if user provides both.
    Returns:
        str: IP address of the target
    """
    if ip and target:  # domain + IP given
        try:
            with open("/etc/hosts", "a") as f:
                f.write(f"\n{ip} {target}\n")
            print(f"[+] Added {target} -> {ip} to /etc/hosts")
            return ip
        except PermissionError:
            print("[-] Permission denied: run with sudo to modify /etc/hosts")
            return ip

    if not ip and not re.match(r"\d+\.\d+\.\d+\.\d+", target):
        # Only domain given → resolve
        try:
            result = subprocess.check_output(["nslookup", target]).decode()
            match = re.search(r"Address: (\d+\.\d+\.\d+\.\d+)", result)
            if match:
                ip = match.group(1)
                print(f"[+] Resolved {target} -> {ip}")
                return ip
        except Exception as e:
            print(f"[-] nslookup failed: {e}")
            return None

    return target  # Already IP


def run_nmap(target, options="-sV -sC -A", udp=False):
    """
    Run Nmap and return output + open ports list.
    Args:
        target (str): Target IP/domain
        options (str): Nmap options (default: -sV -sC -A)
        udp (bool): If True, run an additional -sU UDP scan
    Returns:
        (str, list, list): Nmap output, list of open TCP ports, list of open UDP ports
    """
    try:
        # TCP scan
        output = subprocess.check_output(
            ["nmap"] + options.split() + [target]
        ).decode()

        open_tcp = []
        for line in output.splitlines():
            if re.match(r"^\d+/tcp\s+open", line):
                port = int(line.split("/")[0])
                open_tcp.append(port)

        open_udp = []
        if udp:
            print("[*] Running UDP scan (this may take time)...")
            udp_output = subprocess.check_output(
                ["nmap", "-sU", target]
            ).decode()
            output += "\n\n" + udp_output

            for line in udp_output.splitlines():
                if re.match(r"^\d+/udp\s+open", line):
                    port = int(line.split("/")[0])
                    open_udp.append(port)

        return output, open_tcp, open_udp
    except Exception as e:
        return f"[-] Nmap failed: {e}", [], []


def banner_grab(host, ports):
    """
    Grab banners for given open ports.
    Args:
        host (str): IP/Domain
        ports (list): List of open ports
    Returns:
        dict: {port: banner/None}
    """
    results = {}
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect((host, port))
            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode(errors="ignore")
                results[port] = banner.strip().split("\n")[0]
            except:
                results[port] = "Open (no banner)"
        except:
            results[port] = None
        finally:
            s.close()
    return results
