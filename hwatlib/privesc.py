import argparse
from typing import Any, Dict, List, Optional

from . import postex
from .models import PrivescScore


CONFIRM_HELP = "Actually perform the change"


def run_checks() -> Dict[str, Any]:
    """README helper: privesc.run_checks()."""

    return postex.full_recon()


def enumerate_sudo():
    """README helper: privesc.enumerate_sudo()."""

    return postex.check_sudo_rights()


def enumerate_cron():
    """README helper: privesc.enumerate_cron()."""

    return postex.list_scheduled_tasks()


def kernel_exploits():
    """README helper: privesc.kernel_exploits()."""

    return postex.check_kernel_exploits()


def risk_score(report: Dict[str, Any]) -> PrivescScore:
    """Best-effort privesc risk scoring for the output of postex.full_recon().

    Returns a small, stable structure:
      {score: int, level: str, reasons: [str]}
    """

    NOT_APPLICABLE = "not applicable"
    score = 0
    reasons: List[str] = []

    def has_any(text: str, needles: List[str]) -> bool:
        t = (text or "").lower()
        return any(n in t for n in needles)

    def usable_text(value: Any) -> str:
        return str(value or "")

    sudo_rights = usable_text(report.get("sudo_rights"))
    if has_any(sudo_rights, ["(all", "nopasswd"]):
        score += 35
        reasons.append("sudo_rights_present")

    suid_bins = usable_text(report.get("suid_bins"))
    if suid_bins.strip() and NOT_APPLICABLE not in suid_bins.lower():
        score += 20
        reasons.append("suid_binaries_found")

    history = usable_text(report.get("bash_history"))
    if has_any(history, ["password", "token", "apikey", "secret", "ssh"]):
        score += 10
        reasons.append("history_may_contain_secrets")

    ssh_keys = usable_text(report.get("ssh_keys"))
    ssh_keys_l = ssh_keys.lower()
    if ssh_keys.strip() and NOT_APPLICABLE not in ssh_keys_l and "failed" not in ssh_keys_l:
        score += 10
        reasons.append("ssh_private_keys_may_exist")

    shares = usable_text(report.get("network_shares"))
    if shares.strip() and NOT_APPLICABLE not in shares.lower():
        score += 5
        reasons.append("network_shares_detected")

    score = max(0, min(100, score))
    if score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"
    return PrivescScore(score=score, level=level, reasons=reasons)


def risk_score_dict(report: Dict[str, Any]) -> Dict[str, Any]:
    return risk_score(report).to_dict()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="hwat-post", description="hwatlib privesc/post-exploitation helpers")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("checks", help="Run read-only post-exploitation checks (default)")
    sub.add_parser("sudo", help="Show sudo rights")
    sub.add_parser("cron", help="Show scheduled tasks / crontab")
    sub.add_parser("kernel", help="Show kernel version")

    p_cron = sub.add_parser("add-cronjob", help="Add a cronjob (requires --confirm)")
    p_cron.add_argument("command", help="Command to run")
    p_cron.add_argument("--schedule", default="* * * * *", help="Cron schedule (default: every minute)")
    p_cron.add_argument("--confirm", action="store_true", help=CONFIRM_HELP)

    p_ssh = sub.add_parser("backdoor-ssh", help="Append a pubkey to authorized_keys (requires --confirm)")
    p_ssh.add_argument("pubkey", help="Public key string")
    p_ssh.add_argument("--confirm", action="store_true", help=CONFIRM_HELP)

    p_task = sub.add_parser("add-schtask", help="Create a Windows scheduled task (requires --confirm)")
    p_task.add_argument("command", help="Command to run")
    p_task.add_argument("--name", default="hwat_backdoor", help="Task name")
    p_task.add_argument("--schedule", default="MINUTE", help="schtasks schedule")
    p_task.add_argument("--confirm", action="store_true", help=CONFIRM_HELP)

    p_hash = sub.add_parser("extract-hashes-windows", help="Save SAM/SYSTEM hives (requires --confirm)")
    p_hash.add_argument("--save-dir", default=None, help="Directory to save hives")
    p_hash.add_argument("--confirm", action="store_true", help=CONFIRM_HELP)

    args = parser.parse_args(argv)

    # Preserve old behavior: no subcommand -> full checks.
    cmd = args.cmd or "checks"

    return _dispatch_cli(cmd, args, parser)


def _dispatch_cli(cmd: str, args, parser: argparse.ArgumentParser) -> int:
    read_only = {
        "checks": lambda: postex.pretty_report(run_checks()),
        "sudo": lambda: postex.pretty_report(enumerate_sudo()),
        "cron": lambda: postex.pretty_report(enumerate_cron()),
        "kernel": kernel_exploits,
    }

    if cmd in read_only:
        print(read_only[cmd]())
        return 0

    mutators = {
        "add-cronjob": lambda: postex.add_cronjob_confirmed(args.command, schedule=args.schedule, confirm=bool(args.confirm)),
        "backdoor-ssh": lambda: postex.backdoor_ssh_confirmed(args.pubkey, confirm=bool(args.confirm)),
        "add-schtask": lambda: postex.add_schtask_confirmed(
            args.command, name=args.name, schedule=args.schedule, confirm=bool(args.confirm)
        ),
        "extract-hashes-windows": lambda: postex.extract_hashes_windows_confirmed(save_dir=args.save_dir, confirm=bool(args.confirm)),
    }

    if cmd in mutators:
        result = mutators[cmd]()
        if isinstance(result, dict):
            print(postex.pretty_report(result))
        else:
            print(result)
        return 0 if bool(getattr(args, "confirm", False)) else 2

    parser.print_help()
    return 2
