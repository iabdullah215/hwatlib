from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
from pathlib import Path
from typing import List, Optional

from .config import load_config
from .http import HttpOptions
from .plugins import list_checks
from .report import HwatReport
from .web import export_sitemap_csv, export_sitemap_json
from .workflows import build_report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="hwat", description="hwatlib unified CLI")
    sub = parser.add_subparsers(dest="cmd")

    p_report = sub.add_parser("report", help="Generate a read-only report")
    p_report.add_argument("target", help="Domain/IP (or URL if --url omitted)")
    p_report.add_argument("--url", default=None, help="Base URL (default: http://<target>)")

    p_report.add_argument(
        "--async",
        dest="async_mode",
        action="store_true",
        help="Use async web mode (requires aiohttp extra)",
    )

    p_report.add_argument("--profile", default="default", help="Config profile name (default: default)")
    p_report.add_argument("--config", default=None, help="Path to config.toml (default: ~/.config/hwat/config.toml)")

    p_report.add_argument("--timeout", type=float, default=None, help="HTTP timeout seconds")
    p_report.add_argument("--verify", dest="verify", action="store_true", help="Verify TLS certs")
    p_report.add_argument("--no-verify", dest="verify", action="store_false", help="Disable TLS verification")
    p_report.set_defaults(verify=None)
    p_report.add_argument("--rate-limit", type=float, default=None, help="Max HTTP requests per second")

    p_report.add_argument("--dns-wordlist", default=None, help="Wordlist path for subdomain discovery")
    p_report.add_argument("--reverse-ip", action="append", default=None, help="IP for reverse-DNS (repeatable)")
    p_report.add_argument("--secrets-path", action="append", default=None, help="Path to scan for secrets (repeatable)")

    p_report.add_argument("--plugin", action="append", default=None, help="Plugin name or module:function (repeatable)")
    p_report.add_argument("--list-plugins", action="store_true", help="List registered plugins and exit")

    p_report.add_argument("--nmap", action="store_true", help="Enable nmap scan (off by default)")

    p_report.add_argument("--out-json", default=None, help="Write full report JSON to file")
    p_report.add_argument("--out-md", default=None, help="Write full report Markdown to file")
    p_report.add_argument("--sitemap-json", default=None, help="Write sitemap links JSON to file")
    p_report.add_argument("--sitemap-csv", default=None, help="Write sitemap links CSV to file")

    p_diff = sub.add_parser("diff", help="Diff two report JSON files")
    p_diff.add_argument("old", help="Path to old report JSON")
    p_diff.add_argument("new", help="Path to new report JSON")

    args = parser.parse_args(argv)

    if args.cmd == "diff":
        from .diff import diff_reports, load_report_json

        old = load_report_json(args.old)
        new = load_report_json(args.new)
        diff = diff_reports(old, new)
        print(json.dumps(diff.to_dict(), indent=2, default=str))
        return 0

    if args.cmd != "report":
        parser.print_help()
        return 2

    exit_code = _maybe_list_plugins(args)
    if exit_code is not None:
        return exit_code

    cfg = load_config(profile=args.profile, path=args.config)
    http = _merge_http_options(cfg.http, args)

    if args.async_mode:
        if importlib.util.find_spec("aiohttp") is None:
            raise SystemExit("Async mode requires aiohttp. Install with: pip install -e '.[async]'")

        from .workflows_async import build_report_async

        report = asyncio.run(
            build_report_async(
                target=args.target,
                url=args.url,
                dns_wordlist=args.dns_wordlist,
                reverse_ips=args.reverse_ip,
                secrets_paths=args.secrets_path,
                plugins=args.plugin,
                http_options=http,
                nmap=bool(args.nmap),
            )
        )
    else:
        report = _run_report(args, http)

    _emit_outputs(report, args)
    return 0


def _maybe_list_plugins(args: argparse.Namespace) -> Optional[int]:
    if not args.list_plugins:
        return None
    plugins = list_checks()
    if not plugins:
        print("(no registered plugins)")
        return 0
    for name, meta in plugins.items():
        desc = getattr(meta, "description", None) or ""
        sev = getattr(meta, "severity", None) or ""
        suffix = ""
        if desc or sev:
            suffix = f" - {sev} {desc}".strip()
        print(f"{name}{suffix}")
    return 0


def _run_report(args: argparse.Namespace, http: HttpOptions) -> HwatReport:
    if args.async_mode:
        return _run_report_async(args, http)
    return build_report(
        target=args.target,
        url=args.url,
        dns_wordlist=args.dns_wordlist,
        reverse_ips=args.reverse_ip,
        secrets_paths=args.secrets_path,
        plugins=args.plugin,
        http_options=http,
        nmap=bool(args.nmap),
    )


def _run_report_async(args: argparse.Namespace, http: HttpOptions) -> HwatReport:
    if importlib.util.find_spec("aiohttp") is None:
        raise SystemExit("Async mode requires aiohttp. Install with: pip install -e '.[async]'")

    from .workflows_async import build_report_async

    return asyncio.run(
        build_report_async(
            target=args.target,
            url=args.url,
            dns_wordlist=args.dns_wordlist,
            reverse_ips=args.reverse_ip,
            secrets_paths=args.secrets_path,
            plugins=args.plugin,
            http_options=http,
            nmap=bool(args.nmap),
        )
    )


def _merge_http_options(base: HttpOptions, args) -> HttpOptions:
    # mutate a copy-ish (HttpOptions is a dataclass)
    http = HttpOptions(**base.__dict__)

    if args.timeout is not None:
        http.timeout = float(args.timeout)
    if args.verify is not None:
        http.verify = bool(args.verify)
    if args.rate_limit is not None:
        http.rate_limit_per_sec = float(args.rate_limit)

    return http


def _emit_outputs(report: HwatReport, args) -> None:
    if args.out_json:
        Path(args.out_json).write_text(report.to_json(indent=2), encoding="utf-8")
    if args.out_md:
        Path(args.out_md).write_text(report.to_markdown(), encoding="utf-8")

    _emit_sitemap_outputs(report, args)

    # Default output to stdout if no files provided
    if not any([args.out_json, args.out_md]):
        print(report.to_json(indent=2))


def _emit_sitemap_outputs(report: HwatReport, args) -> None:
    sitemap = _get_sitemap(report)
    if not sitemap:
        return

    base, links = sitemap
    if args.sitemap_json:
        export_sitemap_json(base, links, args.sitemap_json)
    if args.sitemap_csv:
        export_sitemap_csv(base, links, args.sitemap_csv)


def _get_sitemap(report: HwatReport):
    try:
        web = report.web
        if hasattr(web, "to_dict"):
            web = web.to_dict()
        if not isinstance(web, dict) or not web:
            return None

        sitemap = web.get("sitemap")
        if hasattr(sitemap, "to_dict"):
            sitemap = sitemap.to_dict()
        if not isinstance(sitemap, dict):
            return None

        base = sitemap.get("base")
        links = sitemap.get("links")
        if not isinstance(base, str) or not isinstance(links, list):
            return None
        return base, links
    except Exception:
        return None
