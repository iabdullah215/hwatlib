"""Build a safe-by-default report for a target and print JSON + Markdown.

Usage:
    python examples/recon_report.py <target>   # e.g. an authorized host you own

`build_report` performs no state-changing actions and leaves nmap disabled by
default. Only run this against systems you are authorized to test.
"""

import sys

from hwatlib.workflows import build_report


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"

    report = build_report(target=target, url=f"http://{target}")

    print("=== JSON ===")
    print(report.to_json())

    print("\n=== Markdown ===")
    print(report.to_markdown())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
