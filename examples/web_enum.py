"""Web enumeration: fetch headers/forms/JS and crawl a site.

Usage:
    python examples/web_enum.py <url>   # e.g. http://localhost:8000

Only run this against web applications you are authorized to test.
"""

import sys

from hwatlib import web


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"

    result = web.fetch_all(url)
    print("[headers]")
    for key, value in result.headers.items():
        print(f"  {key}: {value}")

    print("\n[forms]")
    for form in result.forms:
        print(" ", form.to_dict())

    print("\n[js]")
    for src in result.js:
        print(" ", src)

    print("\n[crawl depth=1]")
    crawl = web.crawl(url, depth=1)
    for link in crawl.to_dict().get("links", []):
        print(" ", link)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
