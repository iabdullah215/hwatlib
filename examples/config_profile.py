"""Load a validated config profile (offline, safe to run anywhere).

hwatlib reads ~/.config/hwat/config.toml by default. Invalid or out-of-range
values are ignored with a warning unless strict mode is enabled. See the
"Config / Profiles" section of the README for the schema.
"""

from hwatlib.config import load_config


def main() -> None:
    # Falls back to safe defaults when no config file is present.
    cfg = load_config(profile="default")
    http = cfg.http
    print("Resolved HTTP options for profile 'default':")
    print("  timeout          :", http.timeout)
    print("  verify TLS       :", http.verify)
    print("  max_concurrency  :", http.max_concurrency)
    print("  retries          :", http.retries)

    # strict=True raises ValueError on malformed/out-of-range values instead.
    # cfg = load_config(profile="default", strict=True)


if __name__ == "__main__":
    main()
