# hwatlib Threat Model

This document describes the **security posture of the `hwatlib` software
itself** — how it is designed to behave, what guarantees it offers to the people
who run it, and where the boundaries of its responsibility lie. It is distinct
from [`SECURITY.md`](SECURITY.md), which covers *responsible use* and how to
*report vulnerabilities*.

`hwatlib` is offensive-security tooling. That makes its own security posture
unusual: the library deliberately generates payloads and runs system commands.
The goal of this model is to be explicit about what it does on the operator's
behalf, and to guarantee it does nothing *else* — no hidden network calls, no
self-propagation, no evasion, no exfiltration.

## Scope and audience

- **In scope:** the behaviour of the `hwatlib` Python package and its bundled
  CLIs, its dependency/supply chain, and the data it reads and writes on the
  machine running it.
- **Out of scope:** the security of targets you test, the legality/authorization
  of your engagement (see `SECURITY.md`), and the environment you run it in.
- **Audience:** operators embedding or running hwatlib, and reviewers auditing
  whether it is safe to install and run.

## Assets

| Asset | Why it matters |
| --- | --- |
| Operator's host and credentials | The library runs local commands and reads sensitive files during post-exploitation recon. |
| Findings / report output | May contain secrets, hostnames, and vulnerability data; must not leak. |
| Target scope & authorization | Running against the wrong host is the primary real-world harm. |
| The distributed package (PyPI) | A tampered release would run on many operator machines. |

## Trust boundaries & data flow

1. **Operator → library.** Inputs are targets, URLs, wordlists, config
   (`~/.config/hwat/config.toml` + `HWAT_*` env), and plugin specs. All are
   treated as trusted operator input, but are still validated (config ranges,
   cron-schedule format, command allowlists).
2. **Library → local OS.** Recon/post-exploitation helpers spawn subprocesses
   and read files. This is the highest-risk boundary and is the most controlled
   (see mitigations).
3. **Library → network → target.** HTTP(S), DNS, TCP sockets, and nmap against
   the operator-specified target only.
4. **Library ↔ supply chain.** Third-party dependencies at install time; PyPI at
   release time.

## What hwatlib will do

- Generate offensive payloads (reverse shells, encoders) **as strings**, for the
  operator to use deliberately.
- Run **read-only** recon/enumeration by default.
- Perform state-changing post-exploitation actions **only** behind explicit
  confirmation (`--confirm` / `confirm=True`).
- Talk to the network only to the target(s) the operator specifies.

## What hwatlib will NOT do — design guarantees

These are intentional non-features. Contributions that add them will be
rejected (see `CONTRIBUTING.md`).

- **No detection evasion / anti-forensics.** No log-clearing, no AV/EDR bypass,
  no timestomping. The provided encoders (base64/URL/compressed PowerShell) are
  transport conveniences, documented as such — not evasion tooling.
- **No self-propagation or worm-like behaviour.** It never spreads itself.
- **No telemetry, "phone-home", or exfiltration.** The library makes no network
  calls except to operator-specified targets. Importing it opens no sockets.
- **No automatic exploitation.** It does not chain findings into unattended
  attacks; the operator drives every action.
- **No shell execution of untrusted strings.** Commands run without a shell.
- **No silent state changes.** Destructive actions always require confirmation.

## Threats and mitigations

| Threat | Mitigation in hwatlib |
| --- | --- |
| **Command injection** via crafted inputs feeding a shell | All subprocess calls use `subprocess` with `shell=False`; string commands are tokenised with `shlex`. The legacy `run_command_unsafe_shell()` now delegates to the no-shell path. State-changing post-ex commands are checked against an allowlist. |
| **Unbounded/ hung external tools** (nmap, `find /`, `nslookup`) | Every subprocess is time-bounded: nmap (300s default), post-ex commands (120s, `HWAT_CMD_TIMEOUT`), and `run_command`/`nslookup`/`sudo` probes. |
| **XXE / malicious XML** in sitemaps | XML is parsed with `defusedxml`, disabling entity expansion. |
| **MITM / passive interception** of scan traffic | TLS verification is **on by default**; disabling it is explicit and opt-in, and warning suppression is scoped per-call. |
| **Accidental destructive action** | State-changing helpers refuse to run without `confirm=True`; the CLI mirrors this with `--confirm` and returns a non-zero exit code when unconfirmed. |
| **Secret leakage via logs** | The library attaches only a `NullHandler` on import and never configures output itself; the host application opts into logging. Machine-readable report output goes to stdout; the authorized-use banner and logs go to stderr. |
| **Config-driven misbehaviour** (bad timeouts, proxies) | Config values are range-validated; malformed values fall back to safe defaults, or fail fast in strict mode (`HWAT_CONFIG_STRICT`). |
| **Malicious/broken plugins** | Third-party plugin failures are isolated per-plugin and reported as errors rather than crashing a run; plugin specs are validated (`module:function`). |
| **Broad `except` hiding failures** | A typed exception hierarchy (`HwatlibError` and subclasses) lets callers catch precisely; best-effort broad excepts are documented and log at debug level. |
| **Supply-chain compromise (dependencies)** | Dependencies are version-pinned ranges; `pip-audit` runs in CI on every push/PR and fails on known CVEs; Dependabot proposes updates. |
| **Supply-chain compromise (release tampering)** | Releases use PyPI Trusted Publishing (OIDC, no stored tokens), SLSA build-provenance attestation, Sigstore signatures, and a CycloneDX SBOM (see `RELEASING.md`). |
| **Regressions introducing insecure code** | `bandit` (SAST) and CodeQL (security-extended) run in CI; `main` is branch-protected with required checks, Code Owner review, and signed commits (see `GOVERNANCE.md`). |

## Residual risks (operator responsibilities)

hwatlib cannot mitigate these; they are on the operator:

- **Authorization and scope.** The library cannot know whether you are permitted
  to test a target. Running it against unauthorized systems is illegal — see
  `SECURITY.md`.
- **Handling of output.** Reports may contain secrets; store and transmit them
  securely.
- **Running as root.** Post-exploitation recon is more effective (and more
  dangerous) with elevated privileges; run it in an environment you control.
- **Payload usage.** Generated payloads are inert strings until *you* deploy
  them against a target.

## Reporting

Security issues **in hwatlib itself** should be reported privately per
[`SECURITY.md`](SECURITY.md), not filed as public issues.
