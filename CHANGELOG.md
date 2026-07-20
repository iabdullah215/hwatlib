# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Directory/content brute-forcing** (`web.dir_bruteforce` / `dir_bruteforce_async`):
  wordlist-driven, with extension expansion and status filtering; uses the shared
  `HttpClient` (rate limiting/retries) or `AsyncHttpClient` concurrency. Typed
  `DirBruteResult`/`DirEntry`.
- **Wappalyzer-style tech fingerprinting** (`hwatlib.techrules`): a data-driven
  rule engine over headers/cookies/body/meta with `implies`, wired into
  `web.fingerprint_tech` (now also returns a `technologies` list of
  name/category).
- **Auth/session handling** on `HwatSession`: `set_headers`, `set_cookies`,
  `set_bearer_token`, `set_basic_auth`, and `login_form` (cookies persist on the
  shared client), so `web.scan(client=session.ensure_http())` runs authenticated.
- **Typed exception hierarchy** (`hwatlib.exceptions`): all library errors now
  derive from `HwatlibError`, with `ConfigError`, `PluginError`,
  `DependencyError`, `ScanError`, and `NetworkError` → (`TargetUnreachable`,
  `RequestError`). Several also subclass the built-in they replaced
  (`ValueError`/`RuntimeError`) so existing `except` code keeps working.
- **Structured logging** (`hwatlib.logging_ext`): opt-in JSON log output and a
  context-local **run id** stamped onto every log record and into report
  metadata (`report.metadata["run_id"]`) for end-to-end correlation. New
  `hwat report --log-format {text,json}` flag and `HWAT_LOG_FORMAT=json` env.
- **Subprocess timeouts** everywhere external tools run: `recon.run_nmap`
  (default 300s), post-exploitation commands (default 120s, override with
  `HWAT_CMD_TIMEOUT`), and `utils.run_command`/`nslookup`/`sudo` probes, so a
  hung tool can never block the caller.
- Property-based tests (Hypothesis) for parsers/scoring and opt-in mutation
  testing (mutmut) for the scoring logic (`make mutants`).
- **Automated release pipeline** (`release.yml`): PyPI **Trusted Publishing**
  (OIDC, no stored tokens), CycloneDX **SBOM**, SLSA **build-provenance
  attestation**, and **Sigstore** signing; documented in `RELEASING.md`.
- **API docs published to GitHub Pages** on each release (`docs.yml`).
- **Governance & security docs**: `THREAT_MODEL.md` (the tool's own security
  posture), `GOVERNANCE.md` (branch protection, required checks, signed
  commits) with a `scripts/setup-branch-protection.sh` helper, and
  `.github/CODEOWNERS`.

### Changed
- Raised the global coverage floor from 50% to 80%.
- Grouped GitHub Actions Dependabot updates into a single PR.

### Fixed
- Python 3.9 compatibility: `AsyncHttpClient` now creates its `asyncio.Semaphore`
  lazily inside a running loop instead of at construction time.
- Python 3.9/3.10 compatibility: `recon.banner_grab_async` uses `asyncio.wait_for`
  instead of the 3.11+ `asyncio.timeout`, which previously returned no banners on
  older interpreters.

## [0.3.0] - 2026-07-13

### Changed
- **CLI (breaking):** replaced the ambiguous `hwat-post` console script with
  `hwat-privesc` (privesc + post-exploitation actions, formerly `hwat-post`) and
  added `hwat-postex` for the post-exploitation recon report, so each command
  name matches its module.
- Package version is now single-sourced from `hwatlib.__version__` via setuptools
  dynamic metadata (no longer duplicated in `pyproject.toml`).
- Library logging no longer configures handlers on import; a `NullHandler` is
  attached instead and the CLIs opt into visible output.
- `utils.resolve_host` now prefers the dnspython library (optional `dns` extra)
  over shelling out to `nslookup`, which is used only as a last resort.
- `web` module timeout parameters are now `float` for consistency with the
  float timeouts produced by the config layer.
- Raised the global coverage floor from 45% to 50%.

### Added
- Security scanning in CI: `bandit` (SAST), `pip-audit` (dependency CVEs),
  a CodeQL workflow, and a Dependabot config.
- A prominent **authorized-use** notice: printed to stderr by every CLI on run
  (silence with `HWAT_NO_BANNER=1`) and highlighted in the README.
- `.pre-commit-config.yaml` running ruff, mypy, and hygiene hooks locally.
- `examples/` directory with runnable API snippets, and `make docs` targets to
  generate API reference docs from docstrings with `pdoc`.
- `LICENSE` file (MIT) matching the declared license metadata.
- `py.typed` marker so downstream consumers pick up inline type hints (PEP 561).
- `CHANGELOG.md`, `SECURITY.md`, and `CONTRIBUTING.md`, including an
  authorized/responsible-use policy.
- `pyproject.toml`-based packaging and metadata, GitHub Actions CI
  (Ruff lint, mypy, a test matrix with coverage, and packaging checks), and an
  expanded test suite.

### Fixed
- Hardened sitemap XML parsing against XXE/entity-expansion attacks by switching
  to `defusedxml` (sitemaps are attacker-controlled input).
- Allowed `pytest` 9 (which fixes a known dev-only CVE) on Python 3.10+ while
  keeping `pytest` 8 on 3.9, since pytest 9 dropped Python 3.9 support.
- Cross-version TOML config parsing and Python 3.9 import-time annotation
  handling.

### Removed
- Removed an accidentally committed `.venv310/` virtual environment from version
  control and added an ignore rule to prevent recurrence.
- Removed the redundant `requirements.txt` (duplicated `pyproject.toml`
  dependencies) and the empty `setup.py` shim (unnecessary with the PEP 517
  setuptools backend), and deleted the stray `src/` directory left over from an
  abandoned src-layout.

## [0.2.0] - 2026-01-05

### Added
- Unified `hwat report` CLI with JSON/Markdown output and sitemap export.
- Plugin system, findings model, config profiles, async HTTP, DNS, secrets
  scanning, fingerprinting, and workflow helpers.
- Safer defaults: TLS verification on by default; state-changing
  post-exploitation helpers gated behind explicit confirmation.

[Unreleased]: https://github.com/iabdullah215/hwatlib/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/iabdullah215/hwatlib/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/iabdullah215/hwatlib/releases/tag/v0.2.0
