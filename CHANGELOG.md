# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/iabdullah215/hwatlib/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/iabdullah215/hwatlib/releases/tag/v0.2.0
