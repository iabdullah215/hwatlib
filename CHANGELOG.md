# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `LICENSE` file (MIT) matching the declared license metadata.
- `py.typed` marker so downstream consumers pick up inline type hints (PEP 561).
- `CHANGELOG.md`, `SECURITY.md`, and `CONTRIBUTING.md`, including an
  authorized/responsible-use policy.
- `pyproject.toml`-based packaging and metadata, GitHub Actions CI
  (Ruff lint, mypy, a test matrix with coverage, and packaging checks), and an
  expanded test suite.

### Fixed
- Cross-version TOML config parsing and Python 3.9 import-time annotation
  handling.

### Removed
- Removed an accidentally committed `.venv310/` virtual environment from version
  control and added an ignore rule to prevent recurrence.

## [0.2.0] - 2026-01-05

### Added
- Unified `hwat report` CLI with JSON/Markdown output and sitemap export.
- Plugin system, findings model, config profiles, async HTTP, DNS, secrets
  scanning, fingerprinting, and workflow helpers.
- Safer defaults: TLS verification on by default; state-changing
  post-exploitation helpers gated behind explicit confirmation.

[Unreleased]: https://github.com/iabdullah215/hwatlib/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/iabdullah215/hwatlib/releases/tag/v0.2.0
