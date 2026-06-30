# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Migrated packaging to a `src/` layout with all metadata consolidated into
  `pyproject.toml` (PEP 621). `setup.py` has been removed.

### Added
- `LICENSE` file (MIT) matching the declared license metadata.
- `py.typed` marker so downstream consumers pick up inline type hints (PEP 561).
- GitHub Actions CI: test matrix across Python 3.8–3.13, plus lint
  (Ruff), type-checking (mypy), and a distribution build/check job.
- Ruff and pre-commit configuration for linting and formatting.
- `CHANGELOG.md`, `SECURITY.md`, and `CONTRIBUTING.md`, including an
  authorized/responsible-use policy.

## [0.2.0] - 2026-01-05

### Added
- Unified `hwat report` CLI with JSON/Markdown output and sitemap export.
- Plugin system, findings model, config profiles, async HTTP, DNS, secrets
  scanning, fingerprinting, and workflow helpers.
- Safer defaults: TLS verification on by default; state-changing
  post-exploitation helpers gated behind explicit confirmation.

[Unreleased]: https://github.com/iabdullah215/hwatlib/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/iabdullah215/hwatlib/releases/tag/v0.2.0
