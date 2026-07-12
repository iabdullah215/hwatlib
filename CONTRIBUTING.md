# Contributing to hwatlib

Thanks for your interest in improving `hwatlib`! This document explains how to
set up a development environment, the quality bar for changes, and the ground
rules for contributing to an offensive-security project.

## Responsible-Use Agreement

`hwatlib` is intended for **authorized** security testing only. By contributing
you agree that your contributions are meant to support legitimate penetration
testing, CTF, research, defensive, and educational use cases — **not** to enable
unauthorized access or attacks. Please read [`SECURITY.md`](SECURITY.md) before
contributing. Contributions whose primary purpose is to facilitate illegal
activity (mass exploitation, targeting of third parties without consent,
detection-evasion for malware, etc.) will not be accepted.

## Development Setup

Requires Python 3.9 or newer.

```bash
# Clone and create a virtual environment
git clone https://github.com/iabdullah215/hwatlib
cd hwatlib
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install in editable mode with all development extras
# (dev = test/lint/type tools + pre-commit; security = bandit/pip-audit; docs = pdoc)
pip install -e ".[dev,security,docs,async,dns]"
```

## Quality Checks

All of the following run in CI (see `.github/workflows/ci.yml`) and must pass
before a pull request can be merged. Run them locally first:

```bash
ruff check .              # lint
mypy                      # type-check
pytest --cov=hwatlib --cov-report=term-missing   # tests with coverage
```

CI additionally enforces an **80% coverage threshold on changed files** for pull
requests, runs security scans (`bandit`, `pip-audit`, CodeQL), and runs
packaging checks (`python -m build` + `twine check`).

### Pre-commit hooks

A [`pre-commit`](https://pre-commit.com/) config runs ruff, mypy, and basic
hygiene checks before each commit so issues are caught locally:

```bash
pre-commit install          # one-time, enables the git hook
pre-commit run --all-files  # run against the whole tree
```

## Pull Request Guidelines

1. **Branch** off `main`; keep each PR focused on a single concern.
2. **Add tests** for new behaviour and bug fixes. Network access in tests should
   be mocked so the suite stays hermetic and offline. New/changed code under
   `hwatlib/` is expected to meet the changed-file coverage gate.
3. **Type hints** are expected on new public functions; the package ships a
   `py.typed` marker, so keep the public surface typed.
4. **Update docs** — adjust the `README.md` and add a `CHANGELOG.md` entry under
   `[Unreleased]` describing your change.
5. **Keep defaults safe.** New state-changing or destructive helpers must be
   gated behind explicit confirmation (see the `--confirm` pattern in the CLI
   and `postex`), and risky network behaviour (e.g. disabling TLS verification)
   must be opt-in.
6. **Never commit virtual environments, build artifacts, or caches.** They are
   listed in `.gitignore`; keep them out of version control.
7. Write clear commit messages and a PR description explaining the *why*.

## Reporting Bugs & Requesting Features

Open an issue on GitHub. For security vulnerabilities **in hwatlib itself**,
follow the private disclosure process in [`SECURITY.md`](SECURITY.md) instead of
filing a public issue.

By submitting a contribution, you agree to license your work under the project's
[MIT License](LICENSE).
