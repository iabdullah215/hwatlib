# Project Governance

This document defines the repository-level controls that protect `hwatlib`'s
default branch and release integrity. Branch protection, required status checks,
and commit-signing enforcement live in **GitHub repository settings**, not in the
source tree, so they must be applied by a maintainer with admin rights. The
[`scripts/setup-branch-protection.sh`](scripts/setup-branch-protection.sh)
helper applies the policy below via the GitHub API; this document is the
source of truth for what that policy should be.

## Default branch protection (`main`)

Enforce the following on `main` (Settings → Branches → Branch protection rules,
or run the helper script):

- **Require a pull request before merging.** Direct pushes to `main` are not
  allowed.
  - At least **1 approving review**.
  - **Dismiss stale approvals** when new commits are pushed.
  - **Require review from Code Owners** (see [`.github/CODEOWNERS`](.github/CODEOWNERS)).
- **Require status checks to pass before merging**, with **branches up to date**.
  Required checks (must match the CI job names exactly):
  - `Lint (ruff)`
  - `Type Check (mypy)`
  - `Tests (py3.9)`, `Tests (py3.10)`, `Tests (py3.11)`, `Tests (py3.12)`
  - `Packaging Checks`
  - `SAST (bandit)`
  - `Dependency Audit (pip-audit)`
  - `Analyze (python)` (CodeQL)
- **Require signed commits.** Every commit on `main` must carry a verified
  signature (see below).
- **Require linear history** (no merge commits from non-fast-forward merges).
- **Require conversation resolution before merging.**
- **Include administrators** — the rules apply to maintainers too.
- **Do not allow force pushes or deletions.**

## Signed commits

All commits merged to `main` must be cryptographically signed and show as
**Verified** on GitHub. Contributors set this up once locally:

```bash
# Option A: SSH signing (simplest if you already push over SSH)
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true

# Option B: GPG signing
git config --global user.signingkey <YOUR_GPG_KEY_ID>
git config --global commit.gpgsign true
```

Then add the corresponding **SSH signing key** or **GPG key** to your GitHub
account (Settings → SSH and GPG keys). Release tags should also be signed
(`git tag -s`).

## Release integrity

Releases are automated and produce verifiable provenance — Trusted Publishing
(OIDC, no stored tokens), SLSA build attestation, Sigstore signatures, and a
CycloneDX SBOM. See [`RELEASING.md`](RELEASING.md).

## Applying the policy

A maintainer with admin access runs the helper once (and again whenever CI job
names change):

```bash
gh auth login          # must be an account with admin on the repo
./scripts/setup-branch-protection.sh
```

The script is idempotent — re-running it re-applies the same policy.
