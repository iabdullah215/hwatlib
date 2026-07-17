# Releasing hwatlib

Releases are automated by [`.github/workflows/release.yml`](.github/workflows/release.yml).
When a GitHub Release is published, the workflow builds the distribution,
generates an SBOM, attests build provenance, publishes to PyPI via **Trusted
Publishing (OIDC)**, and signs the artifacts with **Sigstore**.

No PyPI API tokens are stored anywhere: authentication is short-lived OIDC.

## One-time setup

These steps must be done once by a maintainer before the first automated
release. The workflow cannot perform them itself.

### 1. Register the Trusted Publisher on PyPI

On <https://pypi.org/manage/project/hwatlib/settings/publishing/> (and
<https://test.pypi.org/> for TestPyPI), add a **GitHub Actions** trusted
publisher:

| Field             | Value                       |
| ----------------- | --------------------------- |
| Owner             | `iabdullah215`              |
| Repository        | `hwatlib`                   |
| Workflow filename | `release.yml`               |
| Environment       | `pypi` (or `testpypi`)      |

For the very first upload the project may not exist yet — use PyPI's
["pending publisher"](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
flow to reserve the name.

### 2. Create the GitHub Environments

In **Settings → Environments**, create two environments matching the workflow:

- `pypi` — production. Add required reviewers so a human approves each real
  publish.
- `testpypi` — dry-run target for `workflow_dispatch`.

## Cutting a release

1. Bump `__version__` in `hwatlib/__init__.py` and update `CHANGELOG.md`.
2. Commit, tag, and push:

   ```bash
   git tag -a v0.4.0 -m "release: 0.4.0"
   git push origin v0.4.0
   ```

3. Create a GitHub Release from that tag. Publishing it triggers the workflow.
4. Approve the `pypi` deployment when prompted.

### Dry run to TestPyPI

Use **Actions → Release → Run workflow** and pick `testpypi` (or `pypi`) to
publish without cutting a GitHub Release.

## Verifying a published release

Every release ships with provenance consumers can check.

**Build provenance (GitHub attestations):**

```bash
gh attestation verify hwatlib-0.4.0-py3-none-any.whl --repo iabdullah215/hwatlib
```

**Sigstore signatures** (attached to the GitHub Release as `*.sigstore.json`):

```bash
python -m pip install sigstore
sigstore verify identity \
  --cert-identity "https://github.com/iabdullah215/hwatlib/.github/workflows/release.yml@refs/tags/v0.4.0" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  hwatlib-0.4.0-py3-none-any.whl
```

**SBOM:** `hwatlib.cdx.json` (CycloneDX) is attached to the Release and lists
the full runtime dependency closure.
