#!/usr/bin/env bash
#
# Apply hwatlib's branch-protection policy to the default branch via the GitHub
# API. Idempotent: re-running re-applies the same settings. Requires the `gh`
# CLI authenticated as a user with admin rights on the repository.
#
# See GOVERNANCE.md for the policy this enforces.
#
# Usage:
#   ./scripts/setup-branch-protection.sh [branch]   # defaults to "main"

set -euo pipefail

BRANCH="${1:-main}"

if ! command -v gh >/dev/null 2>&1; then
  echo "error: the GitHub CLI (gh) is required. https://cli.github.com/" >&2
  exit 1
fi

# Resolve owner/repo from the current checkout.
REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
echo "Applying branch protection to ${REPO}@${BRANCH}"

# Required status checks must match the CI job names exactly (see GOVERNANCE.md).
read -r -d '' PAYLOAD <<'JSON' || true
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Lint (ruff)",
      "Type Check (mypy)",
      "Tests (py3.9)",
      "Tests (py3.10)",
      "Tests (py3.11)",
      "Tests (py3.12)",
      "Packaging Checks",
      "SAST (bandit)",
      "Dependency Audit (pip-audit)",
      "Analyze (python)"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 1
  },
  "required_linear_history": true,
  "required_conversation_resolution": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "restrictions": null
}
JSON

echo "${PAYLOAD}" | gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  "repos/${REPO}/branches/${BRANCH}/protection" \
  --input -

# Signed commits are a separate endpoint.
gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  "repos/${REPO}/branches/${BRANCH}/protection/required_signatures" >/dev/null

echo "Done. Branch protection and required signatures are enforced on ${BRANCH}."
