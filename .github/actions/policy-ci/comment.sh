#!/usr/bin/env bash
# Create or update one pull-request comment with the policy CI summary.
#
# Environment: SUMMARY_FILE, GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_EVENT_PATH,
# GITHUB_API_URL. Never fails the job: a read-only token (e.g. fork PRs) only warns.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=SCRIPTDIR/lib.sh
. "$here/lib.sh"

marker='<!-- haltsql-policy-ci -->'
api=${GITHUB_API_URL:-https://api.github.com}
warn() { printf '::warning::haltsql-ci: %s\n' "$*" >&2; exit 0; }

[ -n "${GITHUB_TOKEN:-}" ] || warn "no github-token: skipping the PR comment"
[ -f "${SUMMARY_FILE:-}" ] || warn "no summary to post"
pr=$(jq -r '.pull_request.number // empty' "${GITHUB_EVENT_PATH:-/dev/null}" 2>/dev/null)
case "$pr" in '' | *[!0-9]*) warn "not a pull request: skipping the PR comment" ;; esac

gh_api() {
  curl -fsSL --proto '=https' --tlsv1.2 -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H 'Accept: application/vnd.github+json' "$@"
}

body=$(jq -Rs '{body: .}' "$SUMMARY_FILE")
existing=$(gh_api "$api/repos/$GITHUB_REPOSITORY/issues/$pr/comments?per_page=100" |
  jq -r --arg m "$marker" '[.[] | select(.body | startswith($m))][0].id // empty') ||
  warn "cannot list PR comments (token lacks pull-requests: write?)"
if [ -n "$existing" ]; then
  printf '%s' "$body" | gh_api -X PATCH --data-binary @- \
    "$api/repos/$GITHUB_REPOSITORY/issues/comments/$existing" >/dev/null ||
    warn "cannot update the PR comment"
else
  printf '%s' "$body" | gh_api -X POST --data-binary @- \
    "$api/repos/$GITHUB_REPOSITORY/issues/$pr/comments" >/dev/null ||
    warn "cannot create the PR comment"
fi
haltsql_log "PR comment updated"
