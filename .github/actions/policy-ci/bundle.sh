#!/usr/bin/env bash
# Build (and optionally sign and verify) a HaltSQL policy bundle.
#
# Environment:
#   HALTSQL                 haltsql binary (default: haltsql on PATH)
#   INPUT_POLICIES          policy globs/files/directories
#   INPUT_CATALOGS          optional catalog snapshot files ([NAME=]FILE, whitespace separated)
#   INPUT_BUNDLE_NAME       bundle name (default: repository name)
#   INPUT_BUNDLE_VERSION    bundle version (default: short commit SHA)
#   INPUT_BUNDLE_OUTPUT     output path (default: $HALTSQL_CI_OUT/<name>.haltsqlbundle)
#   HALTSQL_SIGNING_KEY     PEM private key (from a secret); when set the bundle is signed
#   INPUT_PUBLIC_KEYS       optional trusted public keys (files or base64) to verify with
#   GITHUB_SHA, GITHUB_SERVER_URL, GITHUB_REPOSITORY  recorded as the bundle source
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=SCRIPTDIR/lib.sh
. "$here/lib.sh"

HALTSQL=${HALTSQL:-haltsql}
out=${HALTSQL_CI_OUT:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/haltsql-ci}
mkdir -p "$out"

policies=()
while IFS= read -r f; do [ -n "$f" ] && policies+=("$f"); done \
  < <(haltsql_expand policy "${INPUT_POLICIES:-}")
[ "${#policies[@]}" -gt 0 ] || haltsql_die "no policy files to bundle"

repo_name=${GITHUB_REPOSITORY:-policies}
repo_name=${repo_name##*/}
name=${INPUT_BUNDLE_NAME:-$repo_name}
sha=${GITHUB_SHA:-}
version=${INPUT_BUNDLE_VERSION:-}
if [ -z "$version" ]; then
  if [ -n "$sha" ]; then version=${sha:0:12}; else version=0.0.0-dev; fi
fi
output=${INPUT_BUNDLE_OUTPUT:-$out/$name.haltsqlbundle}

args=(bundle build "${policies[@]}" --name "$name" --bundle-version "$version" -o "$output")
for c in ${INPUT_CATALOGS:-}; do args+=(--catalog "$c"); done
if [ -n "${GITHUB_SERVER_URL:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
  args+=(--source-url "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY")
fi
if printf '%s' "$sha" | grep -Eq '^[0-9a-f]{7,64}$'; then args+=(--source-commit "$sha"); fi

"$HALTSQL" "${args[@]}" >&2
haltsql_output bundle-path "$output"

if [ -n "${HALTSQL_SIGNING_KEY:-}" ]; then
  "$HALTSQL" bundle sign "$output" --key-env HALTSQL_SIGNING_KEY >&2
  haltsql_output signature-path "$output.sig"
  if [ -n "${INPUT_PUBLIC_KEYS:-}" ]; then
    vargs=(bundle verify "$output")
    for k in $INPUT_PUBLIC_KEYS; do vargs+=(--public-key "$k"); done
    "$HALTSQL" "${vargs[@]}" >&2
  fi
else
  haltsql_log "no signing key given (secret HALTSQL_SIGNING_KEY): the bundle is unsigned"
  haltsql_output signature-path ""
fi
"$HALTSQL" bundle inspect "$output" >&2
printf '%s\n' "$output"
