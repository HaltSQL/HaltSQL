#!/usr/bin/env bash
# HaltSQL policy CI: validate, lint and test policies; write a Markdown summary.
#
# Environment (set by action.yml; usable stand-alone too):
#   HALTSQL            haltsql binary (default: haltsql on PATH)
#   INPUT_POLICIES     policy globs/files/directories (whitespace separated)
#   INPUT_SUITES       test-suite globs/files/directories (optional)
#   INPUT_FAIL_ON_WARNINGS  true to fail on lint warnings (default false)
#   INPUT_MAX_DENIED   denied cases listed per suite in the summary (default 50)
#   HALTSQL_CI_OUT     directory for JSON reports and summary.md
#   GITHUB_STEP_SUMMARY, GITHUB_OUTPUT  set by GitHub Actions
#
# Exit status: 0 all checks passed, 1 a check failed, 2 usage/setup error.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=SCRIPTDIR/lib.sh
. "$here/lib.sh"

HALTSQL=${HALTSQL:-haltsql}
command -v "$HALTSQL" >/dev/null 2>&1 || haltsql_die "haltsql binary not found: $HALTSQL"
command -v jq >/dev/null 2>&1 || haltsql_die "jq is required"

out=${HALTSQL_CI_OUT:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/haltsql-ci}
mkdir -p "$out"
fail_on_warnings=false
haltsql_is_true "${INPUT_FAIL_ON_WARNINGS:-false}" && fail_on_warnings=true
max_denied=${INPUT_MAX_DENIED:-50}
case "$max_denied" in '' | *[!0-9]*) haltsql_die "max-denied must be a number" ;; esac

policies=()
while IFS= read -r f; do [ -n "$f" ] && policies+=("$f"); done \
  < <(haltsql_expand policy "${INPUT_POLICIES:-}")
suites=()
while IFS= read -r f; do [ -n "$f" ] && suites+=("$f"); done \
  < <(haltsql_expand suite "${INPUT_SUITES:-}")

[ "${#policies[@]}" -gt 0 ] || haltsql_die "no policy files match: ${INPUT_POLICIES:-<empty>}"
haltsql_log "${#policies[@]} policy file(s), ${#suites[@]} suite file(s)"

# 1. validate (policies and suites)
set +e
"$HALTSQL" validate --json "${policies[@]}" ${suites[@]+"${suites[@]}"} >"$out/validate.json"
validate_rc=$?
set -e
if [ "$validate_rc" -gt 1 ] || ! jq -e . "$out/validate.json" >/dev/null 2>&1; then
  haltsql_log "validate failed to run (exit $validate_rc)"
  : >"$out/validate.json"
fi

# 2. lint every policy that loads
: >"$out/lint.ndjson"
for p in "${policies[@]}"; do
  set +e
  "$HALTSQL" lint-policy --json "$p" >"$out/lint.one.json" 2>"$out/lint.err"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ] && jq -e . "$out/lint.one.json" >/dev/null 2>&1; then
    jq -c --arg f "$p" '. + {file: $f}' "$out/lint.one.json" >>"$out/lint.ndjson"
  fi
done
jq -s . "$out/lint.ndjson" >"$out/lint.json"

# 3. test suites
test_rc=0
if [ "${#suites[@]}" -gt 0 ]; then
  set +e
  "$HALTSQL" test --json "${suites[@]}" >"$out/test.json"
  test_rc=$?
  set -e
  if [ "$test_rc" -gt 1 ] || ! jq -e . "$out/test.json" >/dev/null 2>&1; then
    haltsql_log "test failed to run (exit $test_rc)"
    jq -n '{ok: false, passed: 0, failed: 0, load_errors: 1, suites: []}' >"$out/test.json"
  fi
else
  : >"$out/test.json"
fi

# 4. summary
jq -n -r \
  --slurpfile validate "$out/validate.json" \
  --slurpfile lint "$out/lint.json" \
  --slurpfile tests "$out/test.json" \
  --arg failwarn "$fail_on_warnings" \
  --arg max_denied "$max_denied" \
  -f "$here/summary.jq" >"$out/summary.md"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "$out/summary.md" >>"$GITHUB_STEP_SUMMARY"
fi

warnings=$(jq '[.[].findings // [] | .[] | select(.severity == "warning")] | length' "$out/lint.json")
passed=$(jq -s -r '.[0].passed // 0' "$out/test.json")
failed=$(jq -s -r '.[0].failed // 0' "$out/test.json")
valid=$(jq -s -r '.[0].ok // false' "$out/validate.json")
tests_ok=true
if [ "${#suites[@]}" -gt 0 ]; then tests_ok=$(jq -s -r '.[0].ok // false' "$out/test.json"); fi

result=pass
[ "$valid" = true ] || result=fail
[ "$tests_ok" = true ] || result=fail
if [ "$fail_on_warnings" = true ] && [ "$warnings" -gt 0 ]; then result=fail; fi

haltsql_output result "$result"
haltsql_output passed "$passed"
haltsql_output failed "$failed"
haltsql_output warnings "$warnings"
haltsql_output summary-file "$out/summary.md"
haltsql_output report-dir "$out"

haltsql_log "result: $result (validate ok: $valid, tests: $passed passed / $failed failed, warnings: $warnings)"
if [ "$result" = pass ]; then exit 0; else exit 1; fi
