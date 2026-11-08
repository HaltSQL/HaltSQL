#!/usr/bin/env bash
# Runs the script sections of ci/gitlab/haltsql.gitlab-ci.yml locally with POSIX sh and a
# locally built haltsql (the install before_script is skipped). Needs python3 with PyYAML
# (set PYTHON to choose the interpreter); skips cleanly otherwise.
#
#   test/bundle/action/test_gitlab.sh HALTSQL_BINARY [BUNDLE_BINARY]
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
[ $# -ge 1 ] || { echo "usage: $0 HALTSQL_BINARY [BUNDLE_BINARY]" >&2; exit 2; }
python=${PYTHON:-python3}
if ! "$python" -c 'import yaml' 2>/dev/null; then
  echo "SKIP: $python has no PyYAML module"
  exit 0
fi
haltsql=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
bundle_bin=${2:-$1}
bundle_bin=$(cd "$(dirname "$bundle_bin")" && pwd)/$(basename "$bundle_bin")

work=$(cd "$(mktemp -d "${TMPDIR:-/tmp}/haltsql-gitlab-test.XXXXXX")" && pwd)
trap '[ -n "${KEEP:-}" ] || rm -rf "$work"' EXIT
pass=0
fail=0
check() {
  if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "  ok   $1"
  else fail=$((fail + 1)); echo "  FAIL $1 (expected [$2], got [$3])"; fi
}

# haltsql on PATH; `haltsql bundle` may come from a separate binary.
mkdir -p "$work/bin"
cat >"$work/bin/haltsql" <<WRAP
#!/bin/sh
if [ "\${1:-}" = bundle ]; then exec "$bundle_bin" "\$@"; fi
exec "$haltsql" "\$@"
WRAP
chmod +x "$work/bin/haltsql"

extract() { # extract JOB -> shell script of its script: section
  "$python" - "$root/ci/gitlab/haltsql.gitlab-ci.yml" "$1" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
def flat(x):
    for i in x:
        if isinstance(i, list):
            yield from flat(i)
        else:
            yield i
print("\n".join(flat(doc[sys.argv[2]]["script"])))
PY
}
extract .haltsql-check >"$work/check.sh"
extract .haltsql-bundle >"$work/bundle.sh"

mkdir -p "$work/repo/policies" "$work/repo/tests" "$work/repo/catalog"
cp "$root/examples/catalog/saas.snapshot.json" "$work/repo/catalog/"
cp "$root/examples/policies/saas.yaml" "$root/examples/policies/writes.yaml" "$work/repo/policies/"
cp "$root/examples/suites/saas.suite.yaml" "$work/repo/tests/"

run_job() { # run_job SCRIPT VAR=VALUE...
  local script="$1"
  shift
  set +e
  # shellcheck disable=SC2016  # expanded by the inner sh
  (cd "$work/repo" && env PATH="$work/bin:$PATH" HALTSQL_OUT="$work/repo/haltsql-ci" \
    HALTSQL_POLICIES=policies HALTSQL_SUITES="" HALTSQL_FAIL_ON_WARNINGS=false \
    CI_PROJECT_NAME=policies CI_COMMIT_SHORT_SHA=0123abcd \
    CI_COMMIT_SHA=0123abcd0123abcd0123abcd0123abcd0123abcd \
    CI_PROJECT_URL=https://gitlab.example.com/acme/policies "$@" \
    sh -c 'mkdir -p "$HALTSQL_OUT"; . "$0"' "$script") >"$work/out" 2>&1
  rc=$?
  set -e
}

echo ".haltsql-check"
run_job "$work/check.sh" HALTSQL_SUITES=tests
check "passing suites exit 0" 0 "$rc"
check "junit testsuite" 1 "$(grep -c '<testsuite name="saas-analytics-basics" tests="6" failures="0">' "$work/repo/haltsql-ci/junit.xml")"
check "junit denied output" 1 "$(grep -c '<testcase name="missing tenant filter" classname="saas-analytics"><system-out>denied: E_TENANT_MISSING</system-out></testcase>' "$work/repo/haltsql-ci/junit.xml")"
if command -v xmllint >/dev/null 2>&1; then
  xmllint --noout "$work/repo/haltsql-ci/junit.xml" && check "junit is well-formed" 0 0
fi
run_job "$work/check.sh" HALTSQL_SUITES=tests HALTSQL_FAIL_ON_WARNINGS=true
check "fail on warnings exit 1" 1 "$rc"
cat >"$work/repo/tests/bad.suite.yaml" <<'YAML'
apiVersion: haltsql.dev/v1
kind: TestSuite
metadata: { name: bad }
policy: ../policies/saas.yaml
defaults: { context: { tenant_id: acme } }
cases:
  - name: "wrong <expectation> & \"quotes\""
    sql: SELECT id FROM orders LIMIT 10
    expect: allow
YAML
run_job "$work/check.sh" HALTSQL_SUITES=tests
check "failing case exit 1" 1 "$rc"
check "junit failure escaped" 1 "$(grep -c 'testcase name="wrong &lt;expectation&gt; &amp; &quot;quotes&quot;"' "$work/repo/haltsql-ci/junit.xml")"
rm "$work/repo/tests/bad.suite.yaml"
run_job "$work/check.sh" HALTSQL_POLICIES=nothing
check "no policies exit 2" 2 "$rc"

echo ".haltsql-bundle"
"$bundle_bin" bundle keygen -o "$work/k" >/dev/null
run_job "$work/bundle.sh" HALTSQL_SIGNING_KEY="$(cat "$work/k")" HALTSQL_PUBLIC_KEYS="$work/k.pub"
check "bundle exit 0" 0 "$rc"
check "bundle verifies" 0 "$("$bundle_bin" bundle verify "$work/repo/haltsql-ci/policies.haltsqlbundle" -k "$work/k.pub" >/dev/null 2>&1; echo $?)"
check "private key not printed" 0 "$(grep -c 'PRIVATE KEY' "$work/out" || true)"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
