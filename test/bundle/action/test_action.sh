#!/usr/bin/env bash
# shellcheck disable=SC2016  # backticks in expected Markdown are literal
# Local tests for the GitHub Action scripts (.github/actions/policy-ci/*.sh), run with a
# locally built haltsql binary. No network access.
#
#   test/bundle/action/test_action.sh _build/default/bin/haltsql/main.exe
#
# The binary must include the `bundle` subcommand for the bundle tests; pass a second
# argument (e.g. _build/default/test/bundle/bundle_cli.exe) to use a separate
# binary for `haltsql bundle ...` before the command is registered in main.ml.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
scripts="$root/.github/actions/policy-ci"
[ $# -ge 1 ] || { echo "usage: $0 HALTSQL_BINARY [BUNDLE_BINARY]" >&2; exit 2; }
haltsql=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
bundle_bin=${2:-$1}
bundle_bin=$(cd "$(dirname "$bundle_bin")" && pwd)/$(basename "$bundle_bin")

work=$(cd "$(mktemp -d "${TMPDIR:-/tmp}/haltsql-action-test.XXXXXX")" && pwd)
trap '[ -n "${KEEP:-}" ] || rm -rf "$work"' EXIT
pass=0
fail=0

ok() { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
ko() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }
check() { # check NAME EXPECTED ACTUAL
  if [ "$2" = "$3" ]; then ok "$1"; else ko "$1 (expected [$2], got [$3])"; fi
}
contains() { # contains NAME FILE TEXT
  if grep -qF -- "$3" "$2"; then ok "$1"; else ko "$1 (missing [$3] in $2)"; fi
}
output_of() { grep "^$1=" "$2" | tail -1 | cut -d= -f2-; }

# -- fixtures
mkdir -p "$work/repo/policies/team" "$work/repo/tests"
cp "$root/examples/policies/saas.yaml" "$work/repo/policies/"
cp "$root/examples/policies/writes.yaml" "$work/repo/policies/team/"
mkdir -p "$work/repo/catalog"
cp "$root/examples/catalog/saas.snapshot.json" "$work/repo/catalog/"
sed 's#\.\./policies/saas.yaml#../policies/saas.yaml#' "$root/examples/suites/saas.suite.yaml" \
  >"$work/repo/tests/saas.suite.yaml"
cat >"$work/repo/tests/broken.suite.yaml" <<'YAML'
apiVersion: haltsql.dev/v1
kind: TestSuite
metadata: { name: broken-expectation }
policy: ../policies/saas.yaml
defaults:
  context: { tenant_id: acme }
cases:
  - name: wrongly expected allow | <b>pipe</b>
    sql: SELECT id FROM orders LIMIT 10
    expect: allow
YAML

run_ci() { # run_ci NAME [VAR=VALUE...]; sets rc, out dir in $o
  local name="$1"
  shift
  o="$work/out-$name"
  mkdir -p "$o"
  : >"$o/gh_output"
  : >"$o/gh_summary"
  set +e
  (cd "$work/repo" && env HALTSQL="$haltsql" HALTSQL_CI_OUT="$o" GITHUB_OUTPUT="$o/gh_output" \
    GITHUB_STEP_SUMMARY="$o/gh_summary" "$@" bash "$scripts/run.sh") >"$o/stdout" 2>"$o/stderr"
  rc=$?
  set -e
}

echo "lib.sh"
# shellcheck source=/dev/null
. "$scripts/lib.sh"
cd "$work/repo"
check "expand directory" "policies/saas.yaml policies/team/writes.yaml" \
    "$(haltsql_expand policy policies | tr '\n' ' ' | sed 's/ $//')"
  check "expand ** (zero and more dirs)" "policies/saas.yaml policies/team/writes.yaml" \
    "$(haltsql_expand policy 'policies/**/*.yaml' | tr '\n' ' ' | sed 's/ $//')"
  check "expand plain glob" "policies/saas.yaml" \
    "$(haltsql_expand policy 'policies/*.yaml' | tr '\n' ' ' | sed 's/ $//')"
  check "expand suites dir" "tests/broken.suite.yaml tests/saas.suite.yaml" \
    "$(haltsql_expand suite tests | tr '\n' ' ' | sed 's/ $//')"
  check "expand no match" "" "$(haltsql_expand policy 'nothing/*.yaml')"
  check "expand dedupe" "policies/saas.yaml" \
    "$(haltsql_expand policy 'policies/saas.yaml policies/*.yaml' | tr '\n' ' ' | sed 's/ $//')"
cd "$root"
printf 'hello\n' >"$work/asset.tar.gz"
sum=$(haltsql_sha256 "$work/asset.tar.gz")
printf '%s  asset.tar.gz\n%s  other.tar.gz\n' "$sum" "$sum" >"$work/SUMS"
if haltsql_verify_sha256 "$work/SUMS" "$work/asset.tar.gz" asset.tar.gz 2>/dev/null; then
  ok "checksum match"
else ko "checksum match"; fi
printf 'tampered\n' >"$work/asset.tar.gz"
if haltsql_verify_sha256 "$work/SUMS" "$work/asset.tar.gz" asset.tar.gz 2>/dev/null; then
  ko "checksum mismatch rejected"
else ok "checksum mismatch rejected"; fi
if haltsql_verify_sha256 "$work/SUMS" "$work/asset.tar.gz" missing.tar.gz 2>/dev/null; then
  ko "unlisted asset rejected"
else ok "unlisted asset rejected"; fi
printf '%s  asset.tar.gz\n%s  asset.tar.gz\n' "$sum" "$sum" >"$work/SUMS2"
if haltsql_verify_sha256 "$work/SUMS2" "$work/asset.tar.gz" asset.tar.gz 2>/dev/null; then
  ko "duplicate listing rejected"
else ok "duplicate listing rejected"; fi

echo "install.sh"
set +e
p=$(INPUT_HALTSQL_PATH="$haltsql" bash "$scripts/install.sh" 2>/dev/null)
rc=$?
set -e
check "haltsql-path exit" 0 "$rc"
check "haltsql-path printed" "$haltsql" "$p"
set +e
INPUT_HALTSQL_PATH="$work/nope" bash "$scripts/install.sh" >/dev/null 2>&1
check "missing haltsql-path exits 2" 2 "$?"
INPUT_INSTALL_METHOD=bogus bash "$scripts/install.sh" >/dev/null 2>&1
check "bad install-method exits 2" 2 "$?"
HALTSQL_RELEASE_BASE_URL=http://mirror.invalid bash "$scripts/install.sh" >/dev/null 2>&1
check "non-https mirror exits 2" 2 "$?"
INPUT_VERSION='v1.0;rm' bash "$scripts/install.sh" >/dev/null 2>&1
check "invalid version exits 2" 2 "$?"
set -e

# container fallback with a fake docker (records its arguments; no network)
digest="sha256:$(printf 'a%.0s' $(seq 64))"
pinned="ghcr.io/haltsql/haltsql@$digest"
mkdir -p "$work/fakebin" "$work/cosignbin"
cat >"$work/fakebin/docker" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
if [ "$1" = inspect ]; then
  # another repository's digest first: must be skipped
  printf 'mirror.example/haltsql@sha256:%s\n' "$(printf 'b%.0s' $(seq 64))"
  printf 'ghcr.io/haltsql/haltsql@sha256:%s\n' "$(printf 'a%.0s' $(seq 64))"
fi
exit 0
FAKE
chmod +x "$work/fakebin/docker"
cat >"$work/cosignbin/cosign" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE_COSIGN_LOG"
exit "${FAKE_COSIGN_RC:-0}"
FAKE
chmod +x "$work/cosignbin/cosign"
: >"$work/docker.log"
set +e
p=$(PATH="$work/fakebin:$PATH" FAKE_DOCKER_LOG="$work/docker.log" RUNNER_TEMP="$work/rt" \
  INPUT_INSTALL_METHOD=docker INPUT_VERSION=0.3.1 GITHUB_PATH="$work/ghpath" \
  bash "$scripts/install.sh" 2>/dev/null)
rc=$?
set -e
check "docker install exit" 0 "$rc"
check "docker wrapper path" "$work/rt/haltsql-install/docker-v0.3.1/haltsql" "$p"
check "docker pull ref" "pull ghcr.io/haltsql/haltsql:0.3.1" "$(head -1 "$work/docker.log")"
check "wrapper added to PATH" "$work/rt/haltsql-install/docker-v0.3.1" "$(cat "$work/ghpath")"
(cd "$work/repo" && PATH="$work/fakebin:$PATH" FAKE_DOCKER_LOG="$work/docker.log" \
  RUNNER_TEMP="$work/rt" "$p" test --json tests)
check "wrapper runs the image by digest" \
  "run --rm -i --user $(id -u):$(id -g) -v $work/repo:$work/repo -v $work/rt:$work/rt -w $work/repo -e HALTSQL_SIGNING_KEY --entrypoint /usr/local/bin/haltsql $pinned test --json tests" \
  "$(tail -1 "$work/docker.log")"

# docker with verify-signature: cosign must verify the pinned digest
: >"$work/docker.log"
: >"$work/cosign.log"
set +e
p=$(PATH="$work/cosignbin:$work/fakebin:$PATH" FAKE_DOCKER_LOG="$work/docker.log" \
  FAKE_COSIGN_LOG="$work/cosign.log" RUNNER_TEMP="$work/rt2" INPUT_INSTALL_METHOD=docker \
  INPUT_VERSION=0.3.1 INPUT_VERIFY_SIGNATURE=true bash "$scripts/install.sh" 2>/dev/null)
rc=$?
set -e
check "verified docker install exit" 0 "$rc"
check "cosign verifies the digest with identity constraints" \
  "verify --certificate-identity-regexp ^https://github.com/HaltSQL/HaltSQL/ --certificate-oidc-issuer https://token.actions.githubusercontent.com $pinned" \
  "$(cat "$work/cosign.log")"
contains "verified wrapper pins the digest" "$p" "$pinned\""
set +e
PATH="$work/cosignbin:$work/fakebin:$PATH" FAKE_DOCKER_LOG="$work/docker.log" \
  FAKE_COSIGN_LOG="$work/cosign.log" FAKE_COSIGN_RC=1 RUNNER_TEMP="$work/rt3" \
  INPUT_INSTALL_METHOD=docker INPUT_VERSION=0.3.1 INPUT_VERIFY_SIGNATURE=true \
  bash "$scripts/install.sh" >/dev/null 2>&1
check "unverifiable image exits 2" 2 "$?"
if [ ! -e "$work/rt3/haltsql-install/docker-v0.3.1/haltsql" ]; then
  ok "no wrapper for an unverified image"
else
  ko "no wrapper for an unverified image"
fi
# without cosign on PATH (fake docker only), verify-signature refuses the image
nocosign=$(mktemp -d "$work/nocosign.XXXXXX")
for t in bash cat head tail grep tr uname dirname basename mkdir rm chmod printf seq id jq curl; do
  tp=$(command -v "$t" 2>/dev/null) && ln -sf "$tp" "$nocosign/$t"
done
: >"$work/docker.log"
PATH="$work/fakebin:$nocosign" FAKE_DOCKER_LOG="$work/docker.log" RUNNER_TEMP="$work/rt4" \
  INPUT_INSTALL_METHOD=docker INPUT_VERSION=0.3.1 INPUT_VERIFY_SIGNATURE=true \
  "$nocosign/bash" "$scripts/install.sh" >/dev/null 2>&1
check "docker + verify-signature without cosign exits 2" 2 "$?"
check "nothing pulled without cosign" "" "$(cat "$work/docker.log")"
# auto + verify-signature: a failed release download must not fall back to docker
: >"$work/docker.log"
PATH="$work/cosignbin:$work/fakebin:$PATH" FAKE_DOCKER_LOG="$work/docker.log" \
  FAKE_COSIGN_LOG="$work/cosign.log" FAKE_COSIGN_RC=1 RUNNER_TEMP="$work/rt5" \
  HALTSQL_RELEASE_BASE_URL=https://127.0.0.1:9 INPUT_VERSION=0.3.1 INPUT_VERIFY_SIGNATURE=true \
  bash "$scripts/install.sh" >/dev/null 2>&1
check "auto + verify-signature + download failure exits 2" 2 "$?"
check "no container fallback under verify-signature" "" "$(grep -c '^pull' "$work/docker.log" | sed 's/^0$//')"
# auto without verify-signature still falls back, pinned by digest
: >"$work/docker.log"
p=$(PATH="$work/fakebin:$PATH" FAKE_DOCKER_LOG="$work/docker.log" RUNNER_TEMP="$work/rt6" \
  HALTSQL_RELEASE_BASE_URL=https://127.0.0.1:9 INPUT_VERSION=0.3.1 \
  bash "$scripts/install.sh" 2>/dev/null)
check "auto fallback exit" 0 "$?"
contains "auto fallback pins the digest" "$p" "$pinned\""
set -e

echo "run.sh: passing suite"
run_ci pass INPUT_POLICIES="policies" INPUT_SUITES="tests/saas.suite.yaml"
check "exit 0" 0 "$rc"
check "result output" pass "$(output_of result "$o/gh_output")"
check "passed output" 6 "$(output_of passed "$o/gh_output")"
check "failed output" 0 "$(output_of failed "$o/gh_output")"
check "warnings output" 3 "$(output_of warnings "$o/gh_output")"
contains "summary title" "$o/gh_summary" "## HaltSQL policy CI: PASS"
contains "summary suite row" "$o/gh_summary" "| saas-analytics-basics | tests/saas.suite.yaml | 6 | 0 | pass |"
contains "summary denied details" "$o/gh_summary" "<details><summary>saas-analytics-basics: 4 denied case(s)</summary>"
contains "summary denied codes" "$o/gh_summary" '| missing tenant filter | yes | `E_TENANT_MISSING` |'
contains "summary marker" "$o/gh_summary" "<!-- haltsql-policy-ci -->"

echo "run.sh: fail-on-warnings"
run_ci warn INPUT_POLICIES="policies" INPUT_SUITES="tests/saas.suite.yaml" INPUT_FAIL_ON_WARNINGS=true
check "exit 1" 1 "$rc"
check "result fail" fail "$(output_of result "$o/gh_output")"
contains "summary notes fail-on-warnings" "$o/gh_summary" "(fail-on-warnings)"

echo "run.sh: failing case"
run_ci failing INPUT_POLICIES="policies" INPUT_SUITES="tests"
check "exit 1" 1 "$rc"
check "failed output" 1 "$(output_of failed "$o/gh_output")"
contains "summary FAIL" "$o/gh_summary" "## HaltSQL policy CI: FAIL"
contains "failed case row escaped" "$o/gh_summary" \
  '| broken-expectation | wrongly expected allow &#124; &lt;b&gt;pipe&lt;/b&gt; | expected allow, got deny [E_TENANT_MISSING]: app.orders (as orders) has no provable tenant predicate on orders.tenant_id in the same SELECT | `E_TENANT_MISSING` |'
contains "unexpected denial marked" "$o/gh_summary" '| wrongly expected allow &#124; &lt;b&gt;pipe&lt;/b&gt; | **no** |'

echo "run.sh: invalid policy"
printf 'apiVersion: haltsql.dev/v1\nkind: Policy\nmetadata: { name: bad }\nbogus: 1\n' \
  >"$work/repo/policies/bad.yaml"
run_ci invalid INPUT_POLICIES="policies"
check "exit 1" 1 "$rc"
contains "validation error listed" "$o/gh_summary" '### Validation errors'
contains "validation error file" "$o/gh_summary" '`policies/bad.yaml`'
rm "$work/repo/policies/bad.yaml"

echo "run.sh: usage errors"
run_ci nomatch INPUT_POLICIES="nothing/*.yaml"
check "no policies exits 2" 2 "$rc"
run_ci nobin INPUT_POLICIES="policies" HALTSQL=/nonexistent/haltsql
check "missing binary exits 2" 2 "$rc"
run_ci baddenied INPUT_POLICIES="policies" INPUT_MAX_DENIED=abc
check "bad max-denied exits 2" 2 "$rc"
run_ci maxdenied INPUT_POLICIES="policies" INPUT_SUITES="tests/saas.suite.yaml" INPUT_MAX_DENIED=1
contains "denied list truncated" "$o/gh_summary" "... 3 more"

echo "bundle.sh"
"$bundle_bin" bundle keygen -o "$work/sign.key" >/dev/null
o="$work/out-bundle"
mkdir -p "$o"
: >"$o/gh_output"
set +e
(cd "$work/repo" && env HALTSQL="$bundle_bin" HALTSQL_CI_OUT="$o" GITHUB_OUTPUT="$o/gh_output" \
  INPUT_POLICIES="policies" INPUT_CATALOGS="saas=catalog/saas.snapshot.json" \
  INPUT_BUNDLE_NAME=ci-test INPUT_BUNDLE_VERSION=1.2.3 \
  GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 GITHUB_SERVER_URL=https://github.com \
  GITHUB_REPOSITORY=acme/policies HALTSQL_SIGNING_KEY="$(cat "$work/sign.key")" \
  INPUT_PUBLIC_KEYS="$work/sign.key.pub" bash "$scripts/bundle.sh") >"$o/stdout" 2>"$o/stderr"
rc=$?
set -e
check "bundle exit 0" 0 "$rc"
b=$(output_of bundle-path "$o/gh_output")
check "bundle path" "$o/ci-test.haltsqlbundle" "$b"
check "signature path" "$o/ci-test.haltsqlbundle.sig" "$(output_of signature-path "$o/gh_output")"
if "$bundle_bin" bundle verify "$b" -k "$work/sign.key.pub" >/dev/null 2>&1; then
  ok "bundle verifies"
else ko "bundle verifies"; fi
"$bundle_bin" bundle inspect "$b" --json >"$o/inspect.json"
check "bundle source commit" 0123456789abcdef0123456789abcdef01234567 \
  "$(jq -r .bundle.metadata.source_commit "$o/inspect.json")"
check "bundle source url" https://github.com/acme/policies \
  "$(jq -r .bundle.metadata.source_url "$o/inspect.json")"
check "bundle catalogs" saas "$(jq -r '.bundle.catalogs[0].name' "$o/inspect.json")"
check "bundle policies" 2 "$(jq -r '.bundle.policies | length' "$o/inspect.json")"
if grep -q "PRIVATE KEY" "$o/stdout" "$o/stderr"; then ko "key not logged"; else ok "key not logged"; fi

# unsigned bundle when no key is given
o2="$work/out-bundle2"
mkdir -p "$o2"
: >"$o2/gh_output"
# unset in the subshell instead of `env -u`, which is not reliable across env
# implementations (GitHub's ubuntu-latest image ships uutils coreutils).
(cd "$work/repo" && unset HALTSQL_SIGNING_KEY GITHUB_REPOSITORY GITHUB_SERVER_URL &&
  HALTSQL="$bundle_bin" HALTSQL_CI_OUT="$o2" \
  GITHUB_OUTPUT="$o2/gh_output" INPUT_POLICIES="policies" bash "$scripts/bundle.sh") \
  >/dev/null 2>"$o2/stderr"
check "unsigned bundle default name" "$o2/policies.haltsqlbundle" "$(output_of bundle-path "$o2/gh_output")"
check "no signature" "" "$(output_of signature-path "$o2/gh_output")"
contains "unsigned warning" "$o2/stderr" "the bundle is unsigned"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
