#!/usr/bin/env bash
# Fail when the version strings that ship in a release drift apart.
#
#   scripts/check-versions.sh                 # every manifest carries one version
#   scripts/check-versions.sh --tag v0.0.1    # ... and it is the version of this tag
#   scripts/check-versions.sh --print         # print the version and exit
#
# A release-candidate tag (vX.Y.Z-rc.N) is checked against X.Y.Z: the manifests
# keep the final version while candidates are cut. Any other tag must match exactly.
#
# HaltSQL versions in lockstep: the OCaml packages, every SDK, the MCP server and
# the Helm chart (both `version` and `appVersion`) carry the same version, so one
# tag names one consistent set of artifacts. Run by ci.yml on every pull request
# and by release.yml before anything is built.
set -euo pipefail

cd "$(dirname "$0")/.."

tag=""
print=0
while [ $# -gt 0 ]; do
  case "$1" in
    --tag) tag="${2:?--tag needs a value}"; shift 2 ;;
    --print) print=1; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "check-versions: unknown argument $1" >&2; exit 2 ;;
  esac
done

failures=0
expected=""
declare -a rows=()

# record FILE LABEL VALUE
record() {
  local file="$1" label="$2" value="$3"
  if [ -z "$value" ]; then
    rows+=("MISSING  $file ($label)")
    failures=$((failures + 1))
    return
  fi
  if [ -z "$expected" ]; then expected="$value"; fi
  if [ "$value" = "$expected" ]; then
    rows+=("ok       $value  $file ($label)")
  else
    rows+=("DRIFT    $value  $file ($label), expected $expected")
    failures=$((failures + 1))
  fi
}

# first_match FILE SED-EXPRESSION: first line the expression prints.
first_match() { sed -nE "$2" "$1" | head -n 1; }

record dune-project "(version)" "$(first_match dune-project 's/^\(version ([^)]+)\)$/\1/p')"
for f in haltsql.opam haltsql-server.opam haltsql-proxy.opam; do
  record "$f" "version" "$(first_match "$f" 's/^version: "([^"]+)"$/\1/p')"
done
record lib/haltsql/haltsql.ml "let version" \
  "$(first_match lib/haltsql/haltsql.ml 's/^let version = "([^"]+)"$/\1/p')"

record clients/python/pyproject.toml "[project] version" \
  "$(first_match clients/python/pyproject.toml 's/^version = "([^"]+)"$/\1/p')"
record clients/python/src/haltsql/_version.py "__version__" \
  "$(first_match clients/python/src/haltsql/_version.py 's/^__version__ = "([^"]+)"$/\1/p')"

record clients/mcp/pyproject.toml "[project] version" \
  "$(first_match clients/mcp/pyproject.toml 's/^version = "([^"]+)"$/\1/p')"
record clients/mcp/src/haltsql_mcp/__init__.py "__version__" \
  "$(first_match clients/mcp/src/haltsql_mcp/__init__.py 's/^__version__ = "([^"]+)"$/\1/p')"
# The MCP server and the framework integrations require haltsql>=<this version>.
record clients/mcp/pyproject.toml "haltsql>= floor" \
  "$(first_match clients/mcp/pyproject.toml 's/^ *"haltsql>=([^"]+)",?$/\1/p')"
for d in integrations/*/; do
  [ -f "$d/pyproject.toml" ] || continue
  record "${d}pyproject.toml" "[project] version" \
    "$(first_match "$d/pyproject.toml" 's/^version = "([^"]+)"$/\1/p')"
  record "${d}pyproject.toml" "haltsql>= floor" \
    "$(first_match "$d/pyproject.toml" 's/.*"haltsql(\[[a-z,]+\])?>=([^",]+)".*/\2/p')"
  inits=("$d"src/*/__init__.py)
  init="${inits[0]}"
  record "$init" "__version__" \
    "$( [ -f "$init" ] && first_match "$init" 's/^__version__ = "([^"]+)"$/\1/p')"
done

record clients/typescript/package.json "version" \
  "$(first_match clients/typescript/package.json 's/^  "version": "([^"]+)",?$/\1/p')"
record clients/typescript/package-lock.json "version" \
  "$(first_match clients/typescript/package-lock.json 's/^  "version": "([^"]+)",?$/\1/p')"
# The @haltsql/native-* optional dependencies are not in the repository; they are
# added at pack time at the client's version (clients/typescript/scripts/set-native-deps.mjs).
record clients/typescript/src/client.ts "VERSION" \
  "$(first_match clients/typescript/src/client.ts 's/^export const VERSION = "([^"]+)";$/\1/p')"

record clients/go/haltsql/client.go "const Version" \
  "$(first_match clients/go/haltsql/client.go 's/^const Version = "([^"]+)"$/\1/p')"

# The project's own <version> is the first one, right after <artifactId>.
record clients/java/pom.xml "project version" \
  "$(first_match clients/java/pom.xml 's/^  <version>([^<]+)<\/version>$/\1/p')"
record clients/java/src/main/java/com/haltsql/client/HaltSQLClient.java "VERSION" \
  "$(first_match clients/java/src/main/java/com/haltsql/client/HaltSQLClient.java \
      's/^ *public static final String VERSION = "([^"]+)";$/\1/p')"

chart=deploy/helm/haltsql/Chart.yaml
record "$chart" "version" "$(first_match "$chart" 's/^version: "?([^"]+)"?$/\1/p')"
record "$chart" "appVersion" "$(first_match "$chart" 's/^appVersion: "?([^"]+)"?$/\1/p')"
record "$chart" "artifacthub.io/images" \
  "$(first_match "$chart" 's/^ *image: ghcr\.io\/haltsql\/haltsql:([^ ]+)$/\1/p')"

console_chart=deploy/helm/haltsql-console/Chart.yaml
record "$console_chart" "version" "$(first_match "$console_chart" 's/^version: "?([^"]+)"?$/\1/p')"
record "$console_chart" "appVersion" "$(first_match "$console_chart" 's/^appVersion: "?([^"]+)"?$/\1/p')"
record "$console_chart" "artifacthub.io/images" \
  "$(first_match "$console_chart" 's/^ *image: ghcr\.io\/haltsql\/haltsql-console:([^ ]+)$/\1/p')"

if [ "$print" = 1 ]; then
  [ "$failures" = 0 ] || { printf '%s\n' "${rows[@]}" >&2; exit 1; }
  echo "$expected"
  exit 0
fi

printf '%s\n' "${rows[@]}"

if [ -n "$tag" ]; then
  case "$tag" in
    v*) ;;
    *) echo "check-versions: tag $tag does not start with v" >&2; exit 2 ;;
  esac
  want="${tag#v}"
  # vX.Y.Z-rc.N is a candidate for X.Y.Z.
  if [[ "$want" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-rc\.[0-9]+$ ]]; then
    want="${BASH_REMATCH[1]}"
  fi
  if [ "$want" != "$expected" ]; then
    echo "check-versions: tag $tag needs version $want, the manifests carry $expected" >&2
    failures=$((failures + 1))
  else
    echo "check-versions: tag $tag matches version $expected"
  fi
fi

if [ "$failures" != 0 ]; then
  echo "check-versions: $failures problem(s); bump every file above together" >&2
  exit 1
fi
echo "check-versions: ${#rows[@]} version strings agree on $expected"
