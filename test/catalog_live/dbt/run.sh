#!/usr/bin/env bash
# Live validation of `haltsql schema import --from dbt` against a real dbt Core run.
#
#   venv (dbt-core + dbt-postgres, pinned) -> fresh database from
#   lab/schemas/saas_shared.sql -> dbt build + dbt docs generate -> import
#   target/manifest.json and target/catalog.json -> diff against the expected
#   manifests -> schema pull -> policy draft --no-name-heuristics -> verify that
#   SELECT * and every PII column are denied (and allowed in the negative
#   control drafted without the dbt manifest) -> haltlab tier 3 (lab/catalogs:
#   adversarial SQL with honeytoken/column-privilege oracles, positive run and
#   empty-manifest negative control; SKIP_TIER3=1 skips it).
#
# Environment (defaults match the haltlab compose Postgres on 127.0.0.1:5417):
#   DBT_PG_HOST DBT_PG_PORT DBT_PG_USER DBT_PG_PASSWORD DBT_PG_DBNAME
#   HALTSQL_BIN   haltsql binary (default: _build/default/bin/haltsql/main.exe, built if missing)
#   DBT_VENV      reuse this venv (default: $WORK/venv, created and pinned)
#   DBT_WORK_DIR  scratch directory for dbt target/, logs and outputs (default: mktemp)
#   PYTHON        interpreter for the venv (default: python3.12, else python3)
#   UPDATE_EXPECTED=1  rewrite expected_*.json from this run instead of diffing
# Only the database named by DBT_PG_DBNAME (default haltsql_dbt_lab) is dropped/recreated.
set -euo pipefail

DBT_CORE_VERSION=1.12.6
DBT_POSTGRES_VERSION=1.11.0

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
PROJECT=$HERE/project

export DBT_PG_HOST=${DBT_PG_HOST:-127.0.0.1}
export DBT_PG_PORT=${DBT_PG_PORT:-5417}
export DBT_PG_USER=${DBT_PG_USER:-postgres}
export DBT_PG_PASSWORD=${DBT_PG_PASSWORD:-haltlab}
export DBT_PG_DBNAME=${DBT_PG_DBNAME:-haltsql_dbt_lab}
export DBT_SEND_ANONYMOUS_USAGE_STATS=false
export DBT_NO_VERSION_CHECK=true
export DBT_USE_COLORS=false

WORK=${DBT_WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/haltsql-dbt.XXXXXX")}
mkdir -p "$WORK"
VENV=${DBT_VENV:-$WORK/venv}

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

if [ -z "${HALTSQL_BIN:-}" ]; then
  HALTSQL_BIN=$ROOT/_build/default/bin/haltsql/main.exe
  if [ ! -x "$HALTSQL_BIN" ]; then
    step "build haltsql"
    opam exec -- dune build --root "$ROOT" bin/haltsql/main.exe
  fi
fi
haltsql() { "$HALTSQL_BIN" "$@"; }

step "dbt venv ($VENV)"
if [ ! -x "$VENV/bin/dbt" ]; then
  PY=${PYTHON:-$(command -v python3.12 || command -v python3)}
  "$PY" -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --upgrade pip
  "$VENV/bin/pip" install --quiet "dbt-core==$DBT_CORE_VERSION" "dbt-postgres==$DBT_POSTGRES_VERSION"
fi
versions=$("$VENV/bin/dbt" --version 2>&1)
printf '%s\n' "$versions" | grep -E 'installed|postgres:'
case "$versions" in *"installed: $DBT_CORE_VERSION"*) ;;
  *) fail "dbt-core is not $DBT_CORE_VERSION in $VENV" ;; esac
case "$versions" in *"postgres: $DBT_POSTGRES_VERSION"*) ;;
  *) fail "dbt-postgres is not $DBT_POSTGRES_VERSION in $VENV" ;; esac

step "database $DBT_PG_DBNAME from lab/schemas/saas_shared.sql"
"$VENV/bin/python" -I "$HERE/setup_db.py" "$ROOT/lab/schemas/saas_shared.sql"

dbt() {
  "$VENV/bin/dbt" "$@" --project-dir "$PROJECT" --profiles-dir "$PROJECT" \
    --target-path "$WORK/target" --log-path "$WORK/logs"
}
step "dbt build"
dbt build
step "dbt docs generate"
dbt docs generate
for f in manifest.json catalog.json; do
  [ -s "$WORK/target/$f" ] || fail "dbt did not write target/$f"
done

step "haltsql schema import --from dbt"
haltsql schema import --from dbt "$WORK/target/manifest.json" -o "$WORK/pii-manifest.json" --json
haltsql schema import --from dbt "$WORK/target/catalog.json" -o "$WORK/pii-catalog.json" --json
if [ "${UPDATE_EXPECTED:-}" = 1 ]; then
  cp "$WORK/pii-manifest.json" "$HERE/expected_manifest.json"
  cp "$WORK/pii-catalog.json" "$HERE/expected_catalog.json"
  echo "updated expected_manifest.json and expected_catalog.json"
fi
diff -u "$HERE/expected_manifest.json" "$WORK/pii-manifest.json" \
  || fail "manifest.json import differs from expected_manifest.json"
diff -u "$HERE/expected_catalog.json" "$WORK/pii-catalog.json" \
  || fail "catalog.json import differs from expected_catalog.json"
echo "imports match expected_manifest.json and expected_catalog.json"

step "haltsql schema pull"
PGPASSWORD=$DBT_PG_PASSWORD haltsql schema pull \
  --dsn "postgres://$DBT_PG_USER@$DBT_PG_HOST:$DBT_PG_PORT/$DBT_PG_DBNAME?sslmode=disable" \
  -o "$WORK/catalog.yaml" --json

step "haltsql policy draft --no-name-heuristics (dbt PII) and negative control (no PII)"
haltsql policy draft --catalog "$WORK/catalog.yaml" \
  --pii "$WORK/pii-manifest.json" --pii "$WORK/pii-catalog.json" \
  --tenant-column tenant_id --no-name-heuristics --name dbt-lab \
  -o "$WORK/policy.yaml" --json
haltsql policy draft --catalog "$WORK/catalog.yaml" \
  --tenant-column tenant_id --no-name-heuristics --name dbt-lab-no-pii \
  -o "$WORK/policy-no-pii.yaml" --json

# schema<TAB>table<TAB>column for every expected PII column (manifest + catalog).
"$VENV/bin/python" -I - "$HERE/expected_manifest.json" "$HERE/expected_catalog.json" \
  >"$WORK/pii-columns.tsv" <<'EOF'
import json, sys
cols = set()
for path in sys.argv[1:]:
    for rel, t in json.load(open(path))["tables"].items():
        schema, table = rel.split(".", 1)
        for c in t["columns"]:
            cols.add((schema, table, c))
for c in sorted(cols):
    print("\t".join(c))
EOF
[ -s "$WORK/pii-columns.tsv" ] || fail "no expected PII columns"

CTX='{"tenant_id":"acme"}'
# verdict POLICY SQL -> ALLOWED | DENIED (column denial) | OTHER (any other outcome).
# Every query carries the tenant predicate, so a DENIED is always the column check.
verdict() {
  local out
  if out=$(haltsql verify -p "$1" -c "$CTX" -s "$2" 2>&1); then echo ALLOWED; else
    case "$out" in
      *E_COLUMN_DENIED*) echo DENIED ;;
      *) printf '%s\n' "$out" >&2; echo OTHER ;;
    esac
  fi
}
W='WHERE tenant_id = $1 LIMIT 10'
quote_ident() {
  case "$1" in *[!a-z0-9_]*) printf '"%s"' "$1" ;; *) printf '%s' "$1" ;; esac
}
expect() { # EXPECTED POLICY SQL
  local got
  got=$(verdict "$2" "$3")
  printf '  %-7s %-7s %s\n' "$got" "($(basename "$2"))" "$3"
  [ "$got" = "$1" ] || { failures=$((failures + 1)); echo "    expected $1"; }
}

step "haltsql verify"
failures=0
pii_count=0
while IFS=$'\t' read -r schema table column; do
  pii_count=$((pii_count + 1))
  sql="SELECT $(quote_ident "$column") FROM $schema.$table $W"
  expect DENIED "$WORK/policy.yaml" "$sql"
  expect ALLOWED "$WORK/policy-no-pii.yaml" "$sql"
done <"$WORK/pii-columns.tsv"
for rel in app.customers app.users app.payments app.audit_events \
  analytics.stg_customers analytics_marts.users_dim; do
  expect DENIED "$WORK/policy.yaml" "SELECT * FROM $rel $W"
  expect ALLOWED "$WORK/policy-no-pii.yaml" "SELECT * FROM $rel $W"
done
# Non-PII columns stay usable (including ones with non-PII tags/meta).
expect ALLOWED "$WORK/policy.yaml" "SELECT id, name, country FROM app.customers $W"
expect ALLOWED "$WORK/policy.yaml" "SELECT full_name, role FROM app.users $W"
expect ALLOWED "$WORK/policy.yaml" "SELECT card_last4, amount_cents FROM app.payments $W"
expect ALLOWED "$WORK/policy.yaml" "SELECT action, detail FROM app.audit_events $W"
expect ALLOWED "$WORK/policy.yaml" "SELECT id, name, country FROM analytics.stg_customers $W"
expect ALLOWED "$WORK/policy.yaml" "SELECT full_name, org_name FROM analytics_marts.users_dim $W"
[ "$failures" -eq 0 ] || fail "$failures verify expectation(s) failed"

step "drafted app.* columns == lab/policies/saas_shared.yaml (hand-curated ground truth)"
"$VENV/bin/python" -I - "$ROOT/lab/policies/saas_shared.yaml" "$WORK/policy.yaml" <<'EOF' \
  || fail "drafted policy differs from the lab policy"
import sys, yaml
want, got = (yaml.safe_load(open(p))["tables"] for p in sys.argv[1:])
bad = 0
for t, spec in sorted(want.items()):
    w, g = spec["columns"], got.get(t, {}).get("columns")
    if w == "*":
        ok = g is not None  # global table: every column readable
    else:
        ok = g is not None and sorted(w) == sorted(g)
    print(("  ok   " if ok else "  DIFF ") + t + ("" if ok else f": want {w}, got {g}"))
    bad += not ok
sys.exit(1 if bad else 0)
EOF
echo "PASS: $pii_count dbt PII columns denied with the dbt manifest and allowed without it"

if [ "${SKIP_TIER3:-}" = 1 ]; then
  echo "(haltlab tier 3 skipped: SKIP_TIER3=1)"
else
  # lab/catalogs: fresh saas_shared database, draft --no-name-heuristics from the
  # manifest, adversarial + targeted SQL with honeytoken and column-privilege
  # oracles (0 leaks), and the empty-manifest negative control (every tagged
  # column must leak). Model relations (analytics.*) are not in that fixture and
  # are listed as ignored; the source tables (app.*) are what it checks.
  step "haltlab tier 3: positive run + negative control"
  export HALTSQL_BIN
  export HALTLAB_DSN=${HALTLAB_DSN:-postgresql://$DBT_PG_USER:$DBT_PG_PASSWORD@$DBT_PG_HOST:$DBT_PG_PORT/postgres}
  make -C "$ROOT/lab" catalog-tier3 \
    PII="$WORK/pii-manifest.json $WORK/pii-catalog.json" FIXTURE=saas_shared MODE=both
fi
echo "work dir: $WORK"
