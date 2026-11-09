#!/usr/bin/env bash
# Opt-in live validation of the DataHub integration (not part of `dune test`):
#
#   up -> seed -> haltsql schema fetch -> assert -> bad-token check -> lab tier-3 -> down
#
# Needs: docker (~4 GiB free memory), Python >= 3.10, the lab Postgres on
# 127.0.0.1:5417 (`make -C lab up`), and a built haltsql
# (`opam exec -- dune build --root . ./bin/haltsql`).
#
# Environment:
#   DH_GMS_PORT       host port for DataHub GMS (default 8596, bound to 127.0.0.1)
#   DH_FRONTEND_PORT  host port for the DataHub frontend (default 9596, 127.0.0.1)
#   PG_HOST/PG_PORT/PG_USER/PGPASSWORD   lab Postgres (127.0.0.1/5417/postgres/haltlab)
#   SRC_DB / DECOY_DB databases created for ingestion (default dh_src_<pid>, dh_decoy_<pid>)
#   DH_VENV           venv with acryl-datahub (created in WORK if missing)
#   PYTHON            interpreter for the venv (default python3.11)
#   WORK              output directory (default: a new temp dir)
#   KEEP_UP=1         leave the DataHub stack running
#   SKIP_TIER3=1      stop after the manifest assertions
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
DH_VERSION=v1.8.0
CLI_VERSION=1.7.0.19
DH_GMS_PORT="${DH_GMS_PORT:-8596}"
DH_FRONTEND_PORT="${DH_FRONTEND_PORT:-9596}"
GMS_URL="http://127.0.0.1:${DH_GMS_PORT}"
FRONTEND_URL="http://127.0.0.1:${DH_FRONTEND_PORT}"
PG_HOST="${PG_HOST:-127.0.0.1}"
PG_PORT="${PG_PORT:-5417}"
PG_USER="${PG_USER:-postgres}"
export PGPASSWORD="${PGPASSWORD:-haltlab}"
SRC_DB="${SRC_DB:-dh_src_$$}"
DECOY_DB="${DECOY_DB:-dh_decoy_$$}"
INSTANCE=haltsql_lab
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/haltsql-dh.XXXXXX")}"
DH_VENV="${DH_VENV:-$WORK/venv}"
PYTHON="${PYTHON:-python3.11}"
HALTSQL="${HALTSQL_BIN:-$ROOT/_build/default/bin/haltsql/main.exe}"
export DH_GMS_PORT DH_FRONTEND_PORT
COMPOSE=(docker compose -p haltsql-dh -f "$HERE/docker-compose.yml")
mkdir -p "$WORK"

log() { printf '[dh-live %s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

cleanup() {
  status=$?
  if [ -x "$DH_VENV/bin/python" ]; then
    "$DH_VENV/bin/python" - "$SRC_DB" "$DECOY_DB" <<'PY' || true
import os, sys, psycopg2
c = psycopg2.connect(host=os.environ.get("PG_HOST", "127.0.0.1"),
                     port=int(os.environ.get("PG_PORT", "5417")),
                     user=os.environ.get("PG_USER", "postgres"),
                     password=os.environ["PGPASSWORD"], dbname="postgres")
c.autocommit = True
for db in sys.argv[1:]:
    c.cursor().execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')
PY
  fi
  if [ "${KEEP_UP:-0}" != 1 ]; then
    log "stopping DataHub (docker compose down -v)"
    "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  fi
  exit $status
}
trap cleanup EXIT
export PG_HOST PG_PORT PG_USER

[ -x "$HALTSQL" ] || { log "haltsql not built: $HALTSQL"; exit 2; }

if [ ! -x "$DH_VENV/bin/datahub" ]; then
  log "installing acryl-datahub[postgres]==$CLI_VERSION into $DH_VENV"
  "$PYTHON" -m venv "$DH_VENV"
  "$DH_VENV/bin/pip" install -q "acryl-datahub[postgres]==$CLI_VERSION"
fi

log "starting DataHub $DH_VERSION (GMS $GMS_URL, frontend $FRONTEND_URL)"
"${COMPOSE[@]}" up -d --wait

log "seeding (databases $SRC_DB and $DECOY_DB, platform instance $INSTANCE)"
"$DH_VENV/bin/python" "$HERE/seed.py" --gms-url "$GMS_URL" --frontend-url "$FRONTEND_URL" \
  --pg-host "$PG_HOST" --pg-port "$PG_PORT" --pg-user "$PG_USER" \
  --src-db "$SRC_DB" --decoy-db "$DECOY_DB" --platform-instance "$INSTANCE" \
  --datahub-bin "$DH_VENV/bin/datahub" \
  --token-out "$WORK/dh.token" > "$WORK/expected.json"

log "haltsql schema fetch --from datahub (page size 4: forces pagination)"
DATAHUB_TOKEN="$(cat "$WORK/dh.token")" HALTSQL_DATAHUB_PAGE_SIZE=4 \
  "$HALTSQL" schema fetch --from datahub --url "$GMS_URL" \
  --token-env DATAHUB_TOKEN --service "$INSTANCE" --database "$SRC_DB" \
  -o "$WORK/pii.dh.json" --snapshot-out "$WORK/cat.dh.json" --json > "$WORK/fetch.json"
cat "$WORK/fetch.json" >&2

log "asserting the manifest equals the labels seed.py applied"
"$DH_VENV/bin/python" "$HERE/assert_fetch.py" \
  "$WORK/expected.json" "$WORK/pii.dh.json" "$WORK/cat.dh.json"

log "same fetch through the frontend's GraphQL root (/api/v2)"
DATAHUB_TOKEN="$(cat "$WORK/dh.token")" \
  "$HALTSQL" schema fetch --from datahub --url "$FRONTEND_URL/api/v2" \
  --token-env DATAHUB_TOKEN --service "$INSTANCE" --database "$SRC_DB" \
  -o "$WORK/pii.dh.frontend.json"
"$DH_VENV/bin/python" "$HERE/assert_fetch.py" \
  "$WORK/expected.json" "$WORK/pii.dh.frontend.json" "$WORK/cat.dh.json"

log "a bad token exits 2 without echoing the token or the response body"
BAD_TOKEN="not-a-valid-datahub-token-$$"
set +e
DATAHUB_TOKEN="$BAD_TOKEN" "$HALTSQL" schema fetch --from datahub --url "$GMS_URL" \
  --token-env DATAHUB_TOKEN --database "$SRC_DB" -o "$WORK/pii.bad.json" \
  2> "$WORK/bad.err"
bad=$?
set -e
cat "$WORK/bad.err" >&2
[ "$bad" = 2 ] || { log "bad token: exit $bad, expected 2"; exit 1; }
if grep -q "$BAD_TOKEN" "$WORK/bad.err"; then log "bad token echoed"; exit 1; fi
[ ! -e "$WORK/pii.bad.json" ] || { log "bad token wrote a manifest"; exit 1; }

if [ "${SKIP_TIER3:-0}" != 1 ]; then
  log "lab tier-3 check (positive run + negative control)"
  make -C "$ROOT/lab" catalog-tier3 PII="$WORK/pii.dh.json"
fi
log "PASS (outputs in $WORK)"
