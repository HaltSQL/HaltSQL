#!/usr/bin/env bash
# Opt-in live validation of the OpenMetadata integration (not part of `dune test`):
#
#   up -> seed -> haltsql schema fetch -> assert -> lab tier-3 -> down
#
# Needs: docker (~3 GiB free memory), Python >= 3.10, the lab Postgres on
# 127.0.0.1:5417 (`make -C lab up`), and a built haltsql
# (`opam exec -- dune build --root . ./bin/haltsql`).
#
# Environment:
#   OM_PORT      host port for the OpenMetadata API (default 8595, bound to 127.0.0.1)
#   PG_HOST/PG_PORT/PG_USER/PGPASSWORD   lab Postgres (127.0.0.1/5417/postgres/haltlab)
#   SRC_DB       source database created for ingestion (default om_src_<pid>)
#   OM_VENV      venv with openmetadata-ingestion (created in WORK if missing)
#   PYTHON       interpreter for the venv (default python3.11)
#   WORK         output directory (default: a new temp dir)
#   KEEP_UP=1    leave the OpenMetadata stack running
#   SKIP_TIER3=1 stop after the manifest assertion
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
OM_VERSION=2.0.7
INGESTION_VERSION=2.0.7.2
OM_PORT="${OM_PORT:-8595}"
OM_URL="http://127.0.0.1:${OM_PORT}"
PG_HOST="${PG_HOST:-127.0.0.1}"
PG_PORT="${PG_PORT:-5417}"
PG_USER="${PG_USER:-postgres}"
export PGPASSWORD="${PGPASSWORD:-haltlab}"
SRC_DB="${SRC_DB:-om_src_$$}"
SERVICE=haltsql_lab_pg
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/haltsql-om.XXXXXX")}"
OM_VENV="${OM_VENV:-$WORK/venv}"
PYTHON="${PYTHON:-python3.11}"
HALTSQL="${HALTSQL_BIN:-$ROOT/_build/default/bin/haltsql/main.exe}"
export OM_PORT
COMPOSE=(docker compose -p haltsql-om -f "$HERE/docker-compose.yml")
mkdir -p "$WORK"

log() { printf '[om-live %s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

cleanup() {
  status=$?
  if [ -x "$OM_VENV/bin/python" ]; then
    "$OM_VENV/bin/python" - "$SRC_DB" <<'PY' || true
import os, sys, psycopg2
c = psycopg2.connect(host=os.environ.get("PG_HOST", "127.0.0.1"),
                     port=int(os.environ.get("PG_PORT", "5417")),
                     user=os.environ.get("PG_USER", "postgres"),
                     password=os.environ["PGPASSWORD"], dbname="postgres")
c.autocommit = True
c.cursor().execute(f'DROP DATABASE IF EXISTS "{sys.argv[1]}" WITH (FORCE)')
PY
  fi
  if [ "${KEEP_UP:-0}" != 1 ]; then
    log "stopping OpenMetadata (docker compose down -v)"
    "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  fi
  exit $status
}
trap cleanup EXIT
export PG_HOST PG_PORT PG_USER

[ -x "$HALTSQL" ] || { log "haltsql not built: $HALTSQL"; exit 2; }

log "starting OpenMetadata $OM_VERSION on $OM_URL"
"${COMPOSE[@]}" up -d --wait

if [ ! -x "$OM_VENV/bin/metadata" ]; then
  log "installing openmetadata-ingestion $INGESTION_VERSION into $OM_VENV"
  "$PYTHON" -m venv "$OM_VENV"
  "$OM_VENV/bin/pip" install -q "openmetadata-ingestion[postgres]==$INGESTION_VERSION"
fi

log "seeding (database $SRC_DB, service $SERVICE)"
"$OM_VENV/bin/python" "$HERE/seed.py" --om-url "$OM_URL" \
  --pg-host "$PG_HOST" --pg-port "$PG_PORT" --pg-user "$PG_USER" \
  --src-db "$SRC_DB" --service "$SERVICE" \
  --metadata-bin "$OM_VENV/bin/metadata" \
  --token-out "$WORK/om.token" > "$WORK/expected.json"

log "haltsql schema fetch --from openmetadata (page size 4: forces pagination)"
OPENMETADATA_TOKEN="$(cat "$WORK/om.token")" HALTSQL_OPENMETADATA_PAGE_SIZE=4 \
  "$HALTSQL" schema fetch --from openmetadata --url "$OM_URL" \
  --token-env OPENMETADATA_TOKEN --service "$SERVICE" --database "$SRC_DB" \
  -o "$WORK/pii.om.json" --snapshot-out "$WORK/cat.om.json"

log "asserting the manifest equals the labels seed.py applied"
"$OM_VENV/bin/python" "$HERE/assert_fetch.py" \
  "$WORK/expected.json" "$WORK/pii.om.json" "$WORK/cat.om.json"

if [ "${SKIP_TIER3:-0}" != 1 ]; then
  log "lab tier-3 check (positive run + negative control)"
  make -C "$ROOT/lab" catalog-tier3 PII="$WORK/pii.om.json"
fi
log "PASS (outputs in $WORK)"
