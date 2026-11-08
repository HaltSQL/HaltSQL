#!/usr/bin/env bash
# Smoke test of the HaltSQL container image (Dockerfile). Runs the real image:
#
#   1. image metadata: runs as non-root (65532), no shell in the image
#   2. haltsql version / validate / verify (allowed -> exit 0, denied -> exit 1)
#   3. haltsql-server: GET /healthz, POST /v1/verify (allowed and denied)
#   4. haltsql-proxy against a real PostgreSQL: an allowed and a denied query
#      through psql (from a postgres client container)
#   5. optionally, the static binaries on a scratch image (SCRATCH_IMAGE)
#
# Usage:
#   docker build -t haltsql-local:dev .
#   docker build --target scratch -t haltsql-local:scratch .
#   SCRATCH_IMAGE=haltsql-local:scratch scripts/docker-smoke.sh
#
# Environment:
#   IMAGE              image under test              (default haltsql-local:dev)
#   SCRATCH_IMAGE      scratch-based image to check  (default: skipped)
#   CLIENT_IMAGE       psql/wget client image        (default postgres:17-alpine)
#   PGHOST_FROM_DOCKER Postgres host as seen from a container
#                                                    (default host.docker.internal)
#   PGPORT             Postgres port                 (default 5417, the lab Postgres)
#   PGUSER             Postgres superuser            (default postgres)
#   HALTSQL_PGPASSWORD its password                  (default haltlab)
#   SKIP_PROXY=1       skip step 4
#   REQUIRE_PROXY=1    fail (instead of skipping step 4) when Postgres is unreachable
#
# Without a Docker daemon the script prints SKIPPED and exits 0. Without a reachable
# Postgres, step 4 is skipped with a message unless REQUIRE_PROXY=1 (CI sets it).
#
# Creates (and always removes) the network and containers haltsql-release-smoke-<pid>-*
# and the database release_smoke_<pid>. Exit status 0 only if every check passed.

set -euo pipefail

IMAGE=${IMAGE:-haltsql-local:dev}
SCRATCH_IMAGE=${SCRATCH_IMAGE:-}
CLIENT_IMAGE=${CLIENT_IMAGE:-postgres:17-alpine}
PG_HOST=${PGHOST_FROM_DOCKER:-host.docker.internal}
PG_PORT=${PGPORT:-5417}
PG_USER=${PGUSER:-postgres}
PG_PASSWORD=${HALTSQL_PGPASSWORD:-haltlab}
SKIP_PROXY=${SKIP_PROXY:-0}
REQUIRE_PROXY=${REQUIRE_PROXY:-0}

if ! docker info > /dev/null 2>&1; then
  echo "docker-smoke: SKIPPED (no Docker daemon reachable)"
  exit 0
fi
if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
  echo "docker-smoke: image $IMAGE not found; build it first: docker build -t $IMAGE ." >&2
  exit 1
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
NAME=haltsql-release-smoke-$$
NET=$NAME-net
DB=release_smoke_$$
# A random password for the proxy's SCRAM user, never written to the config.
AGENT_PW=agent-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
WORK=$(mktemp -d "${TMPDIR:-/tmp}/haltsql-smoke.XXXXXX")
# --add-host makes host.docker.internal work on Linux too (Docker Desktop has it).
HOSTGW=(--add-host=host.docker.internal:host-gateway)

pass=0
fail=0
ok() { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
ko() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ $# -lt 2 ] || printf '%s\n' "$2" | sed 's/^/        /'; }
step() { printf '\n== %s\n' "$1"; }

cleanup() {
  set +e
  if [ "$fail" -gt 0 ]; then
    for c in "$NAME-server" "$NAME-proxy"; do
      if docker container inspect "$c" > /dev/null 2>&1; then
        echo "--- logs of $c"
        docker logs "$c" 2>&1 | tail -n 30
      fi
    done
  fi
  docker rm -f "$NAME-server" "$NAME-proxy" > /dev/null 2>&1
  if [ "$SKIP_PROXY" != 1 ]; then
    psql_admin -c "DROP DATABASE IF EXISTS $DB WITH (FORCE)" > /dev/null 2>&1
  fi
  docker network rm "$NET" > /dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

hs() { docker run --rm -v "$ROOT/examples:/etc/haltsql:ro" --entrypoint /usr/local/bin/haltsql "$IMAGE" "$@"; }
client() { docker run --rm --network "$NET" "${HOSTGW[@]}" "$CLIENT_IMAGE" "$@"; }
psql_admin() { # set PSQL_STDIN=1 to feed SQL on stdin
  docker run --rm ${PSQL_STDIN:+-i} "${HOSTGW[@]}" -e PGPASSWORD="$PG_PASSWORD" "$CLIENT_IMAGE" \
    psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "${PSQL_DB:-postgres}" -v ON_ERROR_STOP=1 -qtA "$@"
}
retry() { # retry N CMD...: until CMD succeeds, 0.5 s apart
  local n=$1; shift
  for _ in $(seq "$n"); do "$@" > /dev/null 2>&1 && return 0; sleep 0.5; done
  return 1
}

docker network create "$NET" > /dev/null

# --------------------------------------------------------------------------- 1
step "image $IMAGE"
user=$(docker image inspect -f '{{.Config.User}}' "$IMAGE")
case "$user" in
  65532:65532 | 65532) ok "runs as non-root user $user" ;;
  *) ko "image user is '$user', expected 65532:65532" ;;
esac
if docker run --rm --entrypoint /bin/sh "$IMAGE" -c true > /dev/null 2>&1; then
  ko "image contains /bin/sh (expected a distroless/static image)"
else
  ok "no shell in the image"
fi
size=$(docker image inspect -f '{{.Size}}' "$IMAGE")
ok "image content size $((size / 1024 / 1024)) MiB (docker image inspect .Size)"

# --------------------------------------------------------------------------- 2
step "haltsql CLI"
if out=$(hs version 2>&1) && grep -q '^haltsql ' <<< "$out"; then
  ok "haltsql version: $(head -1 <<< "$out")"
else
  ko "haltsql version" "$out"
fi
if out=$(hs validate /etc/haltsql/policies/saas.yaml /etc/haltsql/policies/saas.json 2>&1); then
  ok "haltsql validate policies/saas.yaml policies/saas.json"
else
  ko "haltsql validate" "$out"
fi
CTX='{"tenant_id":"acme"}'
# shellcheck disable=SC2016 # $1 is a SQL parameter, not a shell variable
ALLOWED_SQL='SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 10'
# shellcheck disable=SC2016
DENIED_SQL='SELECT email FROM customers WHERE tenant_id = $1 LIMIT 10'
set +e
out=$(hs verify -p /etc/haltsql/policies/saas.yaml -c "$CTX" --sql "$ALLOWED_SQL" --json 2>&1); rc=$?
set -e
if [ $rc -eq 0 ] && grep -q '"allowed": *true' <<< "$out"; then ok "verify allowed query -> exit 0"; else ko "verify allowed query (exit $rc)" "$out"; fi
set +e
out=$(hs verify -p /etc/haltsql/policies/saas.yaml -c "$CTX" --sql "$DENIED_SQL" --json 2>&1); rc=$?
set -e
if [ $rc -eq 1 ] && grep -q 'E_COLUMN_DENIED' <<< "$out"; then ok "verify denied query -> exit 1, E_COLUMN_DENIED"; else ko "verify denied query (exit $rc)" "$out"; fi

# --------------------------------------------------------------------------- 3
step "haltsql-server"
docker run -d --name "$NAME-server" --network "$NET" -v "$ROOT/examples:/etc/haltsql:ro" \
  "$IMAGE" --policy /etc/haltsql/policies/saas.yaml --allow-unauthenticated --audit stdout > /dev/null
SERVER=http://$NAME-server:8080
if retry 60 client wget -q -O /dev/null "$SERVER/healthz"; then
  out=$(client wget -q -O - "$SERVER/healthz")
  if grep -q '"ok"' <<< "$out"; then ok "GET /healthz: $out"; else ko "GET /healthz" "$out"; fi
else
  ko "haltsql-server did not become healthy"
fi
body() { printf '{"sql":"%s","context":%s}' "$1" "$CTX"; }
out=$(client wget -q -O - --header 'Content-Type: application/json' --post-data "$(body "$ALLOWED_SQL")" "$SERVER/v1/verify" 2>&1 || true)
if grep -q '"allowed":true' <<< "$out" && grep -q '"bind_params"' <<< "$out"; then ok "POST /v1/verify allowed (bind_params returned)"; else ko "POST /v1/verify allowed" "$out"; fi
out=$(client wget -q -O - --header 'Content-Type: application/json' --post-data "$(body "$DENIED_SQL")" "$SERVER/v1/verify" 2>&1 || true)
if grep -q '"allowed":false' <<< "$out" && grep -q 'E_COLUMN_DENIED' <<< "$out"; then ok "POST /v1/verify denied (E_COLUMN_DENIED)"; else ko "POST /v1/verify denied" "$out"; fi
if docker logs "$NAME-server" 2>/dev/null | grep -q '"allowed":false'; then ok "audit record for the denial on stdout"; else ko "no audit record for the denial"; fi
if docker logs "$NAME-server" 2>&1 | grep -q 'email FROM customers'; then ko "raw SQL leaked into the logs"; else ok "no raw SQL in logs or audit"; fi

# --------------------------------------------------------------------------- 4
step "haltsql-proxy -> PostgreSQL $PG_HOST:$PG_PORT"
if [ "$SKIP_PROXY" = 1 ]; then
  echo "  skipped (SKIP_PROXY=1)"
elif ! psql_admin -c 'SELECT 1' > /dev/null 2>&1; then
  msg="PostgreSQL unreachable at $PG_HOST:$PG_PORT from a container (start the lab: make -C lab up)"
  if [ "$REQUIRE_PROXY" = 1 ]; then ko "$msg"; else echo "  SKIPPED: $msg"; SKIP_PROXY=1; fi
else
  psql_admin -c "CREATE DATABASE $DB" > /dev/null
  PSQL_STDIN=1 PSQL_DB=$DB psql_admin > /dev/null <<'SQL'
CREATE SCHEMA app;
CREATE TABLE app.orders (id bigint PRIMARY KEY, tenant_id text NOT NULL, status text NOT NULL,
                         total_cents bigint NOT NULL);
INSERT INTO app.orders VALUES (1, 'acme', 'paid', 1200), (2, 'acme', 'new', 800),
                              (3, 'globex', 'paid', 99900);
SQL
  ok "created database $DB"
  verifier=$(printf '%s\n' "$AGENT_PW" | docker run --rm -i --entrypoint /usr/local/bin/haltsql-proxy "$IMAGE" scram-verifier)
  cat > "$WORK/policy.yaml" <<'YAML'
apiVersion: haltsql.dev/v1
kind: Policy
metadata: { name: smoke, owner: release }
dialect: postgres-17
search_path: [app]
statements: { allow: [select] }
require_limit: { max: 100 }
tenancy: { mode: literal, keys: { tenant: "${ctx.tenant_id}" } }
tables:
  app.orders:
    columns: [id, tenant_id, status, total_cents]
    tenant_column: tenant_id
functions: { presets: [aggregates] }
mode: enforce
YAML
  cat > "$WORK/proxy.yaml" <<YAML
apiVersion: haltsql.dev/v1
kind: ProxyConfig
listen: 0.0.0.0:6432
upstream:
  host: $PG_HOST
  port: $PG_PORT
  database: $DB
  user: $PG_USER
  password: \${env:UPSTREAM_PASSWORD}
policies:
  - path: ./policy.yaml
auth:
  method: scram
  users:
    - name: agent
      scram_verifier: "$verifier"
      policy: smoke
      context: { tenant_id: acme }
audit: { type: stdout }
YAML
  chmod 755 "$WORK" && chmod 644 "$WORK"/*.yaml
  proxy_run=(-e UPSTREAM_PASSWORD="$PG_PASSWORD" -v "$WORK:/etc/haltsql:ro" --entrypoint /usr/local/bin/haltsql-proxy "$IMAGE")
  if out=$(docker run --rm "${HOSTGW[@]}" "${proxy_run[@]}" validate --config /etc/haltsql/proxy.yaml 2>&1); then
    ok "haltsql-proxy validate"
  else
    ko "haltsql-proxy validate" "$out"
  fi
  docker run -d --name "$NAME-proxy" --network "$NET" "${HOSTGW[@]}" "${proxy_run[@]}" \
    run --config /etc/haltsql/proxy.yaml > /dev/null
  agent_psql() {
    client env PGPASSWORD="$AGENT_PW" psql "host=$NAME-proxy port=6432 dbname=$DB user=agent sslmode=disable connect_timeout=5" \
      -v VERBOSITY=verbose -qtA -c "$1"
  }
  retry 60 agent_psql "SELECT count(*) FROM app.orders WHERE tenant_id = 'acme' LIMIT 1" || true
  set +e
  out=$(agent_psql "SELECT count(*) FROM app.orders WHERE tenant_id = 'acme' LIMIT 1" 2>&1); rc=$?
  set -e
  if [ $rc -eq 0 ] && [ "$out" = 2 ]; then ok "psql via proxy, allowed query -> 2 rows counted"; else ko "psql via proxy, allowed query (exit $rc)" "$out"; fi
  set +e
  out=$(agent_psql "SELECT count(*) FROM app.orders WHERE tenant_id = 'globex' LIMIT 1" 2>&1); rc=$?
  set -e
  if [ $rc -ne 0 ] && grep -q '42501' <<< "$out" && grep -q 'denied by policy' <<< "$out"; then
    ok "psql via proxy, cross-tenant query -> ERROR 42501 denied by policy"
  else
    ko "psql via proxy, cross-tenant query (exit $rc)" "$out"
  fi
  set +e
  out=$(agent_psql "SELECT id FROM app.orders WHERE tenant_id = 'acme' LIMIT 1; DROP TABLE app.orders" 2>&1); rc=$?
  set -e
  if [ $rc -ne 0 ] && grep -q '42501' <<< "$out"; then ok "psql via proxy, stacked DROP TABLE -> denied"; else ko "psql via proxy, stacked DROP TABLE (exit $rc)" "$out"; fi
  if [ "$(PSQL_DB=$DB psql_admin -c 'SELECT count(*) FROM app.orders')" = 3 ]; then ok "table intact after the denied statements"; else ko "app.orders changed"; fi
  if docker logs "$NAME-proxy" 2>/dev/null | grep '"event":"statement"' | grep -q '"allowed":false'; then
    ok "proxy audit records the denial"
  else
    ko "proxy audit record missing"
  fi
fi

# --------------------------------------------------------------------------- 5
if [ -n "$SCRATCH_IMAGE" ]; then
  step "static binaries on scratch ($SCRATCH_IMAGE)"
  for b in haltsql haltsql-server haltsql-proxy; do
    if out=$(docker run --rm --entrypoint "/usr/local/bin/$b" "$SCRATCH_IMAGE" --version 2>&1); then
      ok "$b --version on an empty filesystem: $out"
    else
      ko "$b on scratch" "$out"
    fi
  done
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
