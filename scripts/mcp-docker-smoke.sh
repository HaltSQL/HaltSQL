#!/usr/bin/env bash
# Smoke test of the haltsql-mcp image (clients/mcp/Dockerfile) against a real
# PostgreSQL, over stdio, the way Claude Desktop or Cursor runs it:
#
#   1. solo/local: only policy.yaml mounted at /config, DSN as the last argument
#   2. config file: /config/haltsql-mcp.yaml (row cap, tenant from the file)
#   3. central: a haltsql-server container verifies (token from server.token_file)
#   4. central via environment variables, overriding a mounted policy.yaml
#   5. fail closed: a wrong sidecar token means nothing runs
#
# The MCP client runs inside the image under test (scripts/mcp_smoke_client.py),
# so the host only needs Docker.
#
# Usage:
#   docker build -t haltsql-local:dev .
#   docker build -f clients/mcp/Dockerfile --build-arg HALTSQL_IMAGE=haltsql-local:dev -t haltsql-mcp:dev .
#   scripts/mcp-docker-smoke.sh
#
# Environment:
#   MCP_IMAGE      image under test                  (default haltsql-mcp:dev)
#   HALTSQL_IMAGE  haltsql-server image for 3-5      (default haltsql-local:dev)
#   PG_IMAGE       Postgres image                    (default postgres:17-alpine)
set -euo pipefail

MCP_IMAGE=${MCP_IMAGE:-haltsql-mcp:dev}
HALTSQL_IMAGE=${HALTSQL_IMAGE:-haltsql-local:dev}
PG_IMAGE=${PG_IMAGE:-postgres:17-alpine}

if ! docker info > /dev/null 2>&1; then
  echo "SKIPPED: no Docker daemon"
  exit 0
fi

run_id="hsmcp-smoke-$$"
net="$run_id"
work=$(mktemp -d)
cleanup() {
  docker rm -f "$run_id-pg" "$run_id-server" > /dev/null 2>&1 || true
  docker network rm "$net" > /dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

repo=$(cd "$(dirname "$0")/.." && pwd)
docker network create "$net" > /dev/null

echo "== image metadata"
user=$(docker image inspect -f '{{.Config.User}}' "$MCP_IMAGE")
[ "$user" = "65532:65532" ] || { echo "FAIL: image runs as '$user', want 65532:65532"; exit 1; }
docker run --rm --entrypoint haltsql "$MCP_IMAGE" version | head -1
docker run --rm "$MCP_IMAGE" --help > /dev/null
echo "ok   non-root, haltsql CLI and haltsql-mcp present"

echo "== Postgres"
docker run -d --name "$run_id-pg" --network "$net" -e POSTGRES_PASSWORD=smoke "$PG_IMAGE" > /dev/null
for _ in $(seq 60); do
  docker exec "$run_id-pg" pg_isready -U postgres -q > /dev/null 2>&1 && break
  sleep 1
done
sleep 1
docker exec -i "$run_id-pg" psql -q -v ON_ERROR_STOP=1 -U postgres <<'SQL'
CREATE SCHEMA app;
CREATE TABLE app.customers (id int, tenant_id text, name text, email text);
INSERT INTO app.customers VALUES
  (1, 'acme', 'Ann', 'ann@acme.example'), (2, 'acme', 'Bob', 'bob@acme.example'),
  (3, 'globex', 'Gus', 'gus@globex.example');
CREATE ROLE agent_ro LOGIN PASSWORD 'ro';
ALTER ROLE agent_ro SET search_path = app;
GRANT USAGE ON SCHEMA app TO agent_ro;
GRANT SELECT ON app.customers TO agent_ro;
SQL
dsn="postgresql://agent_ro:ro@$run_id-pg:5432/postgres"

cat > "$work/policy.yaml" <<'YAML'
apiVersion: haltsql.dev/v1
kind: Policy
metadata: { name: mcp-smoke }
search_path: [app]
statements: { allow: [select] }
require_limit: { max: 1000 }
tenancy:
  mode: bound
  keys: { tenant: "${ctx.tenant_id}" }
tables:
  app.customers:
    columns: [id, tenant_id, name]
    tenant_column: tenant_id
functions:
  presets: [aggregates]
YAML
mkdir -p "$work/solo" "$work/cfg" "$work/central" "$work/server"
cp "$work/policy.yaml" "$work/solo/"
cp "$work/policy.yaml" "$work/cfg/"
cp "$work/policy.yaml" "$work/central/"
cp "$work/policy.yaml" "$work/server/"
chmod -R a+rX "$work"

client() {  # client MODE EXPECT_ROWS docker-run-args... -- entrypoint-args...
  local mode=$1 rows=$2; shift 2
  local dargs=()
  while [ "$1" != "--" ]; do dargs+=("$1"); shift; done
  shift
  docker run --rm -i --read-only --network "$net" \
    -v "$repo/scripts/mcp_smoke_client.py:/smoke/client.py:ro" \
    -e EXPECT_ROWS="$rows" "${dargs[@]}" \
    --entrypoint python "$MCP_IMAGE" -I /smoke/client.py "$mode" "$@"
}

echo "== 1. solo: policy.yaml only, DSN positional"
client local '[[1, "Ann"], [2, "Bob"]]' \
  -e 'HALTSQL_MCP_CONTEXT={"tenant_id":"acme"}' -v "$work/solo:/config:ro" -- "$dsn"

echo "== 2. config file"
cat > "$work/cfg/haltsql-mcp.yaml" <<YAML
database_url: $dsn
policy: policy.yaml
context: { tenant_id: acme }
row_cap: 1
YAML
client local '[[1, "Ann"]]' -v "$work/cfg:/config:ro" --

echo "== 3. central haltsql-server"
token="smoke-token-$$"
hash=$(printf %s "$token" | sha256sum 2> /dev/null | cut -d' ' -f1 || printf %s "$token" | shasum -a 256 | cut -d' ' -f1)
cat > "$work/server/config.yaml" <<YAML
apiVersion: haltsql.dev/v1
kind: Config
server:
  listen: 0.0.0.0:8080
  auth:
    allow_unauthenticated: false
    tokens:
      - { name: mcp, token_sha256: $hash, policy: mcp-smoke }
policies:
  - path: ./policy.yaml
YAML
docker run -d --name "$run_id-server" --network "$net" -v "$work/server:/etc/haltsql:ro" \
  "$HALTSQL_IMAGE" --config /etc/haltsql/config.yaml > /dev/null
sleep 2
printf %s "$token" > "$work/central/token"
cat > "$work/central/haltsql-mcp.yaml" <<YAML
server:
  url: http://$run_id-server:8080
  token_file: token
database_url: $dsn
policy_file: policy.yaml
context: { tenant_id: acme }
YAML
client central '[[1, "Ann"], [2, "Bob"]]' -v "$work/central:/config:ro" --

echo "== 4. central via environment, overriding a mounted policy.yaml"
client central '[[3, "Gus"]]' \
  -e "HALTSQL_URL=http://$run_id-server:8080" -e "HALTSQL_TOKEN=$token" \
  -e 'HALTSQL_MCP_CONTEXT={"tenant_id":"globex"}' -v "$work/solo:/config:ro" -- \
  --policy-file /config/policy.yaml "$dsn"

echo "== 5. fail closed on a bad sidecar token"
client closed '[]' \
  -e "HALTSQL_URL=http://$run_id-server:8080" -e HALTSQL_TOKEN=wrong \
  -e 'HALTSQL_MCP_CONTEXT={"tenant_id":"acme"}' -v "$work/solo:/config:ro" -- "$dsn"

echo "PASS: haltsql-mcp image smoke test"
