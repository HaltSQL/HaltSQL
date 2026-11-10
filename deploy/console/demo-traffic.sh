#!/usr/bin/env bash
# Sends a mix of allowed, denied, shadow-denied and cross-tenant queries through
# haltsql-server's POST /v1/verify so the local console has records, signals and
# a shadow report to show. Pairs with deploy/console/docker-compose.yaml.
#
#   deploy/console/demo-traffic.sh                 # 3 rounds
#   ROUNDS=20 deploy/console/demo-traffic.sh       # more data (cross-tenant signal)
#   EXECUTE=1 deploy/console/demo-traffic.sh       # also run allowed SQL on Postgres
#
# Environment:
#   HALTSQL_URL   haltsql-server base URL     (default http://127.0.0.1:18080)
#   CONSOLE_URL   haltsql-console base URL    (default http://127.0.0.1:8090)
#   ROUNDS        rounds of the query mix     (default 3)
#   EXECUTE=1     run allowed queries against the stack's Postgres (verify, then
#                 execute: the way an agent uses HaltSQL)
#
# The tokens are the well-known LOCAL DEMO tokens from local/haltsql.yaml.

set -euo pipefail

HALTSQL_URL=${HALTSQL_URL:-http://127.0.0.1:18080}
CONSOLE_URL=${CONSOLE_URL:-http://127.0.0.1:8090}
ROUNDS=${ROUNDS:-3}
EXECUTE=${EXECUTE:-0}
HERE=$(cd "$(dirname "$0")" && pwd)
COMPOSE=(docker compose -f "$HERE/docker-compose.yaml")

ANALYTICS=demo-analytics-token
SUPPORT=demo-support-token

allowed=0 denied=0 errors=0

# verify TOKEN TENANT SQL: prints one line per query; SQL must not contain " or \.
verify() {
  local token=$1 tenant=$2 sql=$3 body code verdict
  body=$(printf '{"sql":"%s","context":{"tenant_id":"%s"}}' "$sql" "$tenant")
  if ! verdict=$(curl -sS -w '\n%{http_code}' -H "Authorization: Bearer $token" \
      -H 'Content-Type: application/json' -d "$body" "$HALTSQL_URL/v1/verify"); then
    errors=$((errors + 1)); echo "  ERROR   (unreachable) $sql"; return
  fi
  code=${verdict##*$'\n'}
  verdict=${verdict%$'\n'*}
  if [ "$code" != 200 ]; then
    errors=$((errors + 1)); echo "  HTTP $code $sql: $verdict"; return
  fi
  if printf '%s' "$verdict" | grep -q '"allowed":true'; then
    allowed=$((allowed + 1))
    if printf '%s' "$verdict" | grep -q '"shadow_reasons":\[{'; then
      echo "  ALLOW*  [$tenant] $sql   (shadow mode: would be denied)"
    else
      echo "  ALLOW   [$tenant] $sql"
    fi
    if [ "$EXECUTE" = 1 ]; then
      "${COMPOSE[@]}" exec -T postgres psql -U postgres -d shop -v ON_ERROR_STOP=1 -q \
        -c "SET ROLE agent_ro; $sql" > /dev/null || echo "          (execution failed)"
    fi
  else
    denied=$((denied + 1))
    local codes
    codes=$(printf '%s' "$verdict" | grep -o '"code":"[A-Z_]*"' | cut -d'"' -f4 | sort -u | paste -sd, - || true)
    echo "  DENY    [$tenant] $sql   (${codes:-denied})"
  fi
}

if ! curl -fsS "$HALTSQL_URL/readyz" > /dev/null 2>&1; then
  echo "haltsql-server is not ready at $HALTSQL_URL." >&2
  echo "Start the stack: docker compose -f deploy/console/docker-compose.yaml up -d --build" >&2
  exit 1
fi

for round in $(seq "$ROUNDS"); do
  echo "round $round/$ROUNDS"
  # analytics-agent, tenant acme: everyday traffic.
  verify $ANALYTICS acme "SELECT id, status, total_cents FROM app.orders WHERE tenant_id = 'acme' ORDER BY created_at DESC LIMIT 20"
  verify $ANALYTICS acme "SELECT status, count(*) AS n, sum(total_cents) AS total FROM app.orders WHERE tenant_id = 'acme' GROUP BY status LIMIT 10"
  verify $ANALYTICS acme "SELECT c.name, o.total_cents FROM app.customers c JOIN app.orders o ON o.customer_id = c.id AND o.tenant_id = c.tenant_id WHERE c.tenant_id = 'acme' AND o.tenant_id = 'acme' LIMIT 50"
  verify $ANALYTICS acme "SELECT code, name FROM app.currencies LIMIT 10"
  # Denied: PII column, write, missing LIMIT, unknown table.
  verify $ANALYTICS acme "SELECT name, email FROM app.customers WHERE tenant_id = 'acme' LIMIT 10"
  verify $ANALYTICS acme "DELETE FROM app.orders WHERE tenant_id = 'acme'"
  verify $ANALYTICS acme "SELECT id FROM app.orders WHERE tenant_id = 'acme'"
  verify $ANALYTICS acme "SELECT * FROM pg_catalog.pg_authid LIMIT 1"
  # Cross-tenant: the token's context is acme, the SQL reads globex (or no tenant).
  verify $ANALYTICS acme "SELECT id, total_cents FROM app.orders WHERE tenant_id = 'globex' LIMIT 20"
  verify $ANALYTICS acme "SELECT id, total_cents FROM app.orders WHERE tenant_id = 'acme' OR tenant_id = 'globex' LIMIT 20"
  verify $ANALYTICS acme "SELECT id, total_cents FROM app.orders LIMIT 20"
  # support-bot, shadow mode: violations are allowed but recorded.
  verify $SUPPORT globex "SELECT id, name FROM app.customers WHERE tenant_id = 'globex' LIMIT 5"
  verify $SUPPORT globex "SELECT id, name, email, phone FROM app.customers WHERE tenant_id = 'globex' LIMIT 5"
  verify $SUPPORT globex "SELECT id, status, total_cents FROM app.orders WHERE tenant_id = 'globex' LIMIT 500"
done

echo
echo "allowed $allowed, denied $denied, errors $errors"
if curl -fsS "$CONSOLE_URL/healthz" > /dev/null 2>&1; then
  echo "console: $CONSOLE_URL  (try $CONSOLE_URL/api/v1/overview?range=24h)"
fi
[ "$errors" = 0 ]
