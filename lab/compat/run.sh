#!/usr/bin/env bash
# Postgres flavour compatibility runs (docs/compatibility.md).
#
#   lab/compat/run.sh up                      # start the local engines (compose profile "compat")
#   lab/compat/run.sh local [ENGINE...|all]   # self-test + HaltSQL + proxy parity per engine
#   lab/compat/run.sh cloud ENGINE            # same against HALTLAB_DSN (a managed service)
#   lab/compat/run.sh redshift                # the Redshift grammar suite (no cluster needed)
#   lab/compat/run.sh table                   # Markdown results table from lab/out/compat/*.json
#   lab/compat/run.sh down                    # stop and remove the local engines
#
# Local engines: pg18 supabase alloydb-omni citus timescaledb (ports 55418-55422).
# Cloud engines: aurora-postgresql neon supabase-cloud alloydb. HALTLAB_DSN is
# the admin DSN of the service (a role that may CREATE DATABASE and CREATE
# ROLE); add sslmode=require or sslmode=verify-full&sslrootcert=FILE. The run
# creates and drops a database haltlab_compat_<engine>_pg<N> and creates the
# NOLOGIN roles haltlab_owner, haltlab_rls and haltlab_cols. Never point it at
# a production cluster.
#
# Binaries: HALTSQL_BIN and HALTSQL_PROXY_BIN, else the harness defaults
# (lab/README.md). Exit status: 0 all passed, 1 a run failed, 2 usage error.
set -euo pipefail
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
LAB="$(cd "$(dirname "$0")/.." && pwd)"
cd "$LAB"
PY="${PY:-$LAB/.venv/bin/python}"
COMPOSE=(docker compose -f "$LAB/infra/compose/docker-compose.yml" --profile compat)
LOCAL_ENGINES=(pg18 supabase alloydb-omni citus timescaledb)
CLOUD_ENGINES=(aurora-postgresql neon supabase-cloud alloydb)
SERVICES=()
for e in "${LOCAL_ENGINES[@]}"; do SERVICES+=("compat-$e"); done

usage() { sed -n '2,20p' "$SELF" | sed 's/^# \{0,1\}//' >&2; exit 2; }
contains() { local x="$1"; shift; for y in "$@"; do [[ "$x" == "$y" ]] && return 0; done; return 1; }
need_venv() { [[ -x "$PY" ]] || { echo "error: $PY not found (cd lab && make venv)" >&2; exit 2; }; }

cmd="${1:-}"; shift || true
case "$cmd" in
  up)
    # Only the compat services: the default pg17 service is left alone.
    "${COMPOSE[@]}" up -d --wait --renew-anon-volumes "${SERVICES[@]}" ;;
  down)
    "${COMPOSE[@]}" rm --stop --force --volumes "${SERVICES[@]}" ;;
  local)
    need_venv
    engines=("$@")
    [[ ${#engines[@]} -eq 0 || "${engines[0]}" == all ]] && engines=("${LOCAL_ENGINES[@]}")
    rc=0
    for e in "${engines[@]}"; do
      contains "$e" "${LOCAL_ENGINES[@]}" || { echo "error: unknown local engine $e (${LOCAL_ENGINES[*]})" >&2; exit 2; }
      unset HALTLAB_DSN  # local scenarios carry their own DSN
      "$PY" -m compat run "scenarios/compat-$e.yaml" || rc=1
    done
    "$PY" -m compat table
    exit $rc ;;
  cloud)
    need_venv
    e="${1:-}"
    contains "$e" "${CLOUD_ENGINES[@]}" || { echo "error: cloud engine must be one of: ${CLOUD_ENGINES[*]}" >&2; exit 2; }
    [[ -n "${HALTLAB_DSN:-}" ]] || { echo "error: set HALTLAB_DSN to the $e admin DSN" >&2; exit 2; }
    "$PY" -m compat run "scenarios/compat-$e.yaml" ;;
  redshift)
    bin="${HALTSQL_BIN:-}"
    if [[ -z "$bin" ]]; then
      for c in "$LAB"/../_build/default/bin/haltsql/main.exe "$(command -v haltsql || true)"; do
        [[ -n "$c" && -x "$c" ]] && { bin="$c"; break; }
      done
    fi
    [[ -n "$bin" ]] || { echo "error: haltsql not found (set HALTSQL_BIN)" >&2; exit 2; }
    "$bin" test "$LAB/../test/corpus/compat-redshift.suite.yaml" ;;
  table)
    need_venv
    "$PY" -m compat table "$@" ;;
  *) usage ;;
esac
