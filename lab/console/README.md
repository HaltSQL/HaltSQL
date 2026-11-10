# Console end-to-end check

Runs haltsql-console against real verifiers and real traffic from every
integration, then checks every console endpoint. Everything stays on loopback.

## Prerequisites

```sh
make -C lab up    # lab Postgres on 127.0.0.1:5417
opam exec -- dune build ./bin/server/main.exe ./bin/proxy/main.exe ./bin/console/main.exe ./bin/haltsql/main.exe
```

One virtualenv per adapter, with the adapter and its framework extra installed:
`clients/python/.venv` (SDK; also runs the orchestrator), `clients/mcp/.venv`,
and `integrations/<name>/.venv` for langchain (`[langchain]`), llamaindex
(`[llamaindex]`), vanna (plus `pandas`), crewai, langgraph, openai_agents,
google_adk and semantic_kernel. Or put them in `$E2E_VENV_DIR/venv-<name>`.

## 1. Integration test suites, recorded

`server-wrapper.sh` is a `HALTSQL_SERVER_BIN` that runs the real server the way
the suites' fixtures ask, but writes a hash-chained audit file per suite:

```sh
mkdir -p /tmp/suite-audit
wrap="HALTSQL_SERVER_BIN=$PWD/lab/console/server-wrapper.sh E2E_AUDIT_DIR=/tmp/suite-audit"
wrap="$wrap E2E_REAL_SERVER_BIN=$PWD/_build/default/bin/server/main.exe"
for s in crewai google_adk langgraph openai_agents semantic_kernel; do
  (cd integrations/$s && env $wrap E2E_SUITE=$s .venv/bin/python -m pytest -q)
done
(cd clients/python && env $wrap E2E_SUITE=python-sdk .venv/bin/python -m pytest -q)
```

The wrapper variables are set per command, not exported: the wrapper only works
for a suite (it needs `E2E_SUITE`). `run_e2e.py` never reads `HALTSQL_SERVER_BIN`
anyway; to point it at another server binary use `E2E_SERVER_BIN`.

## 2. Scenario and console checks

```sh
clients/python/.venv/bin/python lab/console/run_e2e.py --suite-audit /tmp/suite-audit
```

It creates a scratch database, starts `haltsql-server` (a token per agent,
admin API, audit file with raw SQL, metrics) and `haltsql-proxy`, drives
allowed, denied and cross-tenant traffic through each adapter
(`drive_adapter.py`), the MCP tools (`drive_mcp.py`) and the proxy (psycopg),
starts the console on those audit files and the suite files, and checks
records, decision trails, chain of custody (cross-checked with
`haltsql audit verify`), overview, signals (the cross-tenant burst must fire a
high signal), cases, agents, fleet, policies, shadow report, playground, data
classification, evidence packs, the activity log and role permissions.

The scratch database gets `lab/console/schema.sql` (the `app.orders` table and
rows the integration packages' fixtures create). A harness error (an adapter
hanging past 300 s, a process that never becomes ready) is reported as a failed
check, and the failure summary is always printed.

`--keep` leaves everything running afterwards so you can explore the console
API by hand. Exit status is non-zero if any check fails.

The harness's own logic (outcome classification, DSN handling, readiness
polling, check predicates) has unit tests that need neither Postgres nor the
binaries: `make -C lab test` runs `lab/console/test_console_e2e_unit.py`.
