# HaltSQL

[![CI](https://github.com/ardada2468/HaltSQL/actions/workflows/ci.yml/badge.svg)](https://github.com/ardada2468/HaltSQL/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status: pre-1.0](https://img.shields.io/badge/status-0.1.0%20preview-orange.svg)

**A policy firewall for LLM-generated PostgreSQL.**

HaltSQL answers one question per statement:

> Is this exact SQL string allowed for this caller, under this policy?

You give it a SQL string, a policy (YAML or JSON), and a context taken from the
caller's authenticated session (tenant ID, user ID). It returns
`allowed: true|false` plus machine-readable reasons an agent can use to fix its
query. It parses with [libpg_query](https://github.com/pganalyze/libpg_query),
the real PostgreSQL parser, so there is no regex guessing and no grammar drift.

HaltSQL never rewrites SQL and never connects to your database. If the answer is
yes, you run the exact string you checked.

It ships as:

- an **OCaml library** (`haltsql`),
- a **CLI** (`haltsql`) for scripts, CI, and debugging, and
- an **HTTP sidecar** (`haltsql-server`) for agents written in any language.

## Why

An LLM that writes SQL is an untrusted client that is authenticated as your
service. Prompt injection can steer it to read another tenant's rows, read
sensitive columns, call functions with side effects, or smuggle a second
statement. HaltSQL rejects anything the policy does not explicitly allow, and
anything it does not fully understand. See the [threat model](docs/threat-model.md).

## 30-second example

`policy.yaml`:

```yaml
apiVersion: haltsql.dev/v1
kind: Policy
metadata: { name: analytics-agent, owner: data-platform }
search_path: [app]
statements: { allow: [select] }
require_limit: { max: 1000 }
tenancy:
  mode: bound                 # the model writes $1; you bind the tenant ID
  keys: { tenant: "${ctx.tenant_id}" }
tables:
  app.orders:
    columns: [id, tenant_id, customer_id, status, total_cents, created_at]
    tenant_column: tenant_id
  app.customers:
    columns: [id, tenant_id, name, created_at]   # email and phone are not readable
    tenant_column: tenant_id
functions:
  presets: [aggregates]
  allow: [date_trunc, lower]
```

A query the model produced, with no tenant filter on `customers` and a column
that is not allowed:

```console
$ haltsql verify --policy policy.yaml --context '{"tenant_id":"acme"}' --json \
    --sql "SELECT o.id, c.email FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.tenant_id = \$1 LIMIT 50"
```

```json
{
  "allowed": false,
  "reasons": [
    {
      "code": "E_COLUMN_DENIED",
      "message": "column app.customers.email is not allowed by policy analytics-agent",
      "rule": "columns.allowlist",
      "loc": 15,
      "hint": "Remove app.customers.email; allowed columns are id, tenant_id, name, created_at."
    },
    {
      "code": "E_TENANT_MISSING",
      "message": "app.customers (alias c) has no tenant predicate in its scope",
      "rule": "tenancy.predicate",
      "loc": 43,
      "hint": "Add c.tenant_id = $1 to the WHERE clause or the JOIN ... ON clause."
    }
  ],
  "shadow_reasons": [],
  "policy": { "name": "analytics-agent", "version": "sha256:4f1c..." },
  "statement_kind": "select",
  "tables": ["app.customers", "app.orders"],
  "columns": ["app.customers.email", "app.customers.id", "app.orders.customer_id", "app.orders.id", "app.orders.tenant_id"],
  "bind_params": [],
  "fingerprint": "a0b1c2d3e4f5a6b7",
  "sql_sha256": "9e2d...",
  "elapsed_us": 212
}
```

The exit code is `1` (denied). Messages, hints, and offsets above are
illustrative; the codes and the JSON shape are the stable contract (see
[verdict.md](docs/verdict.md) and [reason-codes.md](docs/reason-codes.md)).

When the query passes, `bind_params` tells you what to bind:
`[{"param": 1, "value": "acme"}]`. The model never sees the tenant ID.

## Features

- **Deny by default.** Statement kinds, tables, columns, functions, operators,
  and casts are allowlists. Unknown syntax is denied (`E_UNSUPPORTED`), and
  internal errors are denied (`E_INTERNAL`). `verify` never raises.
- **Tenant isolation as a first-class rule.** Every occurrence of a
  tenant-scoped table, in every CTE, subquery, `UNION` branch, `LATERAL`, and
  `EXISTS`, must carry its own tenant predicate. Bound (`$n`) and literal modes,
  composite keys, and sets of allowed tenants. See [tenancy.md](docs/tenancy.md).
- **Real name resolution.** Case folding, quoted identifiers, `U&""` escapes,
  aliases, CTE shadowing, `search_path`, and `*` expansion against a catalog.
- **Statement smuggling defenses.** Exactly one statement; data-modifying CTEs,
  `SELECT ... INTO`, `FOR UPDATE`, and `EXPLAIN ANALYZE` are rejected.
- **Resource limits.** Byte, depth, node, and join budgets; required `LIMIT`.
- **Stable, versioned contract.** Verdict JSON, reason codes, policy
  `apiVersion`, and HTTP `/v1`.
- **YAML or JSON, one meaning.** Same schema, same `policy_version` hash.
  Unknown keys and duplicate keys are errors, so a typo cannot loosen a policy.
- **Shadow mode** for rolling out a new policy without enforcing it.
- **Policy tests in CI** with `kind: TestSuite` and `haltsql test`.

## Status

HaltSQL is **0.1.0, a pre-1.0 preview**. Limits to know about:

- PostgreSQL only. HaltSQL vendors libpg_query 17 (the Postgres 17 grammar);
  `haltsql version` prints the exact version.
- Read-only (`SELECT`) workloads are the main target. Write support is limited
  and must be enabled explicitly per table.
- The policy schema and HTTP API may still change before 1.0. Reason codes are
  never renamed or reused.
- No third-party security audit has happened yet. One is planned before 1.0.
- Performance targets (p99 under 1 ms in-process, under 3 ms over the sidecar
  for queries under 8 KB) are goals, not measured guarantees.

## Install

**From source with opam** (OCaml 5.1 or newer):

```sh
opam pin add haltsql https://github.com/ardada2468/HaltSQL.git
opam pin add haltsql-server https://github.com/ardada2468/HaltSQL.git   # optional sidecar
```

**Docker:**

```sh
docker run --rm -p 127.0.0.1:8080:8080 -v "$PWD:/etc/haltsql:ro" \
  ghcr.io/ardada2468/haltsql:0.1.0 --policy /etc/haltsql/policy.yaml --listen 0.0.0.0:8080 \
  --allow-unauthenticated   # local development only; use a config with tokens otherwise
```

**Release binaries:** static Linux (amd64, arm64) and macOS (arm64) binaries
are attached to each [GitHub release](https://github.com/ardada2468/HaltSQL/releases),
with `SHA256SUMS`, a CycloneDX SBOM, and cosign signatures. See
[deployment.md](docs/deployment.md#verifying-release-artifacts).

## Documentation

| Topic | |
|---|---|
| Get started | [Quickstart](docs/quickstart.md) · [CLI](docs/cli.md) · [HTTP API](docs/http-api.md) |
| Reference | [Policy](docs/policy-reference.md) · [Config](docs/config-reference.md) · [Verdict](docs/verdict.md) · [Reason codes](docs/reason-codes.md) |
| Concepts | [Tenancy semantics](docs/tenancy.md) · [Threat model](docs/threat-model.md) · [Defense in depth](docs/defense-in-depth.md) |
| Operate | [Deployment](docs/deployment.md) · [Integrations](docs/integrations.md) · [Testing](docs/testing.md) |
| Project | [ADRs](docs/adr/) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Governance](GOVERNANCE.md) |

## HaltSQL is one layer of defense in depth

HaltSQL is not a replacement for database permissions or row-level security.
Run agent queries as a read-only role with column-level `GRANT`s, enforce tenant
isolation with Postgres RLS, and set `statement_timeout`. HaltSQL then blocks
bad queries before they reach the database, gives the agent a reason it can act
on, and leaves an audit trail. See [defense-in-depth.md](docs/defense-in-depth.md).

## Security

Please do not report vulnerabilities or policy bypasses in public issues. See
[SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The policy
design is inspired by the MIT-licensed sql-guardrail project.
