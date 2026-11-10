# HaltSQL

[![CI](https://github.com/HaltSQL/HaltSQL/actions/workflows/ci.yml/badge.svg)](https://github.com/HaltSQL/HaltSQL/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Status: pre-1.0](https://img.shields.io/badge/status-0.0.3%20preview-orange.svg)

**A policy firewall for LLM-generated PostgreSQL.**

> **Connecting Claude Desktop, Cursor or an agent to Postgres with
> `@modelcontextprotocol/server-postgres`?** Use
> [`haltsql-mcp`](docs/mcp.md), the safe drop-in replacement. It has the same
> `query(sql)` tool and takes the same connection string, and it adds
> column allowlists, tenant isolation, function allowlists, row caps and
> statement timeouts. It runs from one Docker image with no central server
needed, or calls `haltsql-server` when you want one.
[Switch in five minutes →](docs/mcp.md)

HaltSQL answers one question per statement:

> Is this exact SQL string allowed for this caller, under this policy?

You give it a SQL string, a policy (YAML or JSON), and a context taken from the
caller's authenticated session (tenant ID, user ID). It returns
`allowed: true|false` plus machine-readable reasons an agent can use to fix its
query. It parses with [libpg_query](https://github.com/pganalyze/libpg_query),
the real PostgreSQL parser, so there is no regex guessing and no grammar drift.

HaltSQL never rewrites SQL. The verifier never connects to your database. The optional
proxy and MCP server do, to run queries that passed, and `haltsql schema pull`
reads your schema when you run it. If the answer is yes, you run the exact string you
checked.

## Where HaltSQL sits

Call it in-process (library) or over HTTP (sidecar) before you run the
model's SQL, or put the wire proxy in front of Postgres so unmodified drivers
cannot skip the check. See [deployment modes](docs/how-it-works/deployment-modes.md).

```mermaid
flowchart LR
    AG["LLM agent"] -- "SQL string" --> APP["your application<br/>(adds context from the session)"]
    subgraph H["HaltSQL verify"]
        LIB["library<br/>Haltsql.verify, in-process"]
        SC["sidecar<br/>haltsql-server, POST /v1/verify"]
    end
    APP -- "OCaml call" --> LIB
    APP -- "HTTP" --> SC
    H -- "verdict + reasons" --> APP
    APP -- "allowed: the exact string,<br/>binding bind_params" --> PG[("PostgreSQL")]
    APP -. "denied: reasons the agent can act on" .-> AG
    DRV["unmodified driver<br/>(psql, JDBC, pgx, ...)"] -- "PG wire protocol" --> PX["proxy<br/>haltsql-proxy verifies every statement"]
    PX -- "allowed statements only" --> PG
```

## What ships

HaltSQL ships as:

- an **OCaml library** (`haltsql`),
- a **CLI** (`haltsql`) for scripts, CI, and debugging, plus RLS generation,
  catalog and PII import, policy drafting and signed policy bundles,
- an **HTTP sidecar** (`haltsql-server`) for agents written in any language,
  with built-in TLS/mTLS, OIDC (including [policies from IdP
  groups](docs/authentication.md#policies-from-idp-groups)), secret providers,
  OpenTelemetry, an optional deny-only [Open Policy Agent](docs/opa.md) check,
  and an admin API for live [shadow reports](docs/shadow-reports.md)
  ([authentication](docs/authentication.md)),
- **hash-chained audit** to files, S3, GCS, Kafka and
  Elasticsearch/OpenSearch ([audit sinks](docs/audit-sinks.md)), checked with
  `haltsql audit verify` ([audit-verify.md](docs/audit-verify.md)),
- a **PostgreSQL wire-protocol proxy** (`haltsql-proxy`) that verifies every
  statement an unmodified driver sends, with its own chained audit and hot
  reload ([proxy.md](docs/proxy.md)),
- **signed policy bundles** that the server can pull from an OCI registry,
  S3 or HTTPS and hot-reload ([policy-bundles.md](docs/policy-bundles.md)),
- **client SDKs** for [Python](docs/sdk-python.md),
  [TypeScript](docs/sdk-typescript.md), [Go](docs/sdk-go.md) and
  [Java](docs/sdk-java.md), an [MCP server](docs/mcp.md) that replaces
  `@modelcontextprotocol/server-postgres`, LangChain,
  LlamaIndex and Vanna integrations, and tools for the OpenAI Agents SDK,
  LangGraph, Semantic Kernel, CrewAI and Google ADK
  ([agent frameworks](docs/agent-frameworks.md)),
- deployment tooling: static musl binaries and a distroless image, a
  [Kubernetes operator](docs/kubernetes-operator.md) and
  [Terraform modules](docs/terraform.md) for Kubernetes, AWS, Azure and GCP
  (the cloud modules are statically checked only, not yet applied), and
- a **GitHub Action**, GitLab CI templates and pre-commit hooks for
  [policy CI](docs/policy-ci.md).

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
- **Shadow mode** for rolling out a new policy without enforcing it, with
  [reports](docs/shadow-reports.md) of what would have been denied and
  conservative policy suggestions (`haltsql report --suggest`).
- **Policy tests in CI** with `kind: TestSuite` and `haltsql test`.

## Status

HaltSQL is **0.0.3, a pre-1.0 preview**. Limits to know about:

- PostgreSQL only. HaltSQL vendors libpg_query 17 (the Postgres 17 grammar);
  `haltsql version` prints the exact version.
- Read-only (`SELECT`) workloads are the main target. Write support is limited
  and must be enabled explicitly per table.
- The policy schema and HTTP API may still change before 1.0. Reason codes are
  never renamed or reused.
- No third-party security audit has happened yet. One is planned before 1.0.
- Performance targets (p99 under 1 ms in-process, under 3 ms over the sidecar
  for queries under 8 KB) are goals, not guarantees. One measured run (p50 of
  50–250 µs per verify in process) is in [performance.md](docs/performance.md).
- Tested on PostgreSQL 17 and 18 and several Postgres-compatible engines in
  containers; managed services have not been run yet
  ([compatibility.md](docs/compatibility.md)).

## Install

Every release is signed and attested; see
[verifying a release](docs/security/supply-chain.md#verifying-a-release).

**CLI, server and proxy:** static Linux (amd64, arm64) and macOS (arm64)
binaries on each [GitHub release](https://github.com/HaltSQL/HaltSQL/releases):

```sh
curl -LO https://github.com/HaltSQL/HaltSQL/releases/download/v0.0.3/haltsql-v0.0.3-linux-amd64.tar.gz
tar -xzf haltsql-v0.0.3-linux-amd64.tar.gz && export PATH="$PWD/haltsql-v0.0.3-linux-amd64:$PATH"
```

**Container image** (`linux/amd64`, `linux/arm64`):

```sh
docker run --rm -p 127.0.0.1:8080:8080 -v "$PWD:/etc/haltsql:ro" \
  ghcr.io/haltsql/haltsql:0.0.3 --policy /etc/haltsql/policy.yaml --listen 0.0.0.0:8080 \
  --allow-unauthenticated   # local development only; use a config with tokens otherwise
```

**Kubernetes:**

```sh
helm install haltsql oci://ghcr.io/haltsql/charts/haltsql --version 0.0.3
```

**SDKs and agent integrations:**

| | |
|---|---|
| Python SDK (bundled engine on Linux x86_64/aarch64 and macOS arm64) | `pip install 'haltsql[psycopg]'` |
| TypeScript SDK (bundled engine via `@haltsql/native-*`) | `npm install @haltsql/client` |
| Go SDK | `go get github.com/HaltSQL/HaltSQL/clients/go/haltsql@v0.0.3` |
| MCP server | `pip install 'haltsql-mcp[yaml]'` or `ghcr.io/haltsql/haltsql-mcp:0.0.3` |
| LangChain, LangGraph, LlamaIndex, OpenAI Agents, Google ADK, CrewAI, Semantic Kernel, Vanna | `pip install haltsql-langchain` (and `haltsql-langgraph`, `haltsql-llamaindex`, `haltsql-openai-agents`, `haltsql-google-adk`, `haltsql-crewai`, `haltsql-semantic-kernel`, `haltsql-vanna`) |

The Java SDK is built from source for now ([sdk-java.md](docs/sdk-java.md)).

**From source with opam** (OCaml 5.1 or newer):

```sh
opam pin add haltsql https://github.com/HaltSQL/HaltSQL.git
opam pin add haltsql-server https://github.com/HaltSQL/HaltSQL.git   # optional sidecar
opam pin add haltsql-proxy https://github.com/HaltSQL/HaltSQL.git    # optional wire proxy
```

## Documentation

| Topic | |
|---|---|
| Get started | [Quickstart](docs/quickstart.md) · [CLI](docs/cli.md) · [HTTP API](docs/http-api.md) |
| Reference | [Policy](docs/policy-reference.md) · [Config](docs/config-reference.md) · [Verdict](docs/verdict.md) · [Reason codes](docs/reason-codes.md) |
| How it works | [Architecture](docs/how-it-works/architecture.md) · [Verification pipeline](docs/how-it-works/verification-pipeline.md) · [Deployment modes](docs/how-it-works/deployment-modes.md) · [All explainers](docs/index.md#how-it-works) |
| Concepts | [Tenancy semantics](docs/tenancy.md) · [Threat model](docs/threat-model.md) · [Defense in depth](docs/defense-in-depth.md) |
| Operate | [Deployment](docs/deployment.md) · [Kubernetes operator](docs/kubernetes-operator.md) · [Terraform](docs/terraform.md) · [Authentication and TLS](docs/authentication.md) · [Secrets](docs/secrets.md) · [Audit sinks](docs/audit-sinks.md) · [Audit verify](docs/audit-verify.md) · [Observability](docs/observability.md) · [Performance](docs/performance.md) · [Compatibility](docs/compatibility.md) · [Testing](docs/testing.md) |
| Clients | [Integrations](docs/integrations.md) · [Python](docs/sdk-python.md) · [TypeScript](docs/sdk-typescript.md) · [Go](docs/sdk-go.md) · [Java](docs/sdk-java.md) · [MCP](docs/mcp.md) · [Agent frameworks](docs/agent-frameworks.md) |
| Policy lifecycle | [Schema and PII import](docs/schema-and-pii.md) · [Signed bundles](docs/policy-bundles.md) · [Policy CI](docs/policy-ci.md) · [Shadow reports](docs/shadow-reports.md) · [Open Policy Agent](docs/opa.md) · [RLS generation](docs/rls-generation.md) |
| Proxy | [haltsql-proxy](docs/proxy.md) |
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

MIT License. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The policy
design is inspired by the MIT-licensed sql-guardrail project.
