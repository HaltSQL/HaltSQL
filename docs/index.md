# HaltSQL documentation

HaltSQL is a policy firewall for LLM-generated PostgreSQL. It checks whether an
exact SQL string is allowed for a caller under a declarative policy, and returns
a verdict with machine-readable reasons. It never rewrites SQL and never
connects to the database.

These docs describe version **0.1.0** (pre-1.0).

## Start here

- [Quickstart](quickstart.md): from zero to your first denied query in five minutes.
- [CLI reference](cli.md): every `haltsql` command, flag, and exit code.
- [HTTP API](http-api.md): the `haltsql-server` sidecar ([OpenAPI 3.1](openapi.yaml)).

## Client SDKs and agent integrations

- [Python SDK](sdk-python.md): sync/async clients, guarded execution for
  psycopg 3, asyncpg and SQLAlchemy, a local CLI verifier, and LangChain,
  LlamaIndex and Vanna integrations (`integrations/`).
- [TypeScript SDK](sdk-typescript.md): `@haltsql/client` with `guardedQuery` for node-postgres.
- [Go SDK](sdk-go.md): standard-library client with `GuardedQuery` for `database/sql`.
- [Java SDK](sdk-java.md): `com.haltsql:haltsql-client` with `JdbcGuard` for PgJDBC.
- [MCP server](mcp.md): `haltsql-mcp`, a verified read-only Postgres tool for MCP clients.
- [Integrations overview](integrations.md): the rules every client follows.

## Reference

- [Policy reference](policy-reference.md): every key in a `kind: Policy` document.
- [Config reference](config-reference.md): the `kind: Config` document for the CLI and server.
- [Verdict format](verdict.md): the JSON returned for every check.
- [Reason codes](reason-codes.md): what each code means and how an agent should fix its query.

## Concepts

- [Tenancy semantics](tenancy.md): exactly what HaltSQL must prove before it
  allows a query on a tenant-scoped table.
- [Threat model](threat-model.md): what HaltSQL defends against, and what it does not.
- [Defense in depth](defense-in-depth.md): the database role, RLS, and timeout
  settings to use alongside HaltSQL.

## Operating HaltSQL

- [Deployment](deployment.md): Docker, Kubernetes sidecar, systemd, verifying releases.
- [Authentication and TLS](authentication.md): built-in TLS 1.2/1.3, mTLS
  identities, OIDC/JWT callers, and claim-derived tenant context.
- [Secrets](secrets.md): `${vault:...}`, `${aws-sm:...}` and `${gcp-sm:...}` config placeholders.
- [Audit sinks](audit-sinks.md): hash-chained audit records to files, S3 and GCS, with `on_error` semantics.
- [Observability](observability.md): Prometheus `/metrics` and OpenTelemetry (OTLP) traces and metrics.
- [Signed policy bundles](policy-bundles.md) and [policy CI](policy-ci.md):
  `haltsql bundle`, the GitHub Action, GitLab templates and pre-commit hooks.
- [haltsql-proxy](proxy.md): the PostgreSQL wire-protocol firewall.
- [RLS generation](rls-generation.md): `haltsql rls generate|check` for database-level defense in depth.
- [Schema and PII import](schema-and-pii.md): `haltsql schema pull|import` and `haltsql policy draft`.
- [Integrations](integrations.md): official SDKs, agent tool wrappers, MCP.
- [Testing](testing.md): policy tests in CI, the attack corpus, and the enterprise lab.

## Project

- [Architecture Decision Records](adr/)
  - [0001: Parse with libpg_query](adr/0001-parser-libpg-query.md)
  - [0002: Typed AST, fail closed](adr/0002-typed-ast-fail-closed.md)
  - [0003: Tenancy semantics](adr/0003-tenancy-semantics.md)
  - [0004: Verdict schema and reason codes](adr/0004-verdict-schema-and-reason-codes.md)
  - [0005: Apache-2.0 license](adr/0005-license-apache-2.md)
- [Contributing](../CONTRIBUTING.md) · [Security policy](../SECURITY.md) ·
  [Governance](../GOVERNANCE.md) · [Changelog](../CHANGELOG.md)

## Document kinds at a glance

Everything HaltSQL reads is YAML or JSON with `apiVersion: haltsql.dev/v1` and a
`kind`:

| Kind | Purpose | Reference |
|---|---|---|
| `Policy` | What SQL is allowed | [policy-reference.md](policy-reference.md) |
| `Config` | How the CLI and server run | [config-reference.md](config-reference.md) |
| `TestSuite` | Allow/deny test cases for a policy | [testing.md](testing.md#policy-test-suites) |
| `Catalog` | Schema snapshot (tables and column types) | [policy-reference.md](policy-reference.md#catalog) |
| `Scenario` | Enterprise lab scenario | [testing.md](testing.md#the-enterprise-lab-haltlab) |
| `ProxyConfig` | How `haltsql-proxy` runs | [proxy.md](proxy.md) |
| `PolicyBundle` | Signed set of policies (canonical JSON + `.sig`) | [policy-bundles.md](policy-bundles.md) |

`haltsql validate FILE...` checks any of them, and `haltsql schema export`
writes JSON Schemas for editor autocomplete.
