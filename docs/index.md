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
- [Integrations](integrations.md): Python, TypeScript, and Go clients; agent tool wrappers; MCP.
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

`haltsql validate FILE...` checks any of them, and `haltsql schema export`
writes JSON Schemas for editor autocomplete.
