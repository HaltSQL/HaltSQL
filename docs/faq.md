# Frequently asked questions

Short answers to the questions people ask when they evaluate or adopt
HaltSQL. Each answer links to the page with the details. Terms are defined in
the [glossary](glossary.md).

## The basics

### What does HaltSQL do?

It answers one question for each SQL statement an LLM writes: is this exact
string allowed for this caller, under this policy? You give it the SQL, a
policy in YAML or JSON, and a context from the caller's authenticated session,
such as the tenant ID. It returns a [verdict](verdict.md): `allowed`, plus
[reason codes](reason-codes.md) and hints the agent can use to fix its query.
It parses with libpg_query, the real PostgreSQL parser. See the
[quickstart](quickstart.md).

### Does HaltSQL modify my SQL?

No. HaltSQL never rewrites, reformats or appends to SQL. If the verdict
allows a query, you run the exact string you checked. In bound tenancy mode
the verdict also tells you which values to bind to `$1`, `$2`, and so on, so
the tenant is added as a parameter, not by editing the text. The official
SDKs check that the verdict's `sql_sha256` matches the string they sent. See
[Verdict format](verdict.md) and [Guarded execution](sdk-python.md#guarded-execution).

### Does it need database credentials?

Verification does not. The library, the CLI's `verify` and `haltsql-server`
never connect to the database. Only these parts do:

- `haltsql schema pull` and `haltsql rls check`, which read the system
  catalogs in a read-only transaction.
- [`haltsql-proxy`](proxy.md), which forwards allowed statements to Postgres
  with its own service credentials.
- Your application, or tools such as [`haltsql-mcp`](mcp.md) and the
  [agent framework tools](agent-frameworks.md), which run allowed queries on
  a connection you provide.

### Does HaltSQL use an LLM, or detect prompt injection?

No to both. HaltSQL is deterministic: the same SQL, policy and context always
get the same decision. It judges the SQL, not the prompt that produced it, so
it does not depend on detecting the injection. See the
[threat model](threat-model.md#known-limitations-and-non-goals).

### Where does it run?

Four ways, all with the same verifier: as an OCaml library in your process; as
the `haltsql-server` HTTP sidecar next to your agent; as `haltsql-proxy` in
front of Postgres, for drivers you can't change; or from the CLI. Python can
also verify in-process with the bundled engine. See
[Deployment](deployment.md) and [Deployment modes](how-it-works/deployment-modes.md).

## Security model

### Can the model choose the tenant?

Not in bound mode, the recommended one. The model writes `tenant_id = $1`, and
HaltSQL returns the value to bind from the context your application supplies.
A tenant literal written by the model is denied with `E_TENANT_MISMATCH`. The
context comes from your session, a bearer token, an OIDC claim or an mTLS
identity, and is never a tool argument. See
[Tenancy](tenancy.md#bound-mode-and-literal-mode) and
[Authentication](authentication.md).

### How is HaltSQL different from row-level security?

Row-level security (RLS) filters rows inside the database. HaltSQL decides
before the query runs, and covers things RLS doesn't: which columns and
functions may be used, a single statement per call, a required `LIMIT`, join
and size budgets, and a reason the agent can act on instead of a silently
empty result. They are meant to be used together. `haltsql rls generate`
writes the RLS policies and column grants that mirror a HaltSQL policy. See
[Defense in depth](defense-in-depth.md) and [RLS generation](rls-generation.md).

### Do I still need a restricted database role and RLS?

Yes. HaltSQL is one of three layers. If HaltSQL had a bug, a policy were
misconfigured, or a code path skipped the check, the role and RLS would still
hold. See [Defense in depth](defense-in-depth.md).

### What happens if HaltSQL is down?

Nothing runs. Every official client fails closed: a timeout, a connection
error, an error response or a malformed verdict raises an error or returns a
refusal. It is never treated as allowed. `haltsql-server` also refuses requests
with `503` when it cannot write an audit record. Run one sidecar per agent pod
and probe `/readyz`. See [Python SDK](sdk-python.md#the-rules-it-enforces-for-you)
and [HTTP API](http-api.md).

### What SQL does it allow?

Only what the policy allows. Statement kinds, tables, columns, functions,
operators and casts are all allowlists. Syntax HaltSQL does not analyze is
denied (`E_UNSUPPORTED`), and so is anything that hits an internal error
(`E_INTERNAL`). Several statements in one string, data-modifying CTEs,
`SELECT ... INTO`, `FOR UPDATE` and `EXPLAIN ANALYZE` are always denied. See
[Policy reference](policy-reference.md) and [Reason codes](reason-codes.md).

### Does `SELECT *` work?

With a catalog, yes. When the policy has a `catalog:` snapshot, HaltSQL
expands `*` to the table's real columns and denies the query
(`E_COLUMN_DENIED`) if any of them is not allowed. Without a catalog, `*` is
allowed only on tables declared with `columns: "*"`, and denied everywhere
else. See [catalog](policy-reference.md#catalog).

### Does it support writes (INSERT, UPDATE, DELETE)?

In a limited way, and only when you enable them per table. `INSERT ...
VALUES` with an explicit column list, `UPDATE` of listed columns and
`DELETE` can be allowed. Tenant rules apply to every write, and a tenant
column can never be updated. `INSERT ... SELECT` and `ON CONFLICT` are not
supported. The MCP server and the agent framework tools run only `SELECT`.
See [writes](policy-reference.md#writes) and
[`examples/policies/writes.yaml`](../examples/policies/writes.yaml).

### How is `haltsql-mcp` different from the archived `server-postgres`?

`@modelcontextprotocol/server-postgres` was archived on 2025-05-28. It
passes the model's string straight to the database, and its read-only guard
can be escaped with `COMMIT; ...`. `haltsql-mcp` keeps the same `query(sql)`
tool and connection string. It also checks each query against your policy
first, then runs it read-only with a statement timeout and a row cap, with the
tenant fixed by configuration. See
[the safe drop-in replacement](mcp.md#side-by-side).

### Are queries logged, and can logs be trusted?

Every decision produces an audit record with the caller, policy version,
decision, reason codes, a SHA-256 of the SQL and its fingerprint. The SQL
text itself is not logged unless you set `audit.log_raw_sql: true`. Records
are hash-chained, so `haltsql audit verify` detects edited, deleted or
reordered records. See [Audit sinks](audit-sinks.md) and
[Verifying audit chains](audit-verify.md).

## Compatibility and performance

### Which PostgreSQL versions are supported?

HaltSQL parses with the PostgreSQL 17 grammar (`haltsql version` prints it).
The lab has run its full differential scenario, with zero escapes, on
PostgreSQL 17 and 18, Supabase Postgres, AlloyDB Omni, Citus and TimescaleDB.
The DDL from `haltsql rls generate` targets PostgreSQL 13 to 17. Older servers
are expected to work for the SQL HaltSQL allows, but that is checked in the
lab, not guaranteed. Managed services such as Aurora and Neon have not been
run yet. See [Database compatibility](compatibility.md#results).

### Does it work with MySQL, SQL Server or Redshift?

No. HaltSQL is PostgreSQL only, and other dialects are out of scope before
1.0. Amazon Redshift speaks the Postgres wire protocol but is not supported.
See [Amazon Redshift](compatibility.md#amazon-redshift).

### How fast is it?

On the benchmark machine, a full verdict takes about 50 to 250 µs for
realistic agent queries: 48 µs (p50) for a point lookup in the library, and
278 µs for a request to `haltsql-server`. The proxy adds about 246 µs to a
point select. That is well below a database round trip, and far below an LLM
call. See [Performance](performance.md#summary), and run the harness on your
own hardware before you plan capacity.

### Which languages and agent frameworks are supported?

There are SDKs for [Python](sdk-python.md), [TypeScript](sdk-typescript.md),
[Go](sdk-go.md) and [Java](sdk-java.md), and an [HTTP API](http-api.md) for
anything else. There are tools for the OpenAI Agents SDK, LangGraph, Google
ADK, Semantic Kernel and CrewAI ([Agent frameworks](agent-frameworks.md)),
integrations for LangChain, LlamaIndex and Vanna
([Integrations](integrations.md)), and an [MCP server](mcp.md).

### Can I use it without changing my application?

Yes, with [`haltsql-proxy`](proxy.md). Clients connect to the proxy as if it
were Postgres, and every statement is verified under the policy bound to the
client's identity before it is forwarded. The client cannot skip the check or
choose its tenant.

### How do I install it?

The CLI, `haltsql-server` and `haltsql-proxy` come as release binaries, as a
container image, or from source with opam. See
[Quickstart: Install](quickstart.md#1-install) and
[Deployment](deployment.md#docker). The SDKs and integrations are packages:
`pip install haltsql` (with a bundled engine on Linux and macOS arm64),
`npm install @haltsql/client`, `pip install haltsql-mcp`,
`pip install haltsql-langchain` and the other `haltsql-<framework>` packages,
and the Helm chart at `oci://ghcr.io/haltsql/charts/haltsql`. The Go module is
`github.com/HaltSQL/HaltSQL/clients/go/haltsql`; the Java SDK is built from
source for now ([sdk-java.md](sdk-java.md)).

## Policies in practice

### Do I have to write policies by hand?

No. `haltsql schema pull` snapshots your schema, `haltsql schema import` reads
PII labels from dbt, DataHub, Unity Catalog, Atlan or Collibra, and
`haltsql policy draft` writes a starter policy with sensitive-looking columns
left out. Review the draft before you use it. See
[Catalog snapshots, PII metadata and starter policies](schema-and-pii.md).

### How do I test a policy?

Write `kind: TestSuite` files with SQL that must be allowed or denied, and run
`haltsql test`. The GitHub Action, GitLab templates and pre-commit hooks run
the same checks in CI. See [Testing](testing.md#policy-test-suites),
[Policy CI](policy-ci.md) and the tutorial
[Roll out a policy safely](tutorials/roll-out-a-policy-safely.md).

### How do I roll out a new policy without breaking my agent?

Deploy it with `mode: shadow`. Queries are still allowed, and would-be
denials are recorded in the audit log. `haltsql report --suggest` summarizes
them and proposes conservative changes. It never relaxes tenant isolation.
Switch to `mode: enforce` when the results look right. See
[Shadow reports](shadow-reports.md).

### How do policy changes reach production?

`haltsql-server` reloads policies on file change or `SIGHUP`, atomically,
and keeps the last good set if a reload fails. For production, build a signed
bundle in CI. Servers verify its Ed25519 signature before they load it, and can
poll an OCI registry, S3 or HTTPS for new versions. See
[Signed policy bundles](policy-bundles.md).

### Can it handle composite or hierarchical tenants?

Yes. A table can have several tenant columns (for example `org_id` and
`workspace_id`), and a context value can be a set of tenants, such as a parent
organization and its children. See [Composite keys](tenancy.md#composite-keys)
and [Sets of tenant values](tenancy.md#sets-of-tenant-values).

### Can I add organization-wide rules on top?

Yes. `haltsql-server` can ask Open Policy Agent for a second decision after
HaltSQL allows a query. OPA can only deny further, never allow what HaltSQL
denied. See [Open Policy Agent](opa.md).

## Project

### Is HaltSQL production ready? What does pre-1.0 mean?

HaltSQL is 0.0.3, a pre-1.0 preview. The verdict format within
`haltsql.dev/v1` and the reason codes are stable: reason codes are never
renamed or reused. Other interfaces, including the policy schema and the HTTP
API, may still change before 1.0. Before 1.0, a minor release may contain
breaking changes, and the [changelog](../CHANGELOG.md) calls them out. Pin
versions, and review the [threat model](threat-model.md) and
[testing](testing.md) to judge it for your use. See also
[Stability guarantees](verdict.md#stability-guarantees).

### What is the license?

MIT. See [LICENSE](../LICENSE) and [ADR-0006](adr/0006-license-mit.md). The
vendored libpg_query parser has its own license, listed in [NOTICE](../NOTICE).

### How do I report a vulnerability or a policy bypass?

Privately, through GitHub Security Advisories. Do not open a public issue.
See [SECURITY.md](../SECURITY.md).
