# Glossary

HaltSQL terms in alphabetical order. Each entry links to the page that
describes it in full. For questions rather than definitions, see the
[FAQ](faq.md).

**Admin API.** Optional `haltsql-server` endpoints, `GET /v1/admin/report`
and `GET /v1/admin/status`, for the live shadow report and the server's
status. Off by default, and only callers listed in `server.admin.callers` may
use them. See [server.admin](config-reference.md#serveradmin).

**Allowlist.** Every rule in a policy names what is allowed: statement kinds,
tables, columns, functions, operators and casts. Anything not listed is
denied. This is also called deny by default. See
[Policy reference](policy-reference.md).

**Audit chain.** The hash chain that links audit records. Each record's
`hash` is computed over its content and the previous record's hash
(`prev_hash`), starting from 64 zeros. Editing, deleting, inserting or
reordering a record breaks the chain, which `haltsql audit verify` detects.
Each sink keeps its own chain. See [Verifying audit chains](audit-verify.md).

**Audit record.** One JSON line per verification, written by
`haltsql-server` or `haltsql-proxy`. It holds the caller, policy name and
version, decision, reason codes, `sql_sha256`, fingerprint and timing. It
includes the SQL text only with `log_raw_sql: true`. See
[Audit sinks](audit-sinks.md).

**Audit sink.** Where audit records go: `stdout`, a file, S3, GCS,
Elasticsearch or OpenSearch, or Kafka. With the default `on_error:
fail_closed`, a sink that cannot be written makes the server refuse requests.
See [Audit sinks](audit-sinks.md).

**Bind parameters (`bind_params`).** In bound tenancy mode, the list of
`{param, value}` pairs in an allowed verdict: the values your code must bind
to `$1`, `$2`, ... when it runs the query. Always empty when the query is
denied. See [Verdict format](verdict.md#fields).

**Bound tenancy (bound mode).** The recommended tenancy mode. The model writes
a placeholder (`tenant_id = $1`), and HaltSQL returns the tenant value to bind
from the context. The model never sees or chooses the tenant, and a tenant
literal is denied. See [Bound mode](tenancy.md#bound-mode-recommended).

**Bundle.** See *Policy bundle*.

**Bundle source.** A config entry that makes `haltsql-server` fetch a signed
policy bundle from an OCI registry, S3 or an HTTPS URL, and poll for newer
versions. The signature is checked before anything is parsed, and older
versions are refused (rollback protection). See
[Bundle sources](policy-bundles.md#bundle-sources).

**Caller.** The authenticated identity that sends a verify request to
`haltsql-server`: a static token's name, an OIDC provider and subject, or an
mTLS identity. Every caller is pinned to one policy. See
[Authentication](authentication.md).

**Catalog (catalog snapshot).** A `kind: Catalog` document with the complete,
typed column list of each table, usually made by `haltsql schema pull`. A
policy that references one can expand `SELECT *`, resolve columns precisely
and type-check tenant literals. See [catalog](policy-reference.md#catalog)
and [Catalog snapshots](schema-and-pii.md).

**Composite tenant key.** A table scoped by more than one tenancy key, for
example `org_id` and `workspace_id`. Each tenant column needs its own
predicate. See [Composite keys](tenancy.md#composite-keys).

**Config.** A `kind: Config` document that controls how `haltsql-server` and
the CLI run: listener, TLS, authentication, which policies to load, audit,
telemetry and secrets. It never changes what SQL is allowed. See
[Config reference](config-reference.md).

**Context.** The facts about the caller that a policy may use, such as
`tenant_id` or `user_id`, sent with each verification. It must come from the
caller's authenticated session, a token or an identity, never from the model.
See [Tenancy](tenancy.md#terms) and [HTTP API](http-api.md#authentication).

**Defense in depth.** Using HaltSQL together with a restricted database role
and row-level security, so that each layer covers the others' failures. See
[Defense in depth](defense-in-depth.md).

**Enforce mode.** The default policy mode. A query that breaks a rule gets
`allowed: false`, with the reasons in `reasons`. Compare *Shadow mode*. See
[mode](policy-reference.md#mode).

**External policy.** An optional second decision from Open Policy Agent,
asked by `haltsql-server` after HaltSQL allows a query. It can only deny
further (`E_EXTERNAL_POLICY`). See [Open Policy Agent](opa.md).

**Fail closed.** Any failure ends in "not allowed", never "allowed".
Unsupported syntax and internal errors are denials. A client that cannot get a
valid verdict does not run the query. A server that cannot write its audit
record refuses the request. See [Python SDK](sdk-python.md#the-rules-it-enforces-for-you)
and [Reason codes](reason-codes.md#fail-closed-codes).

**Fingerprint.** The libpg_query fingerprint of a statement. It is the same
for queries that differ only in literal values, which makes it useful for
grouping in logs, reports and dashboards. See [Verdict format](verdict.md#fields).

**Global table.** A table in a policy with no `tenant_column` or
`tenant_columns`, such as a reference table of currencies. It needs no tenant
predicate. See [Tenancy](tenancy.md#terms).

**Guarded execution.** Running a model's query only through a helper that
verifies it, checks that the verdict is for exactly that string, and then runs
it unchanged with the bound parameters, in a `READ ONLY` transaction with a
`statement_timeout`, transaction-local settings and a row cap. Provided by
`haltsql.guard` in the Python SDK and used by `haltsql-mcp` and the agent
framework tools. See [Guarded execution](sdk-python.md#guarded-execution).

**haltlab.** The project's enterprise lab. It builds a realistic database,
runs generated and adversarial queries through HaltSQL, and executes every
allowed query under database oracles to check that nothing escaped. See
[Testing](testing.md#the-enterprise-lab-haltlab).

**haltsql-mcp.** An MCP server, and a drop-in replacement for the archived
`@modelcontextprotocol/server-postgres`. It verifies each query with HaltSQL
before running it read-only. See [haltsql-mcp](mcp.md).

**Hint.** A sentence in a reason that tells the agent how to fix its
query, for example which columns it may read. Its text may change between
releases; the reason code does not. See [Verdict format](verdict.md#reason).

**Lint (`haltsql lint-policy`).** Checks a policy that loads for risky or
suspicious settings, such as `columns: "*"` (`W_BROAD_COLUMNS`). Policy CI can
fail on lint warnings. See [CLI reference](cli.md#haltsql-lint-policy).

**Literal tenancy (literal mode).** A tenancy mode where the model writes the
tenant value as a literal, which must equal the context value exactly. It
means the model must know the tenant ID, so prefer bound mode. See
[Literal mode](tenancy.md#literal-mode).

**Local mode.** Verifying without a sidecar: `haltsql-mcp --local-policy`
and the Python SDK's `LocalVerifier` run the `haltsql` CLI with a policy file.
See [Local mode](sdk-python.md#local-mode-no-sidecar).

**Occurrence.** Each place a table appears in a `FROM` clause or join tree.
Every occurrence of a tenant-scoped table needs its own tenant predicate. See
[Tenancy](tenancy.md#terms).

**PII manifest.** The output of `haltsql schema import`: columns labeled as
personal or sensitive by a data catalog such as dbt, DataHub, Unity Catalog,
Atlan or Collibra. `haltsql policy draft` leaves those columns out, and
`haltsql report` never suggests adding them. See
[Catalog snapshots, PII metadata and starter policies](schema-and-pii.md).

**Policy.** A `kind: Policy` document in YAML or JSON that declares what SQL
one caller may run: statement kinds, tables and columns, tenancy, functions,
limits and mode. Unknown or duplicate keys are errors, so a typo cannot loosen
a policy. See [Policy reference](policy-reference.md).

**Policy bundle.** A single canonical JSON file (`.haltsqlbundle`) holding
validated policies and, optionally, catalogs, with an Ed25519 signature in a
`.sig` file. Servers verify the signature before they load it. See
[Signed policy bundles](policy-bundles.md).

**Policy draft.** A starter policy written by `haltsql policy draft` from a
catalog snapshot and, optionally, a PII manifest. It uses bound tenancy,
allows `select` only, requires a `LIMIT` and leaves out sensitive-looking
columns. Review it before use. See [haltsql policy draft](schema-and-pii.md).

**Policy version.** The `sha256:` hash of a normalized policy, reported in
every verdict and audit record as `policy.version` or `policy_version`. The
YAML and JSON forms of a policy have the same version. See
[Verdict format](verdict.md#fields).

**Proxy (`haltsql-proxy`).** A PostgreSQL wire-protocol firewall. Clients
connect to it as if it were Postgres, and it verifies every statement under
the policy and context bound to the client's identity before it forwards the
statement. Clients cannot skip the check. See [haltsql-proxy](proxy.md).

**Reason.** One entry in a verdict's `reasons` or `shadow_reasons`, with a
`code`, a `message`, the `rule`, a `hint` and usually a `loc` (byte offset in
the SQL). See [Verdict format](verdict.md#reason).

**Reason code.** The stable, machine-readable identifier of why a query was
denied, such as `E_TENANT_MISSING` or `E_COLUMN_DENIED`. Codes are never
renamed or reused. See [Reason codes](reason-codes.md).

**RLS generation.** `haltsql rls generate` turns a policy into PostgreSQL DDL:
a role, column-level grants and row-level security policies keyed on
transaction-local settings. `haltsql rls check` reports drift. See
[RLS generation](rls-generation.md).

**Rollback protection.** A server polling a bundle source accepts a new bundle
only if its `metadata.version` is strictly greater than the current one. To
roll back, publish the old policies under a higher version. See
[What the poller does](policy-bundles.md#what-the-poller-does).

**Row cap.** The maximum number of rows guarded execution returns
(`max_rows`, or `--row-cap` in `haltsql-mcp`). It limits what is returned,
not what the database computes, so keep `require_limit` in the policy. See
[Guarded execution](sdk-python.md#guarded-execution).

**Scope.** One query level: a `SELECT ... FROM ... WHERE ...`. Every CTE body,
subquery and `UNION` branch is its own scope, and a tenant predicate only
covers occurrences in its own scope. See [Tenancy](tenancy.md#terms).

**`search_path`.** The schemas a policy uses to resolve unqualified table
names. Give the database role the same `search_path`, so that Postgres
resolves names the same way HaltSQL checked them. See
[search_path](policy-reference.md#search_path).

**Session preamble.** What the application runs in the same transaction as an
allowed query when RLS is in use: `set_config('haltsql.tenant_id', $1, true)`
with the same context value it sent to HaltSQL. See
[The session preamble](rls-generation.md#the-session-preamble-application-side).

**Shadow mode.** A policy mode where every query is allowed, and what would
have been denied is reported in `shadow_reasons` and the audit log. Use it to
roll out a new or stricter policy. A shadow policy enforces nothing. See
[mode](policy-reference.md#mode).

**Shadow report.** The output of `haltsql report` (or `GET /v1/admin/report`):
a summary of would-be denials from the audit log, and with `--suggest`,
conservative policy changes that never relax tenant isolation. See
[Shadow reports](shadow-reports.md).

**Sidecar (`haltsql-server`).** The HTTP server that exposes verification as
`POST /v1/verify`, usually run next to the agent on `127.0.0.1`. It
authenticates callers, pins each to a policy, writes audit records and
hot-reloads policies. It never connects to the database. See
[HTTP API](http-api.md) and [Deployment](deployment.md).

**Signing key.** The Ed25519 private key that signs policy bundles, made with
`haltsql bundle keygen`. Only the public key is distributed to servers, in
`public_keys`. Its key id is the `sha256:` of the raw public key. See
[Key management and rotation](policy-bundles.md#key-management-and-rotation).

**SQL hash (`sql_sha256`).** The SHA-256 of the exact SQL string, in every
verdict and audit record. Clients check it to make sure a verdict is for the
string they will run, and audit logs use it to refer to a query without
storing it. See [Verdict format](verdict.md#fields).

**Statement kind.** What a statement is: `select`, `insert`, `update` or
`delete`. A policy's `statements.allow` lists the allowed kinds; anything else
is `E_STATEMENT_KIND`. See [statements](policy-reference.md#statements).

**Tenancy key.** A named dimension of tenancy in `tenancy.keys`, mapped to a
context field, for example `tenant: ${ctx.tenant_id}`. See
[Tenancy](tenancy.md#terms).

**Tenant predicate.** A condition that filters a tenant-scoped table to the
caller's tenant, such as `o.tenant_id = $1` in bound mode. It counts only as a
top-level `AND` term of the `WHERE` or `ON` clause in the same scope. Under
`OR`, `NOT` or in `HAVING` it proves nothing. See [The rule](tenancy.md#the-rule).

**Tenant value.** The context value for a tenancy key: one value (`"acme"`)
or a set of values (`["acme", "acme-eu"]`) for hierarchical tenants. See
[Sets of tenant values](tenancy.md#sets-of-tenant-values).

**Tenant-scoped table.** A table with `tenant_column` or `tenant_columns` in
the policy. Every occurrence needs a tenant predicate, or the query is denied
with `E_TENANT_MISSING`. See [Tenancy](tenancy.md#terms).

**Test suite (`kind: TestSuite`).** A file of SQL cases that a policy must
allow or deny, with the expected reason codes or bind parameters, run with
`haltsql test`. See [Policy test suites](testing.md#policy-test-suites).

**Token pinning.** Every caller of `haltsql-server` is pinned to exactly one
policy, so a compromised agent cannot pick a looser one. A static token or an
mTLS identity names its policy. An OIDC token gets it from its provider, or
from a claim limited to the provider's `allowed_policies`. See
[HTTP API](http-api.md#authentication).

**Verdict.** The JSON result of one verification: `allowed`, `reasons`,
`shadow_reasons`, the policy name and version, statement kind, tables and
columns touched, `bind_params`, fingerprint and `sql_sha256`. A denial is a
normal verdict, not an error. See [Verdict format](verdict.md).

**Verifier.** Anything that turns SQL and a context into a verdict: the
library, the CLI, `haltsql-server` (through an SDK client), `LocalVerifier`
or the Python SDK's in-process `NativeVerifier`. They all run the same
analyzer. See [Python SDK](sdk-python.md).
