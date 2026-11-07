# Changelog

All notable changes to HaltSQL are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, minor releases may contain breaking changes; they are called out
under **Changed** or **Removed**. Reason codes are never renamed or reused,
even before 1.0.

## [Unreleased]

### Added
- **haltsql-server: built-in TLS 1.2/1.3 and mTLS** (`server.tls`), with
  certificate hot reload, client-certificate identities (SPIFFE ID or CN) with
  static tenant context, and `--health-listen` for a plain probe port.
- **OIDC/JWT authentication** (`server.auth.oidc`): discovery, JWKS caching
  with stale-while-error, `required_claims`, `context_claims` and a policy
  taken from a claim. New errors `CONTEXT_NOT_ALLOWED` (403) and
  `AUTH_UNAVAILABLE` (503). Audit records gain `caller_type` and `subject`.
  New metrics are `haltsql_auth_total` and `haltsql_tls_reload_total`.
- **Secret providers**: `${vault:path#field}`, `${aws-sm:id[#key]}` and
  `${gcp-sm:name[#key]}` placeholders, configured by a new `secrets` section.
  They are resolved by `haltsql config show`, by `haltsql validate` and by the
  server, both at startup and asynchronously on reload. Error messages never
  contain secret values.
- **S3 and GCS audit sinks** with per-sink `on_error: fail_closed | buffer`.
  Records are batched into hash-chained objects. `/readyz` reports unhealthy
  sinks, and `/metrics` gains the `haltsql_audit_sink_*` series.
- **OpenTelemetry export** (`telemetry.otlp`): one `haltsql.verify` span per
  request that honours W3C `traceparent` and carries the SQL hash, never the
  SQL. The Prometheus metrics are mirrored over OTLP/HTTP JSON.
- **Signed policy bundles**: `haltsql bundle keygen|build|sign|verify|inspect`
  with Ed25519 signatures. The server loads `policies: [{bundle: ...}]` entries,
  verifies the signature before parsing, applies `name_prefix`, refuses
  duplicate names, and re-checks every token, `default_policy`, OIDC and mTLS
  policy reference. Hot reload re-verifies when the bundle or its `.sig` file
  changes.
- **Policy CI**: a GitHub Action (`action.yml`), GitLab CI templates
  (`ci/gitlab/`) and pre-commit hooks (`.pre-commit-hooks.yaml`).
- **haltsql-proxy**: a PostgreSQL v3 wire-protocol firewall (new
  `haltsql-proxy` package and binary). It authenticates clients with
  SCRAM-SHA-256 or client certificates, verifies every statement and rewrites
  tenancy `Bind` parameters from the session identity. It is included in the
  container image and the release archives.
- **`haltsql rls generate|check`**: generates role, grant and RLS DDL from a
  policy, and reports drift between a live database and the policy.
- **`haltsql schema pull|import` and `haltsql policy draft`**: read-only
  catalog snapshots from Postgres; PII labels from dbt, DataHub, Unity Catalog,
  Atlan and Collibra; and a reviewable starter policy.
- **Client SDKs**: Python (`clients/python`, with guarded execution for
  psycopg 3, asyncpg and SQLAlchemy), TypeScript (`clients/typescript`), Go
  (`clients/go`) and Java (`clients/java`). Also an MCP server
  (`clients/mcp`), LangChain, LlamaIndex and Vanna integrations
  (`integrations/`), and shared test vectors (`clients/testvectors`).
- CI jobs for the SDKs, the MCP server and integrations, the GitHub Action
  self-test, and the Postgres integration suites. The lab workflow now runs the
  proxy parity scenario.

### Changed
- `telemetry.otlp_endpoint` must now be an `http(s)` URL. It was previously
  unused, and now drives OTLP export.
- An unknown `--default-policy` value now fails server startup (exit 2)
  instead of failing at request time.
- Packaging: the server-only libraries are now `haltsql-server.auth` and
  `haltsql-server.telemetry`, and the proxy engine is `haltsql-proxy.pgwire`.
  The `haltsql` opam package now also depends on lwt, cohttp and tls,
  because the CLI links the cloud, bundle, RLS and catalog tools. The core
  libraries themselves have no network dependencies.

### Security
- Analyzer: a tenant placeholder used anywhere besides its tenant predicate is
  now denied (`E_PARAM_UNBOUND`, rule `params.tenant_reuse`). Before,
  `WHERE $1::float8 IS NOT NULL AND tenant_id = $1` was allowed. PostgreSQL
  then inferred `$1` as `double precision`, so a large `bigint` tenant ID was
  rounded and could match another tenant's rows. Queries that reuse the tenant
  parameter for a non-tenant column (`status = $1`) are now denied as well.
- haltsql-server: `server.auth.allow_unauthenticated` from the config file or
  `HALTSQL_ALLOW_UNAUTHENTICATED` is now applied on reload (SIGHUP or file
  watch). Before, turning anonymous access off needed a restart, even though
  the reload reported success.
- haltsql-proxy: a client-declared Parse type for a tenancy parameter (for
  example `float8`, `name` or `"char"`) is now reset to unspecified before
  the Parse is forwarded. PostgreSQL then infers the type from the tenant
  predicate, so the client can no longer round or truncate the injected
  tenant value.
- S3/GCS audit sinks: object names now carry a per-process run id
  (`<host>-<run>-<seq>-<sha256>.jsonl`), so two runs never share a sequence
  namespace. A new `spool_dir` sink option persists the chain head and the
  sequence (`head.json`), so the chain continues across restarts and deleting
  an earlier run's objects is detected. Spooled batches keep their object
  name, so a crash after an upload no longer stores the batch twice.
- S3 SigV4: the canonical URI is now the decoded path percent-encoded exactly
  once. Prefixes containing `= : + @ , ;` (for example Hive-style
  `app=haltsql/`) no longer fail with `SignatureDoesNotMatch`. Before, they
  wedged a `fail_closed` sink.
- GitHub Action: with `verify-signature: true`, a failed release download is
  fatal, and there is no container fallback. A container image is used only
  after `cosign verify` of its digest. The image is now always run by
  digest, never by a mutable tag.

## [0.1.0] - 2026-11-07

First preview release. PostgreSQL only. Not yet recommended as the only
control in front of production data; see `docs/defense-in-depth.md`.

### Added
- `haltsql` OCaml library with a total `Haltsql.verify : Policy.t -> Context.t -> string -> Verdict.t`
  that never raises, never rewrites SQL, and never connects to a database.
- SQL parsing with libpg_query 17-6.2.5 (the real PostgreSQL 17 parser),
  vendored and bound by HaltSQL's own thin C stubs (the OCaml runtime lock is
  released while parsing; inputs containing NUL bytes are rejected), then
  converted into a typed AST. Constructs the
  converter does not map are denied (`E_UNSUPPORTED`).
- Policy documents (`kind: Policy`, `apiVersion: haltsql.dev/v1`) in YAML or
  JSON: `search_path`, `catalog`, `limits`, `statements`, `require_limit`,
  `tenancy` (`bound` and `literal` modes, composite keys), `tables` (columns,
  tenant columns, writes), `functions` (allowlist and presets), `operators`,
  `deny_casts`, `allow_explain`, and `mode` (`enforce` or `shadow`).
- Per-scope tenant isolation proof (see `docs/tenancy.md`).
- Stable reason codes and a versioned verdict JSON format.
- Safe YAML/JSON loading: YAML 1.2 core schema, duplicate and unknown keys
  rejected, located error messages, JSON Schemas for every document kind.
- `haltsql` CLI: `verify` (single and `--batch` JSONL), `explain`, `validate`,
  `convert`, `schema export`, `test`, `config show`, `version`.
- `haltsql-server` HTTP sidecar: `POST /v1/verify`, `GET /healthz`,
  `GET /readyz`, `GET /metrics`, `GET /v1/policies`, bearer tokens pinned to
  policies.
- `kind: TestSuite` documents for policy tests in CI.
- Documentation, threat model, ADRs 0001–0005, CI, release and security
  workflows.
- haltlab: the enterprise test lab (Docker Compose Postgres 13–17, synthetic
  multi-tenant schemas with RLS and honeytokens, adversarial workload
  generators, and database oracles that execute every allowed query).
- Test suites: an attack corpus and sql-guardrail conformance suite
  (1,705 cases), property tests, golden verdicts, a fuzzer and benchmarks.

### Security
- libpg_query runs on long-lived worker threads with large stacks, so deeply
  nested input cannot overflow a small domain stack.
- Without a `catalog:` snapshot the catalog is empty; it is never derived
  from allowed-column lists (a derived catalog would make `SELECT *` look safe
  on tables with hidden columns).
- `WITH RECURSIVE` is denied (`E_UNSUPPORTED`); an outer LIMIT cannot bound it.
- `INSERT` may only name columns listed in the table's `columns`.
- `LIKE`, `ILIKE` and `SIMILAR TO` are checked against the operator allowlist.

[Unreleased]: https://github.com/ardada2468/HaltSQL/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ardada2468/HaltSQL/releases/tag/v0.1.0
