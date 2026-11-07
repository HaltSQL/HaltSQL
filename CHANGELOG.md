# Changelog

All notable changes to HaltSQL are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, minor releases may contain breaking changes; they are called out
under **Changed** or **Removed**. Reason codes are never renamed or reused,
even before 1.0.

## [Unreleased]

### Added
- Nothing yet.

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
