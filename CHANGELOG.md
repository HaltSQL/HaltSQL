# Changelog

All notable changes to HaltSQL are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Before 1.0, minor releases may contain breaking changes; they are called out
under **Changed** or **Removed**. Reason codes are never renamed or reused,
even before 1.0.

## [Unreleased]

### Added
- **Static tokens can be bound to a context.** `server.auth.tokens[]` takes
  `context` and `request_context_fields`, like mTLS identities. A bound token's
  tenant comes from the config; a request body that names another tenant gets
  `403 CONTEXT_NOT_ALLOWED`. Tokens without either key behave as before (the
  body supplies the context).
- **Tenant equality propagates through joins in the same `SELECT`.**
  `JOIN customers c ON c.tenant_id = o.tenant_id` with `WHERE o.tenant_id = $1`
  is now allowed: `c` is proven through the equality to the proven `o`. The
  equality must be a top-level `AND` condition in a location that filters the
  occurrence, on bare columns with the same tenancy key; it does not cross
  subquery boundaries ([tenancy.md](docs/tenancy.md#equality-propagation)).
- **Verdicts report the search path, and the Python guard pins it.** The
  verdict's `policy` object gains `search_path`. `haltsql.guard` (and so the
  MCP server and the Python integrations) sets it for the transaction that runs
  the verified SQL, so a role or database default such as
  `ALTER ROLE ... SET search_path` can no longer make a verified `orders`
  resolve to a different table than the one the policy lists.
- **Audit records carry the context.** Server audit records gain `context`
  (the values the statement was verified under) and `context_source`
  (`authenticated` or `request`), so the log shows which tenant a caller acted
  as.

### Changed
- **Guarded executors no longer run what a shadow policy would deny.** A
  `mode: shadow` policy still returns `allowed: true` with `shadow_reasons`,
  but the Python guard (and so the MCP server and every Python integration),
  the TypeScript `guardedQuery`, the Go `GuardedQuery`/`GuardedExec` and the
  Java `JdbcGuard` now treat such a verdict as a denial unless the application
  opts in (`HALTSQL_ALLOW_SHADOW=1` / `guard.set_allow_shadow(True)`,
  `allowShadow: true`, `AllowShadow()`, `.allowShadow()`). Switching a policy
  to shadow on the server can no longer turn enforcement off by itself.
  **Breaking** for shadow rollouts: add the opt-in.
- **`haltsql-server` verifies off the event loop.** Parsing and analysis run on
  a bounded thread pool (`HALTSQL_VERIFY_THREADS`, default the CPU count), so a
  large statement no longer stalls other requests, health checks or reloads.
- **Casts are denied by default.** A new policy section `casts`
  (`allow` / `extend`) lists the allowed cast target types; the default is the
  built-in scalar types (text, integers, numeric, floats, bool, date/time,
  uuid, json, jsonb, bytea). Before, only the types in `deny_casts` were
  refused, so `'x'::xml`, `CAST(x AS oid)` and casts to user-defined types
  passed. `deny_casts` stays as a second guard. **Breaking:** queries that cast
  to another type now get `E_CAST_DENIED`; add the type with
  `casts: { extend: [...] }`. Every policy's `version` hash changes because the
  canonical policy now includes `casts`.
- **PBKDF2 and base64 use maintained libraries.** The SCRAM key derivation
  (`Hi()`) in the proxy, the Kafka audit sink, `haltsql rls` and the catalog
  tools now calls `kdf` (`Pbkdf.pbkdf2`) instead of four hand-written loops,
  and the base64 codecs in `lib/auth`, `lib/bundle` and `lib/rlsgen` are
  built on the `base64` package with the same strictness (canonical
  encodings only). No behaviour change. New direct dependency: `kdf`
  (already a transitive dependency of `tls` and `x509`).
- JWT verification stays in-tree; `docs/authentication.md` records why the
  `jose` package was not adopted, and what the in-tree code is tested
  against: RFC 7515, 7520 and 8037 examples, tokens signed by
  pyca/cryptography for all seven algorithms, about 700 negative cases, and
  a mutation fuzzer (`test/fuzz/fuzz_jwt.ml`) that runs with `dune test`.

### Security
- **Stricter JWK and JWT parsing in `haltsql-server`.** Found by new negative
  tests of the in-tree JWT code:
  - An Ed25519 JWKS key that is a point of small order was loaded; with such a
    key one fixed signature verifies for every message. These keys are now
    refused.
  - RSA keys with an even public exponent, or a modulus over 8192 bits, were
    loaded. Both are now refused.
  - A JWK's `key_ops` was not read: a key published for `sign` or `encrypt`
    only could verify tokens. `key_ops` must now contain `verify` when present.
  - A JWK or JWK Set with duplicate member names was read by its first
    occurrence. It is now refused, as are duplicate member names nested inside
    a token's header or claims.
  - A token with `"b64": false` (RFC 7797) and no `crit` was read as an
    ordinary token. It is now refused; a non-string `typ` is refused too.
  - `exp`, `nbf` or `iat` written as an integer of more than 308 digits was
    read as infinity, so such an `exp` never expired. It is now a bad claim.
  - An `aud` array containing a non-string next to an accepted audience was
    accepted. Every element must now be a string.

## [0.0.2] - 2026-11-10

Packaging fix release. No changes to the engine, the server, the proxy or the
SDK APIs.

### Fixed
- **`@haltsql/client` is published to npm.** 0.0.1 published the three
  `@haltsql/native-*` packages but not the client: the publish job's `npm ci`
  (npm 11) refused the lockfile, which pinned the native packages without lock
  entries. Their optional dependencies are no longer in the committed
  `package.json`; `clients/typescript/scripts/set-native-deps.mjs` adds them at
  pack time, at the client's version, so `npm ci` works before and after a
  release. This also fixes `npm ci` in `clients/typescript` on `main`, which
  failed once 0.0.1 of the native packages was on npm.
- The npm publish job packs every package first and publishes tarballs,
  skipping versions already on npm, so re-running it after a partial publish
  finishes the job. The publish dry run runs the same steps with the same npm
  version, so it catches what the real publish would hit.

## [0.0.1] - 2026-11-09

First preview release. PostgreSQL only. Not yet recommended as the only
control in front of production data; see `docs/defense-in-depth.md`.

### Added
- **Release dry runs.** A `vX.Y.Z-rc.N` tag, or a manual run of
  `release.yml` / `native-packages.yml` with `dry_run`, runs every build,
  smoke test, SBOM, cosign signing and provenance step but publishes only a
  draft GitHub release and packages under `ghcr.io/haltsql/dryrun/` (images
  tagged `dryrun-<run id>`), checks the PyPI files with `twine check --strict`
  and runs `npm publish --dry-run`. A TestPyPI upload runs when the
  `TESTPYPI_PUBLISH` repository variable is set. See
  [releasing.md](docs/operations/releasing.md).
- **Helm chart as a signed OCI artifact.** Releases push the chart to
  `oci://ghcr.io/haltsql/charts/haltsql`, sign its digest with cosign, attest
  its provenance, and attach the chart archive to the GitHub release.
- `scripts/verify-release.sh <tag>` runs the verification that
  [supply-chain.md](docs/security/supply-chain.md#verifying-a-release)
  documents: checksums, every cosign bundle, `gh attestation verify`, image
  signatures, SBOM and SLSA provenance, and the chart. `release.yml` runs it
  as its last job.
- Releases attach `haltsql-<tag>.oci.txt`, the signed list of image and chart
  digests.
- `scripts/check-versions.sh` fails CI when the version in the opam files,
  SDKs, MCP server and Helm chart drift apart, and fails a release whose tag
  does not match them.
- `haltsql-mcp` is built and published to PyPI with `haltsql`.
- **`haltsql schema fetch`**: PII labels from a live data catalog API over
  HTTPS (new `haltsql.catalog_fetch` library: bearer auth with the token from
  `--token-env`/`--token-file`, never the command line; bounded pagination;
  error messages without response bodies or tokens). Providers are added
  separately; see [schema-and-pii.md](docs/schema-and-pii.md#haltsql-schema-fetch-live).
  `--snapshot-out` writes the catalog's view of the tables as a
  **non-authoritative** snapshot (`metadata.authoritative: false`, untyped
  columns).
- `haltsql policy draft` accepts a non-authoritative snapshot: the draft then
  has no `catalog:` reference and a header comment explaining that `SELECT *`
  stays denied.
- **Bundled engine in the Python wheel and npm package.** `pip install haltsql`
  now ships platform wheels (`manylinux_2_28` x86_64/aarch64, `macosx_11_0_arm64`)
  that contain `libhaltsql`, the verification engine as a self-contained C shared
  library, plus the `haltsql` CLI. `haltsql.NativeVerifier` verifies in-process
  (~50us per query) with no sidecar and no setup. `@haltsql/client` gains
  `LocalVerifier`, which drives the CLI from the `@haltsql/native-<platform>`
  packages as one long-lived process. The C ABI is in `native/include/haltsql.h`.
- `haltsql verify --batch` flushes after every result when `--jobs` is 1, so a
  long-lived process can be driven one request at a time over a pipe.
- `haltsql-server` flags `--max-connections`, `--request-timeout`,
  `--idle-timeout` and `--shutdown-timeout`; `/readyz` reports
  `"draining": true` during shutdown; new gauge
  `haltsql_http_open_connections`.
- Cloud deployment guides for [AWS](docs/deploy-aws.md),
  [Google Cloud](docs/deploy-gcp.md) and [Azure](docs/deploy-azure.md), with
  reference manifests in `deploy/cloud/` and architecture diagrams generated
  with mingrammer/diagrams (`make diagrams`).
- TLS/mTLS options in every SDK (custom CA, client certificates) and a
  response-size cap in the Python SDK.
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
- **End-to-end suite** (`test/e2e/`, `make e2e`): a Docker Compose stack of
  the real services (Postgres 17, Keycloak, Kafka, OpenSearch, OPA,
  registry:2, MinIO) and a pytest driver that runs the real `haltsql`,
  `haltsql-server` and `haltsql-proxy` binaries against it. First scenario:
  policy distribution through an OCI registry (signed push, hot update,
  untrusted-signer refusal with the last good bundle kept, restart from cache).
  Runs in the `E2E` job of the Integration workflow.
- End-to-end scenarios for identity (Keycloak groups select the policy, the
  tenant comes from a token claim), OPA (`E_EXTERNAL_POLICY`, both `on_error`
  modes against a stopped, paused or absent OPA, no deny-to-allow) and the
  shadow rollout (`/v1/admin/report`, `haltsql report --suggest --apply-to`,
  then enforce).
- End-to-end scenarios for the audit pipeline (file, Kafka and OpenSearch at
  once; `haltsql audit verify` on every copy, tampering detected in the exports
  and on the services), `haltsql-proxy` in front of Postgres (TLS, SCRAM,
  denied statements absent from the Postgres log, SIGHUP policy reload,
  chained audit file) and the agent frameworks (OpenAI Agents SDK, LangGraph,
  Google ADK tools through each framework's tool-call machinery, cross-tenant
  queries denied and never executed).
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
- **SIEM audit sinks: Elasticsearch/OpenSearch and Kafka** (`audit.sinks`
  entries `type: elasticsearch` and `type: kafka`). They stream records
  instead of uploading objects. The `elasticsearch` sink uses the bulk API
  (`url`/`urls`, `index` or `data_stream`, `auth` as `{api_key}` or
  `{username, password}`, `pipeline`, `tls.ca_file`, `timeout_ms`). The
  `kafka` sink is HaltSQL's own Kafka client: one message per record,
  `brokers`, `topic`, `client_id`, `acks` (`all` or `1`; `0` is rejected),
  `tls` with optional client certificate, and SASL `plain`, `scram-sha-256`
  or `scram-sha-512` (`plain` without TLS only for loopback brokers). Both
  take `on_error: fail_closed | buffer | drop`, `max_buffer_records` and a
  `batch` block (`max_records`, `max_bytes`, `flush_interval_ms`). Kafka
  delivery is at least once, without compression or the idempotent producer.
  New metrics are `haltsql_audit_stream_sink_*`. Tested against Elasticsearch
  8.15, OpenSearch 2.17 and Apache Kafka 3.9 (KRaft) in containers. Kafka
  client-certificate (mTLS) authentication is implemented but not yet covered
  by an integration test.
- **Remote policy bundle sources** (`policies: [{bundle_source: ...}]`): a
  signed bundle fetched from an OCI registry (`oci: REF`, `plain_http` only
  for loopback registries), from S3 or an S3-compatible store (`s3:
  {bucket, key, region, endpoint, credentials}`) or from `https: URL`, then
  polled every `poll_interval_s` (default 60) with hot reload of new
  versions. `public_keys` are mandatory, `name_prefix` and `cache_dir` (the
  last verified bundle, used when the source is unreachable at startup) are
  optional, and `auth` takes `{token}` or `{username, password}` for OCI and
  HTTPS. A bundle that fails its digest, signature or policy checks is
  refused with a stable `bundle_source_*` code and the last good bundle stays
  active. Rollbacks are refused (`bundle_source_rollback`): once a bundle is
  current, a new one must have the same `metadata.name` and a strictly greater
  `metadata.version`, and the bundle restored from `cache_dir` counts as
  current. New library `haltsql.bundle_source`, new metrics
  `haltsql_bundle_source_healthy` and `haltsql_bundle_source_checks_total`.
  Tested against `registry:2` (anonymous, htpasswd and token auth through
  `cesanta/docker_auth`, interoperability with `oras` 1.2), MinIO and an
  HTTPS server with a private CA.
- **`haltsql bundle push --oci REF` and `haltsql bundle pull --oci REF`**:
  publish a signed bundle as an OCI artifact (the `oras push` layout) and
  fetch and verify one; exit code 3 when the registry is unreachable or
  refuses the request.
- **Policies from IdP groups** (`server.auth.oidc[].policy_from_groups`):
  an ordered `map` of `{group, policy}`, a `claim` (default `groups`, dot
  paths such as `realm_access.roles` work) and an optional `default`. The
  first matching entry wins. A missing or malformed claim, no match without
  `default`, and an Entra ID groups overage are rejected with `401`
  (`missing_claim`, `bad_claim`, `no_group_policy`, `groups_overage`).
  Tested against Keycloak 26.
- **Open Policy Agent check** (new top-level `opa` section: `url`,
  `decision_path`, `timeout_ms`, `on_error: deny | allow_haltsql_verdict`,
  `headers`, `tls.ca_file`). haltsql-server asks OPA after HaltSQL has allowed
  a query, and OPA can only further deny. New metrics
  `haltsql_opa_decisions_total{outcome}` and `haltsql_opa_duration_seconds`.
  Example Rego policies with unit tests in `examples/opa/`, including one
  where OPA calls `POST /v1/verify`. Tested against OPA 1.10.
- **New reason code `E_EXTERNAL_POLICY`** (rule `opa.decision`): HaltSQL
  allowed the query and OPA denied it, or OPA could not answer and
  `opa.on_error` is `deny`. Only haltsql-server emits it.
- **Shadow reports**: `haltsql report` reads server and proxy audit logs and
  reports what a policy (typically in shadow mode) would have denied, by
  reason, policy and query (`--since`, `--policy`, `--top`). `--suggest`
  proposes conservative policy changes with the YAML to add, and
  `--apply-to FILE -o OUT` writes a patched copy; it exits 1 if the patch
  would turn a tenancy denial into an allow or the result does not validate.
- **Admin API** (`server.admin`: `enabled`, `callers`, `report_window`,
  `max_tracked_queries`; off by default): `GET /v1/admin/report` serves the
  shadow report live from an in-memory window of recent verdicts, and
  `GET /v1/admin/status` reports policies, bundle sources, audit sinks and
  the OPA settings without secrets. Callers must be listed as
  `token:<name>`, `oidc:<provider>` or `mtls:<identity>`; unauthenticated
  callers never match. New metric `haltsql_admin_requests_total`. Both
  endpoints are in `docs/openapi.yaml`.
- **`haltsql audit verify`**: checks the hash chains of server and proxy
  audit logs: files, rotated sets (`--concat`), mixed container logs
  (`--mixed`), downloaded object-sink directories (`--spool`) and
  `s3://bucket/prefix` read directly (`--endpoint` for S3-compatible
  stores). Exit 0 when every chain verifies, 1 when one is broken.
- **haltsql-proxy: hash-chained audit sinks and hot reload.** `audit.sinks`
  takes `stdout`, `file`, `s3` and `gcs` entries with the server's keys plus
  `on_error: fail_closed | buffer | drop`; a fail-closed sink that cannot be
  written refuses statements with SQLSTATE `58030`
  (`PROXY_AUDIT_UNAVAILABLE`). `SIGHUP`, or `reload.watch: true`
  (`reload.poll_interval_seconds`), reloads the config for new connections
  and keeps the last good config on any error.
- **Kubernetes operator** (`deploy/operator`, API group
  `haltsql.dev/v1alpha1`): `HaltSQLPolicy` (inline policy or a signed bundle
  source, validated with the real `haltsql validate`) and `HaltSQLServer`
  (ConfigMap, Deployment, Service, optional PodDisruptionBudget and
  NetworkPolicy, rollout on config change). Tested with envtest (real
  kube-apiserver and etcd) and end to end on kind.
- **Terraform modules** (`deploy/terraform/modules`): `haltsql-kubernetes`
  (through the Helm chart), `haltsql-aws` (ECS on Fargate), `haltsql-azure`
  (Container Apps) and `haltsql-gcp` (Cloud Run v2), with one example each.
  Bad input fails at plan time; configs hold only secret placeholders. The
  Kubernetes module is applied end to end on kind and its input validation
  has `terraform test` cases. The AWS, Azure and GCP modules have never been
  applied; they are only checked statically (`terraform validate`, tflint
  with the cloud rulesets, trivy). `.github/workflows/terraform-cloud.yml`
  can apply them on manual dispatch once cloud credentials are configured.
- **Helm chart: `extraPolicies`, `extraConfig` and a cache volume.**
  `extraPolicies` appends Config `policies[]` entries (for example a
  `bundle_source`) to the rendered ones; `extraConfig` deep-merges extra
  Config keys (`opa`, `secrets`, `telemetry.otlp`, audit sinks, ...) and
  refuses `policies`. A new `cache` volume (`mountPath`, default
  `/var/cache/haltsql`, and `volume`, default an `emptyDir`) holds bundle
  caches; `bundle_source` entries without `cache_dir` use
  `<cache.mountPath>/bundles`. The Terraform Kubernetes module's
  `bundle_sources` and `config` inputs use them.
- **Agent framework integrations** (`integrations/`): OpenAI Agents SDK
  (`haltsql-openai-agents`), LangGraph (`haltsql-langgraph`), Semantic
  Kernel (`haltsql-semantic-kernel`), CrewAI (`haltsql-crewai`) and Google
  Agent Development Kit (`haltsql-google-adk`). Each gives the agent one
  `haltsql_query` tool whose tenant context comes from application state,
  never from the model. Tested with the real framework objects, the real
  `haltsql` CLI and `haltsql-server`, and the lab Postgres; the tests never
  call an LLM.
- **Postgres flavour compatibility suite** (`lab/compat`): the `pr-smoke`
  workload, with an oracle self-test and proxy parity, against PostgreSQL 18,
  Supabase Postgres, AlloyDB Omni, Citus and TimescaleDB in containers, plus
  cloud scenarios (Aurora, Neon, hosted Supabase, AlloyDB) that need a DSN
  and have not been run. `.github/workflows/compat-cloud.yml` runs the cloud
  scenarios on manual dispatch when their DSN secrets are set (it has not run
  yet); Amazon Redshift, which is not PostgreSQL 17, gets an offline grammar
  suite instead (`test/corpus/compat-redshift.suite.yaml`). Results are in
  `docs/compatibility.md`.
- **Benchmarks** (`bench/`, `scripts/bench.sh`): library, CLI,
  `haltsql-server` and `haltsql-proxy` latency and throughput, with committed
  results (`bench/results/`) and `docs/performance.md`. A small run is a CI
  regression gate against `bench/baseline/ci-small.json`: it fails when a
  workload's calibration-normalized p50 is more than 2.5x the baseline
  (`--max-regress 1.5`).
- **Static musl binaries and image builds**: the Dockerfile builds
  `haltsql`, `haltsql-server` and `haltsql-proxy` as fully static musl
  executables (`HALTSQL_STATIC=1`) on a pinned opam-repository commit, with
  `dist` (release tarball contents), `scratch` (the binaries on an empty
  filesystem) and the default distroless `runtime` targets. `release.yml`
  now builds the release binaries from the `dist` target and smoke-tests the
  image before pushing. New `.github/workflows/build-images.yml` builds the
  amd64 and arm64 images on pull requests that touch the build, checks that
  the binaries are static, runs `scripts/docker-smoke.sh` (non-root image
  without a shell, CLI, server and proxy against a real Postgres) and the
  benchmark gate.
- **Container integration tests in CI**: `.github/workflows/integration.yml`
  runs the Kafka, Elasticsearch, OpenSearch, OPA, Keycloak, OCI registry,
  MinIO and HTTPS suites against real containers (and fails if they skip),
  plus the operator (envtest and kind), Terraform static checks and kind
  apply, and the local lab compat engines.
- **`HALTSQL_SKIP_DOCKER=1`** skips every Docker-based suite run by
  `dune test` (Kafka, Elasticsearch/OpenSearch, OPA, Keycloak, registry,
  MinIO, HTTPS and proxy-audit) with a message; the `dune test` jobs in
  `ci.yml` set it. Without it, a suite whose Docker daemon or image is
  unavailable also skips with a message.
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

### Changed
- **The first release is numbered 0.0.1**, not 0.1.0. Nothing was ever
  tagged or published as 0.1.0; every manifest, image reference, example and
  the section below now say 0.0.1. The framework integrations require
  `haltsql>=0.0.1`.
- The Helm chart now versions in lockstep with HaltSQL: chart `version` is
  `0.0.1` (it was `0.2.0`, never published).
- CI on pull requests runs only the jobs whose files changed: a `changes`
  job (`.github/scripts/changes.sh`) gates every job in `ci.yml` and
  `integration.yml`, so a docs-only PR no longer starts ~30 runners. PRs test
  OCaml 5.4 (Ubuntu and macOS) and Node 22; pushes to `main` still run the
  full OCaml 5.2/5.4 x Ubuntu/macOS and Node 18/20/22 matrices. New `CI ok`
  and `Integration ok` checks sum up each workflow for branch protection.
- **Repository moved to `github.com/HaltSQL/HaltSQL`** (breaking). Go module
  paths are now `github.com/HaltSQL/HaltSQL/clients/go/haltsql`,
  `.../clients/go/pgxtest` and `.../deploy/operator`; container images and
  the Helm chart are published under `ghcr.io/haltsql/`; the docs site is
  `https://haltsql.github.io/`, published from the public
  `HaltSQL/haltsql.github.io` repository; and `cosign verify` must use the new
  repository's workflow identity. Old `ghcr.io/ardada2468/...` images are not
  republished.
- Helm chart: values schema, startup probe, `server.extraConfig`,
  configurable NetworkPolicy egress, extra env/volumes/containers, zone
  spreading, `podMonitoring` for GKE managed Prometheus, and `server.port` is
  honored. Requires Kubernetes 1.27+.
- Release and CI workflows pin actions by commit SHA; the Dockerfile pins
  base images by digest and the opam-repository commit.
- `telemetry.otlp_endpoint` must now be an `http(s)` URL. It was previously
  unused, and now drives OTLP export.
- An unknown `--default-policy` value now fails server startup (exit 2)
  instead of failing at request time.
- Packaging: the server-only libraries are now `haltsql-server.auth` and
  `haltsql-server.telemetry`, and the proxy engine is `haltsql-proxy.pgwire`.
  The `haltsql` opam package now also depends on lwt, cohttp and tls,
  because the CLI links the cloud, bundle, RLS and catalog tools. The core
  libraries themselves have no network dependencies.
- Docs: every diagram is now Mermaid (rendered by GitHub and the docs site),
  the README shows where HaltSQL sits, `CONTRIBUTING.md` documents the OCaml
  style and conventions, and the docs index links every page, including the
  new AWS, Google Cloud and Azure deployment guides.

- **x509 1.2.** Dependencies are now `x509 >= 1.2.0` and
  `tls`/`tls-lwt >= 2.0.4`; the `x509 < 1.2` upper bound is gone. Behaviour
  changes that come with it:
  - Server hostname checks read only DNS SubjectAltName entries. A server
    certificate that names its host only in the subject CN is now rejected
    by haltsql-proxy's upstream `verify-full`, and by the Vault, S3 and OIDC
    HTTPS clients. Reissue such certificates with a DNS SAN.
  - Client-certificate CNs (`subject_cn` identities in haltsql-server and
    haltsql-proxy) are decoded from UTF8String, PrintableString, BMPString
    and UniversalString. A TeletexString, malformed, empty or control-character
    CN is treated as absent and never matches (fail closed).
- haltsql-proxy audit records are now hash-chained like the server's
  (`prev_hash`, `hash`), and the file sink continues the chain across
  restarts. A file whose last line is not a sealed record stops the proxy
  from starting; rotate it first.
- haltsql-server reload (file change or `SIGHUP`) now also applies `opa` and
  `server.admin`. The list of `bundle_source` entries and the audit sinks
  need a restart; new bundles fetched by a running source are applied as
  reloads.

### Fixed
- `haltsql_llamaindex.guarded_nl_sql_query_engine` accepts guard options
  (`max_rows`, `statement_timeout_ms`, `settings`, `read_only`,
  `denials_as_sql_errors`) as keyword arguments; they were passed on to
  `NLSQLTableQueryEngine` and silently ignored. Conflicting or unknown guard
  options raise `TypeError`.
These were found while integrating the unreleased features above.

- Server: two bundle sources updated while a reload waited on the secret
  prefetch (`${vault:...}` and other provider placeholders) lost one update:
  the reload that finished last put the other source's old policies back while
  its status reported the new version, and later polls never re-applied it.
  Bundle-driven reloads (and file/SIGHUP reloads) are now serialized and each
  derives its policy set from the state at commit time.
- Server: at startup a freshly fetched bundle was cached before the startup
  checks ran. When they refused it, the cache held the refused bundle and the
  last good one was deleted, so every later restart failed (even with the
  source down, or back on the good version, refused as a rollback). Bundles
  fetched at startup are now cached only once accepted; a refused one falls
  back to the cached last good bundle.
- OPA: a denial by OPA (or an OPA failure with `on_error: deny`) kept the
  `bind_params` of the HaltSQL verdict; a denied verdict now never carries
  them.
- `haltsql audit verify --allow-redelivery`: exact copies of records already
  seen (Kafka at-least-once re-delivery of a whole batch) are warnings and
  skipped. `verify_chain.py kafka` skips them always; before, a retried batch
  failed both verifiers although the docs said it was skipped.
- `verify_chain.py es`: several chains from genesis (server restarts,
  replicas) are no longer reported as a fork, and a chain that follows a
  missing record (a deleted document) now exits with status 1 instead of 0
  (`--any-start` accepts exports that begin mid-chain). `verify_chain.py kafka`
  likewise fails on a mid-stream start unless `--any-start` is given.
- Terraform `haltsql-aws`: the task role allowed `s3:GetObject` on the bundle
  key only, so the signature GET (`key.sig`) was denied and every S3
  `bundle_source` failed. The statement now lists both exact keys
  (`modules/bundle-object-arns`, checked with `terraform test` and against
  MinIO by `deploy/terraform/test/aws-bundle-policy-minio.sh`).
- Tests: Kafka mTLS (client certificates) is now tested against a real broker
  with `ssl.client.auth=required`, including refusal without a certificate and
  with one from another CA.

- `haltsql bundle build`: a policy without `tenancy` produced a bundle that
  did not load, because the bundle stored an empty `tenancy.keys` that the
  policy loader rejects. The empty key is now left out; the loaded policy and
  its version are unchanged.
- haltsql-server startup with remote bundles: the policy references
  (`default_policy`, tokens, OIDC and mTLS policies) were checked before the
  bundle sources had been fetched, so a config that referenced a policy from
  a `bundle_source` could not start. The server now fetches and verifies
  every bundle source (or restores it from `cache_dir`) first, then checks
  the references.
- Test helpers: `waitpid` (and `Unix.system`) calls in the Docker and
  subprocess test helpers now retry on `EINTR`, so a signal delivered while a
  test waited for a child process no longer failed the test.
- haltsql-server reload: a reload that changed `audit.sinks` was accepted
  and the new sinks were silently never opened. The running sinks still stay
  (audit sinks are opened once, so the chain is not forked), but the reload
  now logs a warning and `GET /v1/admin/status` reports
  `audit_restart_pending: true` until the sinks match again or the server
  restarts.
- haltsql-server: `policy_from_groups` references that a bundle fails to
  provide are reported with their config location
  (`server.auth.oidc[i].policy_from_groups.map[j].policy` or `.default`);
  startup fails closed and a reload (including a new bundle from a
  `bundle_source`) is rejected with the last good set kept. Covered against a
  real registry.
- Wiring tests: the Kafka broker could not read its mounted
  `server.properties` (a `0700` temporary directory), so the Kafka audit-sink
  test never got a broker when the test user and the image's user differed.
- Proxy tests: environment overrides for child processes were appended to the
  inherited environment, so an inherited variable won (getenv returns the
  first match). With AWS keys set in the developer's shell, the MinIO
  `audit verify` step failed with `InvalidAccessKeyId`. Overridden inherited
  entries are now dropped.
- Bundle-source tests: the oras compatibility test reached registry:2 through
  `host.docker.internal`, which on Linux cannot reach a port published on
  127.0.0.1 only. oras now shares the registry container's network namespace.
- `haltsql bundle push|pull --json`: a refused push (signature not made by a
  `--public-key`, bundle that does not load), a failed pull verification or an
  unreachable registry printed only a stderr line, so scripts parsing stdout
  got an empty document. These failures now also print
  `{"ok": false, "exit": N, "error": "..."}`, like `bundle verify --json`; a
  successful push gains `"ok": true`. Found by the new end-to-end suite.
- Docs: `GET /v1/admin/status` shows `signed_by` as the full key id
  (`sha256:<hex>`), as the server reports it.
- Docs: the shadow report's *By caller* section groups server records by the
  audit `caller` (`oidc:<provider>` for OIDC tokens), not by the OIDC subject.
- Parsing after `fork()` no longer hangs: the libpg_query worker pool is
  reset in the child with `pthread_atfork`.
- A very long unknown key in a policy or config no longer allocates a large
  edit-distance matrix for its "did you mean" hint.
- Concurrent reloads (SIGHUP and the file watcher) are serialized, and each
  request uses one consistent policy snapshot.
- The container image builds again on Alpine 3.24 (`gmp-static`), and the
  Helm chart's NetworkPolicy no longer blocks the egress that OIDC, secret
  providers, cloud audit sinks and OTLP need.
- `haltsql-proxy` command-line errors exit `2` (a missing option exited 124).

### Security
- **LangChain, LlamaIndex and Vanna integrations: no database access outside
  HaltSQL.** The guarded LangChain `SQLDatabase` no longer reads sample rows
  for `get_table_info` (they were read straight from the engine, unverified,
  and could show other tenants' rows to the model): `sample_rows_in_table_info`
  is forced to 0 and the internal `_execute` refuses. The guarded LlamaIndex
  `SQLDatabase.insert_into_table` now raises `GuardError` instead of inserting
  through the engine.
- A context callable that returns `None` now refuses the query
  (`haltsql.integration.ContextUnavailable`) in `haltsql-langchain`,
  `haltsql-llamaindex` and `haltsql-vanna` (legacy and 2.x), as in the agent
  packages; it was verified with an empty context. In LangChain an exception
  from the context callable is reported to the model as "SQL verification is
  unavailable" instead of "Database error: ...".
- `read_only=True` (the default) in `haltsql-langchain` and
  `haltsql-llamaindex` now also requires the verdict's `statement_kind` to be
  `select`, refusing other statements before connecting. With
  `read_only=False` the policy decides which kinds run; `SELECT` still runs
  `READ ONLY`, and a verdict without a `statement_kind` never runs. New SDK
  helpers `haltsql.integration.authorize_guarded` and `guard_read_only`;
  `ContextUnavailable` moved to `haltsql.integration` (still exported by
  `haltsql.agent_core`).
- The catalog loader refuses a snapshot marked `metadata.authoritative:
  false` (written by `haltsql schema fetch --snapshot-out`) as a policy
  `catalog:`, file or inline: a data catalog can lag behind the database, and
  the analyzer trusts a catalog as the complete column and relation list
  (`SELECT *` expansion, `search_path` shadowing). Pulled snapshots are
  unchanged.
- **haltsql-proxy no longer prints TLS private keys in errors.** A `tls.key`
  written as `${file:...}` was opened as a path, and the load error echoed the
  PEM. Certificate and key errors now never include the configured value, and
  `tls.cert` / `tls.key` accept inline PEM as well as a path.
- **haltsql-server resource limits**: an oversized declared body is rejected
  with 413 before it is read (it was fully drained first), unread bodies are
  drained only up to the cap, and new request/idle timeouts, a 64 KiB header
  cap and `--max-connections` close slowloris-style gaps.
- **Bounded outbound I/O**: the cloud HTTP client (Vault, AWS/GCP secret
  managers, IMDS, STS, S3/GCS sinks) now enforces its size cap on chunked
  responses, and it, the OIDC JWKS fetch and the OTLP exporter close their
  connections on every error path. The proxy's upstream TLS negotiation and
  cancel requests are bounded by `connect_timeout`.
- `AUTH_UNAVAILABLE` responses no longer include internal OIDC fetch errors.
- Kafka audit sink: TLS to a broker whose name is neither an IP address nor a
  valid DNS host name (for example `kafka_1`) skipped the host name check, so
  any certificate chaining to a trusted root was accepted. Such brokers
  (configured or advertised by Metadata) are now refused. The proxy's
  `upstream.tls.mode: verify-full` rejects such a host at config load and at
  connect time.
- Kafka audit sink: SASL `PLAIN` without TLS checked only the bootstrap
  brokers for loopback; the password was then sent in clear text to the
  partition leader the broker advertised, wherever it was. Every connection is
  now checked, and a non-loopback leader is refused.
- "Loopback only" checks (bundle-source redirects and `plain_http`
  registries, OCI references, Kafka plain text, Vault/OTLP/OPA `http` URLs,
  the catalog tools' sslmode default) treated any host name starting with
  `127.` as loopback, so `127.attacker.example` passed. Only `localhost`,
  `::1` and literal 127.0.0.0/8 IPv4 addresses count now (one shared helper,
  `Haltsql_core.Loopback`). URLs whose host ocaml-uri cuts at an IP-address
  prefix (`http://127.0.0.1.nip.io/`) are refused as malformed.
- Terraform `haltsql-kubernetes`: `bundle_sources[*].auth` values must be
  secret placeholders (`${env:...}`, `${file:...}`, `${vault:...}`,
  `${aws-sm:...}`, `${gcp-sm:...}`). Literal registry passwords and tokens
  were accepted and rendered into the ConfigMap and the Helm values.
- Analyzer: functions that run a SQL string given as an argument (`ts_rewrite`,
  `ts_stat`, `query_to_xml*`, `cursor_to_xml*`, `table_to_xml*`,
  `schema_to_xml*`, `database_to_xml*`, the `dblink` family) are now denied
  even when allowlisted (`E_FUNCTION_DENIED`, rule `functions.dynamic_sql`).
  `haltsql report --suggest`/`--apply-to` and `GET /v1/admin/report` no
  longer suggest `ts_rewrite`, `setseed`, `getpgusername`, `brin_*summarize*`
  or `gin_clean_pending_list`. Before, one shadow denial of
  `ts_rewrite(q, 'SELECT ...')` produced an applicable suggestion, and the
  SQL in its second argument read other tenants' rows.
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
- libpg_query runs on long-lived worker threads with large stacks, so deeply
  nested input cannot overflow a small domain stack.
- Without a `catalog:` snapshot the catalog is empty; it is never derived
  from allowed-column lists (a derived catalog would make `SELECT *` look safe
  on tables with hidden columns).
- `WITH RECURSIVE` is denied (`E_UNSUPPORTED`); an outer LIMIT cannot bound it.
- `INSERT` may only name columns listed in the table's `columns`.
- `LIKE`, `ILIKE` and `SIMILAR TO` are checked against the operator allowlist.

[Unreleased]: https://github.com/HaltSQL/HaltSQL/compare/v0.0.2...HEAD
[0.0.2]: https://github.com/HaltSQL/HaltSQL/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/HaltSQL/HaltSQL/releases/tag/v0.0.1
