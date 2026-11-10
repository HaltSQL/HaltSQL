# Hardening baseline

This page is a secure configuration baseline for production deployments of
HaltSQL. It is for platform and security engineers who deploy
`haltsql-server` or `haltsql-proxy` and want one list of settings to review.
Each row gives the setting, the recommended value, the reason and the page
with the details.

Most defaults are already the safe choice. The rows marked **(not default)**
need an explicit change.

## Database

HaltSQL is one layer of three. A bug in HaltSQL, a policy mistake, or a caller
that skips the check is contained only by the database's own controls
([defense-in-depth.md](../defense-in-depth.md)).

| Setting | Recommended value | Why | Details |
|---|---|---|---|
| Database role for agent queries | A dedicated role: `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, `SELECT` granted only on the policy's tables and columns | The database still enforces the basics if HaltSQL is bypassed or wrong | [Layer 1](../defense-in-depth.md#layer-1-a-dedicated-read-only-role) |
| Role session defaults | `default_transaction_read_only = on`, `statement_timeout` (for example `5s`), `lock_timeout`, `idle_in_transaction_session_timeout` | HaltSQL does not bound how long an allowed query runs | [Layer 1](../defense-in-depth.md#layer-1-a-dedicated-read-only-role) |
| Role `search_path` | Identical to the policy's `search_path` | Otherwise an unqualified name can resolve to a different table than the one HaltSQL checked | [defense-in-depth.md](../defense-in-depth.md#layer-1-a-dedicated-read-only-role) |
| Row-level security | `ENABLE` and `FORCE ROW LEVEL SECURITY` on every tenant table, keyed on a setting your application sets per transaction | Tenant isolation holds even if a query escapes HaltSQL | [Layer 2](../defense-in-depth.md#layer-2-row-level-security-keyed-on-a-session-setting) |
| RLS coverage check | Run `haltsql rls check` against the live database in CI or after migrations | Reports where the role, grants and RLS policies in the database have drifted from the HaltSQL policy | [rls-generation.md](../rls-generation.md) |
| Dangerous functions | Revoke `EXECUTE` from `PUBLIC` on functions you do not need (for example `pg_sleep`) | Defense in depth for functions a policy might allow by mistake | [defense-in-depth.md](../defense-in-depth.md#layer-1-a-dedicated-read-only-role) |

## Policies

| Setting | Recommended value | Why | Details |
|---|---|---|---|
| `mode` | `enforce` (the default). Use `shadow` only during a rollout. | A policy in `shadow` mode reports violations but **allows** the query | [policy-reference.md](../policy-reference.md#mode) |
| `tenancy.mode` | `bound` (the default) | The tenant value is a bound parameter supplied from the context, never written by the model | [tenancy.md](../tenancy.md#bound-mode-recommended) |
| `statements.allow` | `[select]` (the default) unless writes are required | Read-only agents should not be able to write, whatever the SQL says | [policy-reference.md](../policy-reference.md#statements) |
| `require_limit.max` | Set it **(not default)**, for example `1000` | Bounds rows per query; every `SELECT` must end in a constant `LIMIT n` with `n <= max` | [policy-reference.md](../policy-reference.md#require_limit) |
| `limits` | Keep the defaults (`max_bytes` 16384, `max_depth` 64, `max_nodes` 20000, `max_joins` 8) or lower | Bounds parsing and analysis cost and query shape | [policy-reference.md](../policy-reference.md#limits) |
| `tables.*.columns` | Explicit column lists; avoid `"*"` on tables with sensitive columns | `"*"` allows every current and future column | [schema-and-pii.md](../schema-and-pii.md) |
| `allow_explain` | `false` (the default) | Plans expose planner estimates (row counts) that the agent does not need; `EXPLAIN ANALYZE` is always denied | [policy-reference.md](../policy-reference.md#allow_explain) |
| Policy tests | Run `haltsql validate`, `haltsql lint-policy` and `haltsql test` in CI on every policy change | Catches policies that allow more than intended before they ship | [policy-ci.md](../policy-ci.md) |
| `catalog` | A `haltsql schema pull` snapshot in every policy **(not default)**; `haltsql schema check` in the migration pipeline | Without a catalog `SELECT *` and column checks rely on the policy's own lists (`lint-policy` reports `W_NO_CATALOG`); with a stale one, a new column is read unchecked | [schema-and-pii.md](../schema-and-pii.md#haltsql-schema-check) |

## Policy delivery

| Setting | Recommended value | Why | Details |
|---|---|---|---|
| Policy source | Load policies only from signed bundles: `policies[].bundle` or `policies[].bundle_source` **(not default)** | The server verifies the Ed25519 signature before it reads a policy, so a compromised file system or delivery channel cannot change them | [policy-bundles.md](../policy-bundles.md) |
| `public_keys` | Only the current signing key, plus the next one during a rotation | Any listed key may sign | [Key management](../policy-bundles.md#key-management-and-rotation) |
| Signing key | Generated with `haltsql bundle keygen`, stored as a protected CI secret, never committed | Whoever holds it can authorize any policy | [policy-ci.md](../policy-ci.md#signing-in-ci-safely) |
| `bundle_source.oci` | A digest-pinned reference (`repo@sha256:...`) for immutable deployments, or a tag with monotonic `metadata.version` | The poller refuses rollbacks; a digest pins the exact artifact | [config-reference.md](../config-reference.md#bundle_source) |
| `cache_dir` | Set, on a writable volume | The server can restart from the last verified bundle while the source is down; the cache is re-verified on every start | [policy-bundles.md](../policy-bundles.md#cache) |

> **Note:** there is no setting that forbids plain `path:` or `inline:`
> policies. To enforce "signed bundles only", review the config in change
> control, and check that every policy in `GET /v1/admin/status` has
> `origin: bundle_source` (or `bundle_or_file` for local bundles).

## `haltsql-server`: transport and callers

| Setting | Recommended value | Why | Details |
|---|---|---|---|
| `server.tls` | Enabled **(not default)** whenever traffic leaves the pod or host; `min_version: "1.3"` if all clients support it | Without it, tokens and SQL cross the network in clear text | [Built-in TLS](../authentication.md#built-in-tls) |
| `server.listen` | `127.0.0.1:8080` (the default) when TLS is terminated elsewhere or the agent is in the same pod | Keeps the plaintext listener off the network. The container image sets `HALTSQL_LISTEN=0.0.0.0:8080`, which overrides the config file. | [config-reference.md](../config-reference.md#server) |
| `server.tls.client_auth` | `required` with `server.auth.mtls` identities, for service-to-service callers | Strong workload identity; the context comes from config, not the request | [mTLS identities](../authentication.md#mtls-identities) |
| Caller authentication | OIDC or mTLS when the tenant or user must come from an authenticated identity and tenants are many | The tenant comes from a signed token or a certificate, not from the request body | [authentication.md](../authentication.md#static-tokens) |
| `server.auth.tokens[].context` | Set it **(not default)** on every static token whose policy has tenancy, one token per tenant | A token without `context` or `request_context_fields` is unbound: its holder can ask for a verdict for any tenant. The server logs a warning for each such token at start and on reload; the Helm chart refuses to render one with `server.requireBoundTokens: true` | [authentication.md](../authentication.md#static-tokens) |
| `server.auth.oidc[].context_claims` | Map the tenant (and user) fields to claims | The tenant comes from the signed token; the body cannot override it (`403 CONTEXT_NOT_ALLOWED`) | [OIDC](../authentication.md#oidc--jwt-bearer-tokens) |
| `request_context_fields` | `[]` (the default), or the smallest list that works | Every listed field is supplied by the caller, not the identity | [authentication.md](../authentication.md#context-rules) |
| `server.auth.oidc[].required_claims` | A scope or audience-specific claim, for example `scope: sql.verify` | Rejects tokens the IdP issued for other purposes | [OIDC](../authentication.md#oidc--jwt-bearer-tokens) |
| `policy_from_groups` | Most privileged groups first; `default: null`; on Entra ID prefer app roles (`claim: roles`) | The first match wins; no default means unknown callers are rejected; app roles never overflow | [Policies from IdP groups](../authentication.md#policies-from-idp-groups) |
| Static tokens | One token per agent, at least 32 random bytes (`openssl rand -hex 32`), only `token_sha256` in config | HaltSQL stores an unsalted SHA-256, which is safe only for high-entropy tokens | [config-reference.md](../config-reference.md#server) |
| `server.auth.allow_unauthenticated` | `false` (the default); leave `HALTSQL_ALLOW_UNAUTHENTICATED` unset | Unauthenticated callers can name any loaded policy or use `default_policy` | [config-reference.md](../config-reference.md#server) |
| `default_policy` | Unset (the default) | Only used for unauthenticated requests and requests that name no policy | [config-reference.md](../config-reference.md#default_policy) |
| `server.admin` | Disabled (the default), or `callers` limited to mTLS or OIDC identities of operators | The admin report reveals query patterns, and with `log_raw_sql` some SQL | [config-reference.md](../config-reference.md#serveradmin) |
| `/metrics`, `/healthz`, `/readyz` | Restrict with a NetworkPolicy, or serve probes on `--health-listen` and disable Prometheus (`telemetry.metrics.prometheus: false`) if unused | These endpoints need no authentication; metrics are labelled with policy names and reason codes | [http-api.md](../http-api.md#authentication) |
| `limits.max_request_bytes` | `1048576` (the default) or lower | Bounds request size | [config-reference.md](../config-reference.md#limits) |
| `secrets` and placeholders | Every credential through `${vault:...}`, `${aws-sm:...}`, `${gcp-sm:...}`, `${file:...}` or `${env:...}`; never inline | Config files and ConfigMaps hold no secrets | [secrets.md](../secrets.md) |

## Audit

| Setting | Recommended value | Why | Details |
|---|---|---|---|
| `on_error` | `fail_closed` (the default) on at least one sink | No verdict is served without its audit record | [Failure policy](../audit-sinks.md#failure-policy-on_error) |
| `buffer` / `drop` | `buffer` only where availability matters more than synchronous auditing; `drop` only next to another `fail_closed` sink | `drop` discards records with no gap marker in the chain | [config-reference.md](../config-reference.md#streaming-sinks-elasticsearch-and-kafka) |
| `audit.log_raw_sql` | `false` (the default) | SQL can contain sensitive literals; records always carry `sql_sha256` and the fingerprint | [config-reference.md](../config-reference.md#audit) |
| Durable sink | `s3` with `object_lock: {mode: COMPLIANCE, retain_days: N}` and a `spool_dir` on persistent storage **(not default)**, or `gcs` with a bucket retention policy | WORM storage stops whole-log rewrites; the spool keeps the chain continuous across restarts | [Restarts and chain continuity](../audit-sinks.md#restarts-and-chain-continuity) |
| Chain verification | Run `haltsql audit verify --expect-head <recorded head>` on a schedule and alert on failure | A chain proves nothing unless someone checks it | [audit-verify.md](../audit-verify.md) |
| Kafka sink | `tls` enabled, `sasl` with `scram-sha-512`, `acks: all` (the default) | Without `tls` the sink is plaintext | [config-reference.md](../config-reference.md#streaming-sinks-elasticsearch-and-kafka) |
| File sink volume | Mount a writable volume at `/var/log/haltsql` only if you use the file sink | The rest of the root filesystem stays read-only | [deployment.md](../deployment.md) |
| Alerts | On `haltsql_audit_errors_total`, `haltsql_audit_sink_healthy == 0` and `haltsql_reasons_total{code="E_INTERNAL"}` | Detects audit loss and internal errors early | [http-api.md](../http-api.md#get-metrics) |

## OPA

| Setting | Recommended value | Why | Details |
|---|---|---|---|
| `opa.on_error` | `deny` (the default) | An unreachable or misconfigured OPA must not allow queries | [opa.md](../opa.md) |
| `opa.url` | A loopback sidecar, or `https` with `tls.ca_file` | Plain `http` is accepted only for loopback | [config-reference.md](../config-reference.md#opa) |
| `opa.headers` | A bearer token from a secret placeholder, with OPA's own authentication enabled | Stops other workloads from changing OPA's answers | [opa.md](../opa.md) |

OPA can only add denials: a query HaltSQL denies is never sent to OPA, and no
OPA answer turns a denial into an allow. There is nothing to configure for
this.

## `haltsql-proxy`

| Setting | Recommended value | Why | Details |
|---|---|---|---|
| `tls` | Configured **(not default)**; `required: true` (the default once `tls` is set) | Without a `tls` section the proxy accepts plaintext clients | [proxy.md](../proxy.md#config-reference) |
| `auth.method` | `cert` with `tls.client_auth: require`, or `scram` with long random passwords | The identity selects the policy and the context | [proxy.md](../proxy.md#authentication) |
| `upstream.tls.mode` | `verify-full` with `upstream.tls.ca` **(not default; the default is `disable`)** | `require` encrypts without verifying the server | [proxy.md](../proxy.md#config-reference) |
| `upstream.allow_insecure_auth` | `false` (the default) | With it on, the proxy answers an MD5 password request on an unencrypted connection. Move the role to SCRAM-SHA-256 or enable `upstream.tls` instead | [proxy.md](../proxy.md#upstream-transport-security) |
| `upstream.user` | A least-privilege, read-only role, as in [Database](#database) | The proxy's credentials are the only ones clients use | [proxy.md](../proxy.md#operations) |
| `upstream.password` | A `${env:...}` or `${file:...}` placeholder | Never in the file | [proxy.md](../proxy.md#config-reference) |
| `limits` | Set `max_connections`, `max_message_bytes`, `idle_timeout_seconds` for your load | Bounds what one client can consume | [proxy.md](../proxy.md#config-reference) |
| `limits.max_session_lifetime_seconds` | `3600` (the default) or lower; never `0` | A session keeps the identity, policy and upstream connection it started with; the lifetime bounds how long a revoked credential stays usable | [proxy.md](../proxy.md#session-lifetime) |
| `reload.terminate_changed_sessions` | `true` (the default) | A reload ends the sessions whose credentials, policy, context or upstream it changed | [proxy.md](../proxy.md#hot-reload) |
| `limits.max_unauthenticated_per_ip` | `20` (the default) when the proxy sees client addresses; sized to the pool when a load balancer or pooler hides them; never `0` on a reachable listener | One address cannot hold every connection slot with sessions that never authenticate. The cap counts TCP peers, so clients behind one address share it | [proxy.md](../proxy.md#connection-limits) |
| `audit` | A sink with `on_error: fail_closed` (the default) | No statement reaches the database without its audit record | [proxy.md](../proxy.md#failure-policy-on_error) |
| Network | Only the proxy can reach the database (security groups, NetworkPolicy, `pg_hba.conf`) | A client that reaches PostgreSQL directly bypasses the proxy | [deploy-aws.md](../deploy-aws.md) |

## Runtime

| Setting | Recommended value | Why | Details |
|---|---|---|---|
| Image | `ghcr.io/haltsql/haltsql` pinned by digest, signature verified with `cosign verify` | Ensures you run the artifact the release workflow built | [supply-chain.md](supply-chain.md) |
| Base image | The default `distroless/static-debian12:nonroot` runtime stage | No shell, no libc, no package manager | [deployment.md](../deployment.md#what-is-in-the-image) |
| User | Non-root, uid/gid `65532` (the image default) | Limits the impact of a process compromise | [Dockerfile](../../Dockerfile) |
| Root filesystem | `readOnlyRootFilesystem: true` / `docker run --read-only` | Nothing in the image writes to the root filesystem | [Dockerfile](../../Dockerfile) |
| Container security context | `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`, `runAsNonRoot: true` | Set by the Helm chart's defaults | [values.yaml](../../deploy/helm/haltsql/values.yaml) |
| Service account token | `automountServiceAccountToken: false` (the chart default) unless Vault Kubernetes auth needs it | HaltSQL does not call the Kubernetes API | [values.yaml](../../deploy/helm/haltsql/values.yaml) |
| NetworkPolicy | `networkPolicy.enabled: true` (the chart default) with `ingressFrom` set to the agent pods **(an empty list allows any pod in the namespace)**; egress limited with `extraRules` to the endpoints you configured | Egress is denied by default because verification needs no network access | [values.yaml](../../deploy/helm/haltsql/values.yaml) |
| Sidecar topology | One `haltsql-server` per agent pod, reached on `127.0.0.1` | Verification traffic never leaves the pod | [deployment.md](../deployment.md#kubernetes-sidecar) |
| systemd | The shipped unit (`DynamicUser`, `ProtectSystem=strict`, `NoNewPrivileges`, empty `CapabilityBoundingSet`, and more) | Same isolation outside containers; check with `systemd-analyze security` | [deployment.md](../deployment.md#systemd) |

## SDKs and the MCP server

| Setting | Recommended value | Why | Details |
|---|---|---|---|
| Execution path | Only the SDK's guarded-execute helper | It checks `sql_sha256`, binds `bind_params`, and treats any error as a denial | [deployment-modes.md](../how-it-works/deployment-modes.md#mode-4-sdks-and-the-mcp-server) |
| `statement_timeout_ms`, `max_rows` (Python SDK) | Set both | HaltSQL does not limit run time | [sdk-python.md](../sdk-python.md) |
| `haltsql-mcp` row cap and timeout | Keep `--row-cap` (default 200) and `--statement-timeout-ms` (default 5000) | Bounds what one tool call can return and how long it runs | [mcp.md](../mcp.md) |
| `haltsql-mcp` HTTP transport | A tokens file, and a TLS proxy in front | The MCP server has no built-in TLS | [mcp.md](../mcp.md) |
| Shadow opt-in (`HALTSQL_ALLOW_SHADOW`, `set_allow_shadow`, `allowShadow`, `AllowShadow()`) | Unset (the default) in production; set only on the clients of a shadow rollout, and removed after it | With the opt-in, a policy switched to `mode: shadow` on the server stops enforcing for that client | [tutorials/roll-out-a-policy-safely.md](../tutorials/roll-out-a-policy-safely.md) |

## Checking a deployment

- `haltsql config show --config FILE` prints the effective configuration
  (flags, `HALTSQL_*` environment and file merged) with secrets redacted.
- `GET /v1/admin/status` shows loaded policies, their origin and mode,
  bundle signer key ids, audit sink health and the OPA settings.
- `haltsql-proxy validate -c FILE --json` prints the proxy's effective
  config with secrets redacted, and warns (`INSECURE UPSTREAM TRANSPORT`)
  when `upstream.tls.mode` is `disable` for a host that is not loopback.
- The server log at start has no `token is not bound to a context` warning,
  or only for tokens of trusted backends.

## Related

- [overview.md](overview.md)
- [compliance.md](compliance.md)
- [supply-chain.md](supply-chain.md)
- [defense-in-depth.md](../defense-in-depth.md)
- [authentication.md](../authentication.md)
- [config-reference.md](../config-reference.md)
- [proxy.md](../proxy.md)
- [deployment.md](../deployment.md)
