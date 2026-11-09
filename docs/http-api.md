# HTTP API

`haltsql-server` exposes HaltSQL over HTTP so agents in any language can verify
SQL. The machine-readable contract is [openapi.yaml](openapi.yaml) (OpenAPI
3.1). Everything under `/v1` is covered by HaltSQL's compatibility guarantees:
fields are only added, never renamed or removed.

Start it with a config file, or with a single policy for local development:

```sh
haltsql-server --config /etc/haltsql/config.yaml
haltsql-server --policy policy.yaml --listen 127.0.0.1:8080
```

## Authentication

Requests to `/v1/*` are authenticated in this order (details, examples and
the threat model in [authentication.md](authentication.md)):

1. **mTLS identity.** With built-in TLS (`server.tls`) and client
   certificates enabled, a certificate issued by `server.tls.client_ca` whose
   SPIFFE ID (URI SAN) or subject CN matches a `server.auth.mtls` identity
   authenticates the request. The identity pins the policy and supplies a
   static context. A valid certificate that matches no identity falls through
   to bearer authentication.
2. **OIDC bearer token.** A bearer token that is a JWT whose (unverified)
   `iss` equals a configured `server.auth.oidc` issuer is verified by that
   provider: signature against the provider's JWKS (RS256/RS384/RS512/PS256/
   ES256/ES384/EdDSA; never `none` or HMAC), `iss`, `aud`, `exp`/`nbf`/`iat`
   with leeway, and `required_claims`. The policy is pinned by the provider or
   selected by a claim from `allowed_policies`; `context_claims` become the
   context.
3. **Static bearer token.** Anything else is compared (constant time) with the
   SHA-256 hashes in `server.auth.tokens`.

```
Authorization: Bearer <token>
```

**Every caller is pinned to exactly one policy**, so it cannot pick a looser
policy than the one it was given.

**Context from the identity is authoritative.** For OIDC and mTLS callers the
request body's `context` may only set the fields listed in the identity's
`request_context_fields`. Any other field is refused with
`403 CONTEXT_NOT_ALLOWED`, never silently overridden (repeating an
identity-provided field with exactly the same value is accepted). Static
tokens and unauthenticated requests supply the whole context in the body.

Health, readiness, and metrics endpoints do not require a token; restrict them
at the network level if needed, or serve the probes on a separate plain-HTTP
port with `--health-listen` (only `/healthz` and `/readyz` are served there).

If `server.auth.allow_unauthenticated` is `true` (development only), requests
without a token use the `policy` named in the request, or `default_policy`.

## POST /v1/verify

Verify one SQL string.

Request:

```json
{
  "sql": "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50",
  "context": { "tenant_id": "acme" },
  "policy": "analytics-agent"
}
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `sql` | string | yes | The exact SQL string to verify. |
| `context` | object | no | Context values from the caller's authenticated session: strings, integers, or arrays of those. Default `{}`. |
| `policy` | string | no | Policy name. For an authenticated caller it may be omitted; if given, it must equal the caller's pinned policy. |

Response `200 OK` with the [verdict JSON](verdict.md), for **both** allowed and
denied queries. A denial is a normal result, not an HTTP error:

```json
{
  "allowed": true,
  "reasons": [],
  "shadow_reasons": [],
  "policy": { "name": "analytics-agent", "version": "sha256:4f1c9a..." },
  "statement_kind": "select",
  "tables": ["app.orders"],
  "columns": ["app.orders.id", "app.orders.status", "app.orders.tenant_id"],
  "bind_params": [ { "param": 1, "value": "acme" } ],
  "fingerprint": "0a9d55c2e1f04b7c",
  "sql_sha256": "5e8f...",
  "elapsed_us": 94
}
```

Errors use HTTP status codes and a JSON body:

```json
{ "error": { "code": "UNAUTHORIZED", "message": "missing bearer token" } }
```

| Status | `error.code` | When |
|---|---|---|
| `400` | `BAD_REQUEST` | Body is not JSON, `sql` is missing or not a string, or `context` is invalid. |
| `401` | `UNAUTHORIZED` | Missing or invalid bearer token, or a JWT rejected by its OIDC provider (expired, wrong audience, bad signature, ...; the message says why). Sent with a `WWW-Authenticate: Bearer` header. |
| `403` | `FORBIDDEN` | The requested `policy` is not the caller's pinned policy. |
| `403` | `CONTEXT_NOT_ALLOWED` | The body's `context` sets a field the caller's OIDC or mTLS identity does not allow (see [Authentication](#authentication)). |
| `404` | `POLICY_NOT_FOUND` | The request names an unknown policy, or names none and no default policy is configured. |
| `404` | `NOT_FOUND` | Unknown path. |
| `405` | `METHOD_NOT_ALLOWED` | Wrong HTTP method (with an `Allow` header). |
| `413` | `PAYLOAD_TOO_LARGE` | Body exceeds `limits.max_request_bytes`. Checked before authentication, so an oversized request gets `413` even without a token. The connection is then closed. |
| `500` | `INTERNAL` | Unexpected server error. |
| `503` | `NOT_READY` | No policy is loaded. |
| `503` | `POLICY_UNAVAILABLE` | The token's pinned policy is not currently loaded. |
| `503` | `AUDIT_UNAVAILABLE` | The audit record could not be written, so the request is refused (fail closed). |
| `503` | `AUTH_UNAVAILABLE` | The OIDC provider's signing keys could not be fetched and no usable cached keys remain (fail closed; sent with `Retry-After`). The response carries a generic message; the underlying fetch error is logged server-side with the request ID. |

Every response carries an `X-Request-Id` header. Send your own `X-Request-Id`
to correlate logs; otherwise the server generates one.

Clients must treat **any** non-200 response, timeout, or connection error as a
denial (fail closed).

Example:

```sh
curl -sS http://127.0.0.1:8080/v1/verify \
  -H "Authorization: Bearer $HALTSQL_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sql":"SELECT id FROM orders LIMIT 10","context":{"tenant_id":"acme"}}'
```

## GET /v1/policies

List the policies the caller may use: with a token, only its pinned policy;
in unauthenticated development mode, every loaded policy.

```json
{
  "policies": [
    { "name": "analytics-agent", "version": "sha256:4f1c9a...", "mode": "enforce" }
  ]
}
```

## GET /v1/admin/status

Only when [`server.admin`](config-reference.md#serveradmin) is enabled
(otherwise `404 NOT_FOUND`). The caller must authenticate (`401`) and be
listed in `server.admin.callers` (`403 FORBIDDEN` otherwise): a
`token:<name>` entry matches that static token, `oidc:<provider>` any token
verified by that provider, and `mtls:<spiffe-id or CN>` the configured mTLS
identity the client certificate matched. Anonymous callers never match.

```json
{
  "version": "0.1.0",
  "started": "2026-11-07T09:12:03.120Z",
  "uptime_seconds": 5400,
  "config_generation": 3,
  "default_policy": null,
  "policies": [
    { "name": "remote-saas", "version": "sha256:4f1c9a...", "mode": "enforce", "origin": "bundle_source" }
  ],
  "bundle_sources": [
    {
      "source": "oci:ghcr.io/corp/haltsql-policies:prod",
      "current": { "bundle": "prod", "version": "1.4.0", "signed_by": "sha256:a1b2c3d4...",
                   "revision": "sha256:9c0e...", "origin": "source", "policies": ["remote-saas"] },
      "checks": 87, "last_success": "2026-11-07T10:42:01.004Z", "last_error": null
    }
  ],
  "audit_sinks": [ { "name": "kafka://kafka-1:9093/haltsql.audit", "type": "kafka", "healthy": true } ],
  "audit_restart_pending": false,
  "opa": { "host": "127.0.0.1", "decision_path": "haltsql/decision", "timeout_ms": 500, "on_error": "deny" },
  "report": { "tracked_queries": 412, "evicted_queries": 0, "sampled_out": 1290 }
}
```

`origin` is `config` (a policy in the config file), `bundle_source`, or
`bundle_or_file` (a local bundle or a `--policy` file).
`audit_restart_pending` is `true` when the last reload changed `audit.sinks`:
audit sinks are opened once at startup, so records keep going to the listed
running sinks until a restart (the reload also logs a warning). `last_error` carries
the stable bundle-source code and message
([policy-bundles.md](policy-bundles.md#what-the-poller-does)). Header values
and credentials are never included.

## GET /v1/admin/report

Shadow-mode analytics over the server's recent verdicts, with policy
suggestions. Same authorization as `/v1/admin/status`. The query parameters
(`since`, `policy`, `suggest`, `top`) and the response are described in
[shadow-reports.md](shadow-reports.md#server-endpoint-get-v1adminreport).
Every verdict whose audit record was written is fed into the report window.

## GET /healthz

Liveness. Returns `200 {"status":"ok"}` while the process is running. Also
accepts `HEAD`.

## GET /readyz

Readiness. Returns `200 {"status":"ready","policies":N}` when at least one
policy is loaded, otherwise `503 {"status":"not_ready","policies":0}`. Also
accepts `HEAD`. A failed hot reload does not
make the server unready: the last good policies stay active.

It is also `503` while an audit sink refuses writes: an S3/GCS,
Elasticsearch/OpenSearch or Kafka sink in `fail_closed` mode after a failed
delivery, or one whose `buffer` is full. The
body then lists those sinks:
`{"status":"not_ready","policies":N,"unhealthy_audit_sinks":["s3://bucket/prefix/"]}`.
See [audit-sinks.md](audit-sinks.md).

## GET /metrics

Prometheus text format, when `telemetry.metrics.prometheus` is enabled.
Metric names (stable within `/v1`):

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `haltsql_build_info` | gauge | `version`, `pg` | Always 1; HaltSQL and Postgres grammar versions. |
| `haltsql_policies_loaded` | gauge | none | Number of loaded policies. |
| `haltsql_verify_total` | counter | `policy`, `result` (`allowed`, `denied`, `shadow_denied`) | Verify requests by outcome. |
| `haltsql_reasons_total` | counter | `code` | Denial and shadow-denial reasons, by reason code. |
| `haltsql_verify_duration_seconds` | histogram | none | Time spent verifying one SQL string. |
| `haltsql_policy_reload_total` | counter | `result` | Policy reload attempts. |
| `haltsql_audit_errors_total` | counter | none | Audit sink write failures. |
| `haltsql_http_requests_total` | counter | `route`, `status` | HTTP requests. |
| `haltsql_auth_total` | counter | `method` (`token`, `oidc`, `mtls`, `anonymous`, `none`), `result` (`ok`, `rejected`, `unavailable`) | Caller authentication attempts. |
| `haltsql_tls_reload_total` | counter | `result` | TLS certificate reload attempts. |
| `haltsql_opa_decisions_total` | counter | `outcome` (`skipped`, `allowed`, `denied`, `error_allowed`, `error_denied`) | OPA checks, when `opa` is configured ([opa.md](opa.md)). |
| `haltsql_opa_duration_seconds` | summary | none | Time spent waiting for OPA (requests actually sent). |
| `haltsql_admin_requests_total` | counter | `endpoint` (`status`, `report`), `result` (`ok`, `unauthenticated`, `forbidden`, `disabled`) | Admin API requests. |
| `haltsql_bundle_source_healthy` | gauge | `source` | 1 when the last poll of the bundle source succeeded. |
| `haltsql_bundle_source_checks_total` | counter | `source` | Completed polls of the bundle source. |

S3/GCS sinks add the `haltsql_audit_sink_*` metrics and Elasticsearch/Kafka
sinks the `haltsql_audit_stream_sink_*` metrics described in
[audit-sinks.md](audit-sinks.md).

Alert on any increase of `haltsql_reasons_total{code="E_INTERNAL"}`,
`haltsql_audit_errors_total`, `haltsql_opa_decisions_total{outcome="error_denied"}`,
`haltsql_bundle_source_healthy == 0`, and failed policy reloads.

## Operational notes

- **Request size:** keep requests under `limits.max_request_bytes` (default
  1 MiB). The policy's `limits.max_bytes` (default 16 KiB) applies to the SQL
  itself and gives `E_LIMIT`.
- **Hot reload:** `SIGHUP`, or file watching (`--watch` / `reload.watch`,
  polled every 2 seconds), reloads policies, tokens, OIDC and mTLS settings,
  `opa`, `server.admin` and TLS material atomically (OIDC key caches of
  unchanged providers are kept). Enabling or disabling TLS, the audit sinks
  and the list of bundle sources need a restart
  ([config-reference.md](config-reference.md#reload)).
  Invalid policies are rejected and the last good set stays active.
- **Audit:** each request produces an audit event with the caller (token
  name, `oidc:<provider>` or `mtls:<subject>`), `caller_type` (`token`,
  `oidc`, `mtls`, `anonymous`), `subject` (OIDC `sub`, SPIFFE ID or
  certificate CN; `null` for static tokens), policy version, fingerprint, SQL
  hash, verdict, and reason codes. Raw tokens are never logged. Raw SQL is
  logged only if `audit.log_raw_sql` is enabled.
- **Audit is fail-closed:** if an audit sink cannot be written, `/v1/verify`
  returns `503 AUDIT_UNAVAILABLE` instead of a verdict.
- **TLS:** `server.tls` enables built-in TLS 1.2/1.3 (ECDHE + AEAD ciphers
  only; `min_version: "1.3"` for TLS 1.3 only) with optional or required
  client certificates. `SIGHUP` or file watching reloads the certificate,
  key and client CA without dropping the listener; a broken or mismatched
  key keeps the previous material. Without `server.tls`, keep the listener on
  `127.0.0.1` inside the agent's pod, or terminate TLS in a proxy or service
  mesh in front of it.
