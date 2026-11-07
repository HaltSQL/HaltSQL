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

Requests to `/v1/*` carry a bearer token:

```
Authorization: Bearer <token>
```

The server stores only the SHA-256 of each token (`token_sha256` in the
config). **Each token is pinned to exactly one policy**, so a caller cannot pick
a looser policy than the one it was given. Health, readiness, and metrics
endpoints do not require a token; restrict them at the network level if needed.

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
| `policy` | string | no | Policy name. With a token, it may be omitted; if given, it must equal the token's pinned policy. |

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
| `401` | `UNAUTHORIZED` | Missing or invalid bearer token (with a `WWW-Authenticate: Bearer` header). |
| `403` | `FORBIDDEN` | The requested `policy` is not the token's pinned policy. |
| `404` | `POLICY_NOT_FOUND` | The request names an unknown policy, or names none and no default policy is configured. |
| `404` | `NOT_FOUND` | Unknown path. |
| `405` | `METHOD_NOT_ALLOWED` | Wrong HTTP method (with an `Allow` header). |
| `413` | `PAYLOAD_TOO_LARGE` | Body exceeds `server.max_request_bytes`. |
| `500` | `INTERNAL` | Unexpected server error. |
| `503` | `NOT_READY` | No policy is loaded. |
| `503` | `POLICY_UNAVAILABLE` | The token's pinned policy is not currently loaded. |
| `503` | `AUDIT_UNAVAILABLE` | The audit record could not be written, so the request is refused (fail closed). |

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

## GET /healthz

Liveness. Returns `200 {"status":"ok"}` while the process is running. Also
accepts `HEAD`.

## GET /readyz

Readiness. Returns `200 {"status":"ready","policies":N}` when at least one
policy is loaded, otherwise `503 {"status":"not_ready","policies":0}`. Also
accepts `HEAD`. A failed hot reload does not
make the server unready: the last good policies stay active.

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

Alert on any increase of `haltsql_reasons_total{code="E_INTERNAL"}`,
`haltsql_audit_errors_total`, and failed policy reloads.

## Operational notes

- **Request size:** keep requests under `server.max_request_bytes` (default
  1 MiB). The policy's `limits.max_bytes` (default 16 KiB) applies to the SQL
  itself and gives `E_LIMIT`.
- **Hot reload:** `SIGHUP`, or file watching (`--watch` / `reload.watch`,
  polled every 2 seconds), reloads policies atomically.
  Invalid policies are rejected and the last good set stays active.
- **Audit:** each request produces an audit event with the token name, policy
  version, fingerprint, SQL hash, verdict, and reason codes. Raw SQL is logged
  only if `audit.log_raw_sql` is enabled.
- **Audit is fail-closed:** if an audit sink cannot be written, `/v1/verify`
  returns `503 AUDIT_UNAVAILABLE` instead of a verdict.
- **TLS is not built into `haltsql-server` in 0.1.0.** Keep the listener on
  `127.0.0.1` inside the same pod as the agent, or terminate TLS in a proxy or
  service mesh in front of it.
