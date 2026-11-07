# TypeScript / Node.js SDK

`@haltsql/client` is a small client for the [HTTP sidecar](http-api.md). It
has **no runtime dependencies**, ships ESM and CommonJS builds with type
declarations, and needs Node.js 18 or newer (it uses the global `fetch`).

Source: [`clients/typescript`](../clients/typescript).

## Install

```sh
npm install @haltsql/client
```

## Verify a query

```ts
import { HaltSQLClient } from "@haltsql/client";

const haltsql = new HaltSQLClient({
  baseUrl: "http://127.0.0.1:8080",
  token: process.env.HALTSQL_TOKEN, // pinned to one policy on the server
});

const verdict = await haltsql.verify(
  "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50",
  { tenant_id: session.tenantId }, // from the authenticated session, never from the prompt
);

if (!verdict.allowed) {
  // Give the reasons back to the agent so it can fix its query.
  return verdict.reasons.map((r) => ({ code: r.code, message: r.message, hint: r.hint }));
}
```

CommonJS works the same way: `const { HaltSQLClient } = require("@haltsql/client")`.

## Run it with node-postgres

`guardedQuery` verifies the SQL and, only if it is allowed, runs **exactly
that string** with `pg`, binding `verdict.bind_params` as `$1..$n`:

```ts
import pg from "pg";
import { HaltSQLClient, HaltSQLDeniedError, guardedQuery } from "@haltsql/client";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

try {
  const { result, verdict } = await guardedQuery(
    haltsql,
    pool, // a pg.Pool, pg.Client or PoolClient
    sqlFromModel,
    { tenant_id: session.tenantId },
    { onVerdict: (v) => audit.log({ policy: v.policy.version, fp: v.fingerprint, allowed: v.allowed }) },
  );
  return result.rows;
} catch (e) {
  if (e instanceof HaltSQLDeniedError) return { denied: e.codes, reasons: e.verdict.reasons };
  throw e; // sidecar unreachable, timeout, ... : nothing ran
}
```

`pg` is not a dependency of the SDK: `guardedQuery` accepts anything with a
`query(text, values)` method. A set-valued bind param (hierarchical tenants,
`org_id = ANY($1)`) is passed as a JS `string[]`, which node-postgres sends as
a Postgres array.

To bind manually, use `bindParamsToPositional(verdict)`; it returns the values
in `$1..$n` order and throws unless the verdict is an allow with contiguous,
unique placeholders. `toPgArrayLiteral(values)` encodes a `string[]` as
`{"a","b"}` for drivers that need a literal.

## Fail-closed semantics

`verify()` resolves **only** with a strictly validated verdict from an HTTP 200
response. Everything else rejects with a subclass of `HaltSQLError`, whose
`allowed` property is always `false`:

| Error | When |
|---|---|
| `HaltSQLHttpError` | Non-200 status. `status` and `code` (`UNAUTHORIZED`, `FORBIDDEN`, `POLICY_NOT_FOUND`, `AUDIT_UNAVAILABLE`, ... or `HTTP_<status>`). Redirects are never followed. |
| `HaltSQLTimeoutError` | An attempt exceeded `timeoutMs` (after retries). |
| `HaltSQLTransportError` | Connection refused/reset, DNS failure, or the caller aborted. |
| `HaltSQLProtocolError` | Body is not JSON, a required field is missing or mistyped, `allowed` is `true` while `reasons` is not empty, the body is too large, or `sql_sha256` does not equal the SHA-256 of the SQL that was sent. |
| `HaltSQLUsageError` | Bad options or arguments (a non-integer context value, a token with control characters, a denied verdict passed to `bindParamsToPositional`). |
| `HaltSQLDeniedError` | `guardedQuery` only: the policy denied the SQL. `verdict` and `codes` are available. |

Unknown fields in a verdict are ignored, as the [compatibility
rules](verdict.md#stability-guarantees) require. Unknown reason codes are kept
as strings; only `allowed === true` permits running a query.

## Options

```ts
new HaltSQLClient({
  baseUrl: "http://127.0.0.1:8080", // http or https; no credentials in the URL
  token: "...",                     // sent only to /v1/*; never included in errors
  timeoutMs: 5000,                  // per attempt
  maxRetries: 2,                    // on 503, network errors and timeouts
  retryBaseDelayMs: 100,            // exponential backoff with full jitter
  retryMaxDelayMs: 2000,            // also caps Retry-After
  maxResponseBytes: 8 << 20,
  checkSqlHash: true,
  headers: { "x-tenant-shard": "eu" },
  fetch: customFetch,               // e.g. undici with a custom dispatcher
});
```

Per call: `verify(sql, context, { policy, requestId, signal })`. `requestId`
is sent as `X-Request-Id`; an aborted `signal` stops immediately without
retrying.

Other endpoints: `health()` (`GET /healthz`), `ready()` (`GET /readyz`; a 503
resolves `{ ready: false }` and is not retried), and `policies()`
(`GET /v1/policies`).

## Development

```sh
cd clients/typescript
npm ci
npm test            # builds ESM + CJS with tsc, then runs node:test
```

The tests replay real `haltsql-server` responses from
`testdata/vectors.json` against a local fake server, and run integration tests
that skip cleanly when their dependency is missing:

- node-postgres against Postgres 17 (`make -C lab up`; override with
  `HALTSQL_PGHOST`, `HALTSQL_PGPORT`, `HALTSQL_PGUSER`, `HALTSQL_PGPASSWORD`).
  The test creates and drops its own database `haltsql_polyglot_ts`.
- the real sidecar binary (`_build/default/bin/server/main.exe`, or
  `HALTSQL_SERVER_BIN`).

Regenerate the shared vectors after a server change (writes the TypeScript, Go
and Java copies):

```sh
eval $(opam env); dune build ./bin/server/main.exe
node clients/typescript/scripts/gen-testvectors.mjs
```
