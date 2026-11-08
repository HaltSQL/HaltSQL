# Go SDK

`github.com/ardada2468/HaltSQL/clients/go/haltsql` is a client for the
[HTTP sidecar](http-api.md) that uses **only the standard library**
(`net/http`, `database/sql`). Go 1.21 or newer.

Source: [`clients/go/haltsql`](../clients/go/haltsql).

## Install

```sh
go get github.com/ardada2468/HaltSQL/clients/go/haltsql
```

## Verify a query

```go
hc, err := haltsql.New("http://127.0.0.1:8080",
    haltsql.WithToken(os.Getenv("HALTSQL_TOKEN")), // pinned to one policy on the server
    haltsql.WithTimeout(2*time.Second))
if err != nil {
    log.Fatal(err)
}

verdict, err := hc.Verify(ctx,
    "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50",
    haltsql.Context{"tenant_id": session.TenantID}) // from the session, never the prompt
if err != nil {
    return err // fail closed: do not run the query
}
if !verdict.Allowed {
    return deny(verdict.Reasons) // Code, Message, Hint for the agent
}
```

Run SQL only when `err == nil && verdict.Allowed`.

## Run it with database/sql (pgx)

`GuardedQuery` / `GuardedExec` verify the SQL and, only if it is allowed, run
**exactly that string** with any `database/sql` handle (`*sql.DB`, `*sql.Tx`,
`*sql.Conn`), binding the verdict's bind params as `$1..$n`:

```go
import (
    "github.com/ardada2468/HaltSQL/clients/go/haltsql"
    _ "github.com/jackc/pgx/v5/stdlib"
)

db, _ := sql.Open("pgx", os.Getenv("DATABASE_URL"))

rows, verdict, err := haltsql.GuardedQuery(ctx, hc, db, sqlFromModel,
    haltsql.Context{"tenant_id": session.TenantID},
    haltsql.OnVerdict(func(v *haltsql.Verdict) { audit(v.Policy.Version, v.Fingerprint, v.Allowed) }))
var denied *haltsql.DeniedError
switch {
case errors.As(err, &denied):
    return deny(denied.Verdict.Reasons) // nothing was sent to Postgres
case err != nil:
    return err // sidecar error or database error
}
defer rows.Close()
```

With pgx's `database/sql` driver:

- a scalar bind param is a Go `string`; pgx encodes it into the parameter's
  inferred type, so a tenant id binds into `text`, `bigint` or `uuid` columns
  (tested against Postgres 17 with a `bigint` tenant column);
- a set-valued bind param (hierarchical tenants, `org_id = ANY($1)`) is a
  `[]string`, sent as a Postgres array.

For drivers that cannot encode `[]string` (for example `lib/pq`), pass
`haltsql.ArrayLiteralArgs()` to bind sets as `{"a","b"}` literals.

To bind manually: `verdict.Args()` returns `[]any` in `$1..$n` order (or
`verdict.ArgsArrayLiteral()`); both return an error unless the verdict is an
allow with contiguous, unique placeholders. `haltsql.PGArrayLiteral` encodes a
`[]string`.

## Fail-closed semantics

`Verify` returns a verdict **only** for a strictly validated HTTP 200 body.
Every other outcome is an `*haltsql.Error` with a `Kind`:

| Kind | When |
|---|---|
| `KindHTTP` | Non-200 status. `Status` and `Code` (`UNAUTHORIZED`, `FORBIDDEN`, `AUDIT_UNAVAILABLE`, ... or `HTTP_<status>`). Redirects are never followed. |
| `KindTimeout` | An attempt exceeded the timeout (after retries). |
| `KindTransport` | Connection or TLS error, or the caller's context was canceled. |
| `KindProtocol` | Body is not JSON, a required field is missing or mistyped, `allowed` is true while `reasons` is not empty, the body is too large, or `sql_sha256` does not equal the SHA-256 of the SQL that was sent. |
| `KindUsage` | Bad options or arguments (float/bool context values, invalid UTF-8 SQL, a token or request id with control characters). |

`GuardedQuery` / `GuardedExec` additionally return `*haltsql.DeniedError` for a
policy denial. Helpers: `haltsql.IsDenied(err)`, `haltsql.IsKind(err, k)`.
Every error type's `Allowed()` returns `false`.

Unknown verdict fields are ignored ([compatibility
rules](verdict.md#stability-guarantees)); unknown reason codes are kept as
strings.

## Options

| Option | Default | Meaning |
|---|---|---|
| `WithToken(t)` | none | Bearer token for `/v1/*`. Never included in errors. |
| `WithTimeout(d)` | 5s | Per-attempt timeout. |
| `WithRetries(n, base, max)` | 2, 100ms, 2s | Retries on 503, connection errors and timeouts; exponential backoff with full jitter; `max` also caps `Retry-After`. |
| `WithHTTPClient(c)` | new client (`http.DefaultTransport`) | Custom transport, proxy or TLS. Copied; redirects are disabled on the copy. |
| `WithTLSConfig(cfg)` | system roots | TLS for an `https` sidecar: `RootCAs` for a private CA, `Certificates` for mutual TLS. Cloned onto a copy of `http.DefaultTransport`; refuses `InsecureSkipVerify`. Apply after `WithHTTPClient` if you use both. |
| `WithMaxResponseBytes(n)` | 8 MiB | Response size cap. |
| `WithoutSQLHashCheck()` | check on | Disable the `sql_sha256` check. |

Per call: `WithPolicy(name)`, `WithRequestID(id)` (at most 200 printable
ASCII characters, else a `KindUsage` error before anything is sent). Cancel
with the `ctx` argument; a canceled context is not retried.

Every request has a deadline (the per-attempt timeout, or the caller's `ctx`
if it is sooner) and carries `User-Agent: haltsql-client-go/<Version>`. The
worst case for one `Verify` is about `(retries + 1) * timeout` plus the
backoff delays. Only 503, connection errors and timeouts are retried
(`Ready` never is); `POST /v1/verify` has no side effects, so retrying it is
safe.

## TLS and mutual TLS

Certificate verification uses the system roots by default. For a private CA
and a client certificate:

```go
caPEM, _ := os.ReadFile("/etc/haltsql/ca.crt")
roots := x509.NewCertPool()
roots.AppendCertsFromPEM(caPEM)
clientCert, err := tls.LoadX509KeyPair("/etc/haltsql/client.crt", "/etc/haltsql/client.key")
if err != nil { ... }

hc, err := haltsql.New("https://haltsql.internal:8443",
    haltsql.WithToken(os.Getenv("HALTSQL_TOKEN")),
    haltsql.WithTLSConfig(&tls.Config{
        RootCAs:      roots,
        Certificates: []tls.Certificate{clientCert}, // mTLS
        MinVersion:   tls.VersionTLS12,
    }))
```

An untrusted certificate or a host-name mismatch is a `KindTransport` error.

## Sharing, connection reuse and secrets

- A `*Client` is safe for concurrent use. Create one per sidecar and share it:
  the underlying `http.Transport` keeps connections alive, and the SDK always
  drains and closes response bodies so they can be reused.
- The token is only placed in the `Authorization` header. It is not in any
  `Error` message (transport errors include the URL, which cannot carry
  credentials: `New` rejects a URL with user info).

Other endpoints: `Health(ctx)`, `Ready(ctx)` (a 503 returns `Ready: false` and
is not retried), `Policies(ctx)`.

## Development

```sh
cd clients/go/haltsql
go vet ./... && go test -race ./...
```

Tests use `httptest` and replay real `haltsql-server` responses from
`testdata/vectors.json`, plus a recording `database/sql` driver for the guard.

pgx integration tests live in a separate module so the SDK stays
dependency-free. They need Postgres (`make -C lab up`; `HALTSQL_PG*` variables
override the defaults), create and drop the database `haltsql_polyglot_go`,
and skip cleanly when Postgres is unreachable:

```sh
cd clients/go/pgxtest
go test ./...
```
