# TypeScript / Node.js SDK

`@haltsql/client` is a small client for the [HTTP sidecar](http-api.md). It
has **no runtime dependencies**, ships ESM and CommonJS builds with type
declarations, and needs Node.js 18 or newer (it uses the global `fetch`).

Source: [`clients/typescript`](../clients/typescript).

## Install

```sh
npm install @haltsql/client
```

On Linux x64/arm64 (glibc) and macOS arm64 this also installs the compiled
engine, so [`LocalVerifier`](#local-verification-no-sidecar) can verify SQL
locally with no sidecar.

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

`guardedTransaction` verifies the SQL and, only if it is allowed, runs
**exactly that string** with `pg` in a transaction that uses the policy's
search path, binding `verdict.bind_params` as `$1..$n`:

```ts
import pg from "pg";
import { HaltSQLClient, HaltSQLDeniedError, guardedTransaction } from "@haltsql/client";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

try {
  const { result, verdict } = await guardedTransaction(
    haltsql,
    pool, // a pg.Pool
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

On a client it checks out of the pool, `guardedTransaction` sends:

1. `BEGIN READ ONLY` when `verdict.statement_kind` is `select`, otherwise
   `BEGIN`;
2. `SELECT set_config(name, value, true)` for each entry of the `settings`
   option (for example `{ "app.tenant_id": tenantId }` for row-level security,
   or `{ statement_timeout: "5000" }`);
3. `SELECT set_config('search_path', ..., true)` with
   `verdict.policy.search_path`, each schema quoted as an identifier. This is
   the pin: the verified `orders` is the policy's `orders` whatever the role's
   or the database's default search path is. It is applied last, so a
   `search_path` in `settings` does not override it, and it is
   transaction-local, so the session's own search path is back afterwards;
4. the verified string, unchanged;
5. `COMMIT`, or `ROLLBACK` on any error (the error is rethrown and the client
   goes back to the pool).

A denied verdict, a shadow would-deny or a HaltSQL error rejects before a
client is checked out. A verdict without `policy.search_path` (an engine older
than the field) still runs, without step 3.

Which handle to pass:

| You have | Call |
|---|---|
| a `pg.Pool` | `guardedTransaction(haltsql, pool, sql, ctx, opts)`. It needs `connect()`: a transaction must stay on one session, and `pool.query` may use a different one for each statement. |
| a connected `pg.Client`, or a `PoolClient` you checked out | `guardedTransactionOnClient(haltsql, client, sql, ctx, opts)`. The client must be idle (not inside a transaction): the function sends its own `BEGIN` and `COMMIT`. A pool is refused here. |

### `guardedQuery`: one statement, no pin

`guardedQuery(haltsql, db, sql, ctx, opts)` is the low-level form. It verifies
and then makes one `db.query(sql, values)` call on a `pg.Pool`, `pg.Client` or
`PoolClient`. **It does not pin the search path** and opens no transaction.
Use it only when one of these holds:

- the session already uses the policy's search path: you set it on the
  connection (`options: "-c search_path=app"`), the role or the database; or
- the SQL names every table with its schema (`app.orders`).

Otherwise a default such as `ALTER ROLE ... SET search_path = public, app` can
make a verified `orders` read `public.orders`. It is also the form to use
inside a transaction you manage yourself; pin the search path there with
`SELECT set_config('search_path', $1, true)` and `searchPathSetting(verdict)`.

`pg` is not a dependency of the SDK: the helpers accept anything with the
methods they call (`connect()` resolving to a client with `query` and
`release`; or `query(text, values)`). A set-valued bind param (hierarchical
tenants, `org_id = ANY($1)`) is passed as a JS `string[]`, which node-postgres
sends as a Postgres array.

To bind manually, use `bindParamsToPositional(verdict)`; it returns the values
in `$1..$n` order and throws unless the verdict is an allow with contiguous,
unique placeholders. `toPgArrayLiteral(values)` encodes a `string[]` as
`{"a","b"}` for drivers that need a literal.

## Local verification (no sidecar)

`LocalVerifier` verifies SQL on the same machine with the compiled `haltsql`
engine, so a Node.js service or agent needs no sidecar at all:

```ts
import { LocalVerifier } from "@haltsql/client";

const haltsql = await LocalVerifier.create({ policyFile: "policies/saas.yaml" });

const verdict = await haltsql.verify(sqlFromModel, { tenant_id: session.tenantId });
if (verdict.allowed) { /* run exactly sqlFromModel, binding verdict.bind_params */ }

await haltsql.check(sql, ctx);                         // throws HaltSQLDeniedError unless allowed
const verdicts = await haltsql.verifyMany([a, b], ctx); // pipelined, input order
await guardedTransaction(haltsql, pool, sql, ctx);     // same helper as with HaltSQLClient

await haltsql.close(); // or: await using haltsql = await LocalVerifier.create(...)
```

**Zero setup on supported platforms.** The engine ships in per-platform npm
packages that `@haltsql/client` lists as `optionalDependencies` (the same
scheme esbuild uses); npm installs only the one matching the machine:

| Platform | Package |
|---|---|
| Linux x64, glibc | `@haltsql/native-linux-x64` |
| Linux arm64, glibc | `@haltsql/native-linux-arm64` |
| macOS arm64 (Apple silicon) | `@haltsql/native-darwin-arm64` |

Each package holds `bin/haltsql` (the CLI the client runs), `lib/libhaltsql`
(the same engine as a C shared library, `include/haltsql.h`; reserved for a
future in-process binding) and the licenses. On other platforms (musl/Alpine,
macOS x64, Windows), with `npm install --omit=optional`, or with Yarn PnP
setups that drop optional packages, build or download `haltsql` yourself and
point `HALTSQL_BIN` at it.

**Finding the engine**, in order (the first that applies wins; an explicit
choice that is not an executable file is an error, never a silent fallback):

1. the `binary` option;
2. the `HALTSQL_BIN` environment variable;
3. the installed platform package `@haltsql/native-<platform>-<arch>`;
4. `haltsql` in an absolute `PATH` directory.

If none is found the constructor throws a `HaltSQLUsageError` that names the
expected platform package. `verifier.binary` and `verifier.binarySource`
(`option`, `env`, `package` or `path`) say which one was used;
`resolveLocalBinary()` runs the same lookup without starting anything.

**Options:**

```ts
new LocalVerifier({
  policyFile: "policy.yaml",  // or policy: "<YAML or JSON text>" (exactly one of the two)
  policyFormat: "yaml",       // for `policy` only; default: json if it starts with "{"
  binary: "/opt/haltsql/bin/haltsql",
  timeoutMs: 30000,           // per request, from the call to the answer
  verifySqlHash: true,        // check verdict.sql_sha256 against the SQL sent
});
```

An in-memory `policy` is written to a private temporary file (directory
`0700`, file `0600`) that `close()` removes (and, as a fallback, process exit).
Relative paths inside it, such as `catalog: ../catalogs/app.json`, would
resolve against that temporary directory, so use absolute paths there or use
`policyFile`.

`new LocalVerifier(...)` validates options and finds the binary but starts
nothing; the engine starts on the first call. `LocalVerifier.create(...)` (or
`await verifier.start()`) starts it immediately and waits for a probe answer,
so a policy that does not load fails at startup with the engine's message
(`HaltSQLUsageError: haltsql engine failed to start (policy or usage error):
haltsql: cannot load policy: ...`).

**How it works.** The engine runs as one long-lived child process,
`haltsql verify --policy=FILE --batch`, which reads one JSON request per line
on stdin and writes one verdict per line, in order, flushing each. Only the
policy path is on the command line; SQL and context only ever travel over the
pipe. Concurrent `verify()` calls are pipelined with increasing ids, and every
answer must carry the id of the oldest request in flight. An idle verifier
holds no reference on the event loop, so a script that never calls `close()`
still exits (the engine sees end-of-file and exits too).

**Latency.** After the first call (process start and policy load, tens of
milliseconds) a sequential `verify()` costs roughly 0.1-0.5 ms on a laptop:
the engine's own analysis (`elapsed_us`, typically 30-100 us) plus a pipe round
trip. Pipelined calls (`verifyMany`, or many concurrent `verify()`s) amortize
the round trip. One process verifies on one core; for heavy multi-core
throughput run [`haltsql-server`](http-api.md) and use `HaltSQLClient`.

**Fail closed.** `verify()` resolves only with a strictly validated verdict
whose `sql_sha256` equals the SHA-256 of the UTF-8 SQL that was sent.

| Situation | Result |
|---|---|
| Bad options or context, SQL that is not a string or contains a lone UTF-16 surrogate, no engine found, closed verifier | `HaltSQLUsageError` before anything is sent |
| Policy cannot be loaded (engine exits with code 2 before answering) | `HaltSQLUsageError` with the engine's stderr |
| A request takes longer than `timeoutMs` | that request: `HaltSQLTimeoutError`; the engine is killed and everything else in flight rejects with `HaltSQLTransportError` |
| The engine crashes, is killed or cannot be started | every request in flight: `HaltSQLTransportError` (with the exit status and stderr tail) |
| A line that is not JSON, an invalid verdict, an answer out of order, or a `sql_sha256` mismatch | every request in flight: `HaltSQLProtocolError`; the engine is killed |
| The engine rejects one request (`{"id":..,"error":..}`) | that request: `HaltSQLProtocolError`; the engine keeps running |
| `close()` while requests are in flight | they reject with `HaltSQLTransportError` |

After any failure that kills the engine, the next call starts a fresh one.
NUL bytes, newlines and any Unicode in SQL are safe: requests are JSON-encoded
and the engine denies a NUL byte with `E_PARSE`; SQL over the engine's size
limit is denied with `E_LIMIT`.

## Fail-closed semantics

`verify()` resolves **only** with a strictly validated verdict from an HTTP 200
response. Everything else rejects with a subclass of `HaltSQLError`, whose
`allowed` property is always `false`:

| Error | When |
|---|---|
| `HaltSQLHttpError` | Non-200 status. `status` and `code` (`UNAUTHORIZED`, `FORBIDDEN`, `POLICY_NOT_FOUND`, `AUDIT_UNAVAILABLE`, ... or `HTTP_<status>`). Redirects are never followed. |
| `HaltSQLTimeoutError` | An attempt exceeded `timeoutMs` (after retries). |
| `HaltSQLTransportError` | Connection refused/reset, DNS or TLS failure, or the caller aborted. |
| `HaltSQLProtocolError` | Body is not JSON, a required field is missing or mistyped, `allowed` is `true` while `reasons` is not empty, the body is too large, or `sql_sha256` does not equal the SHA-256 of the SQL that was sent. |
| `HaltSQLUsageError` | Bad options or arguments (a non-integer context value, a token or header with control characters, an invalid `requestId`, a denied verdict passed to `bindParamsToPositional`). |
| `HaltSQLDeniedError` | `guardedTransaction`, `guardedTransactionOnClient`, `guardedQuery` and `LocalVerifier.check`: the policy denied the SQL. `verdict` and `codes` are available. |

Unknown fields in a verdict are ignored, as the [compatibility
rules](verdict.md#stability-guarantees) require. Unknown reason codes are kept
as strings; only `allowed === true` permits running a query.

The guarded helpers reject with `HaltSQLDeniedError` for SQL that a
`mode: shadow` policy would deny, unless you pass `{ allowShadow: true }` (for
a [shadow rollout](tutorials/roll-out-a-policy-safely.md)).

**Search path.** The verdict holds only under the policy's search path
(`verdict.policy.search_path`). `guardedTransaction` and
`guardedTransactionOnClient` set it for the transaction that runs the SQL, as
the Python guard, the MCP server and `haltsql-proxy` do. `guardedQuery` runs
one statement on your connection and does not change session settings: with
it, configure the connection or role with that `search_path`, or have the
model write schema-qualified names
([when that is acceptable](#guardedquery-one-statement-no-pin)).

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
  headers: { "x-tenant-shard": "eu" }, // cannot set Authorization; CR/LF rejected
  dispatcher: agent,                // undici Dispatcher: private CA, mTLS, proxy, pool tuning
  fetch: customFetch,               // a fetch implementation; defaults to the global one
});
```

Per call: `verify(sql, context, { policy, requestId, signal })`. `requestId`
is sent as `X-Request-Id` (1-200 printable ASCII characters, else a
`HaltSQLUsageError` before anything is sent); an aborted `signal` stops
immediately without retrying.

Every request carries `User-Agent: haltsql-client-js/<VERSION>` and an
`AbortSignal` that fires after `timeoutMs`, so no call can hang. The worst
case for one `verify()` is about `(maxRetries + 1) * timeoutMs` plus the
backoff delays. Only `503`, network errors and timeouts are retried (`/readyz`
never is); `POST /v1/verify` has no side effects, so retrying it is safe.

## TLS, private CAs and mutual TLS

Certificate verification is on by default (Node's bundled CA store, plus
anything in `NODE_EXTRA_CA_CERTS`). For a private CA or a client certificate,
pass an undici `Agent` as `dispatcher`; it is forwarded to every `fetch`
call. Install `undici` yourself (the SDK has no dependencies):

```ts
import { readFileSync } from "node:fs";
import { Agent } from "undici";

const haltsql = new HaltSQLClient({
  baseUrl: "https://haltsql.internal:8443",
  token: process.env.HALTSQL_TOKEN,
  dispatcher: new Agent({
    connect: {
      ca: readFileSync("/etc/haltsql/ca.crt"),
      cert: readFileSync("/etc/haltsql/client.crt"), // mTLS
      key: readFileSync("/etc/haltsql/client.key"),
    },
  }),
});
```

A TLS failure (untrusted certificate, wrong host name) rejects with
`HaltSQLTransportError` like any other connection error.

## Secrets, sharing and lifetime

- The token is kept in a private field: it is not visible through
  `JSON.stringify`, `util.inspect`, or any error message. Errors keep the
  underlying `fetch` error as `cause` (which never contains request headers).
- One `HaltSQLClient` is safe to share across concurrent requests; create it
  once at startup. Connection reuse is handled by `fetch` (or your
  `dispatcher`).

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
  The tests create and drop their own databases (`haltsql_polyglot_ts`,
  `haltsql_polyglot_ts_tx`). With `HALTSQL_REQUIRE_POSTGRES=1` (set in CI) an
  unreachable Postgres fails the run instead of skipping these tests.
- the real sidecar binary (`_build/default/bin/server/main.exe`, or
  `HALTSQL_SERVER_BIN`).

- the real `haltsql` CLI for `LocalVerifier` (`_build/default/bin/haltsql/main.exe`,
  or `HALTSQL_BIN`): every case in `clients/testvectors/cases`, concurrency,
  crash and timeout handling (also against fake engines), the event loop not
  being held, and warm latency. They skip when the binary is missing unless
  `HALTSQL_REQUIRE_NATIVE=1`.

Platform packages are built from the compiled engine and checked end to end
(pack, offline install into a fresh project, ESM and CommonJS consumers with
no `binary` option and no `HALTSQL_BIN`):

```sh
opam exec -- dune build ./bin/haltsql/main.exe ./native/libhaltsql.so
cd clients/typescript
node scripts/build-native-package.mjs --platform linux-x64 \
  --binary ../../_build/default/bin/haltsql/main.exe \
  --lib ../../_build/default/native/libhaltsql.so --out ../../dist-native/linux-x64
npm run smoke:native   # builds and tests the package for this machine
```

`build-native-package.mjs` checks the binary and library against the target
(ELF/Mach-O, CPU) and refuses dynamic dependencies a stock system may not
have (for example Homebrew's `libgmp`); `--allow-nonsystem-deps` downgrades
that to a warning for local testing only. Publish the three platform packages
before `@haltsql/client`, all at the same version: the client pins them
exactly in `optionalDependencies`.

Regenerate the shared vectors after a server change (writes the TypeScript, Go
and Java copies):

```sh
eval $(opam env); dune build ./bin/server/main.exe
node clients/typescript/scripts/gen-testvectors.mjs
```
