# Python SDK

The `haltsql` package (in [`clients/python`](../clients/python)) is the official
Python client for `haltsql-server`. It needs Python 3.9 or newer and depends
only on `httpx`; guarded execution uses psycopg 3 or asyncpg if you install
them.

```sh
pip install 'haltsql[psycopg]'   # or [asyncpg], or plain haltsql
```

On Linux (manylinux_2_28, x86_64 and aarch64) and macOS arm64, `pip install haltsql`
also installs the compiled verification engine, so you can verify in-process
with no sidecar: see [In-process verification](#in-process-verification-bundled-engine).

## The rules it enforces for you

1. **Fail closed.** A verdict is returned only when the sidecar answered `200`
   with a well-formed verdict for exactly the SQL that was sent (its
   `sql_sha256` is checked). Timeouts, connection errors, 4xx/5xx responses, and
   malformed bodies raise. No code path turns an error into "allowed".
2. **Context from your session.** Every API takes the context from you; nothing
   reads it from the model.
3. **Run the verified string.** The guarded executors send the same `str` they
   verified to the driver with `verdict.bind_args()` as `$n` parameters.

## Clients

```python
from haltsql import HaltSQLClient, AsyncHaltSQLClient, RetryPolicy

hs = HaltSQLClient(
    "http://127.0.0.1:8080",
    token=os.environ["HALTSQL_TOKEN"],
    timeout=2.0,                                  # seconds, per attempt
    retry=RetryPolicy(max_attempts=3, backoff_base=0.05, backoff_max=1.0),
)
verdict = hs.verify(sql, {"tenant_id": tenant})   # allowed or denied verdict
verdict = hs.check(sql, {"tenant_id": tenant})    # raises QueryDenied if denied
hs.policies()   # [PolicyInfo(name, version, mode)]
hs.healthz(); hs.readyz(); hs.is_ready()
```

`HaltSQLClient.from_env()` reads `HALTSQL_URL` (default
`http://127.0.0.1:8080`), `HALTSQL_TOKEN`, `HALTSQL_TIMEOUT` (seconds),
`HALTSQL_POLICY`, and for TLS `HALTSQL_CA_FILE`, `HALTSQL_CLIENT_CERT` and
`HALTSQL_CLIENT_KEY` (see below). Keyword arguments to `from_env(...)` override
the environment. `AsyncHaltSQLClient` has the same methods as coroutines
(`async with AsyncHaltSQLClient.from_env() as hs: ...`).

Optional arguments: `policy=` (default policy name to send), `request_id=` on
`verify`/`check` (sent as `X-Request-Id`, at most 200 printable characters;
the response's id is in `verdict.request_id`), `transport=` / `http_client=`
(custom `httpx` setup), `verify_sql_hash=` (default `True`; leave it on).

### Production settings

| Argument | Default | Notes |
|---|---|---|
| `timeout` | `2.0` s | Per attempt (connect, read, write and pool each). An `httpx.Timeout` is accepted. The worst case for one call is about `max_attempts * timeout` plus the backoff delays. |
| `retry` | `RetryPolicy(max_attempts=3, backoff_base=0.05, backoff_max=1.0, jitter=True)` | `max_attempts=1` disables retries. |
| `verify` | `True` (system CAs) | A CA bundle path for a private CA, or an `ssl.SSLContext`. `False` turns certificate checks off: local testing only. |
| `cert` | none | Client certificate for mutual TLS: one PEM file with certificate and key, or `(cert_file, key_file)`. |
| `max_response_bytes` | 8 MiB | A larger response raises `HaltSQLUnavailable`. |

```python
hs = HaltSQLClient(
    "https://haltsql.internal:8443",
    token=os.environ["HALTSQL_TOKEN"],
    verify="/etc/haltsql/ca.crt",                         # private CA
    cert=("/etc/haltsql/client.crt", "/etc/haltsql/client.key"),  # mTLS
)
```

- **Secrets.** The token is never included in `repr()`, in exception messages,
  or in exception chains (`httpx` errors, which carry the request headers, are
  not chained; only their type name is reported).
- **Redirects** are never followed; a 3xx is an error.
- **Proxies.** `httpx` honours `HTTPS_PROXY` / `NO_PROXY` from the environment.
  For anything else (custom proxies, HTTP/2, pool limits), build your own
  `httpx.Client` and pass `http_client=`; then configure TLS on it, since
  `verify=` / `cert=` cannot be combined with `http_client=`.
- **Sharing.** A `HaltSQLClient` holds a pool of keep-alive connections and is
  safe to share between threads; create one at startup and `close()` it at
  shutdown (or use it as a context manager). Use one `AsyncHaltSQLClient` per
  event loop.

### Errors

| Exception | When | Retried |
|---|---|---|
| `QueryDenied` | The policy denied the query (`check`, `guard.*`). `e.verdict` has the reasons. | no |
| `HaltSQLUnavailable` | Connection error, TLS failure, timeout, HTTP 3xx/5xx, oversized, malformed or mismatched response. `status`, `code`, `request_id` when known. | connection errors, timeouts, 502/503/504 |
| `HaltSQLRequestError` | HTTP 4xx: `UNAUTHORIZED`, `FORBIDDEN`, `POLICY_NOT_FOUND`, `BAD_REQUEST`, `PAYLOAD_TOO_LARGE`. | no |
| `GuardError` | The guarded executor refused (unsupported connection, connection already in a transaction). | no |

All derive from `HaltSQLError`; catching it and carrying on means treating
the query as denied. Retries back off exponentially with jitter and honour
`Retry-After` up to `backoff_max`. Verification is idempotent (it has no side
effects on the server), so a retried `POST /v1/verify` is safe. `/healthz` and
`/readyz` are never retried, so a probe reports the current state.

## Verdicts

`Verdict`, `Reason`, `BindParam`, and `PolicyRef` mirror
[verdict.md](verdict.md) as frozen dataclasses (`reasons`, `tables`, ... are
tuples). Unknown fields are ignored and kept in `verdict.raw`.

```python
verdict.allowed          # bool
verdict.codes            # ["E_TENANT_MISSING", ...]
verdict.reasons[0].hint  # text an agent can follow
verdict.bind_args()      # ["acme"] or [["acme", "acme-eu"]] for tenant sets
verdict.matches_sql(sql) # SHA-256 check
```

`bind_args()` returns the values for `$1..$n` in order and keeps tenant sets
as Python lists (bound as Postgres arrays by psycopg and asyncpg). It raises
`QueryDenied` on a denied verdict and `ValueError` if the placeholders are not
exactly `$1..$n`.

## Guarded execution

```python
from haltsql import guard

result = guard.execute(conn, sql, {"tenant_id": tenant}, verifier=hs,
                       statement_timeout_ms=5000, max_rows=500,
                       settings={"app.tenant_id": tenant})
result.columns, result.rows, result.rowcount, result.truncated, result.verdict
```

| Function | Connection |
|---|---|
| `guard.execute(conn, sql, ctx, ...)` | `psycopg.Connection` (psycopg 3.2+) |
| `await guard.execute_async(conn, sql, ctx, ...)` | `asyncpg.Connection` or `psycopg.AsyncConnection` |
| `guard.execute_on_engine(engine, sql, ctx, ...)` | SQLAlchemy engine with `postgresql+psycopg://` |

Steps: verify (or take a `verdict=` from `guard.authorize`), check it allows
this exact string, open a transaction, `SET TRANSACTION READ ONLY` (default
for `select` verdicts; pass `read_only=False` for write policies), apply
`statement_timeout_ms` and `settings` with `set_config(name, value, true)`,
then send the SQL unchanged (psycopg `RawCursor`, asyncpg prepared statement)
with `verdict.bind_args()`.

- Denied or unverifiable queries raise before the connection is touched.
  `guard.authorize(sql, ctx, verifier=...)` verifies without a connection, so
  you can verify before taking one from a pool and pass `verdict=` later.
- The connection must be idle (not inside a transaction) when `read_only`,
  `statement_timeout_ms`, or `settings` apply; otherwise `GuardError`. With
  psycopg's default (autocommit off), call `conn.rollback()` or `conn.commit()`
  after your own statements.
- `verifier=` defaults to a client built from the environment. `Guard(verifier,
  **defaults)` binds a verifier and defaults once.
- `max_rows` limits what is returned, not what the server computes; keep
  `require_limit` in the policy.

`psycopg2` cannot send `$n` SQL unchanged and is refused.

## Local mode (no sidecar)

```python
from haltsql import LocalVerifier, AsyncLocalVerifier

lv = LocalVerifier("policy.yaml", binary="/usr/local/bin/haltsql", timeout=30)
lv.verify(sql, ctx)                      # one verdict
lv.verify_many([(sql1, ctx), (sql2, ctx)])  # one process for many
```

Each call runs `haltsql verify --policy FILE --batch` and exchanges JSONL over
stdin/stdout (the SQL never appears on a command line). The binary defaults to
`$HALTSQL_BIN`, then the CLI bundled in a platform wheel, then `haltsql` on
`PATH`. A missing binary, timeout, non-zero exit,
or malformed line raises `HaltSQLUnavailable`. Local verifiers work anywhere a
verifier is accepted (`guard.*`, integrations, `haltsql-mcp`).

## In-process verification (bundled engine)

Platform wheels ship the engine itself: `haltsql/_native/libhaltsql.so` (the OCaml
analyzer and the PostgreSQL parser in one self-contained shared library) and the
`haltsql` CLI, which pip also puts on `PATH`. Wheels exist for
**manylinux_2_28 x86_64 / aarch64** and **macOS arm64**; anywhere else pip falls
back to the pure-Python wheel (HTTP client and `LocalVerifier` only).

```python
from haltsql import NativeVerifier, AsyncNativeVerifier

hs = NativeVerifier("policy.yaml")          # or NativeVerifier(policy=doc, policy_format="json")
hs.backend                                  # "library" (in-process) or "process"
verdict = hs.verify(sql, {"tenant_id": tenant})
verdict = hs.check(sql, {"tenant_id": tenant})   # raises QueryDenied
hs.verify_many([(sql1, ctx), (sql2, ctx)])
hs.policy_info()   # {"name": ..., "version": "sha256:...", "mode": "enforce" | "shadow"}
hs.close()         # or: with NativeVerifier(...) as hs: ...

guard.execute(conn, sql, ctx, verifier=hs)  # works anywhere a verifier is accepted
```

`AsyncNativeVerifier` takes the same arguments and has the same methods as
coroutines (calls run in a worker thread; `async with` closes it).

| Backend | How | Cost per call |
|---|---|---|
| `"library"` | `libhaltsql` loaded with ctypes, in-process. ctypes releases the GIL; the library serializes calls, so one verifier can be shared by all threads. | ~0.05-0.15 ms |
| `"process"` | One long-lived `haltsql verify --batch` child, one request at a time over pipes. | ~0.15 ms |
| `LocalVerifier` (for comparison) | A new CLI process per call. | ~20 ms |

`backend="auto"` (default) uses the library if it loads, else the process
backend, else raises `HaltSQLUnavailable` saying what to install;
`hs.fallback_reason` says why the library was not used. Other arguments:
`base_dir=` (resolves a relative `catalog:` in an in-memory policy; default the
current directory), `binary=`, `timeout=` (per request, process backend; default
30 s), `verify_sql_hash=` (leave it on).

| Variable | Effect |
|---|---|
| `HALTSQL_LIB` | Use this `libhaltsql` instead of the bundled one (no silent fallback to the bundled copy if it fails to load). |
| `HALTSQL_BIN` | Use this CLI for the process backend and `LocalVerifier`. |
| `HALTSQL_NATIVE` | With `backend="auto"` only: `0` forces the process backend, `library` forces the library. |

**Fail closed.** A NULL result, unparseable output, a malformed verdict or one
whose `sql_sha256` does not match, an ABI mismatch, or a crashed, hung (past
`timeout`) or garbled child raises `HaltSQLUnavailable`; a request the engine
rejects raises `HaltSQLRequestError` (`BAD_REQUEST`); a policy that cannot be
loaded raises `ValueError` with the engine's message. After `close()`, every
method raises `HaltSQLUnavailable`. SQL is passed with its length, so a NUL byte
is denied (`E_PARSE`) rather than truncating the string. The process backend
kills a misbehaving child; the next call starts a new one (a child found dead
between calls is replaced transparently).

**fork().** The OCaml runtime inside the library does not survive `fork()`.
Create verifiers *after* forking (gunicorn: in `post_fork`; multiprocessing:
in the worker, or use the `spawn` start method). If a process uses the library
and then forks, the child gets `HaltSQLUnavailable` (never a crash) when it
calls it, and `backend="auto"` in the child picks the process backend.

Build a platform wheel yourself with `clients/python/scripts/build_wheel.sh`
(see `--help`).

## Testing your code

`haltsql.testing` has `FakeSidecar` (an in-process HTTP server with scripted
responses: `push(503)`, delays, raw bodies), `FakeVerifier`, `make_verdict`,
and `temporary_database()` (a throwaway database on the lab Postgres). Use them
in tests only.

## Integrations

- MCP server: [mcp.md](mcp.md)
- LangChain: [`integrations/langchain`](../integrations/langchain)
- LlamaIndex: [`integrations/llamaindex`](../integrations/llamaindex)
- Vanna: [`integrations/vanna`](../integrations/vanna)

## Running the SDK's own tests

```sh
cd clients/python
python3 -m venv .venv && .venv/bin/pip install -e '.[psycopg,asyncpg,test]'
.venv/bin/pytest -q
```

Integration tests (marked `integration`) use the binaries in
`_build/default/bin` (or `HALTSQL_BIN` / `HALTSQL_SERVER_BIN`), the shared
[test vectors](../clients/testvectors), and the lab Postgres on port 5417. They
skip when those are unavailable. The `native` tests use
`_build/default/native/libhaltsql.so` (or `HALTSQL_LIB`); `HALTSQL_REQUIRE_NATIVE=1`
makes a missing engine fail instead of skip, and `HALTSQL_WHEEL=dist/haltsql-*.whl`
installs that wheel into a fresh venv and checks it.
