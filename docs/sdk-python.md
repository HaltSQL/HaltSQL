# Python SDK

The `haltsql` package (in [`clients/python`](../clients/python)) is the official
Python client for `haltsql-server`. It needs Python 3.9 or newer and depends
only on `httpx`; guarded execution uses psycopg 3 or asyncpg if you install
them.

```sh
pip install 'haltsql[psycopg]'   # or [asyncpg], or plain haltsql
```

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
`http://127.0.0.1:8080`), `HALTSQL_TOKEN`, `HALTSQL_TIMEOUT` (seconds), and
`HALTSQL_POLICY`. `AsyncHaltSQLClient` has the same methods as coroutines
(`async with AsyncHaltSQLClient.from_env() as hs: ...`).

Optional arguments: `policy=` (default policy name to send), `request_id=` on
`verify`/`check` (sent as `X-Request-Id`; the response's id is in
`verdict.request_id`), `transport=` / `http_client=` (custom `httpx` setup).
The token is never included in `repr()` or error messages.

### Errors

| Exception | When | Retried |
|---|---|---|
| `QueryDenied` | The policy denied the query (`check`, `guard.*`). `e.verdict` has the reasons. | no |
| `HaltSQLUnavailable` | Connection error, timeout, HTTP 5xx, malformed or mismatched verdict. `status`, `code`, `request_id` when known. | connection errors, timeouts, 502/503/504 |
| `HaltSQLRequestError` | HTTP 4xx: `UNAUTHORIZED`, `FORBIDDEN`, `POLICY_NOT_FOUND`, `BAD_REQUEST`, `PAYLOAD_TOO_LARGE`. | no |
| `GuardError` | The guarded executor refused (unsupported connection, connection already in a transaction). | no |

All derive from `HaltSQLError`. Retries back off exponentially with jitter and
honour `Retry-After` up to `backoff_max`. Verification is idempotent, so a
retried `POST /v1/verify` is safe.

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
`$HALTSQL_BIN` or `haltsql` on `PATH`. A missing binary, timeout, non-zero exit,
or malformed line raises `HaltSQLUnavailable`. Local verifiers work anywhere a
verifier is accepted (`guard.*`, integrations, `haltsql-mcp`).

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
skip when those are unavailable.
