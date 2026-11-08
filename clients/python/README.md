# haltsql (Python)

Python client for [HaltSQL](https://github.com/ardada2468/HaltSQL), the policy
firewall for LLM-generated PostgreSQL.

```sh
pip install haltsql            # httpx only
pip install 'haltsql[psycopg]' # + guarded execution on psycopg 3
pip install 'haltsql[asyncpg]' # + guarded execution on asyncpg
```

```python
import psycopg
from haltsql import HaltSQLClient, QueryDenied, guard

hs = HaltSQLClient.from_env()  # HALTSQL_URL, HALTSQL_TOKEN, HALTSQL_TIMEOUT, HALTSQL_CA_FILE, ...

with psycopg.connect(DSN) as conn:
    try:
        result = guard.execute(conn, model_sql, {"tenant_id": session.tenant_id},
                               verifier=hs, statement_timeout_ms=5000, max_rows=500)
        print(result.columns, result.rows)
    except QueryDenied as denied:
        feedback = [(r.code, r.hint) for r in denied.verdict.reasons]  # give to the model
```

- `HaltSQLClient` / `AsyncHaltSQLClient`: the sidecar HTTP API, with
  default timeouts (2 s per attempt), bounded retries, TLS verification on by
  default (private CA via `verify=`, mutual TLS via `cert=`), and a response
  size cap. **Fail closed:** any error raises; nothing is ever treated as
  allowed. The token never appears in `repr()` or error messages.
- `Verdict`, `Reason`, `BindParam`: typed verdicts; `verdict.bind_args()`
  returns positional parameters for `$1..$n`.
- `guard.execute` / `guard.execute_async`: verify, then run exactly the
  verified string with the bound parameters (psycopg 3, asyncpg, SQLAlchemy +
  psycopg 3).
- `LocalVerifier`: verify with the `haltsql` CLI when no sidecar runs.
- `haltsql.testing`: `FakeSidecar`, `FakeVerifier`, `make_verdict` for your tests.

Full guide: [docs/sdk-python.md](../../docs/sdk-python.md).

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install -e '.[psycopg,asyncpg,test]'
.venv/bin/pytest -q
```

Tests that need the real binaries (`_build/default/bin/...`, or
`HALTSQL_BIN` / `HALTSQL_SERVER_BIN`) or the lab Postgres (`make -C lab up`) are
marked `integration` and skip when those are missing.
