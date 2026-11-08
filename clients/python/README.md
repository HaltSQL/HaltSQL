# haltsql (Python)

Python client for [HaltSQL](https://github.com/HaltSQL/HaltSQL), the policy
firewall for LLM-generated PostgreSQL.

```sh
pip install haltsql            # httpx (+ the bundled engine on Linux x86_64/aarch64 and macOS arm64)
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
- `NativeVerifier` / `AsyncNativeVerifier`: verify in-process with the engine
  bundled in platform wheels (manylinux_2_28 x86_64/aarch64, macOS arm64), with
  no sidecar: `NativeVerifier("policy.yaml").verify(sql, ctx)`, ~0.1 ms per call.
  Backends `library` (ctypes) or `process` (one long-lived CLI child); env
  `HALTSQL_LIB`, `HALTSQL_BIN`, `HALTSQL_NATIVE=0|library`. Create it after
  `fork()` (e.g. gunicorn `post_fork`).
- `LocalVerifier`: verify with the `haltsql` CLI (bundled, `$HALTSQL_BIN` or
  `PATH`), one process per call.
- `haltsql.testing`: `FakeSidecar`, `FakeVerifier`, `make_verdict` for your tests.

Full guide: [docs/sdk-python.md](../../docs/sdk-python.md).

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install -e '.[psycopg,asyncpg,test]'
.venv/bin/pytest -q
```

Tests that need the real binaries (`_build/default/bin/...`, or
`HALTSQL_BIN` / `HALTSQL_SERVER_BIN`) or the lab Postgres (`make -C lab up`) are
marked `integration` and skip when those are missing. `native` tests need
`_build/default/native/libhaltsql.so` (or `HALTSQL_LIB`); set
`HALTSQL_REQUIRE_NATIVE=1` to fail instead of skip.

Platform wheel (bundles `libhaltsql` and the CLI; output in `dist/`):

```sh
scripts/build_wheel.sh            # dune release build, strip, tag, delocate/auditwheel
scripts/build_wheel.sh --pure     # py3-none-any wheel without the engine
HALTSQL_WHEEL=$(ls dist/*.whl) .venv/bin/pytest -q -m wheel   # install + smoke-test it
```
