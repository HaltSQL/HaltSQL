# Vanna

`haltsql-vanna` guards [Vanna](https://github.com/vanna-ai/vanna) with
HaltSQL. Every SQL string Vanna generates is verified first, and only the
exact verified string runs, with the bound tenant parameters, in a read-only
transaction. It supports Vanna 2.x through a `SqlRunner` and the legacy Vanna
0.x `VannaBase` through a replacement `run_sql`.

## What it provides

| Name | Kind | What it does |
|---|---|---|
| `HaltSQLSqlRunner(verifier, ...)` | Vanna 2.x `SqlRunner` | Give it to `RunSqlTool(sql_runner=...)`. Takes the tenant from the authenticated `ToolContext.user`, verifies, runs the exact SQL, and returns a pandas `DataFrame`. Async. |
| `install_legacy_run_sql(vn, verifier, context, ...)` | Function | Replaces `vn.run_sql` on a Vanna 0.x `VannaBase` object with a guarded version that returns a `DataFrame`. Sync. |
| `context_from_user_metadata(user)` | Function | The default Vanna 2.x context resolver: returns `user.metadata["haltsql_context"]`, or raises `PermissionError`. |
| `to_dataframe(result)` | Function | Turns a `haltsql.GuardedResult` into a pandas `DataFrame`. |

The package is a thin layer over the [Python SDK](../sdk-python.md). Every
query goes through `haltsql.guard.authorize` (or `authorize_async`), then
`guard.execute` (or `execute_async`). It does not use `HaltSQLToolRunner` from
the [agent frameworks](../agent-frameworks.md) packages.

## Install

The package needs Python 3.9 or newer. The `vanna` extra installs `vanna` 0.7
or newer and pandas 1.5 or newer. The package is not on PyPI yet, so install
it and the Python SDK from a checkout of the repository:

```sh
git clone https://github.com/HaltSQL/HaltSQL && cd HaltSQL
pip install -e clients/python -e 'integrations/vanna[vanna]'
```

The SDK depends on psycopg 3, which needs `libpq` on the machine. If you do
not have it, also run `pip install 'psycopg[binary]'`.

To verify queries you need a running `haltsql-server` (`AsyncHaltSQLClient` or
`HaltSQLClient`), or the `haltsql` CLI and a policy file
(`AsyncLocalVerifier` or `LocalVerifier`). See the
[Python SDK](../sdk-python.md).

## Minimal example

Vanna 2.x:

```python
from haltsql import AsyncHaltSQLClient
from haltsql_vanna import HaltSQLSqlRunner
from vanna.core.user import RequestContext, User, UserResolver
from vanna.tools import RunSqlTool

runner = HaltSQLSqlRunner(
    AsyncHaltSQLClient.from_env(),                    # or AsyncLocalVerifier("policy.yaml")
    dsn="postgresql://agent_ro@db/app",               # a read-only role
)
run_sql = RunSqlTool(sql_runner=runner)               # register it with your Vanna agent

class MyUserResolver(UserResolver):
    async def resolve_user(self, request_context: RequestContext) -> User:
        session = await authenticate(request_context)  # your auth
        return User(id=session.user_id,
                    metadata={"haltsql_context": {"tenant_id": session.tenant_id}})
```

`authenticate` stands for your own authentication. Register `run_sql` and
`MyUserResolver` with your Vanna agent as Vanna's documentation describes.

Vanna 0.x (legacy `VannaBase`):

```python
from haltsql import HaltSQLClient
from haltsql_vanna import install_legacy_run_sql

install_legacy_run_sql(
    vn,                                               # your VannaBase instance
    HaltSQLClient.from_env(),                         # a sync verifier
    lambda: {"tenant_id": current_tenant.get()},      # from your auth, per query
    dsn="postgresql://agent_ro@db/app",
)
vn.ask("How many open orders do we have?")
```

`install_legacy_run_sql` also sets `vn.run_sql_is_set = True` and
`vn.dialect = "PostgreSQL"`.

## Where the tenant comes from

**Vanna 2.x.** `HaltSQLSqlRunner` calls `context_from_user(context.user)` on
every query, where `context` is Vanna's `ToolContext` and `user` is the user
your `UserResolver` authenticated. The default reads
`user.metadata["haltsql_context"]`. The LLM writes only `RunSqlToolArgs.sql`;
it never supplies the context.

| User | Result |
|---|---|
| `metadata["haltsql_context"]` is a mapping | The query is verified with that context. |
| No user, no `metadata`, or no `haltsql_context` mapping | `PermissionError("no HaltSQL context for this user")`. Nothing is verified or run. |
| `haltsql_context` is `{}` | Verified with an empty context. Tenant tables are then denied by the policy. |

To derive the context differently, pass `context_from_user`:

```python
runner = HaltSQLSqlRunner(verifier, dsn=DSN,
                          context_from_user=lambda user: {"tenant_id": lookup_tenant(user.id)})
```

**Vanna 0.x.** `context` is a mapping or a zero-argument callable, evaluated on
every `run_sql`. A callable that returns `None` gives an empty context, which
the policy denies for tenant tables. A callable that raises stops the query
before verification.

## What the model sees

On success, both versions return a pandas `DataFrame` with the result's
columns, up to `max_rows` rows.

On a denial, nothing runs, and `haltsql.QueryDenied` is raised. Its message
lists each reason code with its hint, separated by `; `:

```text
E_TENANT_MISSING: <hint>; E_COLUMN_DENIED: <hint>
```

What the LLM sees then depends on Vanna:

- **Vanna 2.x.** `RunSqlTool` catches exceptions from the runner. In Vanna 2.0
  it gives the LLM `Error executing query: ` followed by the exception message,
  so the model gets the codes and hints. The same applies to a
  `PermissionError` for a missing context, and to verification and database
  errors.
- **Vanna 0.x.** The exception propagates from `vn.run_sql`. How `ask` reports
  it depends on your Vanna version and its settings.

Verification failures raise `HaltSQLUnavailable` or `HaltSQLRequestError`;
database errors raise the driver's exception. See
[reason-codes.md](../reason-codes.md) for every code.

## Configuration

`HaltSQLSqlRunner(verifier, *, dsn=None, connect=None, context_from_user=context_from_user_metadata, max_rows=1000, statement_timeout_ms=5000, settings=None)`:

| Argument | Default | Meaning |
|---|---|---|
| `verifier` | required | `AsyncHaltSQLClient` (recommended), `AsyncLocalVerifier`, or a sync verifier such as `HaltSQLClient`. A sync verifier blocks the event loop while it verifies. |
| `dsn` | `None` | libpq connection string. A new psycopg 3 `AsyncConnection` (autocommit) is opened per query, after verification. Give exactly one of `dsn` and `connect`. |
| `connect` | `None` | `async () -> connection`, returning a psycopg `AsyncConnection` or an asyncpg connection. Called after verification; closed after each query. |
| `context_from_user` | `context_from_user_metadata` | `(user) -> mapping`. Raise to refuse. |
| `max_rows` | `1000` | Row cap. `None` means no cap. |
| `statement_timeout_ms` | `5000` | `statement_timeout` for the query. `None` means none is set. |
| `settings` | `None` | A mapping of transaction-local settings. Fixed for the runner; it cannot depend on the context. |

`install_legacy_run_sql(vn, verifier, context, *, dsn=None, connect=None, max_rows=1000, statement_timeout_ms=5000, settings=None)`:

| Argument | Default | Meaning |
|---|---|---|
| `vn` | required | Your Vanna 0.x `VannaBase` instance. |
| `verifier` | required | A sync verifier: `HaltSQLClient`, `LocalVerifier`, `NativeVerifier`, or any object with `verify(sql, context)`. |
| `context` | required | A mapping, or a zero-argument callable that returns one. |
| `dsn` | `None` | libpq connection string; a psycopg 3 connection (autocommit) is opened per query. Give exactly one of `dsn` and `connect`. |
| `connect` | `None` | Zero-argument callable that returns a `psycopg.Connection`. Closed after each query. |
| `max_rows` | `1000` | Row cap. `None` means no cap. |
| `statement_timeout_ms` | `5000` | `statement_timeout` for the query. `None` means none is set. |
| `settings` | `None` | A mapping of transaction-local settings. |

Both always run in a `READ ONLY` transaction. This cannot be turned off.

## Async support

`HaltSQLSqlRunner.run_sql` is async, as Vanna 2.x requires. With an async
verifier and the default `dsn` (psycopg `AsyncConnection`) or an asyncpg
`connect`, nothing blocks the event loop. The legacy `run_sql` is sync and
needs a sync verifier: an async verifier raises `GuardError`. Rows are returned
whole as a `DataFrame`; streaming rows is not supported.

## Testing

You can test your wiring without a model, a sidecar or a database. Use
`FakeVerifier` from `haltsql.testing`, and stand-ins for Vanna's arguments
(`args.sql` and `context.user.metadata`):

```python
import asyncio
from types import SimpleNamespace

import pytest
from haltsql import QueryDenied
from haltsql.testing import FakeVerifier, make_verdict_dict
from haltsql_vanna import HaltSQLSqlRunner

def deny(sql, ctx, _policy):
    return make_verdict_dict(sql, allowed=False, codes=["E_TENANT_MISSING"])

async def no_db():
    raise AssertionError("connected after a denial")

def test_denial_never_connects():
    runner = HaltSQLSqlRunner(FakeVerifier(deny), connect=no_db)
    user = SimpleNamespace(metadata={"haltsql_context": {"tenant_id": "acme"}})
    with pytest.raises(QueryDenied, match="E_TENANT_MISSING"):
        asyncio.run(runner.run_sql(SimpleNamespace(sql="SELECT id FROM orders LIMIT 10"),
                                   SimpleNamespace(user=user)))
```

The package's own tests use these stand-ins, Vanna's real `SqlRunner`,
`RunSqlToolArgs` and `User` classes when Vanna is installed, and the lab
Postgres for execution:

```sh
make -C lab up
pip install -e clients/python -e 'integrations/vanna[vanna,test]'
pytest -q integrations/vanna
```

`FULL=1 clients/python/run-all-tests.sh` runs them with the other Python
suites.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `PermissionError: no HaltSQL context for this user` | The resolved user has no `metadata["haltsql_context"]` mapping. | Set it in your `UserResolver`, or pass `context_from_user`. |
| Every query on a tenant table is denied with `E_CONTEXT_MISSING` | The context is empty or misses a key the policy needs. | Check the context your resolver or callable returns. |
| `ValueError: pass exactly one of dsn= or connect=` | Both or neither were given. | Pass one. |
| `ValueError: RunSqlToolArgs.sql must be a string` | The tool arguments had no SQL string. | Check how the runner is called. |
| `GuardError: an async verifier was passed to a sync execute()` | The legacy `run_sql` got `AsyncHaltSQLClient` or `AsyncLocalVerifier`. | Use `HaltSQLClient` or `LocalVerifier` with `install_legacy_run_sql`. |
| `HaltSQLUnavailable` | The sidecar or CLI failed, timed out, or returned a verdict for a different string. | Check `HALTSQL_URL` and `HALTSQL_TOKEN`, or the `haltsql` binary. |
| `ImportError` for `pandas` | pandas is not installed. | Install the `vanna` extra. |
| `ImportError: no pq wrapper available` | psycopg cannot find `libpq`. | `pip install 'psycopg[binary]'`, or install `libpq`. |

## Limits

- Read-only only. Queries always run in a `READ ONLY` transaction.
- One statement per call. Rows are returned whole, up to `max_rows`; there is
  no streaming or pagination, and the `DataFrame` does not say whether rows
  were cut.
- The default row cap is `1000`, higher than the other integrations' `200`.
- `HaltSQLSqlRunner` subclasses Vanna's `SqlRunner` only when
  `vanna.capabilities.sql_runner` can be imported (Vanna 2.x). Otherwise it is
  a plain class.
- HaltSQL verifies the PostgreSQL dialect only.

## Related

- [Python SDK](../sdk-python.md): verifiers, async execution and errors.
- [reason-codes.md](../reason-codes.md) and [tenancy.md](../tenancy.md).
- [defense-in-depth.md](../defense-in-depth.md): the database role and
  row-level security to use with HaltSQL.
- [Agent frameworks](../agent-frameworks.md): tools for agent SDKs.
- Source: [`integrations/vanna`](../../integrations/vanna).
