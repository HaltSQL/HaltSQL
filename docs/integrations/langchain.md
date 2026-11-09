# LangChain

`haltsql-langchain` guards LangChain SQL agents with HaltSQL. It offers a
`haltsql_query` tool whose only argument is the SQL, and a wrapper that makes
an existing `SQLDatabase` verify every statement before it runs, so
`SQLDatabaseToolkit` and `create_sql_agent` keep working. The tenant comes from
a mapping or callable you pass in from your authenticated session, never from
the model.

## What it provides

| Name | Kind | What it does |
|---|---|---|
| `HaltSQLQueryTool(runner=...)` | LangChain `BaseTool` | A tool named `haltsql_query` whose only argument is `query`. Returns JSON rows, or the reason codes and hints when nothing ran. Needs `langchain-core`. |
| `HaltSQLQueryRunner(verifier, context, ...)` | Class | The framework-free core: verifies and runs SQL. `run(sql)` returns text for the model; `execute(sql)` returns a `GuardedResult` and raises on denial. |
| `guard_sql_database(db, verifier, context, ...)` | Function | Returns a copy of a `langchain_community` `SQLDatabase` whose `run` and `run_no_throw` verify every statement first. The copy is still an `SQLDatabase`. |

This package does not use `HaltSQLToolRunner` from the
[agent frameworks](../agent-frameworks.md) packages; its runner and result
format are described on this page. It is a thin layer over the
[Python SDK](../sdk-python.md): every query goes through
`haltsql.guard.authorize`, then `guard.execute` or `guard.execute_on_engine`.

## Install

The package needs Python 3.9 or newer. The `langchain` extra installs
`langchain-core` 0.3 or newer, `langchain-community` 0.3 or newer and
SQLAlchemy 2. The package is not on PyPI yet, so install it and the Python SDK
from a checkout of the repository:

```sh
git clone https://github.com/HaltSQL/HaltSQL && cd HaltSQL
pip install -e clients/python -e 'integrations/langchain[langchain]'
```

The SDK depends on psycopg 3, which needs `libpq` on the machine. If you do
not have it, also run `pip install 'psycopg[binary]'`.

To verify queries you need a running `haltsql-server` (`HaltSQLClient`), the
`haltsql` CLI and a policy file (`LocalVerifier`), or a platform wheel of the
SDK with the bundled engine (`NativeVerifier`). See the
[Python SDK](../sdk-python.md).

## Minimal example

A tool whose only argument is the SQL:

```python
import contextvars
import os

import psycopg
from haltsql import HaltSQLClient
from haltsql_langchain import HaltSQLQueryRunner, HaltSQLQueryTool

DSN = os.environ["AGENT_DATABASE_URL"]               # a read-only role
current_tenant = contextvars.ContextVar("tenant")    # set by your request handler

runner = HaltSQLQueryRunner(
    HaltSQLClient.from_env(),                        # or LocalVerifier("policy.yaml")
    context=lambda: {"tenant_id": current_tenant.get()},
    connect=lambda: psycopg.connect(DSN),            # called only after HaltSQL allows the query
)
tool = HaltSQLQueryTool(runner=runner)               # give it to your agent's tools

# Per request, after authenticating the user:
current_tenant.set(user.tenant_id)
print(tool.invoke({"query": "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 10"}))
```

Guarding an existing `SQLDatabase` for `create_sql_agent`:

```python
from langchain_community.agent_toolkits import SQLDatabaseToolkit, create_sql_agent
from langchain_community.utilities import SQLDatabase
from haltsql import HaltSQLClient
from haltsql_langchain import guard_sql_database

db = SQLDatabase.from_uri(
    "postgresql+psycopg://agent_ro@db/app",
    include_tables=["orders"],
    sample_rows_in_table_info=0,                     # see the warning below
)
guarded = guard_sql_database(db, HaltSQLClient.from_env(),
                             lambda: {"tenant_id": current_tenant.get()})
toolkit = SQLDatabaseToolkit(db=guarded, llm=llm)
agent = create_sql_agent(llm, toolkit=toolkit)
```

The engine must use psycopg 3 (`postgresql+psycopg://`).

> **Warning:** `SQLDatabase` reads sample rows of each table for the table
> descriptions it gives the model (`sample_rows_in_table_info`, default 3).
> Those reads go straight to the engine, not through `run`, so HaltSQL does not
> check them, and they can include other tenants' rows. Set
> `sample_rows_in_table_info=0`, and limit the tables with `include_tables`.
> The table descriptions also list every column of those tables, including
> columns the policy denies.

## Where the tenant comes from

`context` is a mapping or a zero-argument callable. A callable is evaluated on
every query, so one runner or guarded database can serve many requests. Reading
a `contextvars.ContextVar` that your request handler sets is the usual pattern.
The model never supplies the context: the tool's only argument is `query`, and
`SQLDatabase.run` takes only SQL. If a tool call carries an extra argument such
as `tenant_id`, LangChain drops it before the tool runs.

| `context` | Result |
|---|---|
| A mapping, or a callable that returns one | The query is verified with that context. |
| A callable that returns `None`, or `{}` | Verified with an empty context. Tenant tables are then denied by the policy, typically with `E_CONTEXT_MISSING`. |
| A callable that raises | Nothing is verified or run. `HaltSQLQueryTool` returns `Database error: <exception type>: ...` to the model (see [Troubleshooting](#troubleshooting)). |

Unlike the [agent-framework packages](../agent-frameworks.md), a missing
context is not refused before verification here. Make sure the callable
returns the context, or raises.

## What the model sees

`HaltSQLQueryTool` (and `HaltSQLQueryRunner.run`) returns text. On success it
is JSON:

```json
{"columns": ["id", "status"], "rows": [[1, "open"], [3, "paid"]], "truncated": false}
```

When HaltSQL denies the query, nothing runs, and the model gets each reason
code with its hint (or the message, if a reason has no hint):

```text
HaltSQL denied the query; it was not executed. Fix the SQL and retry:
- E_TENANT_MISSING: <hint>
```

Other failures:

| Text | Meaning |
|---|---|
| `SQL verification is unavailable; the query was not executed.` | The sidecar or CLI failed, timed out, rejected the request, or returned a verdict for a different string. |
| `The query was not executed: <reason>` | The guarded executor refused, for example an unsupported connection. |
| `Database error: <class>: <first line>` | HaltSQL allowed the query but the database rejected it, or another error occurred. |

The guarded `SQLDatabase` behaves like a normal one:

- `run(sql)` returns the rows as a string such as `[(1, 'open')]`, or `""` when
  there are no rows. On a denial it raises `haltsql.QueryDenied`; on other
  failures it raises the underlying error.
- `run_no_throw(sql)` returns `Error: ` followed by the same text as above.
  LangChain's `QuerySQLDatabaseTool`, which `SQLDatabaseToolkit` uses, calls
  `run_no_throw`, so the model sees the codes and hints.

The default tool description tells the model to filter tenant tables with
`alias.tenant_id = $1`, never to write tenant IDs, and to fix the SQL and
retry after a denial. See [reason-codes.md](../reason-codes.md) for every code.

## Configuration

`HaltSQLQueryRunner(verifier, context, *, engine=None, connect=None, max_rows=200, statement_timeout_ms=5000, settings=None, read_only=True)`:

| Argument | Default | Meaning |
|---|---|---|
| `verifier` | required | `HaltSQLClient`, `LocalVerifier`, `NativeVerifier`, or any object with `verify(sql, context)`. |
| `context` | required | A mapping, or a zero-argument callable that returns one. |
| `engine` | `None` | A SQLAlchemy engine using psycopg 3 (`postgresql+psycopg://`). Give exactly one of `engine` and `connect`. |
| `connect` | `None` | Zero-argument callable that returns a new `psycopg.Connection`. Called only after HaltSQL allows the query; closed after each query. |
| `max_rows` | `200` | Row cap. `None` means no cap. |
| `statement_timeout_ms` | `5000` | `statement_timeout` for the query. `None` means none is set. |
| `settings` | `None` | A mapping of transaction-local settings, for example `{"app.region": "eu"}`. Fixed for the runner; it cannot depend on the context. |
| `read_only` | `True` | Run in a `READ ONLY` transaction. With `False`, statements the policy allows, including writes, run in a read-write transaction. |

`HaltSQLQueryTool` fields (keyword arguments):

| Field | Default | Meaning |
|---|---|---|
| `runner` | required | A `HaltSQLQueryRunner`. |
| `name` | `"haltsql_query"` | Tool name the model sees. |
| `description` | built-in text | Tool description the model sees. |

`guard_sql_database(db, verifier, context, **runner_kwargs)` accepts
`max_rows`, `statement_timeout_ms`, `settings` and `read_only`, as above. It
uses the database's own engine; do not pass `engine` or `connect`.

> **Note:** this package does not check the statement kind itself. With the
> default `read_only=True`, a write that the policy allows reaches Postgres
> and fails there, in the read-only transaction. Keep `statements.allow` to
> `select` in the policy for agent use.

## Async support

None of the classes have async methods. `HaltSQLQueryTool` defines only a sync
implementation, so LangChain's `ainvoke` runs it in a thread pool executor.
The guarded `SQLDatabase` is sync, like `SQLDatabase` itself. Use a sync
verifier and a sync psycopg connection or engine. Rows are returned whole;
streaming rows is not supported.

## Testing

You can test your wiring without a model, a sidecar or a database. Use
`FakeVerifier` from `haltsql.testing` and check that a denial never opens a
connection:

```python
import pytest
from haltsql import QueryDenied
from haltsql.testing import FakeVerifier, make_verdict_dict
from haltsql_langchain import HaltSQLQueryRunner

def deny(sql, ctx, _policy):
    return make_verdict_dict(sql, allowed=False, codes=["E_TENANT_MISSING"])

def no_db():
    raise AssertionError("connected after a denial")

def test_denial_never_connects():
    fv = FakeVerifier(deny)
    runner = HaltSQLQueryRunner(fv, {"tenant_id": "acme"}, connect=no_db)
    assert runner.run("SELECT id FROM orders LIMIT 10").startswith("HaltSQL denied the query")
    with pytest.raises(QueryDenied):
        runner.execute("SELECT id FROM orders LIMIT 10")
    assert fv.calls[0][1] == {"tenant_id": "acme"}
```

The package's own tests cover the runner, the guarded `SQLDatabase` and the
tool. Tests that need LangChain skip when it is not installed, and tests that
run SQL need the lab Postgres:

```sh
make -C lab up
pip install -e clients/python -e 'integrations/langchain[langchain,test]'
pytest -q integrations/langchain
```

`FULL=1 clients/python/run-all-tests.sh` runs them with the other Python
suites.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Every query on a tenant table is denied with `E_CONTEXT_MISSING` | The context callable returned `None` or `{}`, or misses a key the policy needs. | Check the callable. It is evaluated on every query. |
| "Database error: KeyError: ..." or another unexpected type, and nothing ran | The context callable raised. The runner reports every exception this way. | Test the callable on its own. |
| "SQL verification is unavailable" | The sidecar or CLI failed, timed out, rejected the token, or returned a verdict for a different string. | Check `HALTSQL_URL` and `HALTSQL_TOKEN`, or the `haltsql` binary. |
| `ValueError: pass exactly one of engine= or connect=` | Both or neither were given. | Pass one. With `guard_sql_database`, pass neither. |
| `GuardError: caller-supplied parameters are not allowed` | Code called the guarded `run` with `parameters=`. | HaltSQL binds the parameters; pass the SQL alone. |
| `GuardError: fetch='cursor' is not supported` | Code called `run(fetch="cursor")`. | Use `fetch="all"` or `"one"`. |
| `GuardError: could not find the SQLAlchemy engine of this SQLDatabase` | The object passed to `guard_sql_database` has no `_engine` or `engine`. | Pass a `langchain_community` `SQLDatabase`. |
| `ImportError: HaltSQLQueryTool needs langchain-core` | The `langchain` extra is not installed. | `pip install -e 'integrations/langchain[langchain]'`. |
| `ImportError: no pq wrapper available` | psycopg cannot find `libpq`. | `pip install 'psycopg[binary]'`, or install `libpq`. |

## Limits

- One statement per call. Rows are returned whole, up to `max_rows`; there is
  no streaming or pagination.
- The guarded `SQLDatabase` returns a string, so the model is not told when
  rows were cut at `max_rows`. `HaltSQLQueryTool` reports it as `truncated`.
- `fetch="one"` still fetches up to `max_rows` rows and returns the first.
  `execution_options` is accepted and ignored.
- Only `run` and `run_no_throw` are guarded. Other `SQLDatabase` methods, such
  as `get_table_info`, use the engine directly.
- The engine or connection must use psycopg 3. psycopg2 cannot send `$n` SQL
  unchanged and is refused.
- HaltSQL verifies the PostgreSQL dialect only.

## Related

- [LangGraph](langgraph.md): a `ToolNode` tool with the tenant in the runtime
  context, and a retry-on-deny graph.
- [Python SDK](../sdk-python.md): verifiers, `guard.execute` and errors.
- [reason-codes.md](../reason-codes.md) and [tenancy.md](../tenancy.md).
- [defense-in-depth.md](../defense-in-depth.md): the database role and
  row-level security to use with HaltSQL.
- Source: [`integrations/langchain`](../../integrations/langchain).
