# LlamaIndex

`haltsql-llamaindex` guards LlamaIndex text-to-SQL with HaltSQL. LlamaIndex's
SQL retrievers and query engines run SQL through `SQLDatabase.run_sql`, and
this package returns a copy of your `SQLDatabase` whose `run_sql` verifies each
statement first and runs only the exact verified string. The tenant comes from
a mapping or callable you pass in from your authenticated session, never from
the model.

## What it provides

| Name | Kind | What it does |
|---|---|---|
| `guard_sql_database(db, verifier, context, ...)` | Function | Returns a copy of a LlamaIndex `SQLDatabase` whose `run_sql` verifies, then runs the exact SQL with the bound parameters, and whose `insert_into_table` refuses. The copy is still an `SQLDatabase`, so you can pass it anywhere the original went. |
| `guarded_sql_retriever(db, verifier, context, ...)` | Function | A `SQLRetriever` over a guarded copy of `db`. |
| `guarded_nl_sql_query_engine(db, verifier, context, ...)` | Function | An `NLSQLTableQueryEngine` over a guarded copy of `db`, with denials turned into SQL errors the LLM can read. |
| `HaltSQLSQLError` | Exception (a `NotImplementedError`) | Raised instead of the HaltSQL exception when `denials_as_sql_errors=True`. Its message lists the reason codes and hints; `__cause__` is the original error. |

The package is a thin layer over the [Python SDK](../sdk-python.md). Every
query goes through `haltsql.guard.authorize` and `guard.execute_on_engine`.
It does not use `HaltSQLToolRunner` from the
[agent frameworks](../agent-frameworks.md) packages.

## Install

The package needs Python 3.9 or newer. The `llamaindex` extra installs
`llama-index-core` 0.10 or newer and SQLAlchemy 2. Install it from PyPI; it pulls in the `haltsql`
Python SDK:

```sh
pip install 'haltsql-llamaindex[llamaindex]'
```

The SDK depends on psycopg 3, which needs `libpq` on the machine. If you do
not have it, also run `pip install 'psycopg[binary]'`. You also need an LLM
integration for the query engine, such as `llama-index-llms-openai`.

To verify queries you need a running `haltsql-server` (`HaltSQLClient`), the
`haltsql` CLI and a policy file (`LocalVerifier`), or a platform wheel of the
SDK with the bundled engine (`NativeVerifier`). See the
[Python SDK](../sdk-python.md).

## Minimal example

```python
import contextvars

from sqlalchemy import create_engine
from llama_index.core import SQLDatabase
from llama_index.llms.openai import OpenAI
from haltsql import HaltSQLClient
from haltsql_llamaindex import guarded_nl_sql_query_engine

current_tenant = contextvars.ContextVar("tenant")       # set by your request handler

engine = create_engine("postgresql+psycopg://agent_ro@db/app")   # psycopg 3, a read-only role
db = SQLDatabase(engine, include_tables=["orders"])

query_engine = guarded_nl_sql_query_engine(
    db,
    HaltSQLClient.from_env(),                           # or LocalVerifier("policy.yaml")
    lambda: {"tenant_id": current_tenant.get()},        # evaluated on every query
    tables=["orders"],
    llm=OpenAI(model="gpt-4o-mini"),
)

def answer(user, question: str) -> str:
    current_tenant.set(user.tenant_id)                  # from your auth
    return str(query_engine.query(question))
```

To guard other components, pass the guarded copy wherever you passed the
original `SQLDatabase`:

```python
from haltsql_llamaindex import guard_sql_database, guarded_sql_retriever

guarded = guard_sql_database(db, verifier, ctx)         # for any component that takes an SQLDatabase
retriever = guarded_sql_retriever(db, verifier, ctx)    # SQLRetriever: runs SQL you give it
```

The engine must use psycopg 3 (`postgresql+psycopg://`).

The guarded copy never runs SQL on the engine outside HaltSQL: `run_sql` is
verified, and `insert_into_table` (which `SQLStructStoreIndex` uses to load
rows) raises `haltsql.GuardError` instead of inserting. Table descriptions
(`get_single_table_info`) come from schema reflection and read no rows. The
original `db` and the copy's `engine` property still give the raw engine, so
give the agent only the guarded copy.

## Where the tenant comes from

`context` is a mapping or a zero-argument callable. A callable is evaluated on
every `run_sql`, so one guarded database or query engine can serve many
requests. Reading a `contextvars.ContextVar` that your request handler sets is
the usual pattern. The model only writes SQL; it never supplies the context.

| `context` | Result |
|---|---|
| A mapping, or a callable that returns one | The query is verified with that context. |
| A callable that returns `None` | Refused: nothing is verified or run. `run_sql` raises `haltsql.integration.ContextUnavailable`, or, with `denials_as_sql_errors=True`, a `HaltSQLSQLError` reading "No trusted HaltSQL context is configured for this request; the query was not executed." |
| `{}`, or a callable that returns it | Verified with an empty context. Tenant tables are then denied by the policy, typically with `E_CONTEXT_MISSING`. |
| A callable that raises | Nothing is verified or run. `run_sql` raises `haltsql.HaltSQLUnavailable` (the original exception is its `__cause__`), or a `HaltSQLSQLError` reading "SQL verification is unavailable" with `denials_as_sql_errors=True`. |

As in the [agent-framework packages](../agent-frameworks.md), a missing
context is refused before verification.

## What the model sees

On success, the guarded `run_sql` returns what LlamaIndex expects: the rows as
a string, such as `[(1, 'open'), (3, 'paid')]`, and a metadata dict:

```python
{"result": [(1, "open"), (3, "paid")], "col_keys": ["id", "status"], "truncated": False}
```

Long string values are shortened the same way as in LlamaIndex's own
`run_sql`. A statement that returns no columns gives `("", {})`.

On a denial, nothing runs. What happens next depends on
`denials_as_sql_errors`:

- **`False` (default for `guard_sql_database` and `guarded_sql_retriever`).**
  `run_sql` raises `haltsql.QueryDenied`. Its message is the reason codes with
  their hints, such as `E_TENANT_MISSING: <hint>`. Other failures raise the
  underlying error (`HaltSQLUnavailable`, a database error, ...). Your code
  handles them.
- **`True` (default for `guarded_nl_sql_query_engine`).** Every failure raises
  `HaltSQLSQLError` with text written for the model:

  ```text
  HaltSQL denied the query; it was not executed. Fix the SQL and retry:
  - E_TENANT_MISSING: <hint>
  ```

  Verification failures read "SQL verification is unavailable; the query was
  not executed." LlamaIndex's `NLSQLRetriever`, which `NLSQLTableQueryEngine`
  uses, catches errors from `run_sql` when `handle_sql_errors=True` (its
  default) and passes `Error: <message>` on to response synthesis.

The query engine does not retry on its own. If you use it as a tool of an
agent, the agent sees the error text and can ask again. See
[reason-codes.md](../reason-codes.md) for every code.

## Configuration

`guard_sql_database(db, verifier, context, *, max_rows=200, statement_timeout_ms=5000, settings=None, read_only=True, denials_as_sql_errors=False)`:

| Argument | Default | Meaning |
|---|---|---|
| `db` | required | A LlamaIndex `SQLDatabase`. Its engine must use psycopg 3. |
| `verifier` | required | `HaltSQLClient`, `LocalVerifier`, `NativeVerifier`, or any object with `verify(sql, context)`. |
| `context` | required | A mapping, or a zero-argument callable that returns one. |
| `max_rows` | `200` | Row cap. `None` means no cap. |
| `statement_timeout_ms` | `5000` | `statement_timeout` for the query. `None` means none is set. |
| `settings` | `None` | A mapping of transaction-local settings. Fixed for the guarded copy; it cannot depend on the context. |
| `read_only` | `True` | Run only statements whose verdict `statement_kind` is `select`, in a `READ ONLY` transaction. With `False`, see [Read-only and writes](#read-only-and-writes). |
| `denials_as_sql_errors` | `False` | Raise `HaltSQLSQLError` with model-readable text instead of the original exception. |

`guarded_sql_retriever(db, verifier, context, **kwargs)` passes `kwargs` to
`guard_sql_database`.

`guarded_nl_sql_query_engine(db, verifier, context, *, guard_kwargs=None, **engine_kwargs)`:

| Argument | Default | Meaning |
|---|---|---|
| `guard_kwargs` | `None` | A dict of `guard_sql_database` options (`max_rows`, `statement_timeout_ms`, `settings`, `read_only`, `denials_as_sql_errors`). `denials_as_sql_errors` defaults to `True` here. |
| `**engine_kwargs` | none | Guard options given as keywords (for example `max_rows=50`) go to the guard; the rest go to `NLSQLTableQueryEngine`, for example `tables=` and `llm=`. |

Guard options work as keyword arguments (`max_rows=50`) or in `guard_kwargs`
(`guard_kwargs={"max_rows": 50}`). Giving the same option both ways, or an
unknown key in `guard_kwargs`, raises `TypeError`.

### Read-only and writes

With the default `read_only=True`, a statement runs only when the verdict's
`statement_kind` is `select`. Anything else is refused before a connection is
taken, even when the policy allows it, with `GuardError: only SELECT statements
run in read-only mode (this is UPDATE)` (a `HaltSQLSQLError` with
`denials_as_sql_errors=True`).

With `read_only=False`, the policy alone decides: a statement runs when HaltSQL
allows it, whatever its kind. Writes run in a read-write transaction, and
`SELECT` statements still run `READ ONLY`. A verdict without a
`statement_kind` never runs. Allow writes in the policy (`statements.allow`)
only for the agents and tables that need them. `insert_into_table` refuses
either way.

## Async support

The guard is synchronous. `run_sql` verifies and runs on the calling thread,
including when LlamaIndex's async methods (`aquery`, `aretrieve`) call it:
their SQL step calls the sync `run_sql`. Use
a sync verifier. Rows are returned whole; streaming rows is not supported.

## Testing

You can test your wiring without a model, a sidecar or a database. Use
`FakeVerifier` from `haltsql.testing` and a guarded database; a denial raises
before the engine is touched:

```python
import pytest
from haltsql import QueryDenied
from haltsql.testing import FakeVerifier, make_verdict_dict
from haltsql_llamaindex import HaltSQLSQLError, guard_sql_database

def deny(sql, ctx, _policy):
    return make_verdict_dict(sql, allowed=False, codes=["E_TENANT_MISSING"])

class NoEngine:
    def raw_connection(self):
        raise AssertionError("engine used after a denial")

class FakeDB:                       # stands in for SQLDatabase in this unit test
    _engine = NoEngine()

def test_denial_never_touches_the_engine():
    g = guard_sql_database(FakeDB(), FakeVerifier(deny), {"tenant_id": "acme"})
    with pytest.raises(QueryDenied):
        g.run_sql("SELECT id FROM orders LIMIT 10")
    g = guard_sql_database(FakeDB(), FakeVerifier(deny), {"tenant_id": "acme"},
                           denials_as_sql_errors=True)
    with pytest.raises(HaltSQLSQLError, match="E_TENANT_MISSING"):
        g.run_sql("SELECT id FROM orders LIMIT 10")
```

The package's own tests use a real LlamaIndex `SQLDatabase` and `SQLRetriever`
when `llama-index-core` is installed, and the lab Postgres for execution:

```sh
make -C lab up
pip install -e clients/python -e 'integrations/llamaindex[llamaindex,test]'
pytest -q integrations/llamaindex
```

`FULL=1 clients/python/run-all-tests.sh` runs them with the other Python
suites.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Every query on a tenant table is denied with `E_CONTEXT_MISSING` | The context callable returned `{}`, or misses a key the policy needs. | Check the callable. It is evaluated on every query. |
| `ContextUnavailable`, or "No trusted HaltSQL context is configured" | The context callable returned `None`. | Return the context for the current request, for example from a `ContextVar` your handler sets. |
| `GuardError: only SELECT statements run in read-only mode` | The policy allowed a write, but `read_only=True`. | Ask for a `SELECT`, or pass `read_only=False` if the agent should write. |
| `GuardError: insert_into_table is not available on a HaltSQL-guarded SQLDatabase` | `SQLStructStoreIndex` or your code tried to insert rows through the guarded copy. | Load data with the original `SQLDatabase` outside the agent, or with verified `INSERT` statements and `read_only=False`. |
| Allowed SQL fails in Postgres with "relation does not exist" | Postgres resolves unqualified table names with the role's `search_path`, which differs from the policy's. With `SQLDatabase(schema=...)`, the guard does not add the schema prefix, because that would change the verified SQL. | Set the role's `search_path` to the policy's `search_path`, and drop `schema=`. |
| `GuardError: could not find the SQLAlchemy engine of this SQLDatabase` | The object passed in has no `_engine` or `engine`. | Pass a LlamaIndex `SQLDatabase`. |
| `GuardError: psycopg2 cannot send $n placeholders unchanged; use psycopg 3` | The engine uses psycopg2. | Use a `postgresql+psycopg://` URL. |
| `TypeError: guard option 'max_rows' given both as a keyword and in guard_kwargs` | The same option was passed twice. | Pass it one way. |
| `HaltSQLUnavailable`, or "SQL verification is unavailable" | The sidecar or CLI failed, timed out, or returned a verdict for a different string; or the context callable raised. | Check `HALTSQL_URL` and `HALTSQL_TOKEN`, or the `haltsql` binary, and test the callable on its own. |
| `ImportError: no pq wrapper available` | psycopg cannot find `libpq`. | `pip install 'psycopg[binary]'`, or install `libpq`. |

## Limits

- One statement per call. Rows are returned whole, up to `max_rows`; there is
  no streaming or pagination.
- `SQLDatabase(schema=...)` is not supported: the guarded `run_sql` does not
  prefix the schema. Use `search_path` instead.
- `run_sql` is verified and `insert_into_table` refuses. Schema reflection
  (table and column names) and the `engine` property still use the raw engine.
- The table descriptions LlamaIndex gives the model come from the database
  schema, not the policy, so they can name columns the policy denies. Limit
  them with `include_tables`.
- The engine must use psycopg 3.
- HaltSQL verifies the PostgreSQL dialect only.

## Related

- [Python SDK](../sdk-python.md): verifiers, `guard.execute_on_engine` and
  errors.
- [reason-codes.md](../reason-codes.md) and [tenancy.md](../tenancy.md).
- [defense-in-depth.md](../defense-in-depth.md): the database role and
  row-level security to use with HaltSQL.
- [Agent frameworks](../agent-frameworks.md): tools for agent SDKs.
- Source: [`integrations/llamaindex`](../../integrations/llamaindex).
