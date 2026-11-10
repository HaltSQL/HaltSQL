# haltsql-langchain

HaltSQL guard for LangChain SQL agents. Every statement is verified by HaltSQL
before it runs; only the exact verified string runs, with the bound tenant
parameters, read-only by default.

```sh
pip install 'haltsql-langchain[langchain]'
```

## A tool whose only argument is the SQL

```python
import psycopg
from haltsql import HaltSQLClient
from haltsql_langchain import HaltSQLQueryRunner, HaltSQLQueryTool

runner = HaltSQLQueryRunner(
    HaltSQLClient.from_env(),
    context=lambda: {"tenant_id": current_session().tenant_id},  # from your auth, per call
    connect=lambda: psycopg.connect(DSN),
    max_rows=200, statement_timeout_ms=5000,
)
tool = HaltSQLQueryTool(runner=runner)   # name "haltsql_query"; give it to your agent
```

The tool returns JSON rows, or, when nothing ran, the reason codes and hints so
the model can fix its query.

## Guarding an existing SQLDatabase

```python
from langchain_community.utilities import SQLDatabase
from haltsql_langchain import guard_sql_database

db = SQLDatabase.from_uri("postgresql+psycopg://agent_ro@db/app")
guarded = guard_sql_database(db, HaltSQLClient.from_env(), lambda: {"tenant_id": tenant})
# use `guarded` in SQLDatabaseToolkit / create_sql_agent; run() and run_no_throw() are guarded
```

The copy is still an `SQLDatabase`, so toolkits accept it. The engine must use
psycopg 3 (`postgresql+psycopg://`). Caller-supplied `parameters=` and
`fetch="cursor"` are refused.

The copy never reads table rows outside HaltSQL. `SQLDatabase.get_table_info`
normally adds sample rows read straight from the engine
(`sample_rows_in_table_info`, default 3), which would show other tenants' rows
to the model; on the guarded copy it is forced to 0, so table descriptions show
the schema only. The internal `_execute` refuses. Schema reflection (table and
column names) still uses the engine, and the original `db` is unchanged: do not
hand it to the agent.

## Context

The context is a mapping or a zero-argument callable evaluated on every query.
A callable that returns `None` refuses the query: nothing is verified or run,
and the model sees "No trusted HaltSQL context is configured for this request".
A callable that raises is reported as "SQL verification is unavailable", with
no exception details. An explicit `{}` is verified as an empty context (tenant
tables are then denied by the policy).

## Read-only and writes

With `read_only=True` (the default) only statements whose verdict
`statement_kind` is `select` run, in a `READ ONLY` transaction; anything else
is refused before a connection is taken, even when the policy allows it.

With `read_only=False` the policy alone decides: a statement runs only when
HaltSQL allows it, whatever its kind, writes in a read-write transaction and
`SELECT` still `READ ONLY`. A verdict without a `statement_kind` never runs.
Allow writes in the policy only for the tables and columns you mean to.

## Tests

```sh
pytest -q integrations/langchain   # framework tests skip if langchain is not installed
```
