# haltsql-langchain

HaltSQL guard for LangChain SQL agents. Every statement is verified by HaltSQL
before it runs; only the exact verified string runs, with the bound tenant
parameters, read-only by default.

```sh
pip install './integrations/langchain[langchain]'   # needs ../../clients/python too
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

## Tests

```sh
pytest -q integrations/langchain   # framework tests skip if langchain is not installed
```
