# haltsql-llamaindex

HaltSQL guard for LlamaIndex text-to-SQL. LlamaIndex executes SQL through
`SQLDatabase.run_sql`; `guard_sql_database` returns a copy whose `run_sql`
verifies each statement with HaltSQL and runs only the exact verified string
with the bound tenant parameters, read-only.

```sh
pip install './integrations/llamaindex[llamaindex]'   # needs ../../clients/python too
```

```python
from sqlalchemy import create_engine
from llama_index.core import SQLDatabase
from haltsql import HaltSQLClient
from haltsql_llamaindex import guard_sql_database, guarded_nl_sql_query_engine, guarded_sql_retriever

db = SQLDatabase(create_engine("postgresql+psycopg://agent_ro@db/app"), include_tables=["orders"])
ctx = lambda: {"tenant_id": current_session().tenant_id}   # from your auth, per query
hs = HaltSQLClient.from_env()

guarded = guard_sql_database(db, hs, ctx)                  # pass anywhere a SQLDatabase goes
retriever = guarded_sql_retriever(db, hs, ctx)             # SQLRetriever
engine = guarded_nl_sql_query_engine(db, hs, ctx, tables=["orders"], llm=llm)
```

By default a denial raises `haltsql.QueryDenied`. With
`denials_as_sql_errors=True` (the default for `guarded_nl_sql_query_engine`) it
raises `HaltSQLSQLError`, a `NotImplementedError` that LlamaIndex shows to the
LLM so it can fix the query. Do not use `SQLDatabase(schema=...)`: schema
prefixing would change the verified SQL; set `search_path` instead.

## Tests

```sh
pytest -q integrations/llamaindex   # framework tests skip if llama-index-core is not installed
```
