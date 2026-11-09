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
engine = guarded_nl_sql_query_engine(db, hs, ctx, tables=["orders"], llm=llm, max_rows=50)
```

Guard options (`max_rows`, `statement_timeout_ms`, `settings`, `read_only`,
`denials_as_sql_errors`) can be passed to `guarded_nl_sql_query_engine` as
keyword arguments or in `guard_kwargs={...}`; the other keywords go to
`NLSQLTableQueryEngine`. Giving the same option both ways, or an unknown key in
`guard_kwargs`, raises `TypeError`.

The guarded copy never runs SQL on the engine outside HaltSQL: `run_sql` is
verified, and `insert_into_table` (used by `SQLStructStoreIndex`) raises
`haltsql.GuardError`. Table descriptions (`get_single_table_info`) read the
schema only, never rows. The `engine` property still returns the raw engine,
and the original `db` is unchanged: do not hand either to the agent.

A context callable that returns `None` refuses the query
(`haltsql.integration.ContextUnavailable`, or a `HaltSQLSQLError` saying no
trusted context is configured); nothing is verified. An explicit `{}` is
verified as an empty context.

With `read_only=True` (the default) only statements whose verdict
`statement_kind` is `select` run, in a `READ ONLY` transaction; anything else
raises `haltsql.GuardError` before a connection is taken, even when the policy
allows it. With `read_only=False` the policy alone decides: what HaltSQL allows
runs, writes read-write and `SELECT` still `READ ONLY`; a verdict without a
`statement_kind` never runs.

By default a denial raises `haltsql.QueryDenied`. With
`denials_as_sql_errors=True` (the default for `guarded_nl_sql_query_engine`) it
raises `HaltSQLSQLError`, a `NotImplementedError` that LlamaIndex shows to the
LLM so it can fix the query. Do not use `SQLDatabase(schema=...)`: schema
prefixing would change the verified SQL; set `search_path` instead.

## Tests

```sh
pytest -q integrations/llamaindex   # framework tests skip if llama-index-core is not installed
```
