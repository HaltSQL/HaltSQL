# haltsql-vanna

HaltSQL guard for [Vanna](https://github.com/vanna-ai/vanna). Every SQL string
Vanna generates is verified by HaltSQL first; only the exact verified string
runs, with the bound tenant parameters, in a read-only transaction.

```sh
pip install 'haltsql-vanna[vanna]'
```

## Vanna 2.x

```python
from haltsql import AsyncHaltSQLClient
from haltsql_vanna import HaltSQLSqlRunner
from vanna.tools import RunSqlTool

runner = HaltSQLSqlRunner(AsyncHaltSQLClient.from_env(), dsn="postgresql://agent_ro@db/app")
tool = RunSqlTool(sql_runner=runner)
```

The tenant context comes from the authenticated `ToolContext.user`: by default
`user.metadata["haltsql_context"]`, which your `UserResolver` sets from the
request (for example `{"tenant_id": "acme"}`). Pass `context_from_user=` to
derive it differently. A user without a context is refused.

## Vanna 0.x (legacy `VannaBase`)

```python
from haltsql import HaltSQLClient
from haltsql_vanna import install_legacy_run_sql

install_legacy_run_sql(vn, HaltSQLClient.from_env(), lambda: {"tenant_id": tenant},
                       dsn="postgresql://agent_ro@db/app")
vn.ask("How many open orders do we have?")
```

Denials raise `haltsql.QueryDenied`; its message lists the reason codes and hints.
A `context` callable (or a 2.x `context_from_user`) that returns `None` raises
`haltsql.integration.ContextUnavailable`; nothing is verified or run.

## Tests

```sh
pytest -q integrations/vanna   # framework tests skip if vanna is not installed
```
