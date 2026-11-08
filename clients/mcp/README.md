# haltsql-mcp

An MCP server that lets an agent query PostgreSQL only through
[HaltSQL](https://github.com/HaltSQL/HaltSQL): every SQL string is verified
against your policy, then exactly that string runs with server-bound
parameters in a read-only transaction (row cap, `statement_timeout`).

Tools: `query(sql)`, `explain_denial(sql)`, `list_tables()`, `describe_policy()`.
The tenant comes from server configuration (stdio) or the authenticated
bearer token (streamable HTTP), never from tool arguments.

```sh
pip install ../python .   # Python 3.10+
HALTSQL_URL=http://127.0.0.1:8080 HALTSQL_TOKEN=... \
HALTSQL_MCP_DATABASE_URL=postgresql://agent_ro@db/app \
HALTSQL_MCP_CONTEXT='{"tenant_id":"acme"}' haltsql-mcp
```

See [docs/mcp.md](../../docs/mcp.md) for configuration, the tokens file, and
examples. `haltsql-mcp --help` lists every flag.

## Tests

```sh
python3 -m venv .venv && .venv/bin/pip install -e ../python -e '.[test,yaml]'
.venv/bin/pytest -q
```
