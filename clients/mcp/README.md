# haltsql-mcp

The safe drop-in replacement for `@modelcontextprotocol/server-postgres`.
Same `query(sql)` tool, same positional connection string, plus column, tenant
and function guardrails, a row cap and a statement timeout.

```sh
haltsql-mcp --local-policy policy.yaml postgresql://agent_ro@localhost/mydb
```

Or with Docker (includes the `haltsql` CLI; no central server needed):

```sh
docker run -i --rm --read-only -v "$PWD:/config:ro" ghcr.io/haltsql/haltsql-mcp:0.0.3 \
  postgresql://agent_ro@host.docker.internal/mydb      # /config/policy.yaml is picked up
```

Build it with `docker build -f clients/mcp/Dockerfile .` from the repository
root, and see `scripts/mcp-docker-smoke.sh` for the end-to-end test.

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
