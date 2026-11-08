# haltsql-mcp

`haltsql-mcp` (in [`clients/mcp`](../clients/mcp)) is a
[Model Context Protocol](https://modelcontextprotocol.io) server that gives an
agent SQL access to PostgreSQL **through HaltSQL**. Every query is verified
against your policy before it runs, and only the exact verified string runs,
with server-bound parameters, in a read-only transaction.

It uses the official `mcp` Python SDK (1.x or 2.x) and supports stdio and
streamable HTTP.

```sh
pip install ./clients/python ./clients/mcp     # Python 3.10+
```

## Tools

| Tool | Arguments | What it does |
|---|---|---|
| `query` | `sql` | Verify, then run read-only with `statement_timeout` and a row cap. Returns `{allowed, executed, columns, rows, row_count, truncated, row_cap, shadow_reasons}`, or `{allowed: false, executed: false, reasons}` when denied. |
| `explain_denial` | `sql` | Verify only. Returns every reason (code, message, hint, loc), the tables and columns touched, and the policy name and version. Never executes. |
| `list_tables` | none | Tables and columns the policy allows, which are tenant-scoped, and guidance on writing tenant predicates. Needs a policy file. |
| `describe_policy` | none | `/v1/policies` (name, version, mode) plus the policy's rules from the policy file: statements, LIMIT rule, tenancy mode and key names, tables, functions. |

All tools are annotated read-only. Infrastructure failures (sidecar down,
database errors) are MCP tool errors; denials are normal results so the agent
can fix its SQL.

## Tenant context

The tenant context is **never a tool argument**. Extra arguments a model sends
(for example `tenant_id`) are ignored.

- **stdio:** one context per process, from `HALTSQL_MCP_CONTEXT` or
  `--context-file`, set by whoever launches the server for a user.
- **streamable HTTP:** clients authenticate with a bearer token, and each token
  maps to its own context in the tokens file. Without a tokens file the server
  refuses to start (except `--insecure-static-context` on a loopback address,
  for development).

Tokens file (JSON; only SHA-256 hashes are stored):

```json
{
  "tokens": [
    { "name": "agent-acme",   "token_sha256": "<sha256 hex>", "context": { "tenant_id": "acme" } },
    { "name": "agent-globex", "token_sha256": "<sha256 hex>", "context": { "tenant_id": "globex" } }
  ]
}
```

```sh
printf %s "$TOKEN" | shasum -a 256   # value for token_sha256
```

Tokens are compared in constant time against every entry, and the raw token is
never stored or logged.

## Configuration

Flags override environment variables.

| Variable | Flag | Default | Meaning |
|---|---|---|---|
| `HALTSQL_URL` | `--haltsql-url` | `http://127.0.0.1:8080` | Sidecar URL. |
| `HALTSQL_TOKEN` | | none | Sidecar bearer token (pinned to one policy there). |
| `HALTSQL_POLICY` | `--policy` | none | Policy name to send to the sidecar. |
| `HALTSQL_TIMEOUT` | | `2` | Sidecar timeout per attempt, seconds. |
| `HALTSQL_MCP_LOCAL_POLICY` | `--local-policy` | none | Verify with the local `haltsql` CLI and this policy instead of a sidecar. |
| `HALTSQL_BIN` | | `haltsql` on `PATH` | CLI used in local mode (and to read YAML policies without PyYAML). |
| `HALTSQL_MCP_DATABASE_URL` (or `DATABASE_URL`) | `--database-url` | none | libpq DSN. Without it, `query` is disabled. |
| `HALTSQL_MCP_ROW_CAP` | `--row-cap` | `200` | Maximum rows returned (1-10000). |
| `HALTSQL_MCP_STATEMENT_TIMEOUT_MS` | `--statement-timeout-ms` | `5000` | `statement_timeout` per query. |
| `HALTSQL_MCP_SET_CONFIG` | | `{}` | JSON `{"app.tenant_id": "tenant_id"}`: transaction-local custom settings taken from context keys, for row-level security. |
| `HALTSQL_MCP_POLICY_FILE` | `--policy-file` | the local policy | Policy document for `list_tables` / `describe_policy`. |
| `HALTSQL_MCP_CONTEXT` | `--context-file` | `{}` | stdio context (JSON object). |
| `HALTSQL_MCP_TOKENS_FILE` | `--tokens-file` | none | HTTP tokens file. |
| `HALTSQL_MCP_TRANSPORT` | `--transport` | `stdio` | `stdio` or `http`. |
| `HALTSQL_MCP_HOST` / `HALTSQL_MCP_PORT` | `--host` / `--port` | `127.0.0.1` / `8765` | HTTP listener; the endpoint is `/mcp`. |
| `HALTSQL_MCP_PUBLIC_URL` | `--public-url` | `http://HOST:PORT` | External URL (OAuth protected-resource metadata). |

Invalid configuration exits with status `2` and a message on stderr.

## Examples

Claude Desktop / any stdio client:

```json
{
  "mcpServers": {
    "haltsql": {
      "command": "haltsql-mcp",
      "env": {
        "HALTSQL_URL": "http://127.0.0.1:8080",
        "HALTSQL_TOKEN": "…",
        "HALTSQL_MCP_DATABASE_URL": "postgresql://agent_ro@db.internal/app",
        "HALTSQL_MCP_CONTEXT": "{\"tenant_id\": \"acme\"}",
        "HALTSQL_MCP_POLICY_FILE": "/etc/haltsql/policy.yaml"
      }
    }
  }
}
```

Shared HTTP server:

```sh
haltsql-mcp --transport http --host 127.0.0.1 --port 8765 \
  --tokens-file /etc/haltsql-mcp/tokens.json \
  --database-url postgresql://agent_ro@db.internal/app \
  --policy-file /etc/haltsql/policy.yaml
```

No sidecar (local CLI):

```sh
HALTSQL_MCP_CONTEXT='{"tenant_id":"acme"}' haltsql-mcp \
  --local-policy policy.yaml --database-url postgresql://agent_ro@localhost/app
```

## Defense in depth

HaltSQL is the policy check; still connect as a restricted role with row-level
security (see [defense-in-depth.md](defense-in-depth.md)). `HALTSQL_MCP_SET_CONFIG`
sets the tenant for RLS policies inside each query's transaction. TLS is not
built in; keep the HTTP listener on loopback or behind a TLS proxy.

## Tests

```sh
cd clients/mcp
python3 -m venv .venv && .venv/bin/pip install -e ../python -e '.[test,yaml]'
.venv/bin/pytest -q
```

The suite uses an in-process fake sidecar, the MCP in-process and streamable
HTTP clients, and a stdio subprocess. Tests marked `integration` need the lab
Postgres (`make -C lab up`) and skip without it.
