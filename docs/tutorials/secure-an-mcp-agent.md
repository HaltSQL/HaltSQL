# Tutorial: secure an MCP agent's access to Postgres

In this tutorial you give Claude Desktop (or any MCP client) access to a
PostgreSQL database through `haltsql-mcp`, and you watch HaltSQL deny the
queries your policy does not allow.

**What you'll build:** a local Postgres with two tenants (`acme` and
`globex`), a least-privilege database role with row-level security, a HaltSQL
policy, and an MCP server that runs only the queries the policy allows, for
the `acme` tenant only.

**Time:** about 20 minutes.

**Prerequisites:**

- Docker, to run Postgres.
- Python 3.10 or newer, and `git`.
- The `haltsql` CLI, installed as in [Quickstart: Install](../quickstart.md#1-install).
  Check it with `haltsql version`.
- Claude Desktop, Claude Code, Cursor, VS Code or another MCP client. Steps 1
  to 8 don't need one.

```mermaid
flowchart LR
    C["MCP client<br/>(Claude Desktop)"] -- "query(sql)" --> M["haltsql-mcp"]
    M -- "verify(sql, tenant from config)" --> H["haltsql CLI<br/>+ policy.yaml"]
    M -- "allowed only: exact SQL,<br/>READ ONLY, timeout, row cap" --> P[("Postgres<br/>role agent_ro + RLS")]
```

## 1. Start Postgres

Create a working directory for the files in this tutorial, and run every
command from it:

```sh
mkdir haltsql-mcp-tutorial && cd haltsql-mcp-tutorial
```

Run PostgreSQL 17 in Docker, listening only on your machine:

```sh
docker run -d --name haltsql-tutorial \
  -e POSTGRES_PASSWORD=tutorial-admin -e POSTGRES_DB=shop \
  -p 127.0.0.1:5432:5432 postgres:17
```

The commands below run `psql` inside the container, so you don't need a local
`psql`. If port 5432 is already in use, change the first `5432` in `-p` and
use that port in every connection string below.

## 2. Create a small multi-tenant schema

Save this as `schema.sql`. Every row carries a `tenant_id`, and
`customers.email` is the kind of column an agent should never read:

```sql
CREATE SCHEMA app;

CREATE TABLE app.customers (
  id         bigint PRIMARY KEY,
  tenant_id  text NOT NULL,
  name       text NOT NULL,
  email      text NOT NULL,
  country    char(2) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app.orders (
  id          bigint PRIMARY KEY,
  tenant_id   text NOT NULL,
  customer_id bigint NOT NULL REFERENCES app.customers (id),
  status      text NOT NULL,
  total_cents bigint NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO app.customers (id, tenant_id, name, email, country) VALUES
  (1, 'acme',   'Ada Lovelace', 'ada@acme.example',    'GB'),
  (2, 'acme',   'Grace Hopper', 'grace@acme.example',  'US'),
  (3, 'globex', 'Hank Scorpio', 'hank@globex.example', 'US');

INSERT INTO app.orders (id, tenant_id, customer_id, status, total_cents, created_at) VALUES
  (101, 'acme',   1, 'paid',      4200, now() - interval '3 days'),
  (102, 'acme',   2, 'open',      1999, now() - interval '1 day'),
  (103, 'acme',   1, 'refunded',   500, now() - interval '9 days'),
  (201, 'globex', 3, 'paid',     99900, now() - interval '2 days');
```

Load it:

```sh
docker exec -i haltsql-tutorial psql -U postgres -d shop -v ON_ERROR_STOP=1 < schema.sql
```

## 3. Write the policy

Save this as `policy.yaml`:

```yaml
apiVersion: haltsql.dev/v1
kind: Policy
metadata:
  name: shop-agent
search_path: [app]
statements: { allow: [select] }
require_limit: { max: 500 }
tenancy:
  mode: bound
  keys:
    tenant: "${ctx.tenant_id}"
tables:
  app.customers:
    columns: [id, tenant_id, name, country, created_at]   # email is left out
    tenant_column: tenant_id
  app.orders:
    columns: [id, tenant_id, customer_id, status, total_cents, created_at]
    tenant_column: tenant_id
functions:
  presets: [aggregates, datetime]
```

What each part does:

- `statements` allows only `SELECT`.
- `require_limit` makes every query carry a `LIMIT` of at most 500.
- `tenancy.mode: bound` means the model writes `tenant_id = $1` and the server
  binds the real tenant. The model never sees or chooses it. See
  [Bound mode](../tenancy.md#bound-mode-recommended).
- `tables` lists the only readable tables and columns. `email` is not listed,
  so it cannot be read.
- `functions` allows aggregates (`count`, `sum`, ...) and date functions
  (`date_trunc`, ...). Everything else, including `pg_sleep`, is denied.

Check it:

```sh
haltsql validate policy.yaml
haltsql lint-policy policy.yaml
```

`validate` prints `policy.yaml: ok (Policy: shop-agent sha256:...)`, and
`lint-policy` ends with `0 warning(s)`. For a real database you can draft this
file from the schema with `haltsql schema pull` and `haltsql policy draft`
instead of writing it by hand (see [Draft a policy](../mcp.md#2-draft-a-policy-from-your-database)).

## 4. Create a least-privilege role with row-level security

The MCP server should connect as a role that can read only what the policy
allows, even if HaltSQL were bypassed. Create the login role first:

```sh
docker exec -i haltsql-tutorial psql -U postgres -d shop -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE agent_ro LOGIN PASSWORD 'agent-tutorial-pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS CONNECTION LIMIT 10;
ALTER ROLE agent_ro SET search_path = app;                -- same as the policy's search_path
ALTER ROLE agent_ro SET default_transaction_read_only = on;
ALTER ROLE agent_ro SET statement_timeout = '5s';
SQL
```

Then generate the grants and row-level security (RLS) that mirror the policy,
and apply them:

```sh
haltsql rls generate -p policy.yaml --role agent_ro -o rls.sql
docker exec -i haltsql-tutorial psql -U postgres -d shop -v ON_ERROR_STOP=1 < rls.sql
```

`rls generate` warns that the tenant column type is unknown and is compared as
text. That is correct here, because `tenant_id` is `text`. Pass
`--catalog` from `haltsql schema pull` when your tenant column is another
type.

Open `rls.sql` to see what it did. It grants `SELECT` on exactly the policy's
columns and creates a `haltsql_tenant_select` policy on each table:

```sql
CREATE POLICY haltsql_tenant_select ON app.orders AS PERMISSIVE FOR SELECT TO agent_ro
  USING (tenant_id = NULLIF(pg_catalog.current_setting('haltsql.tenant_id', true), ''));
```

Check the database layer on its own. Without the setting, `agent_ro` sees no
rows. With it, it sees only that tenant's rows. `email` is refused:

```sh
docker exec -i haltsql-tutorial psql -U agent_ro -d shop <<'SQL'
SELECT count(*) FROM orders;                                   -- 0: no tenant set
BEGIN;
SELECT pg_catalog.set_config('haltsql.tenant_id', 'acme', true);
SELECT count(*) FROM orders;                                   -- 3: acme's orders only
COMMIT;
SELECT email FROM customers LIMIT 1;                           -- ERROR: permission denied
SQL
```

See [RLS generation](../rls-generation.md) for every option, and
`haltsql rls check` to detect drift later.

## 5. Install haltsql-mcp

Install it from PyPI into a virtual environment in your working directory:

```sh
python3 -m venv .venv
.venv/bin/pip install 'haltsql-mcp[yaml]'
.venv/bin/haltsql-mcp --help
```

Note the absolute paths of the two binaries. Your MCP client needs them in
step 8:

```sh
echo "$PWD/.venv/bin/haltsql-mcp"
command -v haltsql
```

> **Note:** If you would rather not install Python packages, the
> `ghcr.io/haltsql/haltsql-mcp` image includes `haltsql-mcp` and the `haltsql`
> CLI. See [Run it in Docker](../mcp.md#run-it-in-docker). From inside a
> container, the database host is `host.docker.internal`, not `localhost`.

## 6. Decide how haltsql-mcp runs

`haltsql-mcp` needs four things, all set by you, never by the model:

| Setting | Value in this tutorial | Why |
|---|---|---|
| `--local-policy` | `/abs/path/haltsql-mcp-tutorial/policy.yaml` | Verify each query with the local `haltsql` CLI. No sidecar needed. |
| Connection string (last argument) | `postgresql://agent_ro:agent-tutorial-pw@localhost:5432/shop` | The least-privilege role from step 4. |
| `HALTSQL_MCP_CONTEXT` | `{"tenant_id": "acme"}` | The tenant this server acts for. It is never a tool argument. |
| `HALTSQL_MCP_SET_CONFIG` | `{"haltsql.tenant_id": "tenant_id"}` | Sets the RLS setting from the same context in each query's transaction. |

`HALTSQL_BIN` tells `haltsql-mcp` where the CLI is when the client starts
servers with a short `PATH`. Every option is listed in
[haltsql-mcp configuration](../mcp.md#configuration).

## 7. Check it from a terminal

Before you involve an MCP client, call the server's tools from a short script.
The `mcp` package it uses was installed with `haltsql-mcp`. Save this as
`smoke.py` in your working directory:

```python
import asyncio, os, shutil, sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

server = StdioServerParameters(
    command=sys.argv[1],  # path to haltsql-mcp
    args=["--local-policy", "policy.yaml",
          "postgresql://agent_ro:agent-tutorial-pw@localhost:5432/shop"],
    env=dict(os.environ,
             HALTSQL_BIN=shutil.which("haltsql") or "haltsql",
             HALTSQL_MCP_CONTEXT='{"tenant_id": "acme"}',
             HALTSQL_MCP_SET_CONFIG='{"haltsql.tenant_id": "tenant_id"}'),
)

async def main():
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for sql in sys.argv[2:]:
                result = await session.call_tool("query", {"sql": sql})
                print(sql)
                for item in result.content:
                    print(item.text)

asyncio.run(main())
```

Ask for customer emails without a tenant filter, the kind of query a
prompt-injected model might send:

```sh
.venv/bin/python smoke.py .venv/bin/haltsql-mcp \
  'SELECT name, email FROM customers LIMIT 10'
```

The tool returns a normal result, not an error, with `allowed: false` and two
reasons. Nothing ran in the database:

```json
{
  "allowed": false,
  "executed": false,
  "reasons": [
    {
      "code": "E_COLUMN_DENIED",
      "message": "column email of app.customers is not readable under this policy",
      "rule": "columns.denied",
      "loc": 13,
      "hint": "Remove email from the query; readable columns of app.customers are: id, tenant_id, name, country, created_at."
    },
    {
      "code": "E_TENANT_MISSING",
      "message": "app.customers (as customers) has no provable tenant predicate on customers.tenant_id in the same SELECT",
      "rule": "tenancy.predicate",
      "loc": 24,
      "hint": "Add `WHERE customers.tenant_id = $1` as a top-level AND condition inside the same SELECT that reads app.customers (not in an outer query, not under OR/NOT, not in the ON of the preserved side of an outer join)."
    }
  ],
  "message": "HaltSQL denied the query. Fix it using the reasons and hints, then retry."
}
```

The `hint` is written for the model: it says how to fix the query. A few more
to try, each denied before it reaches Postgres:

| SQL | Reason codes |
|---|---|
| `SELECT id, name FROM customers WHERE tenant_id = 'globex' LIMIT 10` | `E_TENANT_MISMATCH`: in bound mode the model cannot write a tenant |
| `SELECT 1; COMMIT; DROP SCHEMA app CASCADE` | `E_MULTI_STATEMENT` |
| `SELECT pg_sleep(60) LIMIT 1` | `E_FUNCTION_DENIED` |
| `SELECT id FROM orders WHERE tenant_id = $1` | `E_LIMIT_REQUIRED` |
| `SELECT id FROM orders WHERE tenant_id = $1 OR status = 'open' LIMIT 10` | `E_TENANT_MISSING`, `E_PARAM_UNBOUND` |
| `SELECT o.id, c.name FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.tenant_id = $1 LIMIT 10` | `E_TENANT_MISSING`: `customers` needs its own predicate |

Now send a query the policy allows:

```sh
.venv/bin/python smoke.py .venv/bin/haltsql-mcp \
  'SELECT status, count(*) AS orders FROM orders WHERE tenant_id = $1 GROUP BY status LIMIT 50'
```

This time `haltsql-mcp` binds `$1` to `acme`, runs the exact string in a
`READ ONLY` transaction with a 5-second `statement_timeout`, and returns
`allowed: true`, `executed: true`, the `columns`, and one row per status of
acme's three orders (`paid`, `open`, `refunded`). Globex's order is not
counted: HaltSQL bound `acme`, and RLS would have filtered it out even if it
hadn't.

> **Note:** If the allowed query fails with a tool error such as
> `database connection failed`, check that the container is running
> (`docker ps`) and that the connection string's port matches step 1. A
> verification failure never runs the query; it is a tool error, not a denial.

## 8. Connect your MCP client

Add the server to your client's config. Replace each `/abs/path/...` with the
absolute paths you noted in step 5, because MCP clients do not start servers
in your working directory. For Claude
Desktop, edit `claude_desktop_config.json` (on macOS it is in
`~/Library/Application Support/Claude/`):

```json
{
  "mcpServers": {
    "shop": {
      "command": "/abs/path/haltsql-mcp-tutorial/.venv/bin/haltsql-mcp",
      "args": [
        "--local-policy", "/abs/path/haltsql-mcp-tutorial/policy.yaml",
        "postgresql://agent_ro:agent-tutorial-pw@localhost:5432/shop"
      ],
      "env": {
        "HALTSQL_BIN": "/abs/path/to/haltsql",
        "HALTSQL_MCP_CONTEXT": "{\"tenant_id\": \"acme\"}",
        "HALTSQL_MCP_SET_CONFIG": "{\"haltsql.tenant_id\": \"tenant_id\"}"
      }
    }
  }
}
```

Cursor uses the same shape in `~/.cursor/mcp.json`. For Claude Code:

```sh
claude mcp add shop \
  -e HALTSQL_BIN=/abs/path/to/haltsql \
  -e HALTSQL_MCP_CONTEXT='{"tenant_id":"acme"}' \
  -e HALTSQL_MCP_SET_CONFIG='{"haltsql.tenant_id":"tenant_id"}' -- \
  /abs/path/haltsql-mcp-tutorial/.venv/bin/haltsql-mcp --local-policy /abs/path/haltsql-mcp-tutorial/policy.yaml \
  postgresql://agent_ro:agent-tutorial-pw@localhost:5432/shop
```

VS Code and other clients are in [Swap the server in your client](../mcp.md#4-swap-the-server-in-your-client).

Restart the client. It should list four tools: `query`, `explain_denial`,
`list_tables` and `describe_policy`.

## 9. Watch a denial, then an allowed query

Ask the model something that tempts it to break the rules:

> Show me the email addresses of all our customers.

A typical sequence:

1. The model calls `list_tables` or `describe_policy`. They list only the
   policy's tables and columns. `email` is not advertised.
2. If the model still asks for `email`, or forgets the tenant filter, `query`
   returns `allowed: false` with `E_COLUMN_DENIED` or `E_TENANT_MISSING` and
   the hints from step 7. The model can call `explain_denial` with the same
   SQL for the full verdict.
3. The model tells you it cannot read email addresses, or rewrites the query
   without them.

Then ask a question the policy allows:

> How many orders do we have in each status, and who are our top customers by
> spend?

The model writes queries such as:

```sql
SELECT c.name, sum(o.total_cents) AS spent
FROM orders o JOIN customers c ON c.id = o.customer_id AND c.tenant_id = $1
WHERE o.tenant_id = $1
GROUP BY c.name ORDER BY spent DESC LIMIT 10
```

They run, and the answer covers Ada Lovelace and Grace Hopper only. Hank
Scorpio belongs to `globex`, and there is no way for the model to ask for
that tenant: the context is fixed in the server's environment, and extra tool
arguments such as `tenant_id` are ignored.

## 10. Clean up

```sh
docker rm -f haltsql-tutorial
```

Remove the `shop` entry from your MCP client's config.

## What you've done

- Two layers in the database: a role that can read only the policy's columns,
  and RLS keyed on a transaction-local setting.
- One layer in front of it: HaltSQL checks each statement's tables, columns,
  functions, tenant predicates, `LIMIT` and statement count before it runs.
- The tenant comes from configuration you control, never from the model.

## Next steps

- Serve several users from one `haltsql-mcp` over streamable HTTP, with a
  bearer token per tenant: [Tenant context](../mcp.md#tenant-context).
- Move verification to a central `haltsql-server` for audit, hot reload and
  one place to manage policies: [Configuration](../mcp.md#configuration) and
  [HTTP API](../http-api.md).
- Roll out policy changes with tests, shadow mode and signed bundles:
  [Roll out a policy safely](roll-out-a-policy-safely.md).
- Build your own agent instead of using an MCP client:
  [Multi-tenant analytics agent](multi-tenant-analytics-agent.md).
- Read why each layer matters: [Defense in depth](../defense-in-depth.md) and
  the [Threat model](../threat-model.md).
