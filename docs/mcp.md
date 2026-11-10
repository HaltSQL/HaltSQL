# haltsql-mcp: the safe drop-in replacement for the Postgres MCP server

If you connected Claude Desktop, Cursor, VS Code or your own agent to
PostgreSQL by following the MCP quickstarts, you are probably running
[`@modelcontextprotocol/server-postgres`][ref-readme]. That server sends
whatever SQL the model writes straight to your database. It checks no
columns, no tenants and no functions. It sets no row cap and no timeout.

`haltsql-mcp` (in [`clients/mcp`](../clients/mcp)) is a replacement you can
swap in directly. It exposes the same `query` tool with the same `sql`
argument, and it takes the connection string the same way, as the last
argument. The difference is what happens before a query runs: HaltSQL parses
the SQL with the real PostgreSQL parser and checks it against your policy.
Only after that check passes does the exact verified string run, with
server-bound parameters, in a read-only transaction that has a
`statement_timeout` and a row cap.

```diff
 {
   "mcpServers": {
-    "postgres": {
-      "command": "npx",
-      "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/mydb"]
-    }
+    "postgres": {
+      "command": "haltsql-mcp",
+      "args": ["--local-policy", "/path/to/policy.yaml", "postgresql://agent_ro@localhost/mydb"],
+      "env": { "HALTSQL_MCP_CONTEXT": "{\"tenant_id\": \"acme\"}" }
+    }
   }
 }
```

Or use Docker with nothing else installed: mount a folder that holds
`policy.yaml` and pass the same connection string.
[Run it in Docker](#run-it-in-docker).

[Switch in five minutes](#switch-in-five-minutes) ·
[What changes for the agent](#what-changes-for-the-agent) ·
[Reference](#tools)

## Why replace `server-postgres`

**It is archived and unmaintained.** On 2025-05-28 the MCP project moved it
to [`modelcontextprotocol/servers-archived`][archived]. Every version on npm
is marked deprecated with the notice "Archived and unmaintained; no security
guarantees". It still had about 146,000 npm downloads in the first week of
November 2026 ([npm API][downloads]).

**Its read-only guard can be escaped, and the published package was never
patched.** The server runs `BEGIN TRANSACTION READ ONLY`, then passes the
model's string to `client.query()`, which accepts several statements
separated by semicolons. Datadog Security Labs [showed][datadog] that
`COMMIT; DROP SCHEMA public CASCADE;` ends the read-only transaction and runs
the `DROP`. A `SET` placed after the `COMMIT` stays on the pooled connection
and affects later callers. A fix was committed to git when the server was
archived ([PR #1889][fix]), but npm `latest` is still 0.6.2 (published
2024-12-04), and that build has the vulnerable code.

**Even when the guard works, read-only is not a policy.** A `READ ONLY`
transaction blocks writes and nothing else. Any model with the tool can still:

- read every column of every table the database role can see, including
  `email`, `ssn` and `password_hash`;
- read every tenant's rows, because nothing scopes a query to the user the
  agent is acting for;
- call any function the role can execute. That includes `pg_sleep` (the
  server sets no timeout) and, when the role is privileged, `pg_read_file`,
  `pg_ls_dir` and `lo_export`. The PostgreSQL docs warn that these
  [bypass all in-database privilege checks][pg-genfile];
- return as many rows as a query produces, because there is no row cap.

Prompt injection makes each of these an attack, not just a mistake. A
support ticket, a web page or a row in the database can tell the model to run
one of these queries.

## Side by side

| | `@modelcontextprotocol/server-postgres` 0.6.2 | `haltsql-mcp` |
|---|---|---|
| Maintenance | Archived 2025-05-28; deprecated on npm | Maintained in this repository; MIT |
| Tool | `query(sql)` | `query(sql)`, plus `explain_denial`, `list_tables`, `describe_policy` |
| Connection string | Positional argument | Positional argument, `--database-url` or `HALTSQL_MCP_DATABASE_URL` |
| SQL parsing | None; the raw string goes to the driver | The PostgreSQL parser ([libpg_query](https://github.com/pganalyze/libpg_query)) |
| Several statements in one call | Runs them all (`COMMIT; DROP ...` escapes read-only) | Denied (`E_MULTI_STATEMENT`) before anything runs |
| Statement types | Anything; relies on `READ ONLY` | Allowlist (`statements.allow`, usually `select`), and the query still runs in `READ ONLY` |
| Tables and columns | All that the role can see | Explicit allowlist per table (`E_TABLE_DENIED`, `E_COLUMN_DENIED`) |
| Tenant isolation | None | Proven tenant predicate on every tenant table, in every subquery, CTE and `UNION` branch (`E_TENANT_MISSING`). The tenant comes from the server, never from the model |
| Functions | All that the role can execute | Allowlist with presets (`E_FUNCTION_DENIED`). Built-in functions that run a SQL string (`query_to_xml`, `dblink`, `ts_rewrite`, ...) are always denied |
| Row cap | None | `--row-cap` (default 200), plus `require_limit` in the policy |
| Timeout | None | `statement_timeout` per query (default 5 s) |
| Connection state | Pooled; `SET` persists between calls | New connection per query; settings are transaction-local |
| Row-level security | None | `HALTSQL_MCP_SET_CONFIG` sets the tenant for RLS in each transaction |
| Denials | Database errors | Reason codes and hints the model uses to fix its SQL |
| Multi-user | stdio only, one database URL | stdio, or streamable HTTP with a bearer token per tenant |
| Audit | None | Hash-chained audit through the sidecar ([audit sinks](audit-sinks.md)) |

## What the same prompts do

Here are queries a misled model might send. The `haltsql-mcp` column shows
real output from `haltsql verify` against
[`examples/policies/saas.yaml`](../examples/policies/saas.yaml) with the
context `{"tenant_id": "acme"}`.

| The model sends | `server-postgres` | `haltsql-mcp` |
|---|---|---|
| `SELECT 1; COMMIT; DROP SCHEMA app CASCADE` | Drops the schema | `E_MULTI_STATEMENT`: expected exactly one statement, found 3 |
| `SELECT name, email FROM customers LIMIT 10` | Returns every tenant's email addresses | `E_COLUMN_DENIED` (email) and `E_TENANT_MISSING` |
| `SELECT id, name FROM customers LIMIT 10` | Returns every tenant's customers | `E_TENANT_MISSING`: no provable tenant predicate on `customers.tenant_id` |
| `SELECT id, name FROM customers WHERE tenant_id = 'globex' LIMIT 10` | Returns another tenant's rows | `E_TENANT_MISMATCH`: the policy binds the tenant; the model cannot choose it |
| `SELECT pg_sleep(60) LIMIT 1` | Holds a connection for 60 s, with no timeout | `E_FUNCTION_DENIED` |
| `SELECT pg_read_file('/etc/passwd') LIMIT 1` | Runs if the role has the privilege | `E_FUNCTION_DENIED` |
| `SELECT id, name FROM customers WHERE tenant_id = $1 LIMIT 10` | Fails: it binds no parameters | Allowed. The server binds `$1` to `acme` and returns at most 200 rows |

A denial is a normal tool result, not an error. It carries the reason codes
and hints, so the model can fix its query and try again. Nothing runs until
the query passes.

## Switch in five minutes

### 1. Install

**Docker (nothing else to install).** The `ghcr.io/haltsql/haltsql-mcp` image
includes `haltsql-mcp` and the `haltsql` CLI, so it verifies queries itself.
You don't need a central server, Python or anything else. See
[Run it in Docker](#run-it-in-docker).

```sh
docker pull ghcr.io/haltsql/haltsql-mcp:0.0.3
alias haltsql='docker run --rm -i -v "$PWD:/w" -w /w --entrypoint haltsql ghcr.io/haltsql/haltsql-mcp:0.0.3'
```

With the alias, a database on your machine is `host.docker.internal` rather
than `localhost` (see
[Reaching your database](#reaching-your-database-from-the-container)).

**pip:**

```sh
pip install 'haltsql-mcp[yaml]'   # Python 3.10+; pulls in the haltsql SDK
```

With pip, install the `haltsql` CLI too. You need it to draft the policy and
to verify queries without a central server. It comes as a release binary or
through opam ([quickstart](quickstart.md#1-install)).

### 2. Draft a policy from your database

You don't have to write the policy by hand. Snapshot the schema, then draft a
policy from the snapshot:

```sh
PGPASSWORD=... haltsql schema pull --dsn postgres://ro@localhost:5432/mydb \
    --schema public -o catalog.json
haltsql policy draft --catalog catalog.json --tenant-column tenant_id \
    --schema public -o policy.yaml
haltsql lint-policy policy.yaml
```

The draft lists every table with an explicit column list. Columns whose names
look like PII (`email`, `phone`, `ssn`, `password`, `token` and similar) are
left out, each with a comment saying why. The draft also sets the tenant
column wherever it exists and requires a `LIMIT`. Review it before you use
it, especially the tenant columns. See
[schema-and-pii.md](schema-and-pii.md) to import PII labels from dbt,
DataHub and other catalogs, and the [policy reference](policy-reference.md)
for every key.

`--tenant-column` is required. If your database is not multi-tenant, pass a
column name that none of your tables have. Every table is then global (the
draft prints a warning saying so), and you can leave out
`HALTSQL_MCP_CONTEXT`.

### 3. Use a restricted role

Connect as a login role that is not a superuser and does not own the tables,
never as your superuser or owner role. `haltsql rls generate` can give that
role exactly the policy's column grants and tenant row-level security. Create
the login role first, because the script only creates the role when it does
not exist, and creates it as `NOLOGIN`:

```sh
psql "$ADMIN_DSN" -c "CREATE ROLE agent_ro LOGIN PASSWORD '...'"
haltsql rls generate -p policy.yaml --catalog catalog.json --role agent_ro -o rls.sql
psql "$ADMIN_DSN" -v ON_ERROR_STOP=1 -f rls.sql
```

Give the role the same `search_path` as the policy. HaltSQL resolves
unqualified table names with the policy's `search_path`, and Postgres must
resolve them the same way:

```sql
ALTER ROLE agent_ro SET search_path = public;   -- the policy's search_path
```

Then set `HALTSQL_MCP_SET_CONFIG='{"haltsql.tenant_id": "tenant_id"}'` so that
each query's transaction sets the tenant the RLS policies read. See
[rls-generation.md](rls-generation.md) and
[Defense in depth](#defense-in-depth).

### 4. Swap the server in your client

**With Docker.** Put `policy.yaml` in a folder and mount it at `/config`. This
works in Claude Desktop (`claude_desktop_config.json`) and Cursor
(`~/.cursor/mcp.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "postgres": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "--read-only",
        "-v", "/path/to/haltsql:/config:ro",
        "-e", "HALTSQL_MCP_CONTEXT",
        "ghcr.io/haltsql/haltsql-mcp:0.0.3",
        "postgresql://agent_ro@host.docker.internal:5432/mydb"
      ],
      "env": { "HALTSQL_MCP_CONTEXT": "{\"tenant_id\": \"acme\"}" }
    }
  }
}
```

**With pip.** Claude Desktop and Cursor use the same shape:

```json
{
  "mcpServers": {
    "postgres": {
      "command": "haltsql-mcp",
      "args": [
        "--local-policy", "/path/to/policy.yaml",
        "postgresql://agent_ro@localhost:5432/mydb"
      ],
      "env": {
        "HALTSQL_MCP_CONTEXT": "{\"tenant_id\": \"acme\"}"
      }
    }
  }
}
```

**VS Code** (`.vscode/mcp.json`):

```json
{
  "servers": {
    "postgres": {
      "command": "haltsql-mcp",
      "args": ["--local-policy", "/path/to/policy.yaml", "postgresql://agent_ro@localhost:5432/mydb"],
      "env": { "HALTSQL_MCP_CONTEXT": "{\"tenant_id\": \"acme\"}" }
    }
  }
}
```

**Claude Code:**

```sh
claude mcp add postgres -e HALTSQL_MCP_CONTEXT='{"tenant_id":"acme"}' -- \
  haltsql-mcp --local-policy /path/to/policy.yaml postgresql://agent_ro@localhost:5432/mydb
```

If `haltsql-mcp` or `haltsql` is not on the `PATH` your client starts
servers with, use absolute paths: point `command` at the binary (for example
`.venv/bin/haltsql-mcp`) and set `HALTSQL_BIN` in `env`.

`--local-policy` verifies queries with the local `haltsql` CLI, so you don't
need anything else running. In production, run the
[`haltsql-server` sidecar](http-api.md) for central policies, hot reload and
audit. Then replace `--local-policy` with `HALTSQL_URL`, `HALTSQL_TOKEN` and
`--policy-file` (see [Configuration](#configuration)).

A single config file can replace the arguments and environment variables
above. See [Config file](#config-file).

### 5. Try it

Restart the client and ask something like "how many orders did we get last
week?" A well-behaved model calls `describe_policy` or `list_tables` first,
then writes a scoped query. To check the guardrails, ask it to show you
customer emails, or every tenant's orders. You should see a denial with
reason codes, and no rows.

## Run it in Docker

The `ghcr.io/haltsql/haltsql-mcp` image is all a solo developer needs. It
includes `haltsql-mcp` and the static `haltsql` CLI, runs as a non-root user,
and works with a read-only root filesystem. MCP clients start it with
`docker run -i` and talk to it over stdio. The same image can also call a
central `haltsql-server`, or serve many clients over HTTP.

### Solo: a folder and a connection string

```text
~/haltsql/
  policy.yaml          # from `haltsql policy draft`, or written by hand
```

```sh
docker run -i --rm --read-only -v ~/haltsql:/config:ro \
  -e HALTSQL_MCP_CONTEXT='{"tenant_id":"acme"}' \
  ghcr.io/haltsql/haltsql-mcp:0.0.3 postgresql://agent_ro@host.docker.internal:5432/mydb
```

When `/config/policy.yaml` exists and nothing else is configured, the image
verifies every query against it with the bundled CLI. No other process is
involved. Leave out `HALTSQL_MCP_CONTEXT` if your policy has no tenant
tables.

### Everything in one config file

Add `haltsql-mcp.yaml` next to the policy. Then the client config is just
`docker run -i --rm --read-only -v ~/haltsql:/config:ro
ghcr.io/haltsql/haltsql-mcp:0.0.3`:

```yaml
# ~/haltsql/haltsql-mcp.yaml
database_url: postgresql://agent_ro:secret@host.docker.internal:5432/mydb
policy: policy.yaml            # relative to this file
context: { tenant_id: acme }
row_cap: 200
statement_timeout_ms: 5000
```

### Central server: policies, audit and hot reload in one place

To verify through a central `haltsql-server` instead, use a `server` block
in place of `policy`:

```yaml
# ~/haltsql/haltsql-mcp.yaml
server:
  url: https://haltsql.internal:8443
  token_file: token            # file holding the sidecar bearer token
  policy: analytics-agent      # optional; a token is usually pinned to one policy
  ca_file: ca.pem              # optional: private CA for https
database_url: postgresql://agent_ro@db.internal:5432/app
policy_file: policy.yaml       # optional: lets list_tables and describe_policy show the rules
context: { tenant_id: acme }
```

You can do the same with environment variables alone:
`-e HALTSQL_URL=https://haltsql.internal:8443 -e HALTSQL_TOKEN=...`. A
`HALTSQL_URL`, a config file or a `--haltsql-url` flag turns off the
automatic `/config/policy.yaml` local mode. If the server can't be reached
or rejects the token, the query is not executed.

### Shared HTTP server

```sh
docker run -d --name haltsql-mcp -p 127.0.0.1:8765:8765 --read-only \
  -v /etc/haltsql-mcp:/config:ro ghcr.io/haltsql/haltsql-mcp:0.0.3 \
  --transport http --tokens-file /config/tokens.json
```

Clients connect to `http://HOST:8765/mcp` with a bearer token from the
[tokens file](#tenant-context), and each token maps to its own tenant
context. The image listens on all interfaces inside the container
(`HALTSQL_MCP_HOST=0.0.0.0`). Without a tokens file, HTTP is refused off
loopback. TLS is not built in, so put a TLS proxy in front.

### What the image does at startup

| In `/config` | And not set | Effect |
|---|---|---|
| `haltsql-mcp.yaml` (or `.yml`, `.json`) | `HALTSQL_MCP_CONFIG`, `--config` | Loaded as the config file |
| `policy.yaml` (or `.yml`, `.json`) | a config file, `HALTSQL_URL`, `HALTSQL_MCP_LOCAL_POLICY`, `--local-policy`, `--haltsql-url` | Verify locally with this policy |

Anything set explicitly wins. Flags override environment variables, which
override the config file.

### Reaching your database from the container

- **Docker Desktop (macOS, Windows):** use `host.docker.internal` as the host
  in the connection string.
- **Linux:** add `--network host` and use `localhost`, or use the database's
  address on a Docker network.
- **Database in Compose:** use its service name and attach the same network
  (`--network NAME`).

### Build the image yourself

```sh
docker build -t haltsql-local:dev .                    # the haltsql CLI image
docker build -f clients/mcp/Dockerfile --build-arg HALTSQL_IMAGE=haltsql-local:dev -t haltsql-mcp:dev .
scripts/mcp-docker-smoke.sh                            # solo, config file, central, fail-closed
```

Release images are signed with cosign and carry SLSA provenance and an SBOM,
like the main image. Pin a version tag or digest in production.

## What changes for the agent

- **The `query` tool is the same.** It still takes one `sql` string. Results
  are structured (`{allowed, executed, columns, rows, row_count, truncated,
  ...}`) instead of a JSON text dump of the rows.
- **Schema discovery is a tool, not a resource.** `server-postgres` exposes a
  `postgres://<host>/<table>/schema` resource for each table in `public`.
  `haltsql-mcp` offers `list_tables` and `describe_policy`, which list only
  what the policy allows. Tables and columns the agent cannot read are not
  advertised.
- **Queries need a `LIMIT`** when the policy sets `require_limit` (drafts
  do).
- **Tenant tables need a tenant predicate.** In `bound` mode the model writes
  `alias.tenant_id = $1` and the server binds the value. The model never sees
  or chooses the tenant ID. The server instructions and `list_tables` tell
  the model this.
- **One statement per call.** Send separate `query` calls instead.

## How it works

```mermaid
sequenceDiagram
    participant M as Model (Claude, Cursor, agent)
    participant S as haltsql-mcp
    participant H as HaltSQL (CLI or sidecar)
    participant P as PostgreSQL
    M->>S: query(sql)
    S->>H: verify(sql, context from server config / bearer token)
    alt denied
        H-->>S: allowed=false, reasons + hints
        S-->>M: {allowed: false, reasons} (nothing ran)
    else allowed
        H-->>S: allowed=true, bind_params
        S->>P: BEGIN; SET TRANSACTION READ ONLY; set_config(statement_timeout and RLS settings, local)
        S->>P: exact SQL with $n bound
        P-->>S: rows
        S-->>M: {allowed: true, columns, rows (capped), truncated}
    end
```

If verification fails for any reason (the sidecar is down, a TLS error, a
malformed verdict, or a verdict for a different string), nothing runs.

[ref-readme]: https://github.com/modelcontextprotocol/servers-archived/blob/main/src/postgres/README.md
[archived]: https://github.com/modelcontextprotocol/servers-archived
[downloads]: https://api.npmjs.org/downloads/point/last-week/@modelcontextprotocol/server-postgres
[datadog]: https://securitylabs.datadoghq.com/articles/mcp-vulnerability-case-study-SQL-injection-in-the-postgresql-mcp-server/
[fix]: https://github.com/modelcontextprotocol/servers/commit/1f705677a930ec618b7a16d87d00cee7db747ff2
[pg-genfile]: https://www.postgresql.org/docs/current/functions-admin.html#FUNCTIONS-ADMIN-GENFILE

## Tools

| Tool | Arguments | What it does |
|---|---|---|
| `query` | `sql` | Verify, then run read-only with `statement_timeout` and a row cap. Returns `{allowed, executed, columns, rows, row_count, truncated, row_cap, shadow_reasons}`, or `{allowed: false, executed: false, reasons}` when denied. |
| `explain_denial` | `sql` | Verify only. Returns every reason (code, message, hint, loc), the tables and columns touched, and the policy name and version. Never executes. |
| `list_tables` | none | Tables and columns the policy allows, which are tenant-scoped, and guidance on writing tenant predicates. Needs a policy file. |
| `describe_policy` | none | `/v1/policies` (name, version, mode) plus the policy's rules from the policy file: statements, LIMIT rule, tenancy mode and key names, tables, functions. |

All tools are annotated read-only. Infrastructure failures (sidecar down, TLS
errors, malformed verdicts, database errors) are MCP tool errors and nothing
runs; their messages never include the sidecar token or internal exception
details. Denials are normal results so the agent can fix its SQL.

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

Flags override environment variables, and environment variables override the
[config file](#config-file).

| Variable | Flag | Default | Meaning |
|---|---|---|---|
| `HALTSQL_MCP_CONFIG` | `--config` | none (Docker: `/config/haltsql-mcp.yaml` if present) | [Config file](#config-file), overridden by environment variables and flags. |
| `HALTSQL_URL` | `--haltsql-url` | `http://127.0.0.1:8080` | Sidecar URL. |
| `HALTSQL_TOKEN` | | none | Sidecar bearer token (pinned to one policy there). |
| `HALTSQL_POLICY` | `--policy` | none | Policy name to send to the sidecar. |
| `HALTSQL_TIMEOUT` | | `2` | Sidecar timeout per attempt, seconds (3 attempts, bounded backoff). |
| `HALTSQL_CA_FILE` | | system CAs | CA bundle for an `https` sidecar with a private CA. |
| `HALTSQL_CLIENT_CERT` | | none | Client certificate (PEM; may also hold the key) for mutual TLS to the sidecar. |
| `HALTSQL_CLIENT_KEY` | | none | Private key for `HALTSQL_CLIENT_CERT` when it is a separate file. |
| `HALTSQL_MCP_LOCAL_POLICY` | `--local-policy` | none | Verify with the local `haltsql` CLI and this policy instead of a sidecar. |
| `HALTSQL_BIN` | | `haltsql` on `PATH` | CLI used in local mode (and to read YAML policies without PyYAML). |
| `HALTSQL_MCP_DATABASE_URL` (or `DATABASE_URL`) | `--database-url`, or the last positional argument | none | libpq DSN. Without it, `query` is disabled. |
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

### Config file

`--config FILE` or `HALTSQL_MCP_CONFIG` loads one YAML or JSON file. In
Docker, `/config/haltsql-mcp.yaml` is loaded automatically. Relative paths
are resolved against the file's own directory, so the same file works both
natively and in a container. Unknown keys are an error, so a typo can't
silently drop a guardrail.

| Key | Same as |
|---|---|
| `database_url` | `HALTSQL_MCP_DATABASE_URL` |
| `policy` | `HALTSQL_MCP_LOCAL_POLICY` (verify locally; not with `server`) |
| `policy_file` | `HALTSQL_MCP_POLICY_FILE` |
| `context` | `HALTSQL_MCP_CONTEXT` (a mapping) |
| `tokens_file` | `HALTSQL_MCP_TOKENS_FILE` |
| `row_cap`, `statement_timeout_ms` | `HALTSQL_MCP_ROW_CAP`, `HALTSQL_MCP_STATEMENT_TIMEOUT_MS` |
| `set_config` | `HALTSQL_MCP_SET_CONFIG` (a mapping) |
| `transport`, `host`, `port`, `public_url` | `HALTSQL_MCP_TRANSPORT`, `_HOST`, `_PORT`, `_PUBLIC_URL` |
| `haltsql_bin` | `HALTSQL_BIN` |
| `server.url` | `HALTSQL_URL` |
| `server.token_file` | `HALTSQL_TOKEN` (the file's contents). An inline `server.token` is rejected, to keep secrets out of config files |
| `server.policy`, `server.timeout` | `HALTSQL_POLICY`, `HALTSQL_TIMEOUT` |
| `server.ca_file`, `server.client_cert`, `server.client_key` | `HALTSQL_CA_FILE`, `HALTSQL_CLIENT_CERT`, `HALTSQL_CLIENT_KEY` |


## Examples

With the sidecar, from any stdio client:

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

No sidecar (local CLI), with the DSN as the last argument as in `server-postgres`:

```sh
HALTSQL_MCP_CONTEXT='{"tenant_id":"acme"}' haltsql-mcp \
  --local-policy policy.yaml postgresql://agent_ro@localhost/app
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
