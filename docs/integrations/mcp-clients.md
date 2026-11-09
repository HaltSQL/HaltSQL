# MCP clients

`haltsql-mcp` is an MCP server that runs model-written SQL on PostgreSQL only
after HaltSQL allows it. This page shows how to add it to Claude Desktop,
Claude Code, Cursor, VS Code and any other MCP client, with Docker or a local
install, verifying locally or through `haltsql-server`. For what the server
does and every setting it takes, see [mcp.md](../mcp.md).

## What the client gets

The server exposes four tools. All are annotated read-only.

| Tool | Arguments | What it does |
|---|---|---|
| `query` | `sql` | Verifies the SQL, then runs exactly that string read-only, with `statement_timeout` and a row cap. |
| `explain_denial` | `sql` | Verifies only and returns every reason, the tables and columns touched, and the policy name and version. Never executes. |
| `list_tables` | none | The tables and columns the policy allows and which are tenant-scoped. Needs a policy file. |
| `describe_policy` | none | The policy's name, version and mode (from `haltsql-server`) and its rules (from the policy file). |

The tenant is never a tool argument. If the model sends extra arguments such
as `tenant_id`, they are ignored. See [Tools](../mcp.md#tools) for the result
shapes.

## Before you start

You need three things whichever client you use:

1. **A policy.** Draft one from your database with `haltsql schema pull` and
   `haltsql policy draft`, then review it. See
   [Draft a policy from your database](../mcp.md#2-draft-a-policy-from-your-database).
2. **A restricted database role.** Connect as a login role that can only read,
   never as a superuser or table owner. See
   [Use a restricted role](../mcp.md#3-use-a-restricted-role) and
   [defense-in-depth.md](../defense-in-depth.md).
3. **The server**, as a Docker image or a local install.

**Docker.** The `ghcr.io/haltsql/haltsql-mcp` image contains `haltsql-mcp`
and the `haltsql` CLI, so it can verify queries with no other process:

```sh
docker pull ghcr.io/haltsql/haltsql-mcp
```

**Local install.** `haltsql-mcp` needs Python 3.10 or newer. Install it from a
checkout of the repository:

```sh
git clone https://github.com/HaltSQL/HaltSQL && cd HaltSQL
pip install ./clients/python './clients/mcp[yaml]'
```

The `yaml` extra installs PyYAML, which the server uses to read YAML config and
policy files. To verify locally you also need the `haltsql` CLI on your `PATH`,
or in `HALTSQL_BIN` (see the [quickstart](../quickstart.md#1-install)).

## Choose how queries are verified

| Mode | How to select it | When to use it |
|---|---|---|
| Local policy | `--local-policy FILE`, `HALTSQL_MCP_LOCAL_POLICY`, or `policy:` in the config file. In Docker, a `policy.yaml` in `/config` is picked up when nothing else is set. | One developer, one machine. Each query runs `haltsql verify` with the policy file. Nothing else needs to run. |
| `haltsql-server` | `HALTSQL_URL` and `HALTSQL_TOKEN`, or a `server:` block in the config file. | Shared or production use: central policies, hot reload and audit. See [http-api.md](../http-api.md). |

If you set neither, the server calls a sidecar at the default
`HALTSQL_URL`, `http://127.0.0.1:8080`. When nothing answers there, every
query fails with "verification is unavailable" and nothing runs.

With `haltsql-server`, also set `HALTSQL_MCP_POLICY_FILE` (or `policy_file:`)
to a copy of the policy if you want `list_tables` and the rules part of
`describe_policy` to work. In local mode the local policy is used for that
automatically.

## How the tenant context is supplied

The context (for example `{"tenant_id": "acme"}`) comes from whoever starts
or authenticates to the server, never from the model:

- **stdio** (the default). One context for the whole process, from
  `HALTSQL_MCP_CONTEXT` (a JSON object), `--context-file FILE`, or `context:`
  in the config file. The client sets it in the server's `env` block.
- **Streamable HTTP.** Each client sends a bearer token. The server looks up
  the token's SHA-256 in a tokens file, and each entry has its own context.
  See [Tenant context](../mcp.md#tenant-context) for the file format.

> **Warning:** with stdio, anyone who can edit the client's config file can
> change the tenant. That is fine for one developer working on their own data.
> When the person using the client must not choose the tenant, run the server
> over HTTP with a tokens file, and give each user only their own token.

If the policy has no tenant tables, leave the context out. If it has tenant
tables and the context is empty, queries on them are denied, typically with
[`E_CONTEXT_MISSING`](../reason-codes.md#e_context_missing).

To also enforce the tenant with row-level security, set
`HALTSQL_MCP_SET_CONFIG`, for example `{"app.tenant_id": "tenant_id"}`. Each
query's transaction then sets `app.tenant_id` to the context's `tenant_id`.
See [rls-generation.md](../rls-generation.md).

## Claude Desktop

Claude Desktop starts stdio servers listed in `claude_desktop_config.json`.
The file is at `~/Library/Application Support/Claude/claude_desktop_config.json`
on macOS and `%APPDATA%\Claude\claude_desktop_config.json` on Windows. You can
also open it from the app's developer settings. Restart Claude Desktop after
you change it.

**Docker.** Put `policy.yaml` in a folder and mount the folder at `/config`:

```json
{
  "mcpServers": {
    "postgres": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm", "--read-only",
        "-v", "/path/to/haltsql:/config:ro",
        "-e", "HALTSQL_MCP_CONTEXT",
        "ghcr.io/haltsql/haltsql-mcp",
        "postgresql://agent_ro@host.docker.internal:5432/mydb"
      ],
      "env": { "HALTSQL_MCP_CONTEXT": "{\"tenant_id\": \"acme\"}" }
    }
  }
}
```

`-e HALTSQL_MCP_CONTEXT` with no value passes the variable from `env` into the
container. Inside the container, a database on your machine is
`host.docker.internal`, not `localhost` (see
[Reaching your database from the container](../mcp.md#reaching-your-database-from-the-container)).

**Local install:**

```json
{
  "mcpServers": {
    "postgres": {
      "command": "/absolute/path/to/haltsql-mcp",
      "args": [
        "--local-policy", "/path/to/policy.yaml",
        "postgresql://agent_ro@localhost:5432/mydb"
      ],
      "env": {
        "HALTSQL_MCP_CONTEXT": "{\"tenant_id\": \"acme\"}",
        "HALTSQL_BIN": "/absolute/path/to/haltsql"
      }
    }
  }
}
```

Use absolute paths. Desktop apps often start servers with a shorter `PATH`
than your shell. Find the paths with `which haltsql-mcp` and `which haltsql`.

**Calling `haltsql-server`:**

```json
{
  "mcpServers": {
    "postgres": {
      "command": "/absolute/path/to/haltsql-mcp",
      "args": ["postgresql://agent_ro@db.internal:5432/app"],
      "env": {
        "HALTSQL_URL": "https://haltsql.internal:8443",
        "HALTSQL_TOKEN": "<sidecar token>",
        "HALTSQL_MCP_CONTEXT": "{\"tenant_id\": \"acme\"}",
        "HALTSQL_MCP_POLICY_FILE": "/path/to/policy.yaml"
      }
    }
  }
}
```

For a private CA or mutual TLS, add `HALTSQL_CA_FILE`, `HALTSQL_CLIENT_CERT`
and `HALTSQL_CLIENT_KEY`. To keep the token out of the client config, use a
config file with `server.token_file` (see [Use a config file](#use-a-config-file)).

## Claude Code

Add the server with `claude mcp add`. Everything after `--` is the command
that starts the server. `-e` sets an environment variable for it.

**Local install:**

```sh
claude mcp add postgres -e HALTSQL_MCP_CONTEXT='{"tenant_id":"acme"}' -- \
  haltsql-mcp --local-policy /path/to/policy.yaml postgresql://agent_ro@localhost:5432/mydb
```

**Docker:**

```sh
claude mcp add postgres -e HALTSQL_MCP_CONTEXT='{"tenant_id":"acme"}' -- \
  docker run -i --rm --read-only -v /path/to/haltsql:/config:ro -e HALTSQL_MCP_CONTEXT \
  ghcr.io/haltsql/haltsql-mcp postgresql://agent_ro@host.docker.internal:5432/mydb
```

**Shared HTTP server** (see [Other MCP clients](#streamable-http)):

```sh
claude mcp add --transport http postgres http://127.0.0.1:8765/mcp \
  --header "Authorization: Bearer $HALTSQL_MCP_TOKEN"
```

By default the server is added for you in the current project only. Pass
`--scope project` to write it to `.mcp.json` in the repository, so your team
gets it too, or `--scope user` for all your projects. Do not commit a
`.mcp.json` that contains a database password or a token. Run `claude mcp
list`, or `/mcp` inside Claude Code, to check that the server connected.

## Cursor

Cursor reads `~/.cursor/mcp.json` (all projects) and `.cursor/mcp.json` (one
project). The stdio entries have the same shape as in Claude Desktop:

```json
{
  "mcpServers": {
    "postgres": {
      "command": "haltsql-mcp",
      "args": [
        "--local-policy", "/path/to/policy.yaml",
        "postgresql://agent_ro@localhost:5432/mydb"
      ],
      "env": { "HALTSQL_MCP_CONTEXT": "{\"tenant_id\": \"acme\"}" }
    }
  }
}
```

For Docker, use the `docker` entry from [Claude Desktop](#claude-desktop)
unchanged. For a shared HTTP server, give a `url` and a header:

```json
{
  "mcpServers": {
    "postgres": {
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

## VS Code

VS Code reads MCP servers from `.vscode/mcp.json` in the workspace. It uses a
`servers` key instead of `mcpServers`:

```json
{
  "servers": {
    "postgres": {
      "type": "stdio",
      "command": "haltsql-mcp",
      "args": ["--local-policy", "/path/to/policy.yaml", "postgresql://agent_ro@localhost:5432/mydb"],
      "env": { "HALTSQL_MCP_CONTEXT": "{\"tenant_id\": \"acme\"}" }
    }
  }
}
```

For Docker, set `"command": "docker"` and use the same `args` and `env` as in
[Claude Desktop](#claude-desktop).

For a shared HTTP server, use `"type": "http"`. An input variable keeps the
token out of the file. VS Code prompts for it the first time:

```json
{
  "inputs": [
    { "type": "promptString", "id": "haltsql-mcp-token", "description": "haltsql-mcp token", "password": true }
  ],
  "servers": {
    "postgres": {
      "type": "http",
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer ${input:haltsql-mcp-token}" }
    }
  }
}
```

For user-level configuration and other options, see the VS Code
documentation.

## Other MCP clients

### stdio

Any client that can start a stdio server needs three things: the command
(`haltsql-mcp`, or `docker` with the `run -i` arguments above), its arguments,
and its environment. The connection string can be the last argument, as with
`@modelcontextprotocol/server-postgres`, or `--database-url`, or
`HALTSQL_MCP_DATABASE_URL`. Give it only once: a positional URL and a
different `--database-url` together are an error.

```sh
HALTSQL_MCP_CONTEXT='{"tenant_id":"acme"}' \
  haltsql-mcp --local-policy policy.yaml postgresql://agent_ro@localhost:5432/mydb
```

The server speaks MCP on stdin and stdout and logs warnings to stderr.

### Streamable HTTP

Run one server for many clients. Each client authenticates with its own
bearer token, and the token decides the tenant:

```sh
TOKEN=$(openssl rand -hex 32)                      # give this to one client
printf %s "$TOKEN" | shasum -a 256                 # put the hash in tokens.json
```

```json
{
  "tokens": [
    { "name": "agent-acme", "token_sha256": "<sha256 hex>", "context": { "tenant_id": "acme" } }
  ]
}
```

```sh
haltsql-mcp --transport http --host 127.0.0.1 --port 8765 \
  --tokens-file /etc/haltsql-mcp/tokens.json \
  --database-url postgresql://agent_ro@db.internal/app \
  --local-policy /etc/haltsql/policy.yaml
```

Clients connect to `http://HOST:8765/mcp` and send `Authorization: Bearer
<token>`. A missing or unknown token gets HTTP 401. TLS is not built in: keep
the listener on loopback or put a TLS proxy in front of it. For the Docker
version, see [Shared HTTP server](../mcp.md#shared-http-server).

## Use a config file

One YAML or JSON file can replace the arguments and most environment
variables. Pass it with `--config FILE` or `HALTSQL_MCP_CONFIG`. In Docker, a
`haltsql-mcp.yaml` in `/config` is loaded automatically. Relative paths are
resolved against the file's directory.

```yaml
# haltsql-mcp.yaml, calling a central haltsql-server
server:
  url: https://haltsql.internal:8443
  token_file: token            # a file holding the sidecar token
  ca_file: ca.pem              # optional
database_url: postgresql://agent_ro@db.internal:5432/app
policy_file: policy.yaml       # optional: for list_tables and describe_policy
context: { tenant_id: acme }
row_cap: 200
statement_timeout_ms: 5000
```

The client entry then only needs `haltsql-mcp --config /path/to/haltsql-mcp.yaml`,
or `docker run -i --rm --read-only -v /path/to/haltsql:/config:ro
ghcr.io/haltsql/haltsql-mcp`. Flags override environment variables, and
environment variables override the file. Unknown keys are an error, and an
inline `server.token` is rejected. See [Config file](../mcp.md#config-file)
for every key.

## Check that it works

1. **Check the policy and context without the client.** This uses the same
   policy and context the server will:

   ```sh
   haltsql verify --policy policy.yaml --context '{"tenant_id":"acme"}' \
     --sql 'SELECT id FROM orders WHERE tenant_id = $1 LIMIT 10'
   ```

   Exit code `0` means allowed. Add `--json` to see the verdict.

2. **Start the server by hand** with the same command, arguments and
   environment as the client config. A configuration error prints
   `haltsql-mcp: <message>` on stderr and exits with status `2`. A valid
   stdio configuration starts and waits for input; stop it with Ctrl-C.

3. **Call the tools from a test client.** The MCP Inspector starts the server
   and lets you call each tool:

   ```sh
   npx @modelcontextprotocol/inspector -e HALTSQL_MCP_CONTEXT='{"tenant_id":"acme"}' \
     haltsql-mcp --local-policy policy.yaml postgresql://agent_ro@localhost:5432/mydb
   ```

   Call `describe_policy`, then `query` with an allowed query, then `query`
   with `SELECT id FROM orders LIMIT 10`. The last one should return
   `"allowed": false` with `E_TENANT_MISSING` and no rows.

4. **Try it in the client.** Restart the client, ask a question about your
   data, then ask for every tenant's rows or for a column the policy does not
   allow. You should see a denial with reason codes, and no rows.

## Common errors

Configuration errors stop the server before it starts. Most clients then show
the server as failed or disconnected. Read the client's MCP log for the
`haltsql-mcp:` line. Claude Desktop writes its logs to `~/Library/Logs/Claude`
on macOS; for other clients, see the client's documentation.

| Message or symptom | Cause | Fix |
|---|---|---|
| The client cannot start the server, or "command not found" | `haltsql-mcp` or `docker` is not on the `PATH` the client uses. | Use the absolute path in `command`. |
| "verification is unavailable; the query was not executed" | Local mode: the `haltsql` CLI is missing or failed. Server mode: `haltsql-server` cannot be reached, timed out, or failed TLS. With neither configured, the default `http://127.0.0.1:8080` is not running. | Set `HALTSQL_BIN` to the CLI, pass `--local-policy`, or check `HALTSQL_URL` and the CA settings. |
| "verification refused (UNAUTHORIZED); the query was not executed" | `haltsql-server` rejected `HALTSQL_TOKEN`. Other codes: `FORBIDDEN`, `POLICY_NOT_FOUND`. | Check the token and `HALTSQL_POLICY`. |
| "no database is configured for this server" | No connection string. | Pass it as the last argument, `--database-url` or `HALTSQL_MCP_DATABASE_URL`. |
| "database connection failed: OperationalError" | Postgres is unreachable or rejected the login. | In Docker, use `host.docker.internal` (Docker Desktop) or `--network host` (Linux). Check the role and password. |
| "database error: ..." | HaltSQL allowed the query but Postgres rejected it, for example `57014` (statement timeout) or `42501` (permission denied). | Raise `HALTSQL_MCP_STATEMENT_TIMEOUT_MS`, or grant the role what the policy allows. If table names do not resolve, give the role the policy's `search_path`. |
| Every tenant query is denied with `E_CONTEXT_MISSING` | The context is empty or misses a key the policy needs. | Set `HALTSQL_MCP_CONTEXT`, and check that the JSON is quoted correctly for the client config. |
| "server misconfigured: context has no 'tenant_id' for app.tenant_id" | `HALTSQL_MCP_SET_CONFIG` names a context key that is not in the context. | Add the key to the context, or fix `HALTSQL_MCP_SET_CONFIG`. |
| "no policy file is configured, so the table list is unavailable" | `list_tables` needs the policy document. Server mode does not have it. | Set `HALTSQL_MCP_POLICY_FILE`. |
| "HTTP transport needs a tokens file ..." | `--transport http` without `--tokens-file`. | Add a tokens file. `--insecure-static-context` is for local development on a loopback address only. |
| "a tokens file only applies to the HTTP transport" | A tokens file was set with stdio. | Remove it, or use `--transport http`. |
| "config file ... is YAML; install PyYAML ..." | The `yaml` extra is not installed. | `pip install './clients/mcp[yaml]'`, or write the file as JSON. |
| "file not found: ..." | A policy, tokens, CA or certificate path does not exist. In Docker, the path is inside the container. | Use paths under the mounted `/config` folder. |
| "HALTSQL_MCP_CONTEXT is not valid JSON" | The JSON is malformed, often from shell or JSON-in-JSON quoting. | In JSON config, escape the inner quotes: `"{\"tenant_id\": \"acme\"}"`. |

## Related

- [mcp.md](../mcp.md): why to replace `server-postgres`, the Docker image, and
  every setting.
- [Agent frameworks](../agent-frameworks.md): HaltSQL tools for agent SDKs
  instead of MCP.
- [reason-codes.md](../reason-codes.md): every denial code.
- [tenancy.md](../tenancy.md): how tenant predicates are proven.
- [defense-in-depth.md](../defense-in-depth.md): the database role and
  row-level security to run alongside HaltSQL.
