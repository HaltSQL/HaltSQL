# Google Agent Development Kit

`haltsql-google-adk` gives a [Google ADK](https://github.com/google/adk-python)
agent a `haltsql_query` tool that runs read-only SQL only after HaltSQL has
verified it. It also has a callback and a plugin that verify the SQL argument
of other PostgreSQL tools, such as MCP Toolbox's `postgres-execute-sql`. The
tenant comes from ADK session state, which your application sets when it
creates the session.

## What it provides

| Name | Kind | What it does |
|---|---|---|
| `HaltSQLQueryTool(runner, ...)` | ADK `BaseTool` | A tool named `haltsql_query` whose only argument is `query`. Verifies, then runs the exact SQL in a `READ ONLY` transaction with a statement timeout and a row cap. Returns a dict. |
| `haltsql_before_tool_callback(verifier, ...)` | Function returning a callback | For `LlmAgent(before_tool_callback=...)`. Verifies the SQL argument of the listed tools of one agent before they run. |
| `HaltSQLGuardPlugin(verifier, ...)` | ADK `BasePlugin` | The same check for every agent a `Runner` executes. |
| `build_sql_agent(runner, ...)` | Function returning an `LlmAgent` | An example agent with `HaltSQLQueryTool` and instructions for writing tenant-scoped SQL. |
| `DEFAULT_GUARDED_TOOLS` | Constant | `{"execute_sql": "sql"}`: the tools the callback and plugin check by default. |
| `HaltSQLToolRunner` | Class | Holds the verifier, the connection factory and the limits. Shared by all five agent-framework packages. See [The runner](../agent-frameworks.md#the-runner). |
| `context_from_app(app_state, key="haltsql_context")` | Function | Reads and validates the context from session state or another mapping. |
| `ContextUnavailable` | Exception | Raised inside the package when no context can be read. You see it as a refusal. |
| `TOOL_NAME`, `DEFAULT_CONTEXT_KEY` | Constants | `"haltsql_query"` and `"haltsql_context"`. |

The package is a thin layer over the [Python SDK](../sdk-python.md). Every
query goes through `haltsql.guard.authorize`.

## Install

The package needs Python 3.11 or newer and `google-adk` 2.9 or newer, below 3.
It is not on PyPI yet, so install it and the Python SDK from a checkout of the
repository:

```sh
git clone https://github.com/HaltSQL/HaltSQL && cd HaltSQL
pip install -e clients/python -e integrations/google_adk
```

The SDK depends on psycopg 3, which needs `libpq` on the machine. If you do
not have it, also run `pip install 'psycopg[binary]'`.

To verify queries you need a running `haltsql-server` (`HaltSQLClient`), the
`haltsql` CLI and a policy file (`LocalVerifier`), or a platform wheel of the
SDK with the bundled engine (`NativeVerifier`). See the
[Python SDK](../sdk-python.md).

## Minimal example

```python
import os

import psycopg
from google.adk.runners import InMemoryRunner
from google.genai import types
from haltsql import HaltSQLClient
from haltsql_google_adk import HaltSQLToolRunner, build_sql_agent

DSN = os.environ["AGENT_DATABASE_URL"]          # a read-only role

runner = HaltSQLToolRunner(
    HaltSQLClient.from_env(),                   # or LocalVerifier("policy.yaml")
    connect=lambda: psycopg.connect(DSN),       # called only after HaltSQL allows the query
)
agent = build_sql_agent(runner, model="gemini-2.5-flash")
adk = InMemoryRunner(agent=agent, app_name="analytics")

async def answer(user, question: str) -> str:
    session = await adk.session_service.create_session(
        app_name="analytics", user_id=user.id,
        state={"haltsql_context": {"tenant_id": user.tenant_id}},   # from your auth
    )
    reply = ""
    async for event in adk.run_async(
        user_id=user.id, session_id=session.id,
        new_message=types.Content(role="user", parts=[types.Part(text=question)]),
    ):
        if event.is_final_response() and event.content and event.content.parts:
            reply = event.content.parts[0].text or ""
    return reply
```

`user` is your authenticated user. To add the tool to an agent of your own,
use `LlmAgent(..., tools=[HaltSQLQueryTool(runner)])`.

## Where the tenant comes from

`HaltSQLQueryTool` reads the HaltSQL context from session state, from the
`haltsql_context` key by default (`state_key=` changes it). Set the key when
you create the session, from your authenticated user. The value may also be a
zero-argument callable that returns the mapping.

> **Warning:** session state is writable by tools and by an agent's
> `output_key`. Do not let any tool, callback or `output_key` write the
> `haltsql_context` key, or the model could influence the tenant.

| Session state | Result |
|---|---|
| `haltsql_context` holds a mapping | The query is verified with that context. |
| No `haltsql_context` key | Refused before verification: "No trusted HaltSQL context is configured for this run". |
| `haltsql_context` is `{}` | Verified with an empty context. Tenant tables are then denied by the policy. |
| `haltsql_context` is not a mapping | Refused: "The query was not executed: 'haltsql_context' must be a mapping". |

The tool declares only `query`. If a function call carries any other argument,
such as `tenant_id`, the tool refuses it and nothing is verified or run.

## What the model sees

The tool returns a dict, which ADK sends to the model as the function
response. On success:

```json
{"status": "ok", "executed": true, "columns": ["id", "status"],
 "rows": [[1, "open"], [3, "paid"]], "row_count": 2, "truncated": false}
```

When HaltSQL denies the query, nothing runs, and the model gets each reason
with its code and hint:

```json
{"status": "denied", "executed": false,
 "reasons": [{"code": "E_TENANT_MISMATCH", "message": "...",
              "hint": "Use a $n placeholder (e.g. orders.tenant_id = $1) instead of a tenant literal; HaltSQL returns the value to bind."}],
 "message": "HaltSQL denied the query; it was not executed. Fix the SQL and retry:\n- E_TENANT_MISMATCH: Use a $n placeholder ..."}
```

Other failures have `"status": "error"`. With `"executed": false`, nothing
ran: HaltSQL was unavailable, no context was configured, the statement was not
a `SELECT`, or the database could not be reached. With `"executed": true`,
HaltSQL allowed the query but the database rejected it, for example on a
statement timeout.

The instructions of `build_sql_agent` tell the model to retry after `denied`
at most three times, and to report that the data is unavailable after
`error`. See [reason-codes.md](../reason-codes.md) for every code.

## Guarding other PostgreSQL tools

ADK can load PostgreSQL tools from other sources, for example the
`postgres-execute-sql` tool of MCP Toolbox for Databases through
`ToolboxToolset`, or your own `execute_sql` function. To verify their SQL
before they run, use one of these:

```python
from google.adk.agents import LlmAgent
from google.adk.runners import Runner
from haltsql import LocalVerifier
from haltsql_google_adk import HaltSQLGuardPlugin, haltsql_before_tool_callback

verifier = LocalVerifier("policy.yaml")   # a policy in literal tenancy mode
# execute_sql is your existing tool; sessions is your session service.

# One agent:
agent = LlmAgent(name="db_agent", model="gemini-2.5-flash", tools=[execute_sql],
                 before_tool_callback=haltsql_before_tool_callback(verifier))

# Every agent a runner executes:
runner = Runner(agent=agent, app_name="analytics", session_service=sessions,
                plugins=[HaltSQLGuardPlugin(verifier)])
```

`tools=` maps tool names to the name of their SQL argument. The default is
`{"execute_sql": "sql"}`. Tools that are not listed are not checked. For a
listed tool, the guard verifies the SQL with the context from session state.
If HaltSQL allows it without bound parameters, the tool runs. Otherwise the
guard returns the refusal dict, and ADK sends it to the model instead of
running the tool.

> **Warning:** the guarded tool cannot receive HaltSQL's `$n` values, so the
> guard refuses any SQL that HaltSQL allows only with bound parameters. Use
> literal tenancy for those tools (see
> [tenancy.md](../tenancy.md#bound-mode-and-literal-mode)), or use
> `HaltSQLQueryTool`. The guard checks only the SQL: run those tools with a
> read-only role and their own timeouts.

Plugins run before an agent's own callbacks. If you use the callback form and
the agent has several before-tool callbacks, list HaltSQL's first and do not
let a later one change the arguments. Do not use the guard with BigQuery or
Spanner tools: HaltSQL verifies the PostgreSQL dialect only.

## Configuration

`HaltSQLToolRunner(verifier, connect, *, max_rows=200, statement_timeout_ms=5000, settings=None)`:

| Argument | Default | Meaning |
|---|---|---|
| `verifier` | required | `HaltSQLClient`, `LocalVerifier`, `NativeVerifier`, or any object with `verify(sql, context)`. |
| `connect` | required | Zero-argument callable that returns a new psycopg 3 connection. Called only after HaltSQL allows the query. The runner closes the connection after each query. |
| `max_rows` | `200` | Row cap, 1 to 100000. `truncated` tells the model more rows were available. |
| `statement_timeout_ms` | `5000` | `statement_timeout` for the query, 1 to 3600000. |
| `settings` | `None` | Transaction-local settings: a mapping, or a function of the verified context, for example `lambda ctx: {"app.tenant_id": ctx["tenant_id"]}` for row-level security. |

`HaltSQLQueryTool(runner, *, state_key="haltsql_context", name="haltsql_query", description=DEFAULT_DESCRIPTION)`:

| Argument | Default | Meaning |
|---|---|---|
| `runner` | required | A `HaltSQLToolRunner`. Anything else raises `TypeError`. |
| `state_key` | `"haltsql_context"` | Session-state key that holds the context. |
| `name` | `"haltsql_query"` | Tool name the model sees. |
| `description` | built-in text | Tool description the model sees. |

`haltsql_before_tool_callback(verifier, *, tools=None, state_key="haltsql_context")` and
`HaltSQLGuardPlugin(verifier, *, tools=None, state_key="haltsql_context", name="haltsql_guard")`:

| Argument | Default | Meaning |
|---|---|---|
| `verifier` | required | Any object with `verify(sql, context)`. |
| `tools` | `None` (`{"execute_sql": "sql"}`) | Tool name to SQL argument name. Must not be empty. |
| `state_key` | `"haltsql_context"` | Session-state key that holds the context. |
| `name` | `"haltsql_guard"` | Plugin name (plugin only). |

`build_sql_agent(runner, *, model="gemini-2.5-flash", name="sql_analyst", instruction=SQL_AGENT_INSTRUCTION, state_key="haltsql_context", **agent_kwargs)`:

| Argument | Default | Meaning |
|---|---|---|
| `runner` | required | A `HaltSQLToolRunner`. |
| `model` | `"gemini-2.5-flash"` | Passed to `LlmAgent`. |
| `name` | `"sql_analyst"` | Agent name. |
| `instruction` | built-in text | Agent instruction. |
| `state_key` | `"haltsql_context"` | Passed to `HaltSQLQueryTool`. |
| `**agent_kwargs` | none | Other `LlmAgent` arguments. |

Every query that `HaltSQLQueryTool` runs is in a `READ ONLY` transaction, and
only statements whose verdict `statement_kind` is `select` are run. These
cannot be turned off.

## Async support

ADK calls tools and callbacks asynchronously. `HaltSQLQueryTool` reads session
state on the event loop, then runs verification and execution in a worker
thread (`asyncio.to_thread`). The callback and plugin also verify in a worker
thread. Use a sync verifier and a sync psycopg connection. Rows are returned
whole; streaming rows is not supported.

## Testing

You can test your wiring without a model, a sidecar or a database. Use
`FakeVerifier` from `haltsql.testing` and check that a denial never opens a
connection:

```python
from haltsql.testing import FakeVerifier, make_verdict_dict
from haltsql_google_adk import HaltSQLToolRunner

def deny(sql, ctx, _policy):
    return make_verdict_dict(sql, allowed=False, codes=["E_TENANT_MISSING"])

def no_db():
    raise AssertionError("connected after a denial")

def test_denial_never_connects():
    out = HaltSQLToolRunner(FakeVerifier(deny), no_db).run("SELECT id FROM orders LIMIT 10",
                                                            {"tenant_id": "acme"})
    assert out["status"] == "denied" and out["reasons"][0]["code"] == "E_TENANT_MISSING"
```

The package's own tests use an `InMemoryRunner` session and ADK's
function-call handler, with the real `haltsql` CLI, a real `haltsql-server`
and the lab Postgres. They never call an LLM:

```sh
make -C lab up
dune build ./bin/haltsql/main.exe ./bin/server/main.exe
ONLY=agents clients/python/run-all-tests.sh
```

`integrations/google_adk/constraints.txt` lists the exact versions the tests
were run with. See [Testing](../agent-frameworks.md#testing).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "No trusted HaltSQL context is configured for this run" | The session state has no `haltsql_context` (or your `state_key`). | Pass `state={"haltsql_context": {...}}` to `create_session`. |
| Every query on a tenant table is denied | The context is empty or misses a key the policy needs (`E_CONTEXT_MISSING`), or the model wrote a tenant literal (`E_TENANT_MISMATCH`). | Check the context. In bound mode the model must write `$1`. |
| "pass exactly one argument, 'query'" | The function call had extra or missing arguments. | Nothing to fix in your code: the model sees the message. |
| The guard refuses allowed SQL with "HaltSQL allows it only with bound parameters" | The policy uses bound tenancy. | Use `HaltSQLQueryTool`, or literal tenancy for that tool. |
| The guard does not check a tool | The tool's name is not in `tools=`. | Add `{"<tool name>": "<sql argument>"}`. |
| "SQL verification is unavailable" | The sidecar or CLI failed, timed out, or returned a verdict for a different string. | Check `HALTSQL_URL` and `HALTSQL_TOKEN`, or the `haltsql` binary. |
| "The database is unavailable" | `connect` raised. | Check the DSN and network. |
| `ValueError: tools must map tool names to SQL argument names` | `tools=` is empty or has non-string entries. | Pass a non-empty mapping of strings. |
| `ImportError: no pq wrapper available` | psycopg cannot find `libpq`. | `pip install 'psycopg[binary]'`, or install `libpq`. |

## Limits

- `HaltSQLQueryTool` runs read-only `SELECT` only. Write policies are not
  supported.
- One statement per call. Rows are returned whole, up to `max_rows`; there is
  no streaming or pagination.
- `connect` must return a psycopg 3 connection.
- The callback and plugin check SQL only, cannot be used with bound tenancy,
  and do not check tools that are not listed in `tools=`.
- HaltSQL verifies the PostgreSQL dialect only, so it cannot guard ADK's
  BigQuery, Spanner (GoogleSQL) or Bigtable tools.

## Related

- [Agent frameworks](../agent-frameworks.md): what all five packages share.
- [Python SDK](../sdk-python.md): verifiers, `guard.execute` and errors.
- [MCP clients](mcp-clients.md): `haltsql-mcp` for MCP-based agents.
- [reason-codes.md](../reason-codes.md) and [tenancy.md](../tenancy.md).
- [defense-in-depth.md](../defense-in-depth.md).
- Source: [`integrations/google_adk`](../../integrations/google_adk).
