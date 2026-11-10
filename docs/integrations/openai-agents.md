# OpenAI Agents SDK

`haltsql-openai-agents` gives an [OpenAI Agents SDK](https://github.com/openai/openai-agents-python)
agent a `haltsql_query` tool that runs read-only SQL only after HaltSQL has
verified it. It also has a tool input guardrail that verifies the SQL argument
of a tool you already have. The tenant comes from the run context your
application passes to `Runner.run`, never from the model.

## What it provides

| Name | Kind | What it does |
|---|---|---|
| `haltsql_query_tool(runner, ...)` | Function returning a `FunctionTool` | A tool named `haltsql_query` whose only argument is `query`. Verifies, then runs the exact SQL in a `READ ONLY` transaction with a statement timeout and a row cap. |
| `haltsql_tool_input_guardrail(verifier, ...)` | Function returning a `ToolInputGuardrail` | Verifies the SQL argument of another tool before that tool runs, and rejects the call if HaltSQL does not allow it. |
| `HaltSQLToolRunner` | Class | Holds the verifier, the connection factory and the limits. Shared by all five agent-framework packages. See [The runner](../agent-frameworks.md#the-runner). |
| `context_from_app(app_state, key="haltsql_context")` | Function | Reads and validates the context from an object or mapping. Used by default to read the run context. |
| `ContextUnavailable` | Exception | Raised inside the package when no context can be read. You see it as a refusal, not as an exception. |
| `TOOL_NAME`, `DEFAULT_CONTEXT_KEY` | Constants | `"haltsql_query"` and `"haltsql_context"`. |

The package is a thin layer over the [Python SDK](../sdk-python.md). Every
query goes through `haltsql.guard.authorize` and `guard.execute`.

## Install

The package needs Python 3.10 or newer and `openai-agents` 0.22 or newer,
below 1.0. Install it from PyPI; it pulls in the `haltsql`
Python SDK:

```sh
pip install haltsql-openai-agents
```

The SDK depends on psycopg 3, which needs `libpq` on the machine. If you do
not have it, also run `pip install 'psycopg[binary]'`.

To verify queries you need one of these:

- a running `haltsql-server` (use `HaltSQLClient`, see [http-api.md](../http-api.md)),
- the `haltsql` CLI and a policy file (use `LocalVerifier`), or
- a platform wheel of the SDK with the bundled engine (use `NativeVerifier`,
  see [In-process verification](../sdk-python.md#in-process-verification-bundled-engine)).

## Minimal example

```python
import asyncio
import os
from dataclasses import dataclass, field

import psycopg
from agents import Agent, Runner
from haltsql import HaltSQLClient
from haltsql_openai_agents import HaltSQLToolRunner, haltsql_query_tool

DSN = os.environ["AGENT_DATABASE_URL"]          # a read-only role

@dataclass
class AppContext:                               # passed to Runner.run; never sent to the model
    user_id: str
    haltsql_context: dict = field(default_factory=dict)

runner = HaltSQLToolRunner(
    HaltSQLClient.from_env(),                   # or LocalVerifier("policy.yaml")
    connect=lambda: psycopg.connect(DSN),       # called only after HaltSQL allows the query
)

agent = Agent(
    name="analyst",
    instructions="Answer questions about the user's orders with the haltsql_query tool.",
    tools=[haltsql_query_tool(runner)],
)

async def answer(user, question: str) -> str:
    ctx = AppContext(user_id=user.id, haltsql_context={"tenant_id": user.tenant_id})
    result = await Runner.run(agent, question, context=ctx)
    return result.final_output
```

`user` is your authenticated user. Create the runner and the agent once at
startup. Build the run context per request.

## Where the tenant comes from

The tool reads the HaltSQL context from the run context, the object you pass
as `Runner.run(..., context=...)`. The SDK never sends that object to the
model. By default the tool reads its `haltsql_context` attribute, or its
`haltsql_context` key if it is a mapping. The value may also be a
zero-argument callable that returns the mapping.

To read the context from your own object, pass `context_from`:

```python
tool = haltsql_query_tool(
    runner,
    context_from=lambda app: {"tenant_id": app.session.tenant_id},
)
```

What happens in each case:

| Run context | Result |
|---|---|
| Has `haltsql_context` (or `context_from` returns a mapping) | The query is verified with that context. |
| No run context, no `haltsql_context`, or `context_from` returns `None` | Refused before verification: "No trusted HaltSQL context is configured for this run". |
| `haltsql_context` is `{}` | Verified with an empty context. Tenant tables are then denied by the policy. |
| The value is not a valid context (for example a float value) | Refused: "The query was not executed: ..." with the validation error. |

The tool's JSON schema has only `query`, with `additionalProperties: false`
and strict mode on. If a tool call carries any other argument, such as
`tenant_id`, the call is refused and nothing is verified or run.

## What the model sees

The tool returns JSON text. On success:

```json
{"status":"ok","executed":true,"columns":["id","status"],"rows":[[1,"open"],[3,"paid"]],"row_count":2,"truncated":false}
```

When HaltSQL denies the query, nothing runs, and the model gets each reason
with its code and hint:

```json
{"status":"denied","executed":false,
 "reasons":[{"code":"E_TENANT_MISMATCH","message":"...","hint":"Use a $n placeholder (e.g. orders.tenant_id = $1) instead of a tenant literal; HaltSQL returns the value to bind."}],
 "message":"HaltSQL denied the query; it was not executed. Fix the SQL and retry:\n- E_TENANT_MISMATCH: Use a $n placeholder ..."}
```

Other failures have `"status": "error"`. With `"executed": false`, nothing
ran: HaltSQL was unavailable, no context was configured, the statement was not
a `SELECT`, or the database could not be reached. With `"executed": true`,
HaltSQL allowed the query but the database rejected it, for example on a
statement timeout. The message gives the database error's class and its
first line. Verification failures are reported without internal details.

The default tool description tells the model to filter tenant tables with
`alias.tenant_id = $1`, never to write tenant IDs, and to fix the SQL and
retry after a denial. See [reason-codes.md](../reason-codes.md) for every
code.

## Guarding a tool you already have

`haltsql_tool_input_guardrail` checks the SQL argument of an existing tool
before the SDK runs it:

```python
from agents import function_tool
from haltsql import LocalVerifier
from haltsql_openai_agents import haltsql_tool_input_guardrail

guard = haltsql_tool_input_guardrail(LocalVerifier("policy.yaml"), sql_arg="sql")

@function_tool(tool_input_guardrails=[guard])
def run_sql(sql: str) -> str:
    """Run SQL against the warehouse."""
    ...
```

If HaltSQL does not allow the SQL, the guardrail calls `reject_content`. The
tool does not run and the model gets the refusal JSON. The guardrail also
rejects the call when the argument is missing, no context is configured,
HaltSQL is unavailable, or the statement is not a `SELECT`.

> **Warning:** the guarded tool cannot receive HaltSQL's `$n` values, so the
> guardrail refuses any SQL that HaltSQL allows only with bound parameters.
> Use it with a policy in literal tenancy mode (see
> [tenancy.md](../tenancy.md#bound-mode-and-literal-mode)), or use
> `haltsql_query_tool` instead. The guardrail checks only the SQL. The guarded
> tool must still use a read-only role, a timeout and a row limit.

## Configuration

`HaltSQLToolRunner(verifier, connect, *, max_rows=200, statement_timeout_ms=5000, settings=None)`:

| Argument | Default | Meaning |
|---|---|---|
| `verifier` | required | `HaltSQLClient`, `LocalVerifier`, `NativeVerifier`, or any object with `verify(sql, context)`. |
| `connect` | required | Zero-argument callable that returns a new psycopg 3 connection. Called only after HaltSQL allows the query. The runner closes the connection after each query. |
| `max_rows` | `200` | Row cap, 1 to 100000. `truncated` tells the model more rows were available. |
| `statement_timeout_ms` | `5000` | `statement_timeout` for the query, 1 to 3600000. |
| `settings` | `None` | Transaction-local settings: a mapping, or a function of the verified context, for example `lambda ctx: {"app.tenant_id": ctx["tenant_id"]}` for row-level security. |

`haltsql_query_tool(runner, *, context_from=None, name="haltsql_query", description=DEFAULT_DESCRIPTION)`:

| Argument | Default | Meaning |
|---|---|---|
| `runner` | required | A `HaltSQLToolRunner`. |
| `context_from` | `None` | `f(run_context) -> mapping`. Default: the run context's `haltsql_context` attribute or key. |
| `name` | `"haltsql_query"` | Tool name the model sees. |
| `description` | built-in text | Tool description the model sees. |

`haltsql_tool_input_guardrail(verifier, *, sql_arg="query", context_from=None, name="haltsql_sql_guardrail")`:

| Argument | Default | Meaning |
|---|---|---|
| `verifier` | required | Any object with `verify(sql, context)`. |
| `sql_arg` | `"query"` | Name of the guarded tool's SQL argument. |
| `context_from` | `None` | As for `haltsql_query_tool`. |
| `name` | `"haltsql_sql_guardrail"` | Guardrail name. |

Every query runs in a `READ ONLY` transaction, and only statements whose
verdict `statement_kind` is `select` are run. These cannot be turned off.

## Async support

The tool is async. Verification and execution run in a worker thread
(`asyncio.to_thread`), so they do not block the event loop. The guardrail also
runs its check in a worker thread. Use a sync verifier (`HaltSQLClient`,
`LocalVerifier`, `NativeVerifier`) and a sync psycopg connection: the runner
calls them from that thread. Results are returned whole; streaming rows is not
supported.

## Testing

You can test your wiring without a model, a sidecar or a database. Use
`FakeVerifier` from `haltsql.testing` and check that a denial never opens a
connection:

```python
from haltsql.testing import FakeVerifier, make_verdict_dict
from haltsql_openai_agents import HaltSQLToolRunner

def deny(sql, ctx, _policy):
    return make_verdict_dict(sql, allowed=False, codes=["E_TENANT_MISSING"])

def no_db():
    raise AssertionError("connected after a denial")

def test_denial_never_connects():
    fv = FakeVerifier(deny)
    out = HaltSQLToolRunner(fv, no_db).run("SELECT id FROM orders LIMIT 10", {"tenant_id": "acme"})
    assert out["status"] == "denied" and out["reasons"][0]["code"] == "E_TENANT_MISSING"
    assert fv.calls == [("SELECT id FROM orders LIMIT 10", {"tenant_id": "acme"})]
```

The package's own tests run tool calls through the SDK's function-tool
executor with the real `haltsql` CLI, a real `haltsql-server` and the lab
Postgres. They never call an LLM:

```sh
make -C lab up
dune build ./bin/haltsql/main.exe ./bin/server/main.exe
ONLY=agents clients/python/run-all-tests.sh
```

`integrations/openai_agents/constraints.txt` lists the exact versions the
tests were run with. See [Testing](../agent-frameworks.md#testing).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "No trusted HaltSQL context is configured for this run" | `Runner.run` got no `context=`, the context has no `haltsql_context`, or `context_from` returned `None` or raised a `LookupError`. | Pass the run context, or fix `context_from`. |
| Every query on a tenant table is denied | The context is empty or misses a key the policy needs (`E_CONTEXT_MISSING`), or the model wrote a tenant literal (`E_TENANT_MISMATCH`). | Check the context. In bound mode the model must write `$1`. |
| "pass exactly one argument, 'query'" | The tool call had extra or missing arguments. | Nothing to fix in your code: the model sees the message and retries. |
| "SQL verification is unavailable" | The sidecar or CLI failed, timed out, or returned a verdict for a different string. An unexpected exception in `context_from` (other than `LookupError` or `ValueError`) is also reported this way. | Check `HALTSQL_URL` and `HALTSQL_TOKEN`, or the `haltsql` binary. Test `context_from` on its own. |
| "The database is unavailable" | `connect` raised. | Check the DSN and network. |
| `ValueError` when building the runner | `verifier` has no `verify`, `connect` is not callable, or a limit is out of range. | Fix the argument named in the message. |
| The guardrail rejects allowed SQL with "HaltSQL allows it only with bound parameters" | The policy uses bound tenancy. | Use `haltsql_query_tool`, or literal tenancy for that tool. |
| `ImportError: no pq wrapper available` | psycopg cannot find `libpq`. | `pip install 'psycopg[binary]'`, or install `libpq`. |

## Limits

- Read-only `SELECT` only. Write policies are not supported by this tool.
- One statement per call. Rows are returned whole, up to `max_rows`; there is
  no streaming or pagination.
- `connect` must return a psycopg 3 connection. psycopg2 and asyncpg are not
  supported here.
- The guardrail checks SQL only, and cannot be used with bound tenancy.
- HaltSQL verifies the PostgreSQL dialect only.

## Related

- [Agent frameworks](../agent-frameworks.md): what all five packages share.
- [Python SDK](../sdk-python.md): verifiers, `guard.execute` and errors.
- [reason-codes.md](../reason-codes.md) and [tenancy.md](../tenancy.md).
- [defense-in-depth.md](../defense-in-depth.md): the database role and
  row-level security to use with HaltSQL.
- Source: [`integrations/openai_agents`](../../integrations/openai_agents).
