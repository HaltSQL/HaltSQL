# CrewAI

`haltsql-crewai` gives a [CrewAI](https://github.com/crewAIInc/crewAI) agent
a `haltsql_query` tool that runs read-only SQL only after HaltSQL has verified
it. The tenant comes from a mapping or callable you give the tool when you
build the crew for a request. It never comes from crew inputs, task text or
tool arguments.

## What it provides

| Name | Kind | What it does |
|---|---|---|
| `HaltSQLQueryTool(runner=..., context=...)` | CrewAI `BaseTool` | A tool named `haltsql_query` whose only argument is `query`. Verifies, then runs the exact SQL in a `READ ONLY` transaction with a statement timeout and a row cap. Returns JSON text. |
| `HaltSQLToolRunner` | Class | Holds the verifier, the connection factory and the limits. Shared by all five agent-framework packages. See [The runner](../agent-frameworks.md#the-runner). |
| `context_from_app(app_state, key="haltsql_context")` | Function | Reads and validates a context stored under a key of an object or mapping. Useful inside your own `context` callable. |
| `ContextUnavailable` | Exception | Raised inside the package when no context is available. You see it as a refusal. |
| `TOOL_NAME`, `DEFAULT_CONTEXT_KEY` | Constants | `"haltsql_query"` and `"haltsql_context"`. |

The package is a thin layer over the [Python SDK](../sdk-python.md). Every
query goes through `haltsql.guard.authorize` and `guard.execute`.

## Install

The package needs Python 3.10 to 3.13 and `crewai` 1.15 or newer, below 2. Install it from PyPI; it pulls in the `haltsql`
Python SDK:

```sh
pip install haltsql-crewai
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
from crewai import Agent, Crew, Task
from haltsql import HaltSQLClient
from haltsql_crewai import HaltSQLQueryTool, HaltSQLToolRunner

DSN = os.environ["AGENT_DATABASE_URL"]          # a read-only role

runner = HaltSQLToolRunner(
    HaltSQLClient.from_env(),                   # or LocalVerifier("policy.yaml")
    connect=lambda: psycopg.connect(DSN),       # called only after HaltSQL allows the query
)

def answer(user, question: str) -> str:
    tool = HaltSQLQueryTool(runner=runner, context={"tenant_id": user.tenant_id})
    analyst = Agent(role="Analyst", goal="Answer questions about the user's orders",
                    backstory="Writes careful SQL.", tools=[tool])
    task = Task(description=question, expected_output="A short answer", agent=analyst)
    return str(Crew(agents=[analyst], tasks=[task]).kickoff())
```

`user` is your authenticated user. The runner is shared. The tool, and the
crew that uses it, are built per request with that request's context.

## Where the tenant comes from

`context` is either a mapping or a zero-argument callable. A callable is
evaluated on every call, for example one that reads the current session from
a `contextvars.ContextVar`:

```python
tool = HaltSQLQueryTool(runner=runner, context=lambda: {"tenant_id": session.tenant_id})
```

Do not take the tenant from crew inputs (`kickoff(inputs=...)`) or task text:
the model can read and influence both.

| `context` | Result |
|---|---|
| A mapping, or a callable that returns one | The query is verified with that context. |
| A callable that returns `None` | Refused before verification: "No trusted HaltSQL context is configured for this run". |
| `{}`, or a callable that returns `{}` | Verified with an empty context. Tenant tables are then denied by the policy. |
| Not a mapping or callable | `TypeError` when you create the tool. |

The argument schema forbids extra fields. If the model sends `tenant_id` as
well as `query`, the call fails validation and nothing runs.

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
statement timeout.

See [reason-codes.md](../reason-codes.md) for every code.

## Configuration

`HaltSQLToolRunner(verifier, connect, *, max_rows=200, statement_timeout_ms=5000, settings=None)`:

| Argument | Default | Meaning |
|---|---|---|
| `verifier` | required | `HaltSQLClient`, `LocalVerifier`, `NativeVerifier`, or any object with `verify(sql, context)`. |
| `connect` | required | Zero-argument callable that returns a new psycopg 3 connection. Called only after HaltSQL allows the query. The runner closes the connection after each query. |
| `max_rows` | `200` | Row cap, 1 to 100000. `truncated` tells the model more rows were available. |
| `statement_timeout_ms` | `5000` | `statement_timeout` for the query, 1 to 3600000. |
| `settings` | `None` | Transaction-local settings: a mapping, or a function of the verified context, for example `lambda ctx: {"app.tenant_id": ctx["tenant_id"]}` for row-level security. |

`HaltSQLQueryTool` fields (keyword arguments):

| Field | Default | Meaning |
|---|---|---|
| `runner` | required | A `HaltSQLToolRunner`. |
| `context` | required | A mapping, or a zero-argument callable that returns a mapping or `None`. |
| `name` | `"haltsql_query"` | Tool name the model sees. |
| `description` | built-in text | Tool description the model sees. |

`runner` and `context` are excluded from the tool's serialized form, and
`context` is left out of its `repr`. Other `BaseTool` fields work as usual.

Every query runs in a `READ ONLY` transaction, and only statements whose
verdict `statement_kind` is `select` are run. These cannot be turned off.

## Async support

The tool implements both `_run` and `_arun`. The async path runs verification
and execution in a worker thread (`asyncio.to_thread`), so the event loop is
not blocked. Use a sync verifier and a sync psycopg connection either way.
Rows are returned whole; streaming rows is not supported.

## Testing

You can test your wiring without a model, a sidecar or a database. Use
`FakeVerifier` from `haltsql.testing` and call the tool directly:

```python
import json

from haltsql.testing import FakeVerifier, make_verdict_dict
from haltsql_crewai import HaltSQLQueryTool, HaltSQLToolRunner

def deny(sql, ctx, _policy):
    return make_verdict_dict(sql, allowed=False, codes=["E_TENANT_MISSING"])

def no_db():
    raise AssertionError("connected after a denial")

def test_denial_never_connects():
    tool = HaltSQLQueryTool(runner=HaltSQLToolRunner(FakeVerifier(deny), no_db),
                            context={"tenant_id": "acme"})
    out = json.loads(tool.run(query="SELECT id FROM orders LIMIT 10"))
    assert out["status"] == "denied" and out["reasons"][0]["code"] == "E_TENANT_MISSING"
```

The package's own tests use `BaseTool.run`, the structured-tool path and a
real `Agent`, with the real `haltsql` CLI, a real `haltsql-server` and the lab
Postgres. They never call an LLM:

```sh
make -C lab up
dune build ./bin/haltsql/main.exe ./bin/server/main.exe
ONLY=agents clients/python/run-all-tests.sh
```

`integrations/crewai/constraints.txt` lists the exact versions the tests were
run with. See [Testing](../agent-frameworks.md#testing).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "No trusted HaltSQL context is configured for this run" | The `context` callable returned `None`, or raised a `LookupError`. | Build the tool per request with that request's context. |
| Every query on a tenant table is denied | The context is empty or misses a key the policy needs (`E_CONTEXT_MISSING`), or the model wrote a tenant literal (`E_TENANT_MISMATCH`). | Check the context. In bound mode the model must write `$1`. |
| A validation error about extra inputs, or "pass exactly one argument, 'query'" | The model sent an argument other than `query`. | Nothing to fix in your code; the call was rejected and nothing ran. |
| "SQL verification is unavailable" | The sidecar or CLI failed, timed out, or returned a verdict for a different string. An unexpected exception in the `context` callable is also reported this way. | Check `HALTSQL_URL` and `HALTSQL_TOKEN`, or the `haltsql` binary. Test the callable on its own. |
| "The database is unavailable" | `connect` raised. | Check the DSN and network. |
| `TypeError: context must be a mapping or a zero-argument callable` | `context` was a string or another type. | Pass a mapping or a callable. |
| `ImportError: no pq wrapper available` | psycopg cannot find `libpq`. | `pip install 'psycopg[binary]'`, or install `libpq`. |

## Limits

- Read-only `SELECT` only. Write policies are not supported by this tool.
- One statement per call. Rows are returned whole, up to `max_rows`; there is
  no streaming or pagination.
- `connect` must return a psycopg 3 connection.
- Python 3.14 is not supported (the package requires Python below 3.14).
- HaltSQL verifies the PostgreSQL dialect only.

## Related

- [Agent frameworks](../agent-frameworks.md): what all five packages share.
- [Python SDK](../sdk-python.md): verifiers, `guard.execute` and errors.
- [reason-codes.md](../reason-codes.md) and [tenancy.md](../tenancy.md).
- [defense-in-depth.md](../defense-in-depth.md).
- Source: [`integrations/crewai`](../../integrations/crewai).
