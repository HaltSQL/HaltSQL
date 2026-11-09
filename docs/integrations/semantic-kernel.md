# Semantic Kernel

`haltsql-semantic-kernel` gives a [Semantic Kernel](https://github.com/microsoft/semantic-kernel)
(Python) agent a plugin with one function, `query`, that runs read-only SQL
only after HaltSQL has verified it. With the suggested plugin name, the model
sees the function as `haltsql-query`. The tenant comes from a mapping or
callable your application gives the plugin, never from `KernelArguments`.

## What it provides

| Name | Kind | What it does |
|---|---|---|
| `HaltSQLPlugin(runner, context)` | Class | A native plugin with one `kernel_function`, `query`, whose only argument is `query`. Verifies, then runs the exact SQL in a `READ ONLY` transaction with a statement timeout and a row cap. Returns JSON text. |
| `PLUGIN_NAME` | Constant | `"haltsql"`, the suggested plugin name. With the function name `query`, the model sees `haltsql-query`. |
| `HaltSQLToolRunner` | Class | Holds the verifier, the connection factory and the limits. Shared by all five agent-framework packages. See [The runner](../agent-frameworks.md#the-runner). |
| `context_from_app(app_state, key="haltsql_context")` | Function | Reads and validates a context stored under a key of an object or mapping. Useful inside your own `context` callable. |
| `ContextUnavailable` | Exception | Raised inside the package when no context is available. You see it as a refusal. |
| `TOOL_NAME`, `DEFAULT_CONTEXT_KEY` | Constants | `"haltsql_query"` and `"haltsql_context"`. |

The package is a thin layer over the [Python SDK](../sdk-python.md). Every
query goes through `haltsql.guard.authorize` and `guard.execute`.

## Install

The package needs Python 3.11 or newer and `semantic-kernel` 1.44 or newer,
below 2. It is not on PyPI yet, so install it and the Python SDK from a
checkout of the repository:

```sh
git clone https://github.com/HaltSQL/HaltSQL && cd HaltSQL
pip install -e clients/python -e integrations/semantic_kernel
```

The SDK depends on psycopg 3, which needs `libpq` on the machine. If you do
not have it, also run `pip install 'psycopg[binary]'`.

To verify queries you need a running `haltsql-server` (`HaltSQLClient`), the
`haltsql` CLI and a policy file (`LocalVerifier`), or a platform wheel of the
SDK with the bundled engine (`NativeVerifier`). See the
[Python SDK](../sdk-python.md).

## Minimal example

```python
import contextvars
import os

import psycopg
from semantic_kernel import Kernel
from semantic_kernel.connectors.ai.function_choice_behavior import FunctionChoiceBehavior
from semantic_kernel.connectors.ai.open_ai import OpenAIChatCompletion, OpenAIChatPromptExecutionSettings
from semantic_kernel.contents import ChatHistory
from haltsql import HaltSQLClient
from haltsql_semantic_kernel import PLUGIN_NAME, HaltSQLPlugin, HaltSQLToolRunner

DSN = os.environ["AGENT_DATABASE_URL"]           # a read-only role
current_ctx = contextvars.ContextVar("haltsql_ctx", default=None)

runner = HaltSQLToolRunner(
    HaltSQLClient.from_env(),                    # or LocalVerifier("policy.yaml")
    connect=lambda: psycopg.connect(DSN),        # called only after HaltSQL allows the query
)

kernel = Kernel()
kernel.add_service(OpenAIChatCompletion(ai_model_id="gpt-4o-mini"))
kernel.add_plugin(HaltSQLPlugin(runner, context=current_ctx.get), plugin_name=PLUGIN_NAME)

async def answer(user, question: str) -> str:
    current_ctx.set({"tenant_id": user.tenant_id})   # from your auth, per request
    chat = kernel.get_service(type=OpenAIChatCompletion)
    settings = OpenAIChatPromptExecutionSettings(function_choice_behavior=FunctionChoiceBehavior.Auto())
    history = ChatHistory()
    history.add_user_message(question)
    reply = await chat.get_chat_message_content(history, settings, kernel=kernel)
    return str(reply)
```

`user` is your authenticated user. The chat service and execution settings
are standard Semantic Kernel; use whichever connector you already have. The
HaltSQL part is the `HaltSQLPlugin` line and setting `current_ctx` per
request.

## Where the tenant comes from

`context` is either a mapping or a zero-argument callable. A callable is
evaluated on every call, so one plugin can serve many requests. Reading a
`contextvars.ContextVar` that your request handler sets, as above, is the
usual pattern.

The plugin never reads the context from `KernelArguments`, because automatic
function calling merges the model's arguments into them.

| `context` | Result |
|---|---|
| A mapping, or a callable that returns one | The query is verified with that context. |
| A callable that returns `None` (for example a `ContextVar` that was not set) | Refused before verification: "No trusted HaltSQL context is configured for this run". |
| A callable that returns `{}` | Verified with an empty context. Tenant tables are then denied by the policy. |
| Not a mapping or callable | `TypeError` when you create the plugin. |

The callable runs in a worker thread, and `contextvars` values are copied into
that thread, so a `ContextVar` set in the request's task is visible.

If the model sends arguments the function does not declare, such as
`tenant_id`, Semantic Kernel itself refuses the call with an "unexpected
argument" error and the function does not run.

## What the model sees

The function returns JSON text. On success:

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

`HaltSQLPlugin(runner, context)`:

| Argument | Default | Meaning |
|---|---|---|
| `runner` | required | A `HaltSQLToolRunner`. Anything else raises `TypeError`. |
| `context` | required | A mapping, or a zero-argument callable that returns a mapping or `None`. |

The function name (`query`) and its description are fixed. The plugin name is
whatever you pass to `kernel.add_plugin`; `PLUGIN_NAME` is a suggestion.

Every query runs in a `READ ONLY` transaction, and only statements whose
verdict `statement_kind` is `select` are run. These cannot be turned off.

## Async support

The `query` function is async. Verification and execution run in a worker
thread (`asyncio.to_thread`), so the event loop is not blocked. Use a sync
verifier and a sync psycopg connection. Rows are returned whole; streaming
rows is not supported.

## Testing

You can test your wiring without a model, a sidecar or a database. Use
`FakeVerifier` from `haltsql.testing` and invoke the function through the
kernel:

```python
import asyncio
import json

from semantic_kernel import Kernel
from semantic_kernel.functions import KernelArguments
from haltsql.testing import FakeVerifier, make_verdict_dict
from haltsql_semantic_kernel import PLUGIN_NAME, HaltSQLPlugin, HaltSQLToolRunner

def deny(sql, ctx, _policy):
    return make_verdict_dict(sql, allowed=False, codes=["E_TENANT_MISSING"])

def no_db():
    raise AssertionError("connected after a denial")

def test_denial_never_connects():
    kernel = Kernel()
    runner = HaltSQLToolRunner(FakeVerifier(deny), no_db)
    kernel.add_plugin(HaltSQLPlugin(runner, context={"tenant_id": "acme"}), plugin_name=PLUGIN_NAME)
    result = asyncio.run(kernel.invoke(plugin_name=PLUGIN_NAME, function_name="query",
                                       arguments=KernelArguments(query="SELECT id FROM orders LIMIT 10")))
    out = json.loads(str(result.value))
    assert out["status"] == "denied" and out["reasons"][0]["code"] == "E_TENANT_MISSING"
```

The package's own tests use `Kernel.invoke` and `Kernel.invoke_function_call`
with the real `haltsql` CLI, a real `haltsql-server` and the lab Postgres. They
never call an LLM:

```sh
make -C lab up
dune build ./bin/haltsql/main.exe ./bin/server/main.exe
ONLY=agents clients/python/run-all-tests.sh
```

`integrations/semantic_kernel/constraints.txt` lists the exact versions the
tests were run with. See [Testing](../agent-frameworks.md#testing).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "No trusted HaltSQL context is configured for this run" | The `context` callable returned `None`, or raised a `LookupError`. With a `ContextVar`, it was not set in this request's task. | Set the context before you call the kernel, in the same task or a parent of it. |
| Every query on a tenant table is denied | The context is empty or misses a key the policy needs (`E_CONTEXT_MISSING`), or the model wrote a tenant literal (`E_TENANT_MISMATCH`). | Check the context. In bound mode the model must write `$1`. |
| An "unexpected argument" error | The model sent an argument other than `query`. | Nothing to fix in your code; Semantic Kernel refused the call. |
| "SQL verification is unavailable" | The sidecar or CLI failed, timed out, or returned a verdict for a different string. An unexpected exception in the `context` callable is also reported this way. | Check `HALTSQL_URL` and `HALTSQL_TOKEN`, or the `haltsql` binary. Test the callable on its own. |
| "The database is unavailable" | `connect` raised. | Check the DSN and network. |
| `TypeError` when creating the plugin | `runner` is not a `HaltSQLToolRunner`, or `context` is neither a mapping nor callable. | Fix the argument. |
| `ImportError: no pq wrapper available` | psycopg cannot find `libpq`. | `pip install 'psycopg[binary]'`, or install `libpq`. |

## Limits

- Read-only `SELECT` only. Write policies are not supported by this plugin.
- One statement per call. Rows are returned whole, up to `max_rows`; there is
  no streaming or pagination.
- `connect` must return a psycopg 3 connection.
- Python only. The package does not cover Semantic Kernel for .NET or Java.
- HaltSQL verifies the PostgreSQL dialect only.

## Related

- [Agent frameworks](../agent-frameworks.md): what all five packages share.
- [Python SDK](../sdk-python.md): verifiers, `guard.execute` and errors.
- [reason-codes.md](../reason-codes.md) and [tenancy.md](../tenancy.md).
- [defense-in-depth.md](../defense-in-depth.md).
- Source: [`integrations/semantic_kernel`](../../integrations/semantic_kernel).
