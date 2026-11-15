# haltsql-semantic-kernel

HaltSQL for [Semantic Kernel](https://github.com/microsoft/semantic-kernel)
(Python). `HaltSQLPlugin` has one `kernel_function`, `query`. The model sees
it as `haltsql-query`. The function verifies each query with HaltSQL first.
Then it runs exactly the verified string with the bound tenant parameters, in
a `READ ONLY` transaction with a statement timeout and a row cap. It returns
JSON: the rows, or the reason codes and hints.

```sh
pip install haltsql-semantic-kernel
```

```python
import contextvars, psycopg
from semantic_kernel import Kernel
from haltsql import HaltSQLClient
from haltsql_semantic_kernel import HaltSQLPlugin, HaltSQLToolRunner, PLUGIN_NAME

current_ctx = contextvars.ContextVar("haltsql_ctx", default=None)   # set per request

runner = HaltSQLToolRunner(HaltSQLClient.from_env(), lambda: psycopg.connect(DSN))
kernel = Kernel()
kernel.add_plugin(HaltSQLPlugin(runner, context=current_ctx.get), plugin_name=PLUGIN_NAME)
```

The context is a mapping or a callable evaluated on every call. The plugin
never reads it from `KernelArguments`, because function calling merges the
model's arguments into them.

See [docs/agent-frameworks.md](../../docs/agent-frameworks.md).

## Tests

```sh
ONLY=agents clients/python/run-all-tests.sh   # real haltsql CLI/server and the lab Postgres
```
