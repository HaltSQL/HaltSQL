# haltsql-google-adk

HaltSQL for the [Google Agent Development Kit](https://github.com/google/adk-python).

* `HaltSQLQueryTool` is a `BaseTool` named `haltsql_query`. It verifies each
  query with HaltSQL first. Then it runs exactly the verified string with the
  bound tenant parameters, in a `READ ONLY` transaction with a statement
  timeout and a row cap. It returns a dict: the rows, or the reason codes and
  hints.
* `haltsql_before_tool_callback(verifier)` and `HaltSQLGuardPlugin(verifier)`
  verify the SQL argument of other PostgreSQL tools before they run, such as
  MCP Toolbox's `postgres-execute-sql` or your own `execute_sql`.
* `build_sql_agent(runner)` is an example `LlmAgent`.

```sh
pip install haltsql-google-adk
```

```python
import psycopg
from google.adk.runners import InMemoryRunner
from haltsql import HaltSQLClient
from haltsql_google_adk import HaltSQLToolRunner, build_sql_agent

runner = HaltSQLToolRunner(HaltSQLClient.from_env(), lambda: psycopg.connect(DSN))
agent = build_sql_agent(runner, model="gemini-2.5-flash")
adk = InMemoryRunner(agent=agent, app_name="analytics")
session = await adk.session_service.create_session(
    app_name="analytics", user_id=user.id,
    state={"haltsql_context": {"tenant_id": user.tenant_id}})
```

The tenant comes from session state, by default the `haltsql_context` key,
which your application sets. It is never a tool argument.

See [docs/agent-frameworks.md](../../docs/agent-frameworks.md).

## Tests

```sh
ONLY=agents clients/python/run-all-tests.sh   # real haltsql CLI/server and the lab Postgres
```
