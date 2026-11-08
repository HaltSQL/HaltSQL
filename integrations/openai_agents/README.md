# haltsql-openai-agents

HaltSQL for the [OpenAI Agents SDK](https://github.com/openai/openai-agents-python).
The `haltsql_query` function tool verifies each query with HaltSQL first. Then
it runs exactly the verified string with the bound tenant parameters, in a
`READ ONLY` transaction with a statement timeout and a row cap. When nothing
runs, the model gets the reason codes and hints so it can fix the query.

```sh
pip install -e clients/python -e integrations/openai_agents   # from the repository root
```

```python
from dataclasses import dataclass, field
import psycopg
from agents import Agent, Runner
from haltsql import HaltSQLClient
from haltsql_openai_agents import HaltSQLToolRunner, haltsql_query_tool

@dataclass
class AppContext:                       # Runner.run(context=...): never sent to the model
    user_id: str
    haltsql_context: dict = field(default_factory=dict)

runner = HaltSQLToolRunner(HaltSQLClient.from_env(), lambda: psycopg.connect(DSN))
agent = Agent(name="analyst", instructions="Answer with SQL.", tools=[haltsql_query_tool(runner)])
result = await Runner.run(agent, "How many open orders?",
                          context=AppContext(user.id, {"tenant_id": user.tenant_id}))
```

The tenant comes from the run context, by default its `haltsql_context`
attribute or key. Pass `context_from=` to read it from your own context
object. It is never a tool argument.

`haltsql_tool_input_guardrail(verifier, sql_arg="sql")` guards SQL tools you
already have (`@function_tool(tool_input_guardrails=[...])`). Before the tool
runs, the guardrail verifies its SQL argument. If HaltSQL does not allow it,
the call is rejected and the model gets the refusal.

See [docs/agent-frameworks.md](../../docs/agent-frameworks.md).

## Tests

```sh
ONLY=agents clients/python/run-all-tests.sh   # real haltsql CLI/server and the lab Postgres
```
