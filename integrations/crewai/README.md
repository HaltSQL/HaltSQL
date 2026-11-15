# haltsql-crewai

HaltSQL for [CrewAI](https://github.com/crewAIInc/crewAI). `HaltSQLQueryTool`
is a `BaseTool` named `haltsql_query`. It verifies each query with HaltSQL
first. Then it runs exactly the verified string with the bound tenant
parameters, in a `READ ONLY` transaction with a statement timeout and a row
cap. It returns JSON: the rows, or the reason codes and hints.

```sh
pip install haltsql-crewai
```

```python
import psycopg
from crewai import Agent
from haltsql import HaltSQLClient
from haltsql_crewai import HaltSQLQueryTool, HaltSQLToolRunner

tool = HaltSQLQueryTool(
    runner=HaltSQLToolRunner(HaltSQLClient.from_env(), lambda: psycopg.connect(DSN)),
    context=lambda: {"tenant_id": session.tenant_id},   # from your auth, per call
)
analyst = Agent(role="Analyst", goal="Answer questions about orders",
                backstory="Writes careful SQL.", tools=[tool])
```

The context is a mapping or a callable you control. It is never a tool
argument, and the argument schema rejects extra fields.

See [docs/agent-frameworks.md](../../docs/agent-frameworks.md).

## Tests

```sh
ONLY=agents clients/python/run-all-tests.sh   # real haltsql CLI/server and the lab Postgres
```
