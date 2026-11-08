# haltsql-langgraph

HaltSQL for [LangGraph](https://github.com/langchain-ai/langgraph).
`haltsql_query_tool()` is a LangChain tool that works with `ToolNode`. It
verifies each query with HaltSQL first. Then it runs exactly the verified
string with the bound tenant parameters, in a `READ ONLY` transaction with a
statement timeout and a row cap. `build_sql_agent_graph()` is an example agent
graph that retries after a refusal, up to a limit.

```sh
pip install -e clients/python -e integrations/langgraph   # from the repository root
```

```python
import psycopg
from haltsql import HaltSQLClient
from haltsql_langgraph import HaltSQLToolRunner, haltsql_query_tool, build_sql_agent_graph

tool = haltsql_query_tool(HaltSQLToolRunner(HaltSQLClient.from_env(), lambda: psycopg.connect(DSN)))
graph = build_sql_agent_graph(llm.bind_tools([tool]), tool, max_denials=3)
out = graph.invoke({"messages": [("user", "How many open orders?")]},
                   context={"haltsql_context": {"tenant_id": user.tenant_id}})
```

The tenant comes from LangGraph's runtime context (`invoke(..., context=...)`),
which the tool reads through `ToolRuntime`. It is never a tool argument. The
`ToolMessage` content is JSON for the model, and its `artifact` is the same
result as a dict. `is_denial(msg)` tells you whether a message is a refusal.

See [docs/agent-frameworks.md](../../docs/agent-frameworks.md).

## Tests

```sh
ONLY=agents clients/python/run-all-tests.sh   # real haltsql CLI/server and the lab Postgres
```
