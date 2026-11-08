"""Calls the HaltSQL query tool of one agent framework through that
framework's own tool-call machinery, for test_agents.py.

Run with the framework's virtualenv (test/e2e/.venv-agents/<framework>, made
by `test/e2e/stack.sh venv`):

    .venv-agents/openai_agents/bin/python -I drive_tool.py openai_agents < job.json

No model is called. Each call is handed to the framework exactly as a model
turn would carry it (a function/tool call with the model-written arguments),
and the framework runs the tool: the OpenAI Agents SDK's function-tool
executor, a LangGraph StateGraph with a prebuilt ToolNode, ADK's function-call
handler on an InMemoryRunner session. The tool verifies with the real
haltsql-server (HaltSQLClient with a bearer token) and runs allowed queries on
the real Postgres.

job.json (stdin; it carries secrets, so never argv):
    {"server_url": ..., "token": ..., "dsn": ...,
     "calls": [{"query": ..., "context": {...} | null}, ...]}

Prints one JSON document: {"framework": ..., "results": [<tool result>, ...]},
each result being the structured result the framework handed back.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Callable, Dict, List, Optional

for k, v in {
    "OPENAI_AGENTS_DISABLE_TRACING": "1",
    "OTEL_SDK_DISABLED": "true",
    "ADK_DISABLE_TELEMETRY": "1",
    "ANONYMIZED_TELEMETRY": "False",
}.items():
    os.environ.setdefault(k, v)


def make_runner(job: Dict[str, Any], runner_cls: Any) -> Any:
    import psycopg
    from haltsql import HaltSQLClient

    client = HaltSQLClient(job["server_url"], job["token"], timeout=10.0)

    def connect() -> Any:
        return psycopg.connect(job["dsn"], connect_timeout=5)

    return runner_cls(client, connect)


# --------------------------------------------------------------------------
# OpenAI Agents SDK


def openai_agents(job: Dict[str, Any]) -> List[Dict[str, Any]]:
    from agents import Agent, RunConfig, RunContextWrapper, RunHooks
    from agents.run_internal.agent_bindings import bind_public_agent
    from agents.run_internal.run_steps import ToolRunFunction
    from agents.run_internal.tool_execution import execute_function_tool_calls
    from openai.types.responses import ResponseFunctionToolCall

    from haltsql_openai_agents import HaltSQLToolRunner, haltsql_query_tool

    tool = haltsql_query_tool(make_runner(job, HaltSQLToolRunner))
    agent = Agent(name="analyst", instructions="Answer with SQL.", tools=[tool])

    async def call(i: int, query: str, ctx: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        app = {"haltsql_context": ctx} if ctx is not None else {}
        tc = ResponseFunctionToolCall(type="function_call", call_id=f"call_{i}", name=tool.name,
                                      arguments=json.dumps({"query": query}))
        results, _in, _out = await execute_function_tool_calls(
            bindings=bind_public_agent(agent),
            tool_runs=[ToolRunFunction(tool_call=tc, function_tool=tool)],
            hooks=RunHooks(),
            context_wrapper=RunContextWrapper(context=app),
            config=RunConfig(tracing_disabled=True),
        )
        assert len(results) == 1
        return json.loads(results[0].output)

    return [asyncio.run(call(i, c["query"], c.get("context"))) for i, c in enumerate(job["calls"])]


# --------------------------------------------------------------------------
# LangGraph


def langgraph(job: Dict[str, Any]) -> List[Dict[str, Any]]:
    from dataclasses import dataclass, field

    from langchain_core.messages import AIMessage, ToolMessage
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode

    from haltsql_langgraph import HaltSQLToolRunner, haltsql_query_tool

    @dataclass
    class AppContext:
        haltsql_context: Dict[str, Any] = field(default_factory=dict)

    tool = haltsql_query_tool(make_runner(job, HaltSQLToolRunner))
    g = StateGraph(MessagesState, context_schema=AppContext)
    g.add_node("tools", ToolNode([tool]))
    g.add_edge(START, "tools")
    g.add_edge("tools", END)
    graph = g.compile()

    out = []
    for i, c in enumerate(job["calls"]):
        msg = AIMessage(content="", tool_calls=[{"name": tool.name, "args": {"query": c["query"]},
                                                 "id": f"call_{i}"}])
        ctx = c.get("context")
        state = graph.invoke({"messages": [msg]},
                             context=AppContext(ctx) if ctx is not None else None)
        reply = state["messages"][-1]
        assert isinstance(reply, ToolMessage) and reply.tool_call_id == f"call_{i}"
        assert json.loads(reply.content)["status"] == reply.artifact["status"]
        out.append(reply.artifact)
    return out


# --------------------------------------------------------------------------
# Google ADK


def google_adk(job: Dict[str, Any]) -> List[Dict[str, Any]]:
    from google.adk.events import Event
    from google.adk.flows.llm_flows.functions import handle_function_calls_async
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    from haltsql_google_adk import HaltSQLToolRunner, build_sql_agent

    agent = build_sql_agent(make_runner(job, HaltSQLToolRunner))
    app = "haltsql_e2e"
    runner = InMemoryRunner(agent=agent, app_name=app)

    async def call(i: int, query: str, ctx: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        state = {"haltsql_context": ctx} if ctx is not None else {}
        session = await runner.session_service.create_session(app_name=app, user_id=f"u{i}",
                                                               state=state)
        ic = runner._new_invocation_context(session)
        event = Event(
            invocation_id=ic.invocation_id,
            author=agent.name,
            content=types.Content(role="model", parts=[types.Part(
                function_call=types.FunctionCall(id=f"call_{i}", name="haltsql_query",
                                                 args={"query": query}))]),
        )
        tools = {t.name: t for t in await agent.canonical_tools()}
        resp = await handle_function_calls_async(ic, event, tools)
        assert resp is not None
        parts = [p for p in resp.content.parts if p.function_response]
        assert len(parts) == 1 and parts[0].function_response.id == f"call_{i}"
        return dict(parts[0].function_response.response)

    async def all_calls() -> List[Dict[str, Any]]:
        return [await call(i, c["query"], c.get("context")) for i, c in enumerate(job["calls"])]

    return asyncio.run(all_calls())


FRAMEWORKS: Dict[str, Callable[[Dict[str, Any]], List[Dict[str, Any]]]] = {
    "openai_agents": openai_agents,
    "langgraph": langgraph,
    "google_adk": google_adk,
}


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in FRAMEWORKS:
        sys.exit(f"usage: drive_tool.py {{{'|'.join(FRAMEWORKS)}}} < job.json")
    job = json.load(sys.stdin)
    results = FRAMEWORKS[sys.argv[1]](job)
    json.dump({"framework": sys.argv[1], "results": results}, sys.stdout)


if __name__ == "__main__":
    main()
