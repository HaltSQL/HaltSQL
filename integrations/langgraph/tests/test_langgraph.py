"""haltsql-langgraph with real LangGraph objects (ToolNode, StateGraph,
runtime context), the real haltsql CLI / haltsql-server and the lab Postgres.
No LLM is called: the "model" node below is a deterministic script that
writes the tool calls a model would, so the retry loop can be checked."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

import pytest

from conftest import CROSS_TENANT_SQL, OK_SQL, TENANT_HINT, acme_rows, assert_denied_cross_tenant

pytest.importorskip("langgraph", reason="langgraph is not installed (pip install -e integrations/langgraph)")

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage  # noqa: E402
from langgraph.graph import START, END, StateGraph, MessagesState  # noqa: E402
from langgraph.prebuilt import ToolNode  # noqa: E402

from haltsql_langgraph import HaltSQLToolRunner, build_sql_agent_graph, haltsql_query_tool, is_denial  # noqa: E402


@dataclass
class AppContext:
    user_id: str
    haltsql_context: Dict[str, Any] = field(default_factory=dict)


def _call(query: str, i: int = 1) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": "haltsql_query", "args": {"query": query}, "id": f"c{i}"}])


def _tool_node_graph(tool: Any) -> Any:
    g = StateGraph(MessagesState, context_schema=AppContext)
    g.add_node("tools", ToolNode([tool]))
    g.add_edge(START, "tools")
    g.add_edge("tools", END)
    return g.compile()


def test_tool_schema_hides_runtime():
    class V:
        def verify(self, sql, context=None):
            raise AssertionError

    tool = haltsql_query_tool(HaltSQLToolRunner(V(), lambda: None))
    assert tool.name == "haltsql_query"
    assert list(tool.tool_call_schema.model_json_schema()["properties"]) == ["query"]
    with pytest.raises(ValueError):
        build_sql_agent_graph(lambda m: m, tool, max_denials=0)


@pytest.mark.integration
def test_tool_node_allowed_and_denied(local_verifier, connections):
    tool = haltsql_query_tool(HaltSQLToolRunner(local_verifier, connections))
    graph = _tool_node_graph(tool)
    ctx = AppContext("u1", {"tenant_id": "acme"})

    out = graph.invoke({"messages": [_call(OK_SQL)]}, context=ctx)
    msg = out["messages"][-1]
    assert isinstance(msg, ToolMessage) and msg.artifact["rows"] == acme_rows()
    assert json.loads(msg.content)["status"] == "ok" and not is_denial(msg)
    assert connections.opened == 1

    out = asyncio.run(graph.ainvoke({"messages": [_call(CROSS_TENANT_SQL)]}, context=ctx))
    msg = out["messages"][-1]
    assert_denied_cross_tenant(msg.artifact)
    assert TENANT_HINT in msg.content and is_denial(msg)
    assert connections.opened == 1  # denied: never executed


@pytest.mark.integration
def test_context_only_from_runtime(server_verifier, connections):
    tool = haltsql_query_tool(HaltSQLToolRunner(server_verifier, connections))
    graph = _tool_node_graph(tool)
    out = graph.invoke({"messages": [_call(OK_SQL)]}, context=AppContext("u2", {"tenant_id": "globex"}))
    assert out["messages"][-1].artifact["rows"] == [[2, "open"], [4, "paid"]]
    # No runtime context: refused, nothing verified or run.
    out = graph.invoke({"messages": [_call(OK_SQL)]})
    art = out["messages"][-1].artifact
    assert art["status"] == "error" and "No trusted HaltSQL context" in art["message"]
    assert connections.opened == 1
    # A model cannot smuggle a tenant in: the args schema has only "query".
    bad = AIMessage(content="", tool_calls=[{"name": "haltsql_query", "id": "x",
                                             "args": {"query": OK_SQL, "tenant_id": "acme"}}])
    out = graph.invoke({"messages": [bad]}, context=AppContext("u2", {"tenant_id": "globex"}))
    assert out["messages"][-1].artifact["rows"] == [[2, "open"], [4, "paid"]]


class ScriptedModel:
    """Stands in for the LLM: writes a cross-tenant query first, then follows
    the HaltSQL hint, then answers."""

    def __init__(self) -> None:
        self.seen: List[str] = []

    def invoke(self, messages: List[Any]) -> AIMessage:
        last = messages[-1]
        if isinstance(last, HumanMessage):
            return _call(CROSS_TENANT_SQL, 1)
        assert isinstance(last, ToolMessage)
        self.seen.append(last.content)
        if TENANT_HINT in last.content:
            return _call(OK_SQL, 2)
        return AIMessage(content=f"Found {json.loads(last.content)['row_count']} orders.")


@pytest.mark.integration
def test_example_graph_retries_after_denial(local_verifier, connections):
    tool = haltsql_query_tool(HaltSQLToolRunner(local_verifier, connections))
    model = ScriptedModel()
    graph = build_sql_agent_graph(model, tool, context_schema=AppContext)
    out = graph.invoke({"messages": [HumanMessage("List my orders")]},
                       context=AppContext("u1", {"tenant_id": "acme"}))
    assert out["messages"][-1].content == "Found 2 orders."
    assert out["denials"] == 1
    assert TENANT_HINT in model.seen[0]
    assert connections.opened == 1

    # Async execution (ainvoke) works as well.
    amodel = ScriptedModel()
    agraph = build_sql_agent_graph(amodel, tool, context_schema=AppContext)
    aout = asyncio.run(agraph.ainvoke({"messages": [HumanMessage("List my orders")]},
                                      context=AppContext("u1", {"tenant_id": "acme"})))
    assert aout["messages"][-1].content == "Found 2 orders."
    assert aout["denials"] == 1
    assert connections.opened == 2


@pytest.mark.integration
def test_example_graph_stops_after_max_denials(local_verifier, connections):
    tool = haltsql_query_tool(HaltSQLToolRunner(local_verifier, connections))
    calls = []

    def stubborn(messages: List[Any]) -> AIMessage:
        calls.append(len(messages))
        return _call(CROSS_TENANT_SQL, len(calls))

    graph = build_sql_agent_graph(stubborn, tool, max_denials=2)
    out = graph.invoke({"messages": [HumanMessage("x")]},
                       context={"haltsql_context": {"tenant_id": "acme"}})
    assert out["denials"] == 2 and len(calls) == 2
    assert out["messages"][-1].content == "Stopping: HaltSQL refused 2 queries in this run."
    assert connections.opened == 0
