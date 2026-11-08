"""An example LangGraph agent with a bounded retry-on-deny loop.

::

    START -> agent --(tool calls)--> tools -> check --(denials < max)--> agent
               |                                 |
               +--(no tool calls)--> END          +--(denials >= max)--> END

``agent`` is your chat model bound to the HaltSQL tool
(``llm.bind_tools([tool])``); ``tools`` is a ``ToolNode``; ``check`` counts
HaltSQL refusals. A refusal goes back to the model as a ``ToolMessage`` with
the reason codes and hints, so it can fix the SQL; after ``max_denials``
refusals the graph stops with a short message instead of looping.

Usage::

    from haltsql_langgraph import HaltSQLToolRunner, haltsql_query_tool, build_sql_agent_graph

    tool = haltsql_query_tool(HaltSQLToolRunner(HaltSQLClient.from_env(), connect))
    graph = build_sql_agent_graph(llm.bind_tools([tool]), tool)
    out = graph.invoke({"messages": [("user", "How many open orders?")]},
                       context={"haltsql_context": {"tenant_id": session.tenant_id}})
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any, Dict, List, Optional, TypedDict

from langchain_core.messages import AIMessage, AnyMessage
from langchain_core.runnables import RunnableLambda
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from . import is_denial

__all__ = ["SQLAgentState", "build_sql_agent_graph"]


class SQLAgentState(TypedDict, total=False):
    messages: Annotated[List[AnyMessage], add_messages]
    denials: int
    """HaltSQL refusals so far in this run."""


def build_sql_agent_graph(
    model: Any,
    tool: Any,
    *,
    max_denials: int = 3,
    context_schema: Optional[type] = None,
    extra_tools: Optional[List[Any]] = None,
) -> Any:
    """Compile the graph.

    Args:
        model: A runnable (``llm.bind_tools([tool])``) or callable taking the
            message list and returning an ``AIMessage``.
        tool: The tool from :func:`haltsql_langgraph.haltsql_query_tool`.
        max_denials: Stop after this many refused queries (1..20).
        context_schema: Type of the runtime context passed as
            ``graph.invoke(..., context=...)`` (optional).
        extra_tools: Other tools served by the same ``ToolNode``.
    """
    if isinstance(max_denials, bool) or not isinstance(max_denials, int) or not 1 <= max_denials <= 20:
        raise ValueError("max_denials must be an integer in 1..20")
    invoke = model.invoke if hasattr(model, "invoke") else model

    def agent(state: SQLAgentState) -> Dict[str, Any]:
        msg = invoke(state["messages"])
        if not isinstance(msg, AIMessage):
            raise TypeError("the model must return an AIMessage")
        return {"messages": [msg]}

    async def aagent(state: SQLAgentState) -> Dict[str, Any]:
        if hasattr(model, "ainvoke"):
            msg = await model.ainvoke(state["messages"])
        elif asyncio.iscoroutinefunction(model):
            msg = await model(state["messages"])
        else:
            msg = await asyncio.to_thread(invoke, state["messages"])
        if not isinstance(msg, AIMessage):
            raise TypeError("the model must return an AIMessage")
        return {"messages": [msg]}

    def route_agent(state: SQLAgentState) -> str:
        last = state["messages"][-1]
        return "tools" if getattr(last, "tool_calls", None) else END

    def check(state: SQLAgentState) -> Dict[str, Any]:
        new: List[Any] = []
        for m in reversed(state["messages"]):
            if getattr(m, "type", None) != "tool":
                break
            new.append(m)
        denials = state.get("denials", 0) + sum(1 for m in new if is_denial(m))
        out: Dict[str, Any] = {"denials": denials}
        if denials >= max_denials:
            out["messages"] = [AIMessage(
                content=f"Stopping: HaltSQL refused {denials} queries in this run.",
                name="haltsql",
            )]
        return out

    def route_check(state: SQLAgentState) -> str:
        return END if state.get("denials", 0) >= max_denials else "agent"

    g: Any = StateGraph(SQLAgentState, context_schema=context_schema) if context_schema else StateGraph(SQLAgentState)
    g.add_node("agent", RunnableLambda(agent, afunc=aagent))
    g.add_node("tools", ToolNode([tool, *(extra_tools or [])]))
    g.add_node("check", check)
    g.add_edge(START, "agent")
    g.add_conditional_edges("agent", route_agent, ["tools", END])
    g.add_edge("tools", "check")
    g.add_conditional_edges("check", route_check, ["agent", END])
    return g.compile()
