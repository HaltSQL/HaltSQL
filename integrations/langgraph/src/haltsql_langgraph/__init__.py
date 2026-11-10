"""HaltSQL for LangGraph.

* :func:`haltsql_query_tool` builds a LangChain tool named ``haltsql_query``
  for ``langgraph.prebuilt.ToolNode`` (or ``create_react_agent``). Its only
  model-facing argument is the SQL. It verifies with HaltSQL and runs exactly
  the verified string (``READ ONLY``, statement timeout, row cap). The
  ``ToolMessage`` content is JSON for the model; its ``artifact`` is the same
  result as a dict, for your graph's routing.
* :func:`build_sql_agent_graph` (in :mod:`haltsql_langgraph.graph`) is a small
  agent graph with a bounded retry-on-deny loop.

The HaltSQL context (tenant, ...) comes from LangGraph's runtime context,
``graph.invoke(..., context=...)``, which your application sets and the model
never sees. By default it is read from its ``haltsql_context`` attribute or
key. It is never a tool argument.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Optional

from ._core import (
    DEFAULT_CONTEXT_KEY,
    DEFAULT_DESCRIPTION,
    TOOL_NAME,
    ContextUnavailable,
    HaltSQLToolRunner,
    context_from_app,
)

__all__ = [
    "HaltSQLToolRunner",
    "ContextUnavailable",
    "TOOL_NAME",
    "DEFAULT_CONTEXT_KEY",
    "context_from_app",
    "haltsql_query_tool",
    "is_denial",
    "build_sql_agent_graph",
    "__version__",
]
__version__ = "0.0.3"

#: Maps LangGraph's runtime context (``ToolRuntime.context``) to a HaltSQL context.
ContextFrom = Callable[[Any], Mapping[str, Any]]


def _context_getter(context_from: Optional[ContextFrom]) -> Callable[[Any], Mapping[str, Any]]:
    if context_from is None:
        return lambda app: context_from_app(app, DEFAULT_CONTEXT_KEY)

    def get(app: Any) -> Mapping[str, Any]:
        ctx = context_from(app)
        if ctx is None:
            raise ContextUnavailable("context_from returned None")
        return ctx

    return get


def haltsql_query_tool(
    runner: HaltSQLToolRunner,
    *,
    context_from: Optional[ContextFrom] = None,
    name: str = TOOL_NAME,
    description: str = DEFAULT_DESCRIPTION,
) -> Any:
    """A ``StructuredTool`` (``response_format="content_and_artifact"``).

    Args:
        runner: Verifier, connection factory and limits.
        context_from: ``f(runtime_context) -> mapping``. Default: the
            ``haltsql_context`` attribute or key of the graph's runtime context.
        name / description: What the model sees.
    """
    from ._tool import make_tool

    return make_tool(runner, _context_getter(context_from), name, description)


def is_denial(message: Any) -> bool:
    """True if ``message`` is a ``ToolMessage`` from the HaltSQL tool whose query did not run."""
    artifact = getattr(message, "artifact", None)
    return (
        getattr(message, "type", None) == "tool"
        and isinstance(artifact, Mapping)
        and artifact.get("status") in ("denied", "error")
    )


def build_sql_agent_graph(*args: Any, **kwargs: Any) -> Any:
    """See :func:`haltsql_langgraph.graph.build_sql_agent_graph`."""
    from .graph import build_sql_agent_graph as build

    return build(*args, **kwargs)
