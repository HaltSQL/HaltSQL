"""Builds the LangChain tool. No ``from __future__ import annotations`` here:
LangChain reads the real annotations to inject ``ToolRuntime``."""

from typing import Annotated, Any, Callable, Dict, Mapping, Tuple

from langchain_core.tools import StructuredTool
from langgraph.prebuilt import ToolRuntime

from ._core import HaltSQLToolRunner, result_to_text

_QUERY_DOC = "One PostgreSQL SELECT statement with a LIMIT."


def make_tool(
    runner: HaltSQLToolRunner,
    get_ctx: Callable[[Any], Mapping[str, Any]],
    name: str,
    description: str,
) -> StructuredTool:
    def _ctx(runtime: Any) -> Callable[[], Mapping[str, Any]]:
        return lambda: get_ctx(getattr(runtime, "context", None))

    def haltsql_query(query: Annotated[str, _QUERY_DOC], runtime: ToolRuntime) -> Tuple[str, Dict[str, Any]]:
        result = runner.run(query, _ctx(runtime))
        return result_to_text(result), result

    async def ahaltsql_query(query: Annotated[str, _QUERY_DOC], runtime: ToolRuntime) -> Tuple[str, Dict[str, Any]]:
        result = await runner.arun(query, _ctx(runtime))
        return result_to_text(result), result

    return StructuredTool.from_function(
        func=haltsql_query,
        coroutine=ahaltsql_query,
        name=name,
        description=description,
        response_format="content_and_artifact",
    )
