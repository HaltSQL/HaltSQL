"""HaltSQL for CrewAI.

:class:`HaltSQLQueryTool` is a CrewAI ``BaseTool`` named ``haltsql_query``.
Its only argument is the SQL. It verifies with HaltSQL and runs exactly the
verified string (``READ ONLY``, statement timeout, row cap), and returns
JSON: the rows, or the reason codes and hints so the agent can fix the query.

The HaltSQL context (tenant, ...) is a mapping or a zero-argument callable you
give the tool when you build the crew for a request (for example one that
reads the current session from a ``contextvars`` variable). It is never a tool
argument, and never read from crew inputs or task text.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Optional, Type, Union

from crewai.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field

from ._core import (
    DEFAULT_CONTEXT_KEY,
    DEFAULT_DESCRIPTION,
    TOOL_NAME,
    ContextUnavailable,
    HaltSQLToolRunner,
    context_from_app,
    result_to_text,
)

__all__ = [
    "HaltSQLToolRunner",
    "HaltSQLQueryTool",
    "ContextUnavailable",
    "TOOL_NAME",
    "DEFAULT_CONTEXT_KEY",
    "context_from_app",
    "__version__",
]
__version__ = "0.0.1"

ContextSource = Union[Mapping[str, Any], Callable[[], Optional[Mapping[str, Any]]]]


class HaltSQLQueryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(description="One PostgreSQL SELECT statement with a LIMIT.")


class HaltSQLQueryTool(BaseTool):
    """CrewAI tool: verified read-only SQL.

    Example::

        tool = HaltSQLQueryTool(runner=HaltSQLToolRunner(HaltSQLClient.from_env(), connect),
                                context=lambda: {"tenant_id": session.tenant_id})
        analyst = Agent(role="Analyst", goal="...", backstory="...", tools=[tool])
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str = TOOL_NAME
    description: str = DEFAULT_DESCRIPTION
    args_schema: Type[BaseModel] = HaltSQLQueryInput
    runner: HaltSQLToolRunner = Field(exclude=True)
    context: Any = Field(exclude=True, repr=False)
    """The trusted HaltSQL context, or a zero-argument callable returning it per call."""

    def model_post_init(self, __context: Any) -> None:
        super().model_post_init(__context)
        if not (callable(self.context) or isinstance(self.context, Mapping)):
            raise TypeError("context must be a mapping or a zero-argument callable")

    def _ctx(self) -> Mapping[str, Any]:
        ctx = self.context() if callable(self.context) else self.context
        if ctx is None:
            raise ContextUnavailable("the context callable returned None")
        return ctx

    def _run(self, query: str, **extra: Any) -> str:
        if extra:
            return result_to_text({
                "status": "error", "executed": False,
                "message": "The query was not executed: pass exactly one argument, 'query'.",
            })
        return result_to_text(self.runner.run(query, self._ctx))

    async def _arun(self, query: str, **extra: Any) -> str:
        if extra:
            return self._run(query, **extra)
        return result_to_text(await self.runner.arun(query, self._ctx))
