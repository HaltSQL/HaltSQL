"""HaltSQL for the Google Agent Development Kit (``google-adk``).

* :class:`HaltSQLQueryTool` is an ADK ``BaseTool`` named ``haltsql_query``.
  Its only argument is the SQL. It verifies with HaltSQL and runs exactly the
  verified string (``READ ONLY``, statement timeout, row cap). It returns a
  dict: the rows, or the reason codes and hints so the model can fix the query.
* :func:`haltsql_before_tool_callback` and :class:`HaltSQLGuardPlugin` verify
  the SQL argument of *other* PostgreSQL tools before they run (for example
  the ``postgres-execute-sql`` tool of MCP Toolbox for Databases loaded with
  ``ToolboxToolset``, or your own ``execute_sql`` function). When HaltSQL does
  not allow the SQL, the tool is skipped and the model gets the refusal.
* :func:`build_sql_agent` is an example ``LlmAgent`` using the tool.

The HaltSQL context (tenant, ...) comes from ADK session state, by default the
``haltsql_context`` key, which your application sets when it creates the
session (``session_service.create_session(..., state={...})``). It is never a
tool argument. Do not let tools or ``output_key`` write that key.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Mapping, Optional

from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools.base_tool import BaseTool
from google.genai import types

from ._core import (
    DEFAULT_CONTEXT_KEY,
    DEFAULT_DESCRIPTION,
    QUERY_ARG,
    TOOL_NAME,
    ContextUnavailable,
    HaltSQLToolRunner,
    check_only,
    context_from_app,
)

__all__ = [
    "HaltSQLToolRunner",
    "HaltSQLQueryTool",
    "HaltSQLGuardPlugin",
    "ContextUnavailable",
    "TOOL_NAME",
    "DEFAULT_CONTEXT_KEY",
    "DEFAULT_GUARDED_TOOLS",
    "context_from_app",
    "haltsql_before_tool_callback",
    "build_sql_agent",
    "__version__",
]
__version__ = "0.0.3"

#: Tool name -> name of its SQL argument, guarded by default. ``execute_sql``
#: with ``sql`` matches MCP Toolbox's ``postgres-execute-sql`` kind when the
#: tool is named ``execute_sql`` in tools.yaml.
DEFAULT_GUARDED_TOOLS: Mapping[str, str] = {"execute_sql": "sql"}


def _state_context(tool_context: Any, state_key: str) -> Optional[Mapping[str, Any]]:
    """The HaltSQL context from session state, or ``None`` when absent."""
    try:
        return context_from_app(getattr(tool_context, "state", None), state_key)
    except ContextUnavailable:
        return None


def _refusal(message: str) -> Dict[str, Any]:
    return {"status": "error", "executed": False, "message": message}


class HaltSQLQueryTool(BaseTool):
    """ADK tool: verified read-only SQL, context from session state.

    Args:
        runner: Verifier, connection factory and limits.
        state_key: Session-state key holding the HaltSQL context mapping.
        name / description: What the model sees.
    """

    def __init__(
        self,
        runner: HaltSQLToolRunner,
        *,
        state_key: str = DEFAULT_CONTEXT_KEY,
        name: str = TOOL_NAME,
        description: str = DEFAULT_DESCRIPTION,
    ) -> None:
        if not isinstance(runner, HaltSQLToolRunner):
            raise TypeError("runner must be a HaltSQLToolRunner")
        if not isinstance(state_key, str) or not state_key:
            raise ValueError("state_key must be a non-empty string")
        super().__init__(name=name, description=description)
        self.runner = runner
        self.state_key = state_key

    def _get_declaration(self) -> Optional[types.FunctionDeclaration]:
        return types.FunctionDeclaration(
            name=self.name,
            description=self.description,
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={
                    QUERY_ARG: types.Schema(
                        type=types.Type.STRING,
                        description="One PostgreSQL SELECT statement with a LIMIT.",
                    )
                },
                required=[QUERY_ARG],
            ),
        )

    async def run_async(self, *, args: Dict[str, Any], tool_context: Any) -> Dict[str, Any]:
        if not isinstance(args, dict) or set(args) != {QUERY_ARG}:
            return _refusal(f"The query was not executed: pass exactly one argument, {QUERY_ARG!r}.")
        # Read the state now (on the event loop); the runner validates it.
        try:
            ctx: Optional[Mapping[str, Any]] = context_from_app(getattr(tool_context, "state", None), self.state_key)
        except ContextUnavailable:
            ctx = None
        except ValueError as e:
            return _refusal(f"The query was not executed: {e}")
        return await self.runner.arun(args[QUERY_ARG], ctx)


def _make_check(verifier: Any, tools: Optional[Mapping[str, str]], state_key: str) -> Any:
    if verifier is None or not callable(getattr(verifier, "verify", None)):
        raise ValueError("verifier must have a verify(sql, context) method")
    guarded = dict(DEFAULT_GUARDED_TOOLS if tools is None else tools)
    if not guarded or not all(isinstance(k, str) and isinstance(v, str) and k and v for k, v in guarded.items()):
        raise ValueError("tools must map tool names to SQL argument names")

    async def check(tool: Any, args: Dict[str, Any], tool_context: Any) -> Optional[Dict[str, Any]]:
        arg = guarded.get(getattr(tool, "name", None) or "")
        if arg is None:
            return None  # not a guarded tool
        try:
            ctx = _state_context(tool_context, state_key)
        except ValueError as e:
            return _refusal(f"The query was not executed: {e}")
        query = args.get(arg) if isinstance(args, dict) else None
        return await asyncio.to_thread(check_only, verifier, query, ctx)

    return check


def haltsql_before_tool_callback(
    verifier: Any,
    *,
    tools: Optional[Mapping[str, str]] = None,
    state_key: str = DEFAULT_CONTEXT_KEY,
) -> Any:
    """An ``LlmAgent(before_tool_callback=...)`` that verifies other tools' SQL.

    Args:
        verifier: ``HaltSQLClient``, ``LocalVerifier`` or any ``verify(sql, ctx)``.
        tools: Tool name -> SQL argument name (default
            :data:`DEFAULT_GUARDED_TOOLS`). Other tools pass through.
        state_key: Session-state key holding the HaltSQL context.

    For a guarded tool, returns ``None`` (run the tool) only when HaltSQL
    allows the SQL without bound parameters; otherwise returns a refusal dict,
    which ADK sends to the model instead of running the tool. Only use it for
    tools that run PostgreSQL. It checks the SQL only: run such tools with a
    read-only database role and their own timeouts. List it first if the agent
    has several before-tool callbacks, and do not let a later one change the
    arguments.
    """
    return _make_check(verifier, tools, state_key)


class HaltSQLGuardPlugin(BasePlugin):
    """Runner-wide version of :func:`haltsql_before_tool_callback`.

    ``Runner(..., plugins=[HaltSQLGuardPlugin(verifier)])`` guards the listed
    tools of every agent the runner executes. Plugin callbacks run before the
    agents' own callbacks.
    """

    def __init__(
        self,
        verifier: Any,
        *,
        tools: Optional[Mapping[str, str]] = None,
        state_key: str = DEFAULT_CONTEXT_KEY,
        name: str = "haltsql_guard",
    ) -> None:
        super().__init__(name=name)
        self._check = _make_check(verifier, tools, state_key)

    async def before_tool_callback(
        self, *, tool: BaseTool, tool_args: Dict[str, Any], tool_context: Any
    ) -> Optional[Dict[str, Any]]:
        return await self._check(tool, tool_args, tool_context)


SQL_AGENT_INSTRUCTION = (
    "You answer questions about the user's data with the haltsql_query tool. Write one "
    "PostgreSQL SELECT with a LIMIT per call. Tenant-scoped tables must be filtered with "
    "alias.tenant_id = $1; never write tenant IDs yourself. If the tool returns status "
    "'denied', read the reason codes and hints, fix the SQL and try again (at most three "
    "times); if it returns status 'error', tell the user the data is unavailable."
)


def build_sql_agent(
    runner: HaltSQLToolRunner,
    *,
    model: Any = "gemini-2.5-flash",
    name: str = "sql_analyst",
    instruction: str = SQL_AGENT_INSTRUCTION,
    state_key: str = DEFAULT_CONTEXT_KEY,
    **agent_kwargs: Any,
) -> Any:
    """An example ``LlmAgent`` with :class:`HaltSQLQueryTool`.

    Run it with a ``Runner`` whose session state holds the context::

        session = await runner.session_service.create_session(
            app_name=runner.app_name, user_id=user.id,
            state={"haltsql_context": {"tenant_id": user.tenant_id}})
    """
    from google.adk.agents import LlmAgent

    tool = HaltSQLQueryTool(runner, state_key=state_key)
    return LlmAgent(name=name, model=model, instruction=instruction, tools=[tool], **agent_kwargs)
