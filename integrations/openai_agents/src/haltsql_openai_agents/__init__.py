"""HaltSQL for the OpenAI Agents SDK (``openai-agents``).

* :func:`haltsql_query_tool` builds a ``FunctionTool`` named ``haltsql_query``
  whose only argument is the SQL. It verifies with HaltSQL and runs exactly the
  verified string (``READ ONLY``, statement timeout, row cap). The model gets
  back the rows, or the reason codes and hints so it can fix the query.
* :func:`haltsql_tool_input_guardrail` is a tool input guardrail for SQL
  tools you already have: it verifies their SQL argument before they run and
  rejects the call (the model sees the hints) when HaltSQL does not allow it.

The HaltSQL context (tenant, ...) comes from the run context you pass to
``Runner.run(..., context=...)``, which the model never sees, by default
from its ``haltsql_context`` attribute or key. It is never a tool argument.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Mapping, Optional

from ._core import (
    DEFAULT_CONTEXT_KEY,
    DEFAULT_DESCRIPTION,
    QUERY_ARG,
    TOOL_NAME,
    ContextUnavailable,
    HaltSQLToolRunner,
    check_only,
    context_from_app,
    result_to_text,
)

__all__ = [
    "HaltSQLToolRunner",
    "ContextUnavailable",
    "TOOL_NAME",
    "DEFAULT_CONTEXT_KEY",
    "context_from_app",
    "haltsql_query_tool",
    "haltsql_tool_input_guardrail",
    "__version__",
]
__version__ = "0.0.1"

#: Maps the run context object (``RunContextWrapper.context``) to a HaltSQL context.
ContextFrom = Callable[[Any], Mapping[str, Any]]

_PARAMS_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        QUERY_ARG: {
            "type": "string",
            "description": "One PostgreSQL SELECT statement with a LIMIT.",
        }
    },
    "required": [QUERY_ARG],
    "additionalProperties": False,
}


def _context_getter(context_from: Optional[ContextFrom]) -> Callable[[Any], Mapping[str, Any]]:
    if context_from is None:
        return lambda app: context_from_app(app, DEFAULT_CONTEXT_KEY)

    def get(app: Any) -> Mapping[str, Any]:
        ctx = context_from(app)
        if ctx is None:
            raise ContextUnavailable("context_from returned None")
        return ctx

    return get


def _query_from_args(raw: str) -> Any:
    try:
        args = json.loads(raw) if raw else {}
    except ValueError:
        return None
    if not isinstance(args, dict) or set(args) != {QUERY_ARG}:
        return None
    return args[QUERY_ARG]


def haltsql_query_tool(
    runner: HaltSQLToolRunner,
    *,
    context_from: Optional[ContextFrom] = None,
    name: str = TOOL_NAME,
    description: str = DEFAULT_DESCRIPTION,
) -> Any:
    """A ``FunctionTool`` that verifies and runs one read-only query.

    Args:
        runner: Verifier, connection factory and limits.
        context_from: ``f(run_context) -> mapping`` reading the HaltSQL context
            from the object passed as ``Runner.run(..., context=...)``. Default:
            its ``haltsql_context`` attribute or key.
        name / description: What the model sees.

    The tool's output is JSON text: ``{"status": "ok", "columns", "rows",
    "row_count", "truncated"}``, ``{"status": "denied", "reasons": [{code,
    message, hint}], "message"}`` or ``{"status": "error", "message"}``.
    """
    from agents import FunctionTool

    get_ctx = _context_getter(context_from)

    async def on_invoke(tool_ctx: Any, raw_args: str) -> str:
        query = _query_from_args(raw_args)
        if query is None:
            return result_to_text({
                "status": "error", "executed": False,
                "message": f"The query was not executed: pass exactly one argument, {QUERY_ARG!r}.",
            })

        def ctx() -> Mapping[str, Any]:
            return get_ctx(getattr(tool_ctx, "context", None))

        return result_to_text(await runner.arun(query, ctx))

    return FunctionTool(
        name=name,
        description=description,
        params_json_schema=_PARAMS_SCHEMA,
        on_invoke_tool=on_invoke,
        strict_json_schema=True,
    )


def haltsql_tool_input_guardrail(
    verifier: Any,
    *,
    sql_arg: str = QUERY_ARG,
    context_from: Optional[ContextFrom] = None,
    name: str = "haltsql_sql_guardrail",
) -> Any:
    """A ``ToolInputGuardrail`` that verifies another tool's SQL argument.

    Attach it with ``@function_tool(tool_input_guardrails=[...])``. The call
    is rejected (``reject_content``: the tool does not run and the model gets
    the HaltSQL feedback as JSON) when the argument is missing, the query is
    denied, HaltSQL is unavailable, no context is configured, or the verdict
    needs bound parameters the tool cannot pass (use :func:`haltsql_query_tool`
    for tenant-bound queries). This only checks the SQL; read-only execution,
    timeouts and row caps remain the guarded tool's job.
    """
    from agents import ToolGuardrailFunctionOutput, ToolInputGuardrail

    get_ctx = _context_getter(context_from)

    def check(data: Any) -> Any:
        tool_ctx = data.context
        try:
            args = json.loads(tool_ctx.tool_arguments or "{}")
        except ValueError:
            args = None
        query = args.get(sql_arg) if isinstance(args, dict) else None
        refusal: Optional[Dict[str, Any]]
        try:
            ctx: Optional[Mapping[str, Any]] = get_ctx(getattr(tool_ctx, "context", None))
        except ValueError as e:
            refusal = {"status": "error", "executed": False, "message": f"The query was not executed: {e}"}
            return ToolGuardrailFunctionOutput.reject_content(result_to_text(refusal), output_info=refusal)
        except Exception:  # noqa: BLE001 - no usable context: refuse below
            ctx = None
        refusal = check_only(verifier, query, ctx)
        if refusal is None:
            return ToolGuardrailFunctionOutput.allow(output_info={"haltsql": "allowed"})
        return ToolGuardrailFunctionOutput.reject_content(result_to_text(refusal), output_info=refusal)

    async def guardrail_function(data: Any) -> Any:
        import asyncio

        return await asyncio.to_thread(check, data)

    return ToolInputGuardrail(guardrail_function=guardrail_function, name=name)
