"""HaltSQL for Semantic Kernel (Python).

:class:`HaltSQLPlugin` is a native plugin with one ``kernel_function``,
``query`` (the model sees ``haltsql-query`` when the plugin is added as
``haltsql``). Its only argument is the SQL. It verifies with HaltSQL and runs
exactly the verified string (``READ ONLY``, statement timeout, row cap), and
returns JSON: the rows, or the reason codes and hints so the model can fix
the query.

The HaltSQL context (tenant, ...) is a mapping or a zero-argument callable you
give the plugin, evaluated on every call (for example one that reads the
current request's session from a ``contextvars`` variable). It is never read
from ``KernelArguments``, because function-calling merges model-written
arguments into them.
"""

# No ``from __future__ import annotations``: Semantic Kernel reads the real
# parameter annotations to build the function schema.

from typing import Annotated, Any, Callable, Mapping, Optional, Union

from semantic_kernel.functions import kernel_function

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
    "HaltSQLPlugin",
    "ContextUnavailable",
    "TOOL_NAME",
    "PLUGIN_NAME",
    "DEFAULT_CONTEXT_KEY",
    "context_from_app",
    "__version__",
]
__version__ = "0.1.0"

#: Suggested plugin name; with the function name ``query`` the model sees ``haltsql-query``.
PLUGIN_NAME = "haltsql"

ContextSource = Union[Mapping[str, Any], Callable[[], Optional[Mapping[str, Any]]]]


class HaltSQLPlugin:
    """Semantic Kernel plugin: verified read-only SQL.

    Args:
        runner: Verifier, connection factory and limits.
        context: The trusted HaltSQL context, or a callable returning it per
            call (``None`` from the callable refuses the query).

    Example::

        kernel.add_plugin(HaltSQLPlugin(runner, context=lambda: current_tenant_ctx.get()),
                          plugin_name=PLUGIN_NAME)
    """

    def __init__(self, runner: HaltSQLToolRunner, context: ContextSource) -> None:
        if not isinstance(runner, HaltSQLToolRunner):
            raise TypeError("runner must be a HaltSQLToolRunner")
        if not (callable(context) or isinstance(context, Mapping)):
            raise TypeError("context must be a mapping or a zero-argument callable")
        self._runner = runner
        self._context = context

    def _ctx(self) -> Mapping[str, Any]:
        ctx = self._context() if callable(self._context) else self._context
        if ctx is None:
            raise ContextUnavailable("the context callable returned None")
        return ctx

    @kernel_function(name="query", description=DEFAULT_DESCRIPTION)
    async def query(
        self, query: Annotated[str, "One PostgreSQL SELECT statement with a LIMIT."]
    ) -> Annotated[str, "JSON: status ok with columns/rows, or status denied/error with reasons and hints."]:
        return result_to_text(await self._runner.arun(query, self._ctx))
