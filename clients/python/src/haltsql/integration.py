"""Building blocks shared by the framework integrations (LangChain, LlamaIndex,
Vanna) and by your own.

* :data:`ContextSource` / :func:`resolve_context`: the caller's context, given
  as a mapping or as a zero-argument callable evaluated per query (for example
  one that reads the current request's session from a ``contextvars``
  variable). It never comes from the model.
* :func:`feedback_for_model`: a short, LLM-readable explanation of why a query
  did not run, built from reason codes and hints only.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Mapping, Union

from .errors import GuardError, HaltSQLError, HaltSQLRequestError, HaltSQLUnavailable, QueryDenied
from .models import validate_context

__all__ = ["ContextSource", "resolve_context", "feedback_for_model"]

#: A context mapping, or a callable returning one (evaluated on every query).
ContextSource = Union[Mapping[str, Any], Callable[[], Mapping[str, Any]]]


def resolve_context(source: ContextSource) -> Dict[str, Any]:
    """Evaluate ``source`` and validate the result (raises ``ValueError``)."""
    ctx = source() if callable(source) else source
    return validate_context(ctx)


def feedback_for_model(exc: BaseException) -> str:
    """A message safe to return to an agent when a guarded query did not run.

    Denials list each ``CODE: hint`` so the model can fix its SQL. Other
    failures say only that nothing ran, without internal details.
    """
    if isinstance(exc, QueryDenied):
        lines = ["HaltSQL denied the query; it was not executed. Fix the SQL and retry:"]
        for r in exc.verdict.reasons:
            lines.append(f"- {r.code}: {r.hint or r.message}")
        return "\n".join(lines)
    if isinstance(exc, (HaltSQLUnavailable, HaltSQLRequestError)):
        return "SQL verification is unavailable; the query was not executed."
    if isinstance(exc, GuardError):
        return f"The query was not executed: {exc}"
    if isinstance(exc, HaltSQLError):
        return "The query was not executed."
    return f"Database error: {type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}".rstrip(": ")
