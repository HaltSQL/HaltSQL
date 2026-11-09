"""Building blocks shared by the framework integrations (LangChain, LlamaIndex,
Vanna) and by your own.

* :data:`ContextSource` / :func:`resolve_context`: the caller's context, given
  as a mapping or as a zero-argument callable evaluated per query (for example
  one that reads the current request's session from a ``contextvars``
  variable). It never comes from the model. A callable that returns ``None``
  means "no trusted context": the query is refused, never verified with an
  empty context.
* :func:`authorize_guarded`: resolve the context, verify, and check the
  verdict's ``statement_kind`` against ``read_only``, normalizing failures so
  that nothing runs unless every step succeeded.
* :func:`feedback_for_model`: a short, LLM-readable explanation of why a query
  did not run, built from reason codes and hints only.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Mapping, Optional, Tuple, Union

from . import guard
from .errors import GuardError, HaltSQLError, HaltSQLRequestError, HaltSQLUnavailable, QueryDenied
from .models import Verdict, validate_context

__all__ = [
    "ContextSource",
    "ContextUnavailable",
    "resolve_context",
    "authorize_guarded",
    "guard_read_only",
    "feedback_for_model",
]

#: A context mapping, or a callable returning one (evaluated on every query).
ContextSource = Union[Mapping[str, Any], Callable[[], Optional[Mapping[str, Any]]]]


class ContextUnavailable(LookupError):
    """No HaltSQL context could be read from the trusted application state."""


def resolve_context(source: Optional[ContextSource]) -> Dict[str, Any]:
    """Evaluate ``source`` and validate the result.

    Raises :class:`ContextUnavailable` when ``source`` is ``None`` or the
    callable returns ``None`` (nothing is verified then), and ``ValueError``
    when the context is malformed.
    """
    if source is None:
        raise ContextUnavailable("no HaltSQL context is configured")
    ctx = source() if callable(source) else source
    if ctx is None:
        raise ContextUnavailable("the context callable returned None")
    return validate_context(ctx)


def authorize_guarded(
    sql: str,
    source: Optional[ContextSource],
    *,
    verifier: Any,
    read_only: bool = True,
) -> Tuple[Dict[str, Any], Verdict]:
    """Resolve the context and verify ``sql``; return ``(context, verdict)``.

    Raises (and nothing may run then):

    * :class:`ContextUnavailable` when there is no trusted context;
    * :class:`~haltsql.QueryDenied` when the policy denies the SQL;
    * :class:`~haltsql.GuardError` when ``read_only`` is true and the verdict's
      ``statement_kind`` is not ``select``, or when the verdict has no
      ``statement_kind`` at all;
    * :class:`~haltsql.HaltSQLUnavailable` (or another :class:`~haltsql.HaltSQLError`)
      for every other failure, including an exception raised by the context
      callable or a malformed context.
    """
    try:
        ctx = resolve_context(source)
        verdict = guard.authorize(sql, ctx, verifier=verifier)
    except (HaltSQLError, ContextUnavailable):
        raise
    except Exception as e:  # noqa: BLE001 - fail closed without exposing internals
        raise HaltSQLUnavailable(f"could not verify the query ({type(e).__name__})") from e
    kind = verdict.statement_kind
    if kind is None:
        raise GuardError("the verdict has no statement kind")
    if read_only and kind != "select":
        raise GuardError(f"only SELECT statements run in read-only mode (this is {kind.upper()})")
    return ctx, verdict


def guard_read_only(read_only: bool) -> Optional[bool]:
    """The ``read_only`` to pass to :func:`haltsql.guard.execute`.

    ``True`` stays ``True``. ``False`` becomes ``None``: writes the policy
    allowed run read-write, and ``SELECT`` statements still run ``READ ONLY``.
    """
    return True if read_only else None


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
    if isinstance(exc, ContextUnavailable):
        return "No trusted HaltSQL context is configured for this request; the query was not executed."
    if isinstance(exc, (HaltSQLUnavailable, HaltSQLRequestError)):
        return "SQL verification is unavailable; the query was not executed."
    if isinstance(exc, GuardError):
        return f"The query was not executed: {exc}"
    if isinstance(exc, HaltSQLError):
        return "The query was not executed."
    return f"Database error: {type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}".rstrip(": ")
