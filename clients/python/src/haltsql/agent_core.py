"""Framework-free core shared by the HaltSQL agent-framework packages.

This module is re-exported by ``haltsql_openai_agents``, ``haltsql_langgraph``,
``haltsql_semantic_kernel``, ``haltsql_crewai`` and ``haltsql_google_adk``. It
only depends on the ``haltsql`` SDK.

* :class:`HaltSQLToolRunner` verifies one model-written statement with
  HaltSQL and, only when the verdict allows exactly that string, runs it
  through :func:`haltsql.guard.execute` in a ``READ ONLY`` transaction with a
  statement timeout and a row cap. It never raises: every outcome is a
  structured result (``status`` ``ok`` / ``denied`` / ``error``) that the
  framework adapters hand back to the model.
* :func:`check_only` verifies SQL that another tool will run (guard hooks
  such as ADK's ``before_tool_callback`` or an Agents SDK tool input
  guardrail); it refuses whenever HaltSQL would need to bind parameters,
  because such a tool cannot pass them.
* :func:`context_from_app` reads the HaltSQL context out of the framework's
  trusted application state (run context, runtime context, session state).
  The context is never taken from model-provided tool arguments.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import decimal
import json
import uuid
from typing import Any, Callable, Dict, List, Mapping, Optional, Union

from . import guard
from .errors import GuardError, HaltSQLError, HaltSQLRequestError, HaltSQLUnavailable, QueryDenied
from .integration import ContextUnavailable, feedback_for_model
from .models import validate_context

__all__ = [
    "TOOL_NAME",
    "QUERY_ARG",
    "DEFAULT_CONTEXT_KEY",
    "DEFAULT_DESCRIPTION",
    "ContextUnavailable",
    "HaltSQLToolRunner",
    "SettingsSource",
    "check_only",
    "context_from_app",
    "result_to_text",
]

#: Name of the query tool in every package (the model sees this name).
TOOL_NAME = "haltsql_query"
#: The tool's single model-facing argument.
QUERY_ARG = "query"
#: Key (or attribute) holding the HaltSQL context in trusted application state.
DEFAULT_CONTEXT_KEY = "haltsql_context"

DEFAULT_DESCRIPTION = (
    "Run one read-only PostgreSQL query and get the rows back. Input: a single "
    "SELECT statement with a LIMIT. The tenant is fixed by the application: filter "
    "tenant-scoped tables with alias.tenant_id = $1 and never write tenant IDs "
    "yourself. If the result has status 'denied', nothing ran: read the reason codes "
    "and hints, fix the SQL and call the tool again."
)

_MAX_QUERY_CHARS = 65536

#: Transaction-local settings: a mapping, or a function of the verified context
#: (e.g. ``lambda ctx: {"app.tenant_id": ctx["tenant_id"]}`` for row-level security).
SettingsSource = Union[Mapping[str, str], Callable[[Mapping[str, Any]], Mapping[str, str]]]


def context_from_app(app_state: Any, key: str = DEFAULT_CONTEXT_KEY) -> Dict[str, Any]:
    """Read and validate the HaltSQL context stored under ``key``.

    ``app_state`` is the object the application handed to the framework: a
    mapping (or a mapping-like object with ``get``, such as ADK session
    state) or any object with an attribute named ``key``. The value may be a
    mapping or a zero-argument callable returning one. Raises
    :class:`ContextUnavailable` when it is missing and ``ValueError`` when it is
    not a valid context.
    """
    if app_state is None:
        raise ContextUnavailable("no application context was given to this run")
    value: Any = None
    if isinstance(app_state, Mapping):
        value = app_state.get(key)
    elif callable(getattr(app_state, "get", None)) and hasattr(app_state, "__contains__"):
        value = app_state.get(key) if key in app_state else None
    else:
        value = getattr(app_state, key, None)
    if callable(value):
        value = value()
    if value is None:
        raise ContextUnavailable(f"the application context has no {key!r}")
    if not isinstance(value, Mapping):
        raise ValueError(f"{key!r} must be a mapping")
    return validate_context(value)


def _jsonable(v: Any) -> Any:
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (decimal.Decimal, uuid.UUID)):
        return str(v)
    if isinstance(v, (_dt.datetime, _dt.date, _dt.time)):
        return v.isoformat()
    if isinstance(v, (bytes, bytearray, memoryview)):
        return "\\x" + bytes(v).hex()
    return str(v)


def _denied(exc: QueryDenied) -> Dict[str, Any]:
    reasons = [
        {"code": r.code, "message": r.message, "hint": r.hint}
        for r in exc.verdict.reasons
    ]
    return {
        "status": "denied",
        "executed": False,
        "reasons": reasons,
        "message": feedback_for_model(exc),
    }


def _error(message: str, *, executed: bool = False) -> Dict[str, Any]:
    return {"status": "error", "executed": executed, "message": message}


_NO_CONTEXT = "No trusted HaltSQL context is configured for this run; the query was not executed."
_UNAVAILABLE = "SQL verification is unavailable; the query was not executed."


def _verify_failure(exc: BaseException) -> Dict[str, Any]:
    if isinstance(exc, QueryDenied):
        return _denied(exc)
    if isinstance(exc, LookupError):  # ContextUnavailable, or a KeyError from a context callable
        return _error(_NO_CONTEXT)
    if isinstance(exc, (HaltSQLUnavailable, HaltSQLRequestError)):
        return _error(_UNAVAILABLE)
    if isinstance(exc, ValueError):
        return _error(f"The query was not executed: {exc}")
    if isinstance(exc, HaltSQLError):
        return _error("The query was not executed.")
    # Anything unexpected while verifying: fail closed without internals.
    return _error(_UNAVAILABLE)


def _check_query(query: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(query, str) or not query.strip():
        return _error("The query was not executed: 'query' must be a non-empty SQL string.")
    if len(query) > _MAX_QUERY_CHARS:
        return _error("The query was not executed: the SQL text is too long.")
    return None


class HaltSQLToolRunner:
    """Verify-then-execute for one model-written SQL statement.

    Args:
        verifier: ``haltsql.HaltSQLClient`` (sidecar), ``haltsql.LocalVerifier``
            (the ``haltsql`` CLI), or any object with ``verify(sql, context)``.
        connect: Zero-argument callable returning a new ``psycopg.Connection``
            (psycopg 3). It is called only after HaltSQL allowed the query,
            and the connection is closed afterwards.
        max_rows: Row cap (``truncated`` tells the model more were available).
        statement_timeout_ms: ``statement_timeout`` for the query.
        settings: Extra transaction-local settings, a mapping or a function of
            the verified context (e.g. for row-level security).

    Every query runs in a ``READ ONLY`` transaction, and only statements whose
    verdict ``statement_kind`` is ``select`` are run.
    """

    def __init__(
        self,
        verifier: Any,
        connect: Callable[[], Any],
        *,
        max_rows: int = 200,
        statement_timeout_ms: int = 5000,
        settings: Optional[SettingsSource] = None,
    ) -> None:
        if verifier is None or not callable(getattr(verifier, "verify", None)):
            raise ValueError("verifier must have a verify(sql, context) method")
        if not callable(connect):
            raise ValueError("connect must be a zero-argument callable returning a psycopg connection")
        if isinstance(max_rows, bool) or not isinstance(max_rows, int) or not 1 <= max_rows <= 100000:
            raise ValueError("max_rows must be an integer in 1..100000")
        if (
            isinstance(statement_timeout_ms, bool)
            or not isinstance(statement_timeout_ms, int)
            or not 1 <= statement_timeout_ms <= 3_600_000
        ):
            raise ValueError("statement_timeout_ms must be an integer in 1..3600000")
        if settings is not None and not (callable(settings) or isinstance(settings, Mapping)):
            raise ValueError("settings must be a mapping or a callable(context) -> mapping")
        self.verifier = verifier
        self.connect = connect
        self.max_rows = max_rows
        self.statement_timeout_ms = statement_timeout_ms
        self.settings = settings

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(verifier={self.verifier!r}, max_rows={self.max_rows}, "
            f"statement_timeout_ms={self.statement_timeout_ms})"
        )

    def _settings_for(self, ctx: Mapping[str, Any]) -> Optional[Dict[str, str]]:
        if self.settings is None:
            return None
        s = self.settings(ctx) if callable(self.settings) else self.settings
        return dict(s)

    def run(self, query: Any, context: Union[Mapping[str, Any], Callable[[], Mapping[str, Any]], None]) -> Dict[str, Any]:
        """Verify ``query`` with ``context`` and run it if allowed.

        ``context`` is the trusted HaltSQL context (or a callable returning
        it, or ``None`` when none is configured, which refuses). Returns a
        result dict and never raises.
        """
        bad = _check_query(query)
        if bad is not None:
            return bad
        try:
            if context is None:
                raise ContextUnavailable("no context")
            ctx = validate_context(context() if callable(context) else context)
            verdict = guard.authorize(query, ctx, verifier=self.verifier)
            if verdict.statement_kind != "select":
                return _error("The query was not executed: this tool only runs read-only SELECT statements.")
            settings = self._settings_for(ctx)
        except Exception as e:  # noqa: BLE001 - every failure becomes a structured result
            return _verify_failure(e)
        try:
            conn = self.connect()
        except Exception:  # noqa: BLE001
            return _error("The database is unavailable; the query was not executed.")
        try:
            r = guard.execute(
                conn,
                query,
                ctx,
                verdict=verdict,
                read_only=True,
                statement_timeout_ms=self.statement_timeout_ms,
                settings=settings,
                max_rows=self.max_rows,
            )
        except GuardError as e:
            return _error(f"The query was not executed: {e}")
        except Exception as e:  # noqa: BLE001 - database errors go back to the model
            return _error(feedback_for_model(e), executed=True)
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
        rows: List[Any] = [_jsonable(list(x) if isinstance(x, tuple) else x) for x in r.rows]
        return {
            "status": "ok",
            "executed": True,
            "columns": list(r.columns),
            "rows": rows,
            "row_count": len(rows),
            "truncated": r.truncated,
        }

    async def arun(
        self, query: Any, context: Union[Mapping[str, Any], Callable[[], Mapping[str, Any]], None]
    ) -> Dict[str, Any]:
        """:meth:`run` in a worker thread, so async frameworks are not blocked."""
        return await asyncio.to_thread(self.run, query, context)


def check_only(verifier: Any, query: Any, context: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    """Verify SQL that another tool will run; ``None`` means it may proceed.

    Returns a structured refusal (same shape as :meth:`HaltSQLToolRunner.run`)
    when the query is denied, HaltSQL is unavailable, no context is
    configured, the statement is not a ``SELECT``, or the verdict needs bound
    parameters (``$n`` values the other tool cannot pass).
    """
    bad = _check_query(query)
    if bad is not None:
        return bad
    try:
        if context is None:
            raise ContextUnavailable("no context")
        ctx = validate_context(context)
        verdict = guard.authorize(query, ctx, verifier=verifier)
    except Exception as e:  # noqa: BLE001
        return _verify_failure(e)
    if verdict.statement_kind != "select":
        return _error("The query was not executed: only read-only SELECT statements are allowed.")
    if verdict.bind_params:
        return _error(
            f"The query was not executed: HaltSQL allows it only with bound parameters, which this "
            f"tool cannot pass. Use the {TOOL_NAME} tool instead."
        )
    return None


def result_to_text(result: Mapping[str, Any]) -> str:
    """The result as compact JSON text for the model."""
    return json.dumps(result, ensure_ascii=False, separators=(",", ":"), default=str)
