"""HaltSQL guard for Vanna.

* Vanna 2.x: :class:`HaltSQLSqlRunner` implements Vanna's ``SqlRunner``
  capability. Give it to ``RunSqlTool(sql_runner=...)``. The tenant context is
  derived from the authenticated ``ToolContext.user`` (by default
  ``user.metadata["haltsql_context"]``), never from the LLM's arguments.
* Vanna 0.x (legacy ``VannaBase``): :func:`install_legacy_run_sql` replaces
  ``vn.run_sql`` with a guarded version.

Both verify first, then run exactly the verified string with the bound
parameters in a read-only transaction, and return a pandas ``DataFrame``.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, Mapping, Optional

from haltsql import GuardedResult, guard
from haltsql.integration import ContextSource, ContextUnavailable, resolve_context

__all__ = [
    "HaltSQLSqlRunner",
    "install_legacy_run_sql",
    "context_from_user_metadata",
    "to_dataframe",
    "__version__",
]
__version__ = "0.0.1"

try:  # Vanna 2.x
    from vanna.capabilities.sql_runner import SqlRunner as _SqlRunnerBase
except Exception:  # noqa: BLE001 - vanna not installed or different version
    _SqlRunnerBase = object  # type: ignore[assignment, misc]


def to_dataframe(result: GuardedResult) -> Any:
    """Turn a guarded result into a pandas ``DataFrame``."""
    import pandas as pd  # type: ignore[import-untyped, unused-ignore]

    return pd.DataFrame([list(r) if isinstance(r, tuple) else r for r in result.rows],
                        columns=result.columns or None)


def context_from_user_metadata(user: Any) -> Mapping[str, Any]:
    """Default Vanna 2.x context resolver: ``user.metadata["haltsql_context"]``.

    Set it in your ``UserResolver`` from the authenticated request. Raises
    :class:`PermissionError` when absent, so nothing runs.
    """
    meta = getattr(user, "metadata", None) or {}
    ctx = meta.get("haltsql_context") if isinstance(meta, Mapping) else None
    if not isinstance(ctx, Mapping):
        raise PermissionError("no HaltSQL context for this user")
    return ctx


class HaltSQLSqlRunner(_SqlRunnerBase):  # type: ignore[misc, valid-type]
    """Vanna 2.x ``SqlRunner`` that verifies with HaltSQL before executing.

    Args:
        verifier: ``AsyncHaltSQLClient`` (recommended), ``HaltSQLClient``,
            ``AsyncLocalVerifier``, ...
        dsn: libpq connection string for psycopg 3, or
        connect: ``async () -> connection`` (psycopg ``AsyncConnection`` or asyncpg).
        context_from_user: ``(user) -> context``; defaults to
            :func:`context_from_user_metadata`.
        max_rows / statement_timeout_ms / settings: see :func:`haltsql.guard.execute`.
    """

    def __init__(
        self,
        verifier: Any,
        *,
        dsn: Optional[str] = None,
        connect: Optional[Callable[[], Awaitable[Any]]] = None,
        context_from_user: Callable[[Any], Mapping[str, Any]] = context_from_user_metadata,
        max_rows: Optional[int] = 1000,
        statement_timeout_ms: Optional[int] = 5000,
        settings: Optional[Mapping[str, str]] = None,
    ) -> None:
        if (dsn is None) == (connect is None):
            raise ValueError("pass exactly one of dsn= or connect=")
        self.verifier = verifier
        self._dsn = dsn
        self._connect = connect
        self.context_from_user = context_from_user
        self.guard_kwargs: Dict[str, Any] = {
            "max_rows": max_rows,
            "statement_timeout_ms": statement_timeout_ms,
            "settings": dict(settings) if settings else None,
            "read_only": True,
        }

    async def _open(self) -> Any:
        if self._connect is not None:
            return await self._connect()
        import psycopg

        assert self._dsn is not None
        return await psycopg.AsyncConnection.connect(self._dsn, autocommit=True)

    async def run_sql(self, args: Any, context: Any) -> Any:
        """Vanna's ``SqlRunner.run_sql(args, context) -> DataFrame``.

        Raises :class:`haltsql.QueryDenied` (whose message lists the reason
        codes and hints) when the policy denies the SQL.
        """
        sql = getattr(args, "sql", None)
        if not isinstance(sql, str):
            raise ValueError("RunSqlToolArgs.sql must be a string")
        user_ctx = self.context_from_user(getattr(context, "user", None))
        if user_ctx is None:
            raise ContextUnavailable("context_from_user returned None")
        ctx = resolve_context(user_ctx)
        verdict = await guard.authorize_async(sql, ctx, verifier=self.verifier)
        conn = await self._open()
        try:
            result = await guard.execute_async(conn, sql, ctx, verdict=verdict, **self.guard_kwargs)
        finally:
            closed = conn.close()
            if hasattr(closed, "__await__"):
                await closed
        return to_dataframe(result)


def install_legacy_run_sql(
    vn: Any,
    verifier: Any,
    context: ContextSource,
    *,
    dsn: Optional[str] = None,
    connect: Optional[Callable[[], Any]] = None,
    max_rows: Optional[int] = 1000,
    statement_timeout_ms: Optional[int] = 5000,
    settings: Optional[Mapping[str, str]] = None,
) -> None:
    """Replace ``vn.run_sql`` (Vanna 0.x ``VannaBase``) with a guarded version.

    ``vn.run_sql(sql)`` then verifies with HaltSQL, runs the exact SQL on a
    psycopg 3 connection (``dsn`` or ``connect()``), and returns a DataFrame.
    A ``context`` callable that returns ``None`` raises
    :class:`haltsql.integration.ContextUnavailable` and nothing is verified.
    """
    if (dsn is None) == (connect is None):
        raise ValueError("pass exactly one of dsn= or connect=")
    kw: Dict[str, Any] = {"max_rows": max_rows, "statement_timeout_ms": statement_timeout_ms,
          "settings": dict(settings) if settings else None, "read_only": True}

    def run_sql(sql: str, **_ignored: Any) -> Any:
        ctx = resolve_context(context)
        verdict = guard.authorize(sql, ctx, verifier=verifier)
        if connect is not None:
            conn = connect()
        else:
            import psycopg

            assert dsn is not None
            conn = psycopg.connect(dsn, autocommit=True)
        try:
            return to_dataframe(guard.execute(conn, sql, ctx, verdict=verdict, **kw))
        finally:
            conn.close()

    vn.run_sql = run_sql
    vn.run_sql_is_set = True
    vn.dialect = "PostgreSQL"
