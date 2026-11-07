"""Guarded execution: verify, then run exactly the verified string.

:func:`execute` (psycopg 3 sync), :func:`execute_async` (asyncpg and psycopg 3
async), and :func:`execute_on_engine` (a SQLAlchemy engine backed by psycopg 3)
all follow the same steps:

1. Verify ``sql`` with ``context`` (from the caller's authenticated session).
2. Refuse unless the verdict is allowed and its ``sql_sha256`` matches ``sql``
   (:class:`~haltsql.QueryDenied` / :class:`~haltsql.HaltSQLUnavailable`).
3. Open a transaction (``READ ONLY`` for ``SELECT`` by default), optionally set
   ``statement_timeout`` and session settings with ``set_config(..., true)``.
4. Send the **same** ``str`` object to the driver with ``verdict.bind_args()``
   as positional ``$n`` parameters: psycopg's ``RawCursor`` and asyncpg both
   transmit the SQL text unchanged.

Nothing here formats values into SQL.
"""

from __future__ import annotations

import inspect
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Awaitable, Dict, List, Mapping, Optional, Protocol, Sequence, Union

from .errors import GuardError, HaltSQLUnavailable
from .models import Context, Verdict

__all__ = [
    "Verifier",
    "AsyncVerifier",
    "GuardedResult",
    "Guard",
    "execute",
    "execute_async",
    "execute_on_engine",
    "authorize",
    "authorize_async",
]

_SETTING_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")


class Verifier(Protocol):
    """Anything with ``verify(sql, context) -> Verdict`` (sync)."""

    def verify(self, sql: str, context: Optional[Context] = None) -> Verdict: ...


class AsyncVerifier(Protocol):
    """Anything with ``async verify(sql, context) -> Verdict``."""

    def verify(self, sql: str, context: Optional[Context] = None) -> Awaitable[Verdict]: ...


@dataclass
class GuardedResult:
    """What a guarded execution returns."""

    rows: List[Any]
    """Result rows (tuples by default; psycopg honours the connection's row factory)."""
    columns: List[str]
    """Column names, in order (empty for statements without a result set)."""
    rowcount: int
    """Rows returned, or rows affected for writes (-1 if unknown)."""
    truncated: bool
    """True if ``max_rows`` cut the result short."""
    verdict: Verdict = field(repr=False)
    """The verdict that authorized the execution."""


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

_default_lock = threading.Lock()
_default_sync: Any = None
_default_async: Any = None


def _default_verifier(async_: bool) -> Any:
    """Lazily build a client from ``HALTSQL_*`` environment variables."""
    global _default_sync, _default_async
    with _default_lock:
        if async_:
            if _default_async is None:
                from .client import AsyncHaltSQLClient

                _default_async = AsyncHaltSQLClient.from_env()
            return _default_async
        if _default_sync is None:
            from .client import HaltSQLClient

            _default_sync = HaltSQLClient.from_env()
        return _default_sync


def _authorize(verdict: Any, sql: str) -> Verdict:
    if not isinstance(verdict, Verdict):
        raise HaltSQLUnavailable("verifier did not return a Verdict")
    if not verdict.matches_sql(sql):
        raise HaltSQLUnavailable("verdict is for a different SQL string (sql_sha256 mismatch)")
    return verdict.raise_for_denied()


def _verify_sync(verifier: Optional[Verifier], sql: str, context: Optional[Context]) -> Verdict:
    if not isinstance(sql, str):
        raise TypeError("sql must be a str")
    v = verifier if verifier is not None else _default_verifier(False)
    result = v.verify(sql, context)
    if inspect.isawaitable(result):
        close = getattr(result, "close", None)
        if close is not None:
            close()
        raise GuardError("an async verifier was passed to a sync execute(); use execute_async()")
    return _authorize(result, sql)


async def _verify_async(
    verifier: Union[Verifier, AsyncVerifier, None], sql: str, context: Optional[Context]
) -> Verdict:
    if not isinstance(sql, str):
        raise TypeError("sql must be a str")
    v = verifier if verifier is not None else _default_verifier(True)
    result = v.verify(sql, context)
    if inspect.isawaitable(result):
        result = await result
    return _authorize(result, sql)


def authorize(sql: str, context: Optional[Context], *, verifier: Optional[Verifier] = None) -> Verdict:
    """Verify ``sql`` and return the verdict only if it allows exactly this string.

    Raises :class:`~haltsql.QueryDenied`, :class:`~haltsql.HaltSQLUnavailable`,
    or :class:`~haltsql.HaltSQLRequestError` otherwise. Use it to verify before
    acquiring a database connection, then pass ``verdict=`` to :func:`execute`.
    """
    return _verify_sync(verifier, sql, context)


async def authorize_async(
    sql: str, context: Optional[Context], *, verifier: Union[Verifier, AsyncVerifier, None] = None
) -> Verdict:
    """Async variant of :func:`authorize` (sync or async verifier)."""
    return await _verify_async(verifier, sql, context)


def _settings_list(
    statement_timeout_ms: Optional[int], settings: Optional[Mapping[str, str]]
) -> List["tuple[str, str]"]:
    out: List["tuple[str, str]"] = []
    if statement_timeout_ms is not None:
        if isinstance(statement_timeout_ms, bool) or not isinstance(statement_timeout_ms, int) or statement_timeout_ms <= 0:
            raise ValueError("statement_timeout_ms must be a positive integer")
        out.append(("statement_timeout", str(statement_timeout_ms)))
    for k, val in (settings or {}).items():
        if not isinstance(k, str) or not _SETTING_RE.match(k):
            raise ValueError(f"invalid setting name: {k!r}")
        if not isinstance(val, str):
            raise ValueError(f"setting {k!r} must be a string")
        out.append((k, val))
    return out


def _check_max_rows(max_rows: Optional[int]) -> None:
    if max_rows is not None and (isinstance(max_rows, bool) or not isinstance(max_rows, int) or max_rows < 0):
        raise ValueError("max_rows must be a non-negative integer")


def _read_only(read_only: Optional[bool], verdict: Verdict) -> bool:
    if read_only is None:
        return verdict.statement_kind == "select"
    return bool(read_only)


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------


def _driver(conn: Any) -> str:
    mod = type(conn).__module__ or ""
    if mod.startswith("asyncpg"):
        return "asyncpg"
    if mod.startswith("psycopg2"):
        return "psycopg2"
    if mod.startswith("psycopg"):
        try:
            import psycopg

            if isinstance(conn, psycopg.AsyncConnection):
                return "psycopg-async"
            if isinstance(conn, psycopg.Connection):
                return "psycopg"
        except ImportError:  # pragma: no cover
            pass
    # Duck-typed fakes may declare their kind explicitly.
    kind = getattr(conn, "__haltsql_driver__", None)
    if isinstance(kind, str):
        return kind
    return "unknown"


def _fetch_psycopg(cur: Any, max_rows: Optional[int]) -> "tuple[List[Any], List[str], bool]":
    if cur.description is None:
        return [], [], False
    columns = [d.name for d in cur.description]
    if max_rows is None:
        return list(cur.fetchall()), columns, False
    rows = list(cur.fetchmany(max_rows + 1))
    return rows[:max_rows], columns, len(rows) > max_rows


def _run_psycopg(
    conn: Any,
    sql: str,
    params: Sequence[Any],
    read_only: bool,
    settings: List["tuple[str, str]"],
    max_rows: Optional[int],
) -> "tuple[List[Any], List[str], int, bool]":
    import psycopg

    idle = conn.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
    if (read_only or settings) and not idle:
        raise GuardError(
            "connection is already in a transaction; guarded execution with read_only, "
            "statement_timeout, or settings needs an idle connection"
        )
    with conn.transaction():
        with psycopg.RawCursor(conn) as cur:
            if read_only:
                cur.execute("SET TRANSACTION READ ONLY")
            for name, value in settings:
                cur.execute("SELECT set_config($1, $2, true)", [name, value])
            cur.execute(sql, list(params))
            rows, cols, truncated = _fetch_psycopg(cur, max_rows)
            rowcount = len(rows) if cols else cur.rowcount
    return rows, cols, rowcount, truncated


async def _run_psycopg_async(
    conn: Any,
    sql: str,
    params: Sequence[Any],
    read_only: bool,
    settings: List["tuple[str, str]"],
    max_rows: Optional[int],
) -> "tuple[List[Any], List[str], int, bool]":
    import psycopg

    idle = conn.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
    if (read_only or settings) and not idle:
        raise GuardError(
            "connection is already in a transaction; guarded execution with read_only, "
            "statement_timeout, or settings needs an idle connection"
        )
    async with conn.transaction():
        async with psycopg.AsyncRawCursor(conn) as cur:
            if read_only:
                await cur.execute("SET TRANSACTION READ ONLY")
            for name, value in settings:
                await cur.execute("SELECT set_config($1, $2, true)", [name, value])
            await cur.execute(sql, list(params))
            if cur.description is None:
                return [], [], cur.rowcount, False
            cols = [d.name for d in cur.description]
            if max_rows is None:
                rows = list(await cur.fetchall())
                return rows, cols, len(rows), False
            fetched = list(await cur.fetchmany(max_rows + 1))
            rows = fetched[:max_rows]
            return rows, cols, len(rows), len(fetched) > max_rows


async def _run_asyncpg(
    conn: Any,
    sql: str,
    params: Sequence[Any],
    read_only: bool,
    settings: List["tuple[str, str]"],
    max_rows: Optional[int],
    statement_kind: Optional[str],
) -> "tuple[List[Any], List[str], int, bool]":
    if (read_only or settings) and conn.is_in_transaction():
        raise GuardError(
            "connection is already in a transaction; guarded execution with read_only, "
            "statement_timeout, or settings needs an idle connection"
        )
    async with conn.transaction(readonly=read_only):
        for name, value in settings:
            await conn.execute("SELECT set_config($1, $2, true)", name, value)
        stmt = await conn.prepare(sql)
        cols = [a.name for a in stmt.get_attributes()]
        if not cols:
            await stmt.fetch(*params)
            status = stmt.get_statusmsg() or ""
            tail = status.rsplit(" ", 1)[-1]
            return [], [], int(tail) if tail.isdigit() else -1, False
        if max_rows is not None and statement_kind == "select":
            cur = await stmt.cursor(*params)
            fetched = await cur.fetch(max_rows + 1)
        else:
            fetched = await stmt.fetch(*params)
        rows = [tuple(r) for r in fetched]
        truncated = max_rows is not None and len(rows) > max_rows
        if max_rows is not None:
            rows = rows[:max_rows]
        return rows, cols, len(rows), truncated


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def execute(
    conn: Any,
    sql: str,
    context: Optional[Context],
    *,
    verifier: Optional[Verifier] = None,
    read_only: Optional[bool] = None,
    statement_timeout_ms: Optional[int] = None,
    settings: Optional[Mapping[str, str]] = None,
    max_rows: Optional[int] = None,
    verdict: Optional[Verdict] = None,
) -> GuardedResult:
    """Verify ``sql`` and run it on a psycopg 3 ``Connection``.

    Args:
        conn: An idle ``psycopg.Connection`` (any autocommit setting).
        sql: The SQL produced by the model. Run byte-for-byte as verified.
        context: Context from the caller's authenticated session (never from
            the model), e.g. ``{"tenant_id": session.tenant_id}``.
        verifier: :class:`~haltsql.HaltSQLClient`, :class:`~haltsql.LocalVerifier`
            or any object with ``verify``; defaults to a client built from
            ``HALTSQL_*`` environment variables.
        read_only: Run in a ``READ ONLY`` transaction. Default: only when the
            verdict's ``statement_kind`` is ``select``.
        statement_timeout_ms: ``SET LOCAL statement_timeout`` for this query.
        settings: Extra transaction-local settings (``set_config(k, v, true)``),
            e.g. ``{"app.tenant_id": tenant}`` for row-level security.
        max_rows: Return at most this many rows (``truncated`` tells you if
            more were available).
        verdict: A verdict already obtained with :func:`authorize` for this
            exact ``sql`` (re-checked: allowed and matching ``sql_sha256``);
            ``verifier`` is not called then.

    Raises:
        QueryDenied: the policy denied the query (nothing was executed).
        HaltSQLUnavailable / HaltSQLRequestError: no verdict (nothing executed).
        GuardError: unsupported connection or connection state.
    """
    _check_max_rows(max_rows)
    setts = _settings_list(statement_timeout_ms, settings)
    kind = _driver(conn)
    if kind == "psycopg2":
        raise GuardError("psycopg2 cannot send $n placeholders unchanged; use psycopg 3")
    if kind in ("asyncpg", "psycopg-async"):
        raise GuardError("async connection passed to execute(); use execute_async()")
    if kind != "psycopg":
        raise GuardError(f"unsupported connection type: {type(conn).__name__}")
    verdict = _authorize(verdict, sql) if verdict is not None else _verify_sync(verifier, sql, context)
    params = verdict.bind_args()
    rows, cols, rowcount, truncated = _run_psycopg(
        conn, sql, params, _read_only(read_only, verdict), setts, max_rows
    )
    return GuardedResult(rows=rows, columns=cols, rowcount=rowcount, truncated=truncated, verdict=verdict)


async def execute_async(
    conn: Any,
    sql: str,
    context: Optional[Context],
    *,
    verifier: Union[Verifier, AsyncVerifier, None] = None,
    read_only: Optional[bool] = None,
    statement_timeout_ms: Optional[int] = None,
    settings: Optional[Mapping[str, str]] = None,
    max_rows: Optional[int] = None,
    verdict: Optional[Verdict] = None,
) -> GuardedResult:
    """Async variant of :func:`execute` for asyncpg and ``psycopg.AsyncConnection``.

    ``verifier`` may be sync or async (e.g. :class:`~haltsql.AsyncHaltSQLClient`).
    """
    _check_max_rows(max_rows)
    setts = _settings_list(statement_timeout_ms, settings)
    kind = _driver(conn)
    if kind not in ("asyncpg", "psycopg-async"):
        raise GuardError(f"unsupported async connection type: {type(conn).__name__}")
    verdict = (
        _authorize(verdict, sql) if verdict is not None else await _verify_async(verifier, sql, context)
    )
    params = verdict.bind_args()
    ro = _read_only(read_only, verdict)
    if kind == "asyncpg":
        rows, cols, rowcount, truncated = await _run_asyncpg(
            conn, sql, params, ro, setts, max_rows, verdict.statement_kind
        )
    else:
        rows, cols, rowcount, truncated = await _run_psycopg_async(
            conn, sql, params, ro, setts, max_rows
        )
    return GuardedResult(rows=rows, columns=cols, rowcount=rowcount, truncated=truncated, verdict=verdict)


def execute_on_engine(
    engine: Any,
    sql: str,
    context: Optional[Context],
    **kwargs: Any,
) -> GuardedResult:
    """Run :func:`execute` on a pooled connection of a SQLAlchemy ``Engine``.

    The engine must use the psycopg 3 dialect (``postgresql+psycopg://``).
    SQLAlchemy's ``text()`` rewrites SQL and would not run the verified string
    unchanged, so the raw driver connection is used instead. ``kwargs`` are
    those of :func:`execute`. Verification happens before a connection is
    taken from the pool.
    """
    if kwargs.get("verdict") is None:
        kwargs["verdict"] = authorize(sql, context, verifier=kwargs.get("verifier"))
    else:
        _authorize(kwargs["verdict"], sql)
    raw = engine.raw_connection()
    try:
        driver_conn = getattr(raw, "driver_connection", None) or getattr(raw, "connection", None)
        if driver_conn is None:
            raise GuardError("could not obtain the driver connection from the engine")
        return execute(driver_conn, sql, context, **kwargs)
    finally:
        raw.close()


class Guard:
    """Binds a verifier and execution defaults; see :func:`execute`.

    Example::

        guard = Guard(HaltSQLClient.from_env(), statement_timeout_ms=5000, max_rows=500)
        result = guard.execute(conn, sql, {"tenant_id": session.tenant_id})
    """

    def __init__(
        self,
        verifier: Union[Verifier, AsyncVerifier, None] = None,
        *,
        read_only: Optional[bool] = None,
        statement_timeout_ms: Optional[int] = None,
        settings: Optional[Mapping[str, str]] = None,
        max_rows: Optional[int] = None,
    ) -> None:
        _check_max_rows(max_rows)
        _settings_list(statement_timeout_ms, settings)
        self.verifier = verifier
        self._defaults: Dict[str, Any] = {
            "read_only": read_only,
            "statement_timeout_ms": statement_timeout_ms,
            "settings": dict(settings) if settings else None,
            "max_rows": max_rows,
        }

    def _kw(self, overrides: Mapping[str, Any]) -> Dict[str, Any]:
        kw = dict(self._defaults)
        kw.update(overrides)
        kw["verifier"] = self.verifier
        return kw

    def execute(self, conn: Any, sql: str, context: Optional[Context], **overrides: Any) -> GuardedResult:
        return execute(conn, sql, context, **self._kw(overrides))

    async def execute_async(
        self, conn: Any, sql: str, context: Optional[Context], **overrides: Any
    ) -> GuardedResult:
        return await execute_async(conn, sql, context, **self._kw(overrides))

    def execute_on_engine(
        self, engine: Any, sql: str, context: Optional[Context], **overrides: Any
    ) -> GuardedResult:
        return execute_on_engine(engine, sql, context, **self._kw(overrides))
