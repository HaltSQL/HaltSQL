"""HaltSQL guards for LangChain SQL agents.

Two entry points:

* :class:`HaltSQLQueryTool`: a LangChain tool (``langchain-core``) whose only
  argument is the SQL; it verifies with HaltSQL and runs exactly the verified
  string with the bound parameters.
* :func:`guard_sql_database`: wraps an existing ``SQLDatabase``
  (``langchain-community``) so that ``run`` / ``run_no_throw`` (used by
  ``QuerySQLDatabaseTool``, ``create_sql_agent``, ...) are guarded. The wrapper
  is still an ``SQLDatabase`` instance, so it drops into existing toolkits.
  It never reads table rows outside HaltSQL: ``get_table_info`` shows no
  sample rows, and the internal ``_execute`` refuses.

The tenant context is a mapping or a zero-argument callable you control
(read from the authenticated request), never a tool argument. A callable that
returns ``None`` refuses the query.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Callable, Dict, Mapping, Optional, Type

from haltsql import GuardError, GuardedResult, guard
from haltsql.integration import ContextSource, authorize_guarded, feedback_for_model, guard_read_only

__all__ = ["HaltSQLQueryRunner", "HaltSQLQueryTool", "guard_sql_database", "__version__"]
__version__ = "0.0.3"

DEFAULT_DESCRIPTION = (
    "Run one read-only PostgreSQL query. Input: a single SQL statement with a LIMIT. "
    "The tenant is fixed by the application: filter tenant-scoped tables with "
    "alias.tenant_id = $1 and never write tenant IDs yourself. If the query is denied, "
    "the reply lists reason codes and hints; fix the SQL and try again."
)


class HaltSQLQueryRunner:
    """Framework-free core: verify and run SQL, returning text for the model.

    Args:
        verifier: ``HaltSQLClient``, ``LocalVerifier``, or any ``verify(sql, ctx)``.
        context: The caller's context (mapping or callable), from the session.
        engine: A SQLAlchemy engine using psycopg 3 (``postgresql+psycopg://``), or
        connect: A zero-argument callable returning a ``psycopg.Connection``
            (closed after each query).
        max_rows / statement_timeout_ms / settings: see :func:`haltsql.guard.execute`.
        read_only: ``True`` (default) runs only statements whose verdict
            ``statement_kind`` is ``select``, in a ``READ ONLY`` transaction.
            ``False`` runs whatever statement kind the policy allowed (writes
            read-write, ``SELECT`` still ``READ ONLY``); the policy is then the
            only thing that decides whether writes are allowed.
    """

    def __init__(
        self,
        verifier: Any,
        context: ContextSource,
        *,
        engine: Any = None,
        connect: Optional[Callable[[], Any]] = None,
        max_rows: int = 200,
        statement_timeout_ms: Optional[int] = 5000,
        settings: Optional[Mapping[str, str]] = None,
        read_only: bool = True,
    ) -> None:
        if (engine is None) == (connect is None):
            raise ValueError("pass exactly one of engine= or connect=")
        self.verifier = verifier
        self.context = context
        self.engine = engine
        self.connect = connect
        self.read_only = bool(read_only)
        self.guard_kwargs: Dict[str, Any] = {
            "max_rows": max_rows,
            "statement_timeout_ms": statement_timeout_ms,
            "settings": dict(settings) if settings else None,
            "read_only": guard_read_only(self.read_only),
        }

    def execute(self, sql: str) -> GuardedResult:
        """Verify and run; raises on denial or failure (nothing runs then)."""
        # Verify (and check the statement kind) before taking a database connection.
        ctx, verdict = authorize_guarded(sql, self.context, verifier=self.verifier,
                                         read_only=self.read_only)
        if self.engine is not None:
            return guard.execute_on_engine(self.engine, sql, ctx, verdict=verdict, **self.guard_kwargs)
        assert self.connect is not None
        conn = self.connect()
        try:
            return guard.execute(conn, sql, ctx, verdict=verdict, **self.guard_kwargs)
        finally:
            conn.close()

    def run(self, sql: str) -> str:
        """Verify and run; returns JSON rows, or feedback text if nothing ran."""
        try:
            r = self.execute(sql)
        except Exception as e:  # noqa: BLE001 - every failure becomes model feedback
            return feedback_for_model(e)
        return json.dumps(
            {"columns": r.columns, "rows": [list(x) if isinstance(x, tuple) else x for x in r.rows],
             "truncated": r.truncated},
            default=str,
        )


def _guarded_db_class(base: Type[Any]) -> Type[Any]:
    class GuardedSQLDatabase(base):  # type: ignore[misc, valid-type]
        """An ``SQLDatabase`` whose ``run`` goes through HaltSQL.

        Every path of ``SQLDatabase`` that reads rows or runs SQL on the engine
        is guarded or refused: ``run`` / ``run_no_throw`` verify, sample rows
        are never read for ``get_table_info``, and ``_execute`` refuses.
        Schema reflection (table and column names) still uses the engine.
        """

        _haltsql_runner: HaltSQLQueryRunner

        def _get_sample_rows(self, table: Any) -> str:
            # SQLDatabase reads sample rows straight from the engine; never here.
            return ""

        def _execute(self, *args: Any, **kwargs: Any) -> Any:
            raise GuardError("unverified SQL is not run; use run(), which verifies with HaltSQL")

        def run(self, command: Any, fetch: str = "all", include_columns: bool = False,
                *, parameters: Optional[Dict[str, Any]] = None,
                execution_options: Optional[Dict[str, Any]] = None) -> Any:
            if not isinstance(command, str):
                raise GuardError("only SQL strings can be guarded")
            if parameters:
                raise GuardError("caller-supplied parameters are not allowed; HaltSQL binds them")
            if fetch not in ("all", "one"):
                raise GuardError("fetch='cursor' is not supported by the HaltSQL guard")
            r = self._haltsql_runner.execute(command)
            if not r.columns:
                return ""
            rows = [tuple(x) for x in r.rows]
            if fetch == "one":
                rows = rows[:1]
            if include_columns:
                return str([dict(zip(r.columns, x)) for x in rows])
            return str(rows) if rows else ""

        def run_no_throw(self, command: str, fetch: str = "all", include_columns: bool = False,
                         *, parameters: Optional[Dict[str, Any]] = None,
                         execution_options: Optional[Dict[str, Any]] = None) -> Any:
            try:
                return self.run(command, fetch, include_columns, parameters=parameters)
            except Exception as e:  # noqa: BLE001
                return f"Error: {feedback_for_model(e)}"

    GuardedSQLDatabase.__name__ = f"Guarded{base.__name__}"
    return GuardedSQLDatabase


def guard_sql_database(
    db: Any,
    verifier: Any,
    context: ContextSource,
    **runner_kwargs: Any,
) -> Any:
    """Return a copy of ``db`` (a LangChain ``SQLDatabase``) whose ``run`` and
    ``run_no_throw`` verify every statement with HaltSQL first.

    The copy shares ``db``'s engine; it must use psycopg 3. ``runner_kwargs``
    are those of :class:`HaltSQLQueryRunner` (``max_rows``, ``read_only``, ...).
    The copy never reads sample rows (``sample_rows_in_table_info`` is 0), so
    ``get_table_info`` shows the schema only.
    """
    engine = getattr(db, "_engine", None) or getattr(db, "engine", None)
    if engine is None:
        raise GuardError("could not find the SQLAlchemy engine of this SQLDatabase")
    guarded = copy.copy(db)
    guarded.__class__ = _guarded_db_class(type(db))
    guarded._haltsql_runner = HaltSQLQueryRunner(verifier, context, engine=engine, **runner_kwargs)
    # Sample rows would be read from the engine, unverified and across tenants.
    guarded._sample_rows_in_table_info = 0
    return guarded


try:
    from langchain_core.tools import BaseTool
    from pydantic import BaseModel, ConfigDict, Field

    class _QueryInput(BaseModel):
        query: str = Field(description="One PostgreSQL statement to run (SELECT with a LIMIT).")

    class HaltSQLQueryTool(BaseTool):  # type: ignore[misc]
        """LangChain tool: verify with HaltSQL, then run the exact SQL."""

        model_config = ConfigDict(arbitrary_types_allowed=True)

        name: str = "haltsql_query"
        description: str = DEFAULT_DESCRIPTION
        args_schema: Type[BaseModel] = _QueryInput
        runner: HaltSQLQueryRunner

        def _run(self, query: str, run_manager: Any = None) -> str:
            return self.runner.run(query)

except ImportError:  # langchain-core not installed

    class HaltSQLQueryTool:  # type: ignore[no-redef]
        """Placeholder: install ``haltsql-langchain[langchain]``."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ImportError("HaltSQLQueryTool needs langchain-core: pip install 'haltsql-langchain[langchain]'")

