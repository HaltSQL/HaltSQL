"""HaltSQL guards for LlamaIndex text-to-SQL.

LlamaIndex's ``SQLRetriever``, ``NLSQLRetriever``, ``NLSQLTableQueryEngine``
and friends all execute through ``SQLDatabase.run_sql``. :func:`guard_sql_database`
returns a copy of your ``SQLDatabase`` whose ``run_sql`` verifies every
statement with HaltSQL and then runs exactly the verified string with the bound
parameters. Pass the guarded copy wherever you passed the original.

:func:`guarded_sql_retriever` and :func:`guarded_nl_sql_query_engine` are
shortcuts that build the usual LlamaIndex objects on top of it.

The guarded copy never runs SQL on the engine outside HaltSQL: ``run_sql`` is
verified, and ``insert_into_table`` (used by ``SQLStructStoreIndex``) refuses.
Table descriptions (``get_single_table_info``) read the schema only.

The tenant context is a mapping or zero-argument callable from your
authenticated session, never something the model produces. A callable that
returns ``None`` refuses the query.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, Mapping, Optional, Tuple, Type

from haltsql import GuardError, guard
from haltsql.integration import ContextSource, authorize_guarded, feedback_for_model, guard_read_only

__all__ = [
    "HaltSQLSQLError",
    "guard_sql_database",
    "guarded_sql_retriever",
    "guarded_nl_sql_query_engine",
    "__version__",
]
__version__ = "0.0.3"


class HaltSQLSQLError(NotImplementedError):
    """Raised instead of the HaltSQL exception when ``denials_as_sql_errors``.

    LlamaIndex's NL-to-SQL components catch ``NotImplementedError`` from
    ``run_sql`` (with ``handle_sql_errors=True``) and show the message to the
    LLM, which can then fix its query. ``__cause__`` is the original error.
    """


def _guarded_class(base: Type[Any]) -> Type[Any]:
    class GuardedSQLDatabase(base):  # type: ignore[misc, valid-type]
        _haltsql: Dict[str, Any]

        def run_sql(self, command: str) -> Tuple[str, Dict[str, Any]]:
            cfg = self._haltsql
            if not isinstance(command, str):
                raise GuardError("only SQL strings can be guarded")
            try:
                ctx, verdict = authorize_guarded(command, cfg["context"], verifier=cfg["verifier"],
                                                 read_only=cfg["read_only"])
                result = guard.execute_on_engine(
                    cfg["engine"], command, ctx, verdict=verdict, **cfg["guard_kwargs"]
                )
            except Exception as e:  # noqa: BLE001
                if cfg["denials_as_sql_errors"]:
                    raise HaltSQLSQLError(feedback_for_model(e)) from e
                raise
            if not result.columns:
                return "", {}
            truncate = getattr(self, "truncate_word", None)
            max_len = getattr(self, "_max_string_length", 300)
            rows = [
                tuple(truncate(col, length=max_len) if truncate else col for col in row)
                for row in result.rows
            ]
            return str(rows), {"result": rows, "col_keys": list(result.columns),
                               "truncated": result.truncated}

        def insert_into_table(self, table_name: str, data: dict) -> None:
            # SQLDatabase inserts straight through the engine; never unverified.
            raise GuardError("insert_into_table is not available on a HaltSQL-guarded SQLDatabase")

    GuardedSQLDatabase.__name__ = f"Guarded{base.__name__}"
    return GuardedSQLDatabase


def guard_sql_database(
    db: Any,
    verifier: Any,
    context: ContextSource,
    *,
    max_rows: Optional[int] = 200,
    statement_timeout_ms: Optional[int] = 5000,
    settings: Optional[Mapping[str, str]] = None,
    read_only: bool = True,
    denials_as_sql_errors: bool = False,
) -> Any:
    """Copy ``db`` (a LlamaIndex ``SQLDatabase``) with a guarded ``run_sql``.

    The engine must use psycopg 3 (``postgresql+psycopg://``). With
    ``denials_as_sql_errors=True``, refusals raise :class:`HaltSQLSQLError`
    carrying the reason codes and hints (see its docstring).

    ``read_only=True`` (default) runs only statements whose verdict
    ``statement_kind`` is ``select``, in a ``READ ONLY`` transaction.
    ``read_only=False`` runs whatever statement kind the policy allowed (writes
    read-write, ``SELECT`` still ``READ ONLY``).

    Note: a ``schema=`` given to ``SQLDatabase`` is not prefixed onto the SQL
    (that would change the verified string); set the Postgres ``search_path``
    and the policy's ``search_path`` instead.
    """
    engine = getattr(db, "_engine", None) or getattr(db, "engine", None)
    if engine is None:
        raise GuardError("could not find the SQLAlchemy engine of this SQLDatabase")
    guarded = copy.copy(db)
    guarded.__class__ = _guarded_class(type(db))
    guarded._haltsql = {
        "verifier": verifier,
        "context": context,
        "engine": engine,
        "denials_as_sql_errors": denials_as_sql_errors,
        "read_only": bool(read_only),
        "guard_kwargs": {
            "max_rows": max_rows,
            "statement_timeout_ms": statement_timeout_ms,
            "settings": dict(settings) if settings else None,
            "read_only": guard_read_only(bool(read_only)),
        },
    }
    return guarded


def guarded_sql_retriever(db: Any, verifier: Any, context: ContextSource, **kwargs: Any) -> Any:
    """``SQLRetriever`` over a guarded copy of ``db`` (needs ``llama-index-core``).

    ``kwargs`` go to :func:`guard_sql_database`.
    """
    from llama_index.core.retrievers import SQLRetriever

    return SQLRetriever(guard_sql_database(db, verifier, context, **kwargs))


#: Keyword arguments of :func:`guard_sql_database` (the guard options).
GUARD_OPTIONS = frozenset(
    {"max_rows", "statement_timeout_ms", "settings", "read_only", "denials_as_sql_errors"}
)


def guarded_nl_sql_query_engine(
    db: Any,
    verifier: Any,
    context: ContextSource,
    *,
    guard_kwargs: Optional[Mapping[str, Any]] = None,
    **engine_kwargs: Any,
) -> Any:
    """``NLSQLTableQueryEngine`` over a guarded copy of ``db``.

    Denials are fed back to the LLM as SQL errors so it can retry; nothing
    unverified ever runs. Guard options (``max_rows``, ``statement_timeout_ms``,
    ``settings``, ``read_only``, ``denials_as_sql_errors``) may be given as
    keyword arguments or in ``guard_kwargs`` (not both for the same option).
    The other ``engine_kwargs`` (``tables``, ``llm``, ...) go to
    ``NLSQLTableQueryEngine``.
    """
    from llama_index.core.query_engine import NLSQLTableQueryEngine

    gk = dict(guard_kwargs or {})
    unknown = set(gk) - GUARD_OPTIONS
    if unknown:
        raise TypeError(f"unknown guard option(s): {', '.join(sorted(unknown))}")
    for name in GUARD_OPTIONS & set(engine_kwargs):
        if name in gk:
            raise TypeError(f"guard option {name!r} given both as a keyword and in guard_kwargs")
        gk[name] = engine_kwargs.pop(name)
    gk.setdefault("denials_as_sql_errors", True)
    return NLSQLTableQueryEngine(sql_database=guard_sql_database(db, verifier, context, **gk), **engine_kwargs)
