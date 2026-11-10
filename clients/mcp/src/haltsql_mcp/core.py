"""Tool logic for haltsql-mcp, independent of the MCP SDK (easy to test).

Invariants:

* The tenant context comes from :attr:`HaltSQLTools.context_provider`
  (server configuration or the authenticated session). No tool takes it as an
  argument, so a prompt-injected model cannot choose a tenant.
* ``query`` executes only through :func:`haltsql.guard.execute_async`: verify,
  then run exactly the verified string with the bound parameters, in a
  ``READ ONLY`` transaction with ``statement_timeout`` and a row cap.
* Any verification failure means nothing runs.
"""

from __future__ import annotations

import base64
import datetime as _dt
import decimal
import ipaddress
import json
import os
import subprocess
import uuid
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional

from haltsql import (
    GuardError,
    HaltSQLRequestError,
    HaltSQLUnavailable,
    QueryDenied,
    Verdict,
    guard,
)

__all__ = ["ToolFailure", "HaltSQLTools", "jsonable", "load_policy_document", "summarize_policy"]

MAX_SQL_CHARS = 100_000
MAX_CELL_CHARS = 10_000


class ToolFailure(Exception):
    """A tool error whose message is safe to show to the model."""


ContextProvider = Callable[[], Mapping[str, Any]]
Connect = Callable[[], Awaitable[Any]]


def jsonable(value: Any) -> Any:
    """Convert a database value into JSON-safe data."""
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, str) and len(value) > MAX_CELL_CHARS:
            return value[:MAX_CELL_CHARS] + "...[truncated]"
        return value
    if isinstance(value, float):
        return value if value == value and value not in (float("inf"), float("-inf")) else str(value)
    if isinstance(value, decimal.Decimal):
        return str(value)
    if isinstance(value, (_dt.datetime, _dt.date, _dt.time)):
        return value.isoformat()
    if isinstance(value, _dt.timedelta):
        return value.total_seconds()
    if isinstance(value, (uuid.UUID, ipaddress.IPv4Address, ipaddress.IPv6Address,
                          ipaddress.IPv4Network, ipaddress.IPv6Network,
                          ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"base64": base64.b64encode(bytes(value)[:MAX_CELL_CHARS]).decode()}
    if isinstance(value, Mapping):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [jsonable(v) for v in value]
    return str(value)


def _reasons(verdict: Verdict) -> List[Dict[str, Any]]:
    return [r.to_dict() for r in verdict.reasons]


def load_policy_document(path: str, haltsql_bin: Optional[str] = None) -> Dict[str, Any]:
    """Read a policy (JSON, or YAML via PyYAML or ``haltsql convert``)."""
    with open(path, "rb") as f:
        raw = f.read()
    if path.endswith(".json"):
        data = json.loads(raw)
    else:
        try:
            import yaml  # type: ignore[import-untyped]

            data = yaml.safe_load(raw)
        except ImportError:
            binary = haltsql_bin or os.environ.get("HALTSQL_BIN") or "haltsql"
            proc = subprocess.run(
                [binary, "convert", path, "--to", "json"],
                capture_output=True, timeout=10, check=False,
            )
            if proc.returncode != 0:
                raise ToolFailure("policy file is YAML; install PyYAML or the haltsql CLI to read it")
            data = json.loads(proc.stdout)
    if not isinstance(data, dict):
        raise ToolFailure("policy file is not a mapping")
    return data


def summarize_policy(doc: Mapping[str, Any]) -> Dict[str, Any]:
    """The parts of a policy an agent needs to write accepted SQL.

    Tenancy key *names* are included, never context values.
    """
    meta = doc.get("metadata") or {}
    tenancy = doc.get("tenancy") or {}
    keys = tenancy.get("keys") or {}
    tables_out: List[Dict[str, Any]] = []
    for name, spec in sorted((doc.get("tables") or {}).items()):
        spec = spec or {}
        entry: Dict[str, Any] = {"table": name, "columns": spec.get("columns", [])}
        if "tenant_column" in spec:
            entry["tenant_columns"] = {spec["tenant_column"]: next(iter(keys), "tenant")}
        elif "tenant_columns" in spec:
            entry["tenant_columns"] = dict(spec["tenant_columns"])
        entry["tenant_scoped"] = "tenant_columns" in entry
        if spec.get("writes"):
            entry["writes"] = spec["writes"]
        tables_out.append(entry)
    out: Dict[str, Any] = {
        "name": meta.get("name"),
        "description": meta.get("description"),
        "search_path": doc.get("search_path", []),
        "statements": (doc.get("statements") or {}).get("allow", ["select"]),
        "require_limit": doc.get("require_limit"),
        "mode": doc.get("mode", "enforce"),
        "tenancy": {"mode": tenancy.get("mode"), "keys": sorted(keys)} if tenancy else None,
        "tables": tables_out,
        "functions": doc.get("functions"),
    }
    return out


def _tenancy_guidance(summary: Optional[Mapping[str, Any]]) -> str:
    base = (
        "Only tables and columns listed here are readable. Every tenant-scoped table, in every "
        "subquery, CTE and UNION branch, needs its own predicate on its tenant column."
    )
    ten = (summary or {}).get("tenancy") or {}
    if ten.get("mode") == "bound":
        return base + (" Write the predicate as alias.tenant_column = $1 (one $n per tenancy key, "
                       "or = ANY($n) for tenant sets); the server binds the values. Never write "
                       "tenant IDs into the SQL.")
    if ten.get("mode") == "literal":
        return base + " Write the predicate with the caller's tenant value as a literal."
    return base


class HaltSQLTools:
    """Implements the four tools. ``verifier`` may be sync or async.

    Args:
        verifier: :class:`haltsql.AsyncHaltSQLClient`, :class:`haltsql.AsyncLocalVerifier`, ...
        context_provider: Returns the caller's context; raises
            :class:`PermissionError` when the session is not authenticated.
        connect: ``async () -> connection`` (psycopg ``AsyncConnection`` or
            asyncpg); ``None`` disables ``query``.
        row_cap / statement_timeout_ms / set_config: execution limits.
        policy_file: Policy document for ``describe_policy`` / ``list_tables``.
        policies_lister: ``async () -> list[PolicyInfo]`` (``/v1/policies``).
    """

    def __init__(
        self,
        verifier: Any,
        context_provider: ContextProvider,
        *,
        connect: Optional[Connect] = None,
        row_cap: int = 200,
        statement_timeout_ms: int = 5000,
        set_config: Optional[Mapping[str, str]] = None,
        policy_file: Optional[str] = None,
        policies_lister: Optional[Callable[[], Awaitable[Any]]] = None,
        haltsql_bin: Optional[str] = None,
    ) -> None:
        self.verifier = verifier
        self.context_provider = context_provider
        self.connect = connect
        self.row_cap = row_cap
        self.statement_timeout_ms = statement_timeout_ms
        self.set_config = dict(set_config or {})
        self.policy_file = policy_file
        self.policies_lister = policies_lister
        self.haltsql_bin = haltsql_bin
        self._summary: Optional[Dict[str, Any]] = None

    # -- helpers -----------------------------------------------------------
    def _context(self) -> Dict[str, Any]:
        try:
            ctx = self.context_provider()
        except PermissionError as e:
            raise ToolFailure(str(e) or "not authenticated") from None
        return dict(ctx)

    @staticmethod
    def _check_sql(sql: Any) -> str:
        if not isinstance(sql, str) or not sql.strip():
            raise ToolFailure("sql must be a non-empty string")
        if len(sql) > MAX_SQL_CHARS:
            raise ToolFailure(f"sql is longer than {MAX_SQL_CHARS} characters")
        return sql

    async def _verify(self, sql: str, ctx: Mapping[str, Any]) -> Verdict:
        try:
            result = self.verifier.verify(sql, ctx)
            if hasattr(result, "__await__"):
                result = await result
        except HaltSQLRequestError as e:
            raise ToolFailure(f"verification refused ({e.code}); the query was not executed") from None
        except HaltSQLUnavailable:
            raise ToolFailure("verification is unavailable; the query was not executed") from None
        except Exception:  # noqa: BLE001 - any other failure also means deny
            raise ToolFailure("verification failed; the query was not executed") from None
        if not isinstance(result, Verdict) or not result.matches_sql(sql):
            raise ToolFailure("verification returned an invalid verdict; the query was not executed")
        return result

    def _settings(self, ctx: Mapping[str, Any]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for setting, key in self.set_config.items():
            if key not in ctx:
                raise ToolFailure(f"server misconfigured: context has no {key!r} for {setting}")
            v = ctx[key]
            out[setting] = ",".join(str(x) for x in v) if isinstance(v, list) else str(v)
        return out

    def _policy_summary(self) -> Optional[Dict[str, Any]]:
        if self.policy_file is None:
            return None
        if self._summary is None:
            try:
                self._summary = summarize_policy(load_policy_document(self.policy_file, self.haltsql_bin))
            except ToolFailure:
                raise
            except Exception as e:  # noqa: BLE001
                raise ToolFailure(f"could not read the policy file: {type(e).__name__}") from None
        return self._summary

    # -- tools -------------------------------------------------------------
    async def query(self, sql: str) -> Dict[str, Any]:
        """Verify, then run the SQL read-only and return rows (or the denial)."""
        sql = self._check_sql(sql)
        if self.connect is None:
            raise ToolFailure("no database is configured for this server")
        ctx = self._context()
        settings = self._settings(ctx)
        verdict = await self._verify(sql, ctx)
        if not verdict.allowed:
            return {
                "allowed": False,
                "executed": False,
                "reasons": _reasons(verdict),
                "message": "HaltSQL denied the query. Fix it using the reasons and hints, then retry.",
            }
        if verdict.shadow_reasons and not guard.shadow_allowed():
            # A shadow-mode policy would deny this. Running it needs an explicit
            # opt-in on this server (HALTSQL_ALLOW_SHADOW=1), so a policy switched
            # to shadow elsewhere cannot silently turn enforcement off here.
            return {
                "allowed": False,
                "executed": False,
                "reasons": [r.to_dict() for r in verdict.shadow_reasons],
                "message": "HaltSQL denied the query. Fix it using the reasons and hints, then retry.",
            }
        try:
            conn = await self.connect()
        except Exception as e:  # noqa: BLE001
            raise ToolFailure(f"database connection failed: {type(e).__name__}") from None
        try:
            # The guard re-checks the verdict against this exact string.
            result = await guard.execute_async(
                conn, sql, ctx,
                verdict=verdict,
                read_only=True,
                statement_timeout_ms=self.statement_timeout_ms,
                settings=settings,
                max_rows=self.row_cap,
            )
        except QueryDenied as e:  # pragma: no cover - verdict already checked
            return {
                "allowed": False,
                "executed": False,
                "reasons": [r.to_dict() for r in e.reasons],
            }
        except (GuardError, HaltSQLUnavailable) as e:
            raise ToolFailure(f"query not executed: {e}") from None
        except Exception as e:  # noqa: BLE001 - database error
            raise ToolFailure(f"database error: {_db_error(e)}") from None
        finally:
            close = getattr(conn, "close", None)
            if close is not None:
                r = close()
                if hasattr(r, "__await__"):
                    await r
        return {
            "allowed": True,
            "executed": True,
            "columns": result.columns,
            "rows": [jsonable(list(r) if isinstance(r, tuple) else r) for r in result.rows],
            "row_count": len(result.rows),
            "truncated": result.truncated,
            "row_cap": self.row_cap,
            "shadow_reasons": [r.to_dict() for r in verdict.shadow_reasons],
        }

    async def explain_denial(self, sql: str) -> Dict[str, Any]:
        """Verify only; explain why the SQL would be denied (never executes)."""
        sql = self._check_sql(sql)
        ctx = self._context()
        verdict = await self._verify(sql, ctx)
        out: Dict[str, Any] = {
            "allowed": verdict.allowed,
            "reasons": _reasons(verdict),
            "shadow_reasons": [r.to_dict() for r in verdict.shadow_reasons],
            "statement_kind": verdict.statement_kind,
            "tables": list(verdict.tables),
            "columns": list(verdict.columns),
            "policy": {"name": verdict.policy.name, "version": verdict.policy.version},
        }
        if verdict.allowed:
            out["message"] = "This query is allowed; run it with the query tool."
        return out

    async def list_tables(self) -> Dict[str, Any]:
        """Tables and columns the policy allows."""
        self._context()  # require an authenticated session for schema info too
        summary = self._policy_summary()
        if summary is None:
            raise ToolFailure("no policy file is configured, so the table list is unavailable")
        return {
            "tables": [
                {k: t[k] for k in ("table", "columns", "tenant_scoped", "tenant_columns") if k in t}
                for t in summary["tables"]
            ],
            "guidance": _tenancy_guidance(summary),
        }

    async def describe_policy(self) -> Dict[str, Any]:
        """Policy name/version/mode (from /v1/policies) and its rules (from the policy file)."""
        self._context()
        out: Dict[str, Any] = {}
        if self.policies_lister is not None:
            try:
                infos = await self.policies_lister()
                out["policies"] = [{"name": p.name, "version": p.version, "mode": p.mode} for p in infos]
            except (HaltSQLUnavailable, HaltSQLRequestError):
                out["policies_error"] = "could not list policies from the HaltSQL sidecar"
        summary = self._policy_summary()
        if summary is not None:
            out["policy"] = summary
            out["guidance"] = _tenancy_guidance(summary)
        if not out:
            raise ToolFailure("no policy information is configured")
        return out


def _db_error(e: BaseException) -> str:
    sqlstate = getattr(e, "sqlstate", None)
    diag = getattr(e, "diag", None)
    primary = getattr(diag, "message_primary", None) if diag is not None else None
    text = str(e).strip()
    msg = primary or (text.splitlines()[0] if text else type(e).__name__)
    return f"{sqlstate} {msg}" if sqlstate else msg
