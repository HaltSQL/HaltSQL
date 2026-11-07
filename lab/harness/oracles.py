"""The judges (PLAN.md §8.4): the database, not HaltSQL, decides whether an
allowed query was actually safe.

Every allowed query is executed inside ONE read-only, repeatable-read
transaction that is always rolled back, under three roles:

* ``haltlab_owner`` — owns the tables, not subject to RLS. This is what the
  query returns in production with the binds HaltSQL told us to use.
* ``haltlab_rls`` — subject to row-level security keyed on ``app.*`` settings
  that carry the caller's tenancy. Any row the owner run returns that the RLS
  run does not is a tenant escape (multiset difference).
* ``haltlab_cols`` — has ``SELECT`` only on the policy's allowed columns. A
  permission error (SQLSTATE 42501) means HaltSQL allowed a denied column.

Additionally the owner run's output is scanned for honeytoken markers that the
caller must not see, and side effects are detected: write attempts (25006 in
a read-only transaction), changed settings, transaction control escaping our
transaction, leftover advisory locks, and timeouts (57014).

Repeatable read gives all three runs the same snapshot, and ``now()`` is
fixed for the transaction, so legitimate queries produce identical results.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence

from datagen.honeytokens import Registry, classify, extract_markers

SQLSTATE_INSUFFICIENT_PRIVILEGE = "42501"
SQLSTATE_READ_ONLY = "25006"
SQLSTATE_QUERY_CANCELED = "57014"

OWNER_ROLE = "haltlab_owner"
RLS_ROLE = "haltlab_rls"
COLS_ROLE = "haltlab_cols"

_SETTINGS_SNAPSHOT = (
    "SELECT name, setting FROM pg_settings "
    "WHERE name NOT IN ('role', 'session_authorization', 'transaction_read_only', "
    "'statement_timeout', 'transaction_isolation') ORDER BY name"
)


class PQResult(Protocol):  # the subset of psycopg.pq.PGresult we use
    status: Any
    ntuples: int
    nfields: int

    def get_value(self, row: int, col: int) -> bytes | None: ...
    def error_field(self, code: Any) -> bytes | None: ...


@dataclass
class Run:
    ok: bool
    rows: list[tuple[bytes | None, ...]] = field(default_factory=list)
    sqlstate: str | None = None
    message: str | None = None


@dataclass
class Finding:
    oracle: str  # rls | honeytoken | columns | side_effect | timeout
    detail: str


@dataclass
class ItemResult:
    id: str
    executed: bool
    findings: list[Finding] = field(default_factory=list)
    owner_rows: int = 0
    execution_error: str | None = None

    @property
    def escape(self) -> bool:
        return any(f.oracle in ("rls", "honeytoken", "columns") for f in self.findings)

    @property
    def column_leak(self) -> bool:
        return any(f.oracle == "columns" or (f.oracle == "honeytoken" and f.detail.startswith("column"))
                   for f in self.findings)

    @property
    def side_effect(self) -> bool:
        return any(f.oracle == "side_effect" for f in self.findings)


def encode_param(value: Any) -> bytes | None:
    """Text-format parameter. Lists become Postgres array literals."""
    if value is None:
        return None
    if isinstance(value, list):
        items = []
        for v in value:
            s = str(v).replace("\\", "\\\\").replace('"', '\\"')
            items.append(f'"{s}"')
        return ("{" + ",".join(items) + "}").encode()
    return str(value).encode()


def bind_values(verdict: dict[str, Any]) -> list[bytes | None]:
    """Positional parameters from the verdict's bind_params ($1..$max)."""
    binds = {int(b["param"]): b["value"] for b in verdict.get("bind_params") or []}
    if not binds:
        return []
    return [encode_param(binds.get(i)) for i in range(1, max(binds) + 1)]


def tenancy_settings(keys: Sequence[tuple[str, str]], context: dict[str, Any]) -> list[tuple[str, str]]:
    """``app.<context field>`` settings read by the fixtures' RLS policies."""
    out = []
    for _key, fieldname in keys:
        v = context.get(fieldname)
        text = ",".join(str(x) for x in v) if isinstance(v, list) else ("" if v is None else str(v))
        out.append((f"app.{fieldname}", text))
    return out


class Session:
    """Thin wrapper over a libpq connection (psycopg.pq.PGconn) in autocommit mode."""

    def __init__(self, pgconn: Any) -> None:
        from psycopg import pq

        self.pg = pgconn
        self.pq = pq

    def run(self, sql: str, params: Sequence[bytes | None] | None = None) -> Run:
        pq = self.pq
        if params is None:
            res = self.pg.exec_(sql.encode())
        else:
            res = self.pg.exec_params(sql.encode(), list(params))
        if res.status in (pq.ExecStatus.TUPLES_OK, pq.ExecStatus.COMMAND_OK, pq.ExecStatus.EMPTY_QUERY):
            rows = [tuple(res.get_value(r, c) for c in range(res.nfields)) for r in range(res.ntuples)]
            return Run(True, rows)
        state = res.error_field(pq.DiagnosticField.SQLSTATE)
        msg = res.error_field(pq.DiagnosticField.MESSAGE_PRIMARY)
        return Run(False, sqlstate=state.decode() if state else None,
                   message=msg.decode("utf-8", "replace") if msg else None)

    def must(self, sql: str, params: Sequence[bytes | None] | None = None) -> Run:
        r = self.run(sql, params)
        if not r.ok:
            raise RuntimeError(f"harness statement failed ({r.sqlstate}): {r.message}: {sql}")
        return r

    @property
    def in_transaction(self) -> bool:
        ts = self.pg.transaction_status
        return ts in (self.pq.TransactionStatus.INTRANS, self.pq.TransactionStatus.INERROR)


def _snapshot(s: Session, settings: list[tuple[str, str]]) -> dict[str, str]:
    snap = {(r[0] or b"").decode(): (r[1] or b"").decode() for r in s.must(_SETTINGS_SNAPSHOT).rows}
    for name, _ in settings:
        r = s.must("SELECT current_setting($1, true)", [name.encode()])
        snap[name] = (r.rows[0][0] or b"").decode()
    return snap


_LEADING_NOISE = re.compile(r"^(?:\s+|--[^\n]*\n?|/\*.*?\*/)*", re.S)


def is_explain(sql: str) -> bool:
    """EXPLAIN output is a plan, not row data, and legitimately differs per role."""
    rest = _LEADING_NOISE.sub("", sql, count=1)
    return rest[:7].lower() == "explain"


def _decode_rows(rows: list[tuple[bytes | None, ...]]) -> list[tuple[str | None, ...]]:
    return [tuple(None if v is None else v.decode("utf-8", "replace") for v in row) for row in rows]


def check_item(
    s: Session,
    item: dict[str, Any],
    verdict: dict[str, Any],
    keys: Sequence[tuple[str, str]],
    registry: Registry,
    allowed: dict[str, set[str]],
    statement_timeout_ms: int,
) -> ItemResult:
    """Execute one allowed query under all oracles. The database state is never changed."""
    res = ItemResult(id=str(item["id"]), executed=True)
    sql = item["sql"]
    params = bind_values(verdict)
    settings = tenancy_settings(keys, item.get("context") or {})

    s.must("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
    try:
        s.must(f"SET LOCAL statement_timeout = {int(statement_timeout_ms)}")
        for name, value in settings:
            s.must("SELECT set_config($1, $2, true)", [name.encode(), value.encode()])
        s.must("SAVEPOINT haltlab_item")

        # 1. Reference run as the table owner.
        s.must(f"SET LOCAL ROLE {OWNER_ROLE}")
        before = _snapshot(s, settings)
        owner = s.run(sql, params)
        if not s.in_transaction:  # the query ended our transaction (COMMIT/ROLLBACK/...)
            res.findings.append(Finding("side_effect", "transaction control escaped the harness transaction"))
            return res
        if owner.ok:
            after = _snapshot(s, settings)
            changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
            for k in changed:
                res.findings.append(Finding("side_effect", f"setting changed: {k}"))
        elif owner.sqlstate == SQLSTATE_READ_ONLY:
            res.findings.append(Finding("side_effect", f"write attempted: {owner.message}"))
        elif owner.sqlstate == SQLSTATE_QUERY_CANCELED:
            res.findings.append(Finding("timeout", f"exceeded statement_timeout {statement_timeout_ms} ms"))
        else:
            res.execution_error = f"{owner.sqlstate}: {owner.message}"
        s.must("ROLLBACK TO SAVEPOINT haltlab_item")

        if owner.ok:
            res.owner_rows = len(owner.rows)
            # 2. Honeytokens in what the caller would receive.
            for leak in classify(extract_markers(_decode_rows(owner.rows)), registry, allowed):
                where = f"{leak.table}.{leak.column}" if leak.column else leak.table
                res.findings.append(Finding("honeytoken", f"{leak.kind} marker {leak.marker} from {where}"))

            # 3. RLS differential (skipped for EXPLAIN: plans differ per role by design).
            s.must(f"SET LOCAL ROLE {RLS_ROLE}")
            rls = s.run(sql, params)
            s.must("ROLLBACK TO SAVEPOINT haltlab_item")
            if rls.ok and not is_explain(sql):
                extra = Counter(owner.rows) - Counter(rls.rows)
                if extra:
                    res.findings.append(Finding(
                        "rls", f"{sum(extra.values())} row(s) visible to the owner run are hidden by RLS"))
            elif rls.sqlstate != SQLSTATE_INSUFFICIENT_PRIVILEGE:
                res.execution_error = res.execution_error or f"rls run {rls.sqlstate}: {rls.message}"

        # 4. Column privileges.
        s.must(f"SET LOCAL ROLE {COLS_ROLE}")
        cols = s.run(sql, params)
        s.must("ROLLBACK TO SAVEPOINT haltlab_item")
        if not cols.ok and cols.sqlstate == SQLSTATE_INSUFFICIENT_PRIVILEGE:
            res.findings.append(Finding("columns", f"permission denied for column-limited role: {cols.message}"))
    finally:
        if s.in_transaction:
            s.run("ROLLBACK")
        # Session-level advisory locks survive ROLLBACK.
        locks = s.must("SELECT count(*) FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'advisory'")
        if int(locks.rows[0][0] or b"0") > 0:
            res.findings.append(Finding("side_effect", "advisory lock left held"))
            s.must("SELECT pg_advisory_unlock_all()")
    return res
