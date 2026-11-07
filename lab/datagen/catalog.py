"""Catalog introspection: the facts datagen needs about each table."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ColumnInfo:
    name: str
    type: str  # base type name after resolving domains/arrays, e.g. "text", "int8", "numeric"
    nullable: bool = True
    is_array: bool = False
    generated: bool = False  # GENERATED ALWAYS AS (...) STORED
    identity_always: bool = False
    serial: bool = False  # integer column with nextval() default or identity
    char_max: int | None = None  # varchar(n)/char(n) length
    enum_labels: tuple[str, ...] = ()
    domain: str | None = None
    has_default: bool = False


@dataclass(frozen=True)
class ForeignKey:
    columns: tuple[str, ...]
    ref_schema: str
    ref_table: str
    ref_columns: tuple[str, ...]


@dataclass
class TableInfo:
    schema: str
    name: str
    kind: str  # r (table) | p (partitioned) | v (view) | m (matview)
    columns: list[ColumnInfo]
    pk: tuple[str, ...] = ()
    fks: list[ForeignKey] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str]:
        return (self.schema, self.name)

    @property
    def dotted(self) -> str:
        return f"{self.schema}.{self.name}"

    @property
    def insertable(self) -> bool:
        return self.kind in ("r", "p")

    def column(self, name: str) -> ColumnInfo | None:
        for c in self.columns:
            if c.name == name:
                return c
        return None


class Conn(Protocol):
    def execute(self, query: Any, params: Any = ...) -> Any: ...


_COLS_SQL = """
SELECT n.nspname, c.relname, c.relkind, a.attname, a.attnum,
       COALESCE(bt.typname, t.typname) AS base_type,
       t.typtype, t.typcategory = 'A' OR COALESCE(bt.typcategory, '') = 'A' AS is_array,
       COALESCE(et.typname, bet.typname) AS elem_type,
       NOT a.attnotnull AS nullable, a.attgenerated = 's' AS generated,
       a.attidentity AS identity,
       pg_get_expr(d.adbin, d.adrelid) AS default_expr,
       CASE WHEN a.atttypmod > 4 AND COALESCE(bt.typname, t.typname) IN ('varchar', 'bpchar')
            THEN a.atttypmod - 4 END AS char_max,
       CASE WHEN t.typtype = 'd' THEN t.typname END AS domain,
       COALESCE(et.oid, bet.oid, bt.oid, t.oid) AS label_type
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
JOIN pg_type t ON t.oid = a.atttypid
LEFT JOIN pg_type bt ON t.typtype = 'd' AND bt.oid = t.typbasetype
LEFT JOIN pg_type et ON et.oid = t.typelem AND t.typcategory = 'A'
LEFT JOIN pg_type bet ON bet.oid = bt.typelem AND bt.typcategory = 'A'
LEFT JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
WHERE n.nspname = ANY(%s) AND c.relkind IN ('r', 'p', 'v', 'm') AND NOT c.relispartition
ORDER BY n.nspname, c.relname, a.attnum
"""

_ENUM_SQL = "SELECT enumtypid, enumlabel FROM pg_enum ORDER BY enumtypid, enumsortorder"

_PK_SQL = """
SELECT n.nspname, c.relname, array_agg(a.attname ORDER BY k.ord) AS cols
FROM pg_constraint con
JOIN pg_class c ON c.oid = con.conrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord)
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
WHERE con.contype = 'p' AND n.nspname = ANY(%s) AND NOT c.relispartition
GROUP BY n.nspname, c.relname
"""

_FK_SQL = """
SELECT n.nspname, c.relname, con.conname,
       array_agg(a.attname ORDER BY k.ord) AS cols,
       rn.nspname AS ref_schema, rc.relname AS ref_table,
       array_agg(ra.attname ORDER BY k.ord) AS ref_cols
FROM pg_constraint con
JOIN pg_class c ON c.oid = con.conrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_class rc ON rc.oid = con.confrelid
JOIN pg_namespace rn ON rn.oid = rc.relnamespace
CROSS JOIN LATERAL unnest(con.conkey, con.confkey) WITH ORDINALITY AS k(attnum, refattnum, ord)
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
JOIN pg_attribute ra ON ra.attrelid = rc.oid AND ra.attnum = k.refattnum
WHERE con.contype = 'f' AND n.nspname = ANY(%s) AND NOT c.relispartition
GROUP BY n.nspname, c.relname, con.conname, rn.nspname, rc.relname
ORDER BY n.nspname, c.relname, con.conname
"""

_INT_TYPES = {"int2", "int4", "int8"}


def introspect(conn: Any, schemas: list[str]) -> list[TableInfo]:
    """Read tables/columns/PKs/FKs of ``schemas`` (partitions excluded), sorted."""
    labels: dict[int, list[str]] = {}
    for oid, label in conn.execute(_ENUM_SQL).fetchall():
        labels.setdefault(int(oid), []).append(label)
    tables: dict[tuple[str, str], TableInfo] = {}
    for row in conn.execute(_COLS_SQL, (schemas,)).fetchall():
        (nsp, rel, kind, att, _num, base, _typtype, is_array, elem, nullable, generated,
         identity, default_expr, char_max, domain, label_type) = row
        tb = tables.setdefault((nsp, rel), TableInfo(nsp, rel, kind, []))
        ty = elem if is_array and elem else base
        default_expr = default_expr or ""
        serial = (ty in _INT_TYPES) and (identity in ("a", "d") or "nextval(" in default_expr)
        tb.columns.append(
            ColumnInfo(
                name=att,
                type=ty,
                nullable=bool(nullable),
                is_array=bool(is_array),
                generated=bool(generated),
                identity_always=identity == "a",
                serial=serial,
                char_max=int(char_max) if char_max else None,
                enum_labels=tuple(labels.get(int(label_type), ())),
                domain=domain,
                has_default=bool(default_expr) or identity in ("a", "d"),
            )
        )
    for nsp, rel, cols in conn.execute(_PK_SQL, (schemas,)).fetchall():
        if (nsp, rel) in tables:
            tables[(nsp, rel)].pk = tuple(cols)
    for nsp, rel, _name, cols, rs, rt, rcols in conn.execute(_FK_SQL, (schemas,)).fetchall():
        if (nsp, rel) in tables:
            tables[(nsp, rel)].fks.append(ForeignKey(tuple(cols), rs, rt, tuple(rcols)))
    return topo_sort([tables[k] for k in sorted(tables)])


def topo_sort(tables: list[TableInfo]) -> list[TableInfo]:
    """Parents before children (FK order); stable for determinism; cycles broken by name."""
    by_key = {t.key: t for t in tables}
    done: set[tuple[str, str]] = set()
    out: list[TableInfo] = []

    def visit(t: TableInfo, stack: set[tuple[str, str]]) -> None:
        if t.key in done or t.key in stack:
            return
        stack.add(t.key)
        for fk in t.fks:
            parent = by_key.get((fk.ref_schema, fk.ref_table))
            if parent is not None and parent.key != t.key:
                visit(parent, stack)
        stack.discard(t.key)
        done.add(t.key)
        out.append(t)

    for t in tables:
        visit(t, set())
    return out
